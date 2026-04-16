from pathlib import Path
from typing import Any, Mapping

from backend_engine.agents.llm_agent import BaseLLMAgent, LLMDecisionError
from backend_engine.core.models import AgentDecision, VulnerabilityInfo, WorldState


def _vulnerability_score(value: VulnerabilityInfo | dict[str, Any]) -> int:
    if isinstance(value, VulnerabilityInfo):
        return value.score
    if isinstance(value, dict):
        raw_score = value.get("score", 0)
        if isinstance(raw_score, (int, float)):
            return int(raw_score)
    return 0


def _pick_best_vuln_id(vulnerabilities: Mapping[str, VulnerabilityInfo | dict[str, Any]] | None) -> str | None:
    if not vulnerabilities:
        return None
    vuln_id, _ = max(vulnerabilities.items(), key=lambda item: (_vulnerability_score(item[1]), item[0]))
    return vuln_id


class RedAgent(BaseLLMAgent):
    def __init__(self) -> None:
        prompt_path = Path(__file__).resolve().parent.parent / "prompts" / "red_attacker.md"
        super().__init__(
            agent_name="Red",
            agent_type="Red",
            prompt_path=prompt_path,
            max_retries=3,
        )

    def decide(self, state: WorldState, context_markdown: str | None = None) -> AgentDecision:
        visible_nodes = set(state.red_visible_nodes)
        if not visible_nodes:
            visible_nodes = {"internet", "fw", "web"} & set(state.network_nodes)

        if not context_markdown:
            raise LLMDecisionError("红方缺少 context_markdown，无法进行 LLM 决策。")

        try:
            return super().decide(
                state,
                context_markdown,
                allowed_targets=visible_nodes,
            )
        except Exception as exc:
            print(f"[RedAgent] LLM 决策失败，回退到规则策略：{exc}")
            return self._fallback_decide(state)

    def _fallback_decide(self, state: WorldState) -> AgentDecision:
        visible_nodes = set(state.red_visible_nodes)
        recon_nodes = set(state.red_recon_nodes)
        known_vulnerabilities = state.red_known_vulnerabilities
        nodes = state.network_nodes

        if not visible_nodes:
            visible_nodes = {"internet", "fw", "web"} & set(nodes)

        if "web" in visible_nodes and "web" not in recon_nodes and nodes["web"].status != "Compromised":
            return AgentDecision(
                agent_type="Red",
                thought="情报仍然不足，先对 web 做 Recon，确认端口与漏洞详情。",
                action_type="Recon",
                target="web",
                payload="对 web 执行低噪声侦察，收集端口与漏洞情报",
            )

        if "web" in visible_nodes and nodes["web"].status != "Compromised" and known_vulnerabilities.get("web"):
            vuln_id = _pick_best_vuln_id(known_vulnerabilities["web"])
            return AgentDecision(
                agent_type="Red",
                thought="web 已经完成侦察，存在可用漏洞，优先从公网入口建立首个据点。",
                action_type="ExploitService",
                target="web",
                vuln_id=vuln_id,
                payload=f"利用 vuln_id={vuln_id} 通过公网服务攻破 web",
            )

        if nodes["web"].status == "Compromised" and "app" in visible_nodes and "app" not in recon_nodes:
            return AgentDecision(
                agent_type="Red",
                thought="已控制 web，据此继续侦察 app，确认下一跳漏洞。",
                action_type="Recon",
                target="app",
                payload="通过 web 据点对 app 执行低噪声横向侦察",
            )

        if (
            nodes["web"].status == "Compromised"
            and "app" in visible_nodes
            and nodes["app"].status != "Compromised"
            and known_vulnerabilities.get("app")
        ):
            vuln_id = _pick_best_vuln_id(known_vulnerabilities["app"])
            return AgentDecision(
                agent_type="Red",
                thought="app 已被识别出可利用漏洞，可利用既有 web 据点进行横向移动。",
                action_type="LateralMove",
                target="app",
                vuln_id=vuln_id,
                payload=f"利用 vuln_id={vuln_id} 从 web 横向进入 app",
            )

        if nodes["app"].status == "Compromised" and "db" in visible_nodes and "db" not in recon_nodes:
            return AgentDecision(
                agent_type="Red",
                thought="应用层已经失陷，先侦察 db，确认数据库漏洞与导出路径。",
                action_type="Recon",
                target="db",
                payload="通过 app 到 db 的信任路径执行静默侦察",
            )

        if (
            nodes["app"].status == "Compromised"
            and "db" in visible_nodes
            and nodes["db"].status != "Compromised"
            and known_vulnerabilities.get("db")
        ):
            vuln_id = _pick_best_vuln_id(known_vulnerabilities["db"])
            return AgentDecision(
                agent_type="Red",
                thought="数据库目标已识别且存在可用漏洞，尝试直接导出高价值数据。",
                action_type="ExfiltrateDatabase",
                target="db",
                vuln_id=vuln_id,
                payload=f"利用 vuln_id={vuln_id} 对 db 执行数据导出",
            )

        for node_name in sorted(visible_nodes):
            if node_name in nodes and node_name not in recon_nodes and nodes[node_name].status != "Compromised":
                return AgentDecision(
                    agent_type="Red",
                    thought=f"当前对 {node_name} 的情报还不够，先补一轮 Recon。",
                    action_type="Recon",
                    target=node_name,
                    payload=f"对 {node_name} 执行补充侦察",
                )

        return AgentDecision(
            agent_type="Red",
            thought="尚未形成新的稳定利用路径，继续维持低噪声侦察。",
            action_type="Recon",
            target=next(iter(sorted(visible_nodes))) if visible_nodes else "internet",
            payload="对当前可见边界执行低噪声扫描",
        )
