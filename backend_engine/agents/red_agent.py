from pathlib import Path

from backend_engine.agents.llm_agent import BaseLLMAgent, LLMDecisionError
from backend_engine.core.models import AgentDecision, WorldState


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
                thought="当前只掌握边界资产轮廓，先对 Web 做侦察以确认服务与漏洞面。",
                action_type="Recon",
                target="web",
                payload="对 Web 入口执行低噪声扫描",
            )

        if "web" in visible_nodes and nodes["web"].status != "Compromised" and known_vulnerabilities.get("web"):
            return AgentDecision(
                agent_type="Red",
                thought="Recon 已确认 Web 存在可利用面，优先从公网入口建立首个据点。",
                action_type="ExploitService",
                target="web",
                payload="通过公网 HTTP 服务利用 CVE-WEB-2026-0001",
            )

        if nodes["web"].status == "Compromised" and "app" in visible_nodes and "app" not in recon_nodes:
            return AgentDecision(
                agent_type="Red",
                thought="Web 已失陷，先侦察与其相邻的内网应用节点，确认下一跳情报。",
                action_type="Recon",
                target="app",
                payload="通过 Web 据点对 App 节点执行低噪声横向侦察",
            )

        if (
            nodes["web"].status == "Compromised"
            and "app" in visible_nodes
            and nodes["app"].status != "Compromised"
            and known_vulnerabilities.get("app")
        ):
            return AgentDecision(
                agent_type="Red",
                thought="App 节点已被观察到存在薄弱点，可以基于 Web 据点实施横向移动。",
                action_type="LateralMove",
                target="app",
                payload="复用从 Web 节点窃取的凭据横向进入 App",
            )

        if nodes["app"].status == "Compromised" and "db" in visible_nodes and "db" not in recon_nodes:
            return AgentDecision(
                agent_type="Red",
                thought="应用层已被控制，先侦察数据库节点的端口与弱点，再决定是否下探。",
                action_type="Recon",
                target="db",
                payload="通过 App 到 DB 的信任路径执行静默侦察",
            )

        if (
            nodes["app"].status == "Compromised"
            and "db" in visible_nodes
            and nodes["db"].status != "Compromised"
            and known_vulnerabilities.get("db")
        ):
            return AgentDecision(
                agent_type="Red",
                thought="数据库目标已经完成识别，且仍存在可利用面，可以尝试导出高价值数据。",
                action_type="ExfiltrateDatabase",
                target="db",
                payload="利用 App 到 DB 的信任链路并尝试导出记录",
            )

        for node_name in sorted(visible_nodes):
            if node_name in nodes and node_name not in recon_nodes and nodes[node_name].status != "Compromised":
                return AgentDecision(
                    agent_type="Red",
                    thought=f"当前对 {node_name} 仍缺乏足够情报，先补一轮侦察再决定攻击动作。",
                    action_type="Recon",
                    target=node_name,
                    payload=f"对 {node_name} 执行补充侦察",
                )

        return AgentDecision(
            agent_type="Red",
            thought="当前未形成新的可利用路径，继续维持低噪声侦察节奏。",
            action_type="Recon",
            target=next(iter(sorted(visible_nodes))) if visible_nodes else "internet",
            payload="对当前可见边界执行低噪声扫描",
        )
