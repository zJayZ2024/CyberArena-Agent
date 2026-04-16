from typing import Any

from backend_engine.core.models import AgentDecision, VulnerabilityInfo, WorldState


def _vulnerability_score(value: VulnerabilityInfo | dict[str, Any]) -> int:
    if isinstance(value, VulnerabilityInfo):
        return value.score
    if isinstance(value, dict):
        raw_score = value.get("score", 0)
        if isinstance(raw_score, (int, float)):
            return int(raw_score)
    return 0


def _pick_best_vuln_id(vulnerabilities: dict[str, VulnerabilityInfo | dict[str, Any]]) -> str | None:
    if not vulnerabilities:
        return None
    vuln_id, _ = max(vulnerabilities.items(), key=lambda item: (_vulnerability_score(item[1]), item[0]))
    return vuln_id


class RedAgent:
    agent_name = "Red"

    def decide(self, state: WorldState) -> AgentDecision:
        nodes = state.network_nodes

        if nodes["web"].status != "Compromised" and not state.red_recon_nodes:
            return AgentDecision(
                agent_type="Red",
                thought="先对 web 做侦察，确认具体漏洞。",
                action_type="Recon",
                target="web",
                payload="侦察 web 节点，确认端口与漏洞",
            )

        if nodes["web"].status != "Compromised" and nodes["web"].vulnerabilities:
            vuln_id = _pick_best_vuln_id(nodes["web"].vulnerabilities)
            return AgentDecision(
                agent_type="Red",
                thought="web 存在可用漏洞，优先建立首个据点。",
                action_type="ExploitService",
                target="web",
                vuln_id=vuln_id,
                payload=f"利用 vuln_id={vuln_id} 攻击 web",
            )

        if nodes["web"].status == "Compromised" and nodes["app"].status != "Compromised":
            vuln_id = _pick_best_vuln_id(nodes["app"].vulnerabilities)
            if vuln_id:
                return AgentDecision(
                    agent_type="Red",
                    thought="以 web 为据点横向进入 app。",
                    action_type="LateralMove",
                    target="app",
                    vuln_id=vuln_id,
                    payload=f"利用 vuln_id={vuln_id} 横向进入 app",
                )

        if nodes["app"].status == "Compromised" and nodes["db"].status != "Compromised":
            vuln_id = _pick_best_vuln_id(nodes["db"].vulnerabilities)
            if vuln_id:
                return AgentDecision(
                    agent_type="Red",
                    thought="尝试对 db 做数据导出。",
                    action_type="ExfiltrateDatabase",
                    target="db",
                    vuln_id=vuln_id,
                    payload=f"利用 vuln_id={vuln_id} 对 db 导出数据",
                )

        return AgentDecision(
            agent_type="Red",
            thought="没有明确利用路径，继续 Recon。",
            action_type="Recon",
            target="web",
            payload="继续侦察 web",
        )
