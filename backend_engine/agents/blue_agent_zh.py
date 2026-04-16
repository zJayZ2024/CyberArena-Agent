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


class BlueAgent:
    agent_name = "Blue"

    def decide(self, state: WorldState, red_action: AgentDecision | None = None) -> AgentDecision:
        nodes = state.network_nodes

        if red_action and red_action.target and red_action.target in nodes:
            if red_action.action_type == "Recon":
                return AgentDecision(
                    agent_type="Blue",
                    thought="检测到侦察行为。根据 SOP，优先监控。",
                    action_type="Monitor",
                    target=red_action.target,
                    payload=f"针对 {red_action.target} 提升监控与告警灵敏度",
                )

            target_node = nodes[red_action.target]
            if target_node.status == "Compromised":
                return AgentDecision(
                    agent_type="Blue",
                    thought=f"{red_action.target.upper()} 已失陷，优先恢复。",
                    action_type="RestoreNode",
                    target=red_action.target,
                    payload=f"恢复 {red_action.target} 到干净基线",
                )

            vuln_id = _pick_best_vuln_id(target_node.vulnerabilities)
            if vuln_id:
                return AgentDecision(
                    agent_type="Blue",
                    thought=f"{red_action.target.upper()} 存在高价值漏洞，优先修补。",
                    action_type="PatchNode",
                    target=red_action.target,
                    vuln_id=vuln_id,
                    payload=f"修补 {red_action.target} 的 vuln_id={vuln_id}",
                )

        for node_name in ("db", "app", "web"):
            if nodes[node_name].status == "Compromised":
                return AgentDecision(
                    agent_type="Blue",
                    thought=f"{node_name.upper()} 已失陷，必须优先恢复。",
                    action_type="RestoreNode",
                    target=node_name,
                    payload=f"恢复 {node_name} 到干净基线",
                )

        for node_name in ("app", "web", "db"):
            vuln_id = _pick_best_vuln_id(nodes[node_name].vulnerabilities)
            if nodes[node_name].status == "Normal" and vuln_id:
                return AgentDecision(
                    agent_type="Blue",
                    thought=f"{node_name.upper()} 仍存在高价值漏洞，优先修补。",
                    action_type="PatchNode",
                    target=node_name,
                    vuln_id=vuln_id,
                    payload=f"修补 {node_name} 的 vuln_id={vuln_id}",
                )

        return AgentDecision(
            agent_type="Blue",
            thought="关键节点已基本稳定，继续保持全局监控。",
            action_type="Monitor",
            target="network",
            payload="审查告警并维持监控覆盖",
        )
