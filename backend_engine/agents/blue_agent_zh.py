from backend_engine.core.models import AgentDecision, WorldState


class BlueAgent:
    agent_name = "Blue"

    def decide(self, state: WorldState, red_action: AgentDecision | None = None) -> AgentDecision:
        nodes = state.network_nodes

        if red_action and red_action.target and red_action.target in nodes:
            if red_action.action_type == "Recon":
                return AgentDecision(
                    agent_type="Blue",
                    thought="检测到侦察行为。根据 SOP，当前只能执行 Monitor，避免高扰动修补影响业务稳定性。",
                    action_type="Monitor",
                    target=red_action.target,
                    payload=f"针对 {red_action.target} 提升监控与告警灵敏度",
                )

            target_node = nodes[red_action.target]
            if target_node.vulnerabilities or target_node.status == "Compromised":
                return AgentDecision(
                    agent_type="Blue",
                    thought=(
                        f"红方本回合正在集中施压 {red_action.target.upper()}，"
                        "应立即围绕该节点做针对性响应。"
                    ),
                    action_type="RestoreNode" if target_node.status == "Compromised" else "PatchNode",
                    target=red_action.target,
                    payload=f"直接响应红方对 {red_action.target} 的本回合攻势",
                )

        for node_name in ("db", "app", "web"):
            if nodes[node_name].status == "Compromised":
                return AgentDecision(
                    agent_type="Blue",
                    thought=f"{node_name.upper()} 已失陷，必须优先隔离并恢复。",
                    action_type="RestoreNode",
                    target=node_name,
                    payload=f"隔离 {node_name} 并从干净快照恢复",
                )

        for node_name in ("app", "web", "db"):
            if nodes[node_name].status == "Normal" and nodes[node_name].vulnerabilities:
                return AgentDecision(
                    agent_type="Blue",
                    thought=f"{node_name.upper()} 仍存在已知弱点，应立即修补加固。",
                    action_type="PatchNode",
                    target=node_name,
                    payload=f"修补 {node_name} 上最优先的漏洞",
                )

        return AgentDecision(
            agent_type="Blue",
            thought="关键节点已基本稳定，继续保持边界监控。",
            action_type="Monitor",
            target="network",
            payload="审查告警并维持监控覆盖",
        )
