from backend_engine.core.models import AgentDecision, WorldState


class BlueAgent:
    agent_name = "Blue"

    def decide(self, state: WorldState, red_action: AgentDecision | None = None) -> AgentDecision:
        nodes = state.network_nodes

        if red_action and red_action.target and red_action.target in nodes:
            target_node = nodes[red_action.target]
            if red_action.action_type != "Recon" and (
                target_node.vulnerabilities or target_node.status == "Compromised"
            ):
                return AgentDecision(
                    agent_type="Blue",
                    thought=(
                        f"\u7ea2\u65b9\u672c\u56de\u5408\u6b63\u5728\u96c6\u4e2d\u65bd\u538b {red_action.target.upper()}\uff0c"
                        "\u5e94\u7acb\u5373\u56f4\u7ed5\u8be5\u8282\u70b9\u505a\u9488\u5bf9\u6027\u54cd\u5e94\u3002"
                    ),
                    action_type="RestoreNode" if target_node.status == "Compromised" else "PatchNode",
                    target=red_action.target,
                    payload=f"\u76f4\u63a5\u54cd\u5e94\u7ea2\u65b9\u5bf9 {red_action.target} \u7684\u672c\u56de\u5408\u653b\u52bf",
                )

        for node_name in ("db", "app", "web"):
            if nodes[node_name].status == "Compromised":
                return AgentDecision(
                    agent_type="Blue",
                    thought=f"{node_name.upper()} \u5df2\u5931\u9677\uff0c\u5fc5\u987b\u4f18\u5148\u9694\u79bb\u5e76\u6062\u590d\u3002",
                    action_type="RestoreNode",
                    target=node_name,
                    payload=f"\u9694\u79bb {node_name} \u5e76\u4ece\u5e72\u51c0\u5feb\u7167\u6062\u590d",
                )

        for node_name in ("app", "web", "db"):
            if nodes[node_name].status == "Normal" and nodes[node_name].vulnerabilities:
                return AgentDecision(
                    agent_type="Blue",
                    thought=f"{node_name.upper()} \u4ecd\u5b58\u5728\u5df2\u77e5\u5f31\u70b9\uff0c\u5e94\u7acb\u5373\u4fee\u8865\u52a0\u56fa\u3002",
                    action_type="PatchNode",
                    target=node_name,
                    payload=f"\u4fee\u8865 {node_name} \u4e0a\u6700\u4f18\u5148\u7684\u6f0f\u6d1e",
                )

        return AgentDecision(
            agent_type="Blue",
            thought="\u5173\u952e\u8282\u70b9\u5df2\u57fa\u672c\u7a33\u5b9a\uff0c\u7ee7\u7eed\u4fdd\u6301\u8fb9\u754c\u76d1\u63a7\u3002",
            action_type="Monitor",
            target="web",
            payload="\u5ba1\u67e5\u544a\u8b66\u5e76\u7ef4\u6301\u76d1\u63a7\u8986\u76d6",
        )
