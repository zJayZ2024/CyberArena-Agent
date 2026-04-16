from backend_engine.agents.referee_agent_zh import RefereeAgent
from backend_engine.core.models import ActionLog, AgentDecision, WorldState
from backend_engine.core.scoring import apply_round_scores, recalculate_scores
from backend_engine.engine.actions import ACTION_REGISTRY


class RefereeEngine:
    def __init__(self) -> None:
        self.referee = RefereeAgent()

    def resolve_round(self, state: WorldState, red: AgentDecision, blue: AgentDecision) -> WorldState:
        next_state = state.model_copy(deep=True)
        next_state.turn += 1
        next_state.action_logs = []

        red_result = ACTION_REGISTRY.resolve(
            next_state,
            red,
            locale="zh",
            opposing_decision=blue,
        )
        blue_result = ACTION_REGISTRY.resolve(
            next_state,
            blue,
            locale="zh",
            opposing_decision=red,
        )
        score_summary = apply_round_scores(next_state, red_result, blue_result)
        recalculate_scores(next_state)

        next_state.action_logs.append(
            ActionLog(
                agent_type="Red",
                thought=red.thought,
                action_type=red.action_type,
                payload=red.payload,
                referee_result=red_result.message,
            )
        )
        next_state.action_logs.append(
            ActionLog(
                agent_type="Blue",
                thought=blue.thought,
                action_type=blue.action_type,
                payload=blue.payload,
                referee_result=blue_result.message,
            )
        )
        next_state.action_logs.append(
            self.referee.log_resolution(
                red,
                blue,
                f"\u7ea2\u65b9\uff1a{red_result.message}\uff1b\u84dd\u65b9\uff1a{blue_result.message}",
                metadata={"score_summary": score_summary},
            )
        )

        return next_state

    def _apply_blue(self, state: WorldState, decision: AgentDecision) -> str:
        if not decision.target or decision.target not in state.network_nodes:
            return "\u84dd\u65b9\u672a\u9009\u62e9\u6709\u6548\u76ee\u6807"

        node = state.network_nodes[decision.target]

        if decision.action_type == "RestoreNode":
            node.status = "Defended"
            if node.vulnerabilities:
                node.vulnerabilities = node.vulnerabilities[1:]
            return f"{decision.target} \u5df2\u6062\u590d\u5e76\u8fdb\u5165\u9632\u5fa1\u6001"

        if decision.action_type == "PatchNode":
            node.status = "Defended"
            if node.vulnerabilities:
                node.vulnerabilities = node.vulnerabilities[1:]
            return f"{decision.target} \u5df2\u5b8c\u6210\u8865\u4e01\u4fee\u590d\u5e76\u5f97\u5230\u52a0\u56fa"

        return "\u84dd\u65b9\u6267\u884c\u76d1\u63a7\uff0c\u672c\u56de\u5408\u672a\u6539\u53d8\u62d3\u6251\u72b6\u6001"

    def _apply_red(self, state: WorldState, decision: AgentDecision) -> str:
        if not decision.target or decision.target not in state.network_nodes:
            return "\u7ea2\u65b9\u672a\u9009\u62e9\u6709\u6548\u76ee\u6807"

        node = state.network_nodes[decision.target]

        if decision.action_type == "Recon":
            return f"\u5df2\u5bf9 {decision.target} \u5b8c\u6210\u4fa6\u5bdf\uff0c\u4f46\u672a\u76f4\u63a5\u9020\u6210\u72b6\u6001\u53d8\u5316"

        if node.status == "Defended":
            return f"\u9488\u5bf9 {decision.target} \u7684\u653b\u51fb\u88ab\u73b0\u6709\u9632\u5fa1\u6210\u529f\u62e6\u622a"

        if node.vulnerabilities:
            node.status = "Compromised"
            return f"{decision.target} \u5df2\u88ab\u6210\u529f\u653b\u7834"

        return f"{decision.target} \u5df2\u4e0d\u5b58\u5728\u53ef\u76f4\u63a5\u5229\u7528\u7684\u5f31\u70b9"
