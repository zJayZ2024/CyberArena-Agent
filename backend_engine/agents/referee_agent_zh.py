from backend_engine.core.models import ActionLog, AgentDecision


class RefereeAgent:
    agent_name = "Referee"

    def log_resolution(self, red: AgentDecision, blue: AgentDecision, result: str) -> ActionLog:
        return ActionLog(
            agent_type="Referee",
            thought=(
                f"\u672c\u56de\u5408\u5df2\u5b8c\u6210\u88c1\u5b9a\uff1a"
                f"\u7ea2\u65b9\u52a8\u4f5c\u4e3a {red.action_type}\uff0c"
                f"\u84dd\u65b9\u52a8\u4f5c\u4e3a {blue.action_type}\u3002"
            ),
            action_type="ResolveRound",
            payload=f"{red.target or '\u65e0\u76ee\u6807'}|{blue.target or '\u65e0\u76ee\u6807'}",
            referee_result=result,
        )
