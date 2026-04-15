from backend_engine.core.models import ActionLog, AgentDecision


class RefereeAgent:
    agent_name = "Referee"

    def log_resolution(self, red: AgentDecision, blue: AgentDecision, result: str) -> ActionLog:
        return ActionLog(
            agent_type="Referee",
            thought=f"本回合已完成裁定：红方动作为 {red.action_type}，蓝方动作为 {blue.action_type}。",
            action_type="ResolveRound",
            payload=f"{red.target or '无目标'}|{blue.target or '无目标'}",
            referee_result=result,
        )
