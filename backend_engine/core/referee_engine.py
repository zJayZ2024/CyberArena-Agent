from backend_engine.agents.referee_agent import RefereeAgent
from backend_engine.core.models import ActionLog, AgentDecision, WorldState
from backend_engine.core.scoring import recalculate_scores
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
            locale="en",
            opposing_decision=blue,
        )
        blue_result = ACTION_REGISTRY.resolve(
            next_state,
            blue,
            locale="en",
            opposing_decision=red,
        )

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
                f"Red: {red_result.message}; Blue: {blue_result.message}",
            )
        )

        return recalculate_scores(next_state)

    def _apply_blue(self, state: WorldState, decision: AgentDecision) -> str:
        if not decision.target or decision.target not in state.network_nodes:
            return "蓝方未选择有效目标"

        node = state.network_nodes[decision.target]

        if decision.action_type == "RestoreNode":
            node.status = "Defended"
            if node.vulnerabilities:
                node.vulnerabilities = node.vulnerabilities[1:]
            return f"{decision.target} 已恢复并进入防御态"

        if decision.action_type == "PatchNode":
            node.status = "Defended"
            if node.vulnerabilities:
                node.vulnerabilities = node.vulnerabilities[1:]
            if node.exposed_ports:
                node.exposed_ports = node.exposed_ports[:-1]
            return f"{decision.target} 已完成补丁修复并得到加固"

        return "蓝方执行监控，本回合未改变拓扑状态"

    def _apply_red(self, state: WorldState, decision: AgentDecision) -> str:
        if not decision.target or decision.target not in state.network_nodes:
            return "红方未选择有效目标"

        node = state.network_nodes[decision.target]

        if decision.action_type == "Recon":
            return f"已对 {decision.target} 完成侦察，但未直接造成状态变化"

        if node.status == "Defended":
            return f"针对 {decision.target} 的攻击被现有防御成功拦截"

        if node.vulnerabilities:
            node.status = "Compromised"
            return f"{decision.target} 已被成功攻破"

        return f"{decision.target} 已不存在可直接利用的弱点"
