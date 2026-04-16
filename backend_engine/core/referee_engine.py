from __future__ import annotations

from backend_engine.agents.referee_agent import RefereeAgent
from backend_engine.core.models import ActionLog, AgentDecision, SecurityAlert, WorldState
from backend_engine.core.scoring import apply_round_scores, recalculate_scores
from backend_engine.engine.actions import ACTION_REGISTRY, ActionResult, PERIMETER_KEYWORDS


def _is_perimeter_node(node_name: str) -> bool:
    lowered = node_name.lower()
    return lowered == "internet" or any(keyword in lowered for keyword in PERIMETER_KEYWORDS)


def _append_unique(items: list[str], value: str) -> None:
    if value not in items:
        items.append(value)


def _build_adjacency_map(state: WorldState) -> dict[str, list[str]]:
    adjacency: dict[str, list[str]] = {node_name: [] for node_name in state.network_nodes}

    for edge in state.edges:
        if edge.source not in state.network_nodes or edge.target not in state.network_nodes:
            continue
        if edge.target not in adjacency[edge.source]:
            adjacency[edge.source].append(edge.target)
        if edge.source not in adjacency[edge.target]:
            adjacency[edge.target].append(edge.source)

    return adjacency


class RefereeEngine:
    def __init__(self) -> None:
        self.referee = RefereeAgent()

    def prepare_state(self, state: WorldState) -> WorldState:
        self._ensure_initial_red_visibility(state)
        return state

    def resolve_red_phase(self, state: WorldState, red: AgentDecision) -> tuple[WorldState, ActionResult, list[SecurityAlert]]:
        next_state = state.model_copy(deep=True)
        self.prepare_state(next_state)

        next_state.turn += 1
        next_state.action_logs = []
        next_state.security_alerts = []

        red_result = ACTION_REGISTRY.resolve(
            next_state,
            red,
            locale="zh",
            opposing_decision=None,
        )

        self._update_red_perception(next_state, red, red_result)
        recent_alerts = self._build_security_alerts(next_state, red, red_result)
        next_state.security_alerts = recent_alerts

        return next_state, red_result, recent_alerts

    def finalize_round(
        self,
        state: WorldState,
        red: AgentDecision,
        red_result: ActionResult,
        blue: AgentDecision,
    ) -> WorldState:
        next_state = state.model_copy(deep=True)
        self.prepare_state(next_state)

        blue_result = ACTION_REGISTRY.resolve(
            next_state,
            blue,
            locale="zh",
            opposing_decision=red,
        )
        score_summary = apply_round_scores(next_state, red_result, blue_result)
        recalculate_scores(next_state)

        next_state.action_logs = [
            ActionLog(
                agent_type="Red",
                thought=red.thought,
                action_type=red.action_type,
                payload=red.payload,
                referee_result=red_result.message,
                metadata=red_result.metadata,
            ),
            ActionLog(
                agent_type="Blue",
                thought=blue.thought,
                action_type=blue.action_type,
                payload=blue.payload,
                referee_result=blue_result.message,
                metadata=blue_result.metadata,
            ),
            self.referee.log_resolution(
                red,
                blue,
                f"红方：{red_result.message}；蓝方：{blue_result.message}",
                metadata={
                    "red_result": red_result.metadata,
                    "blue_result": blue_result.metadata,
                    "recent_alerts": [alert.model_dump(mode="json") for alert in next_state.security_alerts],
                    "score_summary": score_summary,
                },
            ),
        ]

        return next_state

    def resolve_round(self, state: WorldState, red: AgentDecision, blue: AgentDecision) -> WorldState:
        interim_state, red_result, _ = self.resolve_red_phase(state, red)
        return self.finalize_round(interim_state, red, red_result, blue)

    def _ensure_initial_red_visibility(self, state: WorldState) -> None:
        if state.red_visible_nodes:
            return

        for node_name, node in state.network_nodes.items():
            if not _is_perimeter_node(node_name):
                continue

            _append_unique(state.red_visible_nodes, node_name)
            if node.exposed_ports:
                state.red_known_services[node_name] = list(node.exposed_ports)

    def _update_red_perception(self, state: WorldState, red: AgentDecision, red_result: ActionResult) -> None:
        target = red.target
        if not target or target not in state.network_nodes:
            return

        _append_unique(state.red_visible_nodes, target)

        if red.action_type == "Recon" and red_result.success:
            _append_unique(state.red_recon_nodes, target)

            observed_ports = red_result.metadata.get("observed_ports", [])
            if observed_ports:
                state.red_known_services[target] = list(observed_ports)

            suspected_vulnerabilities = red_result.metadata.get("suspected_vulnerabilities", [])
            if suspected_vulnerabilities:
                state.red_known_vulnerabilities[target] = list(suspected_vulnerabilities)

        target_node = state.network_nodes[target]
        if target_node.status == "Compromised":
            _append_unique(state.red_visible_nodes, target)
            state.red_known_services[target] = list(target_node.exposed_ports)
            state.red_known_vulnerabilities[target] = list(target_node.vulnerabilities)
            self._expand_visibility_from_compromise(state, target)

    def _expand_visibility_from_compromise(self, state: WorldState, compromised_node: str) -> None:
        adjacency = _build_adjacency_map(state)
        for neighbor in adjacency.get(compromised_node, []):
            _append_unique(state.red_visible_nodes, neighbor)

    def _build_security_alerts(
        self,
        state: WorldState,
        red: AgentDecision,
        red_result: ActionResult,
    ) -> list[SecurityAlert]:
        target = red.target
        if target and target in state.network_nodes:
            target_status = state.network_nodes[target].status
        else:
            target_status = "Unknown"

        if red.action_type == "Recon":
            return [
                SecurityAlert(
                    severity="WARN",
                    message=f"[告警] {target or '未知目标'} 节点出现侦察扫描痕迹。",
                    target=target,
                    source_action=red.action_type,
                    metadata=red_result.metadata,
                )
            ]

        severity = "CRIT" if red_result.effect in {"compromise", "exfiltration"} else "WARN"
        return [
            SecurityAlert(
                severity=severity,
                message=f"[{severity}] {target or '未知目标'} 节点遭到 {red.action_type} 攻击，当前状态为 {target_status}。",
                target=target,
                source_action=red.action_type,
                metadata=red_result.metadata,
            )
        ]
