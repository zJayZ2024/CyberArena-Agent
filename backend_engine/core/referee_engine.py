from __future__ import annotations

import copy
from typing import Any

from backend_engine.agents.referee_agent import RefereeAgent
from backend_engine.core.models import ActionLog, AgentDecision, SecurityAlert, VulnerabilityInfo, WorldState
from backend_engine.core.scoring import apply_round_scores, recalculate_scores
from backend_engine.engine.actions import ACTION_REGISTRY, ActionContext, ActionResult, PERIMETER_KEYWORDS


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


def _coerce_vulnerability_snapshot(payload: dict[str, object]) -> dict[str, VulnerabilityInfo]:
    snapshot: dict[str, VulnerabilityInfo] = {}
    for vuln_id, value in payload.items():
        if isinstance(value, VulnerabilityInfo):
            snapshot[vuln_id] = value
        else:
            snapshot[vuln_id] = VulnerabilityInfo.model_validate(value)
    return snapshot


class RefereeEngine:
    def __init__(self) -> None:
        self.referee = RefereeAgent()
        self.blue_previous_state_snapshot: WorldState | None = None
        self.blue_previous_alerts: list[SecurityAlert] = []
        self.score_repeat_tracker: dict[str, dict[str, Any]] = {
            "Red": {"action_type": None, "target": None, "streak": 0},
            "Blue": {"action_type": None, "target": None, "streak": 0},
        }

    def prepare_state(self, state: WorldState) -> WorldState:
        self._ensure_initial_red_visibility(state)
        if self.blue_previous_state_snapshot is None:
            self.blue_previous_state_snapshot = copy.deepcopy(state)
            self.blue_previous_alerts = copy.deepcopy(state.security_alerts)
        return state

    def get_blue_perceived_state(self) -> WorldState:
        if self.blue_previous_state_snapshot is None:
            raise RuntimeError("blue_previous_state_snapshot 尚未初始化。")
        return copy.deepcopy(self.blue_previous_state_snapshot)

    def get_blue_recent_alerts(self) -> list[SecurityAlert]:
        return copy.deepcopy(self.blue_previous_alerts)

    def resolve_red_phase(self, state: WorldState, red: AgentDecision) -> tuple[WorldState, ActionResult, list[SecurityAlert]]:
        next_state = state.model_copy(deep=True)
        self.prepare_state(next_state)
        visible_alerts = self.get_blue_recent_alerts()

        next_state.turn += 1
        next_state.action_logs = []
        next_state.security_alerts = []

        red_result = self._adjudicate_action(
            next_state,
            red,
            locale="zh",
            opposing_decision=None,
        )
        self._purge_invalid_red_intel(next_state, red, red_result)
        self._update_red_perception(next_state, red, red_result)
        next_state.security_alerts = self._build_security_alerts(next_state, red, red_result)
        return next_state, red_result, visible_alerts

    def resolve_blue_phase(
        self,
        state: WorldState,
        blue: AgentDecision,
        *,
        opposing_decision: AgentDecision | None = None,
    ) -> tuple[WorldState, ActionResult]:
        next_state = state.model_copy(deep=True)
        self.prepare_state(next_state)
        blue_result = self._adjudicate_action(
            next_state,
            blue,
            locale="zh",
            opposing_decision=opposing_decision,
        )
        return next_state, blue_result

    def finalize_round(
        self,
        state: WorldState,
        red: AgentDecision,
        red_result: ActionResult,
        blue: AgentDecision,
    ) -> WorldState:
        next_state, blue_result = self.resolve_blue_phase(state, blue, opposing_decision=red)
        recalculate_scores(next_state)
        score_summary = apply_round_scores(
            next_state,
            red_decision=red,
            red_result=red_result,
            blue_decision=blue,
            blue_result=blue_result,
            repeat_tracker=self.score_repeat_tracker,
        )
        red_delta = int(score_summary["red_delta"])
        blue_delta = int(score_summary["blue_delta"])

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
                f"Red: {red_result.message}; Blue: {blue_result.message}",
                metadata={
                    "red_result": red_result.metadata,
                    "blue_result": blue_result.metadata,
                    "recent_alerts": [alert.model_dump(mode="json") for alert in next_state.security_alerts],
                    "score_summary": {
                        "red_delta": red_delta,
                        "blue_delta": blue_delta,
                        "red_score": next_state.red_score,
                        "blue_score": next_state.blue_score,
                        "red_breakdown": score_summary.get("red_breakdown", {}),
                        "blue_breakdown": score_summary.get("blue_breakdown", {}),
                    },
                },
            ),
        ]

        self.blue_previous_state_snapshot = copy.deepcopy(next_state)
        self.blue_previous_alerts = copy.deepcopy(next_state.security_alerts)
        return next_state

    def resolve_round(self, state: WorldState, red: AgentDecision, blue: AgentDecision) -> WorldState:
        interim_state, red_result, _ = self.resolve_red_phase(state, red)
        return self.finalize_round(interim_state, red, red_result, blue)

    def _adjudicate_action(
        self,
        state: WorldState,
        decision: AgentDecision,
        *,
        locale: str = "zh",
        opposing_decision: AgentDecision | None = None,
    ) -> ActionResult:
        action = ACTION_REGISTRY.get(decision.action_type)
        if action is None:
            return ActionResult(
                success=False,
                effect="rejected",
                message=f"非法动作：{decision.action_type}" if locale == "zh" else f"Illegal action: {decision.action_type}",
                metadata={
                    "action_type": decision.action_type,
                    "agent_type": decision.agent_type,
                    "target": decision.target,
                    "vuln_id": decision.vuln_id,
                    "score_awarded": 0,
                    "llm_score_suggest": 0,
                    "validation": "failed",
                },
            )

        context = ActionContext(
            state=state,
            decision=decision,
            locale="zh" if locale == "zh" else "en",
            opposing_decision=opposing_decision,
        )
        validation_error = action.validate(context)
        if validation_error is not None:
            metadata = dict(validation_error.metadata)
            metadata.update({"score_awarded": 0, "llm_score_suggest": 0, "validation": "failed"})
            return ActionResult(
                success=False,
                effect=validation_error.effect,
                message=validation_error.message,
                metadata=metadata,
            )

        descriptor = action.descriptor(locale="zh").as_dict()
        judgement = self.referee.judge_action(
            state,
            decision,
            action_descriptor=descriptor,
            validation_summary={
                "validated": True,
                "target": decision.target,
                "vuln_id": decision.vuln_id,
            },
        )

        if not judgement.is_success:
            return ActionResult(
                success=False,
                effect=judgement.effect or "failed",
                message=judgement.rationale,
                metadata={
                    "action_type": decision.action_type,
                    "agent_type": decision.agent_type,
                    "target": decision.target,
                    "vuln_id": decision.vuln_id,
                    "score_awarded": 0,
                    "llm_score_suggest": max(0, int(judgement.llm_score_suggest)),
                    "referee_effect": judgement.effect,
                    "referee_rationale": judgement.rationale,
                    "validation": "passed",
                },
            )

        execute_result = action.execute(context)
        if not execute_result.success:
            metadata = dict(execute_result.metadata)
            metadata.update(
                {
                    "score_awarded": 0,
                    "llm_score_suggest": max(0, int(judgement.llm_score_suggest)),
                    "execution": "failed_after_judgement",
                }
            )
            return ActionResult(
                success=False,
                effect=execute_result.effect,
                message=execute_result.message,
                metadata=metadata,
            )

        metadata = dict(execute_result.metadata)
        metadata.update(
            {
                "score_awarded": 0,
                "llm_score_suggest": max(0, int(judgement.llm_score_suggest)),
                "referee_effect": judgement.effect,
                "referee_rationale": judgement.rationale,
                "validation": "passed",
            }
        )
        return ActionResult(
            success=True,
            effect=judgement.effect or execute_result.effect,
            message=judgement.rationale,
            metadata=metadata,
        )

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
            was_recon_before = target in state.red_recon_nodes
            known_services_before = set(state.red_known_services.get(target, []))
            known_vulnerabilities_before = set(state.red_known_vulnerabilities.get(target, {}).keys())
            _append_unique(state.red_recon_nodes, target)
            observed_ports = red_result.metadata.get("observed_ports", [])
            if observed_ports:
                state.red_known_services[target] = list(observed_ports)
            suspected_vulnerabilities = red_result.metadata.get("suspected_vulnerabilities", {})
            if suspected_vulnerabilities:
                state.red_known_vulnerabilities[target] = _coerce_vulnerability_snapshot(suspected_vulnerabilities)
            observed_ports_set = set(observed_ports)
            observed_vulnerabilities_set = set(suspected_vulnerabilities.keys())
            intel_gain = bool(
                observed_ports_set - known_services_before
                or observed_vulnerabilities_set - known_vulnerabilities_before
                or not was_recon_before
            )
            red_result.metadata.update(
                {
                    "intel_gain": intel_gain,
                    "intel_new_ports": sorted(observed_ports_set - known_services_before),
                    "intel_new_vulnerabilities": sorted(observed_vulnerabilities_set - known_vulnerabilities_before),
                }
            )

        target_node = state.network_nodes[target]
        if target_node.status == "Compromised":
            _append_unique(state.red_visible_nodes, target)
            state.red_known_services[target] = list(target_node.exposed_ports)
            state.red_known_vulnerabilities[target] = dict(target_node.vulnerabilities)
            self._expand_visibility_from_compromise(state, target)

    def _expand_visibility_from_compromise(self, state: WorldState, compromised_node: str) -> None:
        adjacency = _build_adjacency_map(state)
        for neighbor in adjacency.get(compromised_node, []):
            _append_unique(state.red_visible_nodes, neighbor)

    def _extract_vuln_id(self, decision: AgentDecision, result: ActionResult | None = None) -> str | None:
        if decision.vuln_id:
            return decision.vuln_id
        if result is not None:
            vuln_id = result.metadata.get("vuln_id")
            if isinstance(vuln_id, str) and vuln_id:
                return vuln_id
        return None

    def _purge_invalid_red_intel(
        self,
        state: WorldState,
        red: AgentDecision,
        red_result: ActionResult,
    ) -> None:
        if red.action_type not in {"ExploitService", "LateralMove"}:
            return

        target = red.target
        if not target:
            return

        vuln_id = self._extract_vuln_id(red, red_result)
        if not vuln_id:
            return

        if not self._should_invalidate_red_vuln_intel(red_result):
            return

        known_vulnerabilities = state.red_known_vulnerabilities.get(target)
        if not known_vulnerabilities or vuln_id not in known_vulnerabilities:
            return

        known_vulnerabilities.pop(vuln_id, None)
        if not known_vulnerabilities:
            state.red_known_vulnerabilities.pop(target, None)

    def _should_invalidate_red_vuln_intel(self, red_result: ActionResult) -> bool:
        if red_result.success:
            return False
        if red_result.effect not in {"failed", "rejected"}:
            return False

        reason = red_result.message.lower()
        invalidation_signals = (
            "不存在于目标节点",
            "不存在该漏洞",
            "目标当前没有可操作的剩余漏洞",
            "节点已被防御加固",
            "已被防御加固",
            "does not exist on the target",
            "no remaining vulnerabilities",
            "already hardened",
            "hardened",
            "patched",
        )
        return any(signal in reason for signal in invalidation_signals)

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
                    message=f"[WARN] {target or 'unknown'} 节点出现侦察痕迹。",
                    target=target,
                    source_action=red.action_type,
                    metadata=red_result.metadata,
                )
            ]

        severity = "CRIT" if red_result.success and red_result.effect in {"compromise", "exfiltration"} else "WARN"
        vuln_id = self._extract_vuln_id(red, red_result)
        return [
            SecurityAlert(
                severity=severity,
                message=(
                    f"[{severity}] {target or 'unknown'} 节点遭到 {red.action_type} 攻击，"
                    f"vuln_id={vuln_id or 'unknown'}，当前状态为 {target_status}。"
                ),
                target=target,
                source_action=red.action_type,
                metadata=red_result.metadata,
            )
        ]
