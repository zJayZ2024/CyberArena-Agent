from __future__ import annotations

import copy
import random
from typing import Any

from backend_engine.agents.referee_agent import RefereeAgent
from backend_engine.core.models import ActionLog, AgentDecision, SecurityAlert, VulnerabilityInfo, WorldState
from backend_engine.core.scoring import ROUND_SCORE_BUDGET, apply_round_scores, recalculate_scores
from backend_engine.engine.actions import ACTION_REGISTRY, ActionContext, ActionResult, PERIMETER_KEYWORDS

RED_ATTACK_ACTIONS = {"ExploitService", "LateralMove", "ExfiltrateDatabase", "ReactivateFoothold"}
RED_HIGH_IMPACT_ACTIONS = {"ExploitService", "LateralMove", "ExfiltrateDatabase", "ReactivateFoothold"}
PREVENTIVE_PATCH_INTERVAL = 2
PREVENTIVE_PATCH_NODE_COOLDOWN = 2
TIER0_PROACTIVE_LOCK_ROUNDS = 2
MONITOR_DISCOVERY_PER_TURN = 2


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
    def __init__(
        self,
        *,
        use_probability: bool = False,
        random_seed: int | None = None,
        recon_lookback_turns: int = 3,
    ) -> None:
        self.referee = RefereeAgent()
        self.use_probability = use_probability
        self._rng = random.Random(random_seed)
        self._recon_lookback_turns = max(1, recon_lookback_turns)
        self.blue_previous_state_snapshot: WorldState | None = None
        self.blue_previous_alerts: list[SecurityAlert] = []
        self.red_recon_history: dict[str, list[int]] = {}
        self.score_repeat_tracker: dict[str, dict[str, Any]] = {
            "Red": {"action_type": None, "target": None, "streak": 0},
            "Blue": {"action_type": None, "target": None, "streak": 0},
        }

    def prepare_state(self, state: WorldState) -> WorldState:
        if not state.core_assets:
            state.core_assets = ["db"]
        state.red_anchored_nodes = [node for node in state.red_anchored_nodes if node in state.network_nodes]
        if not isinstance(state.blue_known_vulnerabilities, dict):
            state.blue_known_vulnerabilities = {}
        if not isinstance(state.blue_monitored_nodes, list):
            state.blue_monitored_nodes = []
        if not isinstance(state.blue_preventive_patch_cooldowns, dict):
            state.blue_preventive_patch_cooldowns = {}
        if not isinstance(state.winner_locked, bool):
            state.winner_locked = False

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
        self._update_blue_intel_from_red(next_state, red, red_result)
        self._record_red_recon(next_state, red, red_result)
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
        red_result, blue_result, interaction_meta = self._apply_same_turn_interaction(
            next_state,
            red=red,
            red_result=red_result,
            blue=blue,
            blue_result=blue_result,
        )
        self._apply_blue_post_action_updates(next_state, blue, blue_result)
        self._synchronize_known_vulnerability_maps(next_state)
        self._update_winner_lock(next_state)
        next_state.security_alerts = self._build_security_alerts(next_state, red, red_result)
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
                    "interaction": interaction_meta,
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

        policy_error = self._apply_runtime_policy(state, decision, locale=locale)
        if policy_error is not None:
            metadata = dict(policy_error.metadata)
            metadata.update({"score_awarded": 0, "llm_score_suggest": 0, "validation": "failed"})
            return ActionResult(
                success=False,
                effect=policy_error.effect,
                message=policy_error.message,
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

        probability_gate = self._evaluate_probability_gate(state, decision)
        if probability_gate is not None and not probability_gate["passed"]:
            return ActionResult(
                success=False,
                effect="failed",
                message=(
                    f"动作因概率门控失败：{probability_gate['probability']:.2f} 未命中。"
                    if locale == "zh"
                    else f"Action failed probability gate: probability={probability_gate['probability']:.2f}."
                ),
                metadata={
                    "action_type": decision.action_type,
                    "agent_type": decision.agent_type,
                    "target": decision.target,
                    "vuln_id": decision.vuln_id,
                    "score_awarded": 0,
                    "llm_score_suggest": max(0, int(judgement.llm_score_suggest)),
                    "referee_effect": "probability_failed",
                    "referee_rationale": judgement.rationale,
                    "validation": "passed",
                    "probability_gate": probability_gate,
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
        if probability_gate is not None:
            metadata["probability_gate"] = probability_gate
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

    def _evaluate_probability_gate(
        self,
        state: WorldState,
        decision: AgentDecision,
    ) -> dict[str, Any] | None:
        if not self.use_probability:
            return None
        target = decision.target
        vuln_id = decision.vuln_id
        if not target or not vuln_id:
            return None
        node = state.network_nodes.get(target)
        if node is None:
            return None
        vulnerability = node.vulnerabilities.get(vuln_id)
        if vulnerability is None:
            return None

        probability: float | None = None
        reason = ""
        if decision.action_type in RED_ATTACK_ACTIONS:
            probability = float(vulnerability.exploit_prob)
            reason = "exploit_prob"
        elif decision.action_type == "PatchNode":
            probability = float(vulnerability.patch_prob)
            reason = "patch_prob"
        if probability is None:
            return None

        roll = self._rng.random()
        return {
            "used": True,
            "probability": max(0.0, min(1.0, probability)),
            "roll": round(roll, 6),
            "passed": roll <= probability,
            "reason": reason,
        }

    def _apply_runtime_policy(
        self,
        state: WorldState,
        decision: AgentDecision,
        *,
        locale: str = "zh",
    ) -> ActionResult | None:
        if decision.action_type != "PreventivePatch":
            return None
        target = decision.target
        if not target:
            return None

        active_crit = any(alert.severity == "CRIT" for alert in state.security_alerts)
        if active_crit:
            return ActionResult(
                success=False,
                effect="failed",
                message=(
                    "当前存在 CRIT 活跃威胁，禁止执行预防性修补。"
                    if locale == "zh"
                    else "PreventivePatch blocked: active CRIT threat exists."
                ),
                metadata={
                    "action_type": decision.action_type,
                    "agent_type": decision.agent_type,
                    "target": decision.target,
                    "vuln_id": decision.vuln_id,
                    "policy_block": "preventive_patch_blocked_by_crit",
                },
            )

        if state.turn - int(state.blue_last_preventive_patch_turn) < PREVENTIVE_PATCH_INTERVAL:
            return ActionResult(
                success=False,
                effect="failed",
                message=(
                    "预防性修补触发回合节流：每 2 回合最多 1 次。"
                    if locale == "zh"
                    else "PreventivePatch throttled: at most once every 2 turns."
                ),
                metadata={
                    "action_type": decision.action_type,
                    "agent_type": decision.agent_type,
                    "target": decision.target,
                    "vuln_id": decision.vuln_id,
                    "policy_block": "preventive_patch_interval_limit",
                },
            )

        available_turn = int(state.blue_preventive_patch_cooldowns.get(target, -999))
        if state.turn < available_turn:
            return ActionResult(
                success=False,
                effect="failed",
                message=(
                    f"{target} 节点仍在预防性修补冷却期内。"
                    if locale == "zh"
                    else f"{target} is still in preventive patch cooldown."
                ),
                metadata={
                    "action_type": decision.action_type,
                    "agent_type": decision.agent_type,
                    "target": decision.target,
                    "vuln_id": decision.vuln_id,
                    "policy_block": "preventive_patch_node_cooldown",
                },
            )

        if state.turn <= TIER0_PROACTIVE_LOCK_ROUNDS and target in state.core_assets:
            has_evidence = self._has_core_risk_evidence(state, target)
            if not has_evidence:
                return ActionResult(
                    success=False,
                    effect="failed",
                    message=(
                        "开局前 2 回合禁止无证据对核心资产执行预防性修补。"
                        if locale == "zh"
                        else "Tier-0 preventive patch blocked in opening rounds without evidence."
                    ),
                    metadata={
                        "action_type": decision.action_type,
                        "agent_type": decision.agent_type,
                        "target": decision.target,
                        "vuln_id": decision.vuln_id,
                        "policy_block": "tier0_opening_lock",
                    },
                )
        return None

    def _has_core_risk_evidence(self, state: WorldState, target: str) -> bool:
        if target in state.red_recon_nodes:
            return True
        recent_recon_turns = self.red_recon_history.get(target, [])
        if any(0 <= state.turn - turn <= self._recon_lookback_turns for turn in recent_recon_turns):
            return True
        return any(alert.target == target for alert in state.security_alerts)

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

    def _update_blue_intel_from_red(self, state: WorldState, red: AgentDecision, red_result: ActionResult) -> None:
        target = red.target
        if not target or target not in state.network_nodes:
            return
        vuln_id = self._extract_vuln_id(red, red_result)
        if vuln_id:
            confidence = 1.0 if red_result.success else 0.8
            self._confirm_blue_vulnerability(state, target=target, vuln_id=vuln_id, confidence=confidence)

    def _apply_blue_post_action_updates(
        self,
        state: WorldState,
        blue: AgentDecision,
        blue_result: ActionResult,
    ) -> None:
        if not blue_result.success:
            if blue.action_type == "Monitor":
                blue_result.metadata["intel_gain"] = False
            return

        if blue.action_type == "Monitor":
            self._apply_monitor_discovery(state, blue, blue_result)
            return

        if blue.action_type in {"PatchNode", "PreventivePatch"}:
            target = blue.target or str(blue_result.metadata.get("target") or "")
            vuln_id = self._extract_vuln_id(blue, blue_result)
            if target and vuln_id:
                self._confirm_blue_vulnerability(state, target=target, vuln_id=vuln_id, confidence=1.0)
            if blue.action_type == "PreventivePatch" and target:
                state.blue_last_preventive_patch_turn = int(state.turn)
                state.blue_preventive_patch_cooldowns[target] = int(state.turn + PREVENTIVE_PATCH_NODE_COOLDOWN)
            return

        if blue.action_type == "DeepRestore":
            target = blue.target or str(blue_result.metadata.get("target") or "")
            removed_vulns = blue_result.metadata.get("removed_vulnerabilities", [])
            if target and isinstance(removed_vulns, list):
                for row in removed_vulns:
                    if not isinstance(row, dict):
                        continue
                    vuln_id = str(row.get("vuln_id", "")).strip()
                    if vuln_id:
                        self._confirm_blue_vulnerability(state, target=target, vuln_id=vuln_id, confidence=1.0)

    def _apply_monitor_discovery(self, state: WorldState, blue: AgentDecision, blue_result: ActionResult) -> None:
        scope = blue.target or "network"
        if scope in {"network", "all"}:
            candidate_nodes = list(state.network_nodes.keys())
        elif scope in state.network_nodes:
            candidate_nodes = [scope]
        else:
            candidate_nodes = []

        for node_name in candidate_nodes:
            _append_unique(state.blue_monitored_nodes, node_name)

        discoveries: list[tuple[int, str, str]] = []
        for node_name in candidate_nodes:
            node = state.network_nodes[node_name]
            known_map = state.blue_known_vulnerabilities.get(node_name, {})
            if not isinstance(known_map, dict):
                known_map = {}
            for vuln_id, vuln in node.vulnerabilities.items():
                if vuln_id in known_map:
                    continue
                discoveries.append((int(vuln.score), node_name, vuln_id))

        discoveries.sort(reverse=True)
        selected = discoveries[:MONITOR_DISCOVERY_PER_TURN]
        for _, node_name, vuln_id in selected:
            self._confirm_blue_vulnerability(state, target=node_name, vuln_id=vuln_id, confidence=0.7)

        intel_rows = [{"target": node_name, "vuln_id": vuln_id} for _, node_name, vuln_id in selected]
        blue_result.metadata.update(
            {
                "intel_gain": bool(selected),
                "intel_new_vulnerabilities": intel_rows,
                "monitor_scope": scope,
            }
        )

    def _confirm_blue_vulnerability(
        self,
        state: WorldState,
        *,
        target: str,
        vuln_id: str,
        confidence: float,
    ) -> None:
        if target not in state.network_nodes:
            return
        node = state.network_nodes[target]
        if vuln_id not in node.vulnerabilities:
            return
        confidence = max(0.0, min(1.0, float(confidence)))
        node_map = state.blue_known_vulnerabilities.setdefault(target, {})
        existing = float(node_map.get(vuln_id, 0.0))
        node_map[vuln_id] = max(existing, confidence)

    def _update_winner_lock(self, state: WorldState) -> None:
        if state.winner_locked:
            return
        core_assets = [node_name for node_name in state.core_assets if node_name in state.network_nodes] or ["db"]
        for node_name in core_assets:
            node = state.network_nodes.get(node_name)
            if node is not None and node.status == "Compromised":
                state.winner_locked = True
                state.winner_side = "Red"
                state.winner_reason = f"Red controlled core asset: {node_name}"
                return

    def _synchronize_known_vulnerability_maps(self, state: WorldState) -> None:
        for node_name in list(state.red_known_vulnerabilities.keys()):
            node = state.network_nodes.get(node_name)
            if node is None:
                state.red_known_vulnerabilities.pop(node_name, None)
                continue
            known_map = state.red_known_vulnerabilities.get(node_name, {})
            if not isinstance(known_map, dict):
                state.red_known_vulnerabilities.pop(node_name, None)
                continue
            for vuln_id in list(known_map.keys()):
                if vuln_id not in node.vulnerabilities:
                    known_map.pop(vuln_id, None)
            if not known_map:
                state.red_known_vulnerabilities.pop(node_name, None)

        for node_name in list(state.blue_known_vulnerabilities.keys()):
            node = state.network_nodes.get(node_name)
            if node is None:
                state.blue_known_vulnerabilities.pop(node_name, None)
                continue
            known_map = state.blue_known_vulnerabilities.get(node_name, {})
            if not isinstance(known_map, dict):
                state.blue_known_vulnerabilities.pop(node_name, None)
                continue
            for vuln_id in list(known_map.keys()):
                if vuln_id not in node.vulnerabilities:
                    known_map.pop(vuln_id, None)
            if not known_map:
                state.blue_known_vulnerabilities.pop(node_name, None)

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

    def _record_red_recon(self, state: WorldState, red: AgentDecision, red_result: ActionResult) -> None:
        if red.action_type != "Recon" or not red_result.success:
            return
        target = red.target
        if not target:
            return
        turns = self.red_recon_history.setdefault(target, [])
        turns.append(int(state.turn))
        self.red_recon_history[target] = sorted(set(turns))[-20:]

    def _apply_same_turn_interaction(
        self,
        state: WorldState,
        *,
        red: AgentDecision,
        red_result: ActionResult,
        blue: AgentDecision,
        blue_result: ActionResult,
    ) -> tuple[ActionResult, ActionResult, dict[str, Any]]:
        interaction_meta: dict[str, Any] = {
            "type": "independent",
            "perfect_intercept": False,
            "proactive_patch": False,
        }
        if self._is_perfect_intercept(red, red_result, blue, blue_result):
            self._rollback_red_attack_effect(state, red_result)
            red_result.success = False
            red_result.effect = "blocked"
            red_result.message = (
                "同回合完美拦截：蓝方修补命中同目标同漏洞，红方攻击被即时打断。"
            )
            red_result.metadata.update(
                {
                    "execution": "intercepted",
                    "referee_effect": "blocked",
                    "intercepted_by": blue.action_type,
                    "score_awarded": 0,
                }
            )
            base_value = int(blue_result.metadata.get("score_value", 0) or 0)
            boosted = int(round(base_value * 1.5))
            blue_result.metadata.update(
                {
                    "interaction_bonus": "perfect_intercept",
                    "score_multiplier": 1.5,
                    "score_multiplier_reason": "same_round_patch_intercept",
                    "score_budget_override": max(ROUND_SCORE_BUDGET, boosted),
                }
            )
            interaction_meta.update(
                {
                    "type": "perfect_intercept",
                    "perfect_intercept": True,
                    "target": blue.target,
                    "vuln_id": blue.vuln_id,
                    "intercept_by": blue.action_type,
                }
            )
            return red_result, blue_result, interaction_meta

        if (
            red.action_type in RED_ATTACK_ACTIONS
            and blue.action_type in {"PatchNode", "PreventivePatch"}
            and red.target
            and blue.target
            and red.target == blue.target
            and red_result.success
            and blue_result.success
        ):
            red_vuln_id = red.vuln_id or str(red_result.metadata.get("vuln_id", ""))
            blue_vuln_id = blue.vuln_id or str(blue_result.metadata.get("vuln_id", ""))
            if red_vuln_id and blue_vuln_id and red_vuln_id != blue_vuln_id:
                interaction_meta.update(
                    {
                        "type": "bypass",
                        "bypass_reason": "same_target_different_vulnerability",
                        "target": red.target,
                        "red_vuln_id": red_vuln_id,
                        "blue_vuln_id": blue_vuln_id,
                    }
                )

        if self._is_proactive_patch(state, red, blue, blue_result):
            blue_result.metadata.update(
                {
                    "interaction_bonus": "proactive_patch",
                    "score_multiplier": 0.5,
                    "score_multiplier_reason": "recent_red_recon_on_target",
                }
            )
            interaction_meta.update(
                {
                    "type": "proactive_patch",
                    "proactive_patch": True,
                    "target": blue.target,
                    "vuln_id": blue.vuln_id,
                }
            )

        return red_result, blue_result, interaction_meta

    def _is_perfect_intercept(
        self,
        red: AgentDecision,
        red_result: ActionResult,
        blue: AgentDecision,
        blue_result: ActionResult,
    ) -> bool:
        if not (red_result.success and blue_result.success):
            return False
        if blue.action_type not in {"PatchNode", "PreventivePatch"}:
            return False
        if red.action_type not in RED_ATTACK_ACTIONS:
            return False
        if not red.target or not blue.target or red.target != blue.target:
            return False
        red_vuln_id = red.vuln_id or str(red_result.metadata.get("vuln_id", ""))
        blue_vuln_id = blue.vuln_id or str(blue_result.metadata.get("vuln_id", ""))
        if not red_vuln_id or not blue_vuln_id:
            return False
        return red_vuln_id == blue_vuln_id

    def _is_proactive_patch(
        self,
        state: WorldState,
        red: AgentDecision,
        blue: AgentDecision,
        blue_result: ActionResult,
    ) -> bool:
        if blue.action_type != "PatchNode" or not blue_result.success:
            return False
        if not blue.target:
            return False
        if red.action_type in RED_ATTACK_ACTIONS and red.target == blue.target:
            return False
        turns = self.red_recon_history.get(blue.target, [])
        if not turns:
            return False
        current_turn = int(state.turn)
        return any(0 < current_turn - turn <= self._recon_lookback_turns for turn in turns)

    def _rollback_red_attack_effect(self, state: WorldState, red_result: ActionResult) -> None:
        metadata = red_result.metadata if isinstance(red_result.metadata, dict) else {}
        target = metadata.get("target")
        previous_status = metadata.get("previous_status")
        if not isinstance(target, str) or target not in state.network_nodes:
            return
        if not isinstance(previous_status, str):
            return
        state.network_nodes[target].status = previous_status

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
