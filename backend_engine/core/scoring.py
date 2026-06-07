from __future__ import annotations

from typing import Any

from backend_engine.core.models import AgentDecision, WorldState
from backend_engine.engine.actions import ActionResult

# State-change scoring is the primary policy. Legacy action metadata is kept as
# a fallback for single-action evaluation paths that do not provide snapshots.
ROUND_SCORE_BUDGET = 60
BLUE_REMEDIATION_ACTIONS = {"PatchNode", "RestoreNode", "DeepRestore", "PreventivePatch"}
BLUE_REMEDIATION_BASE_SCALE = 0.8

RED_STATE_SCORE = {
    "recon_known": 2,
    "confirmed_service": 3,
    "confirmed_vulnerability": 5,
    "credential_known": 6,
    "session_active": 8,
    "foothold": 12,
    "persistence": 18,
    "compromised": 22,
    "core_compromised": 30,
    "exfiltration": 35,
}

BLUE_STATE_SCORE = {
    "discover_attack_path": 5,
    "monitor_hit": 8,
    "clear_session_active": 8,
    "clear_foothold": 12,
    "clear_persistence": 20,
    "patch_exploited_vulnerability": 14,
    "pivot_interrupt": 18,
    "isolate_exfil_path": 22,
    "restore_core_asset": 25,
}

# Same action on same target in consecutive rounds receives score decay.
REPEAT_DECAY_FACTORS = (1.0, 0.7, 0.4, 0.25)

# Optional fallback constants for remediation actions when score_value is unavailable.
DEFENSE_POLICY_CONSTANTS = {
    "PatchNode": 0,
    "PreventivePatch": 0,
    "RestoreNode": 0,
    "DeepRestore": 0,
    "Isolate": 0,
}


def _coerce_non_negative_int(value: Any, *, default: int = 0) -> int:
    if isinstance(value, bool):
        return default
    if isinstance(value, (int, float)):
        return max(0, int(value))
    return default


def _coerce_positive_float(value: Any, *, default: float = 1.0) -> float:
    if isinstance(value, bool):
        return default
    if isinstance(value, (int, float)):
        numeric = float(value)
        if numeric > 0:
            return numeric
    return default


def _normalize_target(target: str | None) -> str:
    return target or "__none__"


def _repeat_decay(streak: int) -> float:
    if streak <= 1:
        return REPEAT_DECAY_FACTORS[0]
    idx = min(streak - 1, len(REPEAT_DECAY_FACTORS) - 1)
    return REPEAT_DECAY_FACTORS[idx]


def _compute_legacy_base_score(decision: AgentDecision, result: ActionResult) -> tuple[int, str]:
    if not result.success:
        return 0, "failed_or_rejected"

    action_type = decision.action_type
    score_value = _coerce_non_negative_int(result.metadata.get("score_value", 0))
    if score_value > 0:
        operational_cost = _coerce_non_negative_int(result.metadata.get("operational_cost", 0))
        net_score = max(0, score_value - operational_cost)
        if decision.agent_type == "Blue" and decision.action_type in BLUE_REMEDIATION_ACTIONS:
            net_score = int(round(net_score * BLUE_REMEDIATION_BASE_SCALE))
        if operational_cost > 0:
            reason = "action_metadata.score_value_minus_operational_cost"
        else:
            reason = "action_metadata.score_value"
        if decision.agent_type == "Blue" and decision.action_type in BLUE_REMEDIATION_ACTIONS:
            reason = f"{reason}+blue_remediation_scaled"
        milestone_bonus = _coerce_non_negative_int(result.metadata.get("milestone_bonus", 0))
        if milestone_bonus > 0:
            net_score += milestone_bonus
            reason = f"{reason}+milestone_bonus"
        return net_score, reason

    if action_type in DEFENSE_POLICY_CONSTANTS:
        constant_score = _coerce_non_negative_int(DEFENSE_POLICY_CONSTANTS[action_type])
        reason = "defense_policy_constant"
        if decision.agent_type == "Blue" and decision.action_type in BLUE_REMEDIATION_ACTIONS:
            constant_score = int(round(constant_score * BLUE_REMEDIATION_BASE_SCALE))
            reason = f"{reason}+blue_remediation_scaled"
        milestone_bonus = _coerce_non_negative_int(result.metadata.get("milestone_bonus", 0))
        if milestone_bonus > 0:
            constant_score += milestone_bonus
            reason = f"{reason}+milestone_bonus"
        return constant_score, reason

    milestone_bonus = _coerce_non_negative_int(result.metadata.get("milestone_bonus", 0))
    if milestone_bonus > 0:
        return milestone_bonus, "milestone_bonus_only"
    return 0, "no_effective_score_source"


def _node_map(state: WorldState | None) -> dict[str, Any]:
    return state.network_nodes if state is not None else {}


def _vuln_ids(node: Any | None) -> set[str]:
    if node is None:
        return set()
    vulnerabilities = getattr(node, "vulnerabilities", {}) or {}
    return set(vulnerabilities.keys())


def _ports(node: Any | None) -> set[int]:
    if node is None:
        return set()
    return set(int(port) for port in getattr(node, "exposed_ports", []) or [])


def _core_assets(state: WorldState | None) -> set[str]:
    if state is None:
        return {"db"}
    return set(state.core_assets or ["db"])


def _red_state_change_score(
    previous_state: WorldState,
    current_state: WorldState,
    *,
    decision: AgentDecision,
    result: ActionResult,
) -> tuple[int, str, list[dict[str, Any]]]:
    prev_nodes = _node_map(previous_state)
    curr_nodes = _node_map(current_state)
    core_assets = _core_assets(current_state)
    events: list[dict[str, Any]] = []
    score = 0

    for node_name, current in curr_nodes.items():
        previous = prev_nodes.get(node_name)
        prev_red = getattr(previous, "red_state", None)
        curr_red = current.red_state

        if previous is not None and not getattr(prev_red, "recon_known", False) and curr_red.recon_known:
            score += RED_STATE_SCORE["recon_known"]
            events.append({"type": "recon_known", "node": node_name, "points": RED_STATE_SCORE["recon_known"]})

        new_ports = _ports(current) - _ports(previous)
        if new_ports and (node_name in current_state.red_visible_nodes or curr_red.recon_known):
            points = RED_STATE_SCORE["confirmed_service"] * len(new_ports)
            score += points
            events.append({"type": "confirmed_service", "node": node_name, "ports": sorted(new_ports), "points": points})

        new_vulns = _vuln_ids(current) - _vuln_ids(previous)
        known_vulns = set((current_state.red_known_vulnerabilities.get(node_name, {}) or {}).keys())
        visible_new_vulns = new_vulns & known_vulns if known_vulns else set()
        if visible_new_vulns:
            points = RED_STATE_SCORE["confirmed_vulnerability"] * len(visible_new_vulns)
            score += points
            events.append({"type": "confirmed_vulnerability", "node": node_name, "vuln_ids": sorted(visible_new_vulns), "points": points})

        for field_name in ("credential_known", "session_active", "foothold", "persistence"):
            if not getattr(prev_red, field_name, False) and getattr(curr_red, field_name, False):
                points = RED_STATE_SCORE[field_name]
                score += points
                events.append({"type": field_name, "node": node_name, "points": points})

        if previous is not None and previous.status != "Compromised" and current.status == "Compromised":
            points = RED_STATE_SCORE["compromised"]
            score += points
            events.append({"type": "compromised", "node": node_name, "points": points})
            if node_name in core_assets:
                core_points = RED_STATE_SCORE["core_compromised"]
                score += core_points
                events.append({"type": "core_compromised", "node": node_name, "points": core_points})

    if result.success and decision.action_type == "ExfiltrateDatabase":
        score += RED_STATE_SCORE["exfiltration"]
        events.append({"type": "exfiltration", "node": decision.target, "points": RED_STATE_SCORE["exfiltration"]})

    if not events and not result.success:
        return 0, "failed_or_rejected", events
    return score, "state_change_score" if events else "no_red_state_change", events


def _blue_state_change_score(
    previous_state: WorldState,
    current_state: WorldState,
    *,
    decision: AgentDecision,
    result: ActionResult,
    red_decision: AgentDecision | None = None,
    interaction_meta: dict[str, Any] | None = None,
) -> tuple[int, str, list[dict[str, Any]]]:
    prev_nodes = _node_map(previous_state)
    curr_nodes = _node_map(current_state)
    core_assets = _core_assets(current_state)
    interaction_meta = interaction_meta or {}
    events: list[dict[str, Any]] = []
    score = 0

    if decision.action_type == "Monitor" and result.success:
        target = decision.target
        hit = bool(red_decision and target and target == red_decision.target)
        if hit:
            points = BLUE_STATE_SCORE["monitor_hit"]
            score += points
            events.append({"type": "monitor_hit", "node": target, "points": points})
        elif bool(result.metadata.get("intel_gain", False)):
            points = BLUE_STATE_SCORE["discover_attack_path"]
            score += points
            events.append({"type": "discover_attack_path", "node": target, "points": points})

    if decision.action_type == "VulnerabilityScan" and result.success and bool(result.metadata.get("intel_gain", False)):
        points = BLUE_STATE_SCORE["discover_attack_path"]
        score += points
        events.append(
            {
                "type": "confirm_vulnerability_findings",
                "node": decision.target,
                "findings": result.metadata.get("intel_new_vulnerabilities", []),
                "points": points,
            }
        )

    if interaction_meta.get("pivot_interrupt"):
        points = BLUE_STATE_SCORE["pivot_interrupt"]
        score += points
        events.append({"type": "pivot_interrupt", "node": interaction_meta.get("source"), "points": points})

    if interaction_meta.get("path_intercept") or (
        decision.action_type == "Isolate"
        and red_decision is not None
        and red_decision.action_type == "ExfiltrateDatabase"
    ):
        points = BLUE_STATE_SCORE["isolate_exfil_path"]
        score += points
        events.append({"type": "isolate_exfil_path", "node": decision.target, "points": points})

    for node_name, current in curr_nodes.items():
        previous = prev_nodes.get(node_name)
        if previous is None:
            continue
        prev_red = previous.red_state
        curr_red = current.red_state

        for field_name, event_type in (
            ("session_active", "clear_session_active"),
            ("foothold", "clear_foothold"),
            ("persistence", "clear_persistence"),
        ):
            if getattr(prev_red, field_name, False) and not getattr(curr_red, field_name, False):
                points = BLUE_STATE_SCORE[event_type]
                score += points
                events.append({"type": event_type, "node": node_name, "points": points})

        removed_vulns = _vuln_ids(previous) - _vuln_ids(current)
        if removed_vulns and decision.action_type in {"PatchNode", "PreventivePatch", "DeepRestore"}:
            points = BLUE_STATE_SCORE["patch_exploited_vulnerability"] * len(removed_vulns)
            score += points
            events.append({"type": "patch_exploited_vulnerability", "node": node_name, "vuln_ids": sorted(removed_vulns), "points": points})

        if (
            node_name in core_assets
            and previous.status in {"Compromised", "Isolated", "Down"}
            and current.status in {"Normal", "Defended"}
        ):
            points = BLUE_STATE_SCORE["restore_core_asset"]
            score += points
            events.append({"type": "restore_core_asset", "node": node_name, "points": points})

    if not events and not result.success:
        return 0, "failed_or_rejected", events
    return score, "state_change_score" if events else "no_blue_state_change", events


def _compute_repeat_streak(
    decision: AgentDecision,
    *,
    tracker_entry: dict[str, Any],
) -> int:
    action_type = decision.action_type
    target = _normalize_target(decision.target)
    previous_action = tracker_entry.get("action_type")
    previous_target = tracker_entry.get("target")
    previous_streak = _coerce_non_negative_int(tracker_entry.get("streak", 0))

    if previous_action == action_type and previous_target == target:
        return previous_streak + 1
    return 1


def _resolve_score_multiplier(result: ActionResult) -> tuple[float, str]:
    multiplier = _coerce_positive_float(result.metadata.get("score_multiplier", 1.0), default=1.0)
    multiplier = max(0.1, min(3.0, multiplier))
    reason = str(result.metadata.get("score_multiplier_reason", "default_multiplier"))
    return multiplier, reason


def _resolve_budget_cap(result: ActionResult, *, round_score_budget: int) -> tuple[int, bool]:
    budget_cap = max(0, int(round_score_budget))
    override = result.metadata.get("score_budget_override")
    if isinstance(override, bool):
        return budget_cap, False
    if isinstance(override, (int, float)) and int(override) > 0:
        budget_cap = max(budget_cap, int(override))
        return budget_cap, True
    return budget_cap, False


def _apply_single_score(
    state: WorldState,
    *,
    side: str,
    decision: AgentDecision,
    result: ActionResult,
    repeat_tracker: dict[str, dict[str, Any]],
    round_score_budget: int,
    previous_state: WorldState | None = None,
    red_decision: AgentDecision | None = None,
    interaction_meta: dict[str, Any] | None = None,
) -> dict[str, Any]:
    entry = repeat_tracker.setdefault(side, {"action_type": None, "target": None, "streak": 0})
    repeat_streak = _compute_repeat_streak(decision, tracker_entry=entry)
    decay_factor = _repeat_decay(repeat_streak)

    state_events: list[dict[str, Any]] = []
    if previous_state is not None:
        if side == "Red":
            raw_base_score, score_reason, state_events = _red_state_change_score(
                previous_state,
                state,
                decision=decision,
                result=result,
            )
        else:
            raw_base_score, score_reason, state_events = _blue_state_change_score(
                previous_state,
                state,
                decision=decision,
                result=result,
                red_decision=red_decision,
                interaction_meta=interaction_meta,
            )
        if raw_base_score <= 0 and score_reason.startswith("no_"):
            legacy_score, legacy_reason = _compute_legacy_base_score(decision, result)
            raw_base_score = legacy_score
            score_reason = f"{score_reason}+{legacy_reason}"
    else:
        raw_base_score, score_reason = _compute_legacy_base_score(decision, result)
    score_multiplier, multiplier_reason = _resolve_score_multiplier(result)
    adjusted_base_score = int(round(raw_base_score * score_multiplier))
    decayed_score = int(adjusted_base_score * decay_factor)
    budget_cap, budget_overridden = _resolve_budget_cap(result, round_score_budget=round_score_budget)
    score_awarded = min(decayed_score, budget_cap)

    if side == "Red":
        state.red_score = max(0, state.red_score + score_awarded)
    else:
        state.blue_score = max(0, state.blue_score + score_awarded)

    entry.update(
        {
            "action_type": decision.action_type,
            "target": _normalize_target(decision.target),
            "streak": repeat_streak,
        }
    )

    result.metadata.update(
        {
            "score_awarded": score_awarded,
            "score_awarded_action_only": score_awarded,
            "terminal_bonus_awarded": 0,
            "score_base_raw": raw_base_score,
            "score_base": adjusted_base_score,
            "score_reason": score_reason,
            "score_multiplier": score_multiplier,
            "score_multiplier_reason": multiplier_reason,
            "score_repeat_streak": repeat_streak,
            "score_decay_factor": decay_factor,
            "round_score_budget": budget_cap,
            "round_score_budget_overridden": budget_overridden,
            "score_source": "scoring_engine",
            "state_score_events": state_events,
        }
    )

    if decision.action_type == "Recon":
        result.metadata.setdefault("intel_gain", bool(state_events))
        result.metadata["intel_score_policy"] = RED_STATE_SCORE["recon_known"]
        result.metadata["intel_score_threshold_passed"] = bool(state_events)

    return {
        "delta": score_awarded,
        "delta_action_only": score_awarded,
        "delta_terminal_bonus": 0,
        "base": adjusted_base_score,
        "base_raw": raw_base_score,
        "reason": score_reason,
        "multiplier": score_multiplier,
        "multiplier_reason": multiplier_reason,
        "repeat_streak": repeat_streak,
        "decay_factor": decay_factor,
        "budget_cap": budget_cap,
        "budget_overridden": budget_overridden,
    }


def apply_round_scores(
    state: WorldState,
    *,
    red_decision: AgentDecision,
    red_result: ActionResult,
    blue_decision: AgentDecision,
    blue_result: ActionResult,
    repeat_tracker: dict[str, dict[str, Any]],
    round_score_budget: int = ROUND_SCORE_BUDGET,
    previous_state: WorldState | None = None,
    interaction_meta: dict[str, Any] | None = None,
) -> dict[str, Any]:
    red_summary = _apply_single_score(
        state,
        side="Red",
        decision=red_decision,
        result=red_result,
        repeat_tracker=repeat_tracker,
        round_score_budget=round_score_budget,
        previous_state=previous_state,
        red_decision=red_decision,
        interaction_meta=interaction_meta,
    )
    blue_summary = _apply_single_score(
        state,
        side="Blue",
        decision=blue_decision,
        result=blue_result,
        repeat_tracker=repeat_tracker,
        round_score_budget=round_score_budget,
        previous_state=previous_state,
        red_decision=red_decision,
        interaction_meta=interaction_meta,
    )

    return {
        "red_delta": red_summary["delta"],
        "blue_delta": blue_summary["delta"],
        "red_score": state.red_score,
        "blue_score": state.blue_score,
        "red_breakdown": red_summary,
        "blue_breakdown": blue_summary,
    }


def recalculate_scores(state: WorldState) -> WorldState:
    nodes = list(state.network_nodes.values())
    compromised = sum(1 for node in nodes if node.status == "Compromised")
    active_sessions = sum(1 for node in nodes if node.red_state.session_active)
    footholds = sum(1 for node in nodes if node.red_state.foothold)
    unavailable_nodes = sum(1 for node in nodes if node.status in {"Down", "Isolated"} or node.blue_state.isolated)
    exposed_ports = sum(len(node.exposed_ports) for node in nodes)
    vulnerabilities = sum(len(node.vulnerabilities) for node in nodes)

    system_health = 100 - compromised * 20 - footholds * 8 - active_sessions * 4 - unavailable_nodes * 15
    exposure_level = 10 + compromised * 15 + footholds * 10 + active_sessions * 6 + vulnerabilities * 4 + exposed_ports

    state.system_health = max(0, min(100, system_health))
    state.exposure_level = max(0, min(100, exposure_level))
    return state
