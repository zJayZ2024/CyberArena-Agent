from __future__ import annotations

from typing import Any

from backend_engine.core.models import AgentDecision, WorldState
from backend_engine.engine.actions import ActionResult

# Recon and Monitor are intentionally hard-coded to zero score so they cannot be farmed.
ZERO_SCORE_ACTIONS = {"Recon", "Monitor"}
ROUND_SCORE_BUDGET = 30

# Same action on same target in consecutive rounds receives score decay.
REPEAT_DECAY_FACTORS = (1.0, 0.7, 0.4, 0.25)

# Optional fallback constants for remediation actions when score_value is unavailable.
DEFENSE_POLICY_CONSTANTS = {
    "PatchNode": 0,
    "RestoreNode": 0,
    "Isolate": 0,
}


def _coerce_non_negative_int(value: Any, *, default: int = 0) -> int:
    if isinstance(value, bool):
        return default
    if isinstance(value, (int, float)):
        return max(0, int(value))
    return default


def _normalize_target(target: str | None) -> str:
    return target or "__none__"


def _repeat_decay(streak: int) -> float:
    if streak <= 1:
        return REPEAT_DECAY_FACTORS[0]
    idx = min(streak - 1, len(REPEAT_DECAY_FACTORS) - 1)
    return REPEAT_DECAY_FACTORS[idx]


def _compute_base_score(decision: AgentDecision, result: ActionResult) -> tuple[int, str]:
    if not result.success:
        return 0, "failed_or_rejected"

    action_type = decision.action_type
    if action_type in ZERO_SCORE_ACTIONS:
        if action_type == "Recon":
            return 0, "recon_fixed_zero_policy"
        return 0, "monitor_fixed_zero_policy"

    score_value = _coerce_non_negative_int(result.metadata.get("score_value", 0))
    if score_value > 0:
        return score_value, "action_metadata.score_value"

    if action_type in DEFENSE_POLICY_CONSTANTS:
        constant_score = _coerce_non_negative_int(DEFENSE_POLICY_CONSTANTS[action_type])
        return constant_score, "defense_policy_constant"

    return 0, "no_effective_score_source"


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


def _apply_single_score(
    state: WorldState,
    *,
    side: str,
    decision: AgentDecision,
    result: ActionResult,
    repeat_tracker: dict[str, dict[str, Any]],
    round_score_budget: int,
) -> dict[str, Any]:
    entry = repeat_tracker.setdefault(side, {"action_type": None, "target": None, "streak": 0})
    repeat_streak = _compute_repeat_streak(decision, tracker_entry=entry)
    decay_factor = _repeat_decay(repeat_streak)

    base_score, score_reason = _compute_base_score(decision, result)
    decayed_score = int(base_score * decay_factor)
    budget_cap = max(0, int(round_score_budget))
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
            "score_base": base_score,
            "score_reason": score_reason,
            "score_repeat_streak": repeat_streak,
            "score_decay_factor": decay_factor,
            "round_score_budget": budget_cap,
            "score_source": "scoring_engine",
        }
    )

    if decision.action_type == "Recon":
        result.metadata.setdefault("intel_gain", False)
        result.metadata["intel_score_policy"] = 0
        result.metadata["intel_score_threshold_passed"] = False

    return {
        "delta": score_awarded,
        "base": base_score,
        "reason": score_reason,
        "repeat_streak": repeat_streak,
        "decay_factor": decay_factor,
        "budget_cap": budget_cap,
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
) -> dict[str, Any]:
    red_summary = _apply_single_score(
        state,
        side="Red",
        decision=red_decision,
        result=red_result,
        repeat_tracker=repeat_tracker,
        round_score_budget=round_score_budget,
    )
    blue_summary = _apply_single_score(
        state,
        side="Blue",
        decision=blue_decision,
        result=blue_result,
        repeat_tracker=repeat_tracker,
        round_score_budget=round_score_budget,
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
    down_nodes = sum(1 for node in nodes if node.status == "Down")
    exposed_ports = sum(len(node.exposed_ports) for node in nodes)
    vulnerabilities = sum(len(node.vulnerabilities) for node in nodes)

    system_health = 100 - compromised * 20 - down_nodes * 15
    exposure_level = 10 + compromised * 15 + vulnerabilities * 4 + exposed_ports

    state.system_health = max(0, min(100, system_health))
    state.exposure_level = max(0, min(100, exposure_level))
    return state
