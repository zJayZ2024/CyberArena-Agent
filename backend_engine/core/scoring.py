from backend_engine.core.models import WorldState
from backend_engine.engine.actions import ActionResult


def _successful_score(result: ActionResult) -> int:
    if not result.success:
        return 0
    score_value = result.metadata.get("score_value", 0)
    if isinstance(score_value, (int, float)):
        return max(0, int(score_value))
    return 0


def apply_round_scores(
    state: WorldState,
    red_result: ActionResult,
    blue_result: ActionResult,
    *,
    interception_bonus: int = 0,
) -> dict[str, int]:
    red_delta = _successful_score(red_result)
    blue_delta = _successful_score(blue_result) + max(0, interception_bonus)

    state.red_score = max(0, state.red_score + red_delta)
    state.blue_score = max(0, state.blue_score + blue_delta)

    return {
        "red_delta": red_delta,
        "blue_delta": blue_delta,
        "interception_bonus": max(0, interception_bonus),
        "red_score": state.red_score,
        "blue_score": state.blue_score,
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
