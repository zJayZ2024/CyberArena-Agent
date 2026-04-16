from backend_engine.core.models import WorldState
from backend_engine.engine.actions import ActionResult


RED_EFFECT_SCORES = {
    "intel": 5,
    "compromise": 20,
    "exfiltration": 35,
    "blocked": -4,
    "failed": -2,
    "rejected": -5,
}

BLUE_EFFECT_SCORES = {
    "monitoring": 4,
    "hardening": 10,
    "restoration": 15,
    "blocked": 6,
    "failed": -2,
    "rejected": -4,
}


def apply_round_scores(
    state: WorldState,
    red_result: ActionResult,
    blue_result: ActionResult,
) -> dict[str, int]:
    red_delta = RED_EFFECT_SCORES.get(red_result.effect, 0)
    blue_delta = BLUE_EFFECT_SCORES.get(blue_result.effect, 0)

    if red_result.effect == "blocked":
        blue_delta += 6
    elif red_result.effect == "compromise":
        blue_delta -= 10
    elif red_result.effect == "exfiltration":
        blue_delta -= 20

    if blue_result.effect == "hardening":
        red_delta -= 3
    elif blue_result.effect == "restoration":
        red_delta -= 8
    elif blue_result.effect == "monitoring" and red_result.effect == "intel":
        blue_delta += 2

    state.red_score = max(0, state.red_score + red_delta)
    state.blue_score = max(0, state.blue_score + blue_delta)

    return {
        "red_delta": red_delta,
        "blue_delta": blue_delta,
        "red_score": state.red_score,
        "blue_score": state.blue_score,
    }


def recalculate_scores(state: WorldState) -> WorldState:
    nodes = list(state.network_nodes.values())
    compromised = sum(1 for node in nodes if node.status == "Compromised")
    defended = sum(1 for node in nodes if node.status == "Defended")
    exposed_ports = sum(len(node.exposed_ports) for node in nodes)
    vulnerabilities = sum(len(node.vulnerabilities) for node in nodes)

    system_health = 100 - compromised * 20 + defended * 5
    exposure_level = 10 + compromised * 15 + vulnerabilities * 4 + exposed_ports

    state.system_health = max(0, min(100, system_health))
    state.exposure_level = max(0, min(100, exposure_level))
    return state
