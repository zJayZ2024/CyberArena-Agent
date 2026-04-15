from backend_engine.core.models import WorldState


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
