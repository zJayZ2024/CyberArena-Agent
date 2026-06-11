from __future__ import annotations

from typing import Any


def _node_status_delta(previous: dict[str, Any], current: dict[str, Any]) -> list[dict[str, Any]]:
    changes: list[dict[str, Any]] = []
    node_names = sorted(set(previous.keys()) | set(current.keys()))
    for node_name in node_names:
        prev_node = previous.get(node_name, {})
        curr_node = current.get(node_name, {})
        prev_status = prev_node.get("status")
        curr_status = curr_node.get("status")
        if prev_status != curr_status:
            changes.append(
                {
                    "node": node_name,
                    "from": prev_status,
                    "to": curr_status,
                }
            )
    return changes


def _node_vulnerability_delta(previous: dict[str, Any], current: dict[str, Any]) -> list[dict[str, Any]]:
    changes: list[dict[str, Any]] = []
    node_names = sorted(set(previous.keys()) | set(current.keys()))
    for node_name in node_names:
        prev_node = previous.get(node_name, {})
        curr_node = current.get(node_name, {})
        prev_vulns = set((prev_node.get("vulnerabilities") or {}).keys())
        curr_vulns = set((curr_node.get("vulnerabilities") or {}).keys())
        removed = sorted(prev_vulns - curr_vulns)
        added = sorted(curr_vulns - prev_vulns)
        if removed or added:
            changes.append(
                {
                    "node": node_name,
                    "removed": removed,
                    "added": added,
                }
            )
    return changes


def _extract_agent_log(frame: dict[str, Any], agent_type: str) -> dict[str, Any]:
    logs = frame.get("action_logs", [])
    for log in logs:
        if log.get("agent_type") == agent_type:
            metadata = log.get("metadata") if isinstance(log.get("metadata"), dict) else {}
            return {
                "action_type": log.get("action_type"),
                "target": metadata.get("target"),
                "vuln_id": metadata.get("vuln_id"),
                "thought": log.get("thought", ""),
                "referee_result": log.get("referee_result", ""),
                "effect": metadata.get("referee_effect"),
                "score_awarded": metadata.get("score_awarded", 0),
            }
    return {
        "action_type": "",
        "target": None,
        "vuln_id": None,
        "thought": "",
        "referee_result": "",
        "effect": None,
        "score_awarded": 0,
    }


def _extract_referee_meta(frame: dict[str, Any]) -> dict[str, Any]:
    logs = frame.get("action_logs", [])
    for log in logs:
        if log.get("agent_type") == "Referee":
            metadata = log.get("metadata") if isinstance(log.get("metadata"), dict) else {}
            return {
                "summary": log.get("referee_result", ""),
                "interaction": metadata.get("interaction", {}),
                "score_summary": metadata.get("score_summary", {}),
            }
    return {"summary": "", "interaction": {}, "score_summary": {}}


def build_replay_lite(replay: dict[str, Any]) -> dict[str, Any]:
    frames = replay.get("frames", [])
    if not frames:
        return {
            "meta": {
                "schema_version": "1.0",
                "scenario": replay.get("scenario", ""),
                "total_rounds": replay.get("total_rounds", 0),
            },
            "initial_topology": {},
            "rounds": [],
            "final_summary": {},
        }

    first_frame = frames[0]
    initial_edges = first_frame.get("edges") or replay.get("edges") or []
    initial_topology = {
        node_name: {
            "status": node.get("status"),
            "exposed_ports": node.get("exposed_ports", []),
            "vulnerabilities": sorted((node.get("vulnerabilities") or {}).keys()),
        }
        for node_name, node in (first_frame.get("network_nodes") or {}).items()
    }

    rounds: list[dict[str, Any]] = []
    for idx in range(1, len(frames)):
        previous = frames[idx - 1]
        current = frames[idx]
        node_status_changes = _node_status_delta(
            previous.get("network_nodes", {}),
            current.get("network_nodes", {}),
        )
        vulnerability_changes = _node_vulnerability_delta(
            previous.get("network_nodes", {}),
            current.get("network_nodes", {}),
        )
        referee_meta = _extract_referee_meta(current)
        rounds.append(
            {
                "turn": current.get("turn", idx),
                "red_action": _extract_agent_log(current, "Red"),
                "blue_action": _extract_agent_log(current, "Blue"),
                "adjudication": {
                    "summary": referee_meta.get("summary", ""),
                    "interaction": referee_meta.get("interaction", {}),
                },
                "score_delta": referee_meta.get("score_summary", {}),
                "delta": {
                    "node_status_changes": node_status_changes,
                    "vulnerability_changes": vulnerability_changes,
                },
                "state": {
                    "system_health": current.get("system_health"),
                    "exposure_level": current.get("exposure_level"),
                    "red_score": current.get("red_score"),
                    "blue_score": current.get("blue_score"),
                    "winner_locked": current.get("winner_locked"),
                    "winner_side": current.get("winner_side"),
                },
            }
        )

    final_frame = frames[-1]
    return {
        "meta": {
            "schema_version": "1.0",
            "scenario": replay.get("scenario", ""),
            "total_rounds": replay.get("total_rounds", len(frames) - 1),
        },
        "initial_topology": initial_topology,
        "initial_edges": initial_edges,
        "rounds": rounds,
        "final_summary": {
            "turn": final_frame.get("turn"),
            "system_health": final_frame.get("system_health"),
            "exposure_level": final_frame.get("exposure_level"),
            "red_score": final_frame.get("red_score"),
            "blue_score": final_frame.get("blue_score"),
            "winner_locked": final_frame.get("winner_locked"),
            "winner_side": final_frame.get("winner_side"),
            "winner_reason": final_frame.get("winner_reason"),
        },
    }

