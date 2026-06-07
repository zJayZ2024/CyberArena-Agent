from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any, Literal

from backend_engine.core.models import WorldState

AgentType = Literal["Red", "Blue"]

RED_ATTACK_ACTIONS = {"ExploitService", "LateralMove", "ExfiltrateDatabase", "ReactivateFoothold"}
BLUE_RESPONSE_ACTIONS = {"PatchNode", "RestoreNode", "DeepRestore", "Isolate"}


def _metadata(log: Any) -> dict[str, Any]:
    metadata = getattr(log, "metadata", {}) or {}
    return metadata if isinstance(metadata, dict) else {}


def _target_from_log(log: Any) -> str:
    metadata = _metadata(log)
    target = metadata.get("target")
    return target.strip() if isinstance(target, str) and target.strip() else ""


def _effect_from_log(log: Any) -> str:
    return str(_metadata(log).get("referee_effect", "") or "").lower()


def _score_from_log(log: Any) -> int:
    try:
        return int(_metadata(log).get("score_awarded", 0) or 0)
    except Exception:
        return 0


def _is_successful(log: Any) -> bool:
    metadata = _metadata(log)
    if metadata.get("validation") == "failed":
        return False
    if str(metadata.get("execution", "") or "").startswith("blocked"):
        return False
    effect = _effect_from_log(log)
    return effect not in {"blocked", "failed", "rejected"}


def _append_unique(rows: list[Any], value: Any, *, max_items: int = 24) -> None:
    if value in rows:
        rows.remove(value)
    rows.append(value)
    del rows[:-max_items]


def _asset_value(node_name: str) -> int:
    lowered = node_name.lower()
    if lowered == "db" or "database" in lowered or "sql" in lowered:
        return 100
    if "storage" in lowered or "backup" in lowered:
        return 80
    if "app" in lowered or "api" in lowered:
        return 70
    if "dev" in lowered or "ci" in lowered:
        return 62
    if "office" in lowered or "pc" in lowered:
        return 52
    if "vpn" in lowered:
        return 50
    if "web" in lowered:
        return 46
    return 35


@dataclass
class RedMemory:
    discovered_nodes: set[str] = field(default_factory=set)
    known_services: dict[str, set[int]] = field(default_factory=dict)
    known_vulnerabilities: dict[str, set[str]] = field(default_factory=dict)
    failed_exploits: list[dict[str, Any]] = field(default_factory=list)
    credential_store: list[dict[str, Any]] = field(default_factory=list)
    active_sessions: set[str] = field(default_factory=set)
    footholds: set[str] = field(default_factory=set)
    persistence_nodes: set[str] = field(default_factory=set)
    blocked_paths: list[dict[str, Any]] = field(default_factory=list)
    high_value_clues: set[str] = field(default_factory=set)


@dataclass
class BlueMemory:
    alert_history: list[dict[str, Any]] = field(default_factory=list)
    suspicious_nodes: dict[str, float] = field(default_factory=dict)
    suspicious_sources: dict[str, float] = field(default_factory=dict)
    attacked_assets: list[str] = field(default_factory=list)
    patched_vulnerabilities: dict[str, set[str]] = field(default_factory=dict)
    restored_nodes: list[dict[str, Any]] = field(default_factory=list)
    isolated_nodes: set[str] = field(default_factory=set)
    high_risk_paths: list[list[str]] = field(default_factory=list)
    attacker_likely_goals: set[str] = field(default_factory=set)


class AgentMemoryStore:
    """Small in-process memory and rule reflection for one agent.

    The store is intentionally deterministic and derived from settled world states.
    It does not decide actions directly; StrategyBias only nudges candidate ordering.
    """

    def __init__(self, *, agent_type: AgentType, reflection_interval: int = 3) -> None:
        self.agent_type = agent_type
        self.reflection_interval = max(2, reflection_interval)
        self.red = RedMemory()
        self.blue = BlueMemory()
        self._last_observed_turn = -1
        self._last_reflection_turn = -1
        self._reflections: list[dict[str, Any]] = []

    def observe(self, state: WorldState) -> None:
        if state.turn <= self._last_observed_turn:
            return

        self._refresh_state_memory(state)
        self._observe_logs(state)
        self._maybe_reflect(state)
        self._last_observed_turn = state.turn

    def recent_reflections(self, limit: int = 2) -> list[dict[str, Any]]:
        return self._reflections[-max(1, limit) :]

    def as_prompt_context(self) -> dict[str, Any]:
        if self.agent_type == "Red":
            return {
                "discovered_nodes": sorted(self.red.discovered_nodes),
                "known_vulnerabilities": {
                    node: sorted(vulns)
                    for node, vulns in sorted(self.red.known_vulnerabilities.items())
                    if vulns
                },
                "failed_exploits": self.red.failed_exploits[-6:],
                "active_sessions": sorted(self.red.active_sessions),
                "footholds": sorted(self.red.footholds),
                "persistence_nodes": sorted(self.red.persistence_nodes),
                "blocked_paths": self.red.blocked_paths[-5:],
                "high_value_clues": sorted(self.red.high_value_clues),
                "recent_reflections": self.recent_reflections(limit=2),
            }

        return {
            "alert_history": self.blue.alert_history[-6:],
            "suspicious_nodes": dict(sorted(self.blue.suspicious_nodes.items(), key=lambda item: item[1], reverse=True)[:8]),
            "attacked_assets": self.blue.attacked_assets[-8:],
            "patched_vulnerabilities": {
                node: sorted(vulns)
                for node, vulns in sorted(self.blue.patched_vulnerabilities.items())
                if vulns
            },
            "restored_nodes": self.blue.restored_nodes[-6:],
            "isolated_nodes": sorted(self.blue.isolated_nodes),
            "high_risk_paths": self.blue.high_risk_paths[-3:],
            "attacker_likely_goals": sorted(self.blue.attacker_likely_goals),
            "recent_reflections": self.recent_reflections(limit=2),
        }

    def _refresh_state_memory(self, state: WorldState) -> None:
        for node_name in state.red_visible_nodes:
            if node_name in state.network_nodes:
                self.red.discovered_nodes.add(node_name)
        for node_name in state.red_recon_nodes:
            if node_name in state.network_nodes:
                self.red.discovered_nodes.add(node_name)
        for node_name, ports in state.red_known_services.items():
            if node_name not in state.network_nodes:
                continue
            self.red.known_services.setdefault(node_name, set()).update(int(port) for port in ports)
        for node_name, vuln_map in state.red_known_vulnerabilities.items():
            if node_name not in state.network_nodes or not isinstance(vuln_map, dict):
                continue
            self.red.known_vulnerabilities.setdefault(node_name, set()).update(vuln_map.keys())

        self.red.active_sessions.clear()
        self.red.footholds.clear()
        self.red.persistence_nodes.clear()
        for node_name, node in state.network_nodes.items():
            if node.red_state.recon_known:
                self.red.discovered_nodes.add(node_name)
            if node.red_state.credential_known:
                _append_unique(
                    self.red.credential_store,
                    {"node": node_name, "turn": state.turn, "privilege": node.red_state.privilege},
                    max_items=16,
                )
            if node.red_state.session_active or node.status == "Compromised":
                self.red.active_sessions.add(node_name)
            if node.red_state.foothold or node.status == "Compromised":
                self.red.footholds.add(node_name)
            if node.red_state.persistence or node_name in state.red_anchored_nodes:
                self.red.persistence_nodes.add(node_name)
            if node_name in state.core_assets or _asset_value(node_name) >= 70:
                if node_name in self.red.discovered_nodes or node_name in state.red_visible_nodes:
                    self.red.high_value_clues.add(node_name)

            if node.blue_state.isolated or node.status == "Isolated":
                self.blue.isolated_nodes.add(node_name)
            if node.blue_state.restored:
                _append_unique(self.blue.restored_nodes, {"node": node_name, "turn": node.blue_state.last_response_turn}, max_items=16)

    def _observe_logs(self, state: WorldState) -> None:
        red_log = next((log for log in state.action_logs if log.agent_type == "Red"), None)
        blue_log = next((log for log in state.action_logs if log.agent_type == "Blue"), None)

        for alert in state.security_alerts:
            row = alert.model_dump(mode="json")
            _append_unique(self.blue.alert_history, row, max_items=24)
            if alert.target:
                self.blue.suspicious_nodes[alert.target] = min(1.0, self.blue.suspicious_nodes.get(alert.target, 0.0) + self._alert_weight(alert.severity))

        if red_log is not None:
            target = _target_from_log(red_log)
            metadata = _metadata(red_log)
            if target:
                _append_unique(self.blue.attacked_assets, target, max_items=24)
                self.blue.suspicious_nodes[target] = min(1.0, self.blue.suspicious_nodes.get(target, 0.0) + 0.22)
                if _asset_value(target) >= 70 or target in state.core_assets:
                    self.blue.attacker_likely_goals.add(target)

            if red_log.action_type == "Recon" and target:
                self.red.discovered_nodes.add(target)
            if red_log.action_type in RED_ATTACK_ACTIONS and target:
                if _is_successful(red_log):
                    self.red.discovered_nodes.add(target)
                    if red_log.action_type in {"ExploitService", "LateralMove", "ReactivateFoothold"}:
                        self.red.active_sessions.add(target)
                        self.red.footholds.add(target)
                else:
                    _append_unique(
                        self.red.failed_exploits,
                        {
                            "target": target,
                            "vuln_id": metadata.get("vuln_id"),
                            "turn": state.turn,
                            "reason": metadata.get("referee_effect") or metadata.get("execution") or "failed",
                        },
                        max_items=12,
                    )

            if metadata.get("intercepted_by") or _effect_from_log(red_log) == "blocked":
                pivot_source = str(metadata.get("pivot_source", "") or "")
                _append_unique(
                    self.red.blocked_paths,
                    {
                        "turn": state.turn,
                        "action": red_log.action_type,
                        "source": pivot_source,
                        "target": target,
                        "blocked_by": metadata.get("intercepted_by") or metadata.get("referee_effect") or "blue_response",
                    },
                    max_items=12,
                )

        if blue_log is not None:
            target = _target_from_log(blue_log)
            metadata = _metadata(blue_log)
            if blue_log.action_type in {"PatchNode", "PreventivePatch"} and target:
                vuln_id = metadata.get("vuln_id")
                if isinstance(vuln_id, str) and vuln_id:
                    self.blue.patched_vulnerabilities.setdefault(target, set()).add(vuln_id)
            if blue_log.action_type in {"RestoreNode", "DeepRestore"} and target:
                _append_unique(self.blue.restored_nodes, {"node": target, "turn": state.turn}, max_items=16)
                self.blue.suspicious_nodes[target] = max(0.0, self.blue.suspicious_nodes.get(target, 0.0) - 0.18)
            if blue_log.action_type == "Isolate" and target:
                self.blue.isolated_nodes.add(target)

    def _maybe_reflect(self, state: WorldState) -> None:
        if state.turn <= 0 or state.turn == self._last_reflection_turn:
            return

        force = self._has_key_event(state)
        if not force and state.turn % self.reflection_interval != 0:
            return

        reflection = self._build_red_reflection(state) if self.agent_type == "Red" else self._build_blue_reflection(state)
        self._reflections.append(reflection)
        self._reflections = self._reflections[-8:]
        self._last_reflection_turn = state.turn

    def _has_key_event(self, state: WorldState) -> bool:
        red_log = next((log for log in state.action_logs if log.agent_type == "Red"), None)
        if red_log is not None:
            metadata = _metadata(red_log)
            if metadata.get("intercepted_by") or metadata.get("restore_interrupt") or _effect_from_log(red_log) in {"blocked", "exfiltration"}:
                return True
            target = _target_from_log(red_log)
            if target in state.core_assets or red_log.action_type in {"ExfiltrateDatabase", "AnchorFoothold"}:
                return True
        return False

    def _build_red_reflection(self, state: WorldState) -> dict[str, Any]:
        avoid_targets = []
        for row in self.red.blocked_paths[-4:]:
            source = row.get("source")
            if isinstance(source, str) and source:
                avoid_targets.append({"target": source, "reason": f"recently blocked by {row.get('blocked_by')}"})

        footholds = sorted(self.red.footholds or self.red.active_sessions)
        high_value = sorted(self.red.high_value_clues, key=_asset_value, reverse=True)
        prioritized = []
        for node_name in [*high_value, *footholds]:
            if node_name not in prioritized:
                prioritized.append(node_name)

        next_goal = "继续侦察并寻找首个可用入口"
        if footholds and high_value:
            next_goal = f"维护 {footholds[0]} 跳板，并向 {high_value[0]} 路径推进"
        elif footholds:
            next_goal = f"利用 {footholds[0]} 继续横向移动，优先寻找 app/db 路径"

        return {
            "turn": state.turn,
            "agent_type": "Red",
            "summary": f"已发现 {len(self.red.discovered_nodes)} 个节点，当前可用 foothold={footholds[:3]}。",
            "strategy_shift": "避开近期被阻断路径，优先从稳定 foothold 推进。",
            "prioritized_targets": prioritized[:5],
            "avoid": avoid_targets[-4:],
            "maintain": footholds[:4],
            "next_goal": next_goal,
        }

    def _build_blue_reflection(self, state: WorldState) -> dict[str, Any]:
        suspicious = sorted(self.blue.suspicious_nodes.items(), key=lambda item: item[1], reverse=True)
        likely_path = [node for node, score in suspicious if score >= 0.3][:5]
        goals = sorted(self.blue.attacker_likely_goals, key=_asset_value, reverse=True)
        priority_defense = []
        for node, score in suspicious[:3]:
            if score < 0.35:
                continue
            node_state = state.network_nodes.get(node)
            has_red_activity = bool(
                node_state
                and (
                    node_state.status == "Compromised"
                    or node_state.red_state.session_active
                    or node_state.red_state.foothold
                    or node_state.red_state.persistence
                )
            )
            if has_red_activity:
                priority_defense.append(
                    {"action": "RestoreNode", "target": node, "reason": "active red session/foothold requires cleanup"}
                )
            else:
                priority_defense.append(
                    {"action": "Monitor", "target": node, "reason": "suspicious but not confirmed; preserve availability"}
                )
        for core in state.core_assets:
            if core not in [row.get("target") for row in priority_defense]:
                priority_defense.append({"action": "Monitor", "target": core, "reason": "core asset likely objective"})

        avoid = []
        recently_restored = {row.get("node") for row in self.blue.restored_nodes[-3:] if isinstance(row, dict)}
        for node in sorted(node for node in recently_restored if isinstance(node, str) and node):
            avoid.append({"action": "RestoreNode", "target": node, "reason": "recently restored; avoid low-value repetition"})

        return {
            "turn": state.turn,
            "agent_type": "Blue",
            "summary": f"近期高风险节点：{[node for node, _ in suspicious[:4]]}。",
            "likely_attack_path": likely_path,
            "likely_goals": goals[:4] or list(state.core_assets),
            "priority_defense": priority_defense[:5],
            "avoid": avoid[:4],
        }

    @staticmethod
    def _alert_weight(severity: str) -> float:
        if severity == "CRIT":
            return 0.42
        if severity == "WARN":
            return 0.26
        return 0.12


class StrategyBias:
    def __init__(self, memory: AgentMemoryStore) -> None:
        self.memory = memory

    def apply(self, candidates: list[Any]) -> list[Any]:
        if not candidates:
            return []
        if self.memory.agent_type == "Red":
            return self._apply_red(candidates)
        return self._apply_blue(candidates)

    def _apply_red(self, candidates: list[Any]) -> list[Any]:
        latest = self.memory.recent_reflections(limit=1)
        prioritized = set(latest[-1].get("prioritized_targets", [])) if latest else set()
        maintain = set(latest[-1].get("maintain", [])) if latest else set()
        avoid_targets = {
            row.get("target")
            for row in (latest[-1].get("avoid", []) if latest else [])
            if isinstance(row, dict)
        }
        has_active_control = bool(self.memory.red.footholds or self.memory.red.active_sessions)

        failed_pairs = {
            (row.get("target"), row.get("vuln_id"))
            for row in self.memory.red.failed_exploits[-8:]
            if isinstance(row, dict)
        }

        for row in candidates:
            decision = row.decision
            delta = 0.0
            if decision.target in prioritized:
                delta += 14.0
            if decision.target in maintain and decision.action_type in {"AnchorFoothold", "LateralMove", "ReactivateFoothold"}:
                delta += 12.0
            if decision.target in self.memory.red.high_value_clues:
                delta += 5.0
            if decision.target in avoid_targets:
                delta -= 18.0
            if (decision.target, decision.vuln_id) in failed_pairs:
                delta -= 28.0
            if decision.action_type == "Recon" and decision.target in self.memory.red.discovered_nodes:
                delta -= 22.0
            if decision.action_type == "ExploitService" and decision.target in self.memory.red.known_vulnerabilities:
                delta += 18.0
            if decision.action_type == "Recon" and has_active_control:
                delta -= 10.0
            if decision.action_type in {"LateralMove", "ExfiltrateDatabase"} and self.memory.red.footholds:
                delta += 10.0
            if decision.action_type == "AnchorFoothold" and decision.target in (self.memory.red.footholds | self.memory.red.active_sessions):
                delta += 18.0
            self._adjust(row, delta, "memory_bias")
        return sorted(candidates, key=lambda item: (item.heuristic_score, item.candidate_id), reverse=True)

    def _apply_blue(self, candidates: list[Any]) -> list[Any]:
        latest = self.memory.recent_reflections(limit=1)
        priority_targets = {
            row.get("target")
            for row in (latest[-1].get("priority_defense", []) if latest else [])
            if isinstance(row, dict)
        }
        avoid_restore = {
            row.get("target")
            for row in (latest[-1].get("avoid", []) if latest else [])
            if isinstance(row, dict) and row.get("action") == "RestoreNode"
        }

        for row in candidates:
            decision = row.decision
            delta = 0.0
            suspicious_score = self.memory.blue.suspicious_nodes.get(decision.target or "", 0.0)
            if suspicious_score:
                delta += suspicious_score * 14.0
            if decision.target in priority_targets and decision.action_type in BLUE_RESPONSE_ACTIONS | {"Monitor"}:
                delta += 8.0
            if decision.action_type == "Isolate":
                if suspicious_score < 0.65 and decision.target not in self.memory.blue.attacker_likely_goals:
                    delta -= 24.0
                else:
                    delta += 8.0
            if decision.action_type == "RestoreNode" and decision.target in avoid_restore:
                delta -= 24.0
            if decision.action_type == "Monitor" and decision.target in self.memory.blue.attacker_likely_goals:
                delta += 4.0
            self._adjust(row, delta, "memory_bias")
        return sorted(candidates, key=lambda item: (item.heuristic_score, item.candidate_id), reverse=True)

    @staticmethod
    def _adjust(row: Any, delta: float, tag: str) -> None:
        if abs(delta) < 0.01:
            return
        row.heuristic_score += delta
        row.reason = f"{row.reason}；{tag} {delta:+.1f}"
        tags = tuple(getattr(row, "tags", ()))
        if tag not in tags:
            row.tags = (*tags, tag)
