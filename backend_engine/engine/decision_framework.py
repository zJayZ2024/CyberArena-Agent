from __future__ import annotations

import hashlib
import json
import time
from collections import deque
from dataclasses import dataclass
from typing import Any, Iterable, Literal

from backend_engine.agents.llm_agent import LLMDecisionError
from backend_engine.core.models import AgentDecision, SecurityAlert, WorldState
from backend_engine.engine.protocol_library import build_blue_defense_rule, build_red_raw_command
from backend_engine.engine.actions import ACTION_REGISTRY, ActionContext

AgentType = Literal["Red", "Blue"]

RED_PASSIVE_ACTIONS = {"Recon", "AnchorFoothold"}
BLUE_PASSIVE_ACTIONS = {"Monitor", "VulnerabilityScan"}
RED_OBJECTIVE_ACTIONS = {"ExploitService", "LateralMove", "ExfiltrateDatabase", "AnchorFoothold", "ReactivateFoothold"}
BLUE_RESPONSE_ACTIONS = {"PatchNode", "RestoreNode", "DeepRestore", "Isolate"}
RED_ATTACK_ACTIONS = {"ExploitService", "LateralMove", "ExfiltrateDatabase", "ReactivateFoothold"}
RED_VULN_VARIANT_ACTIONS = {"ExploitService", "LateralMove", "ExfiltrateDatabase"}
MAX_RED_VULN_VARIANTS_PER_ACTION_TARGET = 2
MAX_RED_EXPLOIT_VARIANTS_PER_TARGET = 3
CORE_DEFAULT = ("db",)
PREVENTIVE_PATCH_INTERVAL = 2
TIER0_PROACTIVE_LOCK_ROUNDS = 2
RECENT_SELF_ISOLATE_RESTORE_WINDOW = 3

ASSET_STRATEGIC_VALUE = {
    "db": 100,
    "storage": 75,
    "app": 68,
    "dev": 60,
    "office_pc": 52,
    "vpn": 48,
    "web": 45,
    "fw": 38,
    "internet": 20,
}

PERIMETER_KEYWORDS = (
    "web",
    "fw",
    "firewall",
    "gateway",
    "proxy",
    "edge",
    "vpn",
    "mail",
    "dmz",
)
DATABASE_KEYWORDS = ("db", "database", "mysql", "postgres", "sql")
STORAGE_KEYWORDS = ("storage", "nas", "file", "backup")
APPLICATION_KEYWORDS = ("app", "api", "service", "portal")
WORKSTATION_KEYWORDS = ("office", "pc", "workstation", "client", "endpoint")
DEVOPS_KEYWORDS = ("dev", "ci", "jenkins", "build", "git")


def _core_assets(state: WorldState) -> tuple[str, ...]:
    core_assets = tuple(node_name for node_name in state.core_assets if node_name in state.network_nodes)
    return core_assets or CORE_DEFAULT


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


def _is_perimeter_node(node_name: str) -> bool:
    lowered = node_name.lower()
    return lowered == "internet" or any(keyword in lowered for keyword in PERIMETER_KEYWORDS)


def _default_red_visible_nodes(state: WorldState) -> set[str]:
    visible = {node_name for node_name in state.network_nodes if _is_perimeter_node(node_name)}
    if visible:
        return visible
    # Keep one stable seed if topology naming is unusual.
    return {"internet"} & set(state.network_nodes)


def _asset_strategic_value(target: str | None) -> int:
    if not target:
        return 20
    lowered = target.lower()
    if lowered in ASSET_STRATEGIC_VALUE:
        return ASSET_STRATEGIC_VALUE[lowered]
    if any(keyword in lowered for keyword in DATABASE_KEYWORDS):
        return 95
    if any(keyword in lowered for keyword in STORAGE_KEYWORDS):
        return 74
    if any(keyword in lowered for keyword in APPLICATION_KEYWORDS):
        return 66
    if any(keyword in lowered for keyword in DEVOPS_KEYWORDS):
        return 60
    if any(keyword in lowered for keyword in WORKSTATION_KEYWORDS):
        return 52
    if "vpn" in lowered:
        return 48
    if _is_perimeter_node(lowered):
        return 44
    return 36


def _has_red_activity(node: Any) -> bool:
    red_state = getattr(node, "red_state", None)
    return bool(
        getattr(red_state, "session_active", False)
        or getattr(red_state, "foothold", False)
        or getattr(red_state, "persistence", False)
        or getattr(node, "status", "") == "Compromised"
    )


def _recent_warn_or_crit(recent_alerts: Iterable[SecurityAlert] | None, target: str | None) -> tuple[bool, bool]:
    has_warn = False
    has_crit = False
    if not target or not recent_alerts:
        return has_warn, has_crit
    for alert in recent_alerts:
        if alert.target != target:
            continue
        if alert.severity == "CRIT":
            has_crit = True
        elif alert.severity == "WARN":
            has_warn = True
    return has_warn, has_crit


def _recently_self_isolated(state: WorldState, target: str | None) -> bool:
    if not target or target not in state.network_nodes:
        return False
    node = state.network_nodes[target]
    if node.status != "Isolated" and not node.blue_state.isolated:
        return False
    last_turn = int(node.blue_state.last_response_turn)
    return last_turn >= 0 and 0 <= int(state.turn) - last_turn <= RECENT_SELF_ISOLATE_RESTORE_WINDOW


def _shortest_hops_to_core(
    *,
    adjacency: dict[str, list[str]],
    starts: Iterable[str],
    cores: set[str],
) -> int | None:
    queue: deque[tuple[str, int]] = deque()
    visited: set[str] = set()
    for node_name in starts:
        if node_name in cores:
            return 0
        if node_name in adjacency and node_name not in visited:
            visited.add(node_name)
            queue.append((node_name, 0))
    while queue:
        node_name, depth = queue.popleft()
        for neighbor in adjacency.get(node_name, []):
            if neighbor in visited:
                continue
            if neighbor in cores:
                return depth + 1
            visited.add(neighbor)
            queue.append((neighbor, depth + 1))
    return None


@dataclass(slots=True)
class CandidateAction:
    candidate_id: str
    decision: AgentDecision
    expected_impact: float
    expected_risk: float
    progress_value: float
    heuristic_score: float
    tags: tuple[str, ...]
    reason: str

    def as_prompt_row(self) -> dict[str, Any]:
        return {
            "candidate_id": self.candidate_id,
            "action_type": self.decision.action_type,
            "target": self.decision.target,
            "vuln_id": self.decision.vuln_id,
            "payload": self.decision.payload,
            "raw_command": self.decision.raw_command,
            "defense_rule": self.decision.defense_rule,
            "expected_impact": round(self.expected_impact, 2),
            "expected_risk": round(self.expected_risk, 2),
            "progress_value": round(self.progress_value, 2),
            "heuristic_score": round(self.heuristic_score, 2),
            "tags": list(self.tags),
            "reason": self.reason,
        }


@dataclass(slots=True)
class PlannerDecision:
    chosen_candidate_id: str
    backup_candidate_id: str | None
    thought: str
    raw_payload: dict[str, Any]


@dataclass(slots=True)
class IntelPackage:
    visible_nodes: tuple[str, ...]
    known_services: dict[str, tuple[int, ...]]
    known_vulnerabilities: dict[str, tuple[str, ...]]
    compromised_footholds: tuple[str, ...]
    anchored_nodes: tuple[str, ...]
    recon_nodes: tuple[str, ...]
    core_assets: tuple[str, ...]

    def as_dict(self) -> dict[str, Any]:
        return {
            "visible_nodes": list(self.visible_nodes),
            "known_services": {node: list(ports) for node, ports in self.known_services.items()},
            "known_vulnerabilities": {node: list(vuln_ids) for node, vuln_ids in self.known_vulnerabilities.items()},
            "compromised_footholds": list(self.compromised_footholds),
            "anchored_nodes": list(self.anchored_nodes),
            "recon_nodes": list(self.recon_nodes),
            "core_assets": list(self.core_assets),
        }


def build_red_intel_package(state: WorldState) -> IntelPackage:
    visible = set(state.red_visible_nodes)
    if not visible:
        visible.update(_default_red_visible_nodes(state))
    visible.update(node_name for node_name, node in state.network_nodes.items() if node.status == "Compromised")
    visible.update(
        node_name
        for node_name, node in state.network_nodes.items()
        if node.red_state.session_active or node.red_state.foothold or node.red_state.persistence
    )

    known_services: dict[str, tuple[int, ...]] = {}
    for node_name, ports in state.red_known_services.items():
        if node_name in visible:
            known_services[node_name] = tuple(sorted(set(int(port) for port in ports)))

    known_vulns: dict[str, tuple[str, ...]] = {}
    for node_name, vuln_map in state.red_known_vulnerabilities.items():
        if node_name not in visible:
            continue
        if isinstance(vuln_map, dict):
            vuln_ids = sorted(vuln_map.keys())
            if vuln_ids:
                known_vulns[node_name] = tuple(vuln_ids)

    compromised = tuple(
        sorted(
            node_name
            for node_name, node in state.network_nodes.items()
            if node.status == "Compromised" or node.red_state.session_active or node.red_state.foothold
        )
    )
    anchored = tuple(sorted(node_name for node_name in state.red_anchored_nodes if node_name in state.network_nodes))
    recon_nodes = tuple(sorted(set(state.red_recon_nodes)))
    return IntelPackage(
        visible_nodes=tuple(sorted(visible)),
        known_services=known_services,
        known_vulnerabilities=known_vulns,
        compromised_footholds=compromised,
        anchored_nodes=anchored,
        recon_nodes=recon_nodes,
        core_assets=_core_assets(state),
    )


def build_blue_intel_package(state: WorldState) -> dict[str, Any]:
    confirmed_vulns: dict[str, list[str]] = {}
    for node_name, vuln_map in state.blue_known_vulnerabilities.items():
        if not isinstance(vuln_map, dict):
            continue
        vuln_ids = [vuln_id for vuln_id in vuln_map.keys() if vuln_id]
        if vuln_ids:
            confirmed_vulns[node_name] = sorted(vuln_ids)

    node_risk: dict[str, str] = {}
    for node_name, node in state.network_nodes.items():
        if node.status == "Compromised":
            node_risk[node_name] = "CRIT"
        elif node.status == "Down":
            node_risk[node_name] = "WARN"
        elif node_name in state.core_assets:
            node_risk[node_name] = "ELEVATED"
        else:
            node_risk[node_name] = "LOW"

    return {
        "visible_topology_nodes": sorted(state.network_nodes.keys()),
        "node_status": {node_name: node.status for node_name, node in state.network_nodes.items()},
        "node_risk_levels": node_risk,
        "confirmed_vulnerabilities": confirmed_vulns,
        "monitored_nodes": sorted(set(state.blue_monitored_nodes)),
        "core_assets": list(_core_assets(state)),
        "winner_locked": bool(state.winner_locked),
    }


class ActionSpaceBuilder:
    def __init__(self, *, max_candidates: int = 12) -> None:
        self.max_candidates = max(8, max_candidates)

    def build_candidates(
        self,
        state: WorldState,
        *,
        agent_type: AgentType,
        recent_alerts: Iterable[SecurityAlert] | None = None,
        battle_state: dict[str, Any] | None = None,
        opponent_model: dict[str, Any] | None = None,
    ) -> list[CandidateAction]:
        candidates: list[CandidateAction] = []
        seen: set[tuple[str, str | None, str | None]] = set()
        battle_state = battle_state or {}
        opponent_model = opponent_model or {}
        intel_package = build_red_intel_package(state) if agent_type == "Red" else None
        target_pool = self._target_pool(state, agent_type=agent_type, intel_package=intel_package)
        blue_priority_stage = str(battle_state.get("blue_priority_stage", "P2"))

        for action in ACTION_REGISTRY.all():
            if action.agent_type != agent_type:
                continue
            if agent_type == "Red" and state.turn <= 0 and action.action_type != "Recon":
                continue
            if agent_type == "Blue" and action.action_type == "PreventivePatch" and blue_priority_stage != "P2":
                continue

            if not action.requires_target:
                proposed_targets: list[str | None] = [None]
                proposed_targets.extend(action.virtual_targets)
                if action.action_type == "Monitor":
                    proposed_targets.extend(sorted(state.network_nodes))
            else:
                proposed_targets = list(target_pool)
                proposed_targets.extend(action.virtual_targets)

            if agent_type == "Blue" and action.action_type == "PreventivePatch":
                proposed_targets = [
                    target
                    for target in proposed_targets
                    if self._allow_preventive_patch(
                        state,
                        target=target,
                        battle_state=battle_state,
                        recent_alerts=recent_alerts,
                    )
                ]
            if agent_type == "Blue":
                proposed_targets = [
                    target
                    for target in proposed_targets
                    if self._allow_blue_candidate(
                        state,
                        action_type=action.action_type,
                        target=target,
                        battle_state=battle_state,
                        recent_alerts=recent_alerts,
                    )
                ]

            for target in proposed_targets:
                vuln_candidates = self._vuln_candidates(
                    state,
                    target=target,
                    action_type=action.action_type,
                    agent_type=agent_type,
                    intel_package=intel_package,
                )
                if action.action_type in {
                    "Recon",
                    "RestoreNode",
                    "DeepRestore",
                    "Monitor",
                    "VulnerabilityScan",
                    "PreventivePatch",
                    "AnchorFoothold",
                    "ReactivateFoothold",
                }:
                    vuln_candidates = [None]

                for vuln_id in vuln_candidates:
                    draft = AgentDecision(
                        agent_type=agent_type,
                        thought=f"候选动作 {action.action_type}",
                        action_type=action.action_type,
                        target=target,
                        vuln_id=vuln_id,
                        payload=self._build_payload(
                            action_type=action.action_type,
                            target=target,
                            vuln_id=vuln_id,
                            agent_type=agent_type,
                        ),
                        raw_command=self._build_raw_command(
                            action_type=action.action_type,
                            target=target,
                            vuln_id=vuln_id,
                            agent_type=agent_type,
                        ),
                        defense_rule=self._build_defense_rule(
                            action_type=action.action_type,
                            target=target,
                            vuln_id=vuln_id,
                            agent_type=agent_type,
                        ),
                    )

                    validation_error = action.validate(
                        ActionContext(
                            state=state,
                            decision=draft,
                            locale="zh",
                            opposing_decision=None,
                        )
                    )
                    if validation_error is not None:
                        continue

                    # Some actions auto-resolve vuln_id during validation; sync payload to avoid semantic drift.
                    draft.payload = self._build_payload(
                        action_type=draft.action_type,
                        target=draft.target,
                        vuln_id=draft.vuln_id,
                        agent_type=agent_type,
                    )
                    draft.raw_command = self._build_raw_command(
                        action_type=draft.action_type,
                        target=draft.target,
                        vuln_id=draft.vuln_id,
                        agent_type=agent_type,
                    )
                    draft.defense_rule = self._build_defense_rule(
                        action_type=draft.action_type,
                        target=draft.target,
                        vuln_id=draft.vuln_id,
                        agent_type=agent_type,
                    )

                    key = (draft.action_type, draft.target, draft.vuln_id)
                    if key in seen:
                        continue
                    seen.add(key)

                    candidate = self._to_candidate(
                        state,
                        decision=draft,
                        agent_type=agent_type,
                        battle_state=battle_state,
                        recent_alerts=recent_alerts,
                        opponent_model=opponent_model,
                    )
                    candidates.append(candidate)

        candidates.sort(key=lambda row: (row.heuristic_score, row.expected_impact), reverse=True)
        if agent_type == "Red":
            candidates = self._rebalance_red_candidates(candidates)
        return candidates[: self.max_candidates]

    def _target_pool(
        self,
        state: WorldState,
        *,
        agent_type: AgentType,
        intel_package: IntelPackage | None = None,
    ) -> list[str]:
        if agent_type == "Blue":
            return sorted(state.network_nodes.keys())

        if intel_package is not None:
            return sorted(intel_package.visible_nodes)

        visible = set(state.red_visible_nodes)
        if not visible:
            visible.update(_default_red_visible_nodes(state))
        visible.update(node_name for node_name, node in state.network_nodes.items() if node.status == "Compromised")
        return sorted(visible)

    def _vuln_candidates(
        self,
        state: WorldState,
        *,
        target: str | None,
        action_type: str,
        agent_type: AgentType,
        intel_package: IntelPackage | None = None,
    ) -> list[str | None]:
        if not target or target not in state.network_nodes:
            return [None]

        if agent_type == "Red":
            if intel_package is None:
                intel_package = build_red_intel_package(state)
            known_vulns = intel_package.known_vulnerabilities.get(target, ())
            if not known_vulns:
                return [None]
            ranked_vulns = self._rank_known_vulnerabilities(
                state,
                target=target,
                known_vulns=known_vulns,
            )
            if action_type in RED_VULN_VARIANT_ACTIONS:
                return [None, *ranked_vulns[:MAX_RED_VULN_VARIANTS_PER_ACTION_TARGET]]
            return [None, *ranked_vulns[:2]]

        if action_type not in {"PatchNode", "Isolate"}:
            return [None]

        known_vuln_map = state.blue_known_vulnerabilities.get(target, {})
        if not isinstance(known_vuln_map, dict) or not known_vuln_map:
            return [None]

        node = state.network_nodes[target]
        min_confidence = 0.7 if action_type == "PatchNode" else 0.55
        ranked = sorted(
            [
                vuln_id
                for vuln_id in known_vuln_map.keys()
                if vuln_id in node.vulnerabilities
                and float(known_vuln_map.get(vuln_id, 0.0) or 0.0) >= min_confidence
            ],
            key=lambda vuln_id: (
                float(known_vuln_map.get(vuln_id, 0.0)),
                int(node.vulnerabilities[vuln_id].score),
                vuln_id,
            ),
            reverse=True,
        )
        if not ranked:
            return [None]
        return [None, *ranked[:3]]

    def _rank_known_vulnerabilities(
        self,
        state: WorldState,
        *,
        target: str,
        known_vulns: Iterable[str],
    ) -> list[str]:
        node = state.network_nodes.get(target)
        unique = sorted(set(str(vuln_id) for vuln_id in known_vulns if vuln_id))
        if node is None:
            return unique
        return sorted(
            unique,
            key=lambda vuln_id: (
                int(node.vulnerabilities[vuln_id].score) if vuln_id in node.vulnerabilities else -1,
                vuln_id,
            ),
            reverse=True,
        )

    def _rebalance_red_candidates(self, candidates: list[CandidateAction]) -> list[CandidateAction]:
        limited: list[CandidateAction] = []
        overflow: list[CandidateAction] = []
        per_target_variant_count: dict[str, int] = {}

        for row in candidates:
            action_type = row.decision.action_type
            target = row.decision.target or ""
            if action_type in RED_VULN_VARIANT_ACTIONS and target:
                current = per_target_variant_count.get(target, 0)
                if current >= MAX_RED_EXPLOIT_VARIANTS_PER_TARGET:
                    overflow.append(row)
                    continue
                per_target_variant_count[target] = current + 1
            limited.append(row)

        if len(limited) >= self.max_candidates:
            return limited
        limited.extend(overflow)
        return limited

    def _build_payload(
        self,
        *,
        action_type: str,
        target: str | None,
        vuln_id: str | None,
        agent_type: AgentType,
    ) -> str:
        scope = target or "network"
        if action_type == "Recon":
            return f"对 {scope} 执行侦察，补全服务与漏洞情报"
        if action_type == "ExploitService":
            return f"利用 vuln_id={vuln_id} 攻破 {scope} 的对外服务"
        if action_type == "LateralMove":
            return f"利用 vuln_id={vuln_id} 对 {scope} 横向推进"
        if action_type == "ExfiltrateDatabase":
            return f"利用 vuln_id={vuln_id} 对 {scope} 进行数据导出"
        if action_type == "AnchorFoothold":
            return f"在 {scope} 植入持久化扎根并保留再进入能力"
        if action_type == "ReactivateFoothold":
            return f"重激活 {scope} 的扎根据点恢复控制权"
        if action_type == "PatchNode":
            return f"修补 {scope} 上已确认漏洞 vuln_id={vuln_id}"
        if action_type == "PreventivePatch":
            return f"在平静窗口对 {scope} 执行预防性修补"
        if action_type == "RestoreNode":
            return f"恢复 {scope} 到业务可用状态"
        if action_type == "DeepRestore":
            return f"对 {scope} 执行深度恢复并清除持久化风险"
        if action_type == "Isolate":
            if vuln_id:
                return f"隔离 {scope} 并阻断 vuln_id={vuln_id} 攻击链"
            return f"隔离 {scope} 阻断攻击链"
        if action_type == "Monitor":
            if agent_type == "Blue":
                return f"监控 {scope} 并确认可处置漏洞线索"
            return f"监控 {scope}"
        if action_type == "VulnerabilityScan":
            return f"对 {scope} 执行目标化漏洞扫描并生成修补线索"
        return f"执行 {action_type} 于 {scope}"

    def _build_raw_command(
        self,
        *,
        action_type: str,
        target: str | None,
        vuln_id: str | None,
        agent_type: AgentType,
    ) -> str:
        if agent_type != "Red":
            return ""
        return build_red_raw_command(action_type=action_type, target=target, vuln_id=vuln_id)

    def _build_defense_rule(
        self,
        *,
        action_type: str,
        target: str | None,
        vuln_id: str | None,
        agent_type: AgentType,
    ) -> str:
        if agent_type != "Blue":
            return ""
        return build_blue_defense_rule(action_type=action_type, target=target, vuln_id=vuln_id)

    def _allow_preventive_patch(
        self,
        state: WorldState,
        *,
        target: str | None,
        battle_state: dict[str, Any],
        recent_alerts: Iterable[SecurityAlert] | None,
    ) -> bool:
        if not target or target not in state.network_nodes:
            return False
        if str(battle_state.get("blue_priority_stage", "P2")) != "P2":
            return False
        if state.turn - int(state.blue_last_preventive_patch_turn) < PREVENTIVE_PATCH_INTERVAL:
            return False
        available_turn = int(state.blue_preventive_patch_cooldowns.get(target, -999))
        if state.turn < available_turn:
            return False
        if state.turn <= TIER0_PROACTIVE_LOCK_ROUNDS and target in _core_assets(state):
            known_vuln_map = state.blue_known_vulnerabilities.get(target, {})
            has_evidence = bool(isinstance(known_vuln_map, dict) and known_vuln_map)
            if not has_evidence and recent_alerts:
                has_evidence = any(alert.target == target for alert in recent_alerts)
            if not has_evidence:
                return False
        return True

    def _allow_blue_candidate(
        self,
        state: WorldState,
        *,
        action_type: str,
        target: str | None,
        battle_state: dict[str, Any],
        recent_alerts: Iterable[SecurityAlert] | None,
    ) -> bool:
        if action_type not in {"RestoreNode", "DeepRestore", "Isolate"}:
            return True
        if not target or target not in state.network_nodes:
            return True

        node = state.network_nodes[target]
        has_red_activity = _has_red_activity(node)
        has_warn, has_crit = _recent_warn_or_crit(recent_alerts, target)
        blue_stage = str(battle_state.get("blue_priority_stage", "P2"))

        if action_type == "RestoreNode":
            if _recently_self_isolated(state, target) and node.status != "Compromised" and not has_red_activity:
                return False
            if node.status == "Isolated" and not has_red_activity:
                return int(state.turn) - int(node.blue_state.last_response_turn) > RECENT_SELF_ISOLATE_RESTORE_WINDOW
            return True

        if action_type == "DeepRestore":
            return node.status == "Compromised" or node.red_state.persistence or target in state.red_anchored_nodes or has_crit

        if action_type == "Isolate":
            if node.status == "Compromised" or has_red_activity or has_crit:
                return True
            if target in state.core_assets and blue_stage == "P0":
                return True
            # WARN-only pressure should usually be handled with patching or monitoring first.
            return False

        return True

    def _to_candidate(
        self,
        state: WorldState,
        *,
        decision: AgentDecision,
        agent_type: AgentType,
        battle_state: dict[str, Any],
        recent_alerts: Iterable[SecurityAlert] | None,
        opponent_model: dict[str, Any],
    ) -> CandidateAction:
        action_type = decision.action_type
        target = decision.target
        vuln_score = 0
        if target and target in state.network_nodes and decision.vuln_id:
            vulnerability = state.network_nodes[target].vulnerabilities.get(decision.vuln_id)
            if vulnerability is not None:
                vuln_score = int(vulnerability.score)
        vuln_value = max(0, min(30, vuln_score))
        asset_value = _asset_strategic_value(target)

        pressure_target = str(opponent_model.get("pressure_target", "") or "")
        pressure_bonus = 8 if pressure_target and target == pressure_target else 0

        if agent_type == "Red":
            objective_progress = {
                "ExfiltrateDatabase": 100,
                "ReactivateFoothold": 80,
                "LateralMove": 72,
                "ExploitService": 62,
                "AnchorFoothold": 66,
                "Recon": 18,
            }.get(action_type, 26)

            if action_type == "Recon" and target in state.red_recon_nodes:
                objective_progress -= 26
            if action_type == "ExploitService" and target and target in state.red_known_vulnerabilities:
                objective_progress += 16
            if action_type == "AnchorFoothold" and target and target in state.network_nodes:
                node = state.network_nodes[target]
                if node.red_state.session_active or node.red_state.foothold:
                    objective_progress += 18
            if target and target in state.network_nodes and state.network_nodes[target].status == "Compromised":
                if action_type in {"ExploitService", "LateralMove"}:
                    objective_progress -= 24

            path_reachability = self._estimate_path_reachability(state, target=target)
            u_red = (
                0.50 * objective_progress
                + 0.25 * asset_value
                + 0.15 * path_reachability
                + 0.10 * vuln_value
            )
            base_risk = {
                "ExfiltrateDatabase": 30,
                "LateralMove": 24,
                "ExploitService": 22,
                "AnchorFoothold": 14,
                "ReactivateFoothold": 18,
                "Recon": 6,
            }.get(action_type, 12)
            if action_type == "LateralMove" and not decision.vuln_id:
                base_risk += 12
                objective_progress -= 10
            expected_impact = u_red + pressure_bonus
            expected_risk = base_risk
            progress_value = objective_progress
            heuristic = expected_impact + progress_value * 0.20 - expected_risk
        else:
            blue_priority_stage = str(battle_state.get("blue_priority_stage", "P2"))
            base_impact = {
                "DeepRestore": 72,
                "RestoreNode": 68,
                "Isolate": 46,
                "PatchNode": 64,
                "PreventivePatch": 46,
                "Monitor": 20,
                "VulnerabilityScan": 34,
            }.get(action_type, 18)
            base_risk = {
                "DeepRestore": 34,
                "RestoreNode": 18,
                "Isolate": 42,
                "PatchNode": 12,
                "PreventivePatch": 22,
                "Monitor": 6,
                "VulnerabilityScan": 12,
            }.get(action_type, 10)
            progress_value = {
                "DeepRestore": 40,
                "RestoreNode": 38,
                "Isolate": 22,
                "PatchNode": 34,
                "PreventivePatch": 24,
                "Monitor": 12,
                "VulnerabilityScan": 26,
            }.get(action_type, 10)

            if action_type == "DeepRestore":
                has_anchor = bool(target and target in state.red_anchored_nodes)
                if has_anchor:
                    base_impact += 14
                    progress_value += 10
                elif target and target in state.network_nodes and state.network_nodes[target].status == "Compromised":
                    base_impact += 6
                else:
                    base_impact -= 10
                    progress_value -= 8

            if action_type == "Isolate" and target and target in state.network_nodes:
                node = state.network_nodes[target]
                has_warn, has_crit = _recent_warn_or_crit(recent_alerts, target)
                active_red_state = _has_red_activity(node)
                if node.status == "Compromised" or active_red_state or has_crit:
                    base_impact += 30
                    progress_value += 26
                    base_risk -= 8
                elif has_warn:
                    base_impact -= 18
                    progress_value -= 14
                    base_risk += 10
                else:
                    base_impact -= 40
                    progress_value -= 26
                    base_risk += 16

            if action_type == "RestoreNode" and target and target in state.network_nodes:
                node = state.network_nodes[target]
                if node.status == "Isolated" and not _has_red_activity(node):
                    base_impact -= 28
                    progress_value -= 22
                    base_risk += 8
                elif _has_red_activity(node):
                    base_impact += 16
                    progress_value += 14

            if blue_priority_stage == "P0":
                if action_type in BLUE_RESPONSE_ACTIONS:
                    base_impact += 18
                    progress_value += 12
                if action_type in {"Monitor", "PreventivePatch"}:
                    base_impact -= 24
            elif blue_priority_stage == "P1":
                if action_type in {"PatchNode", "Isolate", "RestoreNode", "DeepRestore"}:
                    base_impact += 10
                if action_type == "PreventivePatch":
                    base_impact -= 16
            else:
                if action_type == "PreventivePatch":
                    base_impact += 8
                if action_type == "Monitor":
                    base_impact += 4
                if action_type == "VulnerabilityScan":
                    base_impact += 8

            monitor_no_gain_streak = int(battle_state.get("monitor_no_gain_streak", 0) or 0)
            if action_type == "Monitor" and monitor_no_gain_streak > 0:
                progress_value -= 12 + monitor_no_gain_streak * 4

            alert_bonus = 0
            if recent_alerts:
                for alert in recent_alerts:
                    if not target or alert.target != target:
                        continue
                    if alert.severity == "CRIT":
                        alert_bonus += 16
                    elif alert.severity == "WARN":
                        alert_bonus += 8

            expected_impact = base_impact + asset_value * 0.32 + vuln_value * 0.20 + alert_bonus + pressure_bonus
            expected_risk = base_risk
            heuristic = expected_impact + progress_value - expected_risk

        digest = hashlib.md5(
            f"{decision.action_type}|{decision.target or ''}|{decision.vuln_id or ''}".encode("utf-8")
        ).hexdigest()[:6].upper()
        candidate_id = f"C{digest}"
        tags: list[str] = [action_type.lower()]
        if target:
            tags.append(f"target:{target}")
        if decision.vuln_id:
            tags.append("with_vuln")
        reason = f"{action_type} impact={expected_impact:.1f} risk={expected_risk:.1f} progress={progress_value:.1f}"
        return CandidateAction(
            candidate_id=candidate_id,
            decision=decision,
            expected_impact=expected_impact,
            expected_risk=expected_risk,
            progress_value=progress_value,
            heuristic_score=heuristic,
            tags=tuple(tags),
            reason=reason,
        )

    def _estimate_path_reachability(self, state: WorldState, *, target: str | None) -> float:
        if not target or target not in state.network_nodes:
            return 35.0

        node = state.network_nodes[target]
        if node.status == "Compromised":
            return 92.0

        compromised = {node_name for node_name, row in state.network_nodes.items() if row.status == "Compromised"}
        adjacency = _build_adjacency_map(state)
        if any(neighbor in compromised for neighbor in adjacency.get(target, [])):
            return 84.0

        if target in state.red_recon_nodes:
            return 70.0
        if target in state.red_visible_nodes:
            return 56.0
        return 32.0


class LLMPlanner:
    def __init__(
        self,
        *,
        max_retries: int = 1,
        max_candidate_rows: int = 6,
        max_context_chars: int = 1800,
        max_output_tokens: int = 280,
    ) -> None:
        self.max_retries = max(1, max_retries)
        self.max_candidate_rows = max(3, max_candidate_rows)
        self.max_context_chars = max(800, max_context_chars)
        self.max_output_tokens = max(80, max_output_tokens)

    def plan(
        self,
        *,
        client: Any,
        model_name: str,
        agent_type: AgentType,
        background_prompt: str,
        context_markdown: str,
        battle_state: dict[str, Any],
        opponent_model: dict[str, Any],
        reflections: list[dict[str, Any]],
        candidates: list[CandidateAction],
        intel_package: dict[str, Any] | None = None,
    ) -> PlannerDecision:
        if client is None:
            raise LLMDecisionError("缺少可用的 LLM 客户端。")
        if not candidates:
            raise LLMDecisionError("当前不存在可执行候选动作。")

        limited_candidates = sorted(candidates, key=lambda row: row.heuristic_score, reverse=True)[: self.max_candidate_rows]
        candidate_rows = [row.as_prompt_row() for row in limited_candidates]
        candidate_ids = {row["candidate_id"] for row in candidate_rows}
        role_goal = (
            "红方目标：优先推进到核心资产并实现战局胜利，分数只作参考。"
            if agent_type == "Red"
            else "蓝方目标：优先应对活跃威胁，平静期才允许预防性修补，并维持业务连续性。"
        )
        payload = {
            "agent_type": agent_type,
            "role_goal": role_goal,
            "protocol_requirement": "必须选择自带 raw_command/defense_rule 的候选，不允许生成候选外命令。",
            "battle_state": battle_state,
            "opponent_model": opponent_model,
            "recent_reflections": reflections[-2:],
            "intel_package": intel_package or {},
            "context_markdown": context_markdown[: self.max_context_chars],
            "candidates": candidate_rows,
            "output_schema": {
                "chosen_id": "str",
                "goal_tag": "core_objective|containment|recovery|intel_gain|anti_stagnation|risk_control",
                "risk_tag": "low|medium|high",
                "medium_reason": "str<=240chars",
                "short_reason": "str<=240chars (backward-compatible alias)",
                "backup_id": "str|optional",
            },
        }

        system_prompt = (
            "你是中文网络攻防对抗决策器。\n"
            "你必须结合当前战局和候选动作做取舍，禁止编造候选 ID。\n"
            "候选中的 raw_command / defense_rule 来自真实攻防命令模板库，禁止改写或二次创造。\n"
            "输出必须是严格 JSON，且仅包含 output_schema 允许字段。\n"
            "思考保持中等长度，覆盖目标、风险、依据，避免空泛与过短。\n"
            f"角色规则：\n{background_prompt}"
        )
        messages = [
            {"role": "system", "content": system_prompt},
            {"role": "user", "content": json.dumps(payload, ensure_ascii=False)},
        ]

        last_error: Exception | None = None
        for attempt in range(1, self.max_retries + 1):
            raw_text = ""
            try:
                response = client.chat.completions.create(
                    model=model_name,
                    messages=messages,
                    response_format={"type": "json_object"},
                    temperature=0.2,
                    top_p=0.8,
                    max_tokens=self.max_output_tokens,
                )
                raw_text = response.choices[0].message.content or ""
                parsed = json.loads(raw_text)
                chosen_id = str(
                    parsed.get("chosen_id")
                    or parsed.get("chosen_candidate_id")
                    or ""
                ).strip()
                if chosen_id not in candidate_ids:
                    chosen_id = self._recover_candidate_id(parsed, limited_candidates)
                if chosen_id not in candidate_ids:
                    raise ValueError(f"chosen_id 不在候选集合内: {chosen_id}")

                backup_raw = parsed.get("backup_id") or parsed.get("backup_candidate_id")
                backup_id = str(backup_raw).strip() if isinstance(backup_raw, str) and backup_raw else None
                if backup_id and backup_id not in candidate_ids:
                    backup_id = None

                goal_tag = str(parsed.get("goal_tag", "risk_control") or "risk_control")
                risk_tag = str(parsed.get("risk_tag", "medium") or "medium")
                medium_reason = str(
                    parsed.get("medium_reason")
                    or parsed.get("short_reason")
                    or ""
                ).strip()
                thought = f"goal={goal_tag}; risk={risk_tag}; reason={medium_reason[:240]}"
                return PlannerDecision(
                    chosen_candidate_id=chosen_id,
                    backup_candidate_id=backup_id,
                    thought=thought,
                    raw_payload=parsed,
                )
            except Exception as exc:
                last_error = exc
                if attempt >= self.max_retries:
                    break
                if raw_text:
                    messages.append({"role": "assistant", "content": raw_text})
                messages.append(
                    {
                        "role": "user",
                        "content": (
                            "上一条输出无效。"
                            f"错误原因：{exc}。"
                            f"请仅从这些候选ID选择 chosen_id：{sorted(candidate_ids)}，并保持 JSON 格式。"
                        ),
                    }
                )
                time.sleep(0.3)

        raise LLMDecisionError(f"{agent_type} 候选决策失败：{last_error}")

    def _recover_candidate_id(self, parsed: dict[str, Any], candidates: list[CandidateAction]) -> str:
        for field_name in ("top_candidates", "top3_candidates"):
            rows = parsed.get(field_name)
            if isinstance(rows, list):
                for row in rows:
                    if isinstance(row, dict):
                        candidate_id = str(row.get("candidate_id") or row.get("chosen_id") or "").strip()
                        if candidate_id and any(item.candidate_id == candidate_id for item in candidates):
                            return candidate_id

        action_type = str(parsed.get("action_type", "")).strip()
        target = parsed.get("target")
        vuln_id = parsed.get("vuln_id")
        if not action_type:
            selected = parsed.get("selected_action")
            if isinstance(selected, dict):
                action_type = str(selected.get("action_type", "")).strip()
                target = selected.get("target")
                vuln_id = selected.get("vuln_id")
        if not action_type:
            return ""

        target_str = target if isinstance(target, str) and target else None
        vuln_str = vuln_id if isinstance(vuln_id, str) and vuln_id else None
        exact = [
            item
            for item in candidates
            if item.decision.action_type == action_type
            and item.decision.target == target_str
            and item.decision.vuln_id == vuln_str
        ]
        if exact:
            exact.sort(key=lambda item: item.heuristic_score, reverse=True)
            return exact[0].candidate_id
        same_action = [item for item in candidates if item.decision.action_type == action_type]
        if same_action:
            same_action.sort(key=lambda item: item.heuristic_score, reverse=True)
            return same_action[0].candidate_id
        return ""


class OpponentModeler:
    def __init__(self, *, self_agent_type: AgentType, max_history: int = 12) -> None:
        self.self_agent_type = self_agent_type
        self.max_history = max(6, max_history)
        self._history: list[dict[str, Any]] = []
        self._last_observed_turn = -1

    def observe(self, state: WorldState) -> None:
        if state.turn <= self._last_observed_turn:
            return
        for log in state.action_logs:
            if log.agent_type not in {"Red", "Blue"}:
                continue
            if log.agent_type == self.self_agent_type:
                continue
            metadata = log.metadata if isinstance(log.metadata, dict) else {}
            self._history.append(
                {
                    "turn": state.turn,
                    "action_type": log.action_type,
                    "target": metadata.get("target"),
                    "effect": metadata.get("referee_effect"),
                    "score_awarded": metadata.get("score_awarded", 0),
                }
            )
        self._history = self._history[-self.max_history :]
        self._last_observed_turn = state.turn

    def build(self) -> dict[str, Any]:
        action_counts: dict[str, int] = {}
        target_counts: dict[str, int] = {}
        recent = self._history[-6:]
        for row in recent:
            action_type = str(row.get("action_type", "Unknown"))
            action_counts[action_type] = action_counts.get(action_type, 0) + 1
            target = row.get("target")
            if isinstance(target, str) and target:
                target_counts[target] = target_counts.get(target, 0) + 1

        pressure_target = None
        if target_counts:
            pressure_target = max(target_counts.items(), key=lambda item: item[1])[0]

        inferred_phase = "reconnaissance"
        if action_counts.get("ExfiltrateDatabase", 0) > 0:
            inferred_phase = "objective_push"
        elif action_counts.get("LateralMove", 0) > 0 or action_counts.get("ExploitService", 0) > 0:
            inferred_phase = "intrusion"
        elif action_counts.get("DeepRestore", 0) > 0 or action_counts.get("RestoreNode", 0) > 0:
            inferred_phase = "recovery"

        return {
            "recent_actions": recent,
            "action_counts": action_counts,
            "target_counts": target_counts,
            "pressure_target": pressure_target,
            "inferred_phase": inferred_phase,
        }


class ReflectionEngine:
    def __init__(self, *, self_agent_type: AgentType, max_items: int = 8) -> None:
        self.self_agent_type = self_agent_type
        self.max_items = max(4, max_items)
        self._records: list[dict[str, Any]] = []
        self._last_observed_turn = -1
        self._last_expected: dict[str, Any] | None = None

    def set_expected(self, *, decision: AgentDecision, candidate_id: str, thought: str) -> None:
        self._last_expected = {
            "action_type": decision.action_type,
            "target": decision.target,
            "vuln_id": decision.vuln_id,
            "candidate_id": candidate_id,
            "thought": thought,
        }

    def observe(self, state: WorldState) -> None:
        if state.turn <= self._last_observed_turn:
            return
        own_log = next((log for log in state.action_logs if log.agent_type == self.self_agent_type), None)
        if own_log is None:
            self._last_observed_turn = state.turn
            return

        metadata = own_log.metadata if isinstance(own_log.metadata, dict) else {}
        score_awarded = int(metadata.get("score_awarded", 0) or 0)
        success = metadata.get("validation") == "passed" and metadata.get("execution") != "failed_after_judgement"
        effect = str(metadata.get("referee_effect", "unknown"))
        is_failure = not success or score_awarded <= 0

        # 控制 token 成本：仅每 2 回合短反思一次；但失败回合仍强制记录。
        if state.turn % 2 != 0 and not is_failure:
            self._last_observed_turn = state.turn
            return

        if not success:
            adjustment = "动作未生效，下回合切换目标或动作级别。"
        elif own_log.action_type in {"Recon", "Monitor"} and score_awarded == 0:
            adjustment = "被动动作收益不足，下回合转向推进/处置动作。"
        elif score_awarded == 0:
            adjustment = "收益偏低，下回合优化目标。"
        else:
            adjustment = "策略有效，继续保持并防止重复。"

        self._records.append(
            {
                "turn": state.turn,
                "expected": self._last_expected or {},
                "actual": {
                    "action_type": own_log.action_type,
                    "target": metadata.get("target"),
                    "vuln_id": metadata.get("vuln_id"),
                    "score_awarded": score_awarded,
                    "effect": effect,
                    "success": success,
                },
                "adjustment": adjustment,
            }
        )
        self._records = self._records[-self.max_items :]
        self._last_observed_turn = state.turn

    def recent(self, limit: int = 3) -> list[dict[str, Any]]:
        return self._records[-max(1, limit) :]

    def failure_streak(self, *, limit: int = 4) -> int:
        streak = 0
        for row in reversed(self._records[-max(1, limit) :]):
            actual = row.get("actual", {})
            if actual.get("success") and int(actual.get("score_awarded", 0) or 0) > 0:
                break
            streak += 1
        return streak


class AntiStagnationController:
    def __init__(
        self,
        *,
        self_agent_type: AgentType,
        max_recon_streak: int = 2,
        max_anchor_streak: int = 1,
        max_monitor_streak: int = 2,
        max_monitor_no_gain_streak: int = 2,
        no_progress_threshold: int = 3,
    ) -> None:
        self.self_agent_type = self_agent_type
        self.max_recon_streak = max(1, max_recon_streak)
        self.max_anchor_streak = max(1, max_anchor_streak)
        self.max_monitor_streak = max(1, max_monitor_streak)
        self.max_monitor_no_gain_streak = max(1, max_monitor_no_gain_streak)
        self.no_progress_threshold = max(2, no_progress_threshold)

        self._last_action_type: str | None = None
        self._action_streak = 0
        self._last_progress_signature: tuple[Any, ...] | None = None
        self._no_progress_rounds = 0
        self._monitor_no_gain_streak = 0
        self._zero_score_streak = 0
        self._red_attacked_targets: set[str] = set()
        self._red_used_vuln_ids: set[str] = set()
        self._last_recon_target: str | None = None
        self._recon_same_target_streak = 0
        self._last_monitor_target: str | None = None
        self._monitor_same_target_no_gain_streak = 0
        self._last_observed_turn = -1

    def observe_state(self, state: WorldState) -> None:
        if state.turn <= self._last_observed_turn:
            return

        compromised_count = sum(1 for node in state.network_nodes.values() if node.status == "Compromised")
        if self.self_agent_type == "Red":
            signature = (
                state.red_score,
                compromised_count,
                len(state.red_anchored_nodes),
                int(state.winner_locked),
            )
        else:
            signature = (
                state.blue_score,
                state.system_health,
                state.exposure_level,
                len(state.blue_known_vulnerabilities),
            )

        if self._last_progress_signature == signature:
            self._no_progress_rounds += 1
        else:
            self._no_progress_rounds = 0
        self._last_progress_signature = signature

        own_log = next((log for log in state.action_logs if log.agent_type == self.self_agent_type), None)
        if own_log is not None:
            metadata = own_log.metadata if isinstance(own_log.metadata, dict) else {}
            score_awarded = int(metadata.get("score_awarded", 0) or 0)
            if score_awarded <= 0:
                self._zero_score_streak += 1
            else:
                self._zero_score_streak = 0

            target = metadata.get("target")
            target = target.strip() if isinstance(target, str) else ""

            if self.self_agent_type == "Red":
                if own_log.action_type == "Recon":
                    if target and target == self._last_recon_target:
                        self._recon_same_target_streak += 1
                    else:
                        self._last_recon_target = target or None
                        self._recon_same_target_streak = 1 if target else 0
                elif own_log.action_type != "Recon":
                    self._last_recon_target = None
                    self._recon_same_target_streak = 0

                if own_log.action_type in RED_ATTACK_ACTIONS and target:
                    self._red_attacked_targets.add(target)
                    vuln_id = metadata.get("vuln_id")
                    if isinstance(vuln_id, str) and vuln_id:
                        self._red_used_vuln_ids.add(vuln_id)

            if self.self_agent_type == "Blue":
                if own_log.action_type == "Monitor":
                    intel_gain = bool(metadata.get("intel_gain", False))
                    monitor_target = metadata.get("monitor_scope")
                    if not isinstance(monitor_target, str) or not monitor_target.strip():
                        monitor_target = target
                    monitor_target = monitor_target.strip() if isinstance(monitor_target, str) else ""

                    if intel_gain:
                        self._monitor_no_gain_streak = 0
                        self._monitor_same_target_no_gain_streak = 0
                        self._last_monitor_target = monitor_target or None
                    else:
                        self._monitor_no_gain_streak += 1
                        if monitor_target and monitor_target == self._last_monitor_target:
                            self._monitor_same_target_no_gain_streak += 1
                        else:
                            self._last_monitor_target = monitor_target or None
                            self._monitor_same_target_no_gain_streak = 1 if monitor_target else 0
                elif own_log.action_type != "Monitor":
                    self._monitor_no_gain_streak = 0
                    self._monitor_same_target_no_gain_streak = 0
                    self._last_monitor_target = None

        self._last_observed_turn = state.turn

    def observe_decision(self, action_type: str, target: str | None = None) -> None:
        if self._last_action_type == action_type:
            self._action_streak += 1
        else:
            self._last_action_type = action_type
            self._action_streak = 1

    def no_progress_rounds(self) -> int:
        return self._no_progress_rounds

    def monitor_no_gain_streak(self) -> int:
        return self._monitor_no_gain_streak

    def apply(
        self,
        candidates: list[CandidateAction],
        *,
        state: WorldState,
        battle_state: dict[str, Any],
    ) -> list[CandidateAction]:
        if not candidates:
            return []
        filtered = list(candidates)

        if self.self_agent_type == "Red" and self._last_action_type == "Recon" and self._action_streak >= self.max_recon_streak:
            non_recon = [row for row in filtered if row.decision.action_type != "Recon"]
            if non_recon:
                filtered = non_recon
        if (
            self.self_agent_type == "Red"
            and self._last_recon_target
            and self._recon_same_target_streak >= self.max_recon_streak
        ):
            switched_recon = [
                row
                for row in filtered
                if not (row.decision.action_type == "Recon" and row.decision.target == self._last_recon_target)
            ]
            if switched_recon:
                filtered = switched_recon

        if (
            self.self_agent_type == "Red"
            and self._last_action_type == "AnchorFoothold"
            and self._action_streak >= self.max_anchor_streak
        ):
            non_anchor = [row for row in filtered if row.decision.action_type != "AnchorFoothold"]
            if non_anchor:
                filtered = non_anchor

        if self.self_agent_type == "Red":
            has_active_control = any(
                node.status == "Compromised"
                or node.red_state.session_active
                or node.red_state.foothold
                or node.red_state.persistence
                for node in state.network_nodes.values()
            )
            if not has_active_control:
                initial_access_rows = [row for row in filtered if row.decision.action_type == "ExploitService"]
                if initial_access_rows:
                    # Once reconnaissance confirms a legal entry exploit, advance the kill chain.
                    filtered = initial_access_rows

            lateral_rows = [
                row
                for row in filtered
                if row.decision.action_type == "LateralMove"
                and self._is_strong_lateral_candidate(state, row)
            ]
            internal_compromised = any(
                (
                    node.status == "Compromised"
                    or node.red_state.session_active
                    or node.red_state.foothold
                    or node.red_state.persistence
                )
                and not _is_perimeter_node(node_name)
                for node_name, node in state.network_nodes.items()
            )
            # Prefer depth only when the lateral candidate carries a concrete vuln or target credential signal.
            if lateral_rows and not internal_compromised:
                filtered = lateral_rows

        if self.self_agent_type == "Blue" and self._last_action_type == "Monitor" and self._action_streak >= self.max_monitor_streak:
            non_monitor = [row for row in filtered if row.decision.action_type != "Monitor"]
            if non_monitor:
                filtered = non_monitor

        if (
            self.self_agent_type == "Blue"
            and self._last_monitor_target
            and self._monitor_same_target_no_gain_streak > self.max_monitor_no_gain_streak
        ):
            switched_target = [
                row
                for row in filtered
                if not (row.decision.action_type == "Monitor" and row.decision.target == self._last_monitor_target)
            ]
            if switched_target:
                filtered = switched_target

        if self._no_progress_rounds >= self.no_progress_threshold:
            if self.self_agent_type == "Red":
                progressive = [row for row in filtered if row.decision.action_type not in RED_PASSIVE_ACTIONS]
            else:
                progressive = [row for row in filtered if row.decision.action_type not in BLUE_PASSIVE_ACTIONS]
            if progressive:
                filtered = progressive

        if self.self_agent_type == "Red" and self._zero_score_streak >= 3:
            progressive = [row for row in filtered if row.decision.action_type not in RED_PASSIVE_ACTIONS]
            if progressive:
                filtered = progressive

            untried_targets = [
                row
                for row in filtered
                if row.decision.action_type in RED_ATTACK_ACTIONS
                and row.decision.target
                and row.decision.target not in self._red_attacked_targets
            ]
            if untried_targets:
                filtered = untried_targets

            unused_vuln_rows: list[tuple[CandidateAction, int]] = []
            for row in filtered:
                vuln_id = row.decision.vuln_id
                target = row.decision.target
                if not vuln_id or vuln_id in self._red_used_vuln_ids or not target:
                    continue
                vuln_score = self._vuln_score(state, target=target, vuln_id=vuln_id)
                if vuln_score >= 0:
                    unused_vuln_rows.append((row, vuln_score))
            if unused_vuln_rows:
                best_score = max(score for _, score in unused_vuln_rows)
                filtered = [row for row, score in unused_vuln_rows if score == best_score]

        if self.self_agent_type == "Blue" and battle_state.get("blue_priority_stage") == "P0":
            prioritized = [row for row in filtered if row.decision.action_type in BLUE_RESPONSE_ACTIONS]
            if prioritized:
                filtered = prioritized

        if (
            self.self_agent_type == "Blue"
            and int(battle_state.get("exposure_level", 100) or 100) < 50
            and not battle_state.get("compromised_nodes")
        ):
            preventive_patch = [row for row in filtered if row.decision.action_type == "PreventivePatch"]
            if preventive_patch:
                filtered = preventive_patch
            else:
                non_monitor_isolate = [
                    row for row in filtered if row.decision.action_type not in {"Monitor", "Isolate"}
                ]
                if non_monitor_isolate:
                    filtered = non_monitor_isolate

        filtered.sort(key=lambda row: (row.heuristic_score, row.candidate_id), reverse=True)
        return filtered

    def _vuln_score(self, state: WorldState, *, target: str, vuln_id: str) -> int:
        node = state.network_nodes.get(target)
        if node is None:
            return -1
        vulnerability = node.vulnerabilities.get(vuln_id)
        if vulnerability is None:
            return -1
        return int(vulnerability.score)

    def _is_strong_lateral_candidate(self, state: WorldState, row: CandidateAction) -> bool:
        target = row.decision.target
        if not target or target not in state.network_nodes:
            return False
        node = state.network_nodes[target]
        return bool(row.decision.vuln_id or node.red_state.credential_known)


class FallbackPlanner:
    def choose(
        self,
        *,
        candidates: list[CandidateAction],
        agent_type: AgentType,
        opponent_model: dict[str, Any],
        reflections: list[dict[str, Any]],
    ) -> CandidateAction:
        if not candidates:
            raise LLMDecisionError("FallbackPlanner 无可执行候选动作。")

        pressure_target = opponent_model.get("pressure_target")
        last_adjustment = ""
        if reflections:
            last_adjustment = str(reflections[-1].get("adjustment", ""))

        def score(row: CandidateAction) -> tuple[float, str]:
            base = float(row.heuristic_score)
            if pressure_target and row.decision.target == pressure_target:
                base += 6
            if agent_type == "Red" and row.decision.action_type == "Recon":
                base -= 10
            if agent_type == "Red" and row.decision.action_type == "AnchorFoothold":
                base -= 6
            if agent_type == "Blue" and row.decision.action_type == "Monitor":
                base -= 10
            if "转向推进" in last_adjustment and row.decision.action_type in {"Recon", "AnchorFoothold", "Monitor"}:
                base -= 8
            return (base, row.candidate_id)

        return sorted(candidates, key=score, reverse=True)[0]


def build_battle_state(
    state: WorldState,
    *,
    agent_type: AgentType,
    failure_streak: int,
    no_progress_rounds: int,
    recent_alerts: Iterable[SecurityAlert] | None = None,
    monitor_no_gain_streak: int = 0,
) -> dict[str, Any]:
    controlled_nodes = sorted(
        node_name
        for node_name, node in state.network_nodes.items()
        if node.status == "Compromised"
        or node.red_state.session_active
        or node.red_state.foothold
        or node.red_state.persistence
    )
    compromised_nodes = sorted(node_name for node_name, node in state.network_nodes.items() if node.status == "Compromised")
    down_nodes = sorted(node_name for node_name, node in state.network_nodes.items() if node.status == "Down")
    core_assets = list(_core_assets(state))
    core_compromised = [node_name for node_name in compromised_nodes if node_name in core_assets]
    adjacency = _build_adjacency_map(state)
    compromised_perimeter = [node_name for node_name in controlled_nodes if _is_perimeter_node(node_name)]
    compromised_internal = [node_name for node_name in controlled_nodes if node_name not in compromised_perimeter]
    shortest_hops_to_core = _shortest_hops_to_core(
        adjacency=adjacency,
        starts=controlled_nodes,
        cores=set(core_assets),
    )

    if agent_type == "Red":
        killchain_phase = "recon"
        if compromised_perimeter:
            killchain_phase = "foothold"
        if compromised_internal:
            killchain_phase = "lateral"
        if shortest_hops_to_core is not None and shortest_hops_to_core <= 1 and not core_compromised:
            killchain_phase = "lateral"
        if any(node_name in compromised_nodes for node_name in core_assets):
            killchain_phase = "objective"
    else:
        killchain_phase = "stabilize"
        if core_compromised:
            killchain_phase = "containment"
        elif down_nodes:
            killchain_phase = "restoration"

    pressure_targets: list[str] = []
    high_alert = False
    medium_alert = False
    if recent_alerts:
        for alert in recent_alerts:
            if alert.target:
                pressure_targets.append(alert.target)
            if alert.severity == "CRIT":
                high_alert = True
            elif alert.severity == "WARN":
                medium_alert = True

    blue_priority_stage = "P2"
    if high_alert or core_compromised:
        blue_priority_stage = "P0"
    elif medium_alert:
        blue_priority_stage = "P1"

    return {
        "turn": state.turn,
        "agent_type": agent_type,
        "system_health": state.system_health,
        "exposure_level": state.exposure_level,
        "red_score": state.red_score,
        "blue_score": state.blue_score,
        "compromised_nodes": compromised_nodes,
        "controlled_nodes": controlled_nodes,
        "compromised_perimeter_nodes": compromised_perimeter,
        "compromised_internal_nodes": compromised_internal,
        "down_nodes": down_nodes,
        "core_assets": core_assets,
        "core_assets_compromised": core_compromised,
        "shortest_hops_to_core": shortest_hops_to_core,
        "red_anchored_nodes": list(state.red_anchored_nodes),
        "winner_locked": bool(state.winner_locked),
        "winner_side": state.winner_side,
        "killchain_phase": killchain_phase,
        "failure_streak": failure_streak,
        "no_progress_rounds": no_progress_rounds,
        "monitor_no_gain_streak": monitor_no_gain_streak,
        "pressure_targets": pressure_targets,
        "blue_priority_stage": blue_priority_stage,
    }
