from __future__ import annotations

from dataclasses import dataclass
from typing import Any

from backend_engine.core.models import WorldState


PERIMETER_ENTRY_TARGETS = ("fw", "web", "vpn")
STRICT_ATTACK_PREDECESSORS: dict[str, tuple[str, ...]] = {
    "web": ("fw",),
    "vpn": ("fw",),
    "app": ("web", "dev"),
    "office_pc": ("vpn",),
    "dev": ("office_pc",),
    "storage": ("app", "dev"),
    "db": ("app", "storage"),
}


@dataclass(slots=True, frozen=True)
class AttackTechnique:
    action_type: str
    technique_id: str
    name: str
    phase: str
    source_requirement: str
    target_requirement: str
    required_access: str
    required_credential: str
    required_service: str
    required_vulnerability: str
    blocked_by: tuple[str, ...]
    success_effect: tuple[str, ...]
    failure_effect: tuple[str, ...]
    score_value: int

    def as_dict(self) -> dict[str, Any]:
        return {
            "action_type": self.action_type,
            "technique_id": self.technique_id,
            "name": self.name,
            "phase": self.phase,
            "source_requirement": self.source_requirement,
            "target_requirement": self.target_requirement,
            "required_access": self.required_access,
            "required_credential": self.required_credential,
            "required_service": self.required_service,
            "required_vulnerability": self.required_vulnerability,
            "blocked_by": list(self.blocked_by),
            "success_effect": list(self.success_effect),
            "failure_effect": list(self.failure_effect),
            "score_value": self.score_value,
        }


@dataclass(slots=True, frozen=True)
class AttackGraphEvaluation:
    technique: AttackTechnique
    target: str
    allowed: bool
    source: str = ""
    source_candidates: tuple[str, ...] = ()
    active_blockers: tuple[str, ...] = ()
    credential_known: bool = False
    reusable_token: bool = False
    target_vulnerability: bool = False
    service_open: bool = False
    success_level: str = "none"

    def as_metadata(self, *, score_value: int | None = None) -> dict[str, Any]:
        payload = self.technique.as_dict()
        payload.update(
            {
                "allowed": self.allowed,
                "target": self.target,
                "source": self.source,
                "source_candidates": list(self.source_candidates),
                "active_blockers": list(self.active_blockers),
                "credential_known": self.credential_known,
                "reusable_token": self.reusable_token,
                "target_vulnerability": self.target_vulnerability,
                "service_open": self.service_open,
                "success_level": self.success_level,
                "score_value": self.technique.score_value if score_value is None else score_value,
            }
        )
        return {
            "attack_graph": payload,
            "technique_id": self.technique.technique_id,
            "technique_name": self.technique.name,
            "attack_phase": self.technique.phase,
            "success_effect": list(self.technique.success_effect),
            "failure_effect": list(self.technique.failure_effect),
        }


ATTACK_TECHNIQUES: dict[str, AttackTechnique] = {
    "ExploitService": AttackTechnique(
        action_type="ExploitService",
        technique_id="T1190",
        name="Exploit Public-Facing Application",
        phase="Initial Access",
        source_requirement="internet-facing",
        target_requirement="has_vulnerability",
        required_access="none",
        required_credential="none",
        required_service="service_open",
        required_vulnerability="target_vuln",
        blocked_by=("waf", "patched_vuln", "isolated"),
        success_effect=("SessionActive",),
        failure_effect=("NoSession",),
        score_value=20,
    ),
    "LateralMove": AttackTechnique(
        action_type="LateralMove",
        technique_id="T1021",
        name="Remote Services Lateral Movement",
        phase="Lateral Movement",
        source_requirement="SessionActive/Foothold/Persistence/Compromised",
        target_requirement="reachable + service_open",
        required_access="source_session",
        required_credential="CredentialKnown or target_vuln or reusable_token",
        required_service="service_open",
        required_vulnerability="target_vuln optional when CredentialKnown is present",
        blocked_by=("isolate_source", "isolate_target", "edr", "credential_reset"),
        success_effect=("SessionActive", "Foothold", "Compromised"),
        failure_effect=("NoSession",),
        score_value=16,
    ),
}


def get_attack_technique(action_type: str) -> AttackTechnique | None:
    return ATTACK_TECHNIQUES.get(action_type)


def describe_attack_graph_rules(action_type: str) -> dict[str, Any] | None:
    technique = get_attack_technique(action_type)
    if technique is None:
        return None
    return technique.as_dict()


def evaluate_attack_step(
    state: WorldState,
    *,
    action_type: str,
    target: str,
    vuln_id: str | None = None,
    payload: str = "",
) -> AttackGraphEvaluation | None:
    technique = get_attack_technique(action_type)
    if technique is None:
        return None
    if action_type == "ExploitService":
        return _evaluate_initial_access(state, technique=technique, target=target, vuln_id=vuln_id)
    if action_type == "LateralMove":
        return _evaluate_lateral_movement(
            state,
            technique=technique,
            target=target,
            vuln_id=vuln_id,
            payload=payload,
        )
    return None


def _evaluate_initial_access(
    state: WorldState,
    *,
    technique: AttackTechnique,
    target: str,
    vuln_id: str | None,
) -> AttackGraphEvaluation:
    node = state.network_nodes.get(target)
    blockers: list[str] = []
    service_open = False
    target_vulnerability = False

    if node is None:
        blockers.append("unknown_target")
    else:
        service_open = bool(node.exposed_ports)
        target_vulnerability = bool(vuln_id and vuln_id in node.vulnerabilities)
        if target.lower() not in PERIMETER_ENTRY_TARGETS:
            blockers.append("not_internet_facing")
        if _is_isolated(node):
            blockers.append("isolated")
        if not service_open:
            blockers.append("service_closed")
        if not target_vulnerability:
            blockers.append("patched_vuln")

    return AttackGraphEvaluation(
        technique=technique,
        target=target,
        allowed=not blockers,
        active_blockers=tuple(blockers),
        target_vulnerability=target_vulnerability,
        service_open=service_open,
        success_level="session" if not blockers else "none",
    )


def _evaluate_lateral_movement(
    state: WorldState,
    *,
    technique: AttackTechnique,
    target: str,
    vuln_id: str | None,
    payload: str,
) -> AttackGraphEvaluation:
    node = state.network_nodes.get(target)
    blockers: list[str] = []
    service_open = False
    target_vulnerability = False
    credential_known = _credential_known(payload)
    reusable_token = False
    source_candidates = _source_candidates_for_target(state, target)
    source = source_candidates[0] if source_candidates else ""

    if node is None:
        blockers.append("unknown_target")
    else:
        service_open = bool(node.exposed_ports)
        target_vulnerability = bool(vuln_id and vuln_id in node.vulnerabilities)
        credential_known = credential_known or node.red_state.credential_known
        if source:
            source_node = state.network_nodes.get(source)
            reusable_token = bool(source_node and source_node.red_state.credential_known)
        if _is_isolated(node):
            blockers.append("isolate_target")
        if not service_open:
            blockers.append("service_closed")
        if not source:
            blockers.append(_missing_source_blocker(state, target))
        if not _has_edge(state, source, target):
            blockers.append("not_reachable")
        if not credential_known and not target_vulnerability and not reusable_token:
            blockers.append("credential_reset")

    return AttackGraphEvaluation(
        technique=technique,
        target=target,
        allowed=not blockers,
        source=source,
        source_candidates=source_candidates,
        active_blockers=tuple(blockers),
        credential_known=credential_known,
        reusable_token=reusable_token,
        target_vulnerability=target_vulnerability,
        service_open=service_open,
        success_level=_success_level(target_vulnerability=target_vulnerability, credential_known=credential_known, reusable_token=reusable_token) if not blockers else "none",
    )


def _credential_known(payload: str) -> bool:
    normalized = payload.lower()
    return any(
        token in normalized
        for token in (
            "credentialknown",
            "credential_known",
            "credential=",
            "cred=",
            "stolen credential",
            "known credential",
        )
    )


def _source_candidates_for_target(state: WorldState, target: str) -> tuple[str, ...]:
    candidate_names = _candidate_source_names(state, target)
    usable: list[str] = []
    for node_name in candidate_names:
        node = state.network_nodes.get(node_name)
        if node is None or _is_isolated(node):
            continue
        red_state = node.red_state
        if (
            node.status == "Compromised"
            or red_state.session_active
            or red_state.foothold
            or red_state.persistence
            or node_name in state.red_anchored_nodes
        ):
            usable.append(node_name)
    return tuple(sorted(usable))


def _candidate_source_names(state: WorldState, target: str) -> tuple[str, ...]:
    strict = STRICT_ATTACK_PREDECESSORS.get(target.lower())
    if strict:
        return strict

    neighbors: set[str] = set()
    for edge in state.edges:
        if edge.source == target:
            neighbors.add(edge.target)
        elif edge.target == target:
            neighbors.add(edge.source)
    return tuple(sorted(neighbors))


def _missing_source_blocker(state: WorldState, target: str) -> str:
    for node_name in _candidate_source_names(state, target):
        node = state.network_nodes.get(node_name)
        if node is not None and _is_isolated(node):
            return "isolate_source"
    return "source_requirement"


def _is_isolated(node: Any) -> bool:
    return node.status in {"Down", "Isolated"} or bool(node.blue_state.isolated)


def _has_edge(state: WorldState, source: str, target: str) -> bool:
    if not source:
        return True
    return any(
        (edge.source == source and edge.target == target)
        or (edge.source == target and edge.target == source)
        for edge in state.edges
    )


def _success_level(*, target_vulnerability: bool, credential_known: bool, reusable_token: bool) -> str:
    if target_vulnerability and (credential_known or reusable_token):
        return "high"
    if target_vulnerability:
        return "medium"
    if credential_known or reusable_token:
        return "light"
    return "none"
