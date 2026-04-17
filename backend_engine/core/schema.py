from typing import Any, Dict, List, Literal, Optional

from pydantic import BaseModel, Field, field_validator, model_validator


class VulnerabilityInfo(BaseModel):
    vuln_id: str = Field(..., description="Unique vulnerability identifier.")
    severity: str = Field(..., description="Severity label such as High/Medium/Low.")
    score: int = Field(..., ge=0, description="Score awarded when this vulnerability is successfully used or fixed.")
    exploit_prob: float = Field(..., ge=0.0, le=1.0, description="Probability of successful exploitation.")
    patch_prob: float = Field(..., ge=0.0, le=1.0, description="Probability of successful patching.")


def _default_vulnerability_info(vuln_id: str) -> VulnerabilityInfo:
    return VulnerabilityInfo(
        vuln_id=vuln_id,
        severity="Medium",
        score=10,
        exploit_prob=0.7,
        patch_prob=0.8,
    )


def _coerce_vulnerability_map(value: Any) -> Dict[str, VulnerabilityInfo]:
    if value is None:
        return {}

    if isinstance(value, list):
        return {vuln_id: _default_vulnerability_info(vuln_id) for vuln_id in value}

    if isinstance(value, dict):
        result: Dict[str, VulnerabilityInfo] = {}
        for key, raw in value.items():
            if isinstance(raw, VulnerabilityInfo):
                result[key] = raw
                continue

            if isinstance(raw, str):
                result[key] = _default_vulnerability_info(raw)
                continue

            if isinstance(raw, dict):
                payload = dict(raw)
                payload.setdefault("vuln_id", key)
                result[key] = VulnerabilityInfo.model_validate(payload)
                continue

            raise TypeError(f"Unsupported vulnerability payload for {key}: {type(raw)!r}")
        return result

    raise TypeError(f"Unsupported vulnerabilities value: {type(value)!r}")


class NetworkNode(BaseModel):
    status: Literal["Normal", "Compromised", "Down"] = Field(
        ...,
        description="Current node status.",
    )
    exposed_ports: List[int] = Field(default_factory=list)
    vulnerabilities: Dict[str, VulnerabilityInfo] = Field(default_factory=dict)

    @field_validator("status", mode="before")
    @classmethod
    def _coerce_legacy_status(cls, value: Any) -> Any:
        if value == "Defended":
            return "Normal"
        return value

    @field_validator("vulnerabilities", mode="before")
    @classmethod
    def _coerce_vulnerabilities(cls, value: Any) -> Dict[str, VulnerabilityInfo]:
        return _coerce_vulnerability_map(value)


class TopologyEdge(BaseModel):
    source: str = Field(..., description="The source node id.")
    target: str = Field(..., description="The target node id.")


class ActionLog(BaseModel):
    agent_type: Literal["Red", "Blue", "Referee"] = Field(...)
    thought: str = Field(...)
    action_type: str = Field(...)
    payload: str = Field(...)
    referee_result: str = Field(...)
    metadata: Dict[str, Any] = Field(default_factory=dict)


class AgentDecision(BaseModel):
    agent_type: Literal["Red", "Blue"] = Field(...)
    thought: str = Field(...)
    action_type: str = Field(...)
    target: Optional[str] = Field(default=None)
    vuln_id: Optional[str] = Field(default=None)
    payload: str = Field(default="")


class RefereeJudgement(BaseModel):
    is_success: bool = Field(..., description="Whether the action succeeds from a technical perspective.")
    rationale: str = Field(..., description="Detailed reason why the action succeeds or fails.")
    llm_score_suggest: int = Field(default=0, ge=0, description="Optional score suggested by the referee model.")
    effect: str = Field(..., description="Referee-assigned action effect label, such as compromise/hardening/failed.")

    @model_validator(mode="before")
    @classmethod
    def _coerce_legacy_score_field(cls, value: Any) -> Any:
        if not isinstance(value, dict):
            return value
        payload = dict(value)
        if "llm_score_suggest" not in payload and "score_awarded" in payload:
            payload["llm_score_suggest"] = payload.pop("score_awarded")
        return payload


class SecurityAlert(BaseModel):
    severity: Literal["INFO", "WARN", "CRIT"] = Field(default="INFO")
    message: str = Field(...)
    target: Optional[str] = Field(default=None)
    source_action: str = Field(default="")
    metadata: Dict[str, Any] = Field(default_factory=dict)


class WorldState(BaseModel):
    turn: int = Field(...)
    system_health: int = Field(..., ge=0, le=100)
    exposure_level: int = Field(..., ge=0, le=100)
    red_score: int = Field(default=0, ge=0)
    blue_score: int = Field(default=0, ge=0)
    network_nodes: Dict[str, NetworkNode] = Field(...)
    edges: List[TopologyEdge] = Field(default_factory=list)
    action_logs: List[ActionLog] = Field(default_factory=list)
    security_alerts: List[SecurityAlert] = Field(default_factory=list)
    red_visible_nodes: List[str] = Field(default_factory=list)
    red_recon_nodes: List[str] = Field(default_factory=list)
    red_known_services: Dict[str, List[int]] = Field(default_factory=dict)
    red_known_vulnerabilities: Dict[str, Dict[str, VulnerabilityInfo]] = Field(default_factory=dict)
    red_anchored_nodes: List[str] = Field(default_factory=list)
    blue_known_vulnerabilities: Dict[str, Dict[str, float]] = Field(default_factory=dict)
    blue_monitored_nodes: List[str] = Field(default_factory=list)
    blue_last_preventive_patch_turn: int = Field(default=-99)
    blue_preventive_patch_cooldowns: Dict[str, int] = Field(default_factory=dict)
    core_assets: List[str] = Field(default_factory=lambda: ["db"])
    winner_locked: bool = Field(default=False)
    winner_side: Optional[Literal["Red", "Blue"]] = Field(default=None)
    winner_reason: str = Field(default="")

    @field_validator("red_known_vulnerabilities", mode="before")
    @classmethod
    def _coerce_known_vulnerabilities(cls, value: Any) -> Dict[str, Dict[str, VulnerabilityInfo]]:
        if value is None:
            return {}
        if not isinstance(value, dict):
            raise TypeError("red_known_vulnerabilities must be a dictionary")
        return {
            node_name: _coerce_vulnerability_map(vulnerabilities)
            for node_name, vulnerabilities in value.items()
        }

    @field_validator("blue_known_vulnerabilities", mode="before")
    @classmethod
    def _coerce_blue_known_vulnerabilities(cls, value: Any) -> Dict[str, Dict[str, float]]:
        if value is None:
            return {}
        if not isinstance(value, dict):
            raise TypeError("blue_known_vulnerabilities must be a dictionary")

        normalized: Dict[str, Dict[str, float]] = {}
        for node_name, payload in value.items():
            if payload is None:
                normalized[node_name] = {}
                continue
            if isinstance(payload, list):
                normalized[node_name] = {
                    str(vuln_id): 1.0
                    for vuln_id in payload
                    if isinstance(vuln_id, str) and vuln_id
                }
                continue
            if not isinstance(payload, dict):
                raise TypeError("blue_known_vulnerabilities[node] must be a dict or list")
            node_map: Dict[str, float] = {}
            for vuln_id, confidence in payload.items():
                if not isinstance(vuln_id, str) or not vuln_id:
                    continue
                if isinstance(confidence, bool):
                    numeric = 1.0 if confidence else 0.0
                elif isinstance(confidence, (int, float)):
                    numeric = float(confidence)
                else:
                    numeric = 0.0
                node_map[vuln_id] = max(0.0, min(1.0, numeric))
            normalized[node_name] = node_map
        return normalized

    @field_validator("core_assets", mode="before")
    @classmethod
    def _coerce_core_assets(cls, value: Any) -> List[str]:
        if value is None:
            return ["db"]
        if not isinstance(value, list):
            raise TypeError("core_assets must be a list")
        dedup: List[str] = []
        for node_name in value:
            if isinstance(node_name, str) and node_name and node_name not in dedup:
                dedup.append(node_name)
        return dedup or ["db"]


class SimulationReplay(BaseModel):
    scenario: str = Field(...)
    total_rounds: int = Field(..., ge=0)
    frames: List[WorldState] = Field(default_factory=list)
