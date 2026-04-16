from typing import Any, Dict, List, Literal, Optional

from pydantic import BaseModel, Field


class NetworkNode(BaseModel):
    status: Literal["Normal", "Compromised", "Defended", "Down"] = Field(
        ...,
        description="Current node status.",
    )
    exposed_ports: List[int] = Field(default_factory=list)
    vulnerabilities: List[str] = Field(default_factory=list)


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
    payload: str = Field(default="")


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
    red_known_vulnerabilities: Dict[str, List[str]] = Field(default_factory=dict)


class SimulationReplay(BaseModel):
    scenario: str = Field(...)
    total_rounds: int = Field(..., ge=0)
    frames: List[WorldState] = Field(default_factory=list)
