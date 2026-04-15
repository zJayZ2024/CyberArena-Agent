from typing import Dict, List, Literal, Optional

from pydantic import BaseModel, Field


class NetworkNode(BaseModel):
    status: Literal["Normal", "Compromised", "Defended", "Down"] = Field(
        ...,
        description="Current node status.",
    )
    exposed_ports: List[int] = Field(default_factory=list)
    vulnerabilities: List[str] = Field(default_factory=list)


class ActionLog(BaseModel):
    agent_type: Literal["Red", "Blue", "Referee"] = Field(...)
    thought: str = Field(...)
    action_type: str = Field(...)
    payload: str = Field(...)
    referee_result: str = Field(...)


class AgentDecision(BaseModel):
    agent_type: Literal["Red", "Blue"] = Field(...)
    thought: str = Field(...)
    action_type: str = Field(...)
    target: Optional[str] = Field(default=None)
    payload: str = Field(default="")


class WorldState(BaseModel):
    turn: int = Field(...)
    system_health: int = Field(..., ge=0, le=100)
    exposure_level: int = Field(..., ge=0, le=100)
    network_nodes: Dict[str, NetworkNode] = Field(...)
    action_logs: List[ActionLog] = Field(default_factory=list)
