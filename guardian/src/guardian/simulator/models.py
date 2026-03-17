"""
Simulator data models.

Defines the scenario file format and simulation result structures.
"""

from __future__ import annotations

from datetime import datetime
from enum import Enum

from pydantic import BaseModel, Field


class AdapterType(str, Enum):
    """Supported adapter types for scenario events."""
    direct = "direct"                # Raw ActionRequest
    intune = "intune"                # Intune device action
    entra_id = "entra_id"           # Entra ID admin action
    jamf = "jamf"                    # Jamf Pro device command
    github = "github"                # GitHub deployment
    aws = "aws"                      # CloudTrail event
    kubernetes = "kubernetes"        # K8s admission


class ScenarioEvent(BaseModel):
    """A single event in a scenario timeline."""
    id: str = ""                     # event identifier
    timestamp: str = ""              # ISO 8601 timestamp
    delay_seconds: float = 0         # delay from previous event
    adapter: AdapterType = AdapterType.direct
    description: str = ""            # human-readable description
    phase: str = ""                  # attack phase label
    # The event payload — exactly one of these should be populated
    payload: dict = Field(default_factory=dict)
    # Expected outcome (for validation)
    expect_decision: str = ""        # "allow", "block", "require_review", or ""
    expect_risk_min: float = 0.0     # minimum expected risk score
    expect_risk_max: float = 1.0     # maximum expected risk score
    expect_circuit_breaker: bool | None = None  # expected CB state


class ScenarioMetadata(BaseModel):
    """Metadata about a scenario."""
    name: str
    description: str = ""
    author: str = ""
    version: str = "1.0"
    tags: list[str] = Field(default_factory=list)
    # Scenario configuration overrides
    circuit_breaker_enabled: bool = True
    circuit_breaker_max_per_minute: int = 5
    circuit_breaker_max_per_hour: int = 20
    # Actors to register for this scenario
    register_actors: list[dict] = Field(default_factory=list)


class Scenario(BaseModel):
    """A complete scenario file."""
    metadata: ScenarioMetadata
    events: list[ScenarioEvent]


class EventResult(BaseModel):
    """Result of evaluating a single scenario event."""
    event_id: str
    phase: str = ""
    description: str = ""
    adapter: str
    actor_name: str = ""
    action: str = ""
    decision: str
    risk_score: float
    drift_score: float | None = None
    explanation: str
    circuit_breaker_tripped: bool = False
    entry_id: str = ""
    # Validation
    expectation_met: bool = True
    expectation_details: str = ""
    # AWS-specific
    quarantine_recommended: bool = False
    quarantine_action: str = ""
