"""
Core domain models for Guardian.

All incoming action requests are validated against ActionRequest.
All outgoing decisions are represented as Decision.
The EnrichedContext carries everything the policy and scoring engines need.
"""

from __future__ import annotations

from datetime import datetime, timezone
from enum import Enum
from typing import Optional
from uuid import uuid4

from pydantic import BaseModel, Field, field_validator


class ActorType(str, Enum):
    human = "human"
    automation = "automation"
    ai_agent = "ai_agent"


class PrivilegeLevel(str, Enum):
    standard = "standard"
    elevated = "elevated"
    admin = "admin"


class SensitivityLevel(str, Enum):
    public = "public"
    internal = "internal"
    confidential = "confidential"
    high = "high"          # alias used in asset catalog and action requests
    restricted = "restricted"


class DecisionOutcome(str, Enum):
    allow = "allow"
    allow_with_logging = "allow_with_logging"
    require_review = "require_review"
    block = "block"


class ActionRequest(BaseModel):
    """
    The incoming action request submitted for evaluation.

    All fields are validated at ingestion. actor_type and privilege_level
    are claims only — Identity Attestation verifies them independently.
    business_context is untrusted input and is never evaluated as logic.
    """

    actor_name: str = Field(..., min_length=1, max_length=255)
    actor_type: ActorType
    requested_action: str = Field(..., min_length=1, max_length=255)
    target_system: str = Field(..., min_length=1, max_length=255)
    target_asset: str = Field(..., min_length=1, max_length=255)
    privilege_level: PrivilegeLevel
    sensitivity_level: SensitivityLevel
    business_context: str = Field(default="", max_length=2000)
    timestamp: datetime
    session_id: str = Field(default_factory=lambda: str(uuid4()))

    @field_validator("business_context")
    @classmethod
    def sanitize_business_context(cls, v: str) -> str:
        # Trim and normalize. Injection detection runs in the attestation stage.
        return v.strip()


class RiskSignal(BaseModel):
    """A single scored signal contributing to the overall risk score."""
    source: str          # e.g. "actor_scorer"
    description: str     # human-readable signal description
    contribution: float  # signed contribution to final score


class DriftScore(BaseModel):
    """Output of the Drift Detection Engine."""
    score: float = Field(ge=0.0, le=1.0)
    level_drift_z: float           # z-score vs baseline mean
    pattern_drift_js: float        # Jensen-Shannon divergence
    baseline_days: int             # window used to compute baseline
    alert_triggered: bool = False
    explanation: Optional[str] = None


class Decision(BaseModel):
    """
    The final evaluated decision returned to the caller.

    This is also the basis for the audit log entry.
    """

    entry_id: str = Field(default_factory=lambda: str(uuid4()))
    action_request: ActionRequest
    decision: DecisionOutcome
    risk_score: float = Field(ge=0.0, le=1.0)
    drift_score: Optional[DriftScore] = None
    policy_matched: Optional[str] = None   # rule ID that produced the verdict
    risk_signals: list[RiskSignal] = Field(default_factory=list)
    explanation: str
    safer_alternatives: list[str] = Field(default_factory=list)
    compliance_tags: list[str] = Field(default_factory=list)
    evaluated_at: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))
    previous_hash: Optional[str] = None   # populated by audit logger
    entry_hash: Optional[str] = None      # populated by audit logger
