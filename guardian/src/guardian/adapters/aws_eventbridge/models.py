"""
AWS EventBridge Adapter models.

Models CloudTrail events as they arrive through EventBridge.
"""

from __future__ import annotations

from pydantic import BaseModel, Field


class CloudTrailEvent(BaseModel):
    """Normalized CloudTrail event from EventBridge."""
    event_id: str = ""
    event_time: str = ""
    event_source: str = ""               # iam.amazonaws.com, ec2.amazonaws.com, etc.
    event_name: str = ""                 # DeleteBucket, CreateUser, etc.
    aws_region: str = ""
    source_ip: str = ""
    # Actor identity
    user_identity_type: str = ""         # Root, IAMUser, AssumedRole, FederatedUser
    user_identity_arn: str = ""
    user_identity_account_id: str = ""
    user_identity_principal_id: str = ""
    user_identity_username: str = ""
    access_key_id: str = ""
    session_issuer_arn: str = ""         # for assumed roles
    # Request details
    request_parameters: dict = Field(default_factory=dict)
    response_elements: dict = Field(default_factory=dict)
    error_code: str = ""                 # set if the API call failed
    error_message: str = ""
    # Resources affected
    resources: list[dict] = Field(default_factory=list)


class EventBridgeEvaluation(BaseModel):
    """Guardian's evaluation of a CloudTrail event."""
    event_id: str
    allowed: bool
    decision: str
    risk_score: float
    explanation: str
    entry_id: str
    quarantine_recommended: bool = False
    quarantine_action: str = ""          # e.g., "attach_deny_scp", "disable_access_key"
