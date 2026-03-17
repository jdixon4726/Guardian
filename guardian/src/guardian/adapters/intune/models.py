"""
Intune Adapter request/response models.

Models the Microsoft Graph device management API payloads that Guardian
intercepts as a proxy.
"""

from __future__ import annotations

from pydantic import BaseModel, Field


class IntuneDeviceAction(BaseModel):
    """
    Intercepted device management action.

    The proxy extracts these fields from the inbound Graph API request
    path and body.
    """
    device_id: str = Field(..., min_length=1, description="Intune managed device ID")
    action: str = Field(..., min_length=1, description="Graph action (wipe, retire, delete, etc.)")
    device_name: str = ""
    device_owner: str = ""
    operating_system: str = ""
    compliance_state: str = ""
    # Optional body params from specific actions
    keep_enrollment_data: bool | None = None       # wipe action option
    keep_user_data: bool | None = None             # wipe action option


class IntuneProxyResponse(BaseModel):
    """Response returned to the caller when Guardian intercepts an action."""
    allowed: bool
    decision: str                    # "allow", "block", "require_review"
    risk_score: float
    explanation: str
    entry_id: str                    # audit log entry for traceability
    circuit_breaker_tripped: bool = False
    circuit_breaker_reason: str | None = None


class IntuneCallerIdentity(BaseModel):
    """Identity extracted from the Azure AD Bearer token."""
    user_principal_name: str         # e.g., admin@contoso.com
    object_id: str                   # Azure AD object ID
    tenant_id: str                   # Azure AD tenant ID
    display_name: str = ""
    roles: list[str] = Field(default_factory=list)  # directory roles
