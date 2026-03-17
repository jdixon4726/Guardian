"""
Entra ID Adapter request/response models.
"""

from __future__ import annotations

from pydantic import BaseModel, Field


class EntraAdminAction(BaseModel):
    """Intercepted Entra ID administrative action."""
    action: str = Field(..., min_length=1)  # create_user, assign_role, etc.
    target_type: str = ""                   # user, group, role, policy, app
    target_id: str = ""                     # object ID of the target
    target_display_name: str = ""           # human-readable name
    # Action-specific fields
    role_definition_id: str = ""            # for role assignments
    role_display_name: str = ""             # e.g., "Global Administrator"
    directory_scope: str = "/"              # scope of role assignment
    policy_state: str = ""                  # for conditional access: enabled/disabled
    federation_domain: str = ""             # for federation changes


class EntraProxyResponse(BaseModel):
    """Response returned when Guardian intercepts an Entra ID action."""
    allowed: bool
    decision: str
    risk_score: float
    explanation: str
    entry_id: str
    circuit_breaker_tripped: bool = False
    circuit_breaker_reason: str | None = None
