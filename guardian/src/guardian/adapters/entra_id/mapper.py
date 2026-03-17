"""
Entra ID Admin Action -> ActionRequest Mapper

Maps intercepted Entra ID administrative operations to Guardian's
action taxonomy. Privilege escalation actions (Global Admin assignment,
federation changes) get maximum risk classification.
"""

from __future__ import annotations

import logging
from datetime import datetime, timezone

from guardian.adapters.entra_id.models import EntraAdminAction
from guardian.models.action_request import (
    ActionRequest as GuardianActionRequest,
    ActorType,
    PrivilegeLevel,
    SensitivityLevel,
)

logger = logging.getLogger(__name__)

# Privileged Entra ID roles that get maximum scrutiny
_PRIVILEGED_ROLES = {
    "global administrator", "privileged role administrator",
    "privileged authentication administrator", "security administrator",
    "exchange administrator", "sharepoint administrator",
    "intune administrator", "application administrator",
    "cloud application administrator", "authentication administrator",
}

_ACTION_MAP: dict[str, dict] = {
    # User lifecycle
    "create_user": {
        "action": "create_service_account",
        "sensitivity": SensitivityLevel.high,
        "privilege": PrivilegeLevel.elevated,
    },
    "delete_user": {
        "action": "delete_resource",
        "sensitivity": SensitivityLevel.high,
        "privilege": PrivilegeLevel.elevated,
    },
    "update_user": {
        "action": "change_configuration",
        "sensitivity": SensitivityLevel.internal,
        "privilege": PrivilegeLevel.standard,
    },
    # Role assignments (the Stryker root cause)
    "assign_role": {
        "action": "grant_admin_access",
        "sensitivity": SensitivityLevel.restricted,
        "privilege": PrivilegeLevel.admin,
    },
    "remove_role": {
        "action": "modify_iam_role",
        "sensitivity": SensitivityLevel.restricted,
        "privilege": PrivilegeLevel.admin,
    },
    # Conditional access
    "create_conditional_access_policy": {
        "action": "modify_security_policy",
        "sensitivity": SensitivityLevel.restricted,
        "privilege": PrivilegeLevel.admin,
    },
    "update_conditional_access_policy": {
        "action": "modify_security_policy",
        "sensitivity": SensitivityLevel.restricted,
        "privilege": PrivilegeLevel.admin,
    },
    "delete_conditional_access_policy": {
        "action": "disable_firewall",
        "sensitivity": SensitivityLevel.restricted,
        "privilege": PrivilegeLevel.admin,
    },
    # Federation (external IdP trust — nuclear)
    "create_federation": {
        "action": "grant_admin_access",
        "sensitivity": SensitivityLevel.restricted,
        "privilege": PrivilegeLevel.admin,
    },
    "delete_federation": {
        "action": "modify_security_policy",
        "sensitivity": SensitivityLevel.restricted,
        "privilege": PrivilegeLevel.admin,
    },
    # App registrations
    "create_application": {
        "action": "create_service_account",
        "sensitivity": SensitivityLevel.high,
        "privilege": PrivilegeLevel.elevated,
    },
    "add_app_credential": {
        "action": "escalate_privileges",
        "sensitivity": SensitivityLevel.restricted,
        "privilege": PrivilegeLevel.admin,
    },
    # Group management
    "add_group_member": {
        "action": "add_user_to_group",
        "sensitivity": SensitivityLevel.internal,
        "privilege": PrivilegeLevel.standard,
    },
    "create_group": {
        "action": "change_configuration",
        "sensitivity": SensitivityLevel.internal,
        "privilege": PrivilegeLevel.standard,
    },
    # MFA/Auth methods
    "disable_mfa": {
        "action": "disable_endpoint_protection",
        "sensitivity": SensitivityLevel.restricted,
        "privilege": PrivilegeLevel.admin,
    },
    "reset_password": {
        "action": "modify_device_security",
        "sensitivity": SensitivityLevel.high,
        "privilege": PrivilegeLevel.elevated,
    },
}

# Actions considered destructive for circuit breaker
DESTRUCTIVE_ENTRA_ACTIONS = {
    "delete_user", "assign_role", "remove_role",
    "delete_conditional_access_policy", "create_federation",
    "add_app_credential", "disable_mfa",
}


class EntraAdminMapper:
    """Maps Entra ID admin actions to Guardian ActionRequests."""

    def map_action(
        self,
        admin_action: EntraAdminAction,
        actor_name: str,
        actor_type: ActorType = ActorType.human,
    ) -> GuardianActionRequest:
        mapping = _ACTION_MAP.get(admin_action.action, {
            "action": "change_configuration",
            "sensitivity": SensitivityLevel.internal,
            "privilege": PrivilegeLevel.standard,
        })

        # Escalate if targeting a privileged role
        sensitivity = mapping["sensitivity"]
        privilege = mapping["privilege"]
        if (admin_action.role_display_name.lower() in _PRIVILEGED_ROLES
                or admin_action.action in ("assign_role", "remove_role")):
            sensitivity = SensitivityLevel.restricted
            privilege = PrivilegeLevel.admin

        # Build target asset
        target = admin_action.target_id or admin_action.target_display_name or "unknown"
        target_asset = f"entra-id/{admin_action.target_type}/{target}"

        # Build context
        context_parts = [f"Entra ID {admin_action.action}"]
        if admin_action.target_display_name:
            context_parts.append(f"target={admin_action.target_display_name}")
        if admin_action.role_display_name:
            context_parts.append(f"role={admin_action.role_display_name}")
        if admin_action.federation_domain:
            context_parts.append(f"federation={admin_action.federation_domain}")
        if admin_action.action in DESTRUCTIVE_ENTRA_ACTIONS:
            context_parts.append("HIGH_RISK_ADMIN_ACTION")

        return GuardianActionRequest(
            actor_name=actor_name,
            actor_type=actor_type,
            requested_action=mapping["action"],
            target_system="entra-id",
            target_asset=target_asset,
            privilege_level=privilege,
            sensitivity_level=sensitivity,
            business_context="; ".join(context_parts),
            timestamp=datetime.now(timezone.utc),
        )

    @staticmethod
    def is_destructive(action: str) -> bool:
        return action in DESTRUCTIVE_ENTRA_ACTIONS
