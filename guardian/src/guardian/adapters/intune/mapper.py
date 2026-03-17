"""
Intune Device Action → ActionRequest Mapper

Converts intercepted Microsoft Graph device management actions into
Guardian ActionRequests. Maps Graph API endpoints to Guardian's action
taxonomy with appropriate sensitivity and privilege levels.
"""

from __future__ import annotations

import logging
from datetime import datetime, timezone

from guardian.adapters.intune.models import IntuneDeviceAction
from guardian.models.action_request import (
    ActionRequest as GuardianActionRequest,
    ActorType,
    PrivilegeLevel,
    SensitivityLevel,
)

logger = logging.getLogger(__name__)

# Graph device action → Guardian action mapping
_ACTION_MAP: dict[str, dict] = {
    "wipe": {
        "action": "wipe_device",
        "sensitivity": SensitivityLevel.restricted,
        "privilege": PrivilegeLevel.admin,
        "irreversible": True,
    },
    "retire": {
        "action": "retire_device",
        "sensitivity": SensitivityLevel.high,
        "privilege": PrivilegeLevel.elevated,
        "irreversible": True,
    },
    "delete": {
        "action": "delete_device",
        "sensitivity": SensitivityLevel.high,
        "privilege": PrivilegeLevel.elevated,
        "irreversible": True,
    },
    "resetPasscode": {
        "action": "modify_device_security",
        "sensitivity": SensitivityLevel.high,
        "privilege": PrivilegeLevel.elevated,
        "irreversible": False,
    },
    "disableLostMode": {
        "action": "modify_device_security",
        "sensitivity": SensitivityLevel.high,
        "privilege": PrivilegeLevel.elevated,
        "irreversible": False,
    },
    "remoteLock": {
        "action": "modify_device_security",
        "sensitivity": SensitivityLevel.confidential,
        "privilege": PrivilegeLevel.standard,
        "irreversible": False,
    },
    "shutDown": {
        "action": "change_configuration",
        "sensitivity": SensitivityLevel.internal,
        "privilege": PrivilegeLevel.standard,
        "irreversible": False,
    },
    "rebootNow": {
        "action": "change_configuration",
        "sensitivity": SensitivityLevel.internal,
        "privilege": PrivilegeLevel.standard,
        "irreversible": False,
    },
    "syncDevice": {
        "action": "change_configuration",
        "sensitivity": SensitivityLevel.public,
        "privilege": PrivilegeLevel.standard,
        "irreversible": False,
    },
}

# Actions that the circuit breaker treats as destructive
DESTRUCTIVE_INTUNE_ACTIONS = {"wipe", "retire", "delete"}


class IntuneActionMapper:
    """Maps intercepted Intune device actions to Guardian ActionRequests."""

    def map_action(
        self,
        device_action: IntuneDeviceAction,
        actor_name: str,
        actor_type: ActorType = ActorType.human,
    ) -> GuardianActionRequest:
        """Convert an Intune device action to a Guardian ActionRequest."""
        mapping = _ACTION_MAP.get(device_action.action, {
            "action": "change_configuration",
            "sensitivity": SensitivityLevel.internal,
            "privilege": PrivilegeLevel.standard,
            "irreversible": False,
        })

        # Build target asset identifier
        target_asset = f"intune/{device_action.device_id}"
        if device_action.device_name:
            target_asset = f"intune/{device_action.device_name}/{device_action.device_id}"

        # Build business context
        context_parts = [f"Intune {device_action.action} on device {device_action.device_id}"]
        if device_action.device_name:
            context_parts.append(f"name={device_action.device_name}")
        if device_action.operating_system:
            context_parts.append(f"os={device_action.operating_system}")
        if device_action.device_owner:
            context_parts.append(f"owner={device_action.device_owner}")
        if mapping["irreversible"]:
            context_parts.append("IRREVERSIBLE")

        return GuardianActionRequest(
            actor_name=actor_name,
            actor_type=actor_type,
            requested_action=mapping["action"],
            target_system="intune-device-management",
            target_asset=target_asset,
            privilege_level=mapping["privilege"],
            sensitivity_level=mapping["sensitivity"],
            business_context="; ".join(context_parts),
            timestamp=datetime.now(timezone.utc),
        )

    @staticmethod
    def is_destructive(action: str) -> bool:
        """Check if an Intune action is considered destructive."""
        return action in DESTRUCTIVE_INTUNE_ACTIONS
