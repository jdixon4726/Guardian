"""
Jamf Pro Device Command -> ActionRequest Mapper

Maps Jamf Pro MDM commands to Guardian's action taxonomy.
EraseDevice, WipeComputer, and RemoveDevice are destructive.
"""

from __future__ import annotations

import logging
from datetime import datetime, timezone

from guardian.adapters.jamf.models import JamfDeviceCommand
from guardian.models.action_request import (
    ActionRequest as GuardianActionRequest,
    ActorType,
    PrivilegeLevel,
    SensitivityLevel,
)

logger = logging.getLogger(__name__)

_COMMAND_MAP: dict[str, dict] = {
    # Destructive — irreversible
    "EraseDevice": {
        "action": "wipe_device",
        "sensitivity": SensitivityLevel.restricted,
        "privilege": PrivilegeLevel.admin,
        "irreversible": True,
    },
    "WipeComputer": {
        "action": "wipe_device",
        "sensitivity": SensitivityLevel.restricted,
        "privilege": PrivilegeLevel.admin,
        "irreversible": True,
    },
    "DeleteComputer": {
        "action": "delete_device",
        "sensitivity": SensitivityLevel.high,
        "privilege": PrivilegeLevel.elevated,
        "irreversible": True,
    },
    "DeleteMobileDevice": {
        "action": "delete_device",
        "sensitivity": SensitivityLevel.high,
        "privilege": PrivilegeLevel.elevated,
        "irreversible": True,
    },
    "UnmanageDevice": {
        "action": "retire_device",
        "sensitivity": SensitivityLevel.high,
        "privilege": PrivilegeLevel.elevated,
        "irreversible": True,
    },
    # Security — reversible but high risk
    "DeviceLock": {
        "action": "modify_device_security",
        "sensitivity": SensitivityLevel.high,
        "privilege": PrivilegeLevel.elevated,
        "irreversible": False,
    },
    "ClearPasscode": {
        "action": "modify_device_security",
        "sensitivity": SensitivityLevel.high,
        "privilege": PrivilegeLevel.elevated,
        "irreversible": False,
    },
    "EnableRemoteDesktop": {
        "action": "modify_device_security",
        "sensitivity": SensitivityLevel.confidential,
        "privilege": PrivilegeLevel.elevated,
        "irreversible": False,
    },
    "DisableRemoteDesktop": {
        "action": "change_configuration",
        "sensitivity": SensitivityLevel.internal,
        "privilege": PrivilegeLevel.standard,
        "irreversible": False,
    },
    # Low risk
    "UpdateInventory": {
        "action": "change_configuration",
        "sensitivity": SensitivityLevel.public,
        "privilege": PrivilegeLevel.standard,
        "irreversible": False,
    },
    "BlankPush": {
        "action": "change_configuration",
        "sensitivity": SensitivityLevel.public,
        "privilege": PrivilegeLevel.standard,
        "irreversible": False,
    },
}

DESTRUCTIVE_JAMF_COMMANDS = {
    "EraseDevice", "WipeComputer", "DeleteComputer",
    "DeleteMobileDevice", "UnmanageDevice",
}


class JamfCommandMapper:
    """Maps Jamf Pro MDM commands to Guardian ActionRequests."""

    def map_command(
        self,
        command: JamfDeviceCommand,
        actor_name: str,
        actor_type: ActorType = ActorType.human,
    ) -> GuardianActionRequest:
        mapping = _COMMAND_MAP.get(command.command, {
            "action": "change_configuration",
            "sensitivity": SensitivityLevel.internal,
            "privilege": PrivilegeLevel.standard,
            "irreversible": False,
        })

        target_asset = f"jamf/{command.device_id}"
        if command.device_name:
            target_asset = f"jamf/{command.device_name}/{command.device_id}"

        context_parts = [f"Jamf {command.command} on {command.device_type or 'device'} {command.device_id}"]
        if command.device_name:
            context_parts.append(f"name={command.device_name}")
        if command.serial_number:
            context_parts.append(f"serial={command.serial_number}")
        if mapping.get("irreversible"):
            context_parts.append("IRREVERSIBLE")

        return GuardianActionRequest(
            actor_name=actor_name,
            actor_type=actor_type,
            requested_action=mapping["action"],
            target_system="jamf-pro",
            target_asset=target_asset,
            privilege_level=mapping["privilege"],
            sensitivity_level=mapping["sensitivity"],
            business_context="; ".join(context_parts),
            timestamp=datetime.now(timezone.utc),
        )

    @staticmethod
    def is_destructive(command: str) -> bool:
        return command in DESTRUCTIVE_JAMF_COMMANDS
