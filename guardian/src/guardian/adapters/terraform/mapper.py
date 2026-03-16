"""
Terraform Plan → ActionRequest Mapper

Converts a Terraform plan JSON into a list of Guardian ActionRequests.
Resource type mappings are loaded from config/terraform-mappings.yaml.

Each resource_change in the plan becomes one ActionRequest. The mapper
determines the Guardian action type, sensitivity, and target system
from the Terraform resource type and change actions.
"""

from __future__ import annotations

import fnmatch
import logging
from datetime import datetime, timezone
from pathlib import Path
from typing import Optional

import yaml

from guardian.models.action_request import (
    ActionRequest,
    ActorType,
    PrivilegeLevel,
    SensitivityLevel,
)

logger = logging.getLogger(__name__)

# Terraform change actions → Guardian action mapping
_TF_ACTION_MAP = {
    "delete": "destroy_infrastructure",
    "create": "change_configuration",
    "update": "change_configuration",
}


class ResourceMapping:
    """A single mapping from a Terraform resource type pattern to Guardian metadata."""

    def __init__(self, pattern: str, action: str,
                 sensitivity: str = "internal", system: str = "terraform"):
        self.pattern = pattern
        self.action = action
        self.sensitivity = sensitivity
        self.system = system

    def matches(self, resource_type: str) -> bool:
        return fnmatch.fnmatch(resource_type, self.pattern)


class TerraformPlanMapper:
    """Maps a Terraform plan JSON to Guardian ActionRequests."""

    def __init__(
        self,
        mappings: list[ResourceMapping] | None = None,
        default_action: str = "change_configuration",
        default_sensitivity: str = "internal",
    ):
        self.mappings = mappings or []
        self.default_action = default_action
        self.default_sensitivity = default_sensitivity

    @classmethod
    def from_config(cls, config_path: Path) -> "TerraformPlanMapper":
        """Load mappings from a YAML config file."""
        if not config_path.exists():
            logger.warning("No terraform-mappings.yaml found — using defaults")
            return cls()

        data = yaml.safe_load(config_path.read_text(encoding="utf-8"))
        mappings = []
        for entry in data.get("resource_mappings", []):
            mappings.append(ResourceMapping(
                pattern=entry["pattern"],
                action=entry["action"],
                sensitivity=entry.get("sensitivity", "internal"),
                system=entry.get("system", "terraform"),
            ))

        return cls(
            mappings=mappings,
            default_action=data.get("default_action", "change_configuration"),
            default_sensitivity=data.get("default_sensitivity", "internal"),
        )

    def map_plan(
        self,
        plan_json: dict,
        actor_name: str,
        actor_type: ActorType = ActorType.automation,
        timestamp: datetime | None = None,
    ) -> list[ActionRequest]:
        """
        Convert a Terraform plan into Guardian ActionRequests.

        Each resource_change in the plan becomes one ActionRequest.
        No-op changes are skipped.
        """
        ts = timestamp or datetime.now(timezone.utc)
        requests = []

        for change in plan_json.get("resource_changes", []):
            actions = change.get("change", {}).get("actions", [])

            # Skip no-ops
            if actions == ["no-op"] or not actions:
                continue

            resource_type = change.get("type", "unknown")
            resource_address = change.get("address", "unknown")

            # Determine Guardian action, sensitivity, and system
            guardian_action, sensitivity, system = self._resolve_mapping(
                resource_type, actions,
            )

            # Determine privilege level from change type
            privilege = PrivilegeLevel.standard
            if "delete" in actions:
                privilege = PrivilegeLevel.elevated
            if resource_type.startswith("aws_iam") or "admin" in resource_address:
                privilege = PrivilegeLevel.admin

            requests.append(ActionRequest(
                actor_name=actor_name,
                actor_type=actor_type,
                requested_action=guardian_action,
                target_system=system,
                target_asset=resource_address,
                privilege_level=privilege,
                sensitivity_level=SensitivityLevel(sensitivity),
                business_context=f"Terraform plan: {', '.join(actions)} {resource_address}",
                timestamp=ts,
            ))

        logger.info(
            "Mapped Terraform plan: %d resource changes → %d action requests",
            len(plan_json.get("resource_changes", [])), len(requests),
        )
        return requests

    def _resolve_mapping(
        self, resource_type: str, tf_actions: list[str],
    ) -> tuple[str, str, str]:
        """Resolve resource type to (guardian_action, sensitivity, system)."""
        # Check configured mappings first
        for mapping in self.mappings:
            if mapping.matches(resource_type):
                # Override action for deletes (including replace = create+delete)
                if "delete" in tf_actions:
                    return "destroy_infrastructure", mapping.sensitivity, mapping.system
                return mapping.action, mapping.sensitivity, mapping.system

        # Fall back to TF action type
        for tf_action in ("delete", "update", "create"):
            if tf_action in tf_actions:
                return (
                    _TF_ACTION_MAP.get(tf_action, self.default_action),
                    self.default_sensitivity,
                    "terraform",
                )

        return self.default_action, self.default_sensitivity, "terraform"
