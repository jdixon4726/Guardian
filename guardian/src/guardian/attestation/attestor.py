"""
Identity Attestation

Verifies actor identity against the registry before any policy evaluation.
Self-reported actor_type and privilege_level fields from the ActionRequest
are never trusted — this module independently verifies them.

Attestation failures produce an immediate block with no further evaluation.
"""

from __future__ import annotations

import logging
from dataclasses import dataclass
from enum import Enum
from pathlib import Path
from typing import Optional

import yaml

from guardian.models.action_request import ActionRequest, ActorType, PrivilegeLevel

logger = logging.getLogger(__name__)

_PRIVILEGE_RANK = {
    PrivilegeLevel.standard: 0,
    PrivilegeLevel.elevated: 1,
    PrivilegeLevel.admin: 2,
}


class AttestationFailureReason(str, Enum):
    actor_not_found = "actor_not_found"
    actor_terminated = "actor_terminated"
    actor_type_mismatch = "actor_type_mismatch"
    privilege_exceeds_maximum = "privilege_exceeds_maximum"


@dataclass
class AttestationResult:
    success: bool
    actor_name: str
    verified_actor_type: Optional[ActorType] = None
    verified_max_privilege: Optional[PrivilegeLevel] = None
    actor_owner: Optional[str] = None
    failure_reason: Optional[AttestationFailureReason] = None
    failure_explanation: Optional[str] = None


class ActorRegistry:
    """Loads and indexes actor records from the YAML registry file."""

    def __init__(self, registry_path: Path):
        self._actors: dict[str, dict] = {}
        self._load(registry_path)

    def _load(self, path: Path) -> None:
        data = yaml.safe_load(path.read_text())
        for actor in data.get("actors", []):
            self._actors[actor["name"]] = actor
        logger.info("Actor registry loaded: %d actors", len(self._actors))

    def get(self, actor_name: str) -> Optional[dict]:
        return self._actors.get(actor_name)


class IdentityAttestor:
    """
    Verifies actor claims against the registry.

    Three checks in order:
      1. Actor exists in registry
      2. Actor is not terminated
      3. Claimed actor_type matches registry record
      4. Claimed privilege_level does not exceed registry maximum
    """

    def __init__(self, registry: ActorRegistry):
        self.registry = registry

    def attest(self, request: ActionRequest) -> AttestationResult:
        record = self.registry.get(request.actor_name)

        if record is None:
            return AttestationResult(
                success=False,
                actor_name=request.actor_name,
                failure_reason=AttestationFailureReason.actor_not_found,
                failure_explanation=(
                    f"Actor '{request.actor_name}' is not registered in the actor registry. "
                    "Unregistered actors cannot be granted any access."
                ),
            )

        if record.get("status") == "terminated":
            return AttestationResult(
                success=False,
                actor_name=request.actor_name,
                failure_reason=AttestationFailureReason.actor_terminated,
                failure_explanation=(
                    f"Actor '{request.actor_name}' has terminated status. "
                    "Terminated actors are blocked from all actions."
                ),
            )

        registry_type = ActorType(record["type"])
        if request.actor_type != registry_type:
            return AttestationResult(
                success=False,
                actor_name=request.actor_name,
                failure_reason=AttestationFailureReason.actor_type_mismatch,
                failure_explanation=(
                    f"Actor '{request.actor_name}' claimed type '{request.actor_type.value}' "
                    f"but registry records type '{registry_type.value}'. "
                    "Identity claim mismatch — possible spoofing attempt."
                ),
            )

        registry_max = PrivilegeLevel(record["max_privilege_level"])
        if _PRIVILEGE_RANK[request.privilege_level] > _PRIVILEGE_RANK[registry_max]:
            return AttestationResult(
                success=False,
                actor_name=request.actor_name,
                failure_reason=AttestationFailureReason.privilege_exceeds_maximum,
                failure_explanation=(
                    f"Actor '{request.actor_name}' requested privilege level "
                    f"'{request.privilege_level.value}' which exceeds their registered "
                    f"maximum of '{registry_max.value}'."
                ),
            )

        return AttestationResult(
            success=True,
            actor_name=request.actor_name,
            verified_actor_type=registry_type,
            verified_max_privilege=registry_max,
            actor_owner=record.get("owner"),
        )
