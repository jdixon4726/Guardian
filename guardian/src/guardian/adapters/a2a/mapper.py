"""
A2A Task Delegation -> ActionRequest Mapper

Maps agent-to-agent task delegations to Guardian's action taxonomy.
Delegation depth, permission scope, and task type determine risk.

Key risk signals:
  - Deep delegation chains (>3 hops) — harder to audit, more blast radius
  - Cross-framework delegation — trust boundary crossing
  - Privilege-expanding delegations — receiver has more permissions than sender
  - Unknown receiver agents — no behavioral baseline
"""

from __future__ import annotations

import logging
from datetime import datetime, timezone

from guardian.adapters.a2a.models import A2ATaskDelegation
from guardian.models.action_request import (
    ActionRequest as GuardianActionRequest,
    ActorType,
    PrivilegeLevel,
    SensitivityLevel,
)

logger = logging.getLogger(__name__)

# Task types that carry elevated risk
_HIGH_RISK_TASKS = {
    "deploy", "deployment", "release", "infrastructure_change",
    "database_migration", "security_config", "credential_rotation",
    "user_management", "permission_change", "data_deletion",
}

_MODERATE_RISK_TASKS = {
    "code_review", "code_generation", "data_query", "report_generation",
    "monitoring", "alerting", "notification",
}

# Permissions that indicate privilege escalation
_PRIVILEGED_PERMISSIONS = {
    "admin", "write", "delete", "execute", "deploy",
    "manage_users", "manage_roles", "manage_secrets",
}


class A2ATaskMapper:
    """Maps A2A delegations to Guardian ActionRequests."""

    def map_delegation(
        self, delegation: A2ATaskDelegation,
    ) -> GuardianActionRequest:
        # The actor is the sender (the delegating agent)
        actor_name = f"a2a-{delegation.sender_agent_id}"
        actor_type = ActorType.ai_agent

        # Classify the delegation
        action, sensitivity, privilege = self._classify(delegation)

        # Escalate based on delegation depth
        if delegation.delegation_depth > 3:
            sensitivity = SensitivityLevel.restricted
            privilege = PrivilegeLevel.admin

        # Escalate if requesting privileged permissions
        if any(p in _PRIVILEGED_PERMISSIONS for p in delegation.requested_permissions):
            privilege = PrivilegeLevel.admin
            if sensitivity.value in ("public", "internal"):
                sensitivity = SensitivityLevel.high

        # Target is the receiving agent
        target_asset = f"a2a/{delegation.receiver_agent_id}"
        if delegation.receiver_agent_name:
            target_asset = f"a2a/{delegation.receiver_agent_name}/{delegation.receiver_agent_id}"

        # Build context
        context_parts = [
            f"A2A delegation: {delegation.sender_agent_id} -> {delegation.receiver_agent_id}",
            f"task={delegation.task_type or 'untyped'}",
            f"depth={delegation.delegation_depth}",
        ]
        if delegation.delegation_chain:
            context_parts.append(f"chain={'->'.join(delegation.delegation_chain[-3:])}")
        if delegation.requested_permissions:
            context_parts.append(f"perms={','.join(delegation.requested_permissions[:5])}")
        if delegation.requested_tools:
            context_parts.append(f"tools={','.join(delegation.requested_tools[:5])}")
        if delegation.delegation_depth > 3:
            context_parts.append("DEEP_DELEGATION_CHAIN")
        if delegation.original_requester:
            context_parts.append(f"origin={delegation.original_requester}")

        return GuardianActionRequest(
            actor_name=actor_name,
            actor_type=actor_type,
            requested_action=action,
            target_system="a2a-agent-network",
            target_asset=target_asset,
            privilege_level=privilege,
            sensitivity_level=sensitivity,
            business_context="; ".join(context_parts),
            timestamp=datetime.now(timezone.utc),
        )

    def chain_risk_level(self, delegation: A2ATaskDelegation) -> str:
        """Assess the risk level of the delegation chain."""
        depth = delegation.delegation_depth
        has_privileged_perms = any(
            p in _PRIVILEGED_PERMISSIONS for p in delegation.requested_permissions
        )

        if depth > 5 or (depth > 3 and has_privileged_perms):
            return "critical"
        if depth > 3 or has_privileged_perms:
            return "high"
        if depth > 1:
            return "medium"
        return "low"

    def _classify(
        self, delegation: A2ATaskDelegation,
    ) -> tuple[str, SensitivityLevel, PrivilegeLevel]:
        task = delegation.task_type.lower() if delegation.task_type else ""

        if task in _HIGH_RISK_TASKS:
            return "change_configuration", SensitivityLevel.high, PrivilegeLevel.elevated

        if task in _MODERATE_RISK_TASKS:
            return "change_configuration", SensitivityLevel.internal, PrivilegeLevel.standard

        # Default: moderate
        return "change_configuration", SensitivityLevel.internal, PrivilegeLevel.standard
