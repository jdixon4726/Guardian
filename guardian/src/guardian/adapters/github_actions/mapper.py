"""
GitHub Deployment -> ActionRequest Mapper

Maps GitHub deployment protection rule requests to Guardian's
action taxonomy. Production environments get highest scrutiny.
Bot actors and modified workflow files trigger elevated risk.
"""

from __future__ import annotations

import logging
from datetime import datetime, timezone

from guardian.adapters.github_actions.models import GitHubDeploymentRequest
from guardian.models.action_request import (
    ActionRequest as GuardianActionRequest,
    ActorType,
    PrivilegeLevel,
    SensitivityLevel,
)

logger = logging.getLogger(__name__)

_ENVIRONMENT_SENSITIVITY = {
    "production": SensitivityLevel.restricted,
    "prod": SensitivityLevel.restricted,
    "staging": SensitivityLevel.high,
    "stage": SensitivityLevel.high,
    "preview": SensitivityLevel.confidential,
    "development": SensitivityLevel.internal,
    "dev": SensitivityLevel.internal,
}

_ENVIRONMENT_PRIVILEGE = {
    "production": PrivilegeLevel.elevated,
    "prod": PrivilegeLevel.elevated,
    "staging": PrivilegeLevel.standard,
    "stage": PrivilegeLevel.standard,
}


class GitHubDeploymentMapper:
    """Maps GitHub deployment requests to Guardian ActionRequests."""

    def map_deployment(
        self, deployment: GitHubDeploymentRequest,
    ) -> GuardianActionRequest:
        env = deployment.environment.lower()
        sensitivity = _ENVIRONMENT_SENSITIVITY.get(env, SensitivityLevel.internal)
        privilege = _ENVIRONMENT_PRIVILEGE.get(env, PrivilegeLevel.standard)

        # Determine actor type
        if deployment.sender_type == "Bot":
            actor_type = ActorType.automation
        else:
            actor_type = ActorType.human

        # Determine action based on event type
        action = "change_configuration"  # default: deploy
        if deployment.triggering_event == "workflow_dispatch":
            action = "change_configuration"
        elif env in ("production", "prod"):
            action = "change_configuration"  # still config, but sensitivity handles it

        actor_name = f"github-{deployment.sender_login}"

        context_parts = [
            f"GitHub deploy to {deployment.environment}",
            f"workflow={deployment.workflow_name}",
            f"repo={deployment.repository_full_name}",
            f"ref={deployment.workflow_ref}",
            f"trigger={deployment.triggering_event}",
        ]
        if deployment.head_branch:
            context_parts.append(f"branch={deployment.head_branch}")
        if deployment.repository_visibility == "public":
            context_parts.append("PUBLIC_REPO")

        return GuardianActionRequest(
            actor_name=actor_name,
            actor_type=actor_type,
            requested_action=action,
            target_system=f"github-{deployment.repository_full_name}",
            target_asset=f"environment/{deployment.environment}",
            privilege_level=privilege,
            sensitivity_level=sensitivity,
            business_context="; ".join(context_parts),
            timestamp=datetime.now(timezone.utc),
        )
