"""
CloudTrail Event -> ActionRequest Mapper

Maps AWS CloudTrail events to Guardian's action taxonomy.
Covers IAM, EC2, S3, RDS, Lambda, and other critical services.
"""

from __future__ import annotations

import logging
from datetime import datetime, timezone

from guardian.adapters.aws_eventbridge.models import CloudTrailEvent
from guardian.models.action_request import (
    ActionRequest as GuardianActionRequest,
    ActorType,
    PrivilegeLevel,
    SensitivityLevel,
)

logger = logging.getLogger(__name__)

# CloudTrail event name -> Guardian action mapping
_EVENT_MAP: dict[str, dict] = {
    # IAM — privilege escalation
    "CreateUser": {"action": "create_service_account", "sensitivity": "high", "privilege": "elevated"},
    "DeleteUser": {"action": "delete_resource", "sensitivity": "high", "privilege": "elevated"},
    "CreateAccessKey": {"action": "escalate_privileges", "sensitivity": "restricted", "privilege": "admin"},
    "CreateLoginProfile": {"action": "escalate_privileges", "sensitivity": "restricted", "privilege": "admin"},
    "AttachUserPolicy": {"action": "grant_admin_access", "sensitivity": "restricted", "privilege": "admin"},
    "AttachRolePolicy": {"action": "grant_admin_access", "sensitivity": "restricted", "privilege": "admin"},
    "PutUserPolicy": {"action": "grant_admin_access", "sensitivity": "restricted", "privilege": "admin"},
    "PutRolePolicy": {"action": "grant_admin_access", "sensitivity": "restricted", "privilege": "admin"},
    "CreateRole": {"action": "modify_iam_role", "sensitivity": "restricted", "privilege": "admin"},
    "DeleteRole": {"action": "delete_resource", "sensitivity": "restricted", "privilege": "admin"},
    "UpdateAssumeRolePolicy": {"action": "modify_iam_role", "sensitivity": "restricted", "privilege": "admin"},
    # EC2 — infrastructure
    "TerminateInstances": {"action": "terminate_instances", "sensitivity": "high", "privilege": "elevated"},
    "DeleteSecurityGroup": {"action": "disable_firewall", "sensitivity": "high", "privilege": "elevated"},
    "AuthorizeSecurityGroupIngress": {"action": "modify_firewall_rule", "sensitivity": "high", "privilege": "elevated"},
    "DeleteVpc": {"action": "delete_vpc", "sensitivity": "restricted", "privilege": "admin"},
    "DeleteSubnet": {"action": "destroy_infrastructure", "sensitivity": "high", "privilege": "elevated"},
    # S3 — data
    "DeleteBucket": {"action": "destroy_infrastructure", "sensitivity": "restricted", "privilege": "admin"},
    "PutBucketPolicy": {"action": "modify_security_policy", "sensitivity": "high", "privilege": "elevated"},
    "PutBucketPublicAccessBlock": {"action": "modify_security_policy", "sensitivity": "restricted", "privilege": "admin"},
    "DeleteBucketPolicy": {"action": "disable_firewall", "sensitivity": "restricted", "privilege": "admin"},
    # RDS — database
    "DeleteDBInstance": {"action": "drop_database", "sensitivity": "restricted", "privilege": "admin"},
    "DeleteDBCluster": {"action": "drop_database", "sensitivity": "restricted", "privilege": "admin"},
    "ModifyDBInstance": {"action": "change_configuration", "sensitivity": "high", "privilege": "elevated"},
    "DeleteDBSnapshot": {"action": "destroy_infrastructure", "sensitivity": "restricted", "privilege": "admin"},
    # Lambda
    "DeleteFunction20150331": {"action": "destroy_infrastructure", "sensitivity": "high", "privilege": "elevated"},
    "UpdateFunctionCode20150331v2": {"action": "change_configuration", "sensitivity": "high", "privilege": "elevated"},
    # KMS — encryption
    "DisableKey": {"action": "disable_endpoint_protection", "sensitivity": "restricted", "privilege": "admin"},
    "ScheduleKeyDeletion": {"action": "destroy_infrastructure", "sensitivity": "restricted", "privilege": "admin"},
    # CloudTrail — covering tracks
    "StopLogging": {"action": "disable_endpoint_protection", "sensitivity": "restricted", "privilege": "admin"},
    "DeleteTrail": {"action": "disable_endpoint_protection", "sensitivity": "restricted", "privilege": "admin"},
    # GuardDuty
    "DeleteDetector": {"action": "disable_endpoint_protection", "sensitivity": "restricted", "privilege": "admin"},
    # Organizations
    "LeaveOrganization": {"action": "destroy_infrastructure", "sensitivity": "restricted", "privilege": "admin"},
}

# Events that warrant quarantine recommendation
_QUARANTINE_EVENTS = {
    "CreateAccessKey", "AttachUserPolicy", "AttachRolePolicy",
    "PutUserPolicy", "PutRolePolicy", "StopLogging", "DeleteTrail",
    "DeleteDetector", "LeaveOrganization", "DisableKey",
    "ScheduleKeyDeletion", "DeleteBucket",
}

_SENSITIVITY_MAP = {
    "public": SensitivityLevel.public,
    "internal": SensitivityLevel.internal,
    "confidential": SensitivityLevel.confidential,
    "high": SensitivityLevel.high,
    "restricted": SensitivityLevel.restricted,
}

_PRIVILEGE_MAP = {
    "standard": PrivilegeLevel.standard,
    "elevated": PrivilegeLevel.elevated,
    "admin": PrivilegeLevel.admin,
}


class CloudTrailMapper:
    """Maps CloudTrail events to Guardian ActionRequests."""

    def map_event(self, event: CloudTrailEvent) -> GuardianActionRequest:
        mapping = _EVENT_MAP.get(event.event_name, {
            "action": "change_configuration",
            "sensitivity": "internal",
            "privilege": "standard",
        })

        # Resolve actor
        actor_name = self._resolve_actor(event)
        actor_type = self._resolve_actor_type(event)
        sensitivity = _SENSITIVITY_MAP[mapping["sensitivity"]]
        privilege = _PRIVILEGE_MAP[mapping["privilege"]]

        # Build target asset
        target_asset = self._resolve_target(event)
        target_system = f"aws-{event.event_source.split('.')[0]}"

        context_parts = [
            f"AWS {event.event_name} via {event.event_source}",
            f"region={event.aws_region}",
            f"source_ip={event.source_ip}",
        ]
        if event.error_code:
            context_parts.append(f"FAILED: {event.error_code}")
        if event.event_name in _QUARANTINE_EVENTS:
            context_parts.append("QUARANTINE_CANDIDATE")

        # Parse timestamp
        try:
            timestamp = datetime.fromisoformat(event.event_time.replace("Z", "+00:00"))
        except (ValueError, AttributeError):
            timestamp = datetime.now(timezone.utc)

        return GuardianActionRequest(
            actor_name=actor_name,
            actor_type=actor_type,
            requested_action=mapping["action"],
            target_system=target_system,
            target_asset=target_asset,
            privilege_level=privilege,
            sensitivity_level=sensitivity,
            business_context="; ".join(context_parts),
            timestamp=timestamp,
        )

    def should_quarantine(self, event: CloudTrailEvent) -> bool:
        return event.event_name in _QUARANTINE_EVENTS

    def quarantine_action(self, event: CloudTrailEvent) -> str:
        """Recommend a quarantine action for high-risk events."""
        if event.event_name in ("StopLogging", "DeleteTrail", "DeleteDetector"):
            return "attach_deny_scp"
        if event.event_name in ("CreateAccessKey", "AttachUserPolicy", "PutUserPolicy"):
            return "disable_access_key"
        if event.event_name in ("LeaveOrganization",):
            return "attach_deny_scp"
        return "notify_security_team"

    def _resolve_actor(self, event: CloudTrailEvent) -> str:
        if event.user_identity_username:
            return f"aws-{event.user_identity_account_id}-{event.user_identity_username}"
        if event.session_issuer_arn:
            # Assumed role: extract role name
            parts = event.session_issuer_arn.split("/")
            role = parts[-1] if parts else "unknown-role"
            return f"aws-role-{role}"
        if event.user_identity_arn:
            parts = event.user_identity_arn.split("/")
            return f"aws-{parts[-1]}" if parts else "unknown-aws-actor"
        return "unknown-aws-actor"

    def _resolve_actor_type(self, event: CloudTrailEvent) -> ActorType:
        if event.user_identity_type == "AssumedRole":
            return ActorType.automation
        if event.user_identity_type == "AWSService":
            return ActorType.automation
        return ActorType.human

    def _resolve_target(self, event: CloudTrailEvent) -> str:
        if event.resources:
            arns = [r.get("ARN", r.get("arn", "")) for r in event.resources if r.get("ARN") or r.get("arn")]
            if arns:
                return arns[0]
        # Fall back to request parameters
        params = event.request_parameters
        for key in ("bucketName", "instanceId", "functionName", "dBInstanceIdentifier",
                     "roleName", "userName", "groupName", "keyId", "trailName", "detectorId"):
            if key in params:
                return str(params[key])
        return f"{event.event_source}/{event.event_name}"
