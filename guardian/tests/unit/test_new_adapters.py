"""
Unit tests for Entra ID, Jamf, GitHub Actions, and AWS EventBridge adapters.
"""

from __future__ import annotations

import pytest

from guardian.adapters.entra_id.mapper import EntraAdminMapper, DESTRUCTIVE_ENTRA_ACTIONS
from guardian.adapters.entra_id.models import EntraAdminAction
from guardian.adapters.jamf.mapper import JamfCommandMapper, DESTRUCTIVE_JAMF_COMMANDS
from guardian.adapters.jamf.models import JamfDeviceCommand
from guardian.adapters.github_actions.mapper import GitHubDeploymentMapper
from guardian.adapters.github_actions.models import GitHubDeploymentRequest
from guardian.adapters.aws_eventbridge.mapper import CloudTrailMapper
from guardian.adapters.aws_eventbridge.models import CloudTrailEvent
from guardian.models.action_request import ActorType, PrivilegeLevel, SensitivityLevel


# ── Entra ID Mapper ─────────────────────────────────────────────────────────

class TestEntraAdminMapper:
    @pytest.fixture
    def mapper(self):
        return EntraAdminMapper()

    def test_assign_global_admin_role(self, mapper):
        action = EntraAdminAction(
            action="assign_role",
            target_type="user",
            target_id="user-obj-001",
            target_display_name="Rogue Admin",
            role_display_name="Global Administrator",
        )
        request = mapper.map_action(action, actor_name="attacker@corp.com")
        assert request.requested_action == "grant_admin_access"
        assert request.sensitivity_level == SensitivityLevel.restricted
        assert request.privilege_level == PrivilegeLevel.admin
        assert "HIGH_RISK_ADMIN_ACTION" in request.business_context

    def test_create_user(self, mapper):
        action = EntraAdminAction(action="create_user", target_type="user", target_display_name="new-user")
        request = mapper.map_action(action, actor_name="admin@corp.com")
        assert request.requested_action == "create_service_account"
        assert request.sensitivity_level == SensitivityLevel.high

    def test_disable_mfa(self, mapper):
        action = EntraAdminAction(action="disable_mfa", target_type="user", target_display_name="victim")
        request = mapper.map_action(action, actor_name="admin@corp.com")
        assert request.requested_action == "disable_endpoint_protection"
        assert request.sensitivity_level == SensitivityLevel.restricted

    def test_create_federation(self, mapper):
        action = EntraAdminAction(
            action="create_federation", target_type="domain",
            federation_domain="evil.com",
        )
        request = mapper.map_action(action, actor_name="admin@corp.com")
        assert request.requested_action == "grant_admin_access"
        assert "federation=evil.com" in request.business_context

    def test_delete_conditional_access(self, mapper):
        action = EntraAdminAction(action="delete_conditional_access_policy", target_type="policy")
        request = mapper.map_action(action, actor_name="admin@corp.com")
        assert request.requested_action == "disable_firewall"

    def test_unknown_action_defaults(self, mapper):
        action = EntraAdminAction(action="some_new_action", target_type="unknown")
        request = mapper.map_action(action, actor_name="admin@corp.com")
        assert request.requested_action == "change_configuration"

    def test_is_destructive(self):
        assert EntraAdminMapper.is_destructive("assign_role") is True
        assert EntraAdminMapper.is_destructive("disable_mfa") is True
        assert EntraAdminMapper.is_destructive("create_user") is False
        assert EntraAdminMapper.is_destructive("add_group_member") is False


# ── Jamf Mapper ──────────────────────────────────────────────────────────────

class TestJamfCommandMapper:
    @pytest.fixture
    def mapper(self):
        return JamfCommandMapper()

    def test_erase_device_maps_to_wipe(self, mapper):
        cmd = JamfDeviceCommand(device_id="jamf-001", command="EraseDevice", device_name="MACBOOK-CEO")
        request = mapper.map_command(cmd, actor_name="jamf-admin@corp.com")
        assert request.requested_action == "wipe_device"
        assert request.sensitivity_level == SensitivityLevel.restricted
        assert request.privilege_level == PrivilegeLevel.admin
        assert "IRREVERSIBLE" in request.business_context
        assert request.target_system == "jamf-pro"

    def test_wipe_computer(self, mapper):
        cmd = JamfDeviceCommand(device_id="jamf-002", command="WipeComputer")
        request = mapper.map_command(cmd, actor_name="admin")
        assert request.requested_action == "wipe_device"

    def test_delete_computer(self, mapper):
        cmd = JamfDeviceCommand(device_id="jamf-003", command="DeleteComputer")
        request = mapper.map_command(cmd, actor_name="admin")
        assert request.requested_action == "delete_device"

    def test_device_lock_is_moderate(self, mapper):
        cmd = JamfDeviceCommand(device_id="jamf-004", command="DeviceLock")
        request = mapper.map_command(cmd, actor_name="admin")
        assert request.requested_action == "modify_device_security"
        assert "IRREVERSIBLE" not in request.business_context

    def test_update_inventory_is_low_risk(self, mapper):
        cmd = JamfDeviceCommand(device_id="jamf-005", command="UpdateInventory")
        request = mapper.map_command(cmd, actor_name="admin")
        assert request.requested_action == "change_configuration"
        assert request.sensitivity_level == SensitivityLevel.public

    def test_serial_number_in_context(self, mapper):
        cmd = JamfDeviceCommand(device_id="j-1", command="EraseDevice", serial_number="C02XYZ123")
        request = mapper.map_command(cmd, actor_name="admin")
        assert "serial=C02XYZ123" in request.business_context

    def test_is_destructive(self):
        assert JamfCommandMapper.is_destructive("EraseDevice") is True
        assert JamfCommandMapper.is_destructive("WipeComputer") is True
        assert JamfCommandMapper.is_destructive("UpdateInventory") is False


# ── GitHub Actions Mapper ────────────────────────────────────────────────────

class TestGitHubDeploymentMapper:
    @pytest.fixture
    def mapper(self):
        return GitHubDeploymentMapper()

    def test_production_deploy_is_restricted(self, mapper):
        deploy = GitHubDeploymentRequest(
            environment="production",
            sender_login="alice",
            sender_type="User",
            repository_full_name="acme/backend",
            workflow_name="deploy.yml",
        )
        request = mapper.map_deployment(deploy)
        assert request.sensitivity_level == SensitivityLevel.restricted
        assert request.privilege_level == PrivilegeLevel.elevated
        assert request.actor_type == ActorType.human
        assert request.actor_name == "github-alice"

    def test_staging_deploy_is_high(self, mapper):
        deploy = GitHubDeploymentRequest(
            environment="staging",
            sender_login="bot",
            sender_type="Bot",
        )
        request = mapper.map_deployment(deploy)
        assert request.sensitivity_level == SensitivityLevel.high
        assert request.actor_type == ActorType.automation

    def test_dev_deploy_is_low(self, mapper):
        deploy = GitHubDeploymentRequest(environment="development", sender_login="dev")
        request = mapper.map_deployment(deploy)
        assert request.sensitivity_level == SensitivityLevel.internal

    def test_public_repo_noted_in_context(self, mapper):
        deploy = GitHubDeploymentRequest(
            environment="production",
            sender_login="attacker",
            repository_full_name="attacker/fork",
            repository_visibility="public",
        )
        request = mapper.map_deployment(deploy)
        assert "PUBLIC_REPO" in request.business_context

    def test_context_includes_workflow_info(self, mapper):
        deploy = GitHubDeploymentRequest(
            environment="prod",
            sender_login="user",
            workflow_name="release.yml",
            repository_full_name="org/repo",
            triggering_event="push",
            head_branch="main",
        )
        request = mapper.map_deployment(deploy)
        assert "workflow=release.yml" in request.business_context
        assert "branch=main" in request.business_context


# ── AWS CloudTrail Mapper ────────────────────────────────────────────────────

class TestCloudTrailMapper:
    @pytest.fixture
    def mapper(self):
        return CloudTrailMapper()

    def test_create_access_key_is_privilege_escalation(self, mapper):
        event = CloudTrailEvent(
            event_name="CreateAccessKey",
            event_source="iam.amazonaws.com",
            user_identity_username="admin-user",
            user_identity_account_id="123456789012",
            user_identity_type="IAMUser",
            aws_region="us-east-1",
            source_ip="1.2.3.4",
            request_parameters={"userName": "admin-user"},
        )
        request = mapper.map_event(event)
        assert request.requested_action == "escalate_privileges"
        assert request.sensitivity_level == SensitivityLevel.restricted
        assert request.privilege_level == PrivilegeLevel.admin

    def test_stop_logging_is_defense_evasion(self, mapper):
        event = CloudTrailEvent(
            event_name="StopLogging",
            event_source="cloudtrail.amazonaws.com",
            user_identity_username="attacker",
            user_identity_account_id="123456789012",
            request_parameters={"name": "main-trail"},
        )
        request = mapper.map_event(event)
        assert request.requested_action == "disable_endpoint_protection"
        assert request.sensitivity_level == SensitivityLevel.restricted

    def test_terminate_instances(self, mapper):
        event = CloudTrailEvent(
            event_name="TerminateInstances",
            event_source="ec2.amazonaws.com",
            user_identity_username="admin",
            user_identity_account_id="123456789012",
        )
        request = mapper.map_event(event)
        assert request.requested_action == "terminate_instances"

    def test_delete_bucket(self, mapper):
        event = CloudTrailEvent(
            event_name="DeleteBucket",
            event_source="s3.amazonaws.com",
            user_identity_username="admin",
            user_identity_account_id="123456789012",
            request_parameters={"bucketName": "prod-data"},
        )
        request = mapper.map_event(event)
        assert request.requested_action == "destroy_infrastructure"
        assert "prod-data" in request.target_asset

    def test_delete_db_instance(self, mapper):
        event = CloudTrailEvent(
            event_name="DeleteDBInstance",
            event_source="rds.amazonaws.com",
            user_identity_username="admin",
            user_identity_account_id="123456789012",
            request_parameters={"dBInstanceIdentifier": "prod-db"},
        )
        request = mapper.map_event(event)
        assert request.requested_action == "drop_database"

    def test_assumed_role_actor_type(self, mapper):
        event = CloudTrailEvent(
            event_name="CreateAccessKey",
            event_source="iam.amazonaws.com",
            user_identity_type="AssumedRole",
            session_issuer_arn="arn:aws:iam::123456789012:role/deploy-role",
        )
        request = mapper.map_event(event)
        assert request.actor_type == ActorType.automation
        assert "deploy-role" in request.actor_name

    def test_should_quarantine(self, mapper):
        assert mapper.should_quarantine(CloudTrailEvent(event_name="StopLogging")) is True
        assert mapper.should_quarantine(CloudTrailEvent(event_name="DeleteDetector")) is True
        assert mapper.should_quarantine(CloudTrailEvent(event_name="CreateAccessKey")) is True
        assert mapper.should_quarantine(CloudTrailEvent(event_name="TerminateInstances")) is False

    def test_quarantine_action(self, mapper):
        assert mapper.quarantine_action(CloudTrailEvent(event_name="StopLogging")) == "attach_deny_scp"
        assert mapper.quarantine_action(CloudTrailEvent(event_name="CreateAccessKey")) == "disable_access_key"

    def test_unknown_event_defaults(self, mapper):
        event = CloudTrailEvent(event_name="SomeNewAPICall", event_source="new.amazonaws.com")
        request = mapper.map_event(event)
        assert request.requested_action == "change_configuration"

    def test_source_ip_in_context(self, mapper):
        event = CloudTrailEvent(
            event_name="DeleteBucket",
            event_source="s3.amazonaws.com",
            source_ip="185.220.101.42",
        )
        request = mapper.map_event(event)
        assert "source_ip=185.220.101.42" in request.business_context

    def test_target_from_resources(self, mapper):
        event = CloudTrailEvent(
            event_name="TerminateInstances",
            event_source="ec2.amazonaws.com",
            resources=[{"ARN": "arn:aws:ec2:us-east-1:123:instance/i-abc123"}],
        )
        request = mapper.map_event(event)
        assert "arn:aws:ec2" in request.target_asset
