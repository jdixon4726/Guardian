"""
Unit tests for the Intune adapter: mapper, identity resolver, and proxy.
"""

from __future__ import annotations

import base64
import json

import pytest

from guardian.adapters.identity import ResolvedIdentity
from guardian.adapters.intune.identity import IntuneIdentityResolver
from guardian.adapters.intune.mapper import IntuneActionMapper, DESTRUCTIVE_INTUNE_ACTIONS
from guardian.adapters.intune.models import IntuneDeviceAction
from guardian.models.action_request import ActorType, PrivilegeLevel, SensitivityLevel


# ── Helpers ──────────────────────────────────────────────────────────────────

def _make_jwt(claims: dict) -> str:
    """Build a fake JWT with the given payload claims."""
    header = base64.urlsafe_b64encode(json.dumps({"alg": "RS256"}).encode()).rstrip(b"=")
    payload = base64.urlsafe_b64encode(json.dumps(claims).encode()).rstrip(b"=")
    signature = base64.urlsafe_b64encode(b"fakesig").rstrip(b"=")
    return f"{header.decode()}.{payload.decode()}.{signature.decode()}"


def _make_device_action(
    action: str = "wipe",
    device_id: str = "device-001",
    device_name: str = "LAPTOP-ACME",
    operating_system: str = "Windows",
) -> IntuneDeviceAction:
    return IntuneDeviceAction(
        device_id=device_id,
        action=action,
        device_name=device_name,
        operating_system=operating_system,
    )


# ── Identity Resolver Tests ─────────────────────────────────────────────────

class TestIntuneIdentityResolver:
    @pytest.fixture
    def resolver(self):
        return IntuneIdentityResolver()

    def test_resolves_identity_from_valid_jwt(self, resolver):
        token = _make_jwt({
            "upn": "admin@contoso.com",
            "oid": "abc-123",
            "tid": "tenant-456",
            "name": "Admin User",
            "roles": ["DeviceManagementManagedDevices.ReadWrite.All"],
        })
        identity = resolver.resolve({"authorization": f"Bearer {token}"})

        assert identity.actor_name == "intune-tenant-456-admin@contoso.com"
        assert identity.actor_source == "intune_azure_ad"
        assert identity.authenticated is True
        assert identity.confidence == 0.9

    def test_missing_auth_header_returns_unauthenticated(self, resolver):
        identity = resolver.resolve({"authorization": ""})
        assert identity.authenticated is False
        assert identity.confidence == 0.0
        assert "unknown" in identity.actor_name

    def test_non_bearer_auth_returns_unauthenticated(self, resolver):
        identity = resolver.resolve({"authorization": "Basic abc123"})
        assert identity.authenticated is False

    def test_malformed_jwt_returns_low_confidence(self, resolver):
        identity = resolver.resolve({"authorization": "Bearer not-a-jwt"})
        assert identity.authenticated is False
        assert identity.confidence == 0.1

    def test_jwt_with_unique_name_fallback(self, resolver):
        """Falls back to unique_name if upn is absent."""
        token = _make_jwt({
            "unique_name": "service@contoso.com",
            "oid": "svc-001",
            "tid": "tenant-789",
        })
        identity = resolver.resolve({"authorization": f"Bearer {token}"})
        assert "service@contoso.com" in identity.actor_name


# ── Mapper Tests ─────────────────────────────────────────────────────────────

class TestIntuneActionMapper:
    @pytest.fixture
    def mapper(self):
        return IntuneActionMapper()

    def test_wipe_maps_to_destructive_action(self, mapper):
        action = _make_device_action(action="wipe")
        request = mapper.map_action(action, actor_name="intune-tenant-admin@corp.com")

        assert request.requested_action == "wipe_device"
        assert request.sensitivity_level == SensitivityLevel.restricted
        assert request.privilege_level == PrivilegeLevel.admin
        assert request.target_system == "intune-device-management"
        assert "device-001" in request.target_asset
        assert "IRREVERSIBLE" in request.business_context

    def test_retire_maps_correctly(self, mapper):
        action = _make_device_action(action="retire")
        request = mapper.map_action(action, actor_name="admin")

        assert request.requested_action == "retire_device"
        assert request.sensitivity_level == SensitivityLevel.high
        assert request.privilege_level == PrivilegeLevel.elevated

    def test_delete_maps_correctly(self, mapper):
        action = _make_device_action(action="delete")
        request = mapper.map_action(action, actor_name="admin")

        assert request.requested_action == "delete_device"
        assert request.privilege_level == PrivilegeLevel.elevated

    def test_reset_passcode_maps_correctly(self, mapper):
        action = _make_device_action(action="resetPasscode")
        request = mapper.map_action(action, actor_name="admin")

        assert request.requested_action == "modify_device_security"
        assert request.sensitivity_level == SensitivityLevel.high
        assert "IRREVERSIBLE" not in request.business_context

    def test_sync_device_maps_to_low_risk(self, mapper):
        action = _make_device_action(action="syncDevice")
        request = mapper.map_action(action, actor_name="admin")

        assert request.requested_action == "change_configuration"
        assert request.sensitivity_level == SensitivityLevel.public
        assert request.privilege_level == PrivilegeLevel.standard

    def test_unknown_action_maps_to_default(self, mapper):
        action = _make_device_action(action="unknownNewAction")
        request = mapper.map_action(action, actor_name="admin")

        assert request.requested_action == "change_configuration"
        assert request.sensitivity_level == SensitivityLevel.internal

    def test_target_asset_includes_device_name(self, mapper):
        action = _make_device_action(device_name="CEO-LAPTOP", device_id="dev-999")
        request = mapper.map_action(action, actor_name="admin")

        assert "CEO-LAPTOP" in request.target_asset
        assert "dev-999" in request.target_asset

    def test_target_asset_without_device_name(self, mapper):
        action = IntuneDeviceAction(device_id="dev-123", action="wipe")
        request = mapper.map_action(action, actor_name="admin")

        assert request.target_asset == "intune/dev-123"

    def test_business_context_includes_os(self, mapper):
        action = _make_device_action(operating_system="iOS")
        request = mapper.map_action(action, actor_name="admin")

        assert "os=iOS" in request.business_context

    def test_actor_type_defaults_to_human(self, mapper):
        action = _make_device_action()
        request = mapper.map_action(action, actor_name="admin")
        assert request.actor_type == ActorType.human

    def test_actor_type_can_be_overridden(self, mapper):
        action = _make_device_action()
        request = mapper.map_action(
            action, actor_name="automation-bot", actor_type=ActorType.automation,
        )
        assert request.actor_type == ActorType.automation


class TestDestructiveActionClassification:
    def test_wipe_is_destructive(self):
        assert IntuneActionMapper.is_destructive("wipe") is True

    def test_retire_is_destructive(self):
        assert IntuneActionMapper.is_destructive("retire") is True

    def test_delete_is_destructive(self):
        assert IntuneActionMapper.is_destructive("delete") is True

    def test_sync_is_not_destructive(self):
        assert IntuneActionMapper.is_destructive("syncDevice") is False

    def test_reset_passcode_is_not_destructive(self):
        assert IntuneActionMapper.is_destructive("resetPasscode") is False

    def test_destructive_set_matches(self):
        assert DESTRUCTIVE_INTUNE_ACTIONS == {"wipe", "retire", "delete"}
