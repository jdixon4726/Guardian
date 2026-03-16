"""
Unit tests for Identity Attestation.
"""

import pytest
from pathlib import Path
from guardian.attestation.attestor import ActorRegistry, IdentityAttestor, AttestationFailureReason
from guardian.models.action_request import ActionRequest, ActorType, PrivilegeLevel, SensitivityLevel
from datetime import datetime, timezone

REGISTRY = ActorRegistry(Path(__file__).parent.parent.parent / "config" / "actor-registry.yaml")


def make_request(**kwargs):
    defaults = dict(
        actor_name="deploy-bot-prod",
        actor_type=ActorType.automation,
        requested_action="read_config",
        target_system="test",
        target_asset="test",
        privilege_level=PrivilegeLevel.standard,
        sensitivity_level=SensitivityLevel.internal,
        timestamp=datetime.now(timezone.utc),
    )
    defaults.update(kwargs)
    return ActionRequest(**defaults)


@pytest.fixture
def attestor():
    return IdentityAttestor(REGISTRY)


class TestAttestationSuccess:

    def test_known_active_actor_passes(self, attestor):
        r = attestor.attest(make_request(actor_name="deploy-bot-prod",
                                         actor_type=ActorType.automation))
        assert r.success
        assert r.verified_actor_type == ActorType.automation

    def test_human_actor_passes(self, attestor):
        r = attestor.attest(make_request(actor_name="alice.chen",
                                         actor_type=ActorType.human))
        assert r.success

    def test_ai_agent_passes(self, attestor):
        r = attestor.attest(make_request(actor_name="infra-agent-prod",
                                         actor_type=ActorType.ai_agent))
        assert r.success


class TestAttestationFailure:

    def test_unknown_actor_fails(self, attestor):
        r = attestor.attest(make_request(actor_name="ghost-bot-99"))
        assert not r.success
        assert r.failure_reason == AttestationFailureReason.actor_not_found

    def test_terminated_actor_fails(self, attestor):
        r = attestor.attest(make_request(actor_name="former-employee",
                                         actor_type=ActorType.human))
        assert not r.success
        assert r.failure_reason == AttestationFailureReason.actor_terminated

    def test_actor_type_mismatch_fails(self, attestor):
        """Automation claiming to be human must fail."""
        r = attestor.attest(make_request(actor_name="deploy-bot-prod",
                                         actor_type=ActorType.human))
        assert not r.success
        assert r.failure_reason == AttestationFailureReason.actor_type_mismatch

    def test_privilege_exceeds_max_fails(self, attestor):
        """security-scanner-bot has max=standard; claiming elevated must fail."""
        r = attestor.attest(make_request(actor_name="security-scanner-bot",
                                         actor_type=ActorType.automation,
                                         privilege_level=PrivilegeLevel.elevated))
        assert not r.success
        assert r.failure_reason == AttestationFailureReason.privilege_exceeds_maximum

    def test_admin_privilege_for_non_admin_actor_fails(self, attestor):
        r = attestor.attest(make_request(actor_name="deploy-bot-prod",
                                         actor_type=ActorType.automation,
                                         privilege_level=PrivilegeLevel.admin))
        assert not r.success
        assert r.failure_reason == AttestationFailureReason.privilege_exceeds_maximum
