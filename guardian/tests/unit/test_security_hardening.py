"""
Unit tests for Guardian security hardening measures.

Tests cover:
  - Bundle signature verification (sign, verify, tamper detection)
  - Audit log replication sink interface
  - Adapter-derived actor identity resolution
  - Reconciliation engine (ungoverned action detection)
"""

import json
from datetime import datetime, timedelta, timezone
from pathlib import Path
from tempfile import TemporaryDirectory

import pytest

from guardian.adapters.identity import (
    DirectIdentityResolver,
    TerraformIdentityResolver,
    KubernetesIdentityResolver,
)
from guardian.audit.logger import AuditLogger, FileReplicationSink
from guardian.config.signature import BundleVerifier
from guardian.models.action_request import (
    ActionRequest, ActorType, Decision, DecisionOutcome,
    PrivilegeLevel, SensitivityLevel,
)
from guardian.reconciliation.engine import (
    ExternalAction,
    ReconciliationEngine,
    ExternalActivitySource,
)


# ── Bundle Signature Verification ────────────────────────────────────────


class TestBundleVerifier:
    def test_sign_and_verify_succeeds(self, tmp_path):
        # Create a config bundle
        (tmp_path / "guardian.yaml").write_text("scoring:\n  weights:\n    action: 0.30")
        (tmp_path / "actor-registry.yaml").write_text("actors: []")

        verifier = BundleVerifier(secret="test-secret-123")
        verifier.sign_bundle(tmp_path)

        result = verifier.verify(tmp_path, mode="enforce")
        assert result.valid
        assert result.manifest_hash is not None

    def test_tampered_file_detected(self, tmp_path):
        (tmp_path / "guardian.yaml").write_text("scoring:\n  weights:\n    action: 0.30")
        verifier = BundleVerifier(secret="test-secret-123")
        verifier.sign_bundle(tmp_path)

        # Tamper with the config file
        (tmp_path / "guardian.yaml").write_text("scoring:\n  weights:\n    action: 0.99")

        result = verifier.verify(tmp_path, mode="enforce")
        assert not result.valid
        assert "modified" in result.reason

    def test_missing_signature_fails_in_enforce_mode(self, tmp_path):
        (tmp_path / "guardian.yaml").write_text("test: true")
        # Write manifest but no signature
        verifier = BundleVerifier(secret="test-secret")
        manifest = verifier.compute_manifest(tmp_path)
        (tmp_path / "bundle-manifest.json").write_text(json.dumps(manifest))

        result = verifier.verify(tmp_path, mode="enforce")
        assert not result.valid
        assert "bundle.sig" in result.reason

    def test_missing_signature_warns_in_warn_mode(self, tmp_path):
        (tmp_path / "guardian.yaml").write_text("test: true")
        result = BundleVerifier(secret="test").verify(tmp_path, mode="warn")
        assert result.valid  # warns but doesn't fail

    def test_verification_off_always_passes(self, tmp_path):
        result = BundleVerifier().verify(tmp_path, mode="off")
        assert result.valid

    def test_wrong_secret_fails(self, tmp_path):
        (tmp_path / "guardian.yaml").write_text("test: true")
        signer = BundleVerifier(secret="correct-secret")
        signer.sign_bundle(tmp_path)

        wrong_verifier = BundleVerifier(secret="wrong-secret")
        result = wrong_verifier.verify(tmp_path, mode="enforce")
        assert not result.valid
        assert "tampered" in result.reason.lower()

    def test_deleted_file_detected(self, tmp_path):
        (tmp_path / "a.yaml").write_text("a: 1")
        (tmp_path / "b.yaml").write_text("b: 2")
        verifier = BundleVerifier(secret="secret")
        verifier.sign_bundle(tmp_path)

        # Delete a file
        (tmp_path / "b.yaml").unlink()

        result = verifier.verify(tmp_path, mode="enforce")
        assert not result.valid

    def test_no_secret_fails_in_enforce_mode(self, tmp_path):
        (tmp_path / "guardian.yaml").write_text("test: true")
        (tmp_path / "bundle-manifest.json").write_text("{}")
        (tmp_path / "bundle.sig").write_text("fake")

        result = BundleVerifier(secret=None).verify(tmp_path, mode="enforce")
        assert not result.valid


# ── Audit Log Replication ────────────────────────────────────────────────


class TestAuditReplication:
    def _make_decision(self):
        return Decision(
            action_request=ActionRequest(
                actor_name="test-bot",
                actor_type=ActorType.automation,
                requested_action="read_config",
                target_system="test",
                target_asset="test-asset",
                privilege_level=PrivilegeLevel.standard,
                sensitivity_level=SensitivityLevel.internal,
                timestamp=datetime.now(timezone.utc),
            ),
            decision=DecisionOutcome.allow,
            risk_score=0.2,
            explanation="Test decision",
        )

    def test_replication_sink_receives_entries(self, tmp_path):
        primary = tmp_path / "audit.jsonl"
        replica = tmp_path / "replica.jsonl"

        sink = FileReplicationSink(replica)
        logger = AuditLogger(primary, replication_sinks=[sink])

        decision = self._make_decision()
        logger.write(decision)

        assert replica.exists()
        lines = replica.read_text(encoding="utf-8").strip().split("\n")
        assert len(lines) == 1

    def test_multiple_sinks(self, tmp_path):
        primary = tmp_path / "audit.jsonl"
        replica1 = tmp_path / "replica1.jsonl"
        replica2 = tmp_path / "replica2.jsonl"

        logger = AuditLogger(primary, replication_sinks=[
            FileReplicationSink(replica1),
            FileReplicationSink(replica2),
        ])
        logger.write(self._make_decision())

        assert replica1.exists()
        assert replica2.exists()

    def test_sink_failure_does_not_block_write(self, tmp_path):
        primary = tmp_path / "audit.jsonl"

        class FailingSink(FileReplicationSink):
            def replicate(self, *a, **kw):
                raise OSError("disk full")

        logger = AuditLogger(primary, replication_sinks=[
            FailingSink(tmp_path / "will-fail.jsonl"),
        ])
        # Should not raise
        result = logger.write(self._make_decision())
        assert result.entry_hash is not None
        assert primary.exists()


# ── Adapter-Derived Actor Identity ───────────────────────────────────────


class TestTerraformIdentity:
    def test_workspace_identity(self):
        resolver = TerraformIdentityResolver()
        result = resolver.resolve({
            "workspace_name": "production-vpc",
            "organization_name": "acme-corp",
            "run_created_by": "alice@acme.com",
        })
        assert result.actor_name == "terraform-acme-corp-production-vpc"
        assert result.authenticated
        assert result.confidence == 1.0

    def test_fallback_to_triggered_by(self):
        resolver = TerraformIdentityResolver()
        result = resolver.resolve({
            "workspace_name": "",
            "run_created_by": "bob@acme.com",
        })
        assert result.actor_name == "bob@acme.com"
        assert result.confidence == 0.7

    def test_unknown_returns_unauthenticated(self):
        resolver = TerraformIdentityResolver()
        result = resolver.resolve({})
        assert not result.authenticated
        assert result.confidence == 0.0


class TestKubernetesIdentity:
    def test_service_account_identity(self):
        resolver = KubernetesIdentityResolver()
        result = resolver.resolve({
            "service_account": "deploy-bot",
            "namespace": "production",
        })
        assert result.actor_name == "k8s-production-deploy-bot"
        assert result.authenticated
        assert result.confidence == 1.0

    def test_unknown_returns_unauthenticated(self):
        resolver = KubernetesIdentityResolver()
        result = resolver.resolve({})
        assert not result.authenticated


class TestDirectIdentity:
    def test_caller_asserted_is_lower_confidence(self):
        resolver = DirectIdentityResolver()
        result = resolver.resolve({"actor_name": "some-bot"})
        assert result.actor_name == "some-bot"
        assert result.confidence == 0.5  # not adapter-verified


# ── Reconciliation Engine ────────────────────────────────────────────────


class MockActivitySource(ExternalActivitySource):
    def __init__(self, actions: list[ExternalAction]):
        self._actions = actions

    def fetch_actions(self, start, end):
        return [a for a in self._actions
                if start <= a.timestamp <= end]

    def source_name(self):
        return "mock"


class TestReconciliation:
    def test_all_governed_produces_clean_report(self, tmp_path):
        now = datetime.now(timezone.utc)
        audit_path = tmp_path / "audit.jsonl"

        # Write a governed action to the audit log
        logger = AuditLogger(audit_path)
        decision = Decision(
            action_request=ActionRequest(
                actor_name="bot-a",
                actor_type=ActorType.automation,
                requested_action="modify_firewall_rule",
                target_system="aws-vpc",
                target_asset="sg-123",
                privilege_level=PrivilegeLevel.standard,
                sensitivity_level=SensitivityLevel.internal,
                timestamp=now,
            ),
            decision=DecisionOutcome.allow,
            risk_score=0.2,
            explanation="test",
        )
        logger.write(decision)

        # External source reports the same action
        source = MockActivitySource([
            ExternalAction(
                source="cloudtrail",
                actor="bot-a",
                action="modify_firewall_rule",
                resource="sg-123",
                timestamp=now,
                event_id="evt-1",
            ),
        ])

        engine = ReconciliationEngine([source], audit_path)
        report = engine.reconcile(window_minutes=10, at=now + timedelta(seconds=1))
        assert report.total_ungoverned == 0

    def test_ungoverned_action_detected(self, tmp_path):
        now = datetime.now(timezone.utc)
        audit_path = tmp_path / "audit.jsonl"
        audit_path.write_text("")  # empty audit log

        # External source reports an action with no Guardian decision
        source = MockActivitySource([
            ExternalAction(
                source="cloudtrail",
                actor="rogue-user",
                action="DeleteSecurityGroup",
                resource="sg-999",
                timestamp=now,
                event_id="evt-2",
            ),
        ])

        engine = ReconciliationEngine([source], audit_path)
        report = engine.reconcile(window_minutes=10, at=now + timedelta(seconds=1))
        assert report.total_ungoverned == 1
        assert report.ungoverned_actions[0].severity == "high"

    def test_critical_action_severity(self, tmp_path):
        now = datetime.now(timezone.utc)
        source = MockActivitySource([
            ExternalAction(
                source="cloudtrail",
                actor="attacker",
                action="CreateAccessKey",
                resource="iam-user-backdoor",
                timestamp=now,
                event_id="evt-3",
            ),
        ])

        engine = ReconciliationEngine([source], tmp_path / "empty.jsonl")
        report = engine.reconcile(window_minutes=10, at=now + timedelta(seconds=1))
        assert report.ungoverned_actions[0].severity == "critical"
