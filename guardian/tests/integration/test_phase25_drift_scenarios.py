"""
Phase 2.5 Drift Detection Integration Tests

Tests drift detection through the full Guardian pipeline, verifying that
behavioral anomalies influence the final decision and risk score.
"""

from __future__ import annotations

from datetime import datetime, timedelta, timezone
from pathlib import Path

import pytest

from guardian.drift.baseline import BaselineStore
from guardian.drift.alerts import AlertPublisher
from guardian.models.action_request import (
    ActionRequest,
    ActorType,
    DecisionOutcome,
    PrivilegeLevel,
    SensitivityLevel,
)
from guardian.pipeline import GuardianPipeline

ROOT = Path(__file__).parent.parent.parent
CONFIG = ROOT / "config"
POLICIES = ROOT / "policies"
AUDIT = ROOT / "tests" / "test-drift-audit.jsonl"


@pytest.fixture(scope="module")
def drift_pipeline():
    """Pipeline with in-memory baseline store for drift testing."""
    AUDIT.parent.mkdir(parents=True, exist_ok=True)
    if AUDIT.exists():
        AUDIT.unlink()

    from guardian.attestation.attestor import ActorRegistry
    from guardian.audit.logger import AuditLogger
    from guardian.enrichment.context import AssetCatalog, MaintenanceWindowStore
    from guardian.policy.engine import PolicyEngine
    from guardian.policy.loaders import PolicyLoader

    actor_registry = ActorRegistry(CONFIG / "actor-registry.yaml")
    asset_catalog = AssetCatalog(CONFIG / "asset-catalog.yaml")
    window_store = MaintenanceWindowStore(CONFIG / "maintenance-windows.yaml")

    loader = PolicyLoader(POLICIES)
    deny_rules, conditional_rules, allow_rules = loader.load_all()
    policy_engine = PolicyEngine(deny_rules, conditional_rules, allow_rules)

    audit_logger = AuditLogger(AUDIT)
    baseline_store = BaselineStore(":memory:")
    alert_publisher = AlertPublisher()  # no file, just in-memory counting

    pipeline = GuardianPipeline(
        actor_registry=actor_registry,
        asset_catalog=asset_catalog,
        window_store=window_store,
        policy_engine=policy_engine,
        audit_logger=audit_logger,
        baseline_store=baseline_store,
        alert_publisher=alert_publisher,
    )
    # Expose for assertions
    pipeline._test_baseline_store = baseline_store
    pipeline._test_alert_publisher = alert_publisher
    return pipeline


def _make_request(
    actor: str,
    action: str,
    target_system: str = "aws-vpc-prod",
    target_asset: str = "sg-0a1b2c3d",
    actor_type: ActorType = ActorType.automation,
    privilege: PrivilegeLevel = PrivilegeLevel.elevated,
    sensitivity: SensitivityLevel = SensitivityLevel.high,
    timestamp: datetime | None = None,
) -> ActionRequest:
    if timestamp is None:
        timestamp = datetime(2025, 3, 15, 2, 15, 0, tzinfo=timezone.utc)
    return ActionRequest(
        actor_name=actor,
        actor_type=actor_type,
        requested_action=action,
        target_system=target_system,
        target_asset=target_asset,
        privilege_level=privilege,
        sensitivity_level=sensitivity,
        timestamp=timestamp,
    )


class TestDriftIntegration:
    """Test that drift detection integrates with the full pipeline."""

    def test_new_actor_gets_neutral_drift(self, drift_pipeline):
        """First evaluation for an actor should have neutral drift."""
        request = _make_request(
            "deploy-bot-prod", "modify_firewall_rule",
            timestamp=datetime(2025, 3, 15, 2, 15, 0, tzinfo=timezone.utc),
        )
        decision = drift_pipeline.evaluate(request)
        assert decision.drift_score is not None
        assert decision.drift_score.score == 0.0

    def test_baseline_builds_over_evaluations(self, drift_pipeline):
        """After enough evaluations, a baseline should be established."""
        store = drift_pipeline._test_baseline_store

        for i in range(6):
            request = _make_request(
                "deploy-bot-prod", "modify_firewall_rule",
                timestamp=datetime(2025, 3, 15, 2 + i, 15, 0, tzinfo=timezone.utc),
            )
            drift_pipeline.evaluate(request)

        store.recompute_baseline("deploy-bot-prod")
        baseline = store.get_baseline("deploy-bot-prod")
        assert baseline.has_baseline

    def test_anomalous_action_after_baseline_shows_drift(self, drift_pipeline):
        """After building a baseline, an anomalous action should produce drift."""
        store = drift_pipeline._test_baseline_store

        # Build baseline with consistent behavior
        actor = "security-scanner-bot"
        for i in range(10):
            request = _make_request(
                actor, "read_config",
                actor_type=ActorType.automation,
                privilege=PrivilegeLevel.standard,
                sensitivity=SensitivityLevel.internal,
                target_system="aws-vpc-prod",
                target_asset="dev-sandbox",
                timestamp=datetime(2025, 3, 1, i, 0, 0, tzinfo=timezone.utc),
            )
            drift_pipeline.evaluate(request)

        store.recompute_baseline(actor)

        # Now send an anomalous request — security scanner trying to modify IAM
        anomalous = _make_request(
            actor, "modify_iam_role",
            actor_type=ActorType.automation,
            privilege=PrivilegeLevel.standard,
            sensitivity=SensitivityLevel.restricted,
            target_system="aws-iam",
            target_asset="role-data-pipeline-prod",
            timestamp=datetime(2025, 3, 15, 12, 0, 0, tzinfo=timezone.utc),
        )
        decision = drift_pipeline.evaluate(anomalous)

        assert decision.drift_score is not None
        assert decision.drift_score.score > 0.0, (
            "Anomalous action should produce non-zero drift"
        )
        assert decision.drift_score.level_drift_z > 0.0, (
            "Risk spike should be reflected in z-score"
        )

    def test_drift_score_present_in_decision(self, drift_pipeline):
        """Every decision should include a drift score."""
        request = _make_request(
            "alice.chen", "modify_firewall_rule",
            actor_type=ActorType.human,
            privilege=PrivilegeLevel.elevated,
            timestamp=datetime(2025, 3, 15, 2, 30, 0, tzinfo=timezone.utc),
        )
        decision = drift_pipeline.evaluate(request)
        assert decision.drift_score is not None
        assert decision.drift_score.explanation is not None


class TestPhase1ScenariosStillPass:
    """
    Verify that Phase 1 core scenarios still pass with drift detection active.
    Drift detection must not break existing behavior.
    """

    def test_s001_ai_agent_block_unaffected(self, drift_pipeline):
        """Deny rules still fire regardless of drift state."""
        request = ActionRequest(
            actor_name="infra-agent-prod",
            actor_type=ActorType.ai_agent,
            requested_action="disable_endpoint_protection",
            target_system="server-fleet-prod",
            target_asset="endpoint-protection-group-A",
            privilege_level=PrivilegeLevel.elevated,
            sensitivity_level=SensitivityLevel.high,
            business_context="Testing",
            timestamp=datetime(2025, 3, 15, 14, 32, 0, tzinfo=timezone.utc),
        )
        decision = drift_pipeline.evaluate(request)
        assert decision.decision == DecisionOutcome.block

    def test_s002_maintenance_window_unaffected(self, drift_pipeline):
        """Maintenance window conditional still works."""
        request = ActionRequest(
            actor_name="deploy-bot-prod",
            actor_type=ActorType.automation,
            requested_action="modify_firewall_rule",
            target_system="aws-vpc-prod",
            target_asset="sg-0a1b2c3d",
            privilege_level=PrivilegeLevel.elevated,
            sensitivity_level=SensitivityLevel.high,
            business_context="Weekly deployment",
            timestamp=datetime(2025, 3, 15, 2, 15, 0, tzinfo=timezone.utc),
        )
        decision = drift_pipeline.evaluate(request)
        assert decision.decision == DecisionOutcome.allow_with_logging

    def test_s003_privilege_escalation_unaffected(self, drift_pipeline):
        """Privilege escalation conditional still works."""
        request = ActionRequest(
            actor_name="data-pipeline-bot",
            actor_type=ActorType.automation,
            requested_action="modify_iam_role",
            target_system="aws-iam",
            target_asset="role-data-pipeline-prod",
            privilege_level=PrivilegeLevel.elevated,
            sensitivity_level=SensitivityLevel.restricted,
            business_context="Need S3 permissions",
            timestamp=datetime(2025, 3, 15, 11, 45, 0, tzinfo=timezone.utc),
        )
        decision = drift_pipeline.evaluate(request)
        assert decision.decision == DecisionOutcome.require_review
