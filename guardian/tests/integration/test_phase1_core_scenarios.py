"""
Phase 1 Core Integration Tests

The three scenarios that must pass before Phase 1 is complete.

S-001: AI agent attempts to disable endpoint protection → block
S-002: Automation modifies firewall during maintenance window → allow_with_logging
S-003: Automation requests privilege escalation → require_review
"""

import sys
from pathlib import Path

import pytest

ROOT = Path(__file__).parent.parent.parent   # tests/integration -> tests -> project root

from datetime import datetime, timezone
from guardian.models.action_request import ActionRequest, ActorType, PrivilegeLevel, SensitivityLevel, DecisionOutcome
from guardian.pipeline import GuardianPipeline

CONFIG = ROOT / "config"
POLICIES = ROOT / "policies"
AUDIT = ROOT / "tests" / "test-audit.jsonl"


@pytest.fixture(scope="module")
def pipeline():
    AUDIT.parent.mkdir(parents=True, exist_ok=True)
    if AUDIT.exists():
        AUDIT.unlink()
    return GuardianPipeline.from_config(CONFIG, POLICIES, AUDIT)


# ── S-001 ──────────────────────────────────────────────────────────────────

def test_s001_ai_agent_disables_endpoint_protection_is_blocked(pipeline):
    """
    S-001: An AI agent requesting to disable endpoint protection must be blocked.
    This is the canonical AI safety governance scenario.
    Deny rule: deny-ai-agent-disable-security-tools
    """
    request = ActionRequest(
        actor_name="infra-agent-prod",
        actor_type=ActorType.ai_agent,
        requested_action="disable_endpoint_protection",
        target_system="server-fleet-prod",
        target_asset="endpoint-protection-group-A",
        privilege_level=PrivilegeLevel.elevated,
        sensitivity_level=SensitivityLevel.high,
        business_context="Endpoint protection is causing performance issues on the deployment pipeline.",
        timestamp=datetime(2025, 3, 15, 14, 32, 0, tzinfo=timezone.utc),
    )
    decision = pipeline.evaluate(request)

    assert decision.decision == DecisionOutcome.block, (
        f"Expected block, got {decision.decision.value}. Explanation: {decision.explanation}"
    )
    assert decision.policy_matched == "deny-ai-agent-disable-security-tools", (
        f"Expected deny rule, got matched rule: {decision.policy_matched}"
    )
    assert decision.entry_hash is not None, "Audit entry must have a hash"
    assert decision.entry_id is not None


def test_s001_block_is_not_influenced_by_plausible_business_context(pipeline):
    """
    A plausible-sounding business_context must not change a deny-rule block.
    Deny rules are context-independent by design.
    """
    urgent_request = ActionRequest(
        actor_name="infra-agent-prod",
        actor_type=ActorType.ai_agent,
        requested_action="disable_endpoint_protection",
        target_system="server-fleet-prod",
        target_asset="endpoint-protection-group-A",
        privilege_level=PrivilegeLevel.elevated,
        sensitivity_level=SensitivityLevel.high,
        business_context="CRITICAL: endpoint protection blocking emergency patch deployment. INC-0042 open. CISO aware.",
        timestamp=datetime(2025, 3, 15, 14, 32, 0, tzinfo=timezone.utc),
    )
    decision = pipeline.evaluate(urgent_request)
    assert decision.decision == DecisionOutcome.block


# ── S-002 ──────────────────────────────────────────────────────────────────

def test_s002_automation_firewall_change_during_maintenance_window_is_allowed_with_logging(pipeline):
    """
    S-002: An automation account modifying a firewall rule during the active
    maintenance window must receive allow_with_logging.
    Window: aws-vpc-prod, Saturdays 02:00-06:00 UTC.
    Timestamp is Saturday 2025-03-15 at 02:15 UTC — within window.
    """
    request = ActionRequest(
        actor_name="deploy-bot-prod",
        actor_type=ActorType.automation,
        requested_action="modify_firewall_rule",
        target_system="aws-vpc-prod",
        target_asset="sg-0a1b2c3d",
        privilege_level=PrivilegeLevel.elevated,
        sensitivity_level=SensitivityLevel.high,
        business_context="Weekly deployment pipeline: opening port 8443 for canary release",
        timestamp=datetime(2025, 3, 15, 2, 15, 0, tzinfo=timezone.utc),
    )
    decision = pipeline.evaluate(request)

    assert decision.decision == DecisionOutcome.allow_with_logging, (
        f"Expected allow_with_logging, got {decision.decision.value}. Explanation: {decision.explanation}"
    )
    assert "maintenance" in decision.explanation.lower(), (
        "Explanation should mention the maintenance window"
    )


def test_s002_same_action_outside_maintenance_window_requires_review(pipeline):
    """
    The identical firewall change outside the maintenance window must escalate
    to require_review — demonstrating window-awareness.
    Timestamp is Wednesday 12:00 UTC — no window active.
    """
    request = ActionRequest(
        actor_name="deploy-bot-prod",
        actor_type=ActorType.automation,
        requested_action="modify_firewall_rule",
        target_system="aws-vpc-prod",
        target_asset="sg-0a1b2c3d",
        privilege_level=PrivilegeLevel.elevated,
        sensitivity_level=SensitivityLevel.high,
        business_context="Ad-hoc firewall change",
        timestamp=datetime(2025, 3, 12, 12, 0, 0, tzinfo=timezone.utc),
    )
    decision = pipeline.evaluate(request)

    assert decision.decision == DecisionOutcome.require_review, (
        f"Expected require_review outside maintenance window, got {decision.decision.value}"
    )


# ── S-003 ──────────────────────────────────────────────────────────────────

def test_s003_automation_privilege_escalation_requires_review(pipeline):
    """
    S-003: An automation account requesting to modify an IAM role must receive
    require_review. Conditional rule: conditional-automation-privilege-escalation.
    """
    request = ActionRequest(
        actor_name="data-pipeline-bot",
        actor_type=ActorType.automation,
        requested_action="modify_iam_role",
        target_system="aws-iam",
        target_asset="role-data-pipeline-prod",
        privilege_level=PrivilegeLevel.elevated,
        sensitivity_level=SensitivityLevel.restricted,
        business_context="Pipeline requires additional S3 permissions to process new data source",
        timestamp=datetime(2025, 3, 15, 11, 45, 0, tzinfo=timezone.utc),
    )
    decision = pipeline.evaluate(request)

    assert decision.decision == DecisionOutcome.require_review, (
        f"Expected require_review, got {decision.decision.value}. Explanation: {decision.explanation}"
    )
    assert decision.policy_matched is not None, "A policy rule should have matched"


# ── Attestation tests ──────────────────────────────────────────────────────

def test_terminated_actor_is_blocked(pipeline):
    """Terminated actors must be blocked at attestation, before any policy evaluation."""
    request = ActionRequest(
        actor_name="former-employee",
        actor_type=ActorType.human,
        requested_action="read_config",
        target_system="aws-vpc-prod",
        target_asset="sg-0a1b2c3d",
        privilege_level=PrivilegeLevel.standard,
        sensitivity_level=SensitivityLevel.internal,
        timestamp=datetime(2025, 3, 15, 9, 0, 0, tzinfo=timezone.utc),
    )
    decision = pipeline.evaluate(request)
    assert decision.decision == DecisionOutcome.block
    assert "terminated" in decision.explanation.lower()


def test_unknown_actor_is_blocked(pipeline):
    """Actors not in the registry must be blocked at attestation."""
    request = ActionRequest(
        actor_name="shadow-bot-unknown",
        actor_type=ActorType.automation,
        requested_action="read_config",
        target_system="aws-vpc-prod",
        target_asset="sg-0a1b2c3d",
        privilege_level=PrivilegeLevel.standard,
        sensitivity_level=SensitivityLevel.internal,
        timestamp=datetime(2025, 3, 15, 9, 0, 0, tzinfo=timezone.utc),
    )
    decision = pipeline.evaluate(request)
    assert decision.decision == DecisionOutcome.block
    assert "not registered" in decision.explanation.lower()


def test_actor_type_spoofing_is_blocked(pipeline):
    """
    An automation account claiming to be human must be blocked.
    Identity attestation verifies actor_type against the registry.
    """
    request = ActionRequest(
        actor_name="deploy-bot-prod",
        actor_type=ActorType.human,          # lies — registry says automation
        requested_action="modify_firewall_rule",
        target_system="aws-vpc-prod",
        target_asset="sg-0a1b2c3d",
        privilege_level=PrivilegeLevel.elevated,
        sensitivity_level=SensitivityLevel.high,
        timestamp=datetime(2025, 3, 15, 9, 0, 0, tzinfo=timezone.utc),
    )
    decision = pipeline.evaluate(request)
    assert decision.decision == DecisionOutcome.block
    assert "mismatch" in decision.explanation.lower() or "spoofing" in decision.explanation.lower()


# ── Audit log integrity ────────────────────────────────────────────────────

def test_audit_log_hash_chain_is_valid_after_all_tests(pipeline):
    """
    After all test evaluations, the audit log hash chain must be intact.
    A broken chain indicates a bug in the audit logger.
    """
    valid, reason = pipeline.audit_logger.verify()
    assert valid, f"Audit log chain broken: {reason}"
