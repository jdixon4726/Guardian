"""
Unit tests for the Decision Engine matrix.

Verifies that the policy × risk band matrix produces correct outcomes
and that the escalation / de-escalation rules from decision-semantics.md hold.
"""

import pytest
from guardian.decision.engine import DecisionEngine
from guardian.models.action_request import DecisionOutcome
from guardian.policy.engine import PolicyVerdict


def decide(policy_outcome: DecisionOutcome, risk_score: float) -> DecisionOutcome:
    engine = DecisionEngine()
    verdict = PolicyVerdict(
        outcome=policy_outcome,
        rule_id="test-rule",
        matched=policy_outcome != DecisionOutcome.require_review,
        explanation="Test verdict",
    )
    result = engine.decide(verdict, risk_score, "Test policy", "Test signals")
    return result.outcome


class TestBlockIsAlwaysFinal:

    def test_block_with_low_risk_stays_block(self):
        assert decide(DecisionOutcome.block, 0.1) == DecisionOutcome.block

    def test_block_with_zero_risk_stays_block(self):
        assert decide(DecisionOutcome.block, 0.0) == DecisionOutcome.block


class TestRequireReviewIsSticky:
    """require_review cannot be downgraded by a low risk score."""

    def test_require_review_with_low_risk_stays_review(self):
        assert decide(DecisionOutcome.require_review, 0.1) == DecisionOutcome.require_review

    def test_require_review_with_zero_risk_stays_review(self):
        assert decide(DecisionOutcome.require_review, 0.0) == DecisionOutcome.require_review


class TestAllowEscalation:
    """A high or critical risk score escalates an allow upward."""

    def test_allow_with_low_risk_stays_allow(self):
        assert decide(DecisionOutcome.allow, 0.20) == DecisionOutcome.allow

    def test_allow_with_medium_risk_becomes_allow_with_logging(self):
        assert decide(DecisionOutcome.allow, 0.45) == DecisionOutcome.allow_with_logging

    def test_allow_with_high_risk_becomes_require_review(self):
        assert decide(DecisionOutcome.allow, 0.70) == DecisionOutcome.require_review

    def test_allow_with_critical_risk_becomes_block(self):
        assert decide(DecisionOutcome.allow, 0.90) == DecisionOutcome.block


class TestAllowWithLoggingEscalation:

    def test_allow_with_logging_medium_risk_unchanged(self):
        assert decide(DecisionOutcome.allow_with_logging, 0.45) == DecisionOutcome.allow_with_logging

    def test_allow_with_logging_high_risk_escalates_to_review(self):
        assert decide(DecisionOutcome.allow_with_logging, 0.70) == DecisionOutcome.require_review

    def test_allow_with_logging_critical_risk_escalates_to_review(self):
        # Critical risk with allow_with_logging → require_review (not block)
        assert decide(DecisionOutcome.allow_with_logging, 0.90) == DecisionOutcome.require_review


class TestRiskBandBoundaries:
    """Verify boundary values map to the correct bands."""

    def test_score_030_is_low(self):
        assert decide(DecisionOutcome.allow, 0.30) == DecisionOutcome.allow

    def test_score_031_is_medium(self):
        assert decide(DecisionOutcome.allow, 0.31) == DecisionOutcome.allow_with_logging

    def test_score_060_is_medium(self):
        assert decide(DecisionOutcome.allow, 0.60) == DecisionOutcome.allow_with_logging

    def test_score_061_is_high(self):
        assert decide(DecisionOutcome.allow, 0.61) == DecisionOutcome.require_review

    def test_score_080_is_high(self):
        assert decide(DecisionOutcome.allow, 0.80) == DecisionOutcome.require_review

    def test_score_081_is_critical(self):
        assert decide(DecisionOutcome.allow, 0.81) == DecisionOutcome.block
