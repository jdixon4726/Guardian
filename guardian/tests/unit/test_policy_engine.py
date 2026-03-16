"""
Unit tests for the Policy Engine.

Tests each rule type in isolation, conflict resolution logic,
and the short-circuit deny-wins behavior.
"""

import pytest
from guardian.models.action_request import DecisionOutcome
from guardian.policy.engine import (
    AllowRule,
    ConditionalRule,
    DenyRule,
    PolicyEngine,
    PolicyVerdict,
)


def make_engine(deny=None, conditional=None, allow=None) -> PolicyEngine:
    return PolicyEngine(
        deny_rules=deny or [],
        conditional_rules=conditional or [],
        allow_rules=allow or [],
    )


class TestDenyRules:

    def test_matching_deny_rule_returns_block(self):
        rule = DenyRule("d1", "Test deny", {"actor_type": "ai_agent"})
        engine = make_engine(deny=[rule])
        verdict = engine.evaluate({"actor_type": "ai_agent"})
        assert verdict.outcome == DecisionOutcome.block
        assert verdict.rule_id == "d1"

    def test_non_matching_deny_rule_passes_through(self):
        rule = DenyRule("d1", "Test deny", {"actor_type": "ai_agent"})
        engine = make_engine(deny=[rule])
        verdict = engine.evaluate({"actor_type": "automation"})
        assert verdict.outcome == DecisionOutcome.require_review  # default
        assert not verdict.matched

    def test_deny_rule_with_list_condition_matches_any(self):
        rule = DenyRule("d1", "Test deny", {
            "requested_action": ["disable_antivirus", "disable_edr"]
        })
        engine = make_engine(deny=[rule])
        assert engine.evaluate({"requested_action": "disable_antivirus"}).outcome == DecisionOutcome.block
        assert engine.evaluate({"requested_action": "disable_edr"}).outcome == DecisionOutcome.block
        assert engine.evaluate({"requested_action": "read_config"}).outcome == DecisionOutcome.require_review

    def test_deny_halts_pipeline_before_conditional(self):
        """A matching deny rule must prevent conditional rule evaluation."""
        deny = DenyRule("d1", "Deny", {"actor_type": "ai_agent"})
        # This conditional would allow the action — deny must win
        conditional = ConditionalRule("c1", "Allow conditionally",
                                      {"actor_type": "ai_agent"}, DecisionOutcome.allow)
        engine = make_engine(deny=[deny], conditional=[conditional])
        verdict = engine.evaluate({"actor_type": "ai_agent"})
        assert verdict.outcome == DecisionOutcome.block
        assert verdict.rule_id == "d1"

    def test_first_matching_deny_rule_wins(self):
        rule1 = DenyRule("d1", "First deny", {"actor_type": "ai_agent"})
        rule2 = DenyRule("d2", "Second deny", {"actor_type": "ai_agent"})
        engine = make_engine(deny=[rule1, rule2])
        verdict = engine.evaluate({"actor_type": "ai_agent"})
        assert verdict.rule_id == "d1"


class TestConditionalRules:

    def test_matching_conditional_returns_its_outcome(self):
        rule = ConditionalRule("c1", "Conditional", {"privilege_level": "elevated"},
                               DecisionOutcome.require_review)
        engine = make_engine(conditional=[rule])
        verdict = engine.evaluate({"privilege_level": "elevated"})
        assert verdict.outcome == DecisionOutcome.require_review
        assert verdict.rule_id == "c1"

    def test_conflict_resolution_most_restrictive_wins(self):
        """When multiple conditional rules match, the most restrictive verdict wins."""
        c_allow = ConditionalRule("c-allow", "Allow", {"actor_type": "automation"},
                                  DecisionOutcome.allow_with_logging)
        c_review = ConditionalRule("c-review", "Review", {"actor_type": "automation"},
                                   DecisionOutcome.require_review)
        engine = make_engine(conditional=[c_allow, c_review])
        verdict = engine.evaluate({"actor_type": "automation"})
        assert verdict.outcome == DecisionOutcome.require_review

    def test_conflict_resolution_block_beats_all(self):
        c_allow = ConditionalRule("c1", "Allow", {"x": "y"}, DecisionOutcome.allow)
        c_review = ConditionalRule("c2", "Review", {"x": "y"}, DecisionOutcome.require_review)
        c_block = ConditionalRule("c3", "Block", {"x": "y"}, DecisionOutcome.block)
        engine = make_engine(conditional=[c_allow, c_review, c_block])
        verdict = engine.evaluate({"x": "y"})
        assert verdict.outcome == DecisionOutcome.block


class TestAllowRules:

    def test_matching_allow_rule_returns_allow(self):
        rule = AllowRule("a1", "Allow dev sandbox", {"target_system": "aws-dev"})
        engine = make_engine(allow=[rule])
        verdict = engine.evaluate({"target_system": "aws-dev"})
        assert verdict.outcome == DecisionOutcome.allow

    def test_allow_rule_does_not_fire_when_deny_matches(self):
        deny = DenyRule("d1", "Block all ai agents", {"actor_type": "ai_agent"})
        allow = AllowRule("a1", "Allow all", {})
        engine = make_engine(deny=[deny], allow=[allow])
        verdict = engine.evaluate({"actor_type": "ai_agent"})
        assert verdict.outcome == DecisionOutcome.block


class TestDefaultBehavior:

    def test_no_matching_rule_returns_require_review(self):
        """The safe default — no rule matched — must be require_review, never allow."""
        engine = make_engine()
        verdict = engine.evaluate({"actor_type": "automation", "requested_action": "unknown_action"})
        assert verdict.outcome == DecisionOutcome.require_review
        assert not verdict.matched

    def test_empty_context_uses_default(self):
        engine = make_engine()
        verdict = engine.evaluate({})
        assert verdict.outcome == DecisionOutcome.require_review
