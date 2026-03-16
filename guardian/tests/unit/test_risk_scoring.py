"""
Unit tests for the Risk Scoring Engine.

Validates that score bands are correct, signals are populated,
and that drift elevates scores as expected.
"""

import pytest
from datetime import datetime, timezone
from guardian.scoring.engine import RiskScoringEngine, action_scorer, actor_scorer, asset_scorer, context_scorer
from guardian.enrichment.context import EnrichedContext, AssetContext, MaintenanceWindowContext, ActorHistoryContext
from guardian.attestation.attestor import AttestationResult
from guardian.models.action_request import ActionRequest, ActorType, PrivilegeLevel, SensitivityLevel


def make_context(
    action="read_config",
    actor_type=ActorType.automation,
    privilege=PrivilegeLevel.standard,
    sensitivity=SensitivityLevel.internal,
    criticality="medium",
    in_window=False,
):
    request = ActionRequest(
        actor_name="test-bot",
        actor_type=actor_type,
        requested_action=action,
        target_system="test-system",
        target_asset="test-asset",
        privilege_level=privilege,
        sensitivity_level=sensitivity,
        timestamp=datetime.now(timezone.utc),
    )
    return EnrichedContext(
        request=request,
        attestation=AttestationResult(success=True, actor_name="test-bot",
                                       verified_actor_type=actor_type),
        asset=AssetContext(asset_id="test-asset", criticality=criticality,
                           sensitivity=sensitivity.value, found=True),
        maintenance_window=MaintenanceWindowContext(system="test-system",
                                                    in_window=in_window),
        actor_history=ActorHistoryContext(actor_name="test-bot"),
    )


class TestActionScorer:

    def test_destructive_action_scores_high(self):
        r = action_scorer(make_context(action="delete_resource"))
        assert r.score >= 0.85

    def test_security_control_action_scores_high(self):
        r = action_scorer(make_context(action="disable_endpoint_protection"))
        assert r.score >= 0.80

    def test_privilege_action_scores_medium_high(self):
        r = action_scorer(make_context(action="modify_iam_role"))
        assert r.score >= 0.65

    def test_moderate_action_scores_medium(self):
        r = action_scorer(make_context(action="modify_firewall_rule"))
        assert 0.3 <= r.score <= 0.65

    def test_unknown_action_scores_baseline(self):
        r = action_scorer(make_context(action="some_novel_unknown_action"))
        assert r.score <= 0.35

    def test_elevated_privilege_adds_to_score(self):
        standard = action_scorer(make_context(action="read_config", privilege=PrivilegeLevel.standard))
        elevated = action_scorer(make_context(action="read_config", privilege=PrivilegeLevel.elevated))
        assert elevated.score > standard.score

    def test_signals_are_populated(self):
        r = action_scorer(make_context(action="delete_resource"))
        assert len(r.signals) > 0


class TestActorScorer:

    def test_ai_agent_scores_higher_than_automation(self):
        ai = actor_scorer(make_context(actor_type=ActorType.ai_agent))
        auto = actor_scorer(make_context(actor_type=ActorType.automation))
        assert ai.score > auto.score

    def test_automation_scores_higher_than_human(self):
        auto = actor_scorer(make_context(actor_type=ActorType.automation))
        human = actor_scorer(make_context(actor_type=ActorType.human))
        assert auto.score > human.score


class TestAssetScorer:

    def test_restricted_critical_asset_scores_high(self):
        r = asset_scorer(make_context(sensitivity=SensitivityLevel.restricted, criticality="critical"))
        assert r.score >= 0.7

    def test_public_low_criticality_scores_low(self):
        r = asset_scorer(make_context(sensitivity=SensitivityLevel.public, criticality="low"))
        assert r.score <= 0.15


class TestContextScorer:

    def test_in_window_reduces_score(self):
        in_window = context_scorer(make_context(in_window=True))
        out_window = context_scorer(make_context(in_window=False))
        assert in_window.score < out_window.score

    def test_high_drift_elevates_score(self):
        no_drift = context_scorer(make_context(), drift_score=0.0)
        high_drift = context_scorer(make_context(), drift_score=0.9)
        assert high_drift.score > no_drift.score


class TestCompositeScoring:

    def test_composite_score_is_bounded(self):
        engine = RiskScoringEngine()
        ctx = make_context(action="delete_resource", actor_type=ActorType.ai_agent,
                           sensitivity=SensitivityLevel.restricted, criticality="critical")
        score, _ = engine.score(ctx, drift_score=1.0)
        assert 0.0 <= score <= 1.0

    def test_low_risk_scenario_scores_low(self):
        engine = RiskScoringEngine()
        ctx = make_context(action="read_config", actor_type=ActorType.human,
                           sensitivity=SensitivityLevel.public, criticality="low",
                           in_window=True)
        score, _ = engine.score(ctx, drift_score=0.0)
        assert score < 0.40

    def test_high_risk_scenario_scores_high(self):
        engine = RiskScoringEngine()
        ctx = make_context(action="disable_endpoint_protection", actor_type=ActorType.ai_agent,
                           sensitivity=SensitivityLevel.restricted, criticality="critical",
                           in_window=False)
        score, _ = engine.score(ctx, drift_score=0.8)
        assert score >= 0.65
