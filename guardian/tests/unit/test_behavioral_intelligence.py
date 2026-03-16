"""
Unit tests for Darktrace-inspired behavioral intelligence components.

Tests cover:
  - Bayesian confidence scoring (wide-then-narrow intervals)
  - Peer group auto-discovery and cold-start inheritance
  - Multi-dimensional anomaly scoring with composite model breaches
"""

import math
from datetime import datetime, timedelta, timezone

import pytest

from guardian.behavioral.anomaly import (
    AnomalyAssessment,
    MultiDimensionalAnomalyScorer,
)
from guardian.behavioral.confidence import (
    BayesianConfidenceScorer,
    ConfidenceEstimate,
)
from guardian.behavioral.peer_groups import PeerGroupEngine
from guardian.drift.baseline import BaselineStore


# ── Bayesian Confidence Scoring ──────────────────────────────────────────


class TestBayesianConfidence:
    def test_new_actor_has_wide_interval(self):
        scorer = BayesianConfidenceScorer()
        estimate = scorer.estimate("automation", risky_count=0, normal_count=0)
        assert estimate.width > 0.3
        assert estimate.is_uncertain
        assert not estimate.is_precise

    def test_interval_narrows_with_observations(self):
        scorer = BayesianConfidenceScorer()
        few = scorer.estimate("automation", risky_count=1, normal_count=4)
        many = scorer.estimate("automation", risky_count=10, normal_count=40)
        assert many.width < few.width

    def test_confidence_increases_with_observations(self):
        scorer = BayesianConfidenceScorer()
        few = scorer.estimate("automation", risky_count=1, normal_count=4)
        many = scorer.estimate("automation", risky_count=10, normal_count=40)
        assert many.confidence > few.confidence

    def test_established_actor_has_precise_interval(self):
        scorer = BayesianConfidenceScorer()
        estimate = scorer.estimate("automation", risky_count=5, normal_count=95)
        assert estimate.is_precise or estimate.width < 0.15

    def test_ai_agent_has_higher_prior_risk(self):
        scorer = BayesianConfidenceScorer()
        ai = scorer.estimate("ai_agent", risky_count=0, normal_count=0)
        human = scorer.estimate("human", risky_count=0, normal_count=0)
        assert ai.mean > human.mean

    def test_risky_history_raises_mean(self):
        scorer = BayesianConfidenceScorer()
        clean = scorer.estimate("automation", risky_count=2, normal_count=48)
        risky = scorer.estimate("automation", risky_count=20, normal_count=30)
        assert risky.mean > clean.mean

    def test_estimate_bounded_zero_to_one(self):
        scorer = BayesianConfidenceScorer()
        extreme = scorer.estimate("automation", risky_count=1000, normal_count=0)
        assert 0.0 <= extreme.lower <= extreme.mean <= extreme.upper <= 1.0


# ── Peer Group Auto-Discovery ────────────────────────────────────────────


@pytest.fixture
def baseline_store():
    s = BaselineStore(":memory:")
    yield s
    s.close()


class TestPeerGroups:
    def _seed_actor(self, store, actor, actions, risk=0.3):
        now = datetime.now(timezone.utc)
        for i, action in enumerate(actions):
            store.record_observation(
                actor, action, risk,
                now - timedelta(hours=i),
            )
        store.recompute_baseline(actor)

    def test_similar_actors_grouped(self, baseline_store):
        # Two deploy bots with similar behavior
        self._seed_actor(baseline_store, "deploy-bot-prod",
                        ["modify_firewall_rule"] * 10, risk=0.3)
        self._seed_actor(baseline_store, "deploy-bot-staging",
                        ["modify_firewall_rule"] * 10, risk=0.25)

        engine = PeerGroupEngine(baseline_store)
        groups = engine.discover_groups()

        assert len(groups) >= 1
        # Both should be in the same group
        a1 = engine.assess("deploy-bot-prod", 0.3)
        a2 = engine.assess("deploy-bot-staging", 0.3)
        assert a1 is not None and a2 is not None
        assert a1.group_id == a2.group_id

    def test_peer_baseline_for_cold_start(self, baseline_store):
        """New actor with no history can inherit peer group baseline."""
        self._seed_actor(baseline_store, "deploy-bot-prod",
                        ["modify_firewall_rule"] * 15, risk=0.3)
        self._seed_actor(baseline_store, "deploy-bot-staging",
                        ["modify_firewall_rule"] * 15, risk=0.25)

        engine = PeerGroupEngine(baseline_store)
        engine.discover_groups()

        # Get peer baseline (simulating cold-start for a new deploy-bot)
        baseline = engine.get_peer_baseline("deploy-bot-prod")
        assert baseline is not None
        assert baseline.has_baseline
        assert 0.2 < baseline.mean_risk < 0.4

    def test_anomaly_detected_vs_peers(self, baseline_store):
        self._seed_actor(baseline_store, "deploy-bot-prod",
                        ["read_config"] * 10, risk=0.15)
        self._seed_actor(baseline_store, "deploy-bot-staging",
                        ["read_config"] * 10, risk=0.15)

        engine = PeerGroupEngine(baseline_store)
        engine.discover_groups()

        # Normal action for the peer group
        normal = engine.assess("deploy-bot-prod", 0.15)
        assert normal is not None
        assert not normal.is_peer_anomaly

        # Anomalous action relative to peers
        anomalous = engine.assess("deploy-bot-prod", 0.90)
        assert anomalous is not None
        assert anomalous.is_peer_anomaly


# ── Multi-Dimensional Anomaly Scoring ────────────────────────────────────


class TestMultiDimensionalAnomaly:
    def test_normal_behavior_no_breach(self):
        scorer = MultiDimensionalAnomalyScorer(breach_threshold=2)
        result = scorer.score(
            level_drift_z=0.5,
            pattern_drift_js=0.05,
            velocity_hourly=5,
            velocity_daily=40,
            trust_level=0.6,
            risk_score=0.3,
        )
        assert not result.is_model_breach
        assert result.anomalous_dimensions == 0

    def test_single_dimension_not_breach(self):
        """One anomalous dimension alone should NOT trigger a breach."""
        scorer = MultiDimensionalAnomalyScorer(breach_threshold=2)
        result = scorer.score(
            level_drift_z=4.0,  # very high — but only one dimension
            pattern_drift_js=0.05,
            velocity_hourly=5,
            velocity_daily=40,
            trust_level=0.6,
            risk_score=0.3,
        )
        assert result.anomalous_dimensions == 1
        assert not result.is_model_breach

    def test_two_dimensions_trigger_breach(self):
        scorer = MultiDimensionalAnomalyScorer(breach_threshold=2)
        result = scorer.score(
            level_drift_z=3.5,          # anomalous
            pattern_drift_js=0.50,      # anomalous
            velocity_hourly=5,
            velocity_daily=40,
            trust_level=0.6,
            risk_score=0.3,
        )
        assert result.anomalous_dimensions >= 2
        assert result.is_model_breach
        assert "MODEL BREACH" in result.explanation

    def test_compromise_scenario_triggers_breach(self):
        """Simulated compromise: high drift + high velocity + low trust."""
        scorer = MultiDimensionalAnomalyScorer(breach_threshold=2)
        result = scorer.score(
            level_drift_z=5.0,
            pattern_drift_js=0.60,
            velocity_hourly=80,
            velocity_daily=200,
            trust_level=0.2,
            risk_score=0.9,
        )
        assert result.is_model_breach
        assert result.anomalous_dimensions >= 3
        assert result.composite_score > 0.5

    def test_peer_deviation_counted(self):
        scorer = MultiDimensionalAnomalyScorer(breach_threshold=2)
        result = scorer.score(
            level_drift_z=3.0,
            pattern_drift_js=0.10,
            velocity_hourly=5,
            velocity_daily=40,
            trust_level=0.6,
            risk_score=0.3,
            peer_z_score=3.5,  # anomalous for peer group too
        )
        assert result.anomalous_dimensions >= 2
        assert result.is_model_breach

    def test_composite_score_bounded(self):
        scorer = MultiDimensionalAnomalyScorer()
        result = scorer.score(
            level_drift_z=10.0,
            pattern_drift_js=1.0,
            velocity_hourly=200,
            velocity_daily=2000,
            trust_level=0.0,
            risk_score=1.0,
            peer_z_score=10.0,
            is_outside_normal_hours=True,
        )
        assert 0.0 <= result.composite_score <= 1.0

    def test_explanation_lists_flagged_dimensions(self):
        scorer = MultiDimensionalAnomalyScorer(breach_threshold=2)
        result = scorer.score(
            level_drift_z=4.0,
            pattern_drift_js=0.50,
            velocity_hourly=5,
            velocity_daily=40,
            trust_level=0.6,
            risk_score=0.3,
        )
        assert "level_drift" in result.explanation
        assert "pattern_drift" in result.explanation

    def test_breach_ratio(self):
        scorer = MultiDimensionalAnomalyScorer(breach_threshold=2)
        result = scorer.score(
            level_drift_z=4.0,
            pattern_drift_js=0.50,
            velocity_hourly=80,
            velocity_daily=40,
            trust_level=0.6,
            risk_score=0.3,
        )
        assert result.breach_ratio > 0.0
        assert result.breach_ratio <= 1.0
