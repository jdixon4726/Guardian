"""
Phase 2.5 Drift Detection Tests

Four fixture-based scenarios:
  1. Normal actor — consistent behavior, no drift expected
  2. Privilege creep — gradual risk score elevation over time
  3. Compromise event — abrupt spike in risk from anomalous action
  4. AI anomaly — suspiciously regular behavior then sudden escalation
"""

from __future__ import annotations

import math
from datetime import datetime, timedelta, timezone

import pytest

from guardian.drift.baseline import BaselineStore, ActorBaseline
from guardian.drift.engine import (
    DriftDetectionEngine,
    _jensen_shannon_divergence,
    MIN_OBSERVATIONS,
)


@pytest.fixture
def store():
    """In-memory baseline store for testing."""
    s = BaselineStore(":memory:")
    yield s
    s.close()


@pytest.fixture
def engine(store):
    return DriftDetectionEngine(store)


def _seed_baseline(
    store: BaselineStore,
    actor: str,
    actions: list[tuple[str, float]],
    start: datetime | None = None,
    interval_hours: int = 1,
) -> None:
    """Helper: record observations and recompute baseline.

    Defaults to recent timestamps so observations fall within the 30-day
    rolling window used by recompute_baseline().
    """
    if start is None:
        start = datetime.now(timezone.utc) - timedelta(days=7)
    for i, (action_type, risk_score) in enumerate(actions):
        ts = start + timedelta(hours=i * interval_hours)
        store.record_observation(actor, action_type, risk_score, ts)
    store.recompute_baseline(actor)


# ── Utility tests ──────────────────────────────────────────────────────────


class TestJensenShannonDivergence:
    def test_identical_distributions_return_zero(self):
        p = {"a": 0.5, "b": 0.3, "c": 0.2}
        assert _jensen_shannon_divergence(p, p) < 0.01

    def test_completely_different_distributions(self):
        p = {"a": 1.0}
        q = {"b": 1.0}
        js = _jensen_shannon_divergence(p, q)
        assert js > 0.8  # near-maximum divergence

    def test_empty_distributions_return_zero(self):
        assert _jensen_shannon_divergence({}, {}) == 0.0

    def test_partial_overlap(self):
        p = {"a": 0.7, "b": 0.3}
        q = {"a": 0.3, "b": 0.5, "c": 0.2}
        js = _jensen_shannon_divergence(p, q)
        assert 0.0 < js < 1.0


# ── Baseline Store tests ──────────────────────────────────────────────────


class TestBaselineStore:
    def test_empty_baseline_for_unknown_actor(self, store):
        b = store.get_baseline("unknown-actor")
        assert b.observation_count == 0
        assert not b.has_baseline

    def test_baseline_requires_minimum_observations(self, store):
        for i in range(MIN_OBSERVATIONS - 1):
            store.record_observation(
                "actor-a", "read_config", 0.2,
                datetime.now(timezone.utc) - timedelta(days=7) + timedelta(hours=i),
            )
        store.recompute_baseline("actor-a")
        b = store.get_baseline("actor-a")
        assert not b.has_baseline

    def test_baseline_activates_at_minimum_observations(self, store):
        for i in range(MIN_OBSERVATIONS):
            store.record_observation(
                "actor-a", "read_config", 0.2 + i * 0.01,
                datetime.now(timezone.utc) - timedelta(days=7) + timedelta(hours=i),
            )
        store.recompute_baseline("actor-a")
        b = store.get_baseline("actor-a")
        assert b.has_baseline
        assert b.observation_count == MIN_OBSERVATIONS

    def test_action_distribution_sums_to_one(self, store):
        actions = [
            ("read_config", 0.2), ("read_config", 0.2),
            ("modify_firewall_rule", 0.4), ("modify_firewall_rule", 0.4),
            ("restart_service", 0.3),
        ]
        _seed_baseline(store, "actor-b", actions)
        b = store.get_baseline("actor-b")
        assert abs(sum(b.action_distribution.values()) - 1.0) < 0.001

    def test_recompute_all_baselines(self, store):
        _seed_baseline(store, "actor-x", [("a", 0.2)] * 5)
        _seed_baseline(store, "actor-y", [("b", 0.3)] * 5)
        count = store.recompute_all_baselines()
        assert count == 2


# ── Scenario 1: Normal actor (no drift) ──────────────────────────────────


class TestNormalActor:
    """Actor with consistent behavior should produce no drift signal."""

    def test_consistent_behavior_yields_low_drift(self, store, engine):
        # Seed with consistent low-risk read operations
        actions = [("read_config", 0.20 + i * 0.005) for i in range(20)]
        _seed_baseline(store, "steady-actor", actions)

        # Evaluate a new action that's consistent with baseline
        result = engine.evaluate(
            "steady-actor", "read_config", 0.21,
            datetime.now(timezone.utc),
        )

        assert result.score < 0.20, f"Expected low drift, got {result.score}"
        assert not result.alert_triggered
        assert abs(result.level_drift_z) < 2.0

    def test_multiple_consistent_actions_stay_low(self, store, engine):
        actions = [("read_config", 0.20)] * 15
        _seed_baseline(store, "boring-actor", actions)

        for i in range(5):
            result = engine.evaluate(
                "boring-actor", "read_config", 0.20,
                datetime.now(timezone.utc) + timedelta(hours=i),
            )
        assert result.score < 0.25
        assert not result.alert_triggered


# ── Scenario 2: Privilege creep (gradual elevation) ──────────────────────


class TestPrivilegeCreep:
    """Gradual increase in risk scores over time should trigger drift."""

    def test_gradual_risk_elevation_triggers_drift(self, store, engine):
        # Baseline: low-risk actions over 30 days
        baseline_actions = [("read_config", 0.15)] * 20
        _seed_baseline(store, "creep-actor", baseline_actions)

        # Now the actor starts doing progressively riskier things
        result = engine.evaluate(
            "creep-actor", "modify_iam_role", 0.70,
            datetime.now(timezone.utc),
        )

        assert result.score > 0.3, f"Expected elevated drift, got {result.score}"
        assert result.level_drift_z > 2.0, "z-score should be significantly elevated"

    def test_privilege_creep_triggers_alert_at_extreme(self, store, engine):
        baseline_actions = [("read_config", 0.10)] * 25
        _seed_baseline(store, "escalator", baseline_actions)

        result = engine.evaluate(
            "escalator", "escalate_privileges", 0.90,
            datetime.now(timezone.utc),
        )

        assert result.alert_triggered, "Should trigger alert on extreme deviation"
        assert result.level_drift_z > Z_SCORE_THRESHOLD, (
            f"z-score {result.level_drift_z} should exceed alert threshold"
        )


# ── Scenario 3: Compromise event (abrupt spike) ──────────────────────────


class TestCompromiseEvent:
    """Sudden behavioral change (new action types + high risk) should alert."""

    def test_abrupt_action_type_change_triggers_pattern_drift(self, store, engine):
        # Baseline: actor only does read_config and restart_service
        baseline_actions = [
            ("read_config", 0.15), ("read_config", 0.15),
            ("restart_service", 0.25), ("read_config", 0.15),
            ("restart_service", 0.25), ("read_config", 0.15),
            ("read_config", 0.15), ("restart_service", 0.25),
            ("read_config", 0.15), ("read_config", 0.15),
        ]
        _seed_baseline(store, "compromised-actor", baseline_actions)

        # Compromise: suddenly attempts to export data (never seen before)
        result = engine.evaluate(
            "compromised-actor", "export_data", 0.80,
            datetime.now(timezone.utc),
        )

        assert result.score > 0.4, f"Expected high drift, got {result.score}"
        assert result.alert_triggered, "Compromise event should trigger alert"
        assert result.level_drift_z > 2.0, "Risk spike should show in z-score"

    def test_compromise_explanation_mentions_deviation(self, store, engine):
        baseline_actions = [("read_config", 0.10)] * 15
        _seed_baseline(store, "victim", baseline_actions)

        result = engine.evaluate(
            "victim", "disable_endpoint_protection", 0.95,
            datetime.now(timezone.utc),
        )

        assert "baseline" in result.explanation.lower() or "σ" in result.explanation


# ── Scenario 4: AI anomaly (regularity then escalation) ──────────────────


class TestAIAnomaly:
    """
    AI agent with suspiciously regular behavior (low variance) that then
    escalates should trigger both regularity and level drift alerts.
    """

    def test_regular_behavior_flagged(self, store, engine):
        # AI agent performing identical actions with zero variance
        baseline_actions = [("check_status", 0.20)] * 25
        _seed_baseline(store, "robot-agent", baseline_actions)

        baseline = store.get_baseline("robot-agent")
        assert baseline.variance_score < 0.10, (
            f"Expected low variance for identical actions, got {baseline.variance_score}"
        )

    def test_regular_then_escalation_triggers_alert(self, store, engine):
        # Phase 1: identical actions (builds low-variance baseline)
        baseline_actions = [("check_status", 0.20)] * 25
        _seed_baseline(store, "drifting-ai", baseline_actions)

        # Phase 2: sudden escalation
        result = engine.evaluate(
            "drifting-ai", "escalate_privileges", 0.85,
            datetime.now(timezone.utc),
        )

        assert result.alert_triggered, "Regularity + escalation should trigger alert"
        assert result.score > 0.5, f"Expected high composite drift, got {result.score}"
        assert "regular" in result.explanation.lower() or "variance" in result.explanation.lower()

    def test_regularity_bonus_increases_composite_score(self, store, engine):
        # Compare: regular actor vs. varied actor, same escalation
        regular_actions = [("check_status", 0.20)] * 25
        _seed_baseline(store, "regular-ai", regular_actions)

        varied_actions = [
            ("check_status", 0.10), ("read_config", 0.30),
            ("restart_service", 0.40), ("check_status", 0.15),
            ("modify_firewall_rule", 0.50), ("read_config", 0.20),
            ("check_status", 0.25), ("restart_service", 0.35),
            ("read_config", 0.15), ("check_status", 0.20),
        ]
        _seed_baseline(store, "varied-actor", varied_actions)

        result_regular = engine.evaluate(
            "regular-ai", "escalate_privileges", 0.85,
            datetime.now(timezone.utc),
        )
        result_varied = engine.evaluate(
            "varied-actor", "escalate_privileges", 0.85,
            datetime.now(timezone.utc),
        )

        assert result_regular.score > result_varied.score, (
            f"Regular actor ({result_regular.score}) should have higher drift "
            f"than varied actor ({result_varied.score})"
        )


# ── Edge cases ────────────────────────────────────────────────────────────


class TestEdgeCases:
    def test_no_baseline_returns_neutral_drift(self, engine):
        result = engine.evaluate(
            "brand-new-actor", "read_config", 0.15,
            datetime.now(timezone.utc),
        )
        assert result.score == 0.0
        assert not result.alert_triggered
        assert "insufficient" in result.explanation.lower()

    def test_drift_score_bounded_zero_to_one(self, store, engine):
        baseline_actions = [("read_config", 0.01)] * 20
        _seed_baseline(store, "extreme-test", baseline_actions)

        result = engine.evaluate(
            "extreme-test", "destroy_infrastructure", 1.0,
            datetime.now(timezone.utc),
        )
        assert 0.0 <= result.score <= 1.0

    def test_observation_recorded_after_evaluation(self, store, engine):
        engine.evaluate(
            "new-actor", "read_config", 0.15,
            datetime.now(timezone.utc),
        )
        actors = store.get_all_actor_names()
        assert "new-actor" in actors


# ── Alert threshold constant for test reference ──
Z_SCORE_THRESHOLD = 2.5
