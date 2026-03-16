"""
Tests for Guardian refinements:
  1. Operator feedback loop
  2. TRIGGERED edge confidence scoring
  3. Graph TTL and archival
  4. Archetype baselines for cold-start
"""

from __future__ import annotations

from datetime import datetime, timedelta, timezone
from uuid import uuid4

import pytest

from guardian.behavioral.archetypes import (
    AI_AGENT_GENERAL,
    ARGOCD_CONTROLLER,
    BUILTIN_ARCHETYPES,
    DATADOG_AGENT,
    GITHUB_ACTIONS_BOT,
    TERRAFORM_RUNNER,
    match_archetype,
)
from guardian.feedback.store import (
    FeedbackStats,
    FeedbackStore,
    FeedbackType,
    PriorAdjustment,
)
from guardian.graph.models import DecisionEvent, EdgeType
from guardian.graph.store import GraphStore


def _now() -> datetime:
    return datetime.now(timezone.utc)


def _make_event(
    event_id: str | None = None,
    actor: str = "deploy-bot",
    action: str = "terraform.apply",
    target: str = "prod-vpc",
    system: str = "terraform-cloud",
    decision: str = "allow",
    risk: float = 0.3,
    timestamp: datetime | None = None,
    triggered_by: str | None = None,
    actor_type: str = "automation",
) -> DecisionEvent:
    ts = timestamp or _now()
    eid = event_id or str(uuid4())
    return DecisionEvent(
        event_id=eid, timestamp=ts,
        actor_id=f"actor:{actor}", actor_name=actor, actor_type=actor_type,
        action_id=f"action:{action}", action_name=action,
        action_family="infrastructure_change",
        target_id=f"target:{system}:{target}", target_name=target,
        target_system=system, system_id=f"system:{system}",
        system_name=system, decision=decision, risk_score=risk,
        drift_score=0.0, trust_score=0.5,
        triggered_by_event_id=triggered_by,
    )


# ══════════════════════════════════════════════════════════════════════════════
# 1. OPERATOR FEEDBACK LOOP
# ══════════════════════════════════════════════════════════════════════════════

class TestFeedbackStore:
    def test_record_and_retrieve(self):
        store = FeedbackStore()
        fb = store.record(
            decision_entry_id="dec-1",
            feedback_type=FeedbackType.false_positive,
            operator="alice",
            reason="This was a known deployment",
            actor_name="deploy-bot",
            actor_type="automation",
        )
        assert fb.feedback_id
        assert fb.feedback_type == FeedbackType.false_positive

        retrieved = store.get_feedback_for_decision("dec-1")
        assert len(retrieved) == 1
        assert retrieved[0].operator == "alice"

    def test_multiple_feedback_on_same_decision(self):
        store = FeedbackStore()
        store.record("dec-1", FeedbackType.false_positive, "alice")
        store.record("dec-1", FeedbackType.confirmed_correct, "bob")

        feedback = store.get_feedback_for_decision("dec-1")
        assert len(feedback) == 2

    def test_feedback_count(self):
        store = FeedbackStore()
        store.record("dec-1", FeedbackType.false_positive, "alice")
        store.record("dec-2", FeedbackType.confirmed_correct, "bob")
        assert store.feedback_count() == 2


class TestFeedbackStats:
    def test_overall_stats(self):
        store = FeedbackStore()
        store.record("d1", FeedbackType.confirmed_correct, "alice")
        store.record("d2", FeedbackType.confirmed_correct, "alice")
        store.record("d3", FeedbackType.false_positive, "bob")
        store.record("d4", FeedbackType.false_negative, "charlie")

        stats = store.get_overall_stats()
        assert stats.total_feedback == 4
        assert stats.confirmed_correct == 2
        assert stats.false_positives == 1
        assert stats.false_negatives == 1
        assert stats.false_positive_rate == 0.25
        assert stats.accuracy_rate == 0.5

    def test_stats_per_actor(self):
        store = FeedbackStore()
        store.record("d1", FeedbackType.false_positive, "alice", actor_name="bot-a")
        store.record("d2", FeedbackType.confirmed_correct, "alice", actor_name="bot-a")
        store.record("d3", FeedbackType.false_positive, "bob", actor_name="bot-b")

        stats_a = store.get_stats_for_actor("bot-a")
        assert stats_a.total_feedback == 2
        assert stats_a.false_positives == 1

        stats_b = store.get_stats_for_actor("bot-b")
        assert stats_b.total_feedback == 1

    def test_empty_stats(self):
        store = FeedbackStore()
        stats = store.get_overall_stats()
        assert stats.total_feedback == 0
        assert stats.false_positive_rate == 0.0
        assert stats.accuracy_rate == 1.0  # assume correct when no feedback


class TestBayesianPriorAdjustment:
    def test_false_positives_increase_beta(self):
        store = FeedbackStore()
        for i in range(5):
            store.record(
                f"d{i}", FeedbackType.false_positive, "alice",
                actor_type="automation",
            )

        adjustments = store.compute_prior_adjustments()
        assert len(adjustments) == 1
        adj = adjustments[0]
        assert adj.actor_type == "automation"
        assert adj.beta_adjustment == 2.5  # 5 * 0.5
        assert adj.alpha_adjustment == 0.0

    def test_false_negatives_increase_alpha(self):
        store = FeedbackStore()
        for i in range(3):
            store.record(
                f"d{i}", FeedbackType.false_negative, "alice",
                actor_type="ai_agent",
            )

        adjustments = store.compute_prior_adjustments()
        adj = next(a for a in adjustments if a.actor_type == "ai_agent")
        assert adj.alpha_adjustment == 1.5  # 3 * 0.5
        assert adj.beta_adjustment == 0.0

    def test_adjustments_capped(self):
        store = FeedbackStore()
        for i in range(20):
            store.record(
                f"d{i}", FeedbackType.false_positive, "alice",
                actor_type="automation",
            )

        adjustments = store.compute_prior_adjustments()
        adj = adjustments[0]
        assert adj.beta_adjustment == 5.0  # capped

    def test_no_adjustments_for_confirmed_only(self):
        store = FeedbackStore()
        store.record("d1", FeedbackType.confirmed_correct, "alice", actor_type="automation")
        adjustments = store.compute_prior_adjustments()
        assert len(adjustments) == 0


class TestCascadeSuppression:
    def test_add_and_check_suppression(self):
        store = FeedbackStore()
        store.add_cascade_suppression(
            actor_pattern="deploy-bot",
            system_pattern="terraform-cloud",
            reason="Known deployment chain",
            created_by="alice",
        )
        assert store.is_cascade_suppressed("deploy-bot", "terraform-cloud")
        assert not store.is_cascade_suppressed("other-bot", "terraform-cloud")

    def test_wildcard_suppression(self):
        store = FeedbackStore()
        store.add_cascade_suppression("*", "terraform-cloud", "All TF cascades known", "alice")
        assert store.is_cascade_suppressed("any-bot", "terraform-cloud")

    def test_expired_suppression(self):
        store = FeedbackStore()
        expired = _now() - timedelta(hours=1)
        store.add_cascade_suppression(
            "deploy-bot", "terraform-cloud", "temp", "alice",
            expires_at=expired,
        )
        assert not store.is_cascade_suppressed("deploy-bot", "terraform-cloud")


# ══════════════════════════════════════════════════════════════════════════════
# 2. TRIGGERED EDGE CONFIDENCE SCORING
# ══════════════════════════════════════════════════════════════════════════════

class TestEdgeConfidence:
    def test_same_system_high_confidence(self):
        store = GraphStore()
        now = _now()

        # CI bot acts on terraform-cloud
        e1 = _make_event(event_id="e1", actor="ci-bot", system="terraform-cloud",
                         timestamp=now - timedelta(seconds=10))
        store.record_event(e1)

        # Terraform runner acts on same system 10 seconds later
        e2 = _make_event(event_id="e2", actor="tf-runner", system="terraform-cloud",
                         timestamp=now)

        triggered_by = store.infer_triggered_by(e2, window_seconds=300)
        assert triggered_by == "e1"

    def test_distant_events_lower_confidence(self):
        store = GraphStore()
        now = _now()

        # Event 290 seconds ago (near edge of window)
        e1 = _make_event(event_id="e1", actor="ci-bot", system="terraform-cloud",
                         timestamp=now - timedelta(seconds=290))
        store.record_event(e1)

        # Event 10 seconds ago (recent)
        e2 = _make_event(event_id="e2", actor="other-bot", system="terraform-cloud",
                         timestamp=now - timedelta(seconds=10))
        store.record_event(e2)

        # New event — should prefer e2 (more recent)
        e3 = _make_event(event_id="e3", actor="tf-runner", system="terraform-cloud",
                         timestamp=now)
        triggered_by = store.infer_triggered_by(e3, window_seconds=300)
        assert triggered_by == "e2"

    def test_different_system_lower_confidence(self):
        store = GraphStore()
        now = _now()

        # Event on different system
        e1 = _make_event(event_id="e1", actor="ci-bot", system="github",
                         timestamp=now - timedelta(seconds=30))
        store.record_event(e1)

        # Event on same system
        e2 = _make_event(event_id="e2", actor="other-bot", system="terraform-cloud",
                         timestamp=now - timedelta(seconds=30))
        store.record_event(e2)

        e3 = _make_event(event_id="e3", actor="tf-runner", system="terraform-cloud",
                         timestamp=now)
        triggered_by = store.infer_triggered_by(e3, window_seconds=300)
        # Should prefer same-system event
        assert triggered_by == "e2"


# ══════════════════════════════════════════════════════════════════════════════
# 3. GRAPH TTL AND ARCHIVAL
# ══════════════════════════════════════════════════════════════════════════════

class TestGraphArchival:
    def test_archive_old_events(self):
        store = GraphStore()
        old = _now() - timedelta(days=120)
        recent = _now() - timedelta(days=10)

        store.record_event(_make_event(event_id="old-1", timestamp=old))
        store.record_event(_make_event(event_id="old-2", timestamp=old + timedelta(hours=1)))
        store.record_event(_make_event(event_id="recent-1", timestamp=recent))

        assert store.event_count() == 3

        archived = store.archive_old_events(max_age_days=90)
        assert archived == 2
        assert store.event_count() == 1
        assert store.get_archive_count() == 2

    def test_archive_removes_decision_nodes_and_edges(self):
        store = GraphStore()
        old = _now() - timedelta(days=120)

        store.record_event(_make_event(event_id="old-1", timestamp=old))
        initial_nodes = store.node_count()
        initial_edges = store.edge_count()

        store.archive_old_events(max_age_days=90)

        # Decision node and its edges should be gone
        assert store.node_count() < initial_nodes
        assert store.edge_count() < initial_edges

    def test_archive_preserves_recent_events(self):
        store = GraphStore()
        recent = _now() - timedelta(days=10)
        store.record_event(_make_event(event_id="recent", timestamp=recent))

        archived = store.archive_old_events(max_age_days=90)
        assert archived == 0
        assert store.event_count() == 1

    def test_edge_decay(self):
        store = GraphStore()
        old = _now() - timedelta(days=300)

        # Create events with a TRIGGERED edge
        store.record_event(_make_event(event_id="e1", timestamp=old))
        store.record_event(_make_event(
            event_id="e2", actor="other", triggered_by="e1",
            timestamp=old + timedelta(seconds=30),
        ))

        assert store.edge_count(EdgeType.triggered) == 1

        # Apply decay with short half-life
        # 300 days / 30-day half-life = 10 half-lives → weight * 0.001
        removed = store.apply_edge_decay(half_life_days=30)
        assert removed == 1
        assert store.edge_count(EdgeType.triggered) == 0

    def test_edge_decay_preserves_recent(self):
        store = GraphStore()
        now = _now()

        store.record_event(_make_event(event_id="e1", timestamp=now - timedelta(seconds=30)))
        store.record_event(_make_event(
            event_id="e2", actor="other", triggered_by="e1",
            timestamp=now,
        ))

        removed = store.apply_edge_decay(half_life_days=60)
        assert removed == 0
        assert store.edge_count(EdgeType.triggered) == 1


# ══════════════════════════════════════════════════════════════════════════════
# 4. ARCHETYPE BASELINES
# ══════════════════════════════════════════════════════════════════════════════

class TestArchetypeMatching:
    def test_match_terraform_by_name(self):
        match = match_archetype("terraform-cloud-runner", "automation")
        assert match is not None
        assert match.archetype_id == "archetype:terraform-runner"

    def test_match_github_actions(self):
        match = match_archetype("github-actions-prod", "automation")
        assert match is not None
        assert match.archetype_id == "archetype:github-actions"

    def test_match_argocd(self):
        match = match_archetype("argocd-prod", "automation")
        assert match is not None
        assert match.archetype_id == "archetype:argocd"

    def test_match_ai_agent(self):
        match = match_archetype("ai-remediation-bot", "ai_agent")
        assert match is not None
        assert match.archetype_id == "archetype:ai-agent"

    def test_match_by_system(self):
        match = match_archetype("unknown-bot", "automation", system="kubernetes")
        assert match is not None
        # Both argocd and k8s-controller match on kubernetes — either is valid
        assert match.archetype_id in ("archetype:k8s-controller", "archetype:argocd")

    def test_no_match_for_unknown(self):
        match = match_archetype("totally-custom-thing", "automation")
        assert match is None

    def test_match_monitoring_agent(self):
        match = match_archetype("datadog-collector", "automation")
        assert match is not None
        assert match.archetype_id == "archetype:datadog-agent"

    def test_name_pattern_beats_system_pattern(self):
        # "argocd-prod" on "terraform-cloud" should match argocd, not terraform
        match = match_archetype("argocd-prod", "automation", system="terraform-cloud")
        assert match is not None
        assert match.archetype_id == "archetype:argocd"


class TestArchetypeProperties:
    def test_terraform_archetype_properties(self):
        assert TERRAFORM_RUNNER.risk_tolerance == 0.5
        assert "infrastructure_change" in TERRAFORM_RUNNER.expected_action_families
        assert TERRAFORM_RUNNER.bayesian_prior == (2.0, 4.0)

    def test_ai_agent_highest_scrutiny(self):
        assert AI_AGENT_GENERAL.risk_tolerance < TERRAFORM_RUNNER.risk_tolerance
        assert AI_AGENT_GENERAL.drift_sensitivity > TERRAFORM_RUNNER.drift_sensitivity

    def test_monitoring_agent_lowest_risk(self):
        assert DATADOG_AGENT.risk_tolerance > GITHUB_ACTIONS_BOT.risk_tolerance

    def test_velocity_ranges(self):
        assert DATADOG_AGENT.velocity_range == (50, 500)  # high
        assert TERRAFORM_RUNNER.velocity_range == (0, 1000)  # burst

    def test_builtin_archetypes_count(self):
        assert len(BUILTIN_ARCHETYPES) == 6
