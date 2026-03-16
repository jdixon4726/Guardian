"""
Tests for the Decision Graph — store, builder, queries, cascade detection,
blast radius computation, and graph-aware drift analysis.
"""

from __future__ import annotations

from datetime import datetime, timedelta, timezone
from uuid import uuid4

import pytest

from guardian.graph.builder import GraphBuilder, _classify_action
from guardian.graph.models import (
    AutomationCascade,
    BlastRadius,
    DecisionEvent,
    EdgeType,
    GraphEdge,
    GraphNode,
    NodeType,
)
from guardian.graph.store import GraphStore


# ── Helpers ──────────────────────────────────────────────────────────────────

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
    drift: float = 0.0,
    trust: float = 0.7,
    timestamp: datetime | None = None,
    triggered_by: str | None = None,
    actor_type: str = "automation",
) -> DecisionEvent:
    ts = timestamp or _now()
    eid = event_id or str(uuid4())
    return DecisionEvent(
        event_id=eid,
        timestamp=ts,
        actor_id=f"actor:{actor}",
        actor_name=actor,
        actor_type=actor_type,
        action_id=f"action:{action}",
        action_name=action,
        action_family="infrastructure_change",
        target_id=f"target:{system}:{target}",
        target_name=target,
        target_system=system,
        system_id=f"system:{system}",
        system_name=system,
        decision=decision,
        risk_score=risk,
        drift_score=drift,
        trust_score=trust,
        triggered_by_event_id=triggered_by,
    )


# ── Store basics ─────────────────────────────────────────────────────────────

class TestGraphStore:
    def test_create_store_in_memory(self):
        store = GraphStore()
        assert store.node_count() == 0
        assert store.edge_count() == 0
        assert store.event_count() == 0

    def test_upsert_and_get_node(self):
        store = GraphStore()
        node = GraphNode(
            node_id="actor:test-bot",
            node_type=NodeType.actor,
            label="test-bot",
            properties={"actor_type": "automation"},
        )
        store.upsert_node(node)
        assert store.node_count() == 1

        retrieved = store.get_node("actor:test-bot")
        assert retrieved is not None
        assert retrieved.label == "test-bot"
        assert retrieved.properties["actor_type"] == "automation"

    def test_upsert_updates_existing(self):
        store = GraphStore()
        node = GraphNode(
            node_id="actor:bot",
            node_type=NodeType.actor,
            label="bot-v1",
        )
        store.upsert_node(node)
        node.label = "bot-v2"
        store.upsert_node(node)
        assert store.node_count() == 1
        assert store.get_node("actor:bot").label == "bot-v2"

    def test_add_and_query_edges(self):
        store = GraphStore()
        store.upsert_node(GraphNode("a", NodeType.actor, "a"))
        store.upsert_node(GraphNode("b", NodeType.decision, "b"))
        store.add_edge(GraphEdge("a", "b", EdgeType.initiated, event_id="e1"))

        from_edges = store.get_edges_from("a")
        assert len(from_edges) == 1
        assert from_edges[0].edge_type == EdgeType.initiated

        to_edges = store.get_edges_to("b")
        assert len(to_edges) == 1

    def test_edge_filter_by_type(self):
        store = GraphStore()
        store.upsert_node(GraphNode("a", NodeType.actor, "a"))
        store.upsert_node(GraphNode("b", NodeType.decision, "b"))
        store.upsert_node(GraphNode("c", NodeType.target, "c"))
        store.add_edge(GraphEdge("a", "b", EdgeType.initiated))
        store.add_edge(GraphEdge("b", "c", EdgeType.targeted))

        assert len(store.get_edges_from("a", EdgeType.initiated)) == 1
        assert len(store.get_edges_from("a", EdgeType.targeted)) == 0


# ── Event recording ──────────────────────────────────────────────────────────

class TestEventRecording:
    def test_record_event_creates_nodes_and_edges(self):
        store = GraphStore()
        event = _make_event(event_id="evt-1")
        store.record_event(event)

        # 5 nodes: actor, action, target, system, decision
        assert store.node_count() == 5
        # 4 edges: initiated, requested, targeted, occurred_in
        assert store.edge_count() == 4
        assert store.event_count() == 1

    def test_record_multiple_events_same_actor(self):
        store = GraphStore()
        store.record_event(_make_event(event_id="e1", target="vpc-1"))
        store.record_event(_make_event(event_id="e2", target="vpc-2"))

        # Actor and system nodes are reused
        assert store.node_count(NodeType.actor) == 1
        assert store.node_count(NodeType.decision) == 2
        assert store.node_count(NodeType.target) == 2

    def test_record_event_with_triggered_by(self):
        store = GraphStore()
        store.record_event(_make_event(event_id="upstream"))
        store.record_event(_make_event(
            event_id="downstream",
            actor="argocd",
            triggered_by="upstream",
        ))

        # Should have a TRIGGERED edge
        assert store.edge_count(EdgeType.triggered) == 1


# ── Cascade inference ────────────────────────────────────────────────────────

class TestCascadeInference:
    def test_infer_triggered_by_same_system(self):
        store = GraphStore()
        now = _now()

        # Event 1: deploy-bot applies to terraform-cloud
        e1 = _make_event(event_id="e1", actor="deploy-bot", system="aws-prod",
                         timestamp=now - timedelta(seconds=60))
        store.record_event(e1)

        # Event 2: different actor, same system, within window
        e2 = _make_event(event_id="e2", actor="argocd", system="aws-prod",
                         timestamp=now)

        triggered_by = store.infer_triggered_by(e2, window_seconds=300)
        assert triggered_by == "e1"

    def test_no_inference_outside_window(self):
        store = GraphStore()
        now = _now()

        e1 = _make_event(event_id="e1", timestamp=now - timedelta(seconds=600))
        store.record_event(e1)

        e2 = _make_event(event_id="e2", actor="other-bot", timestamp=now)
        triggered_by = store.infer_triggered_by(e2, window_seconds=300)
        assert triggered_by is None

    def test_no_self_inference(self):
        store = GraphStore()
        now = _now()

        e1 = _make_event(event_id="e1", timestamp=now - timedelta(seconds=30))
        store.record_event(e1)

        # Same actor — should not self-trigger
        e2 = _make_event(event_id="e2", timestamp=now)
        triggered_by = store.infer_triggered_by(e2, window_seconds=300)
        assert triggered_by is None


# ── Blast radius ─────────────────────────────────────────────────────────────

class TestBlastRadius:
    def test_blast_radius_single_target(self):
        store = GraphStore()
        store.record_event(_make_event(event_id="e1"))

        br = store.compute_blast_radius("actor:deploy-bot")
        assert br.direct_targets == 1
        assert br.indirect_targets == 0
        assert br.blast_radius_score > 0

    def test_blast_radius_with_cascade(self):
        store = GraphStore()
        now = _now()

        # deploy-bot -> terraform-cloud -> prod-vpc
        store.record_event(_make_event(
            event_id="e1", actor="deploy-bot", system="terraform-cloud",
            target="prod-vpc", timestamp=now,
        ))
        # argocd triggered by deploy-bot -> k8s -> payment-api
        store.record_event(_make_event(
            event_id="e2", actor="argocd", system="k8s",
            target="payment-api", triggered_by="e1",
            timestamp=now + timedelta(seconds=30),
        ))

        br = store.compute_blast_radius("actor:deploy-bot")
        assert br.direct_targets >= 1
        assert br.indirect_targets >= 1
        assert br.systems_reached >= 1

    def test_blast_radius_unknown_actor(self):
        store = GraphStore()
        br = store.compute_blast_radius("actor:unknown")
        assert br.direct_targets == 0
        assert br.blast_radius_score == 0.0


# ── Cascades ─────────────────────────────────────────────────────────────────

class TestCascades:
    def test_find_cascade_chain(self):
        store = GraphStore()
        now = _now()

        # 3-hop chain: github-actions -> terraform -> k8s
        store.record_event(_make_event(
            event_id="e1", actor="github-actions", system="github",
            target="ci-pipeline", timestamp=now, risk=0.2,
        ))
        store.record_event(_make_event(
            event_id="e2", actor="terraform-runner", system="terraform-cloud",
            target="prod-vpc", triggered_by="e1",
            timestamp=now + timedelta(seconds=30), risk=0.5,
        ))
        store.record_event(_make_event(
            event_id="e3", actor="argocd", system="k8s",
            target="payment-api", triggered_by="e2",
            timestamp=now + timedelta(seconds=60), risk=0.4,
        ))

        cascades = store.find_cascades(min_depth=2)
        assert len(cascades) >= 1

        longest = max(cascades, key=lambda c: c.depth)
        assert longest.depth == 3
        assert longest.events == ["e1", "e2", "e3"]
        assert longest.crosses_trust_boundary  # different actors/systems

    def test_no_cascade_for_isolated_events(self):
        store = GraphStore()
        store.record_event(_make_event(event_id="e1"))
        store.record_event(_make_event(event_id="e2", actor="other"))

        cascades = store.find_cascades(min_depth=2)
        assert len(cascades) == 0

    def test_cascade_min_risk_filter(self):
        store = GraphStore()
        now = _now()

        store.record_event(_make_event(
            event_id="e1", risk=0.1, timestamp=now,
        ))
        store.record_event(_make_event(
            event_id="e2", actor="other", risk=0.1,
            triggered_by="e1", timestamp=now + timedelta(seconds=10),
        ))

        # Total risk = 0.2, filter at 0.5 should exclude
        assert len(store.find_cascades(min_depth=2, min_risk=0.5)) == 0
        # Filter at 0.1 should include
        assert len(store.find_cascades(min_depth=2, min_risk=0.1)) >= 1


# ── Actor/target queries ────────────────────────────────────────────────────

class TestActorTargetQueries:
    def test_get_actor_targets(self):
        store = GraphStore()
        store.record_event(_make_event(event_id="e1", target="vpc-1"))
        store.record_event(_make_event(event_id="e2", target="vpc-2"))
        store.record_event(_make_event(event_id="e3", target="vpc-1"))

        targets = store.get_actor_targets("actor:deploy-bot")
        assert len(targets) == 2
        # vpc-1 should have frequency 2
        vpc1 = next(t for t in targets if "vpc-1" in t["target_id"])
        assert vpc1["frequency"] == 2

    def test_get_target_actors(self):
        store = GraphStore()
        store.record_event(_make_event(event_id="e1", actor="bot-a"))
        store.record_event(_make_event(event_id="e2", actor="bot-b"))

        actors = store.get_target_actors("target:terraform-cloud:prod-vpc")
        assert len(actors) == 2

    def test_get_actor_systems(self):
        store = GraphStore()
        store.record_event(_make_event(event_id="e1", system="aws"))
        store.record_event(_make_event(event_id="e2", system="k8s"))

        systems = store.get_actor_systems("actor:deploy-bot")
        assert set(systems) == {"system:aws", "system:k8s"}


# ── Graph-aware drift ───────────────────────────────────────────────────────

class TestGraphDrift:
    def test_scope_drift_new_target(self):
        store = GraphStore()
        old = _now() - timedelta(days=60)
        recent = _now() - timedelta(days=5)

        # Historical: only touches vpc-1
        store.record_event(_make_event(event_id="e1", target="vpc-1", timestamp=old))

        # Recent: also touches vpc-2 (new target)
        store.record_event(_make_event(event_id="e2", target="vpc-2", timestamp=recent))

        drift = store.detect_scope_drift("actor:deploy-bot", window_days=30)
        assert len(drift["new_targets"]) == 1
        assert drift["is_drifting"] or drift["scope_drift_score"] > 0

    def test_scope_drift_no_change(self):
        store = GraphStore()
        old = _now() - timedelta(days=60)
        recent = _now() - timedelta(days=5)

        store.record_event(_make_event(event_id="e1", target="vpc-1", timestamp=old))
        store.record_event(_make_event(event_id="e2", target="vpc-1", timestamp=recent))

        drift = store.detect_scope_drift("actor:deploy-bot", window_days=30)
        assert len(drift["new_targets"]) == 0
        assert not drift["is_drifting"]

    def test_path_drift_new_chain(self):
        store = GraphStore()
        old = _now() - timedelta(days=60)
        recent = _now() - timedelta(days=5)

        # Historical: deploy-bot acts alone
        store.record_event(_make_event(event_id="e1", timestamp=old))

        # Recent: deploy-bot triggered by a new actor
        store.record_event(_make_event(
            event_id="e-upstream", actor="new-ci-bot", system="github",
            timestamp=recent - timedelta(seconds=60),
        ))
        store.record_event(_make_event(
            event_id="e2", triggered_by="e-upstream",
            timestamp=recent,
        ))

        drift = store.detect_path_drift("actor:deploy-bot", window_days=30)
        assert len(drift["new_upstream_actors"]) >= 1


# ── Action classification ───────────────────────────────────────────────────

class TestActionClassification:
    def test_heuristic_destructive(self):
        assert _classify_action("delete_bucket") == "destructive"
        assert _classify_action("destroy_instance") == "destructive"

    def test_heuristic_infrastructure(self):
        assert _classify_action("create_vpc") == "infrastructure_change"
        assert _classify_action("deploy_service") == "infrastructure_change"

    def test_heuristic_privilege(self):
        assert _classify_action("modify_iam_role") == "privilege_escalation"

    def test_heuristic_config(self):
        assert _classify_action("update_settings") == "configuration_change"

    def test_heuristic_fallback(self):
        assert _classify_action("do_something") == "operational"


# ── Graph stats ──────────────────────────────────────────────────────────────

class TestGraphStats:
    def test_node_and_edge_counts(self):
        store = GraphStore()
        store.record_event(_make_event(event_id="e1"))

        assert store.node_count(NodeType.actor) == 1
        assert store.node_count(NodeType.action) == 1
        assert store.node_count(NodeType.target) == 1
        assert store.node_count(NodeType.system) == 1
        assert store.node_count(NodeType.decision) == 1

        assert store.edge_count(EdgeType.initiated) == 1
        assert store.edge_count(EdgeType.requested) == 1
        assert store.edge_count(EdgeType.targeted) == 1
        assert store.edge_count(EdgeType.occurred_in) == 1

    def test_event_count(self):
        store = GraphStore()
        store.record_event(_make_event(event_id="e1"))
        store.record_event(_make_event(event_id="e2", actor="bot-2"))
        assert store.event_count() == 2
