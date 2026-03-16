"""
Decision Graph node, edge, and event models.

MVP scope (6 node types, 6 edge types):
  Nodes:  Actor, Action, Target, System, Decision
  Edges:  INITIATED, REQUESTED, TARGETED, OCCURRED_IN, RESULTED_IN, TRIGGERED
"""

from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime, timezone
from enum import Enum
from typing import Any


class NodeType(str, Enum):
    actor = "actor"
    action = "action"
    target = "target"
    system = "system"
    decision = "decision"


class EdgeType(str, Enum):
    initiated = "INITIATED"       # actor -> decision
    requested = "REQUESTED"       # decision -> action
    targeted = "TARGETED"         # decision -> target
    occurred_in = "OCCURRED_IN"   # decision -> system
    resulted_in = "RESULTED_IN"   # decision -> outcome (stored as property)
    triggered = "TRIGGERED"       # decision -> decision (cascade link)


@dataclass
class GraphNode:
    """A node in the decision graph."""
    node_id: str                  # e.g. "actor:terraform-cloud-runner"
    node_type: NodeType
    label: str                    # human-readable name
    properties: dict[str, Any] = field(default_factory=dict)
    created_at: datetime = field(default_factory=lambda: datetime.now(timezone.utc))
    updated_at: datetime = field(default_factory=lambda: datetime.now(timezone.utc))


@dataclass
class GraphEdge:
    """A directed edge in the decision graph."""
    from_node_id: str
    to_node_id: str
    edge_type: EdgeType
    event_id: str | None = None   # links to the decision event that created this edge
    weight: float = 1.0           # frequency or confidence weight
    properties: dict[str, Any] = field(default_factory=dict)
    created_at: datetime = field(default_factory=lambda: datetime.now(timezone.utc))


@dataclass
class DecisionEvent:
    """
    A single evaluated decision, normalized for graph ingestion.
    This is the canonical event format that feeds the graph.
    """
    event_id: str                  # maps to Decision.entry_id
    timestamp: datetime

    # Actor
    actor_id: str                  # "actor:{actor_name}"
    actor_name: str
    actor_type: str                # human | automation | ai_agent

    # Action
    action_id: str                 # "action:{requested_action}"
    action_name: str
    action_family: str             # infrastructure_change, security_control, etc.

    # Target
    target_id: str                 # "target:{target_system}:{target_asset}"
    target_name: str
    target_system: str

    # System
    system_id: str                 # "system:{target_system}"
    system_name: str

    # Guardian evaluation
    decision: str                  # allow | allow_with_logging | require_review | block
    risk_score: float
    drift_score: float
    trust_score: float
    is_anomalous: bool = False

    # Cascade link
    triggered_by_event_id: str | None = None

    @classmethod
    def from_decision(
        cls,
        decision: Any,
        action_family: str = "unknown",
        trust_score: float = 0.5,
        is_anomalous: bool = False,
        triggered_by: str | None = None,
    ) -> DecisionEvent:
        """Create a DecisionEvent from a Guardian Decision object."""
        req = decision.action_request
        drift = decision.drift_score

        return cls(
            event_id=decision.entry_id,
            timestamp=decision.evaluated_at,
            actor_id=f"actor:{req.actor_name}",
            actor_name=req.actor_name,
            actor_type=req.actor_type.value,
            action_id=f"action:{req.requested_action}",
            action_name=req.requested_action,
            action_family=action_family,
            target_id=f"target:{req.target_system}:{req.target_asset}",
            target_name=req.target_asset,
            target_system=req.target_system,
            system_id=f"system:{req.target_system}",
            system_name=req.target_system,
            decision=decision.decision.value,
            risk_score=decision.risk_score,
            drift_score=drift.score if drift else 0.0,
            trust_score=trust_score,
            is_anomalous=is_anomalous,
            triggered_by_event_id=triggered_by,
        )


@dataclass
class BlastRadius:
    """Computed blast radius for an actor or system."""
    actor_id: str
    direct_targets: int
    indirect_targets: int
    critical_targets: int
    systems_reached: int
    max_chain_depth: int
    blast_radius_score: float     # [0.0, 1.0]
    chains: list[list[str]] = field(default_factory=list)  # sample chains


@dataclass
class AutomationCascade:
    """A detected multi-hop automation chain."""
    chain_id: str
    events: list[str]             # ordered event_ids
    actors: list[str]             # actors in the chain
    systems: list[str]            # systems traversed
    total_risk: float             # cumulative risk
    depth: int
    starts_at: datetime
    ends_at: datetime
    crosses_trust_boundary: bool = False
