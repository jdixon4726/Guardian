"""
Peer Group Auto-Discovery

Automatically clusters actors with similar behavioral profiles into peer
groups. Inspired by Darktrace's approach where anomalies are scored against
individual, peer group, AND organizational baselines simultaneously.

Key features:
  - New actors inherit their peer group's baseline immediately (cold-start)
  - Anomalies are contextualized: an action unusual for the individual but
    normal for the peer group is scored lower than one unusual for both
  - Peer groups are recomputed periodically from behavioral signals

Clustering is based on:
  - Actor type (ai_agent, automation, human)
  - Action type distribution similarity
  - Risk score distribution similarity
  - Target system patterns
"""

from __future__ import annotations

import logging
import math
from dataclasses import dataclass, field
from datetime import datetime, timezone

from guardian.drift.baseline import ActorBaseline, BaselineStore

logger = logging.getLogger(__name__)


@dataclass
class PeerGroup:
    """A cluster of actors with similar behavioral profiles."""
    group_id: str
    members: list[str]                         # actor names
    mean_risk: float = 0.0
    stddev_risk: float = 0.0
    action_distribution: dict[str, float] = field(default_factory=dict)
    size: int = 0

    @property
    def has_baseline(self) -> bool:
        return self.size >= 2 and self.mean_risk > 0


@dataclass
class PeerGroupAssessment:
    """How an actor's current behavior compares to their peer group."""
    group_id: str
    group_size: int
    z_score_vs_peers: float          # deviation from peer group mean
    is_peer_anomaly: bool            # unusual for the peer group too?
    inherited_baseline: bool = False  # True if actor used peer baseline (cold-start)


class PeerGroupEngine:
    """
    Discovers and maintains peer groups from behavioral baselines.

    Actors are grouped by actor type and behavioral similarity.
    The engine provides peer-relative anomaly scoring.
    """

    def __init__(self, baseline_store: BaselineStore):
        self._store = baseline_store
        self._groups: dict[str, PeerGroup] = {}
        self._actor_group: dict[str, str] = {}  # actor → group_id

    def discover_groups(self) -> dict[str, PeerGroup]:
        """
        Recompute peer groups from all actor baselines.

        Groups actors by type prefix (derived from actor name patterns)
        and behavioral similarity. Simple approach: group by actor type
        prefix and action distribution overlap.
        """
        actors = self._store.get_all_actor_names()
        baselines: dict[str, ActorBaseline] = {}
        for actor in actors:
            b = self._store.get_baseline(actor)
            if b.has_baseline:
                baselines[actor] = b

        if not baselines:
            return {}

        # Phase 1: Group by actor name prefix (simple heuristic)
        # e.g., "deploy-bot-prod" and "deploy-bot-staging" → same group
        prefix_groups: dict[str, list[str]] = {}
        for actor in baselines:
            prefix = self._extract_prefix(actor)
            prefix_groups.setdefault(prefix, []).append(actor)

        # Phase 2: Merge small groups and compute group baselines
        self._groups = {}
        self._actor_group = {}

        for prefix, members in prefix_groups.items():
            if len(members) < 2:
                # Singleton — try to merge with the most similar group
                continue

            group_id = f"pg-{prefix}"
            group_baselines = [baselines[m] for m in members]

            mean_risk = sum(b.mean_risk for b in group_baselines) / len(group_baselines)
            # Pooled stddev
            if len(group_baselines) > 1:
                variance = sum(
                    (b.mean_risk - mean_risk) ** 2 for b in group_baselines
                ) / len(group_baselines)
                stddev = math.sqrt(variance)
            else:
                stddev = group_baselines[0].stddev_risk

            # Merge action distributions
            merged_dist: dict[str, float] = {}
            for b in group_baselines:
                for action, prob in b.action_distribution.items():
                    merged_dist[action] = merged_dist.get(action, 0.0) + prob
            total = sum(merged_dist.values())
            if total > 0:
                merged_dist = {k: v / total for k, v in merged_dist.items()}

            group = PeerGroup(
                group_id=group_id,
                members=members,
                mean_risk=round(mean_risk, 4),
                stddev_risk=round(stddev, 4),
                action_distribution=merged_dist,
                size=len(members),
            )
            self._groups[group_id] = group
            for member in members:
                self._actor_group[member] = group_id

        # Assign singletons to the closest group
        for prefix, members in prefix_groups.items():
            if len(members) >= 2:
                continue
            actor = members[0]
            best_group = self._find_closest_group(baselines[actor])
            if best_group:
                self._actor_group[actor] = best_group
                self._groups[best_group].members.append(actor)
                self._groups[best_group].size += 1

        logger.info(
            "Peer groups discovered: %d groups covering %d actors",
            len(self._groups), len(self._actor_group),
        )
        return self._groups

    def assess(
        self, actor_name: str, current_risk: float,
    ) -> PeerGroupAssessment | None:
        """
        Score an actor's current behavior against their peer group.

        Returns None if the actor has no peer group.
        """
        group_id = self._actor_group.get(actor_name)
        if group_id is None:
            return None

        group = self._groups[group_id]
        if not group.has_baseline:
            return None

        # Z-score against peer group mean
        effective_stddev = max(group.stddev_risk, 0.01)
        z = (current_risk - group.mean_risk) / effective_stddev

        # An action is a peer anomaly if it's unusual for the group too
        is_peer_anomaly = abs(z) > 2.0

        return PeerGroupAssessment(
            group_id=group_id,
            group_size=group.size,
            z_score_vs_peers=round(z, 4),
            is_peer_anomaly=is_peer_anomaly,
        )

    def get_peer_baseline(self, actor_name: str) -> ActorBaseline | None:
        """
        Get the peer group's baseline for cold-start actors.

        Returns None if no peer group exists.
        """
        group_id = self._actor_group.get(actor_name)
        if group_id is None:
            return None

        group = self._groups[group_id]
        if not group.has_baseline:
            return None

        return ActorBaseline(
            actor_name=f"[peer:{group_id}]",
            mean_risk=group.mean_risk,
            stddev_risk=group.stddev_risk,
            observation_count=group.size * 10,  # synthetic count for confidence
            action_distribution=group.action_distribution,
            baseline_days=30,
            variance_score=0.5,  # neutral
        )

    def _extract_prefix(self, actor_name: str) -> str:
        """Extract a grouping prefix from an actor name."""
        # "deploy-bot-prod" → "deploy-bot"
        # "infra-agent-staging" → "infra-agent"
        parts = actor_name.rsplit("-", 1)
        if len(parts) == 2 and parts[1] in (
            "prod", "staging", "dev", "test", "qa",
            "production", "development",
        ):
            return parts[0]
        return actor_name

    def _find_closest_group(self, baseline: ActorBaseline) -> str | None:
        """Find the peer group with the most similar mean risk."""
        best_group = None
        best_distance = float("inf")

        for group_id, group in self._groups.items():
            distance = abs(baseline.mean_risk - group.mean_risk)
            if distance < best_distance:
                best_distance = distance
                best_group = group_id

        # Only assign if reasonably close
        if best_distance < 0.3:
            return best_group
        return None
