"""
Decision Graph Store — SQLite-backed, migration-ready.

Tables:
  graph_nodes         — actors, actions, targets, systems, decisions
  graph_edges         — directed relationships between nodes
  decision_events     — normalized decision records for graph queries

Designed to migrate to PostgreSQL by replacing the connection factory.
All queries use standard SQL (no SQLite-specific extensions).
"""

from __future__ import annotations

import json
import sqlite3
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from guardian.graph.models import (
    AutomationCascade,
    BlastRadius,
    DecisionEvent,
    EdgeType,
    GraphEdge,
    GraphNode,
    NodeType,
)


class GraphStore:
    """SQLite-backed decision graph storage."""

    def __init__(self, db_path: Path | str = ":memory:"):
        self._db_path = str(db_path)
        self._conn = sqlite3.connect(self._db_path, check_same_thread=False)
        self._conn.row_factory = sqlite3.Row
        self._conn.execute("PRAGMA journal_mode=WAL")
        self._conn.execute("PRAGMA foreign_keys=ON")
        self._create_tables()

    def _create_tables(self) -> None:
        self._conn.executescript("""
            CREATE TABLE IF NOT EXISTS graph_nodes (
                node_id     TEXT PRIMARY KEY,
                node_type   TEXT NOT NULL,
                label       TEXT NOT NULL,
                properties  TEXT NOT NULL DEFAULT '{}',
                created_at  TEXT NOT NULL,
                updated_at  TEXT NOT NULL
            );

            CREATE INDEX IF NOT EXISTS idx_nodes_type
                ON graph_nodes(node_type);

            CREATE TABLE IF NOT EXISTS graph_edges (
                id          INTEGER PRIMARY KEY AUTOINCREMENT,
                from_node   TEXT NOT NULL,
                to_node     TEXT NOT NULL,
                edge_type   TEXT NOT NULL,
                event_id    TEXT,
                weight      REAL NOT NULL DEFAULT 1.0,
                properties  TEXT NOT NULL DEFAULT '{}',
                created_at  TEXT NOT NULL,
                FOREIGN KEY (from_node) REFERENCES graph_nodes(node_id),
                FOREIGN KEY (to_node)   REFERENCES graph_nodes(node_id)
            );

            CREATE INDEX IF NOT EXISTS idx_edges_from
                ON graph_edges(from_node);
            CREATE INDEX IF NOT EXISTS idx_edges_to
                ON graph_edges(to_node);
            CREATE INDEX IF NOT EXISTS idx_edges_type
                ON graph_edges(edge_type);
            CREATE INDEX IF NOT EXISTS idx_edges_event
                ON graph_edges(event_id);

            CREATE TABLE IF NOT EXISTS decision_events (
                event_id            TEXT PRIMARY KEY,
                timestamp           TEXT NOT NULL,
                actor_id            TEXT NOT NULL,
                actor_name          TEXT NOT NULL,
                actor_type          TEXT NOT NULL,
                action_id           TEXT NOT NULL,
                action_name         TEXT NOT NULL,
                action_family       TEXT NOT NULL,
                target_id           TEXT NOT NULL,
                target_name         TEXT NOT NULL,
                target_system       TEXT NOT NULL,
                system_id           TEXT NOT NULL,
                system_name         TEXT NOT NULL,
                decision            TEXT NOT NULL,
                risk_score          REAL NOT NULL,
                drift_score         REAL NOT NULL DEFAULT 0.0,
                trust_score         REAL NOT NULL DEFAULT 0.5,
                is_anomalous        INTEGER NOT NULL DEFAULT 0,
                triggered_by_event  TEXT,
                FOREIGN KEY (triggered_by_event) REFERENCES decision_events(event_id)
            );

            CREATE INDEX IF NOT EXISTS idx_events_actor
                ON decision_events(actor_id);
            CREATE INDEX IF NOT EXISTS idx_events_target
                ON decision_events(target_id);
            CREATE INDEX IF NOT EXISTS idx_events_system
                ON decision_events(system_id);
            CREATE INDEX IF NOT EXISTS idx_events_timestamp
                ON decision_events(timestamp);
            CREATE INDEX IF NOT EXISTS idx_events_triggered_by
                ON decision_events(triggered_by_event);
        """)

    # ── Node operations ──────────────────────────────────────────────────────

    def upsert_node(self, node: GraphNode) -> None:
        """Insert or update a graph node."""
        now = datetime.now(timezone.utc).isoformat()
        self._conn.execute(
            """INSERT INTO graph_nodes (node_id, node_type, label, properties, created_at, updated_at)
               VALUES (?, ?, ?, ?, ?, ?)
               ON CONFLICT(node_id) DO UPDATE SET
                   label = excluded.label,
                   properties = excluded.properties,
                   updated_at = ?""",
            (
                node.node_id,
                node.node_type.value,
                node.label,
                json.dumps(node.properties),
                node.created_at.isoformat(),
                now,
                now,
            ),
        )
        self._conn.commit()

    def get_node(self, node_id: str) -> GraphNode | None:
        row = self._conn.execute(
            "SELECT * FROM graph_nodes WHERE node_id = ?", (node_id,)
        ).fetchone()
        if not row:
            return None
        return GraphNode(
            node_id=row["node_id"],
            node_type=NodeType(row["node_type"]),
            label=row["label"],
            properties=json.loads(row["properties"]),
            created_at=datetime.fromisoformat(row["created_at"]),
            updated_at=datetime.fromisoformat(row["updated_at"]),
        )

    # ── Edge operations ──────────────────────────────────────────────────────

    def add_edge(self, edge: GraphEdge) -> None:
        """Add a directed edge to the graph."""
        self._conn.execute(
            """INSERT INTO graph_edges
               (from_node, to_node, edge_type, event_id, weight, properties, created_at)
               VALUES (?, ?, ?, ?, ?, ?, ?)""",
            (
                edge.from_node_id,
                edge.to_node_id,
                edge.edge_type.value,
                edge.event_id,
                edge.weight,
                json.dumps(edge.properties),
                edge.created_at.isoformat(),
            ),
        )
        self._conn.commit()

    def get_edges_from(self, node_id: str, edge_type: EdgeType | None = None) -> list[GraphEdge]:
        if edge_type:
            rows = self._conn.execute(
                "SELECT * FROM graph_edges WHERE from_node = ? AND edge_type = ?",
                (node_id, edge_type.value),
            ).fetchall()
        else:
            rows = self._conn.execute(
                "SELECT * FROM graph_edges WHERE from_node = ?", (node_id,)
            ).fetchall()
        return [self._row_to_edge(r) for r in rows]

    def get_edges_to(self, node_id: str, edge_type: EdgeType | None = None) -> list[GraphEdge]:
        if edge_type:
            rows = self._conn.execute(
                "SELECT * FROM graph_edges WHERE to_node = ? AND edge_type = ?",
                (node_id, edge_type.value),
            ).fetchall()
        else:
            rows = self._conn.execute(
                "SELECT * FROM graph_edges WHERE to_node = ?", (node_id,)
            ).fetchall()
        return [self._row_to_edge(r) for r in rows]

    def _row_to_edge(self, row: sqlite3.Row) -> GraphEdge:
        return GraphEdge(
            from_node_id=row["from_node"],
            to_node_id=row["to_node"],
            edge_type=EdgeType(row["edge_type"]),
            event_id=row["event_id"],
            weight=row["weight"],
            properties=json.loads(row["properties"]),
            created_at=datetime.fromisoformat(row["created_at"]),
        )

    # ── Decision event operations ────────────────────────────────────────────

    def record_event(self, event: DecisionEvent) -> None:
        """Record a decision event and create all associated nodes and edges."""
        now = datetime.now(timezone.utc)

        # Upsert nodes (actor, action, target, system are long-lived; decision is per-event)
        self.upsert_node(GraphNode(
            node_id=event.actor_id,
            node_type=NodeType.actor,
            label=event.actor_name,
            properties={"actor_type": event.actor_type},
        ))
        self.upsert_node(GraphNode(
            node_id=event.action_id,
            node_type=NodeType.action,
            label=event.action_name,
            properties={"action_family": event.action_family},
        ))
        self.upsert_node(GraphNode(
            node_id=event.target_id,
            node_type=NodeType.target,
            label=event.target_name,
            properties={"target_system": event.target_system},
        ))
        self.upsert_node(GraphNode(
            node_id=event.system_id,
            node_type=NodeType.system,
            label=event.system_name,
            properties={},
        ))

        decision_node_id = f"decision:{event.event_id}"
        self.upsert_node(GraphNode(
            node_id=decision_node_id,
            node_type=NodeType.decision,
            label=f"{event.decision} ({event.risk_score:.2f})",
            properties={
                "decision": event.decision,
                "risk_score": event.risk_score,
                "drift_score": event.drift_score,
                "trust_score": event.trust_score,
                "is_anomalous": event.is_anomalous,
            },
        ))

        # Create edges
        edges = [
            GraphEdge(from_node_id=event.actor_id, to_node_id=decision_node_id,
                      edge_type=EdgeType.initiated, event_id=event.event_id),
            GraphEdge(from_node_id=decision_node_id, to_node_id=event.action_id,
                      edge_type=EdgeType.requested, event_id=event.event_id),
            GraphEdge(from_node_id=decision_node_id, to_node_id=event.target_id,
                      edge_type=EdgeType.targeted, event_id=event.event_id),
            GraphEdge(from_node_id=decision_node_id, to_node_id=event.system_id,
                      edge_type=EdgeType.occurred_in, event_id=event.event_id),
        ]

        # Cascade link
        if event.triggered_by_event_id:
            upstream_decision_id = f"decision:{event.triggered_by_event_id}"
            edges.append(GraphEdge(
                from_node_id=upstream_decision_id,
                to_node_id=decision_node_id,
                edge_type=EdgeType.triggered,
                event_id=event.event_id,
                properties={"triggered_by_event": event.triggered_by_event_id},
            ))

        for edge in edges:
            self.add_edge(edge)

        # Record the event row
        self._conn.execute(
            """INSERT OR REPLACE INTO decision_events
               (event_id, timestamp, actor_id, actor_name, actor_type,
                action_id, action_name, action_family,
                target_id, target_name, target_system,
                system_id, system_name,
                decision, risk_score, drift_score, trust_score,
                is_anomalous, triggered_by_event)
               VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)""",
            (
                event.event_id, event.timestamp.isoformat(),
                event.actor_id, event.actor_name, event.actor_type,
                event.action_id, event.action_name, event.action_family,
                event.target_id, event.target_name, event.target_system,
                event.system_id, event.system_name,
                event.decision, event.risk_score, event.drift_score, event.trust_score,
                1 if event.is_anomalous else 0,
                event.triggered_by_event_id,
            ),
        )
        self._conn.commit()

    # ── Cascade inference ────────────────────────────────────────────────────

    def infer_triggered_by(
        self,
        event: DecisionEvent,
        window_seconds: int = 300,
    ) -> str | None:
        """
        Infer which prior event triggered this one.

        Heuristic: find the most recent event within `window_seconds` that
        targeted the same system this actor belongs to, or whose outcome
        affected a target that this event's actor operates on.

        Returns the event_id of the inferred upstream event, or None.
        """
        # Look for recent events that targeted this event's system
        # where a different actor was involved (cross-actor causation)
        rows = self._conn.execute(
            """SELECT event_id, actor_id, target_id, risk_score, timestamp
               FROM decision_events
               WHERE system_id = ?
                 AND actor_id != ?
                 AND decision != 'block'
                 AND timestamp >= ?
                 AND timestamp < ?
               ORDER BY timestamp DESC
               LIMIT 1""",
            (
                event.system_id,
                event.actor_id,
                _subtract_seconds(event.timestamp, window_seconds),
                event.timestamp.isoformat(),
            ),
        ).fetchall()

        if rows:
            return rows[0]["event_id"]

        # Broader check: any recent event whose target is in the same system
        rows = self._conn.execute(
            """SELECT event_id FROM decision_events
               WHERE target_system = ?
                 AND actor_id != ?
                 AND decision != 'block'
                 AND timestamp >= ?
                 AND timestamp < ?
               ORDER BY timestamp DESC
               LIMIT 1""",
            (
                event.target_system,
                event.actor_id,
                _subtract_seconds(event.timestamp, window_seconds),
                event.timestamp.isoformat(),
            ),
        ).fetchall()

        if rows:
            return rows[0]["event_id"]

        return None

    # ── Query: Actor blast radius ────────────────────────────────────────────

    def compute_blast_radius(
        self,
        actor_id: str,
        max_depth: int = 4,
    ) -> BlastRadius:
        """
        Compute the blast radius for an actor.

        Direct: targets this actor has directly affected.
        Indirect: targets reachable through TRIGGERED chains.
        """
        # Direct targets
        direct_targets = set()
        direct_systems = set()

        rows = self._conn.execute(
            """SELECT DISTINCT de.target_id, de.target_system, de.target_name
               FROM decision_events de
               WHERE de.actor_id = ?""",
            (actor_id,),
        ).fetchall()

        for r in rows:
            direct_targets.add(r["target_id"])
            direct_systems.add(r["target_system"])

        # Indirect: follow TRIGGERED edges from this actor's decisions
        indirect_targets = set()
        indirect_systems = set()
        chains: list[list[str]] = []

        # Get all event_ids for this actor
        actor_events = self._conn.execute(
            "SELECT event_id FROM decision_events WHERE actor_id = ?",
            (actor_id,),
        ).fetchall()

        for evt_row in actor_events:
            chain = [evt_row["event_id"]]
            self._follow_triggers(evt_row["event_id"], chain, indirect_targets,
                                  indirect_systems, max_depth, 1)
            if len(chain) > 1:
                chains.append(chain[:5])  # cap chain sample length

        all_targets = direct_targets | indirect_targets
        all_systems = direct_systems | indirect_systems

        # Count critical targets
        critical_count = 0
        if all_targets:
            placeholders = ",".join("?" * len(all_targets))
            crit_rows = self._conn.execute(
                f"""SELECT COUNT(*) as cnt FROM graph_nodes
                    WHERE node_id IN ({placeholders})
                    AND json_extract(properties, '$.criticality') = 'critical'""",
                list(all_targets),
            ).fetchone()
            if crit_rows:
                critical_count = crit_rows["cnt"]

        # Score: weighted combination
        total_targets = len(all_targets) if all_targets else 0
        max_depth_seen = max((len(c) for c in chains), default=0)
        if total_targets == 0:
            score = 0.0
        else:
            score = min(1.0,
                (total_targets / 50.0) * 0.4
                + (critical_count / 10.0) * 0.35
                + (len(all_systems) / 10.0) * 0.15
                + (max_depth_seen / 4.0) * 0.10
            )

        return BlastRadius(
            actor_id=actor_id,
            direct_targets=len(direct_targets),
            indirect_targets=len(indirect_targets),
            critical_targets=critical_count,
            systems_reached=len(all_systems),
            max_chain_depth=max_depth_seen,
            blast_radius_score=round(score, 3),
            chains=chains[:10],
        )

    def _follow_triggers(
        self,
        event_id: str,
        chain: list[str],
        targets: set[str],
        systems: set[str],
        max_depth: int,
        depth: int,
    ) -> None:
        """Recursively follow TRIGGERED edges from a decision."""
        if depth >= max_depth:
            return

        rows = self._conn.execute(
            """SELECT de.event_id, de.target_id, de.target_system
               FROM decision_events de
               WHERE de.triggered_by_event = ?""",
            (event_id,),
        ).fetchall()

        for r in rows:
            targets.add(r["target_id"])
            systems.add(r["target_system"])
            chain.append(r["event_id"])
            self._follow_triggers(r["event_id"], chain, targets, systems, max_depth, depth + 1)

    # ── Query: Automation cascades ───────────────────────────────────────────

    def find_cascades(
        self,
        min_depth: int = 2,
        min_risk: float = 0.0,
        limit: int = 20,
    ) -> list[AutomationCascade]:
        """Find multi-hop automation chains in the graph."""
        # Find root events (not triggered by anything)
        roots = self._conn.execute(
            """SELECT event_id, timestamp FROM decision_events
               WHERE triggered_by_event IS NULL
               ORDER BY timestamp DESC
               LIMIT 500""",
        ).fetchall()

        cascades = []
        for root in roots:
            chain = self._build_chain(root["event_id"])
            if len(chain) >= min_depth:
                total_risk = sum(e["risk_score"] for e in chain)
                if total_risk >= min_risk:
                    actors = list(dict.fromkeys(e["actor_id"] for e in chain))
                    systems = list(dict.fromkeys(e["system_id"] for e in chain))

                    # Check trust boundary crossing: different actor types or systems
                    crosses_trust = len(set(e["actor_type"] for e in chain)) > 1 or len(systems) > 1

                    cascades.append(AutomationCascade(
                        chain_id=f"cascade:{root['event_id']}",
                        events=[e["event_id"] for e in chain],
                        actors=actors,
                        systems=systems,
                        total_risk=round(total_risk, 3),
                        depth=len(chain),
                        starts_at=datetime.fromisoformat(chain[0]["timestamp"]),
                        ends_at=datetime.fromisoformat(chain[-1]["timestamp"]),
                        crosses_trust_boundary=crosses_trust,
                    ))

            if len(cascades) >= limit:
                break

        # Sort by total risk descending
        cascades.sort(key=lambda c: c.total_risk, reverse=True)
        return cascades

    def _build_chain(self, root_event_id: str, max_depth: int = 6) -> list[dict]:
        """Build a chain of events starting from a root event."""
        chain = []
        current_id = root_event_id

        for _ in range(max_depth):
            row = self._conn.execute(
                """SELECT event_id, actor_id, actor_type, action_name,
                          target_id, system_id, decision, risk_score, timestamp
                   FROM decision_events WHERE event_id = ?""",
                (current_id,),
            ).fetchone()

            if not row:
                break

            chain.append(dict(row))

            # Find next event triggered by this one
            next_row = self._conn.execute(
                """SELECT event_id FROM decision_events
                   WHERE triggered_by_event = ?
                   ORDER BY timestamp ASC LIMIT 1""",
                (current_id,),
            ).fetchone()

            if not next_row:
                break
            current_id = next_row["event_id"]

        return chain

    # ── Query: Actor chains ──────────────────────────────────────────────────

    def get_actor_targets(self, actor_id: str) -> list[dict[str, Any]]:
        """Get all targets an actor has affected, with frequency and recency."""
        rows = self._conn.execute(
            """SELECT target_id, target_name, target_system,
                      COUNT(*) as frequency,
                      MAX(timestamp) as last_seen,
                      AVG(risk_score) as avg_risk
               FROM decision_events
               WHERE actor_id = ?
               GROUP BY target_id
               ORDER BY frequency DESC""",
            (actor_id,),
        ).fetchall()
        return [dict(r) for r in rows]

    def get_target_actors(self, target_id: str) -> list[dict[str, Any]]:
        """Get all actors that have affected a target, with frequency."""
        rows = self._conn.execute(
            """SELECT actor_id, actor_name, actor_type,
                      COUNT(*) as frequency,
                      MAX(timestamp) as last_seen,
                      AVG(risk_score) as avg_risk
               FROM decision_events
               WHERE target_id = ?
               GROUP BY actor_id
               ORDER BY frequency DESC""",
            (target_id,),
        ).fetchall()
        return [dict(r) for r in rows]

    def get_actor_systems(self, actor_id: str) -> list[str]:
        """Get all systems an actor has operated in."""
        rows = self._conn.execute(
            """SELECT DISTINCT system_id FROM decision_events
               WHERE actor_id = ?""",
            (actor_id,),
        ).fetchall()
        return [r["system_id"] for r in rows]

    # ── Query: Graph-aware drift ─────────────────────────────────────────────

    def detect_scope_drift(self, actor_id: str, window_days: int = 30) -> dict[str, Any]:
        """
        Detect scope drift: actor touching new targets or systems
        compared to their historical baseline.
        """
        cutoff = _days_ago(window_days)

        # Historical targets (before window)
        historical = self._conn.execute(
            """SELECT DISTINCT target_id FROM decision_events
               WHERE actor_id = ? AND timestamp < ?""",
            (actor_id, cutoff),
        ).fetchall()
        historical_targets = {r["target_id"] for r in historical}

        # Recent targets (within window)
        recent = self._conn.execute(
            """SELECT DISTINCT target_id FROM decision_events
               WHERE actor_id = ? AND timestamp >= ?""",
            (actor_id, cutoff),
        ).fetchall()
        recent_targets = {r["target_id"] for r in recent}

        new_targets = recent_targets - historical_targets

        # Same for systems
        hist_sys = self._conn.execute(
            """SELECT DISTINCT system_id FROM decision_events
               WHERE actor_id = ? AND timestamp < ?""",
            (actor_id, cutoff),
        ).fetchall()
        historical_systems = {r["system_id"] for r in hist_sys}

        recent_sys = self._conn.execute(
            """SELECT DISTINCT system_id FROM decision_events
               WHERE actor_id = ? AND timestamp >= ?""",
            (actor_id, cutoff),
        ).fetchall()
        recent_systems = {r["system_id"] for r in recent_sys}

        new_systems = recent_systems - historical_systems

        scope_score = min(1.0, len(new_targets) * 0.1 + len(new_systems) * 0.3)

        return {
            "actor_id": actor_id,
            "historical_targets": len(historical_targets),
            "recent_targets": len(recent_targets),
            "new_targets": list(new_targets),
            "new_systems": list(new_systems),
            "scope_drift_score": round(scope_score, 3),
            "is_drifting": scope_score > 0.3,
        }

    def detect_path_drift(self, actor_id: str, window_days: int = 30) -> dict[str, Any]:
        """
        Detect path drift: actor participating in new automation chains.
        """
        cutoff = _days_ago(window_days)

        # Historical chains this actor participated in
        historical_chains = self._conn.execute(
            """SELECT DISTINCT triggered_by_event FROM decision_events
               WHERE actor_id = ? AND triggered_by_event IS NOT NULL
                 AND timestamp < ?""",
            (actor_id, cutoff),
        ).fetchall()
        hist_upstream_actors = set()
        for r in historical_chains:
            upstream = self._conn.execute(
                "SELECT actor_id FROM decision_events WHERE event_id = ?",
                (r["triggered_by_event"],),
            ).fetchone()
            if upstream:
                hist_upstream_actors.add(upstream["actor_id"])

        # Recent chains
        recent_chains = self._conn.execute(
            """SELECT DISTINCT triggered_by_event FROM decision_events
               WHERE actor_id = ? AND triggered_by_event IS NOT NULL
                 AND timestamp >= ?""",
            (actor_id, cutoff),
        ).fetchall()
        recent_upstream_actors = set()
        for r in recent_chains:
            upstream = self._conn.execute(
                "SELECT actor_id FROM decision_events WHERE event_id = ?",
                (r["triggered_by_event"],),
            ).fetchone()
            if upstream:
                recent_upstream_actors.add(upstream["actor_id"])

        new_paths = recent_upstream_actors - hist_upstream_actors
        path_score = min(1.0, len(new_paths) * 0.25)

        return {
            "actor_id": actor_id,
            "historical_upstream_actors": list(hist_upstream_actors),
            "new_upstream_actors": list(new_paths),
            "path_drift_score": round(path_score, 3),
            "is_drifting": path_score > 0.2,
        }

    # ── Stats ────────────────────────────────────────────────────────────────

    def node_count(self, node_type: NodeType | None = None) -> int:
        if node_type:
            row = self._conn.execute(
                "SELECT COUNT(*) as cnt FROM graph_nodes WHERE node_type = ?",
                (node_type.value,),
            ).fetchone()
        else:
            row = self._conn.execute("SELECT COUNT(*) as cnt FROM graph_nodes").fetchone()
        return row["cnt"] if row else 0

    def edge_count(self, edge_type: EdgeType | None = None) -> int:
        if edge_type:
            row = self._conn.execute(
                "SELECT COUNT(*) as cnt FROM graph_edges WHERE edge_type = ?",
                (edge_type.value,),
            ).fetchone()
        else:
            row = self._conn.execute("SELECT COUNT(*) as cnt FROM graph_edges").fetchone()
        return row["cnt"] if row else 0

    def event_count(self) -> int:
        row = self._conn.execute("SELECT COUNT(*) as cnt FROM decision_events").fetchone()
        return row["cnt"] if row else 0


def _subtract_seconds(dt: datetime, seconds: int) -> str:
    """Return ISO string of dt minus seconds."""
    from datetime import timedelta
    return (dt - timedelta(seconds=seconds)).isoformat()


def _days_ago(days: int) -> str:
    """Return ISO string of N days ago from now."""
    from datetime import timedelta
    return (datetime.now(timezone.utc) - timedelta(days=days)).isoformat()
