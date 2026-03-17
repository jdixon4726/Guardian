"""
Actor History Store

SQLite-backed append-only record of every action evaluation per actor.
Provides trust level computation, velocity tracking, and profile summaries.

Tables:
  action_history — one row per evaluated action (actor, action, decision, risk, timestamp)
"""

from __future__ import annotations

import logging
import sqlite3
from dataclasses import dataclass, field
from datetime import datetime, timedelta, timezone
from pathlib import Path

from guardian.config.model import TrustConfig

logger = logging.getLogger(__name__)

_SCHEMA = """
CREATE TABLE IF NOT EXISTS action_history (
    id              INTEGER PRIMARY KEY AUTOINCREMENT,
    actor_name      TEXT    NOT NULL,
    action_type     TEXT    NOT NULL,
    target_asset    TEXT    NOT NULL,
    decision        TEXT    NOT NULL,
    risk_score      REAL    NOT NULL,
    privilege_level TEXT    NOT NULL DEFAULT 'standard',
    timestamp       TEXT    NOT NULL,
    created_at      TEXT    NOT NULL DEFAULT (datetime('now'))
);

CREATE INDEX IF NOT EXISTS idx_hist_actor_ts
    ON action_history(actor_name, timestamp);

CREATE INDEX IF NOT EXISTS idx_hist_actor_decision
    ON action_history(actor_name, decision);
"""

_DEFAULT_TRUST = TrustConfig()


@dataclass
class ActorProfile:
    """Summary of an actor's evaluation history and trust level."""
    actor_name: str
    total_actions: int = 0
    total_blocks: int = 0
    total_reviews: int = 0
    total_allows: int = 0
    prior_privilege_escalations: int = 0
    history_days: int = 0
    trust_level: float = 0.5        # [0.0, 1.0] — 0.5 is default for new actors
    actions_last_hour: int = 0
    actions_last_day: int = 0
    first_seen: datetime | None = None
    last_seen: datetime | None = None
    top_actions: dict[str, int] = field(default_factory=dict)


class ActorHistoryStore:
    """Database-backed append-only actor history store.

    Accepts either a legacy db_path (SQLite) or a DatabaseConnection
    from the storage abstraction layer (SQLite or PostgreSQL).
    """

    def __init__(self, db_path: Path | str = ":memory:",
                 trust_config: TrustConfig | None = None,
                 connection=None):
        self._trust = trust_config or _DEFAULT_TRUST
        if connection is not None:
            # Use provided storage abstraction connection
            self._conn = connection.raw
            self._db_conn = connection
        else:
            # Legacy SQLite path (backward compatible)
            self._db_path = str(db_path)
            self._conn = sqlite3.connect(self._db_path, check_same_thread=False)
            self._conn.row_factory = sqlite3.Row
            self._conn.execute("PRAGMA journal_mode=WAL")
            self._db_conn = None
        self._conn.executescript(_SCHEMA) if not connection else connection.executescript(_SCHEMA)
        logger.info("Actor history store initialized")

    def close(self) -> None:
        self._conn.close()

    def record(
        self,
        actor_name: str,
        action_type: str,
        target_asset: str,
        decision: str,
        risk_score: float,
        privilege_level: str = "standard",
        timestamp: datetime | None = None,
    ) -> None:
        """Record a single evaluated action."""
        ts = timestamp or datetime.now(timezone.utc)
        self._conn.execute(
            "INSERT INTO action_history "
            "(actor_name, action_type, target_asset, decision, risk_score, "
            " privilege_level, timestamp) "
            "VALUES (?, ?, ?, ?, ?, ?, ?)",
            (actor_name, action_type, target_asset, decision, risk_score,
             privilege_level, ts.isoformat()),
        )
        self._conn.commit()

    def get_profile(
        self, actor_name: str, at: datetime | None = None,
    ) -> ActorProfile:
        """Build a full actor profile from history."""
        now = at or datetime.now(timezone.utc)

        # Totals by decision
        rows = self._conn.execute(
            "SELECT decision, COUNT(*) as cnt "
            "FROM action_history WHERE actor_name = ? GROUP BY decision",
            (actor_name,),
        ).fetchall()

        totals: dict[str, int] = {}
        for r in rows:
            totals[r["decision"]] = r["cnt"]

        total_actions = sum(totals.values())
        if total_actions == 0:
            return ActorProfile(actor_name=actor_name)

        total_blocks = totals.get("block", 0)
        total_reviews = totals.get("require_review", 0)
        total_allows = (
            totals.get("allow", 0) + totals.get("allow_with_logging", 0)
        )

        # Privilege escalation count
        esc_row = self._conn.execute(
            "SELECT COUNT(*) as cnt FROM action_history "
            "WHERE actor_name = ? AND action_type LIKE '%privilege%'",
            (actor_name,),
        ).fetchone()
        prior_escalations = esc_row["cnt"] if esc_row else 0

        # Time range
        range_row = self._conn.execute(
            "SELECT MIN(timestamp) as first_ts, MAX(timestamp) as last_ts "
            "FROM action_history WHERE actor_name = ?",
            (actor_name,),
        ).fetchone()
        first_seen = datetime.fromisoformat(range_row["first_ts"])
        last_seen = datetime.fromisoformat(range_row["last_ts"])
        history_days = max(1, (last_seen - first_seen).days)

        # Velocity: actions in last hour and last day
        hour_ago = (now - timedelta(hours=1)).isoformat()
        day_ago = (now - timedelta(days=1)).isoformat()

        hour_row = self._conn.execute(
            "SELECT COUNT(*) as cnt FROM action_history "
            "WHERE actor_name = ? AND timestamp >= ?",
            (actor_name, hour_ago),
        ).fetchone()
        day_row = self._conn.execute(
            "SELECT COUNT(*) as cnt FROM action_history "
            "WHERE actor_name = ? AND timestamp >= ?",
            (actor_name, day_ago),
        ).fetchone()

        actions_last_hour = hour_row["cnt"] if hour_row else 0
        actions_last_day = day_row["cnt"] if day_row else 0

        # Top actions
        top_rows = self._conn.execute(
            "SELECT action_type, COUNT(*) as cnt FROM action_history "
            "WHERE actor_name = ? GROUP BY action_type ORDER BY cnt DESC LIMIT 5",
            (actor_name,),
        ).fetchall()
        top_actions = {r["action_type"]: r["cnt"] for r in top_rows}

        # Trust level computation
        trust = self._compute_trust(
            actor_name, total_actions, now,
        )

        return ActorProfile(
            actor_name=actor_name,
            total_actions=total_actions,
            total_blocks=total_blocks,
            total_reviews=total_reviews,
            total_allows=total_allows,
            prior_privilege_escalations=prior_escalations,
            history_days=history_days,
            trust_level=trust,
            actions_last_hour=actions_last_hour,
            actions_last_day=actions_last_day,
            first_seen=first_seen,
            last_seen=last_seen,
            top_actions=top_actions,
        )

    def _compute_trust(
        self, actor_name: str, total_actions: int, now: datetime,
    ) -> float:
        """
        Compute trust level [0.0, 1.0] for an actor.

        New actors start at 0.5 (neutral). Trust builds with clean allows
        and degrades with blocks and reviews, computed over a rolling window.
        Actors with fewer than min_actions cannot exceed 0.5.
        """
        cfg = self._trust
        if total_actions == 0:
            return 0.5

        cutoff = (now - timedelta(days=cfg.window_days)).isoformat()
        rows = self._conn.execute(
            "SELECT decision FROM action_history "
            "WHERE actor_name = ? AND timestamp >= ?",
            (actor_name, cutoff),
        ).fetchall()

        if not rows:
            return 0.5

        trust = 0.5
        for r in rows:
            d = r["decision"]
            if d == "block":
                trust -= cfg.block_penalty
            elif d == "require_review":
                trust -= cfg.review_penalty
            elif d in ("allow", "allow_with_logging"):
                trust += cfg.allow_bonus

        # Cap at 0.5 for actors without enough history
        if total_actions < cfg.min_actions:
            trust = min(trust, 0.5)

        return round(max(0.0, min(1.0, trust)), 3)

    def get_velocity(
        self, actor_name: str, at: datetime | None = None,
    ) -> tuple[int, int]:
        """Return (actions_last_hour, actions_last_day)."""
        now = at or datetime.now(timezone.utc)
        hour_ago = (now - timedelta(hours=1)).isoformat()
        day_ago = (now - timedelta(days=1)).isoformat()

        hour_row = self._conn.execute(
            "SELECT COUNT(*) as cnt FROM action_history "
            "WHERE actor_name = ? AND timestamp >= ?",
            (actor_name, hour_ago),
        ).fetchone()
        day_row = self._conn.execute(
            "SELECT COUNT(*) as cnt FROM action_history "
            "WHERE actor_name = ? AND timestamp >= ?",
            (actor_name, day_ago),
        ).fetchone()

        return (hour_row["cnt"] if hour_row else 0,
                day_row["cnt"] if day_row else 0)

    def get_timeline(
        self, actor_name: str, limit: int = 200,
    ) -> list[dict]:
        """Return recent action history for timeline visualization."""
        rows = self._conn.execute(
            "SELECT action_type, target_asset, decision, risk_score, "
            "privilege_level, timestamp FROM action_history "
            "WHERE actor_name = ? ORDER BY timestamp DESC LIMIT ?",
            (actor_name, limit),
        ).fetchall()
        return [dict(r) for r in rows]

    def get_hourly_pattern(self, actor_name: str) -> list[dict]:
        """Return action counts by hour-of-day for pattern-of-life analysis."""
        rows = self._conn.execute(
            """SELECT
                CAST(strftime('%%H', timestamp) AS INTEGER) as hour,
                decision,
                COUNT(*) as count
            FROM action_history
            WHERE actor_name = ?
            GROUP BY hour, decision
            ORDER BY hour""",
            (actor_name,),
        ).fetchall()
        return [dict(r) for r in rows]
