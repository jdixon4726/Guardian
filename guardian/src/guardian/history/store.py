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

# Trust level thresholds
_TRUST_MIN_ACTIONS = 10          # minimum actions before trust can rise above base
_TRUST_BLOCK_PENALTY = 0.05      # per block in window
_TRUST_REVIEW_PENALTY = 0.02     # per review in window
_TRUST_ALLOW_BONUS = 0.005       # per clean allow in window
_TRUST_WINDOW_DAYS = 30


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
    """SQLite-backed append-only actor history store."""

    def __init__(self, db_path: Path | str = ":memory:"):
        self._db_path = str(db_path)
        self._conn = sqlite3.connect(self._db_path)
        self._conn.row_factory = sqlite3.Row
        self._conn.executescript(_SCHEMA)
        logger.info("Actor history store initialized: %s", self._db_path)

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
        Actors with fewer than _TRUST_MIN_ACTIONS cannot exceed 0.5.
        """
        if total_actions == 0:
            return 0.5

        cutoff = (now - timedelta(days=_TRUST_WINDOW_DAYS)).isoformat()
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
                trust -= _TRUST_BLOCK_PENALTY
            elif d == "require_review":
                trust -= _TRUST_REVIEW_PENALTY
            elif d in ("allow", "allow_with_logging"):
                trust += _TRUST_ALLOW_BONUS

        # Cap at 0.5 for actors without enough history
        if total_actions < _TRUST_MIN_ACTIONS:
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
