"""
Behavioral Baseline Store

SQLite-backed per-actor rolling statistics for drift detection.
Each action evaluation is recorded as an observation. Baselines are
computed as rolling windows over the most recent N days of observations.

Tables:
  observations  — one row per evaluated action (actor, action_type, risk_score, timestamp)
  baselines     — precomputed per-actor statistics (mean, stddev, action distribution)
"""

from __future__ import annotations

import json
import logging
import math
import sqlite3
from collections import Counter
from dataclasses import dataclass, field
from datetime import datetime, timedelta, timezone
from pathlib import Path

logger = logging.getLogger(__name__)

_SCHEMA = """
CREATE TABLE IF NOT EXISTS observations (
    id          INTEGER PRIMARY KEY AUTOINCREMENT,
    actor_name  TEXT    NOT NULL,
    action_type TEXT    NOT NULL,
    risk_score  REAL    NOT NULL,
    timestamp   TEXT    NOT NULL,
    created_at  TEXT    NOT NULL DEFAULT (datetime('now'))
);

CREATE INDEX IF NOT EXISTS idx_obs_actor_ts
    ON observations(actor_name, timestamp);

CREATE TABLE IF NOT EXISTS baselines (
    actor_name          TEXT PRIMARY KEY,
    mean_risk           REAL    NOT NULL DEFAULT 0.0,
    stddev_risk         REAL    NOT NULL DEFAULT 0.0,
    observation_count   INTEGER NOT NULL DEFAULT 0,
    action_distribution TEXT    NOT NULL DEFAULT '{}',
    baseline_days       INTEGER NOT NULL DEFAULT 30,
    variance_score      REAL    NOT NULL DEFAULT 1.0,
    updated_at          TEXT    NOT NULL
);
"""


@dataclass
class ActorBaseline:
    """Precomputed per-actor behavioral baseline."""
    actor_name: str
    mean_risk: float = 0.0
    stddev_risk: float = 0.0
    observation_count: int = 0
    action_distribution: dict[str, float] = field(default_factory=dict)
    baseline_days: int = 30
    variance_score: float = 1.0  # low variance = suspiciously regular

    @property
    def has_baseline(self) -> bool:
        return self.observation_count >= 5


class BaselineStore:
    """SQLite-backed behavioral baseline store."""

    def __init__(self, db_path: Path | str = ":memory:"):
        self._db_path = str(db_path)
        self._conn = sqlite3.connect(self._db_path, check_same_thread=False)
        self._conn.row_factory = sqlite3.Row
        self._conn.execute("PRAGMA journal_mode=WAL")
        self._conn.executescript(_SCHEMA)
        logger.info("Baseline store initialized: %s", self._db_path)

    def close(self) -> None:
        self._conn.close()

    def record_observation(
        self,
        actor_name: str,
        action_type: str,
        risk_score: float,
        timestamp: datetime,
    ) -> None:
        """Record a single action evaluation as an observation."""
        self._conn.execute(
            "INSERT INTO observations (actor_name, action_type, risk_score, timestamp) "
            "VALUES (?, ?, ?, ?)",
            (actor_name, action_type, risk_score, timestamp.isoformat()),
        )
        self._conn.commit()

    def get_baseline(self, actor_name: str) -> ActorBaseline:
        """Retrieve the precomputed baseline for an actor."""
        row = self._conn.execute(
            "SELECT * FROM baselines WHERE actor_name = ?", (actor_name,)
        ).fetchone()
        if row is None:
            return ActorBaseline(actor_name=actor_name)
        return ActorBaseline(
            actor_name=row["actor_name"],
            mean_risk=row["mean_risk"],
            stddev_risk=row["stddev_risk"],
            observation_count=row["observation_count"],
            action_distribution=json.loads(row["action_distribution"]),
            baseline_days=row["baseline_days"],
            variance_score=row["variance_score"],
        )

    def recompute_baseline(
        self, actor_name: str, window_days: int = 30
    ) -> ActorBaseline:
        """
        Recompute the rolling baseline for a single actor.
        Called by the background recomputation job or on-demand.
        """
        cutoff = (datetime.now(timezone.utc) - timedelta(days=window_days)).isoformat()

        rows = self._conn.execute(
            "SELECT action_type, risk_score FROM observations "
            "WHERE actor_name = ? AND timestamp >= ? ORDER BY timestamp",
            (actor_name, cutoff),
        ).fetchall()

        if not rows:
            baseline = ActorBaseline(actor_name=actor_name, baseline_days=window_days)
            self._upsert_baseline(baseline)
            return baseline

        scores = [r["risk_score"] for r in rows]
        actions = [r["action_type"] for r in rows]

        mean = sum(scores) / len(scores)
        variance = sum((s - mean) ** 2 for s in scores) / len(scores)
        stddev = math.sqrt(variance)

        # Action type distribution (normalized)
        counts = Counter(actions)
        total = sum(counts.values())
        distribution = {k: v / total for k, v in counts.items()}

        # Variance score: how regular is the actor's behavior?
        # Low stddev relative to mean indicates suspicious regularity.
        # Normalize: 0.0 = perfectly regular, 1.0 = high variance
        if mean > 0:
            cv = stddev / mean  # coefficient of variation
            variance_score = min(1.0, cv)
        else:
            variance_score = 1.0 if stddev > 0 else 0.0

        baseline = ActorBaseline(
            actor_name=actor_name,
            mean_risk=round(mean, 4),
            stddev_risk=round(stddev, 4),
            observation_count=len(rows),
            action_distribution=distribution,
            baseline_days=window_days,
            variance_score=round(variance_score, 4),
        )
        self._upsert_baseline(baseline)
        return baseline

    def recompute_all_baselines(self, window_days: int = 30) -> int:
        """Recompute baselines for all actors. Returns count of actors updated."""
        actors = self._conn.execute(
            "SELECT DISTINCT actor_name FROM observations"
        ).fetchall()
        for row in actors:
            self.recompute_baseline(row["actor_name"], window_days)
        logger.info("Recomputed baselines for %d actors", len(actors))
        return len(actors)

    def get_all_actor_names(self) -> list[str]:
        """Return all actor names that have observations."""
        rows = self._conn.execute(
            "SELECT DISTINCT actor_name FROM observations"
        ).fetchall()
        return [r["actor_name"] for r in rows]

    def _upsert_baseline(self, baseline: ActorBaseline) -> None:
        self._conn.execute(
            "INSERT INTO baselines "
            "(actor_name, mean_risk, stddev_risk, observation_count, "
            " action_distribution, baseline_days, variance_score, updated_at) "
            "VALUES (?, ?, ?, ?, ?, ?, ?, ?) "
            "ON CONFLICT(actor_name) DO UPDATE SET "
            " mean_risk=excluded.mean_risk, stddev_risk=excluded.stddev_risk, "
            " observation_count=excluded.observation_count, "
            " action_distribution=excluded.action_distribution, "
            " baseline_days=excluded.baseline_days, "
            " variance_score=excluded.variance_score, "
            " updated_at=excluded.updated_at",
            (
                baseline.actor_name,
                baseline.mean_risk,
                baseline.stddev_risk,
                baseline.observation_count,
                json.dumps(baseline.action_distribution),
                baseline.baseline_days,
                baseline.variance_score,
                datetime.now(timezone.utc).isoformat(),
            ),
        )
        self._conn.commit()
