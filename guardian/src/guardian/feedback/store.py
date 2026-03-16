"""
Feedback Store — SQLite-backed operator feedback on Guardian decisions.

Stores feedback, computes aggregate statistics per actor/policy/action,
and provides Bayesian prior adjustments based on accumulated feedback.
"""

from __future__ import annotations

import json
import sqlite3
from dataclasses import dataclass, field
from datetime import datetime, timezone
from enum import Enum
from typing import Any
from uuid import uuid4


class FeedbackType(str, Enum):
    confirmed_correct = "confirmed_correct"
    false_positive = "false_positive"      # Guardian blocked but shouldn't have
    false_negative = "false_negative"      # Guardian allowed but shouldn't have
    known_pattern = "known_pattern"        # Cascade/alert is expected behavior


@dataclass
class OperatorFeedback:
    """A single feedback entry from an operator."""
    feedback_id: str
    decision_entry_id: str
    feedback_type: FeedbackType
    operator: str                          # who submitted the feedback
    reason: str = ""                       # optional explanation
    created_at: datetime = field(default_factory=lambda: datetime.now(timezone.utc))
    metadata: dict[str, Any] = field(default_factory=dict)


@dataclass
class FeedbackStats:
    """Aggregate feedback stats for a given scope (actor, policy, action)."""
    total_feedback: int = 0
    confirmed_correct: int = 0
    false_positives: int = 0
    false_negatives: int = 0
    known_patterns: int = 0

    @property
    def false_positive_rate(self) -> float:
        if self.total_feedback == 0:
            return 0.0
        return self.false_positives / self.total_feedback

    @property
    def accuracy_rate(self) -> float:
        if self.total_feedback == 0:
            return 1.0  # assume correct when no feedback
        return self.confirmed_correct / self.total_feedback


@dataclass
class PriorAdjustment:
    """Bayesian prior adjustment derived from operator feedback."""
    actor_type: str
    alpha_adjustment: float    # added to risky prior
    beta_adjustment: float     # added to normal prior
    reason: str


class FeedbackStore:
    """SQLite-backed feedback storage with aggregate query support."""

    def __init__(self, db_path: str = ":memory:"):
        self._conn = sqlite3.connect(db_path, check_same_thread=False)
        self._conn.row_factory = sqlite3.Row
        self._conn.execute("PRAGMA journal_mode=WAL")
        self._create_tables()

    def _create_tables(self) -> None:
        self._conn.executescript("""
            CREATE TABLE IF NOT EXISTS operator_feedback (
                feedback_id         TEXT PRIMARY KEY,
                decision_entry_id   TEXT NOT NULL,
                feedback_type       TEXT NOT NULL,
                operator            TEXT NOT NULL,
                reason              TEXT NOT NULL DEFAULT '',
                created_at          TEXT NOT NULL,
                -- Denormalized fields from the decision for efficient aggregation
                actor_name          TEXT,
                actor_type          TEXT,
                action_name         TEXT,
                policy_matched      TEXT,
                original_decision   TEXT,
                metadata            TEXT NOT NULL DEFAULT '{}'
            );

            CREATE INDEX IF NOT EXISTS idx_feedback_decision
                ON operator_feedback(decision_entry_id);
            CREATE INDEX IF NOT EXISTS idx_feedback_actor
                ON operator_feedback(actor_name);
            CREATE INDEX IF NOT EXISTS idx_feedback_type
                ON operator_feedback(feedback_type);
            CREATE INDEX IF NOT EXISTS idx_feedback_policy
                ON operator_feedback(policy_matched);

            -- Suppression rules: known_pattern feedback creates suppression entries
            CREATE TABLE IF NOT EXISTS cascade_suppressions (
                suppression_id      TEXT PRIMARY KEY,
                actor_pattern       TEXT NOT NULL,
                system_pattern      TEXT NOT NULL,
                reason              TEXT NOT NULL,
                created_by          TEXT NOT NULL,
                created_at          TEXT NOT NULL,
                expires_at          TEXT
            );
        """)

    # ── Record feedback ──────────────────────────────────────────────────────

    def record(
        self,
        decision_entry_id: str,
        feedback_type: FeedbackType,
        operator: str,
        reason: str = "",
        actor_name: str | None = None,
        actor_type: str | None = None,
        action_name: str | None = None,
        policy_matched: str | None = None,
        original_decision: str | None = None,
        metadata: dict[str, Any] | None = None,
    ) -> OperatorFeedback:
        """Record operator feedback on a decision."""
        feedback = OperatorFeedback(
            feedback_id=str(uuid4()),
            decision_entry_id=decision_entry_id,
            feedback_type=feedback_type,
            operator=operator,
            reason=reason,
            metadata=metadata or {},
        )

        self._conn.execute(
            """INSERT INTO operator_feedback
               (feedback_id, decision_entry_id, feedback_type, operator, reason,
                created_at, actor_name, actor_type, action_name, policy_matched,
                original_decision, metadata)
               VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)""",
            (
                feedback.feedback_id,
                decision_entry_id,
                feedback_type.value,
                operator,
                reason,
                feedback.created_at.isoformat(),
                actor_name,
                actor_type,
                action_name,
                policy_matched,
                original_decision,
                json.dumps(feedback.metadata),
            ),
        )
        self._conn.commit()
        return feedback

    # ── Query feedback ───────────────────────────────────────────────────────

    def get_feedback_for_decision(self, decision_entry_id: str) -> list[OperatorFeedback]:
        rows = self._conn.execute(
            "SELECT * FROM operator_feedback WHERE decision_entry_id = ?",
            (decision_entry_id,),
        ).fetchall()
        return [self._row_to_feedback(r) for r in rows]

    def get_stats_for_actor(self, actor_name: str) -> FeedbackStats:
        return self._aggregate_stats("actor_name = ?", (actor_name,))

    def get_stats_for_policy(self, policy_id: str) -> FeedbackStats:
        return self._aggregate_stats("policy_matched = ?", (policy_id,))

    def get_stats_for_action(self, action_name: str) -> FeedbackStats:
        return self._aggregate_stats("action_name = ?", (action_name,))

    def get_overall_stats(self) -> FeedbackStats:
        return self._aggregate_stats("1=1", ())

    def _aggregate_stats(self, where: str, params: tuple) -> FeedbackStats:
        row = self._conn.execute(
            f"""SELECT
                COUNT(*) as total,
                SUM(CASE WHEN feedback_type = 'confirmed_correct' THEN 1 ELSE 0 END) as confirmed,
                SUM(CASE WHEN feedback_type = 'false_positive' THEN 1 ELSE 0 END) as fp,
                SUM(CASE WHEN feedback_type = 'false_negative' THEN 1 ELSE 0 END) as fn,
                SUM(CASE WHEN feedback_type = 'known_pattern' THEN 1 ELSE 0 END) as kp
            FROM operator_feedback WHERE {where}""",
            params,
        ).fetchone()
        return FeedbackStats(
            total_feedback=row["total"],
            confirmed_correct=row["confirmed"] or 0,
            false_positives=row["fp"] or 0,
            false_negatives=row["fn"] or 0,
            known_patterns=row["kp"] or 0,
        )

    # ── Bayesian prior adjustment ────────────────────────────────────────────

    def compute_prior_adjustments(self) -> list[PriorAdjustment]:
        """
        Compute Bayesian prior adjustments based on accumulated feedback.

        False positives → increase beta (more weight on "normal")
        False negatives → increase alpha (more weight on "risky")
        The magnitude scales with the feedback count.
        """
        adjustments = []

        rows = self._conn.execute(
            """SELECT actor_type, feedback_type, COUNT(*) as cnt
               FROM operator_feedback
               WHERE actor_type IS NOT NULL
               GROUP BY actor_type, feedback_type""",
        ).fetchall()

        # Group by actor_type
        by_type: dict[str, dict[str, int]] = {}
        for r in rows:
            at = r["actor_type"]
            if at not in by_type:
                by_type[at] = {}
            by_type[at][r["feedback_type"]] = r["cnt"]

        for actor_type, counts in by_type.items():
            fp = counts.get("false_positive", 0)
            fn = counts.get("false_negative", 0)

            if fp == 0 and fn == 0:
                continue

            # Scale: each false positive adds 0.5 to beta, each false negative adds 0.5 to alpha
            # Capped at ±5.0 to prevent runaway adjustments
            alpha_adj = min(5.0, fn * 0.5)
            beta_adj = min(5.0, fp * 0.5)

            reason_parts = []
            if fp > 0:
                reason_parts.append(f"{fp} false positives (loosening)")
            if fn > 0:
                reason_parts.append(f"{fn} false negatives (tightening)")

            adjustments.append(PriorAdjustment(
                actor_type=actor_type,
                alpha_adjustment=alpha_adj,
                beta_adjustment=beta_adj,
                reason="; ".join(reason_parts),
            ))

        return adjustments

    # ── Cascade suppressions ─────────────────────────────────────────────────

    def add_cascade_suppression(
        self,
        actor_pattern: str,
        system_pattern: str,
        reason: str,
        created_by: str,
        expires_at: datetime | None = None,
    ) -> str:
        """Add a suppression rule for known cascade patterns."""
        sid = str(uuid4())
        self._conn.execute(
            """INSERT INTO cascade_suppressions
               (suppression_id, actor_pattern, system_pattern, reason, created_by,
                created_at, expires_at)
               VALUES (?, ?, ?, ?, ?, ?, ?)""",
            (
                sid, actor_pattern, system_pattern, reason, created_by,
                datetime.now(timezone.utc).isoformat(),
                expires_at.isoformat() if expires_at else None,
            ),
        )
        self._conn.commit()
        return sid

    def is_cascade_suppressed(self, actor_name: str, system_name: str) -> bool:
        """Check if a cascade involving this actor/system is suppressed."""
        now = datetime.now(timezone.utc).isoformat()
        row = self._conn.execute(
            """SELECT COUNT(*) as cnt FROM cascade_suppressions
               WHERE (actor_pattern = ? OR actor_pattern = '*')
                 AND (system_pattern = ? OR system_pattern = '*')
                 AND (expires_at IS NULL OR expires_at > ?)""",
            (actor_name, system_name, now),
        ).fetchone()
        return row["cnt"] > 0

    def _row_to_feedback(self, row: sqlite3.Row) -> OperatorFeedback:
        return OperatorFeedback(
            feedback_id=row["feedback_id"],
            decision_entry_id=row["decision_entry_id"],
            feedback_type=FeedbackType(row["feedback_type"]),
            operator=row["operator"],
            reason=row["reason"],
            created_at=datetime.fromisoformat(row["created_at"]),
            metadata=json.loads(row["metadata"]),
        )

    def feedback_count(self) -> int:
        row = self._conn.execute("SELECT COUNT(*) as cnt FROM operator_feedback").fetchone()
        return row["cnt"]
