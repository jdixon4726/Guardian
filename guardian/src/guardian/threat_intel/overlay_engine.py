"""
Risk Overlay Engine

Manages the lifecycle of threat-driven risk overlays and provides
the scoring engine with active adjustments for current evaluations.

SECURITY INVARIANTS:
  - Overlays can only INCREASE risk, never decrease it.
  - Maximum adjustment from all combined overlays: 0.30.
  - Overlays expire automatically and cannot be renewed without review.
  - All state changes are audit-logged.
"""

from __future__ import annotations

import hashlib
import json
import logging
import sqlite3
import threading
from datetime import datetime, timedelta, timezone
from pathlib import Path

from guardian.threat_intel.models import (
    OverlayStatus,
    RiskOverlay,
    ThreatFeedSource,
)

logger = logging.getLogger(__name__)

# Maximum combined risk adjustment from all overlays
MAX_COMBINED_OVERLAY = 0.30


class OverlayEngine:
    """
    Manages risk overlays from threat intelligence feeds.

    Thread-safe. Provides get_adjustment() for the scoring engine
    to query active overlays for a given action/system/actor.
    """

    def __init__(self, db_path: Path | str = ":memory:"):
        self._db_path = str(db_path)
        self._conn = sqlite3.connect(self._db_path, check_same_thread=False,
                                      autocommit=True)
        self._conn.row_factory = sqlite3.Row
        self._conn.execute("PRAGMA journal_mode=WAL")
        self._create_tables()
        self._lock = threading.Lock()

    def _create_tables(self) -> None:
        self._conn.execute("""
            CREATE TABLE IF NOT EXISTS overlays (
                overlay_id      TEXT PRIMARY KEY,
                source          TEXT NOT NULL,
                status          TEXT NOT NULL DEFAULT 'pending',
                title           TEXT NOT NULL,
                description     TEXT DEFAULT '',
                risk_adjustment REAL NOT NULL,
                affected_actions TEXT DEFAULT '[]',
                affected_systems TEXT DEFAULT '[]',
                affected_actors TEXT DEFAULT '[]',
                cve_ids         TEXT DEFAULT '[]',
                mitre_techniques TEXT DEFAULT '[]',
                reference_url   TEXT DEFAULT '',
                source_hash     TEXT DEFAULT '',
                source_fetched_at TEXT NOT NULL,
                created_at      TEXT NOT NULL,
                expires_at      TEXT NOT NULL,
                activated_at    TEXT,
                activated_by    TEXT DEFAULT '',
                rejected_at     TEXT,
                rejected_by     TEXT DEFAULT '',
                rejection_reason TEXT DEFAULT ''
            )
        """)
        self._conn.execute("""
            CREATE TABLE IF NOT EXISTS overlay_audit_log (
                id          INTEGER PRIMARY KEY AUTOINCREMENT,
                overlay_id  TEXT NOT NULL,
                action      TEXT NOT NULL,
                actor       TEXT DEFAULT '',
                details     TEXT DEFAULT '',
                timestamp   TEXT NOT NULL
            )
        """)

    def add_overlay(self, overlay: RiskOverlay) -> None:
        """Add a new overlay (status=pending by default)."""
        with self._lock:
            self._conn.execute("""
                INSERT OR REPLACE INTO overlays (
                    overlay_id, source, status, title, description,
                    risk_adjustment, affected_actions, affected_systems,
                    affected_actors, cve_ids, mitre_techniques,
                    reference_url, source_hash, source_fetched_at,
                    created_at, expires_at
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            """, (
                overlay.overlay_id, overlay.source.value, overlay.status.value,
                overlay.title, overlay.description, overlay.risk_adjustment,
                json.dumps(overlay.affected_actions),
                json.dumps(overlay.affected_systems),
                json.dumps(overlay.affected_actors),
                json.dumps(overlay.cve_ids),
                json.dumps(overlay.mitre_techniques),
                overlay.reference_url, overlay.source_hash,
                overlay.source_fetched_at.isoformat(),
                overlay.created_at.isoformat(),
                overlay.expires_at.isoformat(),
            ))
            self._audit("created", overlay.overlay_id,
                         f"source={overlay.source.value} risk_adj={overlay.risk_adjustment}")

    def activate(self, overlay_id: str, activated_by: str = "system") -> bool:
        """Activate a pending overlay (human approval or auto-promote)."""
        with self._lock:
            now = datetime.now(timezone.utc).isoformat()
            result = self._conn.execute("""
                UPDATE overlays SET status = 'active', activated_at = ?,
                    activated_by = ?
                WHERE overlay_id = ? AND status = 'pending'
            """, (now, activated_by, overlay_id))
            if result.rowcount > 0:
                self._audit("activated", overlay_id, f"by={activated_by}")
                return True
            return False

    def reject(self, overlay_id: str, rejected_by: str, reason: str = "") -> bool:
        """Reject a pending overlay after human review."""
        with self._lock:
            now = datetime.now(timezone.utc).isoformat()
            result = self._conn.execute("""
                UPDATE overlays SET status = 'rejected', rejected_at = ?,
                    rejected_by = ?, rejection_reason = ?
                WHERE overlay_id = ? AND status = 'pending'
            """, (now, rejected_by, reason, overlay_id))
            if result.rowcount > 0:
                self._audit("rejected", overlay_id,
                            f"by={rejected_by} reason={reason}")
                return True
            return False

    def expire_stale(self) -> int:
        """Expire overlays past their expiration date."""
        now = datetime.now(timezone.utc).isoformat()
        with self._lock:
            result = self._conn.execute("""
                UPDATE overlays SET status = 'expired'
                WHERE status IN ('pending', 'active') AND expires_at < ?
            """, (now,))
            count = result.rowcount
            if count > 0:
                self._audit("bulk_expired", "system", f"expired {count} overlays")
            return count

    def get_adjustment(
        self,
        action: str = "",
        system: str = "",
        actor: str = "",
    ) -> tuple[float, list[str]]:
        """
        Get the combined risk adjustment from active overlays.

        Returns (adjustment, [overlay_titles]) where adjustment
        is capped at MAX_COMBINED_OVERLAY (0.30).

        SECURITY: Only active overlays contribute. Pending overlays
        do not affect scoring until explicitly approved.
        """
        rows = self._conn.execute("""
            SELECT overlay_id, title, risk_adjustment,
                   affected_actions, affected_systems, affected_actors
            FROM overlays
            WHERE status = 'active'
        """).fetchall()

        total_adj = 0.0
        matched_titles = []

        for row in rows:
            actions = json.loads(row["affected_actions"])
            systems = json.loads(row["affected_systems"])
            actors = json.loads(row["affected_actors"])

            # Match if overlay targets this action/system/actor
            # Empty list = applies to all
            action_match = not actions or action in actions
            system_match = not systems or any(s in system for s in systems)
            actor_match = not actors or actor in actors

            if action_match and system_match and actor_match:
                total_adj += row["risk_adjustment"]
                matched_titles.append(row["title"])

        # Cap combined overlay impact
        capped = min(total_adj, MAX_COMBINED_OVERLAY)
        return capped, matched_titles

    def list_overlays(
        self, status: OverlayStatus | None = None,
    ) -> list[dict]:
        """List overlays, optionally filtered by status."""
        if status:
            rows = self._conn.execute(
                "SELECT * FROM overlays WHERE status = ? ORDER BY created_at DESC",
                (status.value,),
            ).fetchall()
        else:
            rows = self._conn.execute(
                "SELECT * FROM overlays ORDER BY created_at DESC"
            ).fetchall()
        return [dict(r) for r in rows]

    def get_overlay(self, overlay_id: str) -> dict | None:
        row = self._conn.execute(
            "SELECT * FROM overlays WHERE overlay_id = ?", (overlay_id,),
        ).fetchone()
        return dict(row) if row else None

    def get_audit_log(self, overlay_id: str | None = None) -> list[dict]:
        """Get audit trail for overlays."""
        if overlay_id:
            rows = self._conn.execute(
                "SELECT * FROM overlay_audit_log WHERE overlay_id = ? ORDER BY timestamp DESC",
                (overlay_id,),
            ).fetchall()
        else:
            rows = self._conn.execute(
                "SELECT * FROM overlay_audit_log ORDER BY timestamp DESC LIMIT 100"
            ).fetchall()
        return [dict(r) for r in rows]

    def _audit(self, action: str, overlay_id: str, details: str = "") -> None:
        """Record an overlay lifecycle event."""
        self._conn.execute("""
            INSERT INTO overlay_audit_log (overlay_id, action, details, timestamp)
            VALUES (?, ?, ?, ?)
        """, (overlay_id, action, details, datetime.now(timezone.utc).isoformat()))
