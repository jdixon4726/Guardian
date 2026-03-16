"""
Alert Publisher (Phase 2.5)

Publishes drift alerts to a structured log. In Phase 3+ this will be
extended with webhook delivery and integration with external alerting.

Alerts are emitted asynchronously (fire-and-forget) so they never block
the evaluation pipeline.
"""

from __future__ import annotations

import json
import logging
from datetime import datetime, timezone
from pathlib import Path
from typing import Optional

from guardian.models.action_request import DriftScore

logger = logging.getLogger(__name__)

# Dedicated drift alert logger — separate from the main audit log
_alert_logger = logging.getLogger("guardian.drift.alerts")


class AlertPublisher:
    """
    Log-based alert publisher for drift events.

    Writes structured JSON lines to a dedicated alert log file and
    emits Python logging records for operational visibility.
    """

    def __init__(self, alert_log_path: Optional[Path] = None):
        self._log_path = alert_log_path
        if self._log_path:
            self._log_path.parent.mkdir(parents=True, exist_ok=True)
        self._alert_count = 0

    def publish(
        self,
        actor_name: str,
        action_type: str,
        drift_score: DriftScore,
        decision_entry_id: str,
    ) -> None:
        """
        Publish a drift alert if the drift score triggered an alert.
        No-op if alert_triggered is False.
        """
        if not drift_score.alert_triggered:
            return

        self._alert_count += 1

        alert = {
            "alert_type": "behavioral_drift",
            "actor_name": actor_name,
            "action_type": action_type,
            "drift_score": drift_score.score,
            "level_drift_z": drift_score.level_drift_z,
            "pattern_drift_js": drift_score.pattern_drift_js,
            "baseline_days": drift_score.baseline_days,
            "explanation": drift_score.explanation,
            "decision_entry_id": decision_entry_id,
            "timestamp": datetime.now(timezone.utc).isoformat(),
        }

        # Log to Python logging
        _alert_logger.warning(
            "DRIFT ALERT: actor=%s score=%.3f z=%.2f js=%.3f — %s",
            actor_name,
            drift_score.score,
            drift_score.level_drift_z,
            drift_score.pattern_drift_js,
            drift_score.explanation,
        )

        # Write to alert log file
        if self._log_path:
            with open(self._log_path, "a") as f:
                f.write(json.dumps(alert) + "\n")

    @property
    def alert_count(self) -> int:
        return self._alert_count
