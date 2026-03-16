"""
Background Baseline Recomputation Job

Periodically recomputes behavioral baselines for all actors.
Runs as a background thread started at pipeline initialization.

This ensures drift detection operates on fresh baselines even
when the pipeline is idle (no incoming evaluations).
"""

from __future__ import annotations

import logging
import threading
import time
from datetime import datetime, timezone

from guardian.drift.baseline import BaselineStore

logger = logging.getLogger(__name__)

_DEFAULT_INTERVAL = 3600  # 1 hour


class BaselineRecomputeJob:
    """Background thread that recomputes all baselines on a schedule."""

    def __init__(
        self,
        baseline_store: BaselineStore,
        interval_seconds: int = _DEFAULT_INTERVAL,
        window_days: int = 30,
    ):
        self._store = baseline_store
        self._interval = interval_seconds
        self._window_days = window_days
        self._thread: threading.Thread | None = None
        self._stop_event = threading.Event()

    def start(self) -> None:
        """Start the background recomputation loop."""
        if self._thread is not None and self._thread.is_alive():
            return

        self._stop_event.clear()
        self._thread = threading.Thread(
            target=self._run_loop,
            daemon=True,
            name="guardian-baseline-recompute",
        )
        self._thread.start()
        logger.info(
            "Baseline recomputation job started (interval=%ds, window=%dd)",
            self._interval, self._window_days,
        )

    def stop(self) -> None:
        """Signal the background thread to stop."""
        self._stop_event.set()
        if self._thread is not None:
            self._thread.join(timeout=5.0)
            logger.info("Baseline recomputation job stopped")

    def run_once(self) -> int:
        """Run a single recomputation cycle. Returns count of actors updated."""
        try:
            count = self._store.recompute_all_baselines(self._window_days)
            logger.info(
                "Baseline recomputation complete: %d actors updated at %s",
                count, datetime.now(timezone.utc).isoformat(),
            )
            return count
        except Exception as exc:
            logger.error("Baseline recomputation failed: %s", exc)
            return 0

    def _run_loop(self) -> None:
        """Background loop that runs recomputation on schedule."""
        while not self._stop_event.is_set():
            self.run_once()
            self._stop_event.wait(timeout=self._interval)
