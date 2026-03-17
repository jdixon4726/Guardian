"""
Circuit Breaker — Per-Actor Destructive Action Rate Limiter

Tracks sliding-window counts of destructive actions per actor.
When thresholds are exceeded, the breaker trips open and all
subsequent destructive actions from that actor are auto-denied
until the cooldown expires.

This is the layer that would have stopped the Stryker attack:
200,000 remote wipes from a single admin account would trip
the breaker after the first handful, blocking the remaining 199,995.
"""

from __future__ import annotations

import logging
import threading
from collections import defaultdict
from dataclasses import dataclass, field
from datetime import datetime, timedelta, timezone

from guardian.circuit_breaker.models import BreakerState, BreakerTrip

logger = logging.getLogger(__name__)


@dataclass
class CircuitBreakerConfig:
    """Thresholds for the circuit breaker."""
    # Per-minute threshold for destructive actions from a single actor
    max_destructive_per_minute: int = 5
    # Per-hour threshold
    max_destructive_per_hour: int = 20
    # How long the breaker stays open after tripping (seconds)
    cooldown_seconds: int = 300  # 5 minutes
    # Action categories considered "destructive" by the breaker
    destructive_actions: list[str] = field(default_factory=lambda: [
        "destroy_infrastructure", "delete_resource", "drop_database",
        "wipe_storage", "terminate_instances", "delete_vpc",
        "destroy_device", "wipe_device", "retire_device", "delete_device",
        "remote_wipe", "factory_reset",
        "disable_endpoint_protection", "disable_firewall",
        "escalate_privileges", "grant_admin_access",
    ])


@dataclass
class _ActorWindow:
    """Sliding window of destructive action timestamps for one actor."""
    timestamps: list[datetime] = field(default_factory=list)
    state: BreakerState = BreakerState.closed
    tripped_at: datetime | None = None
    trip_count: int = 0


class CircuitBreaker:
    """
    Per-actor circuit breaker for destructive action velocity.

    Thread-safe. Designed to be shared across all adapters.
    """

    def __init__(self, config: CircuitBreakerConfig | None = None):
        self.config = config or CircuitBreakerConfig()
        self._actors: dict[str, _ActorWindow] = defaultdict(_ActorWindow)
        self._lock = threading.Lock()
        self._trips: list[BreakerTrip] = []

    def check(self, actor_name: str, action: str) -> tuple[bool, str | None]:
        """
        Check whether an action should be allowed through the breaker.

        Returns:
            (allowed, reason) — allowed=True means the action passes the
            breaker check. reason is set when allowed=False.
        """
        if action not in self.config.destructive_actions:
            return True, None

        now = datetime.now(timezone.utc)

        with self._lock:
            window = self._actors[actor_name]

            # Check if breaker is open (tripped)
            if window.state == BreakerState.open:
                if window.tripped_at and self._cooldown_expired(window, now):
                    window.state = BreakerState.half_open
                    logger.info(
                        "Circuit breaker half-open for actor=%s (cooldown expired)",
                        actor_name,
                    )
                else:
                    return False, (
                        f"Circuit breaker OPEN for {actor_name}: "
                        f"{window.trip_count} destructive actions exceeded threshold. "
                        f"Cooldown expires in {self._cooldown_remaining(window, now)}s."
                    )

            # Record this action
            window.timestamps.append(now)

            # Prune timestamps older than 1 hour
            cutoff_hour = now - timedelta(hours=1)
            window.timestamps = [t for t in window.timestamps if t > cutoff_hour]

            # Check per-minute threshold
            cutoff_minute = now - timedelta(minutes=1)
            minute_count = sum(1 for t in window.timestamps if t > cutoff_minute)
            if minute_count > self.config.max_destructive_per_minute:
                return self._trip(window, actor_name, minute_count, 60,
                                  self.config.max_destructive_per_minute, now)

            # Check per-hour threshold
            hour_count = len(window.timestamps)
            if hour_count > self.config.max_destructive_per_hour:
                return self._trip(window, actor_name, hour_count, 3600,
                                  self.config.max_destructive_per_hour, now)

            # Half-open probe: if we got here, the probe succeeded
            if window.state == BreakerState.half_open:
                window.state = BreakerState.closed
                window.trip_count = 0
                logger.info("Circuit breaker closed for actor=%s (probe succeeded)", actor_name)

            return True, None

    def _trip(
        self,
        window: _ActorWindow,
        actor_name: str,
        count: int,
        window_seconds: int,
        threshold: int,
        now: datetime,
    ) -> tuple[bool, str]:
        """Trip the breaker open."""
        window.state = BreakerState.open
        window.tripped_at = now
        window.trip_count = count

        reason = (
            f"Circuit breaker TRIPPED for {actor_name}: "
            f"{count} destructive actions in {window_seconds}s "
            f"(threshold: {threshold}). "
            f"All destructive actions blocked for {self.config.cooldown_seconds}s."
        )

        trip = BreakerTrip(
            actor_name=actor_name,
            triggered_at=now,
            action_count=count,
            window_seconds=window_seconds,
            threshold=threshold,
            reason=reason,
        )
        self._trips.append(trip)
        logger.warning(reason)

        return False, reason

    def _cooldown_expired(self, window: _ActorWindow, now: datetime) -> bool:
        if window.tripped_at is None:
            return True
        return now > window.tripped_at + timedelta(seconds=self.config.cooldown_seconds)

    def _cooldown_remaining(self, window: _ActorWindow, now: datetime) -> int:
        if window.tripped_at is None:
            return 0
        expiry = window.tripped_at + timedelta(seconds=self.config.cooldown_seconds)
        remaining = (expiry - now).total_seconds()
        return max(0, int(remaining))

    def get_state(self, actor_name: str) -> BreakerState:
        """Get the current breaker state for an actor."""
        with self._lock:
            return self._actors[actor_name].state

    def get_trips(self, actor_name: str | None = None) -> list[BreakerTrip]:
        """Get trip history, optionally filtered by actor."""
        if actor_name:
            return [t for t in self._trips if t.actor_name == actor_name]
        return list(self._trips)

    def reset(self, actor_name: str) -> None:
        """Manually reset an actor's breaker (e.g., after investigation)."""
        with self._lock:
            if actor_name in self._actors:
                self._actors[actor_name] = _ActorWindow()
                logger.info("Circuit breaker manually reset for actor=%s", actor_name)
