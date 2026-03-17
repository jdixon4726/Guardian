"""
Circuit Breaker data models.
"""

from __future__ import annotations

from datetime import datetime, timezone
from enum import Enum

from pydantic import BaseModel, Field


class BreakerState(str, Enum):
    """Current state of an actor's circuit breaker."""
    closed = "closed"        # normal operation, actions flow through
    open = "open"            # tripped — all destructive actions denied
    half_open = "half_open"  # cooldown expired, next action is a probe


class BreakerTrip(BaseModel):
    """Record of a circuit breaker trip event."""
    actor_name: str
    triggered_at: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))
    action_count: int              # destructive actions in window when tripped
    window_seconds: int            # the window that was exceeded
    threshold: int                 # the threshold that was exceeded
    reason: str                    # human-readable explanation
