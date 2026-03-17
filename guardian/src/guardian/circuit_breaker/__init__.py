"""
Circuit Breaker — Mass-Action Defense

Tracks per-actor destructive action velocity and auto-denies when thresholds
are exceeded. This is a defense-in-depth layer that catches coordinated
mass-action attacks (e.g., Stryker-style wiper attacks) that individual
per-action scoring might miss.

The circuit breaker operates independently of the pipeline's per-action
risk scoring. Even if each individual action scores "moderate," the
aggregate velocity of destructive actions triggers a hard stop.
"""

from guardian.circuit_breaker.breaker import CircuitBreaker, CircuitBreakerConfig
from guardian.circuit_breaker.models import BreakerState, BreakerTrip

__all__ = ["CircuitBreaker", "CircuitBreakerConfig", "BreakerState", "BreakerTrip"]
