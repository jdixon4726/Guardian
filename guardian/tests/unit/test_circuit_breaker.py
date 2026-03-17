"""
Unit tests for the Circuit Breaker module.
"""

from datetime import datetime, timedelta, timezone

import pytest

from guardian.circuit_breaker.breaker import CircuitBreaker, CircuitBreakerConfig
from guardian.circuit_breaker.models import BreakerState


@pytest.fixture
def config():
    return CircuitBreakerConfig(
        max_destructive_per_minute=3,
        max_destructive_per_hour=10,
        cooldown_seconds=60,
        destructive_actions=["wipe_device", "delete_device", "destroy_infrastructure"],
    )


@pytest.fixture
def breaker(config):
    return CircuitBreaker(config)


class TestCircuitBreakerBasic:
    def test_non_destructive_action_always_allowed(self, breaker):
        """Non-destructive actions bypass the breaker entirely."""
        for _ in range(100):
            allowed, reason = breaker.check("admin@corp.com", "change_configuration")
            assert allowed is True
            assert reason is None

    def test_destructive_action_allowed_under_threshold(self, breaker):
        """Destructive actions pass when under the per-minute threshold."""
        for i in range(3):
            allowed, reason = breaker.check("admin@corp.com", "wipe_device")
            assert allowed is True, f"Action {i+1} should be allowed"

    def test_breaker_trips_on_minute_threshold(self, breaker):
        """Breaker trips after exceeding per-minute threshold."""
        # First 3 should pass (threshold is 3)
        for _ in range(3):
            allowed, _ = breaker.check("admin@corp.com", "wipe_device")
            assert allowed is True

        # 4th should trip the breaker
        allowed, reason = breaker.check("admin@corp.com", "wipe_device")
        assert allowed is False
        assert "TRIPPED" in reason
        assert "admin@corp.com" in reason

    def test_tripped_breaker_blocks_subsequent_actions(self, breaker):
        """Once tripped, all destructive actions are blocked."""
        # Trip the breaker
        for _ in range(4):
            breaker.check("admin@corp.com", "wipe_device")

        # Subsequent should be blocked
        allowed, reason = breaker.check("admin@corp.com", "delete_device")
        assert allowed is False
        assert "OPEN" in reason

    def test_breaker_is_per_actor(self, breaker):
        """Different actors have independent breakers."""
        # Trip actor A
        for _ in range(4):
            breaker.check("actor-a", "wipe_device")

        # Actor B should still be fine
        allowed, _ = breaker.check("actor-b", "wipe_device")
        assert allowed is True

    def test_non_destructive_passes_even_when_tripped(self, breaker):
        """Non-destructive actions pass even when the breaker is open."""
        # Trip the breaker
        for _ in range(4):
            breaker.check("admin@corp.com", "wipe_device")

        # Non-destructive should still pass
        allowed, _ = breaker.check("admin@corp.com", "change_configuration")
        assert allowed is True


class TestCircuitBreakerState:
    def test_initial_state_is_closed(self, breaker):
        assert breaker.get_state("any-actor") == BreakerState.closed

    def test_state_transitions_to_open_on_trip(self, breaker):
        for _ in range(4):
            breaker.check("admin", "wipe_device")
        assert breaker.get_state("admin") == BreakerState.open

    def test_trip_is_recorded(self, breaker):
        for _ in range(4):
            breaker.check("admin", "wipe_device")

        trips = breaker.get_trips("admin")
        assert len(trips) == 1
        assert trips[0].actor_name == "admin"
        assert trips[0].threshold == 3
        assert trips[0].action_count == 4

    def test_get_trips_filters_by_actor(self, breaker):
        # Trip actor A
        for _ in range(4):
            breaker.check("actor-a", "wipe_device")
        # Trip actor B
        for _ in range(4):
            breaker.check("actor-b", "wipe_device")

        assert len(breaker.get_trips("actor-a")) == 1
        assert len(breaker.get_trips("actor-b")) == 1
        assert len(breaker.get_trips()) == 2


class TestCircuitBreakerReset:
    def test_manual_reset_clears_state(self, breaker):
        # Trip the breaker
        for _ in range(4):
            breaker.check("admin", "wipe_device")
        assert breaker.get_state("admin") == BreakerState.open

        # Reset
        breaker.reset("admin")
        assert breaker.get_state("admin") == BreakerState.closed

        # Should be able to use again
        allowed, _ = breaker.check("admin", "wipe_device")
        assert allowed is True


class TestCircuitBreakerHourlyThreshold:
    def test_hourly_threshold_trips(self):
        """Breaker trips on hourly threshold even if per-minute is not exceeded."""
        config = CircuitBreakerConfig(
            max_destructive_per_minute=100,  # high per-minute so it doesn't trip
            max_destructive_per_hour=5,
            cooldown_seconds=60,
            destructive_actions=["wipe_device"],
        )
        breaker = CircuitBreaker(config)

        # 5 should pass
        for i in range(5):
            allowed, _ = breaker.check("admin", "wipe_device")
            assert allowed is True, f"Action {i+1} should pass"

        # 6th trips the hourly threshold
        allowed, reason = breaker.check("admin", "wipe_device")
        assert allowed is False
        assert "3600s" in reason


class TestCircuitBreakerDefaults:
    def test_default_config_has_device_actions(self):
        """Default config includes Intune-relevant destructive actions."""
        config = CircuitBreakerConfig()
        assert "wipe_device" in config.destructive_actions
        assert "retire_device" in config.destructive_actions
        assert "delete_device" in config.destructive_actions
        assert "destroy_infrastructure" in config.destructive_actions
