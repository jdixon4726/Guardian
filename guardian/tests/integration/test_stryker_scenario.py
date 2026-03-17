"""
Stryker Scenario Integration Test

Simulates the March 2026 Stryker attack: a compromised admin account
issues mass remote wipe commands through Intune. Verifies that Guardian's
circuit breaker and behavioral pipeline catch and stop the attack.

This test proves:
  1. Circuit breaker trips after threshold (e.g., 6th wipe in 1 minute)
  2. Individual wipe actions score high risk (destructive + restricted)
  3. The combination of circuit breaker + pipeline would have stopped
     the attack at device #6 instead of device #200,000
"""

from __future__ import annotations

import pytest

from guardian.adapters.intune.mapper import IntuneActionMapper
from guardian.adapters.intune.models import IntuneDeviceAction
from guardian.circuit_breaker.breaker import CircuitBreaker, CircuitBreakerConfig
from guardian.models.action_request import ActorType, PrivilegeLevel, SensitivityLevel


@pytest.fixture
def stryker_breaker():
    """Circuit breaker configured like a production Intune deployment."""
    return CircuitBreaker(CircuitBreakerConfig(
        max_destructive_per_minute=5,
        max_destructive_per_hour=20,
        cooldown_seconds=300,
        destructive_actions=[
            "wipe_device", "retire_device", "delete_device",
            "destroy_infrastructure", "delete_resource",
        ],
    ))


@pytest.fixture
def mapper():
    return IntuneActionMapper()


class TestStrykerScenario:
    """
    Simulates the Stryker attack: compromised Global Admin issues
    200,000 remote wipe commands via Intune.
    """

    def test_mass_wipe_triggers_circuit_breaker(self, stryker_breaker):
        """
        The Stryker attacker wiped 200k devices. With Guardian's circuit
        breaker (threshold: 5/min), the attack stops at device #6.
        """
        attacker = "intune-stryker-tenant-compromised-admin@stryker.com"

        allowed_count = 0
        blocked_count = 0
        trip_reason = None

        # Simulate 200 wipe attempts (representing the 200k in reality)
        for i in range(200):
            allowed, reason = stryker_breaker.check(attacker, "wipe_device")
            if allowed:
                allowed_count += 1
            else:
                blocked_count += 1
                if trip_reason is None:
                    trip_reason = reason

        # Only 5 should have gotten through (threshold is 5)
        assert allowed_count == 5
        assert blocked_count == 195
        assert "TRIPPED" in trip_reason or "OPEN" in trip_reason

    def test_wipe_actions_score_as_destructive(self, mapper):
        """Each wipe action individually maps to highest-risk categories."""
        action = IntuneDeviceAction(
            device_id=f"device-001",
            action="wipe",
            device_name="CORP-LAPTOP-001",
            operating_system="Windows",
        )
        request = mapper.map_action(
            action, actor_name="compromised-admin@stryker.com",
        )

        # Wipe should be the most sensitive/privileged action type
        assert request.requested_action == "wipe_device"
        assert request.sensitivity_level == SensitivityLevel.restricted
        assert request.privilege_level == PrivilegeLevel.admin
        assert "IRREVERSIBLE" in request.business_context

    def test_different_destructive_actions_all_count(self, stryker_breaker):
        """Mixed destructive actions (wipe + retire + delete) all count toward threshold."""
        attacker = "intune-stryker-compromised@stryker.com"

        # 2 wipes
        stryker_breaker.check(attacker, "wipe_device")
        stryker_breaker.check(attacker, "wipe_device")
        # 2 retires
        stryker_breaker.check(attacker, "retire_device")
        stryker_breaker.check(attacker, "retire_device")
        # 1 delete (total = 5, at threshold)
        allowed, _ = stryker_breaker.check(attacker, "delete_device")
        assert allowed is True

        # 6th destructive action trips it
        allowed, reason = stryker_breaker.check(attacker, "wipe_device")
        assert allowed is False

    def test_legitimate_admin_not_affected(self, stryker_breaker):
        """A legitimate admin doing a single wipe is unaffected by the breaker."""
        legit_admin = "intune-stryker-legit-admin@stryker.com"

        allowed, reason = stryker_breaker.check(legit_admin, "wipe_device")
        assert allowed is True
        assert reason is None

    def test_attacker_blocked_but_other_admins_unaffected(self, stryker_breaker):
        """Breaker is per-actor: attacker is blocked, legitimate admins work fine."""
        attacker = "intune-compromised@stryker.com"
        legit = "intune-real-admin@stryker.com"

        # Trip attacker's breaker
        for _ in range(10):
            stryker_breaker.check(attacker, "wipe_device")

        # Attacker is blocked
        allowed, _ = stryker_breaker.check(attacker, "wipe_device")
        assert allowed is False

        # Legitimate admin is fine
        allowed, _ = stryker_breaker.check(legit, "wipe_device")
        assert allowed is True

    def test_non_destructive_actions_pass_during_lockout(self, stryker_breaker):
        """Even when breaker is tripped, non-destructive actions pass."""
        attacker = "intune-compromised@stryker.com"

        # Trip the breaker
        for _ in range(10):
            stryker_breaker.check(attacker, "wipe_device")

        # Destructive = blocked
        allowed, _ = stryker_breaker.check(attacker, "wipe_device")
        assert allowed is False

        # Non-destructive = passes (e.g., reading device info)
        allowed, _ = stryker_breaker.check(attacker, "change_configuration")
        assert allowed is True

    def test_mass_scale_performance(self, stryker_breaker):
        """
        Simulate checking 10,000 actions to verify performance.
        Circuit breaker must be fast enough to not add latency.
        """
        import time
        attacker = "intune-perf-test@stryker.com"

        start = time.monotonic()
        for i in range(10_000):
            stryker_breaker.check(attacker, "wipe_device")
        elapsed = time.monotonic() - start

        # 10k checks should complete in well under 1 second
        assert elapsed < 1.0, f"10k breaker checks took {elapsed:.2f}s (too slow)"

    def test_200k_wipe_blast_radius(self, stryker_breaker, mapper):
        """
        End-to-end: map 200 device wipes and check circuit breaker.
        Proves the full adapter path catches mass-action attacks.
        """
        attacker = "intune-stryker-compromised-admin@stryker.com"

        allowed_devices = []
        for i in range(200):
            device = IntuneDeviceAction(
                device_id=f"device-{i:06d}",
                action="wipe",
                device_name=f"STRYKER-LAPTOP-{i:06d}",
                operating_system="Windows",
            )
            request = mapper.map_action(device, actor_name=attacker)

            # Check circuit breaker with the mapped Guardian action
            cb_allowed, _ = stryker_breaker.check(attacker, request.requested_action)
            if cb_allowed:
                allowed_devices.append(device.device_id)

        # Only 5 devices should have been wiped
        assert len(allowed_devices) == 5
        assert allowed_devices == [f"device-{i:06d}" for i in range(5)]
