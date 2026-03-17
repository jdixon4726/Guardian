"""
Integration tests for the Guardian Simulator — Event Replay Engine.

Runs all three scenario files through the full pipeline and validates
that Guardian correctly identifies and stops each attack.
"""

from __future__ import annotations

from pathlib import Path

import pytest

from guardian.simulator import Simulator

SCENARIOS_DIR = Path(__file__).parent.parent.parent / "scenarios"


@pytest.fixture(scope="module")
def simulator():
    """Build a simulator with standard config."""
    return Simulator.from_config()


class TestStrykerScenario:
    def test_stryker_scenario_loads_and_runs(self, simulator):
        report = simulator.run_scenario(SCENARIOS_DIR / "stryker-wiper.json")
        print(report.summary())

        assert report.total_events > 0
        assert report.blocked_count > 0

    def test_stryker_unknown_attacker_blocked(self, simulator):
        report = simulator.run_scenario(SCENARIOS_DIR / "stryker-wiper.json")

        # All events from the rogue admin should be blocked
        rogue_events = [r for r in report.results if "rogue" in r.actor_name]
        assert all(r.decision == "block" for r in rogue_events), (
            f"Rogue admin events not all blocked: "
            f"{[(r.event_id, r.decision) for r in rogue_events]}"
        )

    def test_stryker_circuit_breaker_trips(self, simulator):
        report = simulator.run_scenario(SCENARIOS_DIR / "stryker-wiper.json")
        assert report.circuit_breaker_trips > 0, "Circuit breaker should trip during mass wipe"

    def test_stryker_all_expectations_met(self, simulator):
        report = simulator.run_scenario(SCENARIOS_DIR / "stryker-wiper.json")
        if not report.all_expectations_met:
            failures = [r for r in report.results if not r.expectation_met]
            details = "\n".join(f"  {r.event_id}: {r.expectation_details}" for r in failures)
            pytest.fail(f"Expectations not met:\n{details}")


class TestGitHubSupplyChainScenario:
    def test_github_scenario_loads_and_runs(self, simulator):
        report = simulator.run_scenario(SCENARIOS_DIR / "github-supply-chain.json")
        print(report.summary())

        assert report.total_events > 0

    def test_github_attacker_deploy_blocked(self, simulator):
        report = simulator.run_scenario(SCENARIOS_DIR / "github-supply-chain.json")

        # Events from compromised-maintainer should be blocked
        attacker_events = [r for r in report.results if "compromised" in r.actor_name]
        assert all(r.decision in ("block", "require_review") for r in attacker_events), (
            f"Attacker events not blocked: "
            f"{[(r.event_id, r.decision) for r in attacker_events]}"
        )

    def test_github_all_expectations_met(self, simulator):
        report = simulator.run_scenario(SCENARIOS_DIR / "github-supply-chain.json")
        if not report.all_expectations_met:
            failures = [r for r in report.results if not r.expectation_met]
            details = "\n".join(f"  {r.event_id}: {r.expectation_details}" for r in failures)
            pytest.fail(f"Expectations not met:\n{details}")


class TestAWSCredentialCompromiseScenario:
    def test_aws_scenario_loads_and_runs(self, simulator):
        report = simulator.run_scenario(SCENARIOS_DIR / "aws-credential-compromise.json")
        print(report.summary())

        assert report.total_events > 0

    def test_aws_attack_events_flagged(self, simulator):
        report = simulator.run_scenario(SCENARIOS_DIR / "aws-credential-compromise.json")

        # All attack phase events should be high risk
        attack_events = [r for r in report.results
                         if r.phase in ("persistence", "privilege_escalation",
                                        "defense_evasion", "destruction")]
        assert len(attack_events) > 0, "Should have attack events"
        for event in attack_events:
            assert event.risk_score >= 0.4, (
                f"Attack event {event.event_id} risk too low: {event.risk_score}"
            )

    def test_aws_circuit_breaker_trips_during_destruction(self, simulator):
        report = simulator.run_scenario(SCENARIOS_DIR / "aws-credential-compromise.json")
        assert report.circuit_breaker_trips > 0, "CB should trip during destruction phase"

    def test_aws_all_expectations_met(self, simulator):
        report = simulator.run_scenario(SCENARIOS_DIR / "aws-credential-compromise.json")
        if not report.all_expectations_met:
            failures = [r for r in report.results if not r.expectation_met]
            details = "\n".join(f"  {r.event_id}: {r.expectation_details}" for r in failures)
            pytest.fail(f"Expectations not met:\n{details}")


class TestSimulatorReport:
    def test_report_summary_format(self, simulator):
        report = simulator.run_scenario(SCENARIOS_DIR / "stryker-wiper.json")
        summary = report.summary()

        assert "SIMULATION:" in summary
        assert "Total events:" in summary
        assert "BY PHASE:" in summary
        assert "EVENT LOG:" in summary

    def test_report_by_phase(self, simulator):
        report = simulator.run_scenario(SCENARIOS_DIR / "stryker-wiper.json")
        phases = report.by_phase()

        assert len(phases) > 0
        assert any("baseline" in p for p in phases)
