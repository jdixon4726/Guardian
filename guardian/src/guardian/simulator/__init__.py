"""
Guardian Simulator — Event Replay Engine

Feeds test incidents (JSON scenario files) through Guardian's full
pipeline without requiring real enterprise systems. Enables testing
of decision graphs, risk scoring, behavioral baselines, drift detection,
circuit breakers, and policies against realistic attack scenarios.

Usage:
    from guardian.simulator import Simulator
    sim = Simulator.from_config()
    report = sim.run_scenario("scenarios/stryker-wiper.json")
    print(report.summary())
"""

from guardian.simulator.engine import Simulator, SimulationReport

__all__ = ["Simulator", "SimulationReport"]
