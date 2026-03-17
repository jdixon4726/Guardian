"""
Guardian Simulator Engine

Loads scenario JSON files and replays events through the full Guardian
pipeline. Supports all adapter types, circuit breaker, and validation
of expected outcomes.
"""

from __future__ import annotations

import json
import logging
from datetime import datetime, timezone
from pathlib import Path

from guardian.adapters.aws_eventbridge.mapper import CloudTrailMapper
from guardian.adapters.aws_eventbridge.models import CloudTrailEvent
from guardian.adapters.entra_id.mapper import EntraAdminMapper
from guardian.adapters.entra_id.models import EntraAdminAction
from guardian.adapters.intune.mapper import IntuneActionMapper
from guardian.adapters.intune.models import IntuneDeviceAction
from guardian.adapters.jamf.mapper import JamfCommandMapper
from guardian.adapters.jamf.models import JamfDeviceCommand
from guardian.adapters.github_actions.mapper import GitHubDeploymentMapper
from guardian.adapters.github_actions.models import GitHubDeploymentRequest
from guardian.attestation.attestor import ActorRegistry
from guardian.audit.logger import AuditLogger
from guardian.circuit_breaker.breaker import CircuitBreaker, CircuitBreakerConfig
from guardian.drift.alerts import AlertPublisher
from guardian.drift.baseline import BaselineStore
from guardian.enrichment.context import AssetCatalog, MaintenanceWindowStore
from guardian.models.action_request import (
    ActionRequest,
    ActorType,
    DecisionOutcome,
    PrivilegeLevel,
    SensitivityLevel,
)
from guardian.pipeline import GuardianPipeline
from guardian.policy.engine import PolicyEngine
from guardian.policy.loaders import PolicyLoader
from guardian.simulator.models import (
    AdapterType,
    EventResult,
    Scenario,
    ScenarioEvent,
    ScenarioMetadata,
)

logger = logging.getLogger(__name__)

ROOT = Path(__file__).parent.parent.parent.parent  # src/guardian/simulator -> src/guardian -> src -> project root
CONFIG = ROOT / "config"
POLICIES = ROOT / "policies"


class SimulationReport:
    """Aggregated results from a simulation run."""

    def __init__(self, scenario: Scenario, results: list[EventResult]):
        self.scenario = scenario
        self.results = results

    @property
    def total_events(self) -> int:
        return len(self.results)

    @property
    def allowed_count(self) -> int:
        return sum(1 for r in self.results if r.decision in ("allow", "allow_with_logging"))

    @property
    def blocked_count(self) -> int:
        return sum(1 for r in self.results if r.decision == "block")

    @property
    def review_count(self) -> int:
        return sum(1 for r in self.results if r.decision == "require_review")

    @property
    def circuit_breaker_trips(self) -> int:
        return sum(1 for r in self.results if r.circuit_breaker_tripped)

    @property
    def expectations_met(self) -> int:
        return sum(1 for r in self.results if r.expectation_met)

    @property
    def expectations_failed(self) -> int:
        return sum(1 for r in self.results if not r.expectation_met)

    @property
    def all_expectations_met(self) -> bool:
        return all(r.expectation_met for r in self.results)

    def by_phase(self) -> dict[str, list[EventResult]]:
        phases: dict[str, list[EventResult]] = {}
        for r in self.results:
            phase = r.phase or "unphased"
            phases.setdefault(phase, []).append(r)
        return phases

    def summary(self) -> str:
        lines = [
            f"{'='*70}",
            f"  SIMULATION: {self.scenario.metadata.name}",
            f"  {self.scenario.metadata.description}",
            f"{'='*70}",
            f"  Total events:         {self.total_events}",
            f"  Allowed:              {self.allowed_count}",
            f"  Blocked:              {self.blocked_count}",
            f"  Require review:       {self.review_count}",
            f"  Circuit breaker trips: {self.circuit_breaker_trips}",
            f"  Expectations met:     {self.expectations_met}/{self.total_events}",
        ]

        if self.expectations_failed:
            lines.append(f"\n  FAILED EXPECTATIONS:")
            for r in self.results:
                if not r.expectation_met:
                    lines.append(f"    [{r.event_id}] {r.expectation_details}")

        lines.append(f"\n  BY PHASE:")
        for phase, events in self.by_phase().items():
            allowed = sum(1 for e in events if e.decision in ("allow", "allow_with_logging"))
            blocked = sum(1 for e in events if e.decision in ("block", "require_review"))
            lines.append(f"    {phase:30s} {len(events):3d} events | {allowed} allowed | {blocked} blocked")

        lines.append(f"\n  EVENT LOG:")
        for r in self.results:
            status = "ALLOW" if r.decision in ("allow", "allow_with_logging") else "BLOCK"
            src = "CB" if r.circuit_breaker_tripped else "PIPE"
            check = "+" if r.expectation_met else "X"
            lines.append(
                f"    [{check}] {r.event_id:20s} {r.phase:15s} "
                f"{status:5s} ({src:4s}) risk={r.risk_score:.3f} "
                f"| {r.description[:40]}"
            )

        lines.append(f"{'='*70}")
        return "\n".join(lines)


class Simulator:
    """
    Event replay engine for Guardian.

    Loads scenario files, builds a pipeline with scenario-specific
    configuration, and replays events through the full stack.
    """

    def __init__(
        self,
        pipeline: GuardianPipeline,
        circuit_breaker: CircuitBreaker | None = None,
        actor_registry: ActorRegistry | None = None,
    ):
        self.pipeline = pipeline
        self.circuit_breaker = circuit_breaker
        self.actor_registry = actor_registry
        # Mappers for each adapter type
        self._intune_mapper = IntuneActionMapper()
        self._entra_mapper = EntraAdminMapper()
        self._jamf_mapper = JamfCommandMapper()
        self._github_mapper = GitHubDeploymentMapper()
        self._aws_mapper = CloudTrailMapper()

    @classmethod
    def from_config(
        cls,
        config_dir: Path | None = None,
        policies_dir: Path | None = None,
        cb_config: CircuitBreakerConfig | None = None,
    ) -> "Simulator":
        """Build a simulator with standard Guardian configuration."""
        cfg = config_dir or CONFIG
        pol = policies_dir or POLICIES

        actor_registry = ActorRegistry(cfg / "actor-registry.yaml")
        asset_catalog = AssetCatalog(cfg / "asset-catalog.yaml")
        window_store = MaintenanceWindowStore(cfg / "maintenance-windows.yaml")

        loader = PolicyLoader(pol)
        deny_rules, conditional_rules, allow_rules = loader.load_all()
        policy_engine = PolicyEngine(deny_rules, conditional_rules, allow_rules)

        import tempfile
        audit_path = Path(tempfile.mktemp(suffix="-guardian-sim-audit.jsonl"))
        audit_logger = AuditLogger(audit_path)
        baseline_store = BaselineStore(":memory:")
        alert_publisher = AlertPublisher()

        pipeline = GuardianPipeline(
            actor_registry=actor_registry,
            asset_catalog=asset_catalog,
            window_store=window_store,
            policy_engine=policy_engine,
            audit_logger=audit_logger,
            baseline_store=baseline_store,
            alert_publisher=alert_publisher,
        )

        cb = CircuitBreaker(cb_config or CircuitBreakerConfig())

        return cls(pipeline=pipeline, circuit_breaker=cb, actor_registry=actor_registry)

    def run_scenario(self, scenario_path: str | Path) -> SimulationReport:
        """Load and run a scenario file."""
        path = Path(scenario_path)
        with open(path) as f:
            data = json.load(f)

        scenario = Scenario(**data)
        return self.run(scenario)

    def run(self, scenario: Scenario) -> SimulationReport:
        """Run a scenario object through the pipeline."""
        # Register scenario-specific actors
        if scenario.metadata.register_actors and self.actor_registry:
            for actor in scenario.metadata.register_actors:
                self.actor_registry._actors[actor["name"]] = actor

        # Configure circuit breaker from scenario
        if scenario.metadata.circuit_breaker_enabled and self.circuit_breaker:
            self.circuit_breaker.config.max_destructive_per_minute = (
                scenario.metadata.circuit_breaker_max_per_minute
            )
            self.circuit_breaker.config.max_destructive_per_hour = (
                scenario.metadata.circuit_breaker_max_per_hour
            )

        results = []
        for event in scenario.events:
            result = self._evaluate_event(event)
            results.append(result)

        return SimulationReport(scenario, results)

    def _evaluate_event(self, event: ScenarioEvent) -> EventResult:
        """Evaluate a single scenario event."""
        try:
            # Map to ActionRequest based on adapter type
            action_request = self._map_event(event)

            # Circuit breaker check
            cb_tripped = False
            cb_reason = None
            if self.circuit_breaker:
                cb_allowed, cb_reason = self.circuit_breaker.check(
                    action_request.actor_name,
                    action_request.requested_action,
                )
                if not cb_allowed:
                    cb_tripped = True
                    result = EventResult(
                        event_id=event.id,
                        phase=event.phase,
                        description=event.description,
                        adapter=event.adapter.value,
                        actor_name=action_request.actor_name,
                        action=action_request.requested_action,
                        decision="block",
                        risk_score=1.0,
                        explanation=cb_reason or "Circuit breaker tripped",
                        circuit_breaker_tripped=True,
                    )
                    self._validate_expectations(event, result)
                    return result

            # Full pipeline evaluation
            decision = self.pipeline.evaluate(action_request)

            result = EventResult(
                event_id=event.id,
                phase=event.phase,
                description=event.description,
                adapter=event.adapter.value,
                actor_name=action_request.actor_name,
                action=action_request.requested_action,
                decision=decision.decision.value,
                risk_score=decision.risk_score,
                drift_score=decision.drift_score.score if decision.drift_score else None,
                explanation=decision.explanation,
                entry_id=decision.entry_id,
                quarantine_recommended=(
                    event.adapter == AdapterType.aws
                    and decision.decision in (DecisionOutcome.block, DecisionOutcome.require_review)
                    and self._aws_mapper.should_quarantine(
                        CloudTrailEvent(**event.payload)
                    ) if event.adapter == AdapterType.aws else False
                ),
            )
            self._validate_expectations(event, result)
            return result

        except Exception as exc:
            result = EventResult(
                event_id=event.id,
                phase=event.phase,
                description=event.description,
                adapter=event.adapter.value,
                decision="block",
                risk_score=1.0,
                explanation=f"Simulation error: {exc}",
            )
            self._validate_expectations(event, result)
            return result

    def _map_event(self, event: ScenarioEvent) -> ActionRequest:
        """Map a scenario event to a Guardian ActionRequest."""
        payload = event.payload
        ts = event.timestamp

        if event.adapter == AdapterType.direct:
            # Raw ActionRequest payload
            if ts and "timestamp" not in payload:
                payload["timestamp"] = ts
            if "timestamp" not in payload:
                payload["timestamp"] = datetime.now(timezone.utc).isoformat()
            return ActionRequest(**payload)

        elif event.adapter == AdapterType.intune:
            device = IntuneDeviceAction(**payload)
            actor = payload.get("actor_name", "unknown-intune-actor")
            request = self._intune_mapper.map_action(device, actor_name=actor)
            if ts:
                request = ActionRequest(**{**request.model_dump(), "timestamp": ts})
            return request

        elif event.adapter == AdapterType.entra_id:
            action = EntraAdminAction(**{k: v for k, v in payload.items() if k != "actor_name"})
            actor = payload.get("actor_name", "unknown-entra-actor")
            request = self._entra_mapper.map_action(action, actor_name=actor)
            if ts:
                request = ActionRequest(**{**request.model_dump(), "timestamp": ts})
            return request

        elif event.adapter == AdapterType.jamf:
            cmd = JamfDeviceCommand(**{k: v for k, v in payload.items() if k != "actor_name"})
            actor = payload.get("actor_name", "unknown-jamf-admin")
            request = self._jamf_mapper.map_command(cmd, actor_name=actor)
            if ts:
                request = ActionRequest(**{**request.model_dump(), "timestamp": ts})
            return request

        elif event.adapter == AdapterType.github:
            deployment = GitHubDeploymentRequest(**payload)
            request = self._github_mapper.map_deployment(deployment)
            if ts:
                request = ActionRequest(**{**request.model_dump(), "timestamp": ts})
            return request

        elif event.adapter == AdapterType.aws:
            ct_event = CloudTrailEvent(**payload)
            request = self._aws_mapper.map_event(ct_event)
            return request

        else:
            raise ValueError(f"Unknown adapter type: {event.adapter}")

    def _validate_expectations(self, event: ScenarioEvent, result: EventResult) -> None:
        """Validate result against scenario expectations."""
        failures = []

        if event.expect_decision and result.decision != event.expect_decision:
            failures.append(
                f"Expected decision={event.expect_decision}, got {result.decision}"
            )

        if result.risk_score < event.expect_risk_min:
            failures.append(
                f"Risk {result.risk_score:.3f} < expected min {event.expect_risk_min}"
            )

        if result.risk_score > event.expect_risk_max:
            failures.append(
                f"Risk {result.risk_score:.3f} > expected max {event.expect_risk_max}"
            )

        if event.expect_circuit_breaker is not None:
            if result.circuit_breaker_tripped != event.expect_circuit_breaker:
                failures.append(
                    f"Expected CB tripped={event.expect_circuit_breaker}, "
                    f"got {result.circuit_breaker_tripped}"
                )

        result.expectation_met = len(failures) == 0
        result.expectation_details = "; ".join(failures) if failures else "OK"
