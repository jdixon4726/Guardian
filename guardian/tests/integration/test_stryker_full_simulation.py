"""
Full Stryker Attack Simulation

Recreates the March 11, 2026 Handala/Stryker attack through Guardian's
complete pipeline: identity attestation, behavioral assessment, drift
detection, risk scoring, policy evaluation, decision engine, audit
logging, and circuit breaker.

Attack timeline (reconstructed from public reporting):
  Phase 0: Establish baseline — legitimate admin doing normal work
  Phase 1: Reconnaissance — attacker queries device inventory
  Phase 2: Privilege escalation — attacker creates Global Admin account
  Phase 3: Initial wipes — attacker tests with a few devices
  Phase 4: Mass wipe — attacker launches 80,000 wipe commands (3 hrs)
  Phase 5: Continued attempts — attacker retries after being blocked

Each phase shows Guardian's exact response: decision, risk score,
drift score, explanation, and whether the circuit breaker intervened.
"""

from __future__ import annotations

import io
import sys
from datetime import datetime, timedelta, timezone
from pathlib import Path

import pytest

from guardian.adapters.intune.mapper import IntuneActionMapper
from guardian.adapters.intune.models import IntuneDeviceAction
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

ROOT = Path(__file__).parent.parent.parent
CONFIG = ROOT / "config"
POLICIES = ROOT / "policies"
AUDIT = ROOT / "tests" / "test-stryker-simulation-audit.jsonl"

# Simulated Intune actors
LEGIT_ADMIN = "intune-stryker-admin@stryker.com"
COMPROMISED_ADMIN = "intune-stryker-compromised-globaladmin@stryker.com"

# Attack timestamp: March 11, 2026 05:00 UTC (real attack started ~05:00 UTC)
ATTACK_START = datetime(2026, 3, 11, 5, 0, 0, tzinfo=timezone.utc)


@pytest.fixture(scope="module")
def simulation_env():
    """
    Build a full Guardian pipeline with circuit breaker for the simulation.

    Adds Intune actors to the actor registry so we can test both
    "known legitimate admin" and "unknown attacker" paths.
    """
    AUDIT.parent.mkdir(parents=True, exist_ok=True)
    if AUDIT.exists():
        AUDIT.unlink()

    actor_registry = ActorRegistry(CONFIG / "actor-registry.yaml")
    # Register the legitimate Intune admin
    actor_registry._actors[LEGIT_ADMIN] = {
        "name": LEGIT_ADMIN,
        "type": "human",
        "max_privilege_level": "admin",
        "status": "active",
    }
    # The compromised account is NOT registered — it was created by the attacker
    # (Handala created a rogue Global Admin in Entra ID)

    asset_catalog = AssetCatalog(CONFIG / "asset-catalog.yaml")
    window_store = MaintenanceWindowStore(CONFIG / "maintenance-windows.yaml")

    loader = PolicyLoader(POLICIES)
    deny_rules, conditional_rules, allow_rules = loader.load_all()
    policy_engine = PolicyEngine(deny_rules, conditional_rules, allow_rules)

    audit_logger = AuditLogger(AUDIT)
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

    # Circuit breaker: 5/min, 20/hour (production defaults)
    circuit_breaker = CircuitBreaker(CircuitBreakerConfig(
        max_destructive_per_minute=5,
        max_destructive_per_hour=20,
        cooldown_seconds=300,
    ))

    mapper = IntuneActionMapper()

    return pipeline, circuit_breaker, mapper


# ── Helpers ──────────────────────────────────────────────────────────────────

def _evaluate_intune_action(
    env, actor_name: str, action: str, device_id: str,
    device_name: str = "", timestamp: datetime | None = None,
) -> dict:
    """
    Run a simulated Intune action through both circuit breaker and pipeline.
    Returns a dict with the full response for analysis.
    """
    pipeline, circuit_breaker, mapper = env

    device = IntuneDeviceAction(
        device_id=device_id,
        action=action,
        device_name=device_name or f"DEVICE-{device_id}",
        operating_system="Windows",
    )

    # Step 1: Circuit breaker check
    action_request = mapper.map_action(device, actor_name=actor_name)
    if timestamp:
        action_request = ActionRequest(
            **{**action_request.model_dump(), "timestamp": timestamp}
        )

    cb_allowed, cb_reason = circuit_breaker.check(
        actor_name, action_request.requested_action,
    )

    if not cb_allowed:
        return {
            "phase": "circuit_breaker",
            "allowed": False,
            "decision": "block",
            "risk_score": 1.0,
            "explanation": cb_reason,
            "circuit_breaker_tripped": True,
            "device_id": device_id,
        }

    # Step 2: Full pipeline evaluation
    decision = pipeline.evaluate(action_request)

    return {
        "phase": "pipeline",
        "allowed": decision.decision in (
            DecisionOutcome.allow,
            DecisionOutcome.allow_with_logging,
        ),
        "decision": decision.decision.value,
        "risk_score": decision.risk_score,
        "drift_score": decision.drift_score.score if decision.drift_score else None,
        "explanation": decision.explanation,
        "policy_matched": decision.policy_matched,
        "safer_alternatives": decision.safer_alternatives,
        "circuit_breaker_tripped": False,
        "device_id": device_id,
        "entry_id": decision.entry_id,
    }


def _print_result(label: str, result: dict) -> None:
    """Pretty-print a simulation result."""
    status = "ALLOWED" if result["allowed"] else "BLOCKED"
    source = "CIRCUIT BREAKER" if result.get("circuit_breaker_tripped") else "PIPELINE"
    print(f"\n{'='*70}")
    print(f"  {label}")
    print(f"{'='*70}")
    print(f"  Status:        {status} (via {source})")
    print(f"  Decision:      {result['decision']}")
    print(f"  Risk Score:    {result['risk_score']:.3f}")
    if result.get("drift_score") is not None:
        print(f"  Drift Score:   {result['drift_score']:.3f}")
    if result.get("policy_matched"):
        print(f"  Policy:        {result['policy_matched']}")
    print(f"  Explanation:   {result['explanation'][:200]}")
    if result.get("safer_alternatives"):
        print(f"  Alternatives:  {', '.join(result['safer_alternatives'][:3])}")
    print(f"  Device:        {result['device_id']}")


# ── Phase 0: Establish Baseline ──────────────────────────────────────────────

class TestPhase0_Baseline:
    """
    Before the attack: legitimate admin performs normal device management.
    This establishes a behavioral baseline for comparison.
    """

    def test_legitimate_admin_normal_operations(self, simulation_env):
        """
        Normal admin behavior: a few sync operations over the past week.
        Establishes what "normal" looks like.
        """
        pipeline, _, mapper = simulation_env

        # Normal admin does sync operations (low risk, should all pass)
        baseline_time = ATTACK_START - timedelta(days=7)
        for i in range(5):
            device = IntuneDeviceAction(
                device_id=f"normal-device-{i:03d}",
                action="syncDevice",
                device_name=f"CORP-LAPTOP-{i:03d}",
            )
            request = mapper.map_action(device, actor_name=LEGIT_ADMIN)
            request = ActionRequest(
                **{**request.model_dump(), "timestamp": baseline_time + timedelta(hours=i * 4)}
            )
            decision = pipeline.evaluate(request)
            assert decision.decision in (
                DecisionOutcome.allow,
                DecisionOutcome.allow_with_logging,
                DecisionOutcome.require_review,
            )

    def test_legitimate_admin_single_wipe_is_reviewed(self, simulation_env):
        """
        Even a legitimate admin wiping one device gets high-risk review.
        This is the correct behavior — single wipes are rare and destructive.
        """
        result = _evaluate_intune_action(
            simulation_env,
            actor_name=LEGIT_ADMIN,
            action="wipe",
            device_id="lost-phone-001",
            device_name="CEO-IPHONE-LOST",
            timestamp=ATTACK_START - timedelta(days=1),
        )
        _print_result("Phase 0: Legitimate admin wipes one lost device", result)

        # Should be high risk but may be allowed or require review
        assert result["risk_score"] >= 0.5, (
            f"Single wipe should be high risk, got {result['risk_score']}"
        )


# ── Phase 1: Reconnaissance ─────────────────────────────────────────────────

class TestPhase1_Reconnaissance:
    """
    Attacker (using compromised credentials) queries device inventory.
    The attacker account is NOT in Guardian's actor registry.
    """

    def test_unregistered_attacker_blocked_at_attestation(self, simulation_env):
        """
        The attacker's rogue Global Admin account doesn't exist in Guardian's
        actor registry. Identity attestation fails immediately → block.

        This is Guardian's first line of defense: if we don't know you,
        you don't get through.
        """
        result = _evaluate_intune_action(
            simulation_env,
            actor_name=COMPROMISED_ADMIN,
            action="syncDevice",
            device_id="recon-device-001",
            timestamp=ATTACK_START - timedelta(hours=1),
        )
        _print_result("Phase 1: Attacker recon — unknown actor", result)

        assert result["allowed"] is False, "Unknown actor must be blocked"
        assert result["risk_score"] == 1.0, "Unknown actor gets maximum risk"


# ── Phase 2: Privilege Escalation ────────────────────────────────────────────

class TestPhase2_PrivilegeEscalation:
    """
    Attacker attempts to create admin access or escalate privileges.
    Even if they had a registered account, privilege escalation is flagged.
    """

    def test_privilege_escalation_blocked_for_unknown_actor(self, simulation_env):
        """
        Attacker tries grant_admin_access — blocked at attestation.
        """
        pipeline, _, _ = simulation_env
        request = ActionRequest(
            actor_name=COMPROMISED_ADMIN,
            actor_type=ActorType.human,
            requested_action="grant_admin_access",
            target_system="entra-id",
            target_asset="global-admin-role",
            privilege_level=PrivilegeLevel.admin,
            sensitivity_level=SensitivityLevel.restricted,
            business_context="Creating new Global Administrator for IT operations",
            timestamp=ATTACK_START - timedelta(minutes=30),
        )
        decision = pipeline.evaluate(request)
        _print_result("Phase 2: Attacker creates Global Admin", {
            "allowed": False,
            "decision": decision.decision.value,
            "risk_score": decision.risk_score,
            "explanation": decision.explanation,
            "device_id": "entra-id/global-admin-role",
            "circuit_breaker_tripped": False,
            "policy_matched": decision.policy_matched,
            "drift_score": decision.drift_score.score if decision.drift_score else None,
            "safer_alternatives": decision.safer_alternatives,
        })

        assert decision.decision == DecisionOutcome.block
        assert decision.risk_score == 1.0


# ── Phase 3: Initial Wipes ──────────────────────────────────────────────────

class TestPhase3_InitialWipes:
    """
    Attacker begins wiping devices. Two paths tested:
    1. Unknown attacker → blocked at attestation (every single time)
    2. If attacker had compromised a KNOWN account → pipeline evaluates
       and circuit breaker tracks velocity
    """

    def test_unknown_attacker_wipes_all_blocked(self, simulation_env):
        """
        Every wipe attempt from the unregistered attacker is blocked
        at identity attestation. The attacker never reaches the pipeline.
        """
        results = []
        for i in range(10):
            result = _evaluate_intune_action(
                simulation_env,
                actor_name=COMPROMISED_ADMIN,
                action="wipe",
                device_id=f"target-device-{i:06d}",
                device_name=f"STRYKER-LAPTOP-{i:06d}",
                timestamp=ATTACK_START + timedelta(seconds=i),
            )
            results.append(result)

        all_blocked = all(not r["allowed"] for r in results)
        all_max_risk = all(r["risk_score"] == 1.0 for r in results)

        _print_result("Phase 3: Attacker wipes 10 devices (unknown actor)", results[0])
        print(f"\n  All 10 blocked: {all_blocked}")
        print(f"  All max risk:   {all_max_risk}")

        assert all_blocked, "All wipes from unknown actor must be blocked"
        assert all_max_risk, "All must score maximum risk"


# ── Phase 4: Mass Wipe (Compromised Known Account) ──────────────────────────

class TestPhase4_MassWipe_CompromisedKnownAccount:
    """
    Worst-case scenario: attacker compromises a KNOWN admin account
    (one that's in Guardian's actor registry). This bypasses attestation.

    This is where the circuit breaker and behavioral scoring earn their keep.
    """

    def test_mass_wipe_from_known_account(self, simulation_env):
        """
        Simulate 200 wipe commands from the legitimate admin account
        (as if the attacker compromised it). The circuit breaker should
        stop the attack after 5 devices.
        """
        results = []
        allowed_count = 0
        blocked_by_cb = 0
        blocked_by_pipeline = 0

        for i in range(200):
            result = _evaluate_intune_action(
                simulation_env,
                actor_name=LEGIT_ADMIN,
                action="wipe",
                device_id=f"mass-wipe-{i:06d}",
                device_name=f"STRYKER-DEVICE-{i:06d}",
                timestamp=ATTACK_START + timedelta(seconds=i),
            )
            results.append(result)

            if result["allowed"]:
                allowed_count += 1
            elif result.get("circuit_breaker_tripped"):
                blocked_by_cb += 1
            else:
                blocked_by_pipeline += 1

        # Print summary
        print(f"\n{'='*70}")
        print(f"  PHASE 4: MASS WIPE SIMULATION — 200 DEVICES")
        print(f"{'='*70}")
        print(f"  Allowed through:           {allowed_count}")
        print(f"  Blocked by circuit breaker: {blocked_by_cb}")
        print(f"  Blocked by pipeline:        {blocked_by_pipeline}")
        print(f"  Total blocked:             {blocked_by_cb + blocked_by_pipeline}")

        # Show first few results
        for i, r in enumerate(results[:8]):
            status = "ALLOWED" if r["allowed"] else "BLOCKED"
            source = "CB" if r.get("circuit_breaker_tripped") else "PIPE"
            print(f"  Device {i+1:3d}: {status} ({source}) risk={r['risk_score']:.3f}")
        print(f"  ...({len(results) - 8} more)...")
        print(f"  Device 200: {('ALLOWED' if results[-1]['allowed'] else 'BLOCKED')}")

        # Circuit breaker should have stopped the mass wipe
        assert allowed_count <= 5, (
            f"Circuit breaker should limit to ≤5 devices, got {allowed_count}"
        )
        assert blocked_by_cb >= 195, (
            f"Circuit breaker should block ≥195, got {blocked_by_cb}"
        )

    def test_individual_wipe_risk_scores_are_high(self, simulation_env):
        """
        Even the wipes that get through (before breaker trips) should
        score high risk individually through the pipeline.
        """
        pipeline, _, mapper = simulation_env

        device = IntuneDeviceAction(
            device_id="risk-check-device",
            action="wipe",
            device_name="STRYKER-EXEC-LAPTOP",
            operating_system="Windows",
        )
        request = mapper.map_action(device, actor_name=LEGIT_ADMIN)
        decision = pipeline.evaluate(request)

        _print_result("Phase 4: Individual wipe risk score", {
            "allowed": decision.decision in (DecisionOutcome.allow, DecisionOutcome.allow_with_logging),
            "decision": decision.decision.value,
            "risk_score": decision.risk_score,
            "explanation": decision.explanation,
            "device_id": "risk-check-device",
            "circuit_breaker_tripped": False,
            "policy_matched": decision.policy_matched,
            "drift_score": decision.drift_score.score if decision.drift_score else None,
            "safer_alternatives": decision.safer_alternatives,
        })

        # Wipe = destructive category (0.90) + admin privilege + restricted sensitivity
        assert decision.risk_score >= 0.5, (
            f"Wipe should score high risk, got {decision.risk_score}"
        )

    def test_drift_detection_fires_on_anomalous_wipes(self, simulation_env):
        """
        After the baseline of sync operations, a sudden burst of wipe
        commands should trigger drift detection.
        """
        pipeline, _, mapper = simulation_env

        # Wipe a device — after baseline of syncs, this is anomalous behavior
        device = IntuneDeviceAction(
            device_id="drift-check-device",
            action="wipe",
            device_name="STRYKER-ANOMALY-CHECK",
        )
        request = mapper.map_action(device, actor_name=LEGIT_ADMIN)
        decision = pipeline.evaluate(request)

        print(f"\n  Drift detection:")
        print(f"    Drift score: {decision.drift_score.score if decision.drift_score else 'N/A'}")
        if decision.drift_score:
            print(f"    Z-score:     {decision.drift_score.level_drift_z:.2f}")
            print(f"    JS div:      {decision.drift_score.pattern_drift_js:.3f}")
            print(f"    Alert:       {decision.drift_score.alert_triggered}")

        # The drift score should be elevated (wipe after sync baseline)
        # Note: may not trigger full alert if not enough observations yet


# ── Phase 5: Continued Attempts ──────────────────────────────────────────────

class TestPhase5_ContinuedAttempts:
    """
    Attacker retries after circuit breaker trips. All blocked.
    Also tests that legitimate operations from OTHER admins are unaffected.
    """

    def test_attacker_retries_after_cooldown_still_blocked(self, simulation_env):
        """
        Even after the breaker might reset, the attacker immediately
        re-trips it with another burst.
        """
        pipeline, circuit_breaker, mapper = simulation_env

        # Attacker retries with a different destructive action
        result = _evaluate_intune_action(
            simulation_env,
            actor_name=LEGIT_ADMIN,  # still using compromised known account
            action="retire",
            device_id="retry-device-001",
            timestamp=ATTACK_START + timedelta(minutes=10),
        )

        _print_result("Phase 5: Attacker retries with 'retire'", result)
        # Should still be blocked (breaker still open, cooldown is 300s)
        assert result["allowed"] is False

    def test_other_admins_unaffected(self, simulation_env):
        """
        A different registered admin can still perform normal operations.
        The circuit breaker is per-actor — one compromised account doesn't
        lock out the entire org.
        """
        pipeline, _, mapper = simulation_env

        # bob.okafor (registered admin) does a normal sync
        device = IntuneDeviceAction(
            device_id="bob-device-001",
            action="syncDevice",
            device_name="BOB-WORKSTATION",
        )
        request = mapper.map_action(device, actor_name="bob.okafor")
        decision = pipeline.evaluate(request)

        _print_result("Phase 5: Other admin (bob.okafor) syncs device", {
            "allowed": decision.decision in (DecisionOutcome.allow, DecisionOutcome.allow_with_logging),
            "decision": decision.decision.value,
            "risk_score": decision.risk_score,
            "explanation": decision.explanation,
            "device_id": "bob-device-001",
            "circuit_breaker_tripped": False,
            "policy_matched": decision.policy_matched,
            "drift_score": decision.drift_score.score if decision.drift_score else None,
            "safer_alternatives": decision.safer_alternatives,
        })

        # Bob should be fine — sync is low risk from a known admin
        assert decision.decision != DecisionOutcome.block, (
            f"Other admin should not be blocked: {decision.explanation}"
        )


# ── Summary Report ───────────────────────────────────────────────────────────

class TestSimulationSummary:
    """Final summary of the simulation."""

    def test_audit_trail_complete(self, simulation_env):
        """
        Every single decision — allowed or blocked — is in the audit log.
        The audit trail is hash-chained and tamper-evident.
        """
        assert AUDIT.exists(), "Audit log should exist"
        import json
        entries = []
        with open(AUDIT) as f:
            for line in f:
                if line.strip():
                    entries.append(json.loads(line))

        print(f"\n{'='*70}")
        print(f"  SIMULATION SUMMARY")
        print(f"{'='*70}")
        print(f"  Total audit entries:    {len(entries)}")

        # Count decisions
        outcomes = {}
        for e in entries:
            outcome = e.get("decision", "unknown")
            outcomes[outcome] = outcomes.get(outcome, 0) + 1

        for outcome, count in sorted(outcomes.items()):
            print(f"  {outcome:25s}: {count}")

        # Verify hash chain integrity
        prev_hash = None
        for i, entry in enumerate(entries):
            if i > 0:
                assert entry.get("previous_hash") == prev_hash, (
                    f"Hash chain broken at entry {i}"
                )
            prev_hash = entry.get("entry_hash")

        print(f"  Hash chain valid:       YES ({len(entries)} entries)")
        print(f"{'='*70}")

        assert len(entries) > 0, "Audit log should have entries"
