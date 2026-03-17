"""
Guardian Benchmark — Measure pipeline throughput locally.

No external dependencies needed (uses the pipeline directly, not HTTP).
This measures the raw evaluation speed without network overhead.

Run:
    cd guardian
    python tests/load/benchmark.py
"""

import time
import statistics
from datetime import datetime, timezone
from pathlib import Path

ROOT = Path(__file__).parent.parent.parent
CONFIG = ROOT / "config"
POLICIES = ROOT / "policies"


def main():
    from guardian.pipeline import GuardianPipeline
    from guardian.audit.logger import AuditLogger
    from guardian.drift.baseline import BaselineStore
    from guardian.drift.alerts import AlertPublisher
    from guardian.attestation.attestor import ActorRegistry
    from guardian.enrichment.context import AssetCatalog, MaintenanceWindowStore
    from guardian.policy.engine import PolicyEngine
    from guardian.policy.loaders import PolicyLoader
    from guardian.models.action_request import ActionRequest, ActorType, PrivilegeLevel, SensitivityLevel

    import tempfile

    print("=== Guardian Pipeline Benchmark ===\n")
    print("Building pipeline...")

    actor_registry = ActorRegistry(CONFIG / "actor-registry.yaml")
    asset_catalog = AssetCatalog(CONFIG / "asset-catalog.yaml")
    window_store = MaintenanceWindowStore(CONFIG / "maintenance-windows.yaml")
    loader = PolicyLoader(POLICIES)
    deny_rules, conditional_rules, allow_rules = loader.load_all()
    policy_engine = PolicyEngine(deny_rules, conditional_rules, allow_rules)
    audit_path = Path(tempfile.mktemp(suffix="-bench-audit.jsonl"))
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

    # Test payloads
    payloads = [
        ActionRequest(
            actor_name="deploy-bot-prod", actor_type=ActorType.automation,
            requested_action="change_configuration", target_system="aws-ec2",
            target_asset="prod/ec2/web", privilege_level=PrivilegeLevel.standard,
            sensitivity_level=SensitivityLevel.internal,
            timestamp=datetime.now(timezone.utc),
        ),
        ActionRequest(
            actor_name="terraform-cloud-runner", actor_type=ActorType.automation,
            requested_action="destroy_infrastructure", target_system="aws-vpc-prod",
            target_asset="vpc-prod-main", privilege_level=PrivilegeLevel.admin,
            sensitivity_level=SensitivityLevel.restricted,
            timestamp=datetime.now(timezone.utc),
        ),
        ActionRequest(
            actor_name="alice.chen", actor_type=ActorType.human,
            requested_action="modify_firewall_rule", target_system="aws-vpc-prod",
            target_asset="sg-0a1b2c3d", privilege_level=PrivilegeLevel.elevated,
            sensitivity_level=SensitivityLevel.high,
            timestamp=datetime.now(timezone.utc),
        ),
        ActionRequest(
            actor_name="unknown-actor", actor_type=ActorType.human,
            requested_action="grant_admin_access", target_system="aws-iam",
            target_asset="role-admin", privilege_level=PrivilegeLevel.admin,
            sensitivity_level=SensitivityLevel.restricted,
            timestamp=datetime.now(timezone.utc),
        ),
    ]

    # Warm-up
    print("Warming up (50 evaluations)...")
    for i in range(50):
        pipeline.evaluate(payloads[i % len(payloads)])

    # Wait for async post-decision stages to complete
    pipeline._async_executor.shutdown(wait=True)
    from concurrent.futures import ThreadPoolExecutor
    pipeline._async_executor = ThreadPoolExecutor(max_workers=2, thread_name_prefix="guardian-bench")

    # Benchmark
    iterations = 500
    print(f"Benchmarking ({iterations} evaluations)...\n")

    latencies = []
    decisions = {"allow": 0, "allow_with_logging": 0, "require_review": 0, "block": 0}

    start_total = time.monotonic()

    for i in range(iterations):
        payload = payloads[i % len(payloads)]
        # Refresh timestamp
        payload = ActionRequest(**{**payload.model_dump(), "timestamp": datetime.now(timezone.utc)})

        start = time.monotonic()
        decision = pipeline.evaluate(payload)
        elapsed = time.monotonic() - start

        latencies.append(elapsed * 1000)  # ms
        decisions[decision.decision.value] = decisions.get(decision.decision.value, 0) + 1

    total_time = time.monotonic() - start_total

    # Wait for background tasks
    pipeline._async_executor.shutdown(wait=True)

    # Results
    latencies.sort()
    n = len(latencies)

    print("=== Results ===")
    print(f"  Total evaluations: {iterations}")
    print(f"  Total time:        {total_time:.2f}s")
    print(f"  Throughput:        {iterations / total_time:.1f} evaluations/sec")
    print()
    print(f"  Latency p50:       {latencies[int(n * 0.5)]:.1f}ms")
    print(f"  Latency p95:       {latencies[int(n * 0.95)]:.1f}ms")
    print(f"  Latency p99:       {latencies[int(n * 0.99)]:.1f}ms")
    print(f"  Latency max:       {max(latencies):.1f}ms")
    print(f"  Latency mean:      {statistics.mean(latencies):.1f}ms")
    print(f"  Latency stddev:    {statistics.stdev(latencies):.1f}ms")
    print()
    print(f"  Decisions:")
    for d, count in sorted(decisions.items()):
        print(f"    {d:25s} {count}")
    print()
    print("===============")

    # Cleanup
    if audit_path.exists():
        audit_path.unlink()


if __name__ == "__main__":
    main()
