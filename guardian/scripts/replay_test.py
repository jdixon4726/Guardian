#!/usr/bin/env python3
"""
Guardian Scenario Replay Test

Replays a recorded sequence of action requests through the Guardian API,
validates decisions against expected outcomes, and reports metrics.

Usage:
    python scripts/replay_test.py [--api-url http://localhost:8000] [--scenario scenarios/full-day.jsonl]

Each line in the scenario file is a JSON object with:
  - request: the ActionRequest payload
  - expected_decision: allow | allow_with_logging | require_review | block
  - expected_risk_band: low | medium | high | critical (optional)
  - description: human-readable scenario description
  - delay_seconds: seconds to wait before sending (optional, for cascade timing)
"""

import argparse
import json
import sys
import time
from dataclasses import dataclass, field
from datetime import datetime, timezone
from pathlib import Path

try:
    import httpx
except ImportError:
    print("httpx required: pip install httpx")
    sys.exit(1)


@dataclass
class ReplayResult:
    total: int = 0
    passed: int = 0
    failed: int = 0
    errors: int = 0
    decisions: dict = field(default_factory=lambda: {"allow": 0, "allow_with_logging": 0, "require_review": 0, "block": 0})
    failures: list = field(default_factory=list)
    cascades_detected: int = 0
    avg_risk: float = 0.0
    total_risk: float = 0.0


def run_replay(api_url: str, scenario_path: str, api_key: str | None = None) -> ReplayResult:
    headers = {"Content-Type": "application/json"}
    if api_key:
        headers["Authorization"] = f"Bearer {api_key}"

    client = httpx.Client(base_url=api_url, headers=headers, timeout=30)
    result = ReplayResult()

    scenarios = []
    with open(scenario_path) as f:
        for line in f:
            line = line.strip()
            if not line or line.startswith("#"):
                continue
            scenarios.append(json.loads(line))

    print(f"Replay: {scenario_path}")
    print(f"Scenarios: {len(scenarios)}")
    print(f"API: {api_url}")
    print(f"{'='*70}")

    for i, scenario in enumerate(scenarios):
        delay = scenario.get("delay_seconds", 0)
        if delay:
            time.sleep(delay)

        request = scenario["request"]
        expected_decision = scenario.get("expected_decision")
        expected_band = scenario.get("expected_risk_band")
        description = scenario.get("description", f"Scenario {i+1}")

        # Set timestamp to now
        request["timestamp"] = datetime.now(timezone.utc).isoformat()

        result.total += 1

        try:
            resp = client.post("/v1/evaluate", json=request)
            if resp.status_code != 200:
                result.errors += 1
                print(f"  [{i+1:3d}] ERROR  HTTP {resp.status_code}: {description}")
                continue

            data = resp.json()
            actual_decision = data["decision"]
            actual_band = data.get("risk_band", "")
            risk_score = data.get("risk_score", 0)
            drift = data.get("drift_score")

            result.decisions[actual_decision] = result.decisions.get(actual_decision, 0) + 1
            result.total_risk += risk_score

            # Check expected decision
            decision_ok = True
            band_ok = True

            if expected_decision and actual_decision != expected_decision:
                decision_ok = False
            if expected_band and actual_band != expected_band:
                band_ok = False

            if decision_ok and band_ok:
                result.passed += 1
                icon = "PASS"
                color = "32"
            else:
                result.failed += 1
                icon = "FAIL"
                color = "31"
                result.failures.append({
                    "scenario": i + 1,
                    "description": description,
                    "expected_decision": expected_decision,
                    "actual_decision": actual_decision,
                    "expected_band": expected_band,
                    "actual_band": actual_band,
                    "risk_score": risk_score,
                })

            drift_str = f" drift={drift:.2f}" if drift else ""
            print(f"  [{i+1:3d}] \033[{color}m{icon}\033[0m  {actual_decision:20s} risk={risk_score:.2f}{drift_str}  {description}")

        except Exception as e:
            result.errors += 1
            print(f"  [{i+1:3d}] ERROR  {e}: {description}")

    # Compute averages
    if result.total > 0:
        result.avg_risk = result.total_risk / result.total

    # Check for cascades
    try:
        cascade_resp = client.get("/v1/graph/cascades?min_depth=2&limit=100")
        if cascade_resp.status_code == 200:
            cascades = cascade_resp.json()
            result.cascades_detected = cascades.get("total", 0)
    except Exception:
        pass

    # Print summary
    print(f"\n{'='*70}")
    print(f"Results: {result.passed} passed, {result.failed} failed, {result.errors} errors / {result.total} total")
    print(f"\nDecision distribution:")
    for dec, count in sorted(result.decisions.items()):
        bar = "#" * count
        print(f"  {dec:20s} {count:3d}  {bar}")
    print(f"\nAverage risk score: {result.avg_risk:.3f}")
    print(f"Cascades detected: {result.cascades_detected}")

    if result.failures:
        print(f"\nFailures:")
        for f in result.failures:
            print(f"  #{f['scenario']}: {f['description']}")
            print(f"    Expected: {f['expected_decision']} ({f['expected_band']})")
            print(f"    Actual:   {f['actual_decision']} ({f['actual_band']}) risk={f['risk_score']:.3f}")

    return result


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Replay test scenarios through Guardian")
    parser.add_argument("--api-url", default="http://localhost:8000")
    parser.add_argument("--scenario", default="scenarios/full-day-replay.jsonl")
    parser.add_argument("--api-key", default=None)
    args = parser.parse_args()

    result = run_replay(args.api_url, args.scenario, args.api_key)
    sys.exit(0 if result.failed == 0 and result.errors == 0 else 1)
