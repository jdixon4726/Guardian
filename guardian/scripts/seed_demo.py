#!/usr/bin/env python3
"""
Guardian Demo Data Seeder

Sends realistic evaluation requests through the Guardian API to populate
the dashboard with diverse scenarios: normal operations, privilege escalations,
drift events, cascades, blocks, and mixed decisions.

Usage:
    python scripts/seed_demo.py [--api-url http://localhost:8000] [--api-key KEY]

Scenarios seeded:
  1. Normal CI/CD deployment chain (GitHub Actions -> Terraform -> K8s)
  2. Routine monitoring operations (Datadog agent)
  3. Privilege escalation attempt (AI agent modifying IAM)
  4. After-hours infrastructure change (deploy bot at 3am)
  5. Rapid velocity spike (ArgoCD mass sync)
  6. Unknown actor attempting production access
  7. Normal database maintenance
  8. Cross-system cascade (CI -> Terraform -> AWS -> K8s)
  9. Security scanner routine
  10. Gradual privilege creep (automation account expanding scope)
"""

import argparse
import json
import sys
import time
from datetime import datetime, timedelta, timezone

try:
    import httpx
except ImportError:
    print("httpx required: pip install httpx")
    sys.exit(1)


def now_utc() -> datetime:
    return datetime.now(timezone.utc)


# ── Scenario definitions ─────────────────────────────────────────────────────

SCENARIOS = [
    # --- 1. Normal CI/CD deployment chain ---
    {
        "actor_name": "github-actions-prod",
        "actor_type": "automation",
        "requested_action": "deploy_service",
        "target_system": "github-actions",
        "target_asset": "payment-api",
        "privilege_level": "standard",
        "sensitivity_level": "internal",
        "business_context": "Automated deployment of payment-api v2.14.3 from merged PR #847",
    },
    {
        "actor_name": "terraform-cloud-runner",
        "actor_type": "automation",
        "requested_action": "terraform.apply",
        "target_system": "terraform-cloud",
        "target_asset": "prod-vpc-networking",
        "privilege_level": "elevated",
        "sensitivity_level": "high",
        "business_context": "Infrastructure update triggered by CI pipeline - VPC peering for payment-api",
        "_delay": 5,
    },
    {
        "actor_name": "argocd-prod",
        "actor_type": "automation",
        "requested_action": "sync_deployment",
        "target_system": "kubernetes",
        "target_asset": "payment-api-deployment",
        "privilege_level": "standard",
        "sensitivity_level": "internal",
        "business_context": "ArgoCD sync triggered by Terraform infrastructure change",
        "_delay": 8,
    },

    # --- 2. Routine monitoring ---
    {
        "actor_name": "datadog-collector",
        "actor_type": "automation",
        "requested_action": "collect_metrics",
        "target_system": "monitoring",
        "target_asset": "cluster-metrics",
        "privilege_level": "standard",
        "sensitivity_level": "public",
        "business_context": "Routine metric collection cycle",
    },
    {
        "actor_name": "datadog-collector",
        "actor_type": "automation",
        "requested_action": "collect_logs",
        "target_system": "monitoring",
        "target_asset": "application-logs",
        "privilege_level": "standard",
        "sensitivity_level": "internal",
        "business_context": "Routine log aggregation",
    },

    # --- 3. Privilege escalation attempt ---
    {
        "actor_name": "ai-remediation-bot",
        "actor_type": "ai_agent",
        "requested_action": "modify_iam_role",
        "target_system": "aws-production",
        "target_asset": "admin-role",
        "privilege_level": "admin",
        "sensitivity_level": "restricted",
        "business_context": "Automated incident response - attempting to modify IAM role for access recovery",
    },

    # --- 4. After-hours change ---
    {
        "actor_name": "deploy-bot-prod",
        "actor_type": "automation",
        "requested_action": "restart_service",
        "target_system": "kubernetes",
        "target_asset": "auth-service",
        "privilege_level": "elevated",
        "sensitivity_level": "high",
        "business_context": "Automated restart triggered by health check failure at 3:15 AM UTC",
    },

    # --- 5. Velocity spike - ArgoCD mass sync ---
    {
        "actor_name": "argocd-prod",
        "actor_type": "automation",
        "requested_action": "sync_deployment",
        "target_system": "kubernetes",
        "target_asset": "frontend-v2",
        "privilege_level": "standard",
        "sensitivity_level": "internal",
        "business_context": "Mass sync triggered by cluster migration",
    },
    {
        "actor_name": "argocd-prod",
        "actor_type": "automation",
        "requested_action": "sync_deployment",
        "target_system": "kubernetes",
        "target_asset": "backend-api",
        "privilege_level": "standard",
        "sensitivity_level": "internal",
        "business_context": "Mass sync triggered by cluster migration",
        "_delay": 1,
    },
    {
        "actor_name": "argocd-prod",
        "actor_type": "automation",
        "requested_action": "sync_deployment",
        "target_system": "kubernetes",
        "target_asset": "worker-pool",
        "privilege_level": "standard",
        "sensitivity_level": "internal",
        "business_context": "Mass sync triggered by cluster migration",
        "_delay": 1,
    },
    {
        "actor_name": "argocd-prod",
        "actor_type": "automation",
        "requested_action": "sync_deployment",
        "target_system": "kubernetes",
        "target_asset": "cache-layer",
        "privilege_level": "standard",
        "sensitivity_level": "internal",
        "business_context": "Mass sync triggered by cluster migration",
        "_delay": 1,
    },
    {
        "actor_name": "argocd-prod",
        "actor_type": "automation",
        "requested_action": "sync_deployment",
        "target_system": "kubernetes",
        "target_asset": "message-queue",
        "privilege_level": "standard",
        "sensitivity_level": "internal",
        "business_context": "Mass sync triggered by cluster migration",
        "_delay": 1,
    },

    # --- 6. Unknown actor ---
    {
        "actor_name": "unknown-script-42",
        "actor_type": "automation",
        "requested_action": "delete_bucket",
        "target_system": "aws-production",
        "target_asset": "customer-data-backup",
        "privilege_level": "admin",
        "sensitivity_level": "restricted",
        "business_context": "Cleanup script",
    },

    # --- 7. Normal database maintenance ---
    {
        "actor_name": "deploy-bot-prod",
        "actor_type": "automation",
        "requested_action": "run_migration",
        "target_system": "database",
        "target_asset": "users-db-primary",
        "privilege_level": "elevated",
        "sensitivity_level": "confidential",
        "business_context": "Schema migration for user preferences feature (migration #0047)",
    },

    # --- 8. Cross-system cascade ---
    {
        "actor_name": "github-actions-prod",
        "actor_type": "automation",
        "requested_action": "trigger_pipeline",
        "target_system": "github-actions",
        "target_asset": "infra-pipeline",
        "privilege_level": "standard",
        "sensitivity_level": "internal",
        "business_context": "Infrastructure pipeline triggered by merge to main",
    },
    {
        "actor_name": "terraform-cloud-runner",
        "actor_type": "automation",
        "requested_action": "terraform.apply",
        "target_system": "aws-production",
        "target_asset": "eks-cluster-config",
        "privilege_level": "admin",
        "sensitivity_level": "restricted",
        "business_context": "EKS cluster configuration update from Terraform pipeline",
        "_delay": 3,
    },
    {
        "actor_name": "argocd-prod",
        "actor_type": "automation",
        "requested_action": "sync_deployment",
        "target_system": "kubernetes",
        "target_asset": "ingress-controller",
        "privilege_level": "elevated",
        "sensitivity_level": "high",
        "business_context": "Ingress controller sync following EKS update",
        "_delay": 5,
    },

    # --- 9. Security scanner ---
    {
        "actor_name": "security-scanner-bot",
        "actor_type": "automation",
        "requested_action": "vulnerability_scan",
        "target_system": "security",
        "target_asset": "container-registry",
        "privilege_level": "standard",
        "sensitivity_level": "internal",
        "business_context": "Scheduled weekly vulnerability scan of container images",
    },

    # --- 10. Gradual privilege creep ---
    {
        "actor_name": "data-pipeline-bot",
        "actor_type": "automation",
        "requested_action": "read_table",
        "target_system": "database",
        "target_asset": "analytics-warehouse",
        "privilege_level": "standard",
        "sensitivity_level": "internal",
        "business_context": "Routine ETL data extraction",
    },
    {
        "actor_name": "data-pipeline-bot",
        "actor_type": "automation",
        "requested_action": "modify_schema",
        "target_system": "database",
        "target_asset": "analytics-warehouse",
        "privilege_level": "elevated",
        "sensitivity_level": "confidential",
        "business_context": "Schema modification for new reporting dimension",
        "_delay": 2,
    },
    {
        "actor_name": "data-pipeline-bot",
        "actor_type": "automation",
        "requested_action": "export_data",
        "target_system": "database",
        "target_asset": "customer-pii-table",
        "privilege_level": "admin",
        "sensitivity_level": "restricted",
        "business_context": "Data export for compliance audit",
        "_delay": 2,
    },

    # --- 11. More normal traffic to balance the feed ---
    {
        "actor_name": "deploy-bot-prod",
        "actor_type": "automation",
        "requested_action": "scale_replicas",
        "target_system": "kubernetes",
        "target_asset": "frontend-v2",
        "privilege_level": "standard",
        "sensitivity_level": "internal",
        "business_context": "Horizontal pod autoscaler scale-up during traffic spike",
    },
    {
        "actor_name": "terraform-cloud-runner",
        "actor_type": "automation",
        "requested_action": "terraform.plan",
        "target_system": "terraform-cloud",
        "target_asset": "staging-network",
        "privilege_level": "standard",
        "sensitivity_level": "internal",
        "business_context": "Terraform plan for staging environment update",
    },
    {
        "actor_name": "github-actions-prod",
        "actor_type": "automation",
        "requested_action": "run_tests",
        "target_system": "github-actions",
        "target_asset": "payment-api-tests",
        "privilege_level": "standard",
        "sensitivity_level": "public",
        "business_context": "CI test suite for PR #851",
    },
    {
        "actor_name": "cert-manager",
        "actor_type": "automation",
        "requested_action": "renew_certificate",
        "target_system": "kubernetes",
        "target_asset": "tls-wildcard-cert",
        "privilege_level": "standard",
        "sensitivity_level": "internal",
        "business_context": "Automated TLS certificate renewal (expires in 14 days)",
    },
    {
        "actor_name": "deploy-bot-prod",
        "actor_type": "automation",
        "requested_action": "deploy_service",
        "target_system": "kubernetes",
        "target_asset": "notification-service",
        "privilege_level": "standard",
        "sensitivity_level": "internal",
        "business_context": "Deploy notification-service v1.8.2 - bug fix for email templates",
    },

    # --- 12. AI agent doing something normal ---
    {
        "actor_name": "ai-ops-assistant",
        "actor_type": "ai_agent",
        "requested_action": "analyze_logs",
        "target_system": "monitoring",
        "target_asset": "error-log-stream",
        "privilege_level": "standard",
        "sensitivity_level": "internal",
        "business_context": "AI-assisted log analysis for incident #INC-2847",
    },

    # --- 13. AI agent escalating ---
    {
        "actor_name": "ai-ops-assistant",
        "actor_type": "ai_agent",
        "requested_action": "restart_service",
        "target_system": "kubernetes",
        "target_asset": "auth-service",
        "privilege_level": "elevated",
        "sensitivity_level": "high",
        "business_context": "AI-recommended remediation for incident #INC-2847 - auth service OOM",
        "_delay": 3,
    },

    # --- 14. Destructive action by known actor ---
    {
        "actor_name": "terraform-cloud-runner",
        "actor_type": "automation",
        "requested_action": "terraform.destroy",
        "target_system": "aws-production",
        "target_asset": "legacy-api-gateway",
        "privilege_level": "admin",
        "sensitivity_level": "high",
        "business_context": "Planned teardown of deprecated legacy API gateway (approved in RFC-221)",
    },
]


FEEDBACK_ENTRIES = [
    # Feedback on some decisions after they're made
    {"type": "confirmed_correct", "operator": "alice.chen", "reason": "Correct block on unknown actor"},
    {"type": "false_positive", "operator": "bob.okafor", "reason": "ArgoCD mass sync is expected during migration window"},
    {"type": "confirmed_correct", "operator": "alice.chen", "reason": "AI agent IAM modification correctly flagged"},
    {"type": "known_pattern", "operator": "carol.jones", "reason": "This CI->TF->K8s chain runs on every merge"},
]


def seed(api_url: str, api_key: str | None):
    headers = {"Content-Type": "application/json"}
    if api_key:
        headers["Authorization"] = f"Bearer {api_key}"

    client = httpx.Client(base_url=api_url, headers=headers, timeout=30)
    decision_ids = []

    print(f"Seeding Guardian at {api_url}")
    print(f"{'='*60}")

    # Send evaluations
    for i, scenario in enumerate(SCENARIOS):
        delay = scenario.pop("_delay", 0)
        if delay:
            time.sleep(delay)

        scenario["timestamp"] = now_utc().isoformat()

        try:
            resp = client.post("/v1/evaluate", json=scenario)
            if resp.status_code == 200:
                result = resp.json()
                decision = result["decision"]
                risk = result["risk_score"]
                entry_id = result["entry_id"]
                decision_ids.append(entry_id)

                icon = {"allow": "+", "allow_with_logging": "~", "require_review": "?", "block": "X"}
                color = {"allow": "32", "allow_with_logging": "36", "require_review": "33", "block": "31"}

                print(f"  [{icon.get(decision, '?')}] \033[{color.get(decision, '0')}m{decision:20s}\033[0m "
                      f"risk={risk:.2f}  {scenario['actor_name']:25s} {scenario['requested_action']}")
            else:
                print(f"  [!] HTTP {resp.status_code}: {scenario['actor_name']} - {resp.text[:80]}")
        except Exception as e:
            print(f"  [!] Error: {e}")

    print(f"\n{'='*60}")
    print(f"Sent {len(SCENARIOS)} evaluations, got {len(decision_ids)} decisions")

    # Submit feedback on some decisions
    if len(decision_ids) >= 4:
        print(f"\nSubmitting feedback...")
        feedback_targets = [
            decision_ids[11],  # unknown-script-42 (should be blocked)
            decision_ids[8],   # argocd mass sync
            decision_ids[5],   # AI agent IAM modification
            decision_ids[0],   # first CI/CD deploy
        ]

        for entry_id, fb in zip(feedback_targets, FEEDBACK_ENTRIES):
            try:
                resp = client.post(f"/v1/decisions/{entry_id}/feedback", json={
                    "feedback_type": fb["type"],
                    "operator": fb["operator"],
                    "reason": fb["reason"],
                })
                if resp.status_code == 200:
                    print(f"  Feedback: {fb['type']:20s} by {fb['operator']}")
                else:
                    print(f"  Feedback failed: {resp.status_code}")
            except Exception as e:
                print(f"  Feedback error: {e}")

    # Print summary
    print(f"\n{'='*60}")
    print("Demo data seeded successfully!")
    print(f"\nOpen the dashboard: http://localhost:5173")
    print(f"  - Command Center: see all {len(decision_ids)} decisions")
    print(f"  - Actor Intelligence: try 'deploy-bot-prod' or 'ai-remediation-bot'")
    print(f"  - Automation Graph: see cascade chains")
    print(f"  - Blast Radius: try 'github-actions-prod'")
    print(f"  - Feedback: see accuracy metrics")


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Seed Guardian with demo data")
    parser.add_argument("--api-url", default="http://localhost:8000", help="Guardian API URL")
    parser.add_argument("--api-key", default=None, help="API key (if set)")
    args = parser.parse_args()

    seed(args.api_url, args.api_key)
