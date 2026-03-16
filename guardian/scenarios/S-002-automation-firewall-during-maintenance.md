# S-002: Automation modifies firewall rule during maintenance window

## Scenario

A deployment automation account requests to modify a firewall rule on a production
VPC security group. The request arrives during a scheduled maintenance window.

## Action request

```json
{
  "actor_name": "deploy-bot-prod",
  "actor_type": "automation",
  "requested_action": "modify_firewall_rule",
  "target_system": "aws-vpc-prod",
  "target_asset": "sg-0a1b2c3d",
  "privilege_level": "elevated",
  "sensitivity_level": "high",
  "business_context": "Weekly deployment pipeline: opening port 8443 for canary release",
  "timestamp": "2025-03-15T02:15:00Z"
}
```

## Expected decision

`allow_with_logging`

## Expected evaluation path

1. Identity Attestation: `deploy-bot-prod` registered as `automation`, max privilege `elevated`. Claim matches. Passes.
2. Context Enrichment: asset sensitivity `high`, criticality `critical`. Maintenance window **active** (Saturdays 02:00–06:00 UTC). Actor history: 90 days, 0 blocks, 2 prior reviews.
3. Drift Detection: stable baseline. Drift score: 0.09.
4. Policy Engine: no deny rule matches. Conditional rule `conditional-firewall-maintenance-window` matches — outcome `allow_with_logging`.
5. Risk Scoring: action=0.28, actor=0.18, asset=0.22, context=0.08 (maintenance window credit). Weighted score: **0.38** (Medium band).
6. Decision Engine: policy `allow_with_logging` × Medium risk → **`allow_with_logging`**.

## Expected explanation

"Action allowed with logging. The automation account deploy-bot-prod requested an
elevated-privilege firewall rule modification on a high-sensitivity asset. This action
is conditionally permitted during the active maintenance window (Sat 02:00–06:00 UTC).
The elevated privilege level and asset sensitivity require this action to be retained
in the audit log for review."

## Why this matters

This scenario demonstrates that Guardian is not a blanket block-everything system.
Legitimate automation during defined windows should flow through with minimal friction
and full auditability. The value is in the `allow_with_logging` rather than `allow` —
the audit trail exists, and the action is reviewable, but the pipeline is not blocked.
