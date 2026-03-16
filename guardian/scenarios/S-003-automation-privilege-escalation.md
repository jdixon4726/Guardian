# S-003: Automation account requests privilege escalation

## Scenario

An automation account that normally operates at standard privilege level requests to
escalate its own privileges by modifying an IAM role. No maintenance window is active.

## Action request

```json
{
  "actor_name": "data-pipeline-bot",
  "actor_type": "automation",
  "requested_action": "modify_iam_role",
  "target_system": "aws-iam",
  "target_asset": "role-data-pipeline-prod",
  "privilege_level": "elevated",
  "sensitivity_level": "restricted",
  "business_context": "Pipeline requires additional S3 permissions to process new data source",
  "timestamp": "2025-03-15T11:45:00Z"
}
```

## Expected decision

`require_review`

## Expected evaluation path

1. Identity Attestation: `data-pipeline-bot` registered as `automation`, max privilege `elevated`. Claim matches. Passes.
2. Context Enrichment: asset sensitivity `restricted`, criticality `high`. No maintenance window active. Actor history: 45 days, 1 prior block (different action), 0 prior privilege escalations.
3. Drift Detection: requesting elevated privilege is outside actor's normal pattern (actor usually operates at standard). Pattern drift score elevated: **0.41**.
4. Policy Engine: no deny rule matches. Conditional rule `conditional-automation-privilege-escalation` matches — outcome `require_review`.
5. Risk Scoring: action=0.42, actor=0.31, asset=0.38, context=0.29 (outside window + drift). Weighted score: **0.61** (High band).
6. Decision Engine: policy `require_review` × High risk → **`require_review`**.

## Expected explanation

"Action requires human review. The automation account data-pipeline-bot has requested
an IAM role modification — a privilege escalation action on a restricted asset. This
action is outside the actor's established behavioral pattern (0 prior privilege
escalation requests in 45-day history) and no maintenance window is active. A human
reviewer must approve this action before it proceeds."

## Why this matters

Privilege escalation via automation accounts is one of the most common lateral movement
patterns in cloud infrastructure attacks. A legitimate pipeline should have its
permissions defined at provisioning time, not requested dynamically at runtime. The
`require_review` outcome creates the governance checkpoint needed to either fix the
pipeline design (if legitimate) or block an attack (if malicious).

## Adversarial note

The `business_context` in this scenario is plausible and could fool a human reviewer
acting quickly. Guardian catches this at the policy layer regardless of justification.
