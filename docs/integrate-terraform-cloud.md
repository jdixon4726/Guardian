# Integrate Guardian with Terraform Cloud

Connect Guardian to your Terraform Cloud workspace in 10 minutes. Every `terraform plan` and `terraform apply` will be evaluated by Guardian's behavioral pipeline before execution.

---

## How It Works

```
Developer pushes code
    ↓
Terraform Cloud queues a run
    ↓
TFC sends plan metadata to Guardian (run task webhook)
    ↓
Guardian fetches the plan JSON
    ↓
Each resource change → ActionRequest → 10-stage pipeline evaluation
    ↓
Guardian responds: passed / failed (with explanation)
    ↓
TFC proceeds or blocks the apply
```

Guardian evaluates the **actor** (who triggered the run), the **action** (create/modify/delete), the **target** (resource type and address), and the **context** (time of day, velocity, drift from baseline). A `terraform destroy` on production at 3 AM from an account that normally only runs plans in staging will score very differently than a routine config change during business hours.

---

## Prerequisites

- A running Guardian instance (local, Docker, or [Render](https://guardian-np0a.onrender.com))
- A Terraform Cloud workspace with [run tasks](https://developer.hashicorp.com/terraform/cloud-docs/workspaces/settings/run-tasks) enabled
- Admin access to the TFC organization

---

## Step 1: Get Your Guardian Webhook URL

Your Guardian Terraform webhook endpoint is:

```
https://<your-guardian-host>/v1/terraform/run-task
```

For the Render deployment:
```
https://guardian-np0a.onrender.com/v1/terraform/run-task
```

---

## Step 2: Create a Run Task in Terraform Cloud

1. Go to your TFC organization → **Settings** → **Run Tasks**
2. Click **Create Run Task**
3. Fill in:
   - **Name**: `Guardian Governance`
   - **Endpoint URL**: `https://<your-guardian-host>/v1/terraform/run-task`
   - **HMAC Key**: (optional — for webhook signature verification)
4. Click **Create**

---

## Step 3: Attach the Run Task to a Workspace

1. Go to the workspace you want to protect
2. **Settings** → **Run Tasks**
3. Click **+** next to `Guardian Governance`
4. Set the enforcement level:
   - **Advisory**: Guardian evaluates but doesn't block. Good for initial rollout.
   - **Mandatory**: Guardian must pass for the apply to proceed. Use in production.
5. Set the stage:
   - **Post-plan**: Guardian evaluates after `terraform plan` completes (recommended)
   - **Pre-apply**: Guardian evaluates before `terraform apply` (stricter)

---

## Step 4: Verify

Trigger a plan in the workspace. You should see:

1. TFC sends the plan to Guardian
2. Guardian logs: `Terraform run task: evaluating N resource changes`
3. Guardian responds with `passed` or `failed`
4. The result appears in TFC's run task results panel

---

## What Guardian Evaluates

For each resource change in the plan, Guardian creates an ActionRequest:

| Plan Change | Guardian Action | Risk Category |
|---|---|---|
| `create` | `change_configuration` | Moderate |
| `update` | `change_configuration` | Moderate |
| `delete` | `destroy_infrastructure` | Destructive (0.90) |
| `replace` | `destroy_infrastructure` | Destructive (0.90) |

Resource types are mapped via `config/terraform-mappings.yaml`:

| Resource Pattern | Guardian Action | Sensitivity |
|---|---|---|
| `aws_security_group*` | `modify_firewall_rule` | High |
| `aws_iam_role*` | `modify_iam_role` | Restricted |
| `aws_iam_policy*` | `modify_iam_role` | Restricted |
| `aws_db_instance*` | `change_configuration` | Restricted |
| `aws_instance*` | `change_configuration` | High |
| `aws_s3_bucket*` | `change_configuration` | High |
| `aws_kms_*` | `modify_security_policy` | Restricted |

Add your own mappings by editing `config/terraform-mappings.yaml`.

---

## Example: Guardian Blocks a Dangerous Destroy

A developer queues `terraform destroy` on the production workspace at 2 AM:

```
Plan: 0 to add, 0 to change, 847 to destroy
```

Guardian evaluates each resource deletion:

```
Resource: aws_vpc.prod → destroy_infrastructure (risk: 0.90)
  Actor: terraform-acme-prod-infra
  Privilege: admin
  Sensitivity: restricted
  Context: 2 AM, no maintenance window, actor normally runs during business hours

  Decision: BLOCK
  Risk Score: 0.82
  Explanation: Destructive action on restricted asset outside maintenance window.
    Actor behavioral baseline indicates daytime-only operations.

Guardian result: FAILED
"Guardian blocked 847 action(s): destroy_infrastructure on vpc-prod..."
```

TFC blocks the apply. The developer's on-call lead gets a review request.

---

## Using the SDK

```python
from guardian_sdk import GuardianClient

client = GuardianClient("https://guardian-np0a.onrender.com")

# Evaluate a Terraform-style action directly
decision = client.evaluate(
    actor_name="terraform-acme-prod-infra",
    actor_type="automation",
    action="destroy_infrastructure",
    target_system="aws-vpc-prod",
    target_asset="vpc-prod-main",
    privilege_level="admin",
    sensitivity_level="restricted",
    business_context="Terraform destroy plan: 847 resources",
)

if decision.blocked:
    print(f"BLOCKED: {decision.explanation}")
else:
    print(f"Allowed (risk: {decision.risk_score})")
```

---

## Configuration

### Scoring Weights

Edit `config/guardian.yaml` to adjust how Terraform actions are scored:

```yaml
scoring:
  action_categories:
    destructive:
      - destroy_infrastructure
      - delete_resource
      - delete_vpc
    moderate:
      - change_configuration
      - modify_firewall_rule

  action_category_scores:
    destructive: 0.90
    moderate: 0.45
```

### Actor Registry

Register your Terraform Cloud runner in `config/actor-registry.yaml`:

```yaml
actors:
  - name: terraform-acme-prod-infra
    type: automation
    max_privilege_level: admin
    owner: platform-team@acme.com
    status: active
    notes: "Terraform Cloud runner for production infrastructure."
```

Unregistered actors are blocked at identity attestation (risk score 1.0).

### Resource Mappings

Add custom resource mappings in `config/terraform-mappings.yaml`:

```yaml
mappings:
  - pattern: "aws_rds_cluster*"
    action: change_configuration
    sensitivity: restricted
    system: rds-prod

  - pattern: "aws_lambda_function*"
    action: change_configuration
    sensitivity: high
    system: lambda-prod
```

---

## Troubleshooting

**Guardian returns 503:**
The pipeline isn't initialized. Check the Guardian logs — it may still be starting up (Render free tier has cold starts).

**TFC says "run task timed out":**
TFC expects a response within 10 seconds. Guardian acknowledges immediately and processes asynchronously. If the acknowledgement is slow (cold start), increase the TFC timeout or upgrade to a paid Render plan.

**All actions are blocked:**
Check if the actor is registered in `actor-registry.yaml`. Unregistered actors get risk score 1.0 and are blocked at attestation.

**Actions are allowed that should be blocked:**
Check `policies/deny/` for deny rules. If no deny rule matches, Guardian defaults to `require_review` (not allow). The decision depends on risk score × policy verdict.

---

## Next Steps

- View decisions in the [Guardian dashboard](https://guardian-np0a.onrender.com)
- Search for your Terraform actor in **Actor Intelligence** to see trust trajectory
- Check **Automation Graph** to see how Terraform plans cascade through your infrastructure
- Set up [threat intelligence sync](/v1/threat-intel/sync) to get CISA KEV risk overlays on your infrastructure resources
