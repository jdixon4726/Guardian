# Architecture

## Overview

Guardian is structured as a sequential evaluation pipeline. Each stage enriches the action request with additional context before passing it to the next stage. Any stage can halt the pipeline early — identity attestation failures and hard deny rules both produce an immediate `block` response without evaluating downstream stages.

```
Action Request
      │
      ▼
Identity Attestation
      │
      ▼
Context Enrichment  ←──── Actor History Store
      │             ←──── Asset Catalog
      │             ←──── Maintenance Window Store
      ▼
Drift Detection Engine ←── Behavioral Baseline Store
      │                ──► Alert Publisher (async)
      ▼
Policy Engine
      │
      ▼
Risk Scoring Engine
      │
      ▼
Decision Engine
      │
      ▼
Audit + Explanation ──────► Compliance Mapper (async)
      │
      ▼
Decision Response
```

---

## Stage 1: Action Request

The pipeline begins with an `ActionRequest` — a Pydantic model that validates and normalizes the incoming payload.

### Model fields

| Field | Type | Description |
|---|---|---|
| `actor_name` | `str` | Identifier of the requesting actor |
| `actor_type` | `ActorType` | `human`, `automation`, or `ai_agent` |
| `requested_action` | `str` | Action identifier (e.g., `modify_firewall_rule`) |
| `target_system` | `str` | System the action targets |
| `target_asset` | `str` | Specific asset within the target system |
| `privilege_level` | `PrivilegeLevel` | `standard`, `elevated`, or `admin` |
| `sensitivity_level` | `SensitivityLevel` | `public`, `internal`, `confidential`, or `restricted` |
| `business_context` | `str` | Human-readable justification (treated as untrusted input) |
| `timestamp` | `datetime` | Request timestamp (UTC) |
| `session_id` | `str` | Session identifier for sequence analysis |

### Design notes

- `actor_type` and `privilege_level` are claims, not verified facts. Identity Attestation validates them independently.
- `business_context` is untrusted input. It undergoes injection detection before being included in evaluation context.
- `session_id` links requests for sequence-level analysis in the Drift Detection Engine.

---

## Stage 2: Identity Attestation

Identity Attestation verifies that the actor making the request is who they claim to be, and that their claimed `actor_type` and `privilege_level` match the registry record.

### Responsibilities

- Look up `actor_name` in the actor registry
- Verify that `actor_type` matches the registered type (self-reported type mismatch → `block`)
- Verify that `privilege_level` is within the actor's registered maximum
- Return an `AttestationResult` with verified actor metadata

### Security property

No downstream stage trusts self-reported actor fields. Only the `AttestationResult` produced by this stage is used in subsequent evaluation. This closes the most common bypass vector in governance systems: a compromised automation account claiming to be a human operator.

---

## Stage 3: Context Enrichment

Context Enrichment assembles the full `EnrichedContext` object by pulling from three external stores in parallel.

### Inputs (async parallel fetch)

| Source | Data retrieved |
|---|---|
| Asset Catalog | Asset criticality score, owner, classification tags |
| Actor History Store | Last 90 days of actions, approve/block/review counts, last privilege escalation |
| Maintenance Window Store | Whether current timestamp falls within a defined maintenance window for the target system |

### Output

An `EnrichedContext` object that combines the original `ActionRequest` with all retrieved context. This is the input to all downstream stages.

---

## Stage 4: Drift Detection Engine

The Drift Detection Engine compares the current action's context against the actor's behavioral baseline to produce a `DriftScore`.

### Behavioral baseline model

For each actor, a rolling baseline is maintained over a configurable window (default: 30 days) capturing:

- Mean and standard deviation of risk scores
- Action type distribution (frequency per action category)
- Target system distribution (which systems the actor normally operates on)
- Action velocity (actions per hour, actions per day)
- Privilege level distribution (how often the actor requests elevated vs. standard)

### Drift score calculation

The `DriftScore` is a composite measure with two components:

**Level drift** — A z-score measuring how many standard deviations the current action's estimated risk level is from the actor's baseline mean. Computed as `(current_risk_estimate - baseline_mean) / baseline_stddev`.

**Pattern drift** — A categorical deviation score measuring how unusual the current action's type, target system, and privilege level are relative to the actor's historical distribution. Computed using Jensen-Shannon divergence over the action type distribution.

The final `DriftScore` is a weighted combination: `0.6 * level_drift + 0.4 * pattern_drift`, normalized to [0, 1].

### Alerting

When `DriftScore > threshold` (default: 2.0 standard deviations for level drift), the engine publishes an async alert to the Alert Publisher — independent of the inline decision. This means a `DriftScore` spike triggers a SIEM event even if the action itself is ultimately allowed.

### Special case: regularity detection

An actor with suspiciously low variance (stddev < 0.5 over 30+ days) is flagged as potentially automated in a way that warrants review. Real humans and healthy automation exhibit natural variance. A perfectly regular action pattern is itself anomalous.

---

## Stage 5: Policy Engine

The Policy Engine evaluates the `EnrichedContext` against a set of policy rules and produces a `PolicyVerdict`.

### Rule evaluation order

Rules are evaluated in strict priority order with short-circuit semantics:

1. **Deny rules** — Hard blocks. If any deny rule matches, the pipeline returns `block` immediately. Deny rules do not produce explanations beyond the matching rule identifier.
2. **Conditional rules** — Context-dependent gates. Evaluated in order. A matching conditional rule may produce `require_review`, `allow_with_logging`, or `block` depending on its configuration and the context values.
3. **Allow rules** — Explicit permits. If no deny or conditional rule has produced a terminal verdict and an allow rule matches, the verdict is `allow`.
4. **Default** — If no rule matches, the default is `require_review`.

### Conflict resolution

When multiple conditional rules match a request, the conflict resolver applies the following precedence:

1. The most restrictive verdict wins (`block` > `require_review` > `allow_with_logging` > `allow`)
2. Among equal verdicts, the more specific rule wins (more field conditions = more specific)
3. If specificity is equal, the rule with the lower lexicographic identifier wins (deterministic tie-breaking)

### Policy definition format

Policies are defined in YAML and loaded into typed Pydantic models at startup. Invalid policy files cause a startup failure, not a runtime error.

```yaml
# policies/deny/ai-agent-security-tools.yaml
id: deny-ai-agent-disable-security-tools
type: deny
description: AI agents cannot autonomously disable security tools
conditions:
  actor_type: ai_agent
  requested_action:
    - disable_endpoint_protection
    - disable_antivirus
    - modify_security_policy
mitre_technique: T1562.001
```

---

## Stage 6: Risk Scoring Engine

The Risk Scoring Engine computes a numeric risk score from four independent scorers. Each scorer returns a `(score: float, signals: list[str])` tuple. Signals are passed to the Explanation Layer.

### Scorers

| Scorer | Weight | Inputs | Examples |
|---|---|---|---|
| Action scorer | 0.30 | `requested_action`, action category taxonomy | Destructive actions score higher; read-only actions score lower |
| Actor scorer | 0.25 | `actor_type`, `AttestationResult`, actor history | AI agents score higher than humans for privileged actions; high block-rate history elevates score |
| Asset scorer | 0.25 | Asset criticality, `sensitivity_level` | Restricted assets score higher; public assets score lower |
| Context scorer | 0.20 | `DriftScore`, maintenance window, action velocity | Outside maintenance window elevates score; high drift elevates score significantly |

### Score bands

| Score range | Band | Default decision influence |
|---|---|---|
| 0.0 – 0.3 | Low | Leans toward `allow` |
| 0.3 – 0.6 | Medium | Leans toward `allow_with_logging` |
| 0.6 – 0.8 | High | Leans toward `require_review` |
| 0.8 – 1.0 | Critical | Leans toward `block` |

The final decision is a combination of the `PolicyVerdict` and the risk band. The policy verdict can override the risk band upward (a high-risk score can escalate an `allow` to `require_review`), but not downward (a low-risk score cannot override a policy `block`).

---

## Stage 7: Decision Engine

The Decision Engine combines the `PolicyVerdict` and `RiskScore` into a final `Decision`.

### Decision matrix

| Policy verdict | Risk band | Final decision |
|---|---|---|
| `block` | any | `block` |
| `require_review` | any | `require_review` |
| `allow_with_logging` | low / medium | `allow_with_logging` |
| `allow_with_logging` | high / critical | `require_review` |
| `allow` | low | `allow` |
| `allow` | medium | `allow_with_logging` |
| `allow` | high | `require_review` |
| `allow` | critical | `block` |
| `default` (no rule match) | any | `require_review` |

---

## Stage 8: Audit Log and Explanation Layer

Every decision is written to the audit log regardless of outcome.

### Audit log entry

```json
{
  "entry_id": "ulid-01HX...",
  "previous_hash": "sha256:abc...",
  "entry_hash": "sha256:def...",
  "timestamp": "2025-03-15T14:32:01.234Z",
  "action_request": { ... },
  "enriched_context_summary": { ... },
  "drift_score": 0.23,
  "policy_verdict": "allow",
  "risk_score": 0.41,
  "risk_signals": [
    "Actor type automation on elevated privilege action: +0.18",
    "Asset sensitivity restricted: +0.25",
    "Within maintenance window: -0.08"
  ],
  "final_decision": "allow_with_logging",
  "explanation": "Action allowed with logging. The automation account deploy-bot-prod requested elevated privilege access to a restricted asset. This is within policy during the active maintenance window, but the asset sensitivity level requires this action be logged for review.",
  "compliance_tags": ["NIST-AC-6", "CIS-CSC-5.4"],
  "safer_alternatives": []
}
```

### Hash chaining

Each entry includes the SHA-256 hash of the previous entry. The chain can be independently verified with the `guardian audit verify` command. A broken chain indicates log tampering.

### Compliance tags

Each decision is tagged with applicable compliance control identifiers at write time. See [`compliance-mapping.md`](compliance-mapping.md).

---

## Data Stores

### Actor Registry

The source of truth for actor identity. Stores registered actor name, type, maximum privilege level, owner, and status (active/suspended/terminated). In Phase 1, this is a YAML file. In Phase 2+, it becomes a database.

### Actor History Store

An append-only event store recording every Guardian decision for every actor. Used by Context Enrichment (history signals) and the Drift Detection Engine (baseline computation).

### Behavioral Baseline Store

Per-actor statistical models computed from the Actor History Store on a rolling basis. Updated by a background job. Stores mean, standard deviation, action type distribution, and velocity statistics.

### Asset Catalog

Stores asset metadata: criticality score, classification, owner, system membership, and whether the asset is subject to special governance rules. In Phase 1, this is a YAML file.

### Maintenance Window Store

Stores scheduled maintenance windows per system as cron-style schedules. Used by Context Enrichment and the Context Scorer.

---

## API

Guardian exposes a FastAPI HTTP API.

### Endpoints

| Method | Path | Description |
|---|---|---|
| `POST` | `/v1/evaluate` | Submit an action request for evaluation |
| `GET` | `/v1/audit/{entry_id}` | Retrieve a specific audit entry |
| `GET` | `/v1/audit/verify` | Verify the audit log hash chain |
| `GET` | `/v1/actors/{actor_name}/profile` | Retrieve actor history and baseline |
| `GET` | `/v1/compliance/posture` | Return current compliance posture summary |

### Example request

```bash
curl -X POST http://localhost:8000/v1/evaluate \
  -H "Content-Type: application/json" \
  -d '{
    "actor_name": "deploy-bot-prod",
    "actor_type": "automation",
    "requested_action": "modify_firewall_rule",
    "target_system": "aws-vpc-prod",
    "target_asset": "sg-0a1b2c3d",
    "privilege_level": "elevated",
    "sensitivity_level": "high",
    "business_context": "Weekly deployment pipeline run",
    "timestamp": "2025-03-15T14:32:00Z"
  }'
```

### Example response

```json
{
  "decision": "allow_with_logging",
  "risk_score": 0.41,
  "drift_score": 0.12,
  "explanation": "Action allowed with logging. ...",
  "entry_id": "01HX...",
  "policy_matched": "conditional-firewall-maintenance-window",
  "safer_alternatives": []
}
```
