# Guardian

> An action governance engine for automated and AI-driven operational systems.

Guardian is a portfolio and research project exploring one of the core infrastructure problems of the AI era: **as automation and AI agents gain the ability to take consequential operational actions, organizations need a control layer that evaluates those actions before they execute.**

Guardian is not a firewall. It is not an IAM system. It is a **behavioral governance layer** — a system that inspects proposed actions in context, evaluates them against organizational policy, detects behavioral drift, and returns a decision with a full audit trail and human-readable explanation.

---

## The Problem

Modern organizations operate across dozens of independent systems — cloud infrastructure, CI/CD pipelines, identity providers, SaaS platforms, and automation workflows. Each enforces policies locally. None understands the organization as a whole.

As AI agents and automation scripts gain operational capabilities, three failure modes emerge that existing tooling cannot address:

| Failure mode | Example | Why existing tools miss it |
|---|---|---|
| Configuration drift | Firewall rule quietly weakened over 30 days | Tools inspect state, not the causal action stream |
| Privilege creep | Automation account accumulates excess permissions | IAM systems grant in isolation, never review the pattern |
| Behavioral anomaly | AI agent goal-drifts after prompt injection | No baseline, no deviation detection, no action-level governance |

Guardian addresses all three by sitting at the action layer — evaluating every proposed operational action before it executes.

---

## Architecture

```
Action Request
      │
      ▼
Identity Attestation       ← Verifies actor against registry (no self-reporting)
      │
      ▼
Context Enrichment         ← Asset criticality, maintenance windows, actor history
      │
      ▼
Drift Detection Engine     ← Behavioral baseline comparison, z-score anomaly detection
      │
      ▼
Policy Engine              ← Deny → Conditional → Allow (short-circuit evaluation)
      │
      ▼
Risk Scoring Engine        ← Action + Actor + Asset + Context + Drift signals
      │
      ▼
Decision Engine            ← Policy verdict × risk band → final decision
      │
      ▼
Audit + Explanation        ← Hash-chained log, human-readable rationale, compliance tags
```

**Decision outputs:** `allow` | `allow_with_logging` | `require_review` | `block`

Full architecture documentation: [`docs/architecture.md`](docs/architecture.md)

---

## Action Request Model

Every action submitted to Guardian carries structured metadata:

```json
{
  "actor_name": "deploy-bot-prod",
  "actor_type": "automation",
  "requested_action": "modify_firewall_rule",
  "target_system": "aws-vpc-prod",
  "target_asset": "sg-0a1b2c3d",
  "privilege_level": "elevated",
  "sensitivity_level": "high",
  "business_context": "Weekly deployment pipeline run",
  "timestamp": "2025-03-15T14:32:00Z"
}
```

---

## Scenario Library

Guardian ships with a library of documented action scenarios covering the full decision space. Examples:

- `ai-agent-disables-endpoint-protection` → `block`
- `automation-modifies-firewall-during-maintenance` → `allow_with_logging`
- `automation-escalates-privileges` → `require_review`
- `human-exports-sensitive-data-after-hours` → `require_review`
- `ai-agent-privilege-creep-over-30-days` → behavioral drift detection
- `compromised-account-anomaly-spike` → behavioral drift detection

Full scenario library: [`scenarios/`](scenarios/)

---

## Project Phases

| Phase | Name | Status |
|---|---|---|
| 0 | Foundation — repo, docs, scenarios, architecture | In progress |
| 1 | Prototype — action model, policy engine, risk scoring, audit log | Planned |
| 2 | Contextual intelligence — asset criticality, maintenance windows, actor history | Planned |
| 2.5 | Drift detection — behavioral baseline store, anomaly scoring | Planned |
| 3 | Explanation layer — human-readable rationale, safer alternatives | Planned |
| 4 | Demo interface — decision dashboard | Planned |
| 5 | Compliance intelligence — NIST/SOC2 control mapping, posture reporting | Planned |

Full roadmap: [`docs/roadmap.md`](docs/roadmap.md)

---

## Documentation

| Document | Description |
|---|---|
| [`docs/vision.md`](docs/vision.md) | Project vision and core thesis |
| [`docs/architecture.md`](docs/architecture.md) | Full system architecture and component design |
| [`docs/roadmap.md`](docs/roadmap.md) | Phase-by-phase development plan |
| [`docs/threat-model.md`](docs/threat-model.md) | STRIDE threat model for Guardian itself |
| [`docs/decision-semantics.md`](docs/decision-semantics.md) | Formal semantics for each decision output |
| [`docs/compliance-mapping.md`](docs/compliance-mapping.md) | NIST SP 800-53 and CIS control mappings |

---

## Technology Stack

- **Backend:** Python 3.12, FastAPI, Pydantic v2
- **Storage:** SQLite (dev) / Redis (production baseline store)
- **Policy definitions:** YAML with typed Pydantic validation
- **Audit log:** Append-only JSON with SHA-256 hash chaining
- **Testing:** pytest with adversarial test scenarios

---

## Design Principles

**Deny wins.** Policy evaluation is short-circuit: deny rules evaluate first and halt immediately on match. This is a security property, not a performance optimization.

**Context over metadata.** Guardian never trusts self-reported actor claims. Identity is verified independently. Behavioral history informs every evaluation.

**Explanation is mandatory.** Every decision produces a human-readable rationale. "Blocked" is not an answer. "Blocked because actor type `automation` is prohibited from modifying security group rules on assets classified `high-sensitivity` outside a defined maintenance window" is.

**The audit log is a security artifact.** Hash-chained, append-only, tamper-evident. The audit log can be independently verified. An unverifiable audit log is not an audit log.

**Guardian itself has a threat model.** See [`docs/threat-model.md`](docs/threat-model.md).

---

## Status

This is a learning and portfolio project. It is not production software. The goal is to demonstrate systems thinking at the intersection of cybersecurity, AI security, automation governance, and infrastructure control layers.
