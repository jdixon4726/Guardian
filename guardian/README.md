# Guardian

**Behavioral governance engine for machine identities.**

Guardian evaluates automated operational actions *before* they execute. It answers the question that IAM, OPA, and SIEM cannot: **"Is this automated action normal for this actor, in this context, right now, given the chain of automation that led to it?"**

Guardian is not a firewall, not a SIEM, not a policy engine. It is a **behavioral intelligence layer** that plugs into existing enforcement points (Terraform Cloud, Kubernetes, CI/CD) and provides pre-execution governance with a full audit trail, behavioral anomaly detection, and a causal decision graph that maps how automation flows across your organization.

---

## How It Works

```
Action Request (from Terraform, K8s, CI/CD, or direct API call)
      |
      v
 1. Identity Attestation        - Verify actor against registry (no self-reporting)
 2. Context Enrichment          - Asset criticality, maintenance windows, actor history
 3. Behavioral Assessment       - Trust trajectory, drift detection, peer group analysis
 4. Policy Evaluation           - Deny > Conditional > Allow (pluggable: built-in or OPA)
 5. Risk Scoring                - Action + Actor + Asset + Context signals
 6. Decision Engine             - Policy verdict x risk band = final decision
 7. Audit Log                   - Hash-chained, tamper-evident, with compliance tags
 8. Actor History               - Trust and velocity tracking (append-only)
 9. Alert Publisher             - Drift alerts (fire-and-forget)
10. Decision Graph              - Cascade detection, blast radius tracking
      |
      v
Decision: ALLOW | ALLOW_WITH_LOGGING | REQUIRE_REVIEW | BLOCK
```

**Decision precedence:** deny always wins. Risk can escalate a decision but never override a deny. The system never defaults to automatic allow.

---

## Key Capabilities

### Behavioral Intelligence (the differentiator)
- **Bayesian confidence scoring** — Beta-Binomial updating with wide-then-narrow credible intervals. New actors get conservative estimates that sharpen with observation.
- **Peer group analysis** — Actors clustered by behavioral similarity. Anomalies scored relative to peer group norms, not just individual baselines.
- **Multi-dimensional anomaly detection** — 6 dimensions (level drift, pattern drift, velocity, temporal, trust deviation, peer deviation). Requires 2+ dimensions to fire simultaneously, reducing false positives.
- **Archetype baselines** — 6 pre-built profiles (Terraform runner, GitHub Actions, ArgoCD, Datadog, K8s controller, AI agent) provide day-one value without training data.

### Decision Graph
- **Cascade detection** — Infers cross-system automation chains from temporal proximity and system correlation. Confidence-scored edges prevent phantom cascades.
- **Blast radius computation** — Direct targets, indirect targets via cascades, critical target count, systems reached.
- **Graph-aware drift** — Scope drift (new targets/systems) and path drift (new automation chains) detected from the graph, not just individual actor metrics.
- **Edge decay and archival** — Stale relationships automatically decay. Old events archive to cold storage.

### Operator Feedback Loop
- Operators submit feedback on decisions: confirmed correct, false positive, false negative, known pattern.
- Feedback adjusts Bayesian priors automatically (false positives loosen, false negatives tighten).
- Known cascade patterns can be suppressed with expiration.

### Security Hardening
- **Signed policy bundles** — HMAC-SHA256 verification prevents config tampering.
- **Hash-chained audit log** — SHA-256 chain with pluggable replication sinks.
- **Adapter-derived identity** — Actor identity resolved from Terraform workspace, K8s ServiceAccount, or direct API with confidence scoring.
- **Reconciliation engine** — Compares external activity logs (CloudTrail/Azure) against Guardian's audit log to detect governance bypass.

---

## No LLMs in the Decision Path

Guardian does not use any LLM or SLM for decision-making. Every decision is deterministic, auditable, and reproducible. The core detection is mathematical: Bayesian statistics, z-scores, Jensen-Shannon divergence, peer group clustering.

**Why:** Putting an LLM in the decision path introduces non-determinism, latency, prompt injection risk, and makes decisions unexplainable to auditors.

**Where LLMs could optionally enhance Guardian (not implemented):**
- Explanation generation — turn risk signals into analyst-readable paragraphs
- Policy authoring assistant — natural language to policy YAML
- Audit log summarization — morning briefing from overnight decisions
- Scenario generation — generate test scenarios from infrastructure descriptions

These would all be offline, advisory, and non-blocking. Guardian works without them.

---

## Quick Start

### Local Development

```bash
# Clone and install
git clone https://github.com/jdixon4726/Guardian.git
cd Guardian/guardian
pip install -e ".[dev]"

# Start the API
uvicorn guardian.api.app:app --reload --port 8000

# Start the dashboard (separate terminal)
cd ui
npm install
npm run dev

# Seed demo data (separate terminal)
python scripts/seed_demo.py

# Open http://localhost:5173
```

### Docker

```bash
docker compose up --build
# Open http://localhost:8000
```

### Run Tests

```bash
# Unit and integration tests (261 tests)
pytest tests/ -v

# Replay test against live API (start the API first)
python scripts/replay_test.py
```

---

## Dashboard

The Guardian dashboard provides 6 views:

| View | Purpose |
|---|---|
| **Command Center** | Real-time decision feed with risk gauges, expandable detail cards, inline feedback |
| **Actor Intelligence** | Behavioral profile, trust vs. peer group, scope drift, blast radius, AI Analyst-style insight narratives |
| **Automation Graph** | Interactive force-directed graph of actors, systems, and cascade chains (Cytoscape.js) |
| **Blast Radius** | Direct/indirect/critical target counts, cascade chain visualization |
| **Feedback & Accuracy** | False positive rate, accuracy tracking, Bayesian prior adjustment table |
| **Reconciliation** | Governed vs. ungoverned action coverage, bypass detection |

Light and dark mode. Auto-refresh on all views.

---

## API Endpoints

| Method | Endpoint | Purpose |
|---|---|---|
| POST | `/v1/evaluate` | Submit an action request for governance evaluation |
| GET | `/v1/decisions/recent` | Query recent decisions (filterable by actor, decision type) |
| GET | `/v1/actors/{name}/profile` | Actor trust, velocity, history, top actions |
| POST | `/v1/decisions/{id}/feedback` | Submit operator feedback on a decision |
| GET | `/v1/feedback/stats` | Aggregate feedback statistics and false positive rate |
| GET | `/v1/feedback/prior-adjustments` | Bayesian prior adjustments from accumulated feedback |
| GET | `/v1/graph/actor/{id}/blast-radius` | Compute blast radius (direct + indirect + cascades) |
| GET | `/v1/graph/cascades` | Find multi-hop automation cascades |
| GET | `/v1/graph/actor/{id}/targets` | All targets an actor has affected |
| GET | `/v1/graph/target/{id}/actors` | All actors that affect a target |
| GET | `/v1/graph/actor/{id}/scope-drift` | Detect new targets/systems (graph-aware drift) |
| GET | `/v1/graph/actor/{id}/path-drift` | Detect new automation chains |
| GET | `/v1/graph/stats` | Graph node/edge/event counts |
| GET | `/v1/audit/verify` | Verify audit log hash chain integrity |
| GET | `/v1/reconciliation/report` | Detect ungoverned infrastructure actions |
| GET | `/v1/health` | Deep health check (pipeline, stores, policy engine) |

All endpoints support optional API key authentication via `Authorization: Bearer <key>`.

---

## Architecture

```
guardian/
  src/guardian/
    pipeline.py              # 10-stage evaluation orchestrator
    models/                  # ActionRequest, Decision, DriftScore, RiskSignal
    api/                     # FastAPI app, 18 endpoints, dashboard UI
    behavioral/              # Bayesian confidence, peer groups, anomaly, archetypes
    graph/                   # Decision graph: store, builder, models
    feedback/                # Operator feedback store, prior adjustments
    adapters/
      terraform/             # TFC run task adapter (plan mapper, webhook)
      kubernetes/            # K8s admission webhook adapter
      identity.py            # Adapter-derived actor identity resolvers
    config/                  # GuardianConfig (Pydantic), loader, signature verification
    scoring/                 # Configurable risk scoring (4 independent signals)
    decision/                # Policy x risk matrix (4-outcome model)
    drift/                   # Z-score, JS divergence, regularity detection
    policy/                  # Built-in engine + OPA provider protocol
    audit/                   # Hash-chained logger with replication sinks
    history/                 # SQLite actor history, trust, velocity
    reconciliation/          # Bypass detection (CloudTrail/Azure sources)
    jobs/                    # Background baseline recomputation
  config/                    # YAML: guardian.yaml, actor-registry, assets, policies
  policies/                  # Policy rule definitions (deny, conditional, allow)
  tests/                     # 261 tests (unit, integration, adversarial, replay)
  scripts/                   # seed_demo.py, replay_test.py
  ui/                        # React + Vite dashboard (6 views)
  Dockerfile                 # Multi-stage build (Node + Python)
  docker-compose.yaml        # Single-command deployment
```

---

## Configuration

All behavioral thresholds, scoring weights, and policy parameters are externalized to `config/guardian.yaml`:

```yaml
scoring:
  weights: { action: 0.30, actor: 0.25, asset: 0.25, context: 0.20 }

trust:
  window_days: 30
  min_actions: 10
  block_penalty: 0.05

drift:
  z_score_alert_threshold: 2.5
  js_alert_threshold: 0.35

decision:
  risk_bands: { low_max: 0.30, medium_max: 0.60, high_max: 0.80 }
```

Policy rules are YAML files in `policies/` — deny, conditional, and allow rules loaded at startup. Policy changes go through version control, not API calls.

---

## Testing

| Layer | What | How |
|---|---|---|
| Unit/Integration | 261 tests covering all modules | `pytest tests/ -v` |
| Scenario Replay | 15 full-day scenarios with expected decisions | `python scripts/replay_test.py` |
| Adversarial | Policy bypass attempts, attestation spoofing | `pytest tests/adversarial/ -v` |
| Demo Seeding | 29 realistic evaluations + feedback | `python scripts/seed_demo.py` |

---

## Design Principles

**Deny wins.** Policy evaluation short-circuits on deny. This is a security property.

**No LLMs in the decision path.** Every decision is deterministic and auditable.

**Behavioral intelligence is the core.** The policy engine is pluggable (built-in or OPA). Guardian's value is the trust trajectory, drift detection, peer analysis, and decision graph — the things OPA cannot compute.

**Guardian is an advisor, not an enforcer.** It plugs into enforcement points that already exist (Terraform run tasks, K8s admission webhooks, CI/CD gates). Compromising Guardian gives an attacker the ability to say "allow" — not the ability to modify infrastructure.

**The audit log is a security artifact.** Hash-chained, append-only, tamper-evident, independently verifiable.

**Guardian itself has a threat model.** Signed policy bundles, adapter-derived identity, reconciliation for bypass detection, fail-closed enforcement in all adapters.

---

## Technology

- **Backend:** Python 3.12+, FastAPI, Pydantic v2, SQLite (WAL mode)
- **Frontend:** React, Vite, Recharts, Cytoscape.js
- **Policy:** YAML with Pydantic validation, optional OPA/Rego integration
- **Audit:** Append-only JSONL with SHA-256 hash chaining
- **Testing:** pytest (261 tests), httpx for replay testing
- **Deployment:** Docker, docker-compose

---

## What Guardian Is Not

- **Not a SIEM** — Guardian evaluates actions before execution, not after.
- **Not an IAM system** — Guardian doesn't control who *can* act, it evaluates whether they *should* act right now.
- **Not a policy engine** — OPA does policy better. Guardian complements policy with behavioral intelligence.
- **Not an AI product** — No LLMs in the decision path. Pure math: Bayesian statistics, z-scores, JS divergence.

---

## License

Business Source License 1.1 (BSL 1.1). Free for non-production use and production use that does not compete with Guardian as a hosted service. Converts to Apache 2.0 on 2030-03-16. See [LICENSE](../LICENSE) for details.
