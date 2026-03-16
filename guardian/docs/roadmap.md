# Roadmap

## Phase 0 — Foundation
*Goal: Establish project structure, documentation, and scenario library before writing application code.*

- [x] Repository structure
- [x] README
- [x] Vision document
- [x] Architecture document
- [ ] Threat model document
- [ ] Decision semantics document
- [ ] Compliance mapping document
- [ ] Scenario library (15+ documented scenarios)
- [x] Actor registry schema (YAML)
- [x] Asset catalog schema (YAML)
- [x] Maintenance window schema (YAML)

**Deliverable:** A fully documented system that a security engineer can read and evaluate before any code exists.

---

## Phase 1 — Prototype
*Goal: End-to-end working pipeline for the three core scenarios.*

**Core three scenarios that must pass:**
1. AI agent requests to disable endpoint protection → `block`
2. Automation modifies firewall rule during maintenance window → `allow_with_logging`
3. Automation account requests privilege escalation → `require_review`

**Components:**
- [x] `ActionRequest` Pydantic model with full field validation
- [x] `ActorType`, `PrivilegeLevel`, `SensitivityLevel` enums
- [x] Identity Attestation with YAML-backed actor registry
- [x] Policy Engine with deny/conditional/allow rule loading from YAML
- [x] Four initial deny rules (AI agent security tool access, etc.)
- [x] Risk Scoring Engine with four scorers (action, actor, asset, context)
- [x] Decision Engine with policy × risk matrix
- [x] Audit Logger with SHA-256 hash chaining
- [x] `POST /v1/evaluate` FastAPI endpoint
- [x] Unit tests for each component
- [x] Adversarial tests (policy bypass attempts)

**Deliverable:** A running API that evaluates action requests and returns decisions with full audit trail.

---

## Phase 2 — Contextual Intelligence
*Goal: Move from static evaluation to context-aware evaluation.*

- [x] Asset Catalog with criticality scoring (YAML-backed)
- [x] Maintenance Window Store with cron-schedule parsing
- [x] Actor History Store (SQLite, append-only)
- [x] Actor trust level model (new actors start lower-trust; trust builds over time)
- [x] Action velocity tracking (actions per hour, per day)
- [x] Context Scorer updated with maintenance window and velocity signals
- [x] `GET /v1/actors/{actor_name}/profile` endpoint

**Deliverable:** Decisions that meaningfully change based on time, asset context, and actor history.

---

## Phase 2.5 — Drift Detection
*Goal: Detect behavioral anomalies that rule-based systems cannot see.*

- [x] Behavioral Baseline Store (SQLite, per-actor rolling statistics)
- [x] Background job to recompute baselines hourly
- [x] Level drift scoring (z-score against baseline mean)
- [x] Pattern drift scoring (JS divergence over action type distribution)
- [x] Composite `DriftScore` model
- [x] Alert Publisher (async, log-based in Phase 2.5; webhook in Phase 3+)
- [x] Regularity detection (low variance flagging)
- [x] Drift score integrated into Risk Scoring Engine (Context Scorer)
- [x] Fixture-based tests for four drift scenarios:
  - Normal actor (no drift expected)
  - Privilege creep (gradual score elevation)
  - Compromise event (abrupt spike)
  - AI anomaly (regularity then escalation)

**Deliverable:** Behavioral drift detection that fires on the three adversarial fixture scenarios.

---

## Phase 3 — Architecture Refocus
*Goal: Position behavioral intelligence as the core, with pluggable policy and real-world integration.*

- [x] Configurable `guardian.yaml` master config — externalize all hardcoded values
- [x] `PolicyProvider` protocol — abstract interface for policy evaluation backends
- [x] OPA policy provider adapter (queries external OPA instance via HTTP)
- [x] `BehavioralIntelligenceEngine` — consolidate drift, trust, velocity into single `assess()` call
- [x] `BehavioralAssessment` as first-class return type (trust, drift, velocity, anomaly flag)
- [x] Pipeline restructured: behavioral assessment computed before policy, injected into policy context
- [x] Terraform Cloud run task adapter — plan-to-ActionRequest mapper, webhook router
- [x] Terraform resource type mappings (YAML-configurable)
- [x] 148 tests passing (15 new Terraform mapper + 8 config loader tests)

**Deliverable:** Guardian positioned as a behavioral governance layer that plugs into Terraform Cloud (and OPA) rather than replacing existing policy engines.

---

## Phase 4 — Explanation Layer
*Goal: Make every decision understandable to a non-technical reviewer.*

- [ ] Template-based explanation generation (policy rule → human sentence)
- [ ] Risk signal narrative assembly ("Actor type X on action Y on asset Z contributed +0.18 to risk score")
- [ ] Safer alternative suggestions for blocked/review actions
- [ ] Drift event explanation ("This actor's behavior has deviated 3.2σ from their 30-day baseline")
- [ ] Explanation included in audit log and API response

**Deliverable:** Every decision produces a paragraph a security analyst can act on without reading source code.

---

## Phase 5 — Demo Interface
*Goal: Visual demonstration of Guardian's capabilities.*

- [ ] Decision feed — live stream of recent decisions with risk scores and outcomes
- [ ] Actor profile view — timeline of actor behavior with baseline overlay
- [ ] Drift alert view — behavioral anomalies with explanation
- [ ] Audit log viewer with hash chain verification indicator
- [ ] Scenario simulator — submit pre-built scenarios and watch them evaluate

**Deliverable:** A dashboard suitable for a portfolio demo that makes Guardian's value immediately legible.

---

## Phase 6 — Compliance Intelligence
*Goal: Transform the audit log into a continuous compliance posture report.*

- [ ] Compliance Mapper: tag each decision with NIST SP 800-53 and CIS CSC control identifiers at write time
- [ ] Policy rule → control mapping file (YAML)
- [ ] `GET /v1/compliance/posture` endpoint: control-by-control summary of recent decisions
- [ ] Compliance drift detection: alert when a control's block/review rate changes significantly
- [ ] Export: generate compliance evidence report for a specified time window

**Deliverable:** A posture endpoint that produces SOC2-legible evidence summaries from Guardian's operational log.

---

## Future Directions

**Kubernetes admission webhook** — intercept pod creation and modification requests for governance evaluation. Second real-world integration point after Terraform.

**CI/CD pipeline adapter** — GitHub Actions / GitLab CI events translated to ActionRequests, enabling governance gates on deployments and infrastructure changes.

**Policy bundle signature verification** — GPG/cosign-signed config bundles verified at startup. Ensures config integrity in the deployment pipeline.

**Learned risk model** — replace the weighted scorer with a gradient-boosted classifier trained on the synthetic scenario library, with SHAP values for interpretability.

**Multi-agent trust boundary enforcement** — formalize the rules for how Agent A can request elevated trust for Agent B, with explicit delegation chains and time-bounded grants.

**Policy conflict detection** — static analysis tool that identifies policy rules that contradict each other before they reach the runtime engine.
