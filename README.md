# Guardian

**Runtime governance and privilege control for AI agents and automation identities at the action layer.**

Guardian evaluates automated actions *before* they execute. It answers the question that IAM, policy engines, and SIEMs cannot:

> *"Is this action normal for this actor, in this context, right now, given the chain of automation that led to it?"*

[![Live Demo](https://img.shields.io/badge/Live_Demo-guardian--np0a.onrender.com-blue)](https://guardian-np0a.onrender.com)
[![Tests](https://img.shields.io/badge/tests-407_passing-brightgreen)]()
[![Adapters](https://img.shields.io/badge/adapters-9_platforms-orange)]()
[![License](https://img.shields.io/badge/license-BSL_1.1-yellow)](LICENSE)

---

## The Problem

A compromised credential + a legitimate management tool = catastrophic damage.

**March 2026:** An attacker stole an Intune Global Admin credential and used Microsoft's own Remote Wipe feature to factory-reset 200,000+ devices across 79 countries. No malware. No zero-day. Just a legitimate API call that RBAC said was "allowed."

Traditional security tools couldn't stop it:
- **IAM** said the credential was valid
- **Policy engines (OPA)** said the admin had permission
- **SIEM** detected it after 80,000 devices were already wiped

Guardian would have stopped it at device #6. Here's how:

1. **Identity attestation** — The rogue admin account wasn't in Guardian's actor registry. Blocked immediately.
2. **Behavioral scoring** — Even if using a known account, "wipe 200,000 devices" scores 0.90+ risk (destructive + restricted + admin). Requires human review.
3. **Circuit breaker** — After 5 destructive actions in 1 minute, all subsequent wipes are auto-denied regardless of individual scores.

[See the full Stryker simulation →](guardian/simulator/scenarios/intune_mass_wipe.json)

---

## How It Works

```
Action Request (Terraform, K8s, Intune, GitHub, AWS, MCP, A2A, or direct API)
      │
      ▼
 1. Identity Attestation      — Verify actor against registry
 2. Context Enrichment        — Asset criticality, maintenance windows, velocity
 3. Behavioral Assessment     — Bayesian trust, drift detection, peer groups
 4. Policy Evaluation         — Deny > Conditional > Allow (built-in or OPA)
 5. Risk Scoring              — Action + Actor + Asset + Context (weighted)
 5.5 Threat Intel Overlays    — CISA KEV risk adjustments (can only raise, never lower)
 5.5 Graph Cascade Context    — Actor's recent anomalous history informs scoring
 6. Decision Engine           — Policy × risk band → final decision
 7. Audit Log                 — SHA-256 hash-chained + HMAC signed
 8–10. History, Alerts, Graph — Trust tracking, drift alerts, cascade detection
      │
      ▼
Decision: ALLOW | ALLOW_WITH_LOGGING | REQUIRE_REVIEW | BLOCK
```

**No LLMs in the decision path.** Every decision is deterministic Bayesian math — auditable, explainable, reproducible. EU AI Act compliant by design.

---

## Adapters (9 platforms, 4 integration patterns)

| Adapter | Pattern | What It Governs |
|---|---|---|
| **Terraform Cloud** | Async callback | Infrastructure plan/apply (run task webhook) |
| **Kubernetes** | Admission webhook | Pod/deployment/secret/RBAC operations |
| **Microsoft Intune** | API proxy | Device wipe, retire, delete, passcode reset |
| **Entra ID (Azure AD)** | API proxy | Role assignments, conditional access, federation, MFA |
| **Jamf Pro** | API proxy | Apple MDM: EraseDevice, WipeComputer, DeleteMobile |
| **GitHub Actions** | Deployment gate | Deployment protection rules (approve/deny) |
| **AWS EventBridge** | Event-driven | CloudTrail events: IAM, EC2, S3, RDS, KMS, GuardDuty |
| **MCP** | Protocol-layer | AI agent tool calls (any framework: CrewAI, LangGraph, OpenClaw) |
| **A2A** | Protocol-layer | Agent-to-agent task delegations (delegation chain tracking) |

**Integration patterns:**
1. **Synchronous proxy** — Guardian sits between caller and API, forwards or blocks (Intune, Entra ID, Jamf)
2. **Admission webhook** — Platform sends request, Guardian responds allow/deny (K8s, Terraform)
3. **Event-driven** — Guardian evaluates post-execution, recommends quarantine (AWS EventBridge)
4. **Protocol-layer** — Guardian intercepts MCP tool calls and A2A delegations at the agent protocol boundary

---

## Key Capabilities

### Behavioral Intelligence
- **Bayesian Beta-Binomial trust** — Wide credible intervals for new actors, narrowing with observation
- **Drift detection** — Z-score velocity anomaly + Jensen-Shannon divergence pattern drift
- **Peer group analysis** — Anomalies scored relative to peer group norms
- **Archetype baselines** — Day-one profiles for Terraform, GitHub Actions, ArgoCD, K8s, AI agents

### Circuit Breaker
- Per-actor sliding-window rate limiter for destructive actions
- Configurable thresholds (default: 5/minute, 20/hour)
- Persists across process restarts (SQLite-backed)
- The feature that stops Stryker-style mass-action attacks

### Threat Intelligence
- CISA KEV feed sync with schema validation
- Risk overlays: advisory adjustments that can only **raise** risk, never lower it
- 7 anti-poisoning invariants (max +0.20 per overlay, +0.30 combined, human review gate)
- MITRE ATT&CK technique-to-action mapping

### Decision Graph
- Cross-system automation cascade detection
- Blast radius computation (direct targets, indirect, critical, systems reached)
- Graph context feeds into risk scoring — actors with anomalous history get elevated risk

### Audit & Compliance
- SHA-256 hash-chained audit log (tamper-evident)
- HMAC-SHA256 signed entries (non-repudiation)
- NIST SP 800-53, SOC 2 AI criteria, EU AI Act alignment
- Full operator feedback loop with Bayesian prior adjustment

---

## Event Replay Simulator

Guardian includes an event replay engine that feeds real-world attack scenarios through the full pipeline.

**11 scenarios, 123 events:**

| Scenario | Events | Source Incident |
|---|---|---|
| Intune Mass Wipe | 18 | Stryker/Handala (March 2026) |
| Terraform Destroy | 10 | Compromised CI/CD token |
| SolarWinds SUNBURST | 8 | APT29 build pipeline (2020) |
| Uber Identity Takeover | 12 | Lapsus$ MFA fatigue (2022) |
| BGP Route Hijack | 8 | Cloudflare 1.1.1.1 (June 2024) |
| CI/CD Secret Leak | 8 | tj-actions supply chain (March 2025) |
| IAM Privilege Escalation | 17 | EMERALDWHALE credential theft |
| AWS Credential Compromise | 9 | Cloud lateral movement playbook |
| GitHub Supply Chain | 5 | Workflow injection attack |
| Stryker Wiper (original) | 15 | Full Handala attack reconstruction |
| OpenClaw Rogue Agent | 13 | Prompt injection → mass deletion |

Run locally:
```bash
cd guardian
python -c "
from guardian.simulator import Simulator
sim = Simulator.from_config()
report = sim.run_scenario('simulator/scenarios/intune_mass_wipe.json')
print(report.summary())
"
```

---

## Dashboard

7 views, live at [guardian-np0a.onrender.com](https://guardian-np0a.onrender.com):

- **Command Center** — Real-time decision feed, severity triage, system status, connected adapters, risk pulse waveform
- **Actor Intelligence** — Behavioral profile, trust computation breakdown, activity timeline, pattern of life, scope drift
- **Automation Graph** — Cross-system automation chains (Cytoscape), cascade visualization
- **Blast Radius** — Operational impact measurement, trust boundary crossing
- **Threat Intelligence** — CISA KEV sync, overlay management (approve/reject), MITRE ATT&CK coverage
- **Feedback & Accuracy** — Decision accuracy tracking, Bayesian prior adjustments
- **Reconciliation** — Detect actions that bypassed Guardian governance

Design: Darktrace intelligence aesthetics + Apple Human Interface Guidelines. Glass-morphism, spring-physics animations, SF Pro-inspired typography, 8pt spacing grid.

---

## Quickstart

### Run locally

```bash
git clone https://github.com/jdixon4726/Guardian.git
cd Guardian/guardian
pip install -e ".[dev]"
python -m pytest tests/  # 407 tests
uvicorn guardian.api.app:app --reload  # http://localhost:8000
```

### Run with Docker

```bash
cd Guardian/guardian
docker compose up --build  # http://localhost:8000
```

### Deploy to Render

The repo includes a `render.yaml` blueprint. Connect the repo to Render and it auto-deploys with:
- Auto-generated API key and audit signing key
- Persistent disk for SQLite databases
- Health check on `/v1/health`

---

## API

43 endpoints. Interactive docs at `/docs` (auto-generated by FastAPI).

### Core

| Method | Endpoint | Description |
|---|---|---|
| POST | `/v1/evaluate` | Submit an action request for governance evaluation |
| GET | `/v1/decisions/recent` | Query recent decisions (filter by actor, decision type) |
| GET | `/v1/actors/{name}/profile` | Actor behavioral profile, trust level, velocity |
| GET | `/v1/audit/verify` | Verify audit log hash chain integrity |

### Adapters

| Method | Endpoint | Description |
|---|---|---|
| POST | `/v1/intune/device-action` | Intune device management proxy |
| POST | `/v1/entra-id/admin-action` | Entra ID admin operation proxy |
| POST | `/v1/jamf/device-command` | Jamf Pro MDM command proxy |
| POST | `/v1/kubernetes/admit` | K8s admission webhook |
| POST | `/v1/terraform/run-task` | Terraform Cloud run task callback |
| POST | `/v1/github/deployment-gate` | GitHub deployment protection rule |
| POST | `/v1/aws/evaluate-event` | CloudTrail event evaluation |
| POST | `/v1/mcp/evaluate-tool-call` | MCP tool call governance |
| POST | `/v1/a2a/evaluate-delegation` | A2A agent delegation governance |

### Threat Intelligence

| Method | Endpoint | Description |
|---|---|---|
| POST | `/v1/threat-intel/sync` | Sync CISA KEV feed |
| GET | `/v1/threat-intel/overlays` | List risk overlays |
| POST | `/v1/threat-intel/overlays/{id}/activate` | Approve overlay |
| POST | `/v1/threat-intel/overlays/{id}/reject` | Reject overlay |

### Observability

| Method | Endpoint | Description |
|---|---|---|
| GET | `/metrics` | Prometheus text exposition format |
| GET | `/v1/system/status` | System observability metrics |
| GET | `/v1/systems/connected` | Connected adapter status |
| GET | `/v1/health` | Deep health check |

---

## Architecture

```
guardian/
├── src/guardian/
│   ├── api/app.py              # FastAPI app, 43 endpoints
│   ├── pipeline.py             # 10-stage evaluation pipeline
│   ├── adapters/               # 9 platform adapters
│   │   ├── terraform/          #   Async callback pattern
│   │   ├── kubernetes/         #   Admission webhook pattern
│   │   ├── intune/             #   API proxy pattern
│   │   ├── entra_id/           #   API proxy pattern
│   │   ├── jamf/               #   API proxy pattern
│   │   ├── github_actions/     #   Deployment gate pattern
│   │   ├── aws_eventbridge/    #   Event-driven pattern
│   │   ├── mcp/                #   Protocol-layer (agent tools)
│   │   └── a2a/                #   Protocol-layer (agent delegation)
│   ├── behavioral/             # Bayesian trust, peer groups, anomaly detection
│   ├── drift/                  # Z-score + Jensen-Shannon drift detection
│   ├── scoring/                # 4-dimension risk scoring engine
│   ├── decision/               # Policy × risk band decision matrix
│   ├── circuit_breaker/        # Per-actor destructive action rate limiter
│   ├── threat_intel/           # CISA KEV feed, risk overlays, anti-poisoning
│   ├── graph/                  # Decision graph, cascade detection, blast radius
│   ├── audit/                  # Hash-chained + HMAC-signed audit logger
│   ├── attestation/            # Identity verification against actor registry
│   ├── enrichment/             # Asset catalog, maintenance windows
│   ├── policy/                 # Rule engine (deny > conditional > allow)
│   ├── history/                # Actor trust and velocity tracking
│   ├── simulator/              # Event replay engine
│   └── observability.py        # Prometheus metrics, structured logging
├── config/                     # guardian.yaml, actor registry, asset catalog
├── policies/                   # Policy rules (YAML)
├── scenarios/                  # Attack scenario files (JSON)
├── simulator/scenarios/        # Additional scenario files
├── ui/                         # React dashboard (Vite + Cytoscape + Recharts)
├── tests/                      # 407 tests (unit + integration + simulation)
├── Dockerfile                  # Multi-stage build (Node + Python)
└── docker-compose.yaml
```

---

## What Guardian Is Not

- **Not a firewall.** Guardian doesn't block network traffic.
- **Not a SIEM.** Guardian evaluates *before* execution, not after.
- **Not a policy engine.** Guardian complements OPA — it provides behavioral context that policy engines can't compute.
- **Not an identity provider.** Guardian consumes identity from adapters (Azure AD, K8s ServiceAccount, Terraform workspace).
- **Not an LLM.** Every decision is deterministic math. No prompt injection surface. No hallucination risk.

---

## License

Business Source License 1.1 — see [LICENSE](LICENSE) for details.
