"""
Compliance Framework Mappings

Maps NIST 800-53, HIPAA, FISMA, FedRAMP, EU AI Act, and SOC 2
control requirements to specific Guardian capabilities.

Each control maps to:
  - The Guardian feature that satisfies it
  - The evidence source (audit log, pipeline stage, config)
  - The verification method (hash chain, API endpoint, report)
"""

from __future__ import annotations

from dataclasses import dataclass, field


@dataclass
class ControlMapping:
    """Maps a regulatory control to a Guardian capability."""
    control_id: str             # e.g., "AC-2", "164.312(a)(1)"
    control_name: str           # human-readable name
    framework: str              # NIST-800-53, HIPAA, etc.
    family: str                 # control family (Access Control, Audit, etc.)
    guardian_capability: str    # what Guardian does to satisfy this
    evidence_source: str        # where the evidence lives
    verification: str           # how to verify compliance
    automated: bool = True      # can Guardian verify this automatically?


# ── NIST SP 800-53 Rev 5 ─────────────────────────────────────────────────────

NIST_800_53: list[ControlMapping] = [
    # Access Control (AC)
    ControlMapping(
        "AC-2", "Account Management", "NIST-800-53", "Access Control",
        "Actor registry with status tracking. Terminated actors blocked at identity attestation.",
        "Actor registry YAML + audit log (attestation failures)",
        "GET /v1/actors/{name}/profile — verify status and trust level",
    ),
    ControlMapping(
        "AC-2(4)", "Automated Audit Actions", "NIST-800-53", "Access Control",
        "Every action evaluation produces a hash-chained, HMAC-signed audit entry with actor, action, decision, risk score, and compliance tags.",
        "Audit log (JSONL) + hash chain verification",
        "GET /v1/audit/verify — cryptographic hash chain validation",
    ),
    ControlMapping(
        "AC-3", "Access Enforcement", "NIST-800-53", "Access Control",
        "Pre-execution evaluation: actions are blocked or require review before execution. Deny rules cannot be overridden by risk score.",
        "Pipeline Stage 6 (Decision Engine) + audit log",
        "Audit log entries with decision=block show enforcement",
    ),
    ControlMapping(
        "AC-6", "Least Privilege", "NIST-800-53", "Access Control",
        "Privilege level validation against actor registry max_privilege_level. Privilege escalation attempts flagged and scored.",
        "Identity attestation (Stage 1) + risk scoring (Stage 5)",
        "GET /v1/actors/{name}/profile — check max_privilege_level",
    ),
    ControlMapping(
        "AC-6(9)", "Log Use of Privileged Functions", "NIST-800-53", "Access Control",
        "All privileged actions (elevated/admin) are logged with privilege_level, risk score, and NIST-AC-6 compliance tag.",
        "Audit log — entries with privilege_level != 'standard'",
        "Filter audit log for compliance_tags containing NIST-AC-6",
    ),
    # Audit and Accountability (AU)
    ControlMapping(
        "AU-2", "Event Logging", "NIST-800-53", "Audit and Accountability",
        "Every action evaluation is logged: actor, action, target, decision, risk score, drift score, timestamp, hash chain.",
        "Audit log (JSONL) — append-only, never modified",
        "GET /v1/decisions/recent — verify events are being logged",
    ),
    ControlMapping(
        "AU-3", "Content of Audit Records", "NIST-800-53", "Audit and Accountability",
        "Each audit entry contains: actor identity, action type, target asset, target system, decision outcome, risk score, drift score, policy matched, explanation, compliance tags, timestamp, hash chain.",
        "Audit log entry schema",
        "Examine any audit log entry for required fields",
    ),
    ControlMapping(
        "AU-8", "Time Stamps", "NIST-800-53", "Audit and Accountability",
        "All timestamps in UTC ISO 8601 format. Evaluation timestamp recorded at decision time.",
        "evaluated_at field in every audit entry",
        "Compare audit timestamps against NTP-synced system clock",
    ),
    ControlMapping(
        "AU-9", "Protection of Audit Information", "NIST-800-53", "Audit and Accountability",
        "SHA-256 hash chain prevents tampering. HMAC-SHA256 signatures provide non-repudiation. Append-only log cannot be modified without breaking the chain.",
        "Hash chain + HMAC signatures in audit log",
        "GET /v1/audit/verify — automated chain verification",
    ),
    ControlMapping(
        "AU-10", "Non-repudiation", "NIST-800-53", "Audit and Accountability",
        "HMAC-SHA256 signed audit entries with GUARDIAN_AUDIT_SIGNING_KEY. Each entry is cryptographically bound to the signing key.",
        "entry_signature field in audit entries",
        "Verify HMAC signature against signing key",
    ),
    ControlMapping(
        "AU-12", "Audit Record Generation", "NIST-800-53", "Audit and Accountability",
        "Audit records generated automatically for every evaluation. No manual intervention required. Fail-closed: if audit write fails, the decision is still logged in-memory.",
        "Pipeline Stage 7 (Audit Logger)",
        "GET /v1/system/status — verify events_ingested > 0",
    ),
    # Identification and Authentication (IA)
    ControlMapping(
        "IA-2", "Identification and Authentication", "NIST-800-53", "Identification and Authentication",
        "Identity attestation verifies actor against the actor registry before any evaluation. Unregistered actors are blocked with risk score 1.0.",
        "Pipeline Stage 1 (Identity Attestation)",
        "Audit log entries with decision=block and NIST-IA-2 tag",
    ),
    ControlMapping(
        "IA-8", "Identification and Authentication (Non-Org Users)", "NIST-800-53", "Identification and Authentication",
        "Adapter-derived identity resolution. Each adapter extracts actor identity from platform authentication (Azure AD JWT, K8s ServiceAccount, TFC workspace). Direct API callers get 0.5 confidence.",
        "Identity resolvers per adapter",
        "Check identity confidence in actor profile",
    ),
    # Risk Assessment (RA)
    ControlMapping(
        "RA-3", "Risk Assessment", "NIST-800-53", "Risk Assessment",
        "Continuous, automated risk assessment for every action. 4-dimension scoring: action risk + actor risk + asset risk + context risk. Behavioral drift detection provides ongoing risk monitoring.",
        "Pipeline Stage 5 (Risk Scoring Engine)",
        "GET /v1/decisions/recent — risk_score field on every decision",
    ),
    ControlMapping(
        "RA-5", "Vulnerability Monitoring and Scanning", "NIST-800-53", "Risk Assessment",
        "CISA KEV threat feed integration. Automatic risk overlay creation for known exploited vulnerabilities. Anti-poisoning controls prevent feed manipulation.",
        "Threat intelligence overlays",
        "GET /v1/threat-intel/overlays — active threat overlays",
    ),
    # System and Information Integrity (SI)
    ControlMapping(
        "SI-4", "System Monitoring", "NIST-800-53", "System and Information Integrity",
        "Continuous behavioral monitoring via drift detection (z-score + Jensen-Shannon divergence). Anomalous behavior triggers alerts and risk score elevation.",
        "Pipeline Stage 3 (Behavioral Assessment) + drift alerts",
        "GET /v1/actors/{name}/profile — drift_score and trust_level",
    ),
    ControlMapping(
        "SI-4(5)", "System-Generated Alerts", "NIST-800-53", "System and Information Integrity",
        "Automated drift alerts when actor behavior deviates from baseline. Circuit breaker trips on mass destructive actions. Both generate logged alerts.",
        "Drift alert log + circuit breaker trip log",
        "GET /v1/system/status — check for active alerts",
    ),
]

# ── HIPAA Security Rule ──────────────────────────────────────────────────────

HIPAA: list[ControlMapping] = [
    ControlMapping(
        "164.312(a)(1)", "Access Control", "HIPAA", "Technical Safeguards",
        "Pre-execution evaluation blocks unauthorized actions. Actor registry enforces least privilege. Circuit breaker prevents mass data access.",
        "Pipeline decision engine + actor registry",
        "Audit log showing blocked unauthorized access attempts",
    ),
    ControlMapping(
        "164.312(b)", "Audit Controls", "HIPAA", "Technical Safeguards",
        "Hash-chained, HMAC-signed audit log records every action evaluation. Tamper-evident design ensures audit integrity.",
        "Audit log with hash chain verification",
        "GET /v1/audit/verify",
    ),
    ControlMapping(
        "164.312(c)(1)", "Integrity Controls", "HIPAA", "Technical Safeguards",
        "Audit log integrity via SHA-256 hash chain. Policy bundles verified via HMAC-SHA256 signatures. Configuration tampering detected at startup.",
        "Hash chain + bundle signature verification",
        "GET /v1/audit/verify + startup signature check",
    ),
    ControlMapping(
        "164.312(d)", "Person or Entity Authentication", "HIPAA", "Technical Safeguards",
        "Adapter-derived identity authentication. Azure AD JWT verification for Intune/Entra ID. K8s ServiceAccount verification. mTLS support for service-to-service auth.",
        "Identity resolvers + mTLS configuration",
        "Check identity confidence and authentication source",
    ),
    ControlMapping(
        "164.312(e)(1)", "Transmission Security", "HIPAA", "Technical Safeguards",
        "TLS required for all API communication. mTLS option for enterprise deployments. Bearer token or certificate-based authentication.",
        "API authentication configuration",
        "Verify TLS certificate and auth method",
    ),
    ControlMapping(
        "164.308(a)(1)(ii)(D)", "Information System Activity Review", "HIPAA", "Administrative Safeguards",
        "Dashboard provides real-time visibility: Command Center (decision feed), Actor Intelligence (behavioral profiles), Reconciliation (ungoverned action detection).",
        "Guardian dashboard (7 views)",
        "Access dashboard at deployment URL",
    ),
    ControlMapping(
        "164.308(a)(5)(ii)(C)", "Log-in Monitoring", "HIPAA", "Administrative Safeguards",
        "Actor velocity tracking detects anomalous login/action patterns. Drift detection identifies behavioral deviations from baseline.",
        "Behavioral assessment + velocity tracking",
        "GET /v1/actors/{name}/profile — velocity and drift metrics",
    ),
]

# ── FedRAMP ──────────────────────────────────────────────────────────────────

FEDRAMP: list[ControlMapping] = [
    ControlMapping(
        "CA-7", "Continuous Monitoring", "FedRAMP", "Assessment",
        "Continuous, automated evaluation of every action. Behavioral baselines recomputed hourly. Drift detection runs on every evaluation. Threat intelligence syncs from CISA KEV.",
        "Pipeline + baseline recomputation job + threat intel sync",
        "GET /v1/system/status + /v1/threat-intel/overlays",
    ),
    ControlMapping(
        "IR-4", "Incident Handling", "FedRAMP", "Incident Response",
        "Circuit breaker automatically contains mass-action incidents. Blocked actions generate audit entries with full context for incident investigation.",
        "Circuit breaker + audit log",
        "Review audit log for circuit breaker trip entries",
    ),
    ControlMapping(
        "IR-5", "Incident Monitoring", "FedRAMP", "Incident Response",
        "Real-time decision feed (Command Center), actor behavioral profiles, automation cascade graph, blast radius computation.",
        "Dashboard + /v1/decisions/recent + /v1/graph/cascades",
        "Dashboard Command Center view",
    ),
]

# ── EU AI Act ────────────────────────────────────────────────────────────────

EU_AI_ACT: list[ControlMapping] = [
    ControlMapping(
        "Art-9", "Risk Management System", "EU-AI-Act", "High-Risk AI",
        "Continuous risk assessment for every AI agent action. 4-dimension risk scoring with behavioral drift detection. Risk thresholds configurable per deployment.",
        "Pipeline Stage 5 (Risk Scoring) + behavioral assessment",
        "GET /v1/decisions/recent — risk_score on every AI agent decision",
    ),
    ControlMapping(
        "Art-12", "Record-Keeping", "EU-AI-Act", "High-Risk AI",
        "Hash-chained, HMAC-signed audit log with full decision context: actor, action, risk score, risk factors, explanation, compliance tags.",
        "Audit log (JSONL)",
        "GET /v1/audit/verify — verify log integrity",
    ),
    ControlMapping(
        "Art-13", "Transparency", "EU-AI-Act", "High-Risk AI",
        "No LLMs in the decision path. Every decision is deterministic Bayesian math — fully explainable. Risk factor breakdown shows exactly why each decision was made.",
        "Decision explanation + risk_signals array",
        "Examine explanation and risk_signals in any audit entry",
    ),
    ControlMapping(
        "Art-14", "Human Oversight", "EU-AI-Act", "High-Risk AI",
        "require_review decision outcome mandates human approval before execution. Operator feedback loop with Bayesian prior adjustment. Threat intel overlays require human activation.",
        "Decision engine + feedback store + overlay approval flow",
        "Audit log entries with decision=require_review",
    ),
    ControlMapping(
        "Art-15", "Accuracy, Robustness and Cybersecurity", "EU-AI-Act", "High-Risk AI",
        "Deterministic math (no ML model to adversarially attack). Anti-poisoning controls on threat intel feeds (7 invariants). Policy bundles cryptographically signed.",
        "Pipeline architecture + threat intel anti-poisoning + config signatures",
        "Review anti-poisoning invariants in threat intel module",
    ),
]

# ── All frameworks aggregated ────────────────────────────────────────────────

ALL_CONTROLS: list[ControlMapping] = NIST_800_53 + HIPAA + FEDRAMP + EU_AI_ACT

FRAMEWORK_INDEX: dict[str, list[ControlMapping]] = {
    "NIST-800-53": NIST_800_53,
    "HIPAA": HIPAA,
    "FedRAMP": FEDRAMP,
    "EU-AI-Act": EU_AI_ACT,
}
