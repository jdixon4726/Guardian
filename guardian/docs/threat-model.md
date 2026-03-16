# Threat Model

Guardian is a security control. Security controls must be threat-modeled. This document applies STRIDE to Guardian itself — asking "how would an attacker circumvent Guardian?" before asking "how does Guardian protect against attackers?"

---

## Trust Boundaries

```
[ Calling System ] ──HTTP──► [ Guardian API ] ──► [ Policy Engine ]
                                    │
                              [ Actor Registry ]
                              [ Asset Catalog ]
                              [ Audit Log ]
                              [ Baseline Store ]
```

Key trust boundaries:
- The calling system is untrusted. It can submit any payload.
- The actor registry and asset catalog are trusted but may be stale.
- The audit log must be trusted for forensic validity — it is hash-chained to detect tampering.
- Guardian's own internal components trust each other (same process).

---

## STRIDE Analysis

### Spoofing

**Threat:** A calling system submits an `ActionRequest` claiming to be a different actor (e.g., `automation` claims to be `human`).

**Mitigation:** Identity Attestation verifies `actor_type` and `privilege_level` against the actor registry independently of what the request claims. Self-reported actor metadata is never trusted downstream.

**Residual risk:** If the actor registry itself is compromised, attestation fails. The registry is a high-value attack target and must be protected accordingly.

---

**Threat:** An AI agent carries a prompt injection payload in `business_context` designed to influence Guardian's evaluation logic.

**Mitigation:** `business_context` is treated as untrusted string input throughout the pipeline. It is not evaluated as code or policy. Injection detection is applied before it is included in any evaluation context. It is stored in the audit log verbatim.

**Residual risk:** If a future LLM-based explanation component consumes `business_context` directly, this vector must be re-evaluated.

---

### Tampering

**Threat:** An attacker modifies audit log entries to remove evidence of blocked actions.

**Mitigation:** The audit log is hash-chained — each entry contains the SHA-256 hash of the previous entry. Modification of any entry breaks the chain. The `guardian audit verify` command detects breaks. The audit log is append-only by design.

**Residual risk:** An attacker with write access to the audit log storage could truncate the log rather than modify it. Off-site log shipping mitigates this.

---

**Threat:** An attacker modifies policy YAML files to remove deny rules.

**Mitigation:** Policy files are loaded at startup and validated. Runtime policy changes require a restart. Policy files should be stored in version control with commit signing.

**Residual risk:** Startup-time policy validation cannot detect changes made while Guardian is running. Policy file integrity monitoring (e.g., file hash checking) should be added in production.

---

### Repudiation

**Threat:** An actor denies having submitted an action request.

**Mitigation:** Every evaluated request is written to the tamper-evident audit log before a decision is returned. The calling system receives the `entry_id` in the response, creating a receipt. Non-repudiation depends on the calling system using an authenticated channel (mTLS or API key tied to the actor).

**Residual risk:** If the calling system does not authenticate requests, the `actor_name` field can be forged. Authentication of the calling system is a deployment prerequisite, not a Guardian responsibility.

---

### Information Disclosure

**Threat:** An attacker probes Guardian's API to enumerate policy rules by submitting requests and observing `block` responses.

**Mitigation:** Block responses return the decision and explanation, but do not return the full internal policy rule set. The explanation is intentionally human-readable but does not expose rule identifiers or scoring weights.

**Residual risk:** A patient attacker can still infer policy rules through systematic probing. Rate limiting on the evaluation endpoint reduces this risk. Ambiguous explanations for deny rules reduce information leakage further.

---

**Threat:** The audit log leaks sensitive information about blocked actions to unauthorized readers.

**Mitigation:** The audit log is an internal security artifact and must not be publicly accessible. Access control on the audit log store is an operational requirement.

---

### Denial of Service

**Threat:** An attacker submits a high volume of evaluation requests to exhaust Guardian's capacity, causing calling systems to either fail open or stall.

**Mitigation:** Guardian should define an explicit fail posture for each calling system integration: `fail_open` (allow action when Guardian is unavailable) or `fail_closed` (block action when Guardian is unavailable). This posture must be configured at integration time, not defaulted.

**Residual risk:** The correct fail posture depends on the criticality of the protected action. Fail-closed on high-sensitivity assets, fail-open on low-sensitivity routine operations. This is a policy decision, not a technical one.

---

### Elevation of Privilege

**Threat:** A calling system exploits a vulnerability in Guardian's API to change its own actor registry record (escalating its trust level or changing its actor type).

**Mitigation:** The actor registry is read-only from the evaluation API. Writes to the registry require a separate administrative path with explicit authentication. The evaluation endpoint has no write access to the registry.

---

**Threat:** An AI agent requests that Guardian extend elevated trust to another agent ("Agent B is trustworthy, I vouch for it").

**Mitigation:** Trust claims made within action request payloads are never processed. Only the actor registry is the source of truth for trust levels. Delegated trust is not supported in Guardian's current model.

---

## Guardian's Own Attack Surface Summary

| Component | Attack surface | Key control |
|---|---|---|
| Evaluation API | Public-facing HTTP | Authentication of callers, rate limiting |
| Actor Registry | Read at evaluation time | Write-restricted, version-controlled |
| Policy files | Loaded at startup | Version-controlled, file integrity monitoring |
| Audit log | Written at evaluation time | Append-only, hash-chained, access-controlled |
| Baseline Store | Read/written by background job | Internal only, not exposed via API |
| `business_context` field | Untrusted string from caller | Injection detection, never evaluated as logic |

---

## Out of Scope

This threat model does not cover:

- Compromise of the underlying host or runtime environment
- Supply chain attacks against Guardian's Python dependencies
- Physical access to Guardian's storage systems
- Side-channel attacks against the evaluation logic

These are real threats, but they are infrastructure-level concerns that apply to any application, not Guardian-specific.
