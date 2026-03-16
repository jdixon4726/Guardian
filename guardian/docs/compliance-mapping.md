# Compliance Mapping

Guardian tags every audit entry with applicable compliance control identifiers at write time. This document defines the mapping between Guardian's policy rules and two frameworks: NIST SP 800-53 Rev 5 and CIS Critical Security Controls v8.

---

## NIST SP 800-53 Mappings

### AC — Access Control

| Control | Description | Guardian policy rules |
|---|---|---|
| AC-2 | Account Management | Actor registry maintenance, terminated-actor blocking |
| AC-3 | Access Enforcement | Privilege level enforcement, deny rules for unauthorized access |
| AC-5 | Separation of Duties | AI agent / automation / human actor type restrictions |
| AC-6 | Least Privilege | Privilege escalation review requirements |
| AC-17 | Remote Access | Actions on remote systems during non-maintenance windows |

### AU — Audit and Accountability

| Control | Description | Guardian policy rules |
|---|---|---|
| AU-2 | Event Logging | All evaluation decisions logged to tamper-evident audit log |
| AU-3 | Content of Audit Records | Full context, actor, decision, and explanation in every entry |
| AU-9 | Protection of Audit Information | Hash-chained audit log, append-only |
| AU-12 | Audit Record Generation | Every `POST /v1/evaluate` generates an audit record |

### CM — Configuration Management

| Control | Description | Guardian policy rules |
|---|---|---|
| CM-2 | Baseline Configuration | Configuration change actions require review or are blocked |
| CM-3 | Configuration Change Control | Firewall, security group, and infrastructure change governance |
| CM-5 | Access Restrictions for Change | Elevated privilege required for config changes, subject to review |

### IA — Identification and Authentication

| Control | Description | Guardian policy rules |
|---|---|---|
| IA-2 | Identification and Authentication | Identity attestation verifies all actor claims |
| IA-4 | Identifier Management | Actor registry as authoritative identity source |

### IR — Incident Response

| Control | Description | Guardian policy rules |
|---|---|---|
| IR-5 | Incident Monitoring | Drift detection alerts feed security monitoring |
| IR-6 | Incident Reporting | Block and high-drift events published to alert channel |

### SI — System and Information Integrity

| Control | Description | Guardian policy rules |
|---|---|---|
| SI-3 | Malware Protection | Deny rules blocking disable of endpoint protection |
| SI-7 | Software, Firmware, and Information Integrity | Security tool modification governance |

---

## CIS Critical Security Controls v8 Mappings

| CIS Control | Safeguard | Guardian coverage |
|---|---|---|
| 3.3 | Configure data access control lists | Sensitivity-level-based access decisions |
| 4.1 | Establish and maintain a secure configuration process | Configuration change governance |
| 4.2 | Establish and maintain a secure configuration process for network infrastructure | Firewall and network rule change governance |
| 5.3 | Disable dormant accounts | Terminated actor blocking in identity attestation |
| 5.4 | Restrict administrator privileges | Privilege escalation review requirements |
| 5.6 | Centralize account management | Actor registry as centralized identity source |
| 6.2 | Establish access grants | Allow rules govern access grant actions |
| 6.3 | Require MFA for externally-exposed applications | Out of scope (infrastructure-level control) |
| 8.2 | Collect audit logs | Full audit log for all evaluated actions |
| 8.5 | Collect detailed audit logs | Full context, actor, and explanation in audit entries |
| 8.9 | Centralize audit logs | Centralized audit log with hash chain verification |
| 10.1 | Deploy and maintain anti-malware software | Deny rules blocking disable of endpoint protection |
| 13.1 | Centralize security event alerting | Alert Publisher for drift events and blocks |

---

## Tagging in the Audit Log

Each audit entry includes a `compliance_tags` array. Tags use the format `FRAMEWORK-CONTROL-ID`.

Examples:
- `NIST-AC-6` — NIST SP 800-53 AC-6 (Least Privilege)
- `NIST-AU-2` — NIST SP 800-53 AU-2 (Event Logging)
- `CIS-5.4` — CIS CSC v8 Safeguard 5.4 (Restrict administrator privileges)

Every audit entry is tagged with `NIST-AU-2` and `NIST-AU-12` by default (all evaluations generate audit records). Additional tags are added based on the policy rules matched and the action category.

---

## Compliance Posture Endpoint

`GET /v1/compliance/posture` returns a summary of Guardian's decision output over a specified time window, organized by compliance control.

Example response:

```json
{
  "window": "2025-03-01T00:00:00Z / 2025-03-15T23:59:59Z",
  "controls": {
    "NIST-AC-6": {
      "description": "Least Privilege",
      "evaluations": 47,
      "allow": 22,
      "allow_with_logging": 12,
      "require_review": 9,
      "block": 4
    },
    "NIST-AU-2": {
      "description": "Event Logging",
      "evaluations": 312,
      "audit_entries_written": 312,
      "chain_verified": true
    }
  }
}
```

This output is directly usable as evidence in a SOC2 Type II audit for the relevant controls.
