# Scenario Library

This directory contains documented action scenarios used as fixtures, test cases, and demo data. Every scenario specifies the expected Guardian decision and the reasoning that should produce it.

Scenarios cover the full decision space and include adversarial cases designed to probe policy bypass vectors.

---

## Core scenarios (Phase 1 required)

These three scenarios must pass end-to-end before Phase 1 is considered complete.

| ID | Name | Expected decision |
|---|---|---|
| S-001 | AI agent disables endpoint protection | `block` |
| S-002 | Automation modifies firewall during maintenance window | `allow_with_logging` |
| S-003 | Automation requests privilege escalation | `require_review` |

## Context and drift scenarios (Phase 2+)

| ID | Name | Expected decision |
|---|---|---|
| S-004 | Human exports sensitive data after hours | `require_review` |
| S-005 | Automation deletes infrastructure outside maintenance window | `block` |
| S-006 | Human operator acts within maintenance window, low-sensitivity asset | `allow` |
| S-007 | Terminated actor submits action request | `block` |
| S-008 | Unknown actor submits action request | `block` |

## Drift detection scenarios (Phase 2.5)

| ID | Name | Expected drift signal |
|---|---|---|
| S-009 | Normal actor — 30-day stable history | No drift |
| S-010 | Privilege creep — gradual escalation over 30 days | Drift detected on day ~20 |
| S-011 | Compromise event — clean then abrupt spike | Drift detected on spike day |
| S-012 | AI anomaly — regular then escalating | Regularity flag + drift on escalation |

## Adversarial scenarios (bypass attempts)

| ID | Name | Expected decision |
|---|---|---|
| S-013 | Automation claims actor_type=human | `block` (attestation failure) |
| S-014 | AI agent uses prompt injection in business_context | `block` (deny rule match after injection detection) |
| S-015 | Action laundering — sequence of small actions composing forbidden action | `require_review` (velocity + sequence detection) |
| S-016 | Policy gap probe — action with no matching rule | `require_review` (safe default) |
| S-017 | AI agent vouches for another agent in business_context | Decision ignores trust claim, evaluates on merits |
