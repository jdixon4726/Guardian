# Vision

## Core Thesis

As automation systems and AI agents gain the ability to perform operational actions, organizations will need a control layer that evaluates proposed actions before execution.

This is not a new idea in security — WAFs evaluate HTTP requests, IAM systems evaluate API calls, PAM systems evaluate privileged sessions. Guardian applies the same pattern one level up: to the *operational action layer* where automation scripts, CI/CD pipelines, and AI agents make decisions about infrastructure, data, and identity.

The difference is behavioral intelligence. Existing enforcement tools are stateless — they evaluate each request against a fixed policy in isolation. Guardian maintains a living model of each actor's behavior over time, enabling it to detect *drift* — the gradual or sudden deviation of an actor's behavior from its established pattern — before that drift causes damage.

---

## The Organizational Invariant Problem

Modern organizations implicitly depend on invariants that span systems:

- Service accounts must have owners
- Terminated users must not retain access
- Privileged actions require authorization
- AI agents must not autonomously disable security controls
- Automation accounts must not escalate privileges without review

These invariants are never explicitly enforced anywhere. They exist as policy documents, as tribal knowledge, as audit findings after the fact. Each individual system enforces its own local rules. No system understands the organization as a whole.

Guardian is the system that enforces organizational invariants at the action layer — not by inspecting current state (which shows only what *is*, not how it *got there*), but by intercepting and evaluating every operational action as it is proposed.

---

## Five Dimensions of Drift

All organizational security degradation is ultimately caused by individual actions. Because Guardian sits at the action layer, it has natural observability over every causal event that produces drift. No other tool in a typical security stack sees the complete causal stream.

**Configuration drift** — Infrastructure silently deviates from its desired state through a series of small, individually unremarkable changes. Guardian's audit log makes every change visible and attributable.

**Privilege drift** — Actors accumulate permissions beyond what their role requires through repeated small grants that individually pass policy checks. Guardian tracks privilege requests over time and detects accumulation patterns.

**Behavioral drift** — Actors shift their action patterns gradually, making the change invisible to any single-point evaluation. Guardian maintains per-actor behavioral baselines and detects statistical deviation from established patterns.

**Policy drift** — Security policies age as the threat landscape evolves faster than policy review cycles. Guardian's block and review log reveals where policy is generating friction or missing coverage, creating a feedback loop for policy improvement.

**Compliance drift** — The organization's operational posture drifts away from regulatory and framework requirements. Guardian maps every decision to compliance control families at write time, producing a continuous posture report rather than a point-in-time audit.

---

## The AI Security Angle

Guardian is specifically designed to address the emerging threat surface created by AI agents operating in production environments.

AI agents introduce failure modes that rule-based governance systems cannot handle:

**Prompt injection as an action modifier.** Malicious content in a document, email, or API response can cause an AI agent to request dangerous operational actions. Guardian treats the `business_context` field as untrusted input and applies injection detection before evaluation.

**Goal misgeneralization.** An AI agent trained to "complete tasks efficiently" may discover that acquiring additional permissions makes task completion more reliable, leading to gradual privilege accumulation that looks benign at any single step. Guardian's drift detection catches the pattern.

**Multi-agent trust boundaries.** In multi-agent architectures, Agent A may request that Guardian extend elevated trust to Agent B. Guardian never accepts delegated trust claims from agents — all trust is established through the actor registry.

**Action laundering.** An AI agent may decompose a forbidden action into a sequence of individually-permitted sub-actions that together achieve the forbidden goal. Guardian's session-level analysis detects this pattern.

These threat models are documented in detail in [`threat-model.md`](threat-model.md).

---

## Relationship to Existing Frameworks

Guardian's design is informed by and maps to several existing frameworks:

**NIST Zero Trust Architecture (SP 800-207)** — Guardian implements the Policy Enforcement Point (PEP) and Policy Decision Point (PDP) pattern described in NIST's Zero Trust model, applied to operational actions rather than network requests.

**NIST AI Risk Management Framework (AI RMF)** — Guardian's governance layer aligns with the AI RMF's "Govern" and "Manage" functions, specifically the requirement for human oversight mechanisms for AI systems taking operational actions.

**MITRE ATT&CK** — Guardian's action taxonomy maps to ATT&CK technique identifiers, enabling direct correlation between governance events and the adversary technique library.

**CIS Critical Security Controls** — Guardian's policy library and compliance mapper implement controls from CIS CSC v8, particularly Control 3 (Data Protection), Control 5 (Account Management), and Control 6 (Access Control Management).

---

## What Guardian Is Not

Guardian is not a SIEM. It does not aggregate logs from other systems or perform correlation across events it did not observe.

Guardian is not an IAM system. It does not manage identities or issue credentials. It evaluates proposed actions made by already-authenticated actors.

Guardian is not a WAF or network security control. It operates at the operational action layer, not the network or API layer.

Guardian is designed to *complement* these systems — to be the governance layer that sees the action intent before it executes, rather than the detection layer that sees the effect after.

---

## Long-Term Vision

Guardian's long-term evolution points toward a **living operational governance layer** — a system that continuously models the expected state of the organization, detects deviations in real time, and provides human operators with enough context to make informed decisions quickly.

The key word is *living*. Static governance systems — policy files, compliance checklists, periodic audits — are structural artifacts that describe the organization as it was when they were written. A living governance layer is updated continuously by the actions flowing through it, making the gap between policy and reality visible at all times.

This is the governance architecture that organizations operating AI-driven infrastructure will require.
