# Decision Semantics

Guardian returns one of four decisions for every evaluated action request. The exact meaning of each decision — including what it guarantees, what it does not guarantee, and what happens when SLAs are not met — is specified here.

Ambiguity in a security control is a vulnerability. This document eliminates ambiguity.

---

## `allow`

**Meaning:** Guardian evaluated the action against all applicable policies and risk signals, and determined that the action is permitted to proceed without additional controls.

**Guarantees:**
- The action matched at least one allow rule and no deny or conditional rules that would elevate the decision.
- The risk score falls within the Low band (0.0 – 0.3).
- The actor's identity was successfully attested.
- The behavioral drift score is within normal range.

**Does not guarantee:**
- That the action is safe in absolute terms. Guardian evaluates against defined policy. An action that policy has not anticipated may be allowed incorrectly.
- That the action was correct or intended. Guardian governs authorization, not correctness.

**Caller obligation:** None. The action may proceed.

---

## `allow_with_logging`

**Meaning:** Guardian evaluated the action and determined it is permitted, but the combination of action type, actor, asset, or context warrants explicit audit attention beyond the standard log entry.

**Guarantees:**
- The action matched applicable policy and is permitted.
- The risk score is in the Low or Medium band (0.0 – 0.6).
- A full audit entry has been written to the audit log before this response was returned.

**Does not guarantee:**
- That the action has been reviewed by a human. `allow_with_logging` means "this was flagged for the audit record," not "a human approved this."

**Caller obligation:** The action may proceed. The calling system should confirm that its own audit infrastructure has received the `entry_id` in the response. If the calling system cannot confirm receipt, it should treat the action as `require_review`.

**Human review expectation:** Audit entries tagged `allow_with_logging` should be reviewed in the organization's standard audit review cycle (e.g., weekly). They are not time-sensitive.

---

## `require_review`

**Meaning:** Guardian evaluated the action and determined it cannot be automatically allowed or blocked. A human decision is required before the action proceeds.

**Guarantees:**
- The action has not been permitted to execute.
- A full audit entry has been written before this response was returned.
- The entry has been published to the review queue (in Phase 2+).

**Does not guarantee:**
- That the action is dangerous. `require_review` is a governance gate, not a threat classification.
- That a reviewer will be available within any particular timeframe.

**Caller obligation:** The action must not proceed until a human reviewer approves it through the review workflow. The calling system is responsible for holding the action pending review.

**Review SLA:** Organizations deploying Guardian must define a review SLA. When a `require_review` action exceeds its SLA without a decision, the default behavior is to escalate to `block`. This is the safe default — an expired review is treated as a block, not an auto-allow. The SLA and escalation behavior are configurable per action category.

**SLA expiry semantics:**
- Review approved within SLA → action proceeds
- Review denied within SLA → action blocked
- Review not completed within SLA → escalate to `block` (default), or escalate to human-defined fallback

---

## `block`

**Meaning:** Guardian evaluated the action and determined it must not proceed. The action is prohibited.

**Guarantees:**
- The action matched a deny rule or the risk score entered the Critical band with no overriding allow policy.
- A full audit entry has been written before this response was returned.
- The decision is final and cannot be overridden by re-submitting the same request.

**Does not guarantee:**
- That the action was malicious. A `block` may result from a configuration error, an incorrect policy rule, or a legitimate action that was not anticipated by current policy.

**Caller obligation:** The action must not proceed. The calling system should surface the `explanation` field from the Guardian response to the operator or responsible owner.

**Appeal process:** A blocked action can be appealed through an out-of-band process (not through the Guardian evaluation API, which will return `block` again for the same request). Appeals should result in either a policy change (if the block was incorrect) or a documented exception (if the block was correct but a one-time exception is warranted).

---

## Decision immutability

Once a decision has been written to the audit log, it is immutable. A subsequent request for the same action by the same actor may produce a different decision (because context, baselines, or policies may have changed), but the original decision entry is never modified.

This is a security property. A mutable audit log is not an audit log.

---

## Precedence rules

When policy and risk score suggest different decisions, the following precedence applies:

1. A `block` from a deny rule always wins. Risk score cannot override a deny rule.
2. A high or critical risk score can escalate a policy `allow` to `require_review` or `block`.
3. A low risk score cannot downgrade a policy `require_review` to `allow`.
4. The default decision (no matching rule) is always `require_review`, never `allow`.

In plain terms: policy can block but cannot guarantee allow. Risk can escalate but cannot de-escalate.
