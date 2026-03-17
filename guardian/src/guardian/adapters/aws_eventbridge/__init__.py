"""
AWS EventBridge Adapter — Event-Driven Cloud Evaluation

New integration pattern: instead of synchronous proxy or webhook,
Guardian consumes CloudTrail events via EventBridge in near-real-time
and evaluates them against behavioral baselines.

For destructive actions, Guardian can trigger automated quarantine
(SCP attachment, IAM policy denial) via the response handler.

This is Pattern 3: event-driven evaluation — needed because AWS's
API surface is too broad to proxy comprehensively.
"""
