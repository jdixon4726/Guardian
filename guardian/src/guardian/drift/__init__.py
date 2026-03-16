"""
Drift Detection Engine (Phase 2.5)

Detects behavioral anomalies that rule-based policy systems cannot see:
  - Level drift: z-score of current risk against actor's rolling baseline
  - Pattern drift: Jensen-Shannon divergence of action type distribution
  - Regularity detection: suspiciously low variance flagging
"""
