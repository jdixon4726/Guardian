"""
Decision Engine

Combines the PolicyVerdict and numeric RiskScore into a final DecisionOutcome
using the policy × risk matrix defined in decision-semantics.md.

Key invariants (from decision-semantics.md):
  - A policy block always produces block regardless of risk score.
  - A high or critical risk score can escalate an allow upward.
  - A low risk score cannot downgrade a require_review.
  - The default outcome (no rule match) is require_review, never allow.
"""

from __future__ import annotations

import logging
from dataclasses import dataclass

from guardian.config.model import DecisionConfig
from guardian.models.action_request import DecisionOutcome
from guardian.policy.engine import PolicyVerdict

logger = logging.getLogger(__name__)

_DEFAULT_DECISION = DecisionConfig()


def _risk_band(score: float, cfg: DecisionConfig = _DEFAULT_DECISION) -> str:
    if score <= cfg.low_max:
        return "low"
    if score <= cfg.medium_max:
        return "medium"
    if score <= cfg.high_max:
        return "high"
    return "critical"


# Decision matrix: (policy_outcome, risk_band) → final_outcome
_MATRIX: dict[tuple[str, str], DecisionOutcome] = {
    # Block always wins
    ("block",            "low"):      DecisionOutcome.block,
    ("block",            "medium"):   DecisionOutcome.block,
    ("block",            "high"):     DecisionOutcome.block,
    ("block",            "critical"): DecisionOutcome.block,
    # require_review is sticky — risk cannot de-escalate
    ("require_review",   "low"):      DecisionOutcome.require_review,
    ("require_review",   "medium"):   DecisionOutcome.require_review,
    ("require_review",   "high"):     DecisionOutcome.require_review,
    ("require_review",   "critical"): DecisionOutcome.require_review,
    # allow_with_logging — risk can escalate to review but not block
    ("allow_with_logging", "low"):    DecisionOutcome.allow_with_logging,
    ("allow_with_logging", "medium"): DecisionOutcome.allow_with_logging,
    ("allow_with_logging", "high"):   DecisionOutcome.require_review,
    ("allow_with_logging", "critical"): DecisionOutcome.require_review,
    # allow — risk can escalate fully
    ("allow",            "low"):      DecisionOutcome.allow,
    ("allow",            "medium"):   DecisionOutcome.allow_with_logging,
    ("allow",            "high"):     DecisionOutcome.require_review,
    ("allow",            "critical"): DecisionOutcome.block,
    # Default (no rule matched) — always review
    ("default",          "low"):      DecisionOutcome.require_review,
    ("default",          "medium"):   DecisionOutcome.require_review,
    ("default",          "high"):     DecisionOutcome.require_review,
    ("default",          "critical"): DecisionOutcome.require_review,
}


@dataclass
class DecisionResult:
    outcome: DecisionOutcome
    policy_verdict: PolicyVerdict
    risk_score: float
    risk_band: str
    explanation: str
    safer_alternatives: list[str]


class DecisionEngine:
    """Applies the policy × risk matrix to produce a final decision."""

    def __init__(self, config: DecisionConfig | None = None):
        self.cfg = config or DecisionConfig()

    def decide(self, policy_verdict: PolicyVerdict,
               risk_score: float,
               policy_explanation: str,
               risk_signals_summary: str) -> DecisionResult:

        band = _risk_band(risk_score, self.cfg)
        policy_key = policy_verdict.outcome.value if policy_verdict.matched else "default"

        outcome = _MATRIX[(policy_key, band)]

        explanation = self._build_explanation(
            outcome, policy_verdict, risk_score, band,
            policy_explanation, risk_signals_summary,
        )

        safer_alternatives = self._suggest_alternatives(outcome, policy_verdict)

        logger.debug(
            "Decision: policy=%s risk_score=%.3f band=%s → %s",
            policy_key, risk_score, band, outcome.value,
        )

        return DecisionResult(
            outcome=outcome,
            policy_verdict=policy_verdict,
            risk_score=risk_score,
            risk_band=band,
            explanation=explanation,
            safer_alternatives=safer_alternatives,
        )

    def _build_explanation(
        self,
        outcome: DecisionOutcome,
        verdict: PolicyVerdict,
        risk_score: float,
        band: str,
        policy_explanation: str,
        risk_signals_summary: str,
    ) -> str:
        outcome_phrases = {
            DecisionOutcome.allow:             "Action allowed.",
            DecisionOutcome.allow_with_logging: "Action allowed with logging.",
            DecisionOutcome.require_review:    "Action requires human review.",
            DecisionOutcome.block:             "Action blocked.",
        }
        parts = [outcome_phrases[outcome]]

        if policy_explanation:
            parts.append(policy_explanation)

        parts.append(
            f"Risk score: {risk_score:.2f} ({band} band)."
        )

        if risk_signals_summary:
            parts.append(f"Contributing factors: {risk_signals_summary}")

        return " ".join(parts)

    def _suggest_alternatives(
        self,
        outcome: DecisionOutcome,
        verdict: PolicyVerdict,
    ) -> list[str]:
        if outcome == DecisionOutcome.allow:
            return []

        alternatives = []

        if verdict.rule_id == "deny-ai-agent-disable-security-tools":
            alternatives = [
                "Submit a human-authorized change request for security tool modification.",
                "Schedule the action within a defined maintenance window with explicit CISO approval.",
                "Investigate the root cause requiring security tool modification — this likely indicates a pipeline design issue.",
            ]
        elif "privilege" in (verdict.rule_id or ""):
            alternatives = [
                "Re-evaluate whether the automation account requires this privilege level for its intended function.",
                "If a one-time elevated action is needed, use a human operator account with appropriate authorization.",
                "Submit a privilege review request through the standard IAM governance process.",
            ]
        elif outcome == DecisionOutcome.require_review:
            alternatives = [
                "Submit this action through the standard change management process for human review.",
                "Schedule the action within a defined maintenance window if applicable.",
            ]

        return alternatives
