"""
Policy Engine

Evaluates an EnrichedContext against the loaded rule set and produces a PolicyVerdict.

Evaluation order:
  1. Deny rules  — hard blocks, short-circuit on first match
  2. Conditional rules — context-dependent, evaluated in priority order
  3. Allow rules — explicit permits
  4. Default — require_review if no rule matched

The deny-wins principle is a security property: no combination of allow rules
can override a matching deny rule.
"""

from __future__ import annotations

import logging
from abc import ABC, abstractmethod
from dataclasses import dataclass
from typing import Optional

from guardian.models.action_request import DecisionOutcome

logger = logging.getLogger(__name__)


@dataclass
class PolicyVerdict:
    outcome: DecisionOutcome
    rule_id: Optional[str]
    matched: bool
    explanation: str


class PolicyRule(ABC):
    """Abstract base class for all policy rules."""

    def __init__(self, rule_id: str, description: str):
        self.rule_id = rule_id
        self.description = description

    @abstractmethod
    def evaluate(self, context: dict) -> Optional[PolicyVerdict]:
        """
        Evaluate this rule against the enriched context.

        Returns a PolicyVerdict if this rule matches, None if it does not apply.
        """
        ...


class DenyRule(PolicyRule):
    """
    Hard block rule. Matches produce an immediate block with no further evaluation.

    Deny rules are context-independent by design: a matching deny rule blocks
    the action regardless of business_context, maintenance windows, or risk score.
    """

    def __init__(self, rule_id: str, description: str, conditions: dict,
                 mitre_technique: Optional[str] = None):
        super().__init__(rule_id, description)
        self.conditions = conditions
        self.mitre_technique = mitre_technique

    def evaluate(self, context: dict) -> Optional[PolicyVerdict]:
        if self._conditions_match(context):
            technique_note = f" (MITRE {self.mitre_technique})" if self.mitre_technique else ""
            return PolicyVerdict(
                outcome=DecisionOutcome.block,
                rule_id=self.rule_id,
                matched=True,
                explanation=f"Action blocked by deny rule `{self.rule_id}`{technique_note}. {self.description}"
            )
        return None

    def _conditions_match(self, context: dict) -> bool:
        for field, expected in self.conditions.items():
            actual = context.get(field)
            if isinstance(expected, list):
                if actual not in expected:
                    return False
            else:
                if actual != expected:
                    return False
        return True


class ConditionalRule(PolicyRule):
    """
    Context-dependent rule. May produce allow_with_logging, require_review, or block
    depending on conditions and configured outcome.
    """

    def __init__(self, rule_id: str, description: str,
                 conditions: dict, outcome: DecisionOutcome):
        super().__init__(rule_id, description)
        self.conditions = conditions
        self.outcome = outcome

    def evaluate(self, context: dict) -> Optional[PolicyVerdict]:
        if self._conditions_match(context):
            return PolicyVerdict(
                outcome=self.outcome,
                rule_id=self.rule_id,
                matched=True,
                explanation=f"Conditional rule `{self.rule_id}` matched. {self.description}"
            )
        return None

    def _conditions_match(self, context: dict) -> bool:
        for field, expected in self.conditions.items():
            actual = context.get(field)
            if isinstance(expected, list):
                if actual not in expected:
                    return False
            else:
                if actual != expected:
                    return False
        return True


class AllowRule(ConditionalRule):
    """Explicit permit rule. Inherit conditions matching from ConditionalRule."""

    def __init__(self, rule_id: str, description: str, conditions: dict):
        super().__init__(rule_id, description, conditions, DecisionOutcome.allow)

    def evaluate(self, context: dict) -> Optional[PolicyVerdict]:
        if not self._conditions_match(context):
            return None
        return PolicyVerdict(
            outcome=DecisionOutcome.allow,
            rule_id=self.rule_id,
            matched=True,
            explanation=f"Allow rule `{self.rule_id}` matched. {self.description}",
        )


class PolicyEngine:
    """
    Evaluates enriched context against the loaded rule set.

    Rule priority:
      1. Deny rules (first match halts evaluation)
      2. Conditional rules (most restrictive verdict wins on conflict)
      3. Allow rules (first match)
      4. Default: require_review
    """

    def __init__(self, deny_rules: list[DenyRule],
                 conditional_rules: list[ConditionalRule],
                 allow_rules: list[PolicyRule]):
        self.deny_rules = deny_rules
        self.conditional_rules = conditional_rules
        self.allow_rules = allow_rules
        logger.info(
            "Policy engine loaded: %d deny, %d conditional, %d allow rules",
            len(deny_rules), len(conditional_rules), len(allow_rules)
        )

    def evaluate(self, context: dict) -> PolicyVerdict:
        # Stage 1: deny rules — short-circuit on first match
        for rule in self.deny_rules:
            verdict = rule.evaluate(context)
            if verdict:
                logger.debug("Deny rule matched: %s", rule.rule_id)
                return verdict

        # Stage 2: conditional rules — collect all matches, apply conflict resolution
        conditional_verdicts = []
        for rule in self.conditional_rules:
            verdict = rule.evaluate(context)
            if verdict:
                conditional_verdicts.append(verdict)

        if conditional_verdicts:
            return self._resolve_conflicts(conditional_verdicts)

        # Stage 3: allow rules
        for rule in self.allow_rules:
            verdict = rule.evaluate(context)
            if verdict:
                return verdict

        # Stage 4: default
        return PolicyVerdict(
            outcome=DecisionOutcome.require_review,
            rule_id=None,
            matched=False,
            explanation="No policy rule matched this action. Defaulting to require_review."
        )

    def health_check(self) -> bool:
        """Built-in policy engine is always healthy."""
        return True

    def _resolve_conflicts(self, verdicts: list[PolicyVerdict]) -> PolicyVerdict:
        """
        Conflict resolution: most restrictive verdict wins.
        Precedence: block > require_review > allow_with_logging > allow
        """
        precedence = {
            DecisionOutcome.block: 3,
            DecisionOutcome.require_review: 2,
            DecisionOutcome.allow_with_logging: 1,
            DecisionOutcome.allow: 0,
        }
        return max(verdicts, key=lambda v: precedence[v.outcome])
