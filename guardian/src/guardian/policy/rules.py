"""
AllowRule — explicit permit rule.

Separated from engine.py to keep imports clean when loaders need AllowRule
without importing the full engine module.
"""

from __future__ import annotations

from guardian.policy.engine import ConditionalRule
from guardian.models.action_request import DecisionOutcome
from guardian.policy.engine import PolicyVerdict


class AllowRule(ConditionalRule):
    """Explicit allow rule. Conditions are identical to ConditionalRule."""

    def __init__(self, rule_id: str, description: str, conditions: dict):
        super().__init__(rule_id, description, conditions, DecisionOutcome.allow)

    def evaluate(self, context: dict):
        if not self._conditions_match(context):
            return None
        return PolicyVerdict(
            outcome=DecisionOutcome.allow,
            rule_id=self.rule_id,
            matched=True,
            explanation=f"Allow rule `{self.rule_id}` matched. {self.description}",
        )
