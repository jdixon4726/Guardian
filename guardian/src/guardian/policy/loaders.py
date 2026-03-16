"""
Policy Loader

Reads YAML policy definition files from the policies directory and produces
typed PolicyRule objects suitable for the PolicyEngine.

Loading happens at startup. Invalid YAML or missing required fields cause
a startup failure — not a runtime error. A Guardian instance with broken
policies must not start silently.
"""

from __future__ import annotations

import logging
from pathlib import Path

import yaml

from guardian.models.action_request import DecisionOutcome
from guardian.policy.engine import (
    AllowRule,
    ConditionalRule,
    DenyRule,
    PolicyRule,
)

logger = logging.getLogger(__name__)


class PolicyLoader:
    """Loads all YAML policy files from the policies directory."""

    def __init__(self, policies_dir: Path):
        self.policies_dir = policies_dir

    def load_all(self) -> tuple[list[DenyRule], list[ConditionalRule], list[PolicyRule]]:
        deny: list[DenyRule] = []
        conditional: list[ConditionalRule] = []
        allow: list[PolicyRule] = []

        for path in sorted(self.policies_dir.rglob("*.yaml")):
            try:
                rule = self._load_file(path)
                if rule is None:
                    continue
                if isinstance(rule, DenyRule):
                    deny.append(rule)
                elif isinstance(rule, ConditionalRule):
                    conditional.append(rule)
                else:
                    allow.append(rule)
                logger.debug("Loaded policy rule: %s from %s", rule.rule_id, path.name)
            except Exception as exc:
                raise RuntimeError(
                    f"Failed to load policy file {path}: {exc}"
                ) from exc

        logger.info(
            "Policies loaded: %d deny, %d conditional, %d allow",
            len(deny), len(conditional), len(allow),
        )
        return deny, conditional, allow

    def _load_file(self, path: Path) -> PolicyRule | None:
        data = yaml.safe_load(path.read_text())
        if not data:
            return None

        rule_type = data.get("type")
        rule_id = data["id"]
        description = data.get("description", "").strip()

        if rule_type == "deny":
            return DenyRule(
                rule_id=rule_id,
                description=description,
                conditions=data.get("conditions", {}),
                mitre_technique=data.get("mitre_technique"),
            )

        if rule_type == "conditional":
            # Support window-aware conditional rules
            if "outcome_in_window" in data or "outcome_out_of_window" in data:
                return _WindowAwareConditionalRule(
                    rule_id=rule_id,
                    description=description,
                    conditions=data.get("conditions", {}),
                    outcome_in_window=DecisionOutcome(data["outcome_in_window"]),
                    outcome_out_of_window=DecisionOutcome(data["outcome_out_of_window"]),
                )
            return ConditionalRule(
                rule_id=rule_id,
                description=description,
                conditions=data.get("conditions", {}),
                outcome=DecisionOutcome(data["outcome"]),
            )

        if rule_type == "allow":
            return AllowRule(
                rule_id=rule_id,
                description=description,
                conditions=data.get("conditions", {}),
            )

        logger.warning("Unknown policy rule type '%s' in %s — skipping", rule_type, path.name)
        return None


class _WindowAwareConditionalRule(ConditionalRule):
    """
    A conditional rule whose outcome depends on whether the request
    falls within a maintenance window. The policy YAML specifies
    separate outcomes for in-window and out-of-window cases.
    """

    def __init__(self, rule_id: str, description: str, conditions: dict,
                 outcome_in_window: DecisionOutcome,
                 outcome_out_of_window: DecisionOutcome):
        # outcome is set dynamically at evaluate time
        super().__init__(rule_id, description, conditions, outcome_in_window)
        self.outcome_in_window = outcome_in_window
        self.outcome_out_of_window = outcome_out_of_window

    def evaluate(self, context: dict):
        if not self._conditions_match(context):
            return None

        in_window = context.get("in_maintenance_window", False)
        self.outcome = self.outcome_in_window if in_window else self.outcome_out_of_window

        from guardian.policy.engine import PolicyVerdict
        window_note = "during maintenance window" if in_window else "outside maintenance window"
        return PolicyVerdict(
            outcome=self.outcome,
            rule_id=self.rule_id,
            matched=True,
            explanation=(
                f"Conditional rule `{self.rule_id}` matched ({window_note}). "
                f"{self.description}"
            ),
        )
