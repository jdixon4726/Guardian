"""
OPA Policy Provider

Delegates policy evaluation to an Open Policy Agent instance via HTTP.
Maps OPA's response to Guardian's PolicyVerdict model.

This provider enables organizations to use their existing OPA/Rego policies
while still benefiting from Guardian's behavioral intelligence layer.
"""

from __future__ import annotations

import logging

import httpx

from guardian.config.model import PolicyProviderConfig
from guardian.models.action_request import DecisionOutcome
from guardian.policy.engine import PolicyVerdict

logger = logging.getLogger(__name__)

_OUTCOME_MAP = {
    "allow": DecisionOutcome.allow,
    "allow_with_logging": DecisionOutcome.allow_with_logging,
    "require_review": DecisionOutcome.require_review,
    "block": DecisionOutcome.block,
    "deny": DecisionOutcome.block,
}


class OPAPolicyProvider:
    """
    Policy provider that queries an OPA instance for decisions.

    The OPA policy receives the full Guardian context (including behavioral
    signals like drift_score, trust_level, and is_anomalous) so that Rego
    rules can incorporate Guardian's behavioral intelligence.
    """

    def __init__(self, config: PolicyProviderConfig):
        if not config.opa_url:
            raise ValueError("opa_url is required for OPA policy provider")
        self._url = f"{config.opa_url.rstrip('/')}/v1/data/{config.opa_policy_path}"
        self._timeout = config.opa_timeout_seconds
        self._fallback = config.opa_fallback
        self._client = httpx.Client(timeout=self._timeout)
        logger.info("OPA policy provider initialized: %s", self._url)

    def evaluate(self, context: dict) -> PolicyVerdict:
        """Query OPA and map the response to a PolicyVerdict."""
        try:
            response = self._client.post(self._url, json={"input": context})
            response.raise_for_status()
            result = response.json().get("result", {})

            decision = result.get("decision", "require_review")
            outcome = _OUTCOME_MAP.get(decision, DecisionOutcome.require_review)
            rule_id = result.get("rule_id")
            explanation = result.get("explanation", f"OPA policy returned: {decision}")

            return PolicyVerdict(
                outcome=outcome,
                rule_id=rule_id,
                matched=True,
                explanation=explanation,
            )

        except (httpx.HTTPError, Exception) as exc:
            logger.error("OPA query failed: %s", exc)
            if self._fallback == "block":
                return PolicyVerdict(
                    outcome=DecisionOutcome.block,
                    rule_id=None,
                    matched=False,
                    explanation=f"OPA unreachable — fail-closed to block. Error: {exc}",
                )
            # fallback = "builtin" would be handled at the pipeline level
            return PolicyVerdict(
                outcome=DecisionOutcome.require_review,
                rule_id=None,
                matched=False,
                explanation=f"OPA unreachable — defaulting to require_review. Error: {exc}",
            )

    def health_check(self) -> bool:
        """Check if OPA is reachable."""
        try:
            resp = self._client.get(
                self._url.rsplit("/v1/data", 1)[0] + "/health",
            )
            return resp.status_code == 200
        except httpx.HTTPError:
            return False
