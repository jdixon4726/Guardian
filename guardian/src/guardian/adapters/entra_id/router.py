"""
Entra ID Admin Proxy Router

Intercepts destructive Microsoft Entra ID administrative operations,
evaluates through Guardian's pipeline (with circuit breaker), and
forwards or blocks.

Extends the Intune proxy pattern to cover the identity plane.
"""

from __future__ import annotations

import logging

from fastapi import APIRouter, HTTPException, Request
from fastapi.responses import JSONResponse

from guardian.adapters.intune.identity import IntuneIdentityResolver
from guardian.adapters.entra_id.mapper import EntraAdminMapper
from guardian.adapters.entra_id.models import EntraAdminAction, EntraProxyResponse
from guardian.circuit_breaker.breaker import CircuitBreaker
from guardian.models.action_request import DecisionOutcome

logger = logging.getLogger(__name__)

router = APIRouter(prefix="/v1/entra-id", tags=["entra-id"])

_pipeline = None
_mapper = EntraAdminMapper()
_identity_resolver = IntuneIdentityResolver()  # same Azure AD JWT resolution
_circuit_breaker = None


def configure(pipeline, circuit_breaker: CircuitBreaker | None = None) -> None:
    global _pipeline, _circuit_breaker
    _pipeline = pipeline
    _circuit_breaker = circuit_breaker


@router.post("/admin-action")
async def admin_action(action: EntraAdminAction, request: Request) -> JSONResponse:
    """Intercept and evaluate an Entra ID administrative action."""
    if _pipeline is None:
        raise HTTPException(503, "Guardian pipeline not initialized")

    authorization = request.headers.get("Authorization", "")

    try:
        identity = _identity_resolver.resolve({"authorization": authorization})
        actor_name = identity.actor_name

        # Circuit breaker check
        if _circuit_breaker:
            action_request = _mapper.map_action(action, actor_name=actor_name)
            cb_allowed, cb_reason = _circuit_breaker.check(
                actor_name, action_request.requested_action,
            )
            if not cb_allowed:
                logger.warning(
                    "Entra ID circuit breaker denied: actor=%s action=%s",
                    actor_name, action.action,
                )
                return JSONResponse(status_code=403, content=EntraProxyResponse(
                    allowed=False, decision="block", risk_score=1.0,
                    explanation=cb_reason or "Circuit breaker tripped",
                    entry_id="cb-entra-" + action.action,
                    circuit_breaker_tripped=True, circuit_breaker_reason=cb_reason,
                ).model_dump())

        action_request = _mapper.map_action(action, actor_name=actor_name)
        decision = _pipeline.evaluate(action_request)

        allowed = decision.decision in (
            DecisionOutcome.allow, DecisionOutcome.allow_with_logging,
        )

        logger.info(
            "Entra ID proxy: actor=%s action=%s target=%s -> %s (risk=%.2f)",
            actor_name, action.action, action.target_display_name,
            "allowed" if allowed else "denied", decision.risk_score,
        )

        return JSONResponse(
            status_code=200 if allowed else 403,
            content=EntraProxyResponse(
                allowed=allowed, decision=decision.decision.value,
                risk_score=decision.risk_score,
                explanation=decision.explanation[:1000],
                entry_id=decision.entry_id,
            ).model_dump(),
        )

    except Exception as exc:
        logger.error("Entra ID proxy error: %s", exc)
        return JSONResponse(status_code=403, content=EntraProxyResponse(
            allowed=False, decision="block", risk_score=1.0,
            explanation=f"Guardian evaluation error: {exc}",
            entry_id="error-entra",
        ).model_dump())
