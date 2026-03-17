"""
Intune Device Management Proxy Router

FastAPI router implementing the Guardian Intune proxy gateway.
Intercepts destructive Graph API device management calls, evaluates
through Guardian's pipeline (with circuit breaker), and forwards
or blocks.

Architecture:
  1. Caller sends device action request to Guardian (instead of Graph API)
  2. Guardian extracts identity from Azure AD Bearer token
  3. Circuit breaker checks per-actor destructive velocity
  4. Guardian pipeline evaluates the action
  5. If allowed: forward to real Graph API, return result
  6. If denied: return 403 with Guardian's explanation

Fail-closed: any error in Guardian evaluation = deny.
"""

from __future__ import annotations

import logging

from fastapi import APIRouter, HTTPException, Request
from fastapi.responses import JSONResponse

from guardian.adapters.intune.identity import IntuneIdentityResolver
from guardian.adapters.intune.mapper import IntuneActionMapper
from guardian.adapters.intune.models import (
    IntuneDeviceAction,
    IntuneProxyResponse,
)
from guardian.adapters.intune.proxy import IntuneProxy
from guardian.circuit_breaker.breaker import CircuitBreaker
from guardian.models.action_request import DecisionOutcome

logger = logging.getLogger(__name__)

router = APIRouter(prefix="/v1/intune", tags=["intune"])

_pipeline = None
_mapper = IntuneActionMapper()
_identity_resolver = IntuneIdentityResolver()
_proxy = None
_circuit_breaker = None


def configure(pipeline, proxy: IntuneProxy, circuit_breaker: CircuitBreaker) -> None:
    """Called at app startup to inject dependencies."""
    global _pipeline, _proxy, _circuit_breaker
    _pipeline = pipeline
    _proxy = proxy
    _circuit_breaker = circuit_breaker


@router.post("/device-action")
async def device_action(
    action: IntuneDeviceAction,
    request: Request,
) -> JSONResponse:
    """
    Intercept and evaluate an Intune device management action.

    The caller sends this instead of calling Graph API directly.
    Guardian evaluates, and if allowed, forwards to Graph API.
    """
    if _pipeline is None:
        raise HTTPException(503, "Guardian pipeline not initialized")

    authorization = request.headers.get("Authorization", "")

    try:
        # Step 1: Resolve caller identity from Azure AD token
        identity = _identity_resolver.resolve({
            "authorization": authorization,
        })
        actor_name = identity.actor_name

        # Step 2: Circuit breaker check (before pipeline, ultra-fast)
        if _circuit_breaker:
            cb_allowed, cb_reason = _circuit_breaker.check(
                actor_name, action.action,
            )
            if not cb_allowed:
                logger.warning(
                    "Intune circuit breaker denied: actor=%s action=%s device=%s",
                    actor_name, action.action, action.device_id,
                )
                response = IntuneProxyResponse(
                    allowed=False,
                    decision="block",
                    risk_score=1.0,
                    explanation=cb_reason or "Circuit breaker tripped",
                    entry_id="cb-" + action.device_id,
                    circuit_breaker_tripped=True,
                    circuit_breaker_reason=cb_reason,
                )
                return JSONResponse(
                    status_code=403,
                    content=response.model_dump(),
                )

        # Step 3: Map to Guardian ActionRequest
        action_request = _mapper.map_action(action, actor_name=actor_name)

        # Step 4: Evaluate through the full pipeline
        decision = _pipeline.evaluate(action_request)

        allowed = decision.decision in (
            DecisionOutcome.allow,
            DecisionOutcome.allow_with_logging,
        )

        logger.info(
            "Intune proxy: actor=%s action=%s device=%s → %s (risk=%.2f)",
            actor_name, action.action, action.device_id,
            "allowed" if allowed else "denied",
            decision.risk_score,
        )

        if not allowed:
            response = IntuneProxyResponse(
                allowed=False,
                decision=decision.decision.value,
                risk_score=decision.risk_score,
                explanation=decision.explanation[:1000],
                entry_id=decision.entry_id,
            )
            return JSONResponse(
                status_code=403,
                content=response.model_dump(),
            )

        # Step 5: Forward to real Graph API
        if _proxy:
            result = await _proxy.forward(
                device_id=action.device_id,
                action=action.action,
                authorization=authorization,
                body=_build_forward_body(action),
            )
            return JSONResponse(
                status_code=result.status_code,
                content={
                    "guardian": {
                        "allowed": True,
                        "decision": decision.decision.value,
                        "risk_score": decision.risk_score,
                        "entry_id": decision.entry_id,
                    },
                    "graph_api": result.body,
                },
            )

        # No proxy configured (dry-run / testing mode)
        response = IntuneProxyResponse(
            allowed=True,
            decision=decision.decision.value,
            risk_score=decision.risk_score,
            explanation=decision.explanation[:1000],
            entry_id=decision.entry_id,
        )
        return JSONResponse(
            status_code=200,
            content=response.model_dump(),
        )

    except Exception as exc:
        # Fail-closed: deny on error
        logger.error(
            "Intune proxy error for device=%s action=%s: %s",
            action.device_id, action.action, exc,
        )
        response = IntuneProxyResponse(
            allowed=False,
            decision="block",
            risk_score=1.0,
            explanation=f"Guardian evaluation error: {exc}",
            entry_id="error-" + action.device_id,
        )
        return JSONResponse(
            status_code=403,
            content=response.model_dump(),
        )


@router.get("/breaker/status/{actor_name}")
def breaker_status(actor_name: str) -> dict:
    """Check circuit breaker state for an actor."""
    if not _circuit_breaker:
        return {"state": "disabled"}
    state = _circuit_breaker.get_state(actor_name)
    trips = _circuit_breaker.get_trips(actor_name)
    return {
        "actor": actor_name,
        "state": state.value,
        "trip_count": len(trips),
        "recent_trips": [t.model_dump() for t in trips[-5:]],
    }


def _build_forward_body(action: IntuneDeviceAction) -> dict | None:
    """Build the Graph API request body from the intercepted action."""
    if action.action == "wipe":
        body = {}
        if action.keep_enrollment_data is not None:
            body["keepEnrollmentData"] = action.keep_enrollment_data
        if action.keep_user_data is not None:
            body["keepUserData"] = action.keep_user_data
        return body or None
    return None
