"""
Jamf Pro MDM Proxy Router

Intercepts Jamf Pro device management commands, evaluates through
Guardian's pipeline (with circuit breaker), and forwards or blocks.
"""

from __future__ import annotations

import logging

from fastapi import APIRouter, HTTPException, Request
from fastapi.responses import JSONResponse

from guardian.adapters.jamf.mapper import JamfCommandMapper
from guardian.adapters.jamf.models import JamfDeviceCommand, JamfProxyResponse
from guardian.circuit_breaker.breaker import CircuitBreaker
from guardian.models.action_request import DecisionOutcome

logger = logging.getLogger(__name__)

router = APIRouter(prefix="/v1/jamf", tags=["jamf"])

_pipeline = None
_mapper = JamfCommandMapper()
_circuit_breaker = None


def configure(pipeline, circuit_breaker: CircuitBreaker | None = None) -> None:
    global _pipeline, _circuit_breaker
    _pipeline = pipeline
    _circuit_breaker = circuit_breaker


@router.post("/device-command")
async def device_command(command: JamfDeviceCommand, request: Request) -> JSONResponse:
    """Intercept and evaluate a Jamf Pro device management command."""
    if _pipeline is None:
        raise HTTPException(503, "Guardian pipeline not initialized")

    # Jamf uses Bearer token auth — extract actor from token or header
    actor_name = request.headers.get("X-Guardian-Actor", "unknown-jamf-admin")

    try:
        action_request = _mapper.map_command(command, actor_name=actor_name)

        # Circuit breaker check
        if _circuit_breaker:
            cb_allowed, cb_reason = _circuit_breaker.check(
                actor_name, action_request.requested_action,
            )
            if not cb_allowed:
                logger.warning("Jamf circuit breaker denied: actor=%s cmd=%s", actor_name, command.command)
                return JSONResponse(status_code=403, content=JamfProxyResponse(
                    allowed=False, decision="block", risk_score=1.0,
                    explanation=cb_reason or "Circuit breaker tripped",
                    entry_id="cb-jamf-" + command.device_id,
                    circuit_breaker_tripped=True, circuit_breaker_reason=cb_reason,
                ).model_dump())

        decision = _pipeline.evaluate(action_request)

        allowed = decision.decision in (
            DecisionOutcome.allow, DecisionOutcome.allow_with_logging,
        )

        logger.info(
            "Jamf proxy: actor=%s cmd=%s device=%s -> %s (risk=%.2f)",
            actor_name, command.command, command.device_id,
            "allowed" if allowed else "denied", decision.risk_score,
        )

        return JSONResponse(
            status_code=200 if allowed else 403,
            content=JamfProxyResponse(
                allowed=allowed, decision=decision.decision.value,
                risk_score=decision.risk_score,
                explanation=decision.explanation[:1000],
                entry_id=decision.entry_id,
            ).model_dump(),
        )

    except Exception as exc:
        logger.error("Jamf proxy error: %s", exc)
        return JSONResponse(status_code=403, content=JamfProxyResponse(
            allowed=False, decision="block", risk_score=1.0,
            explanation=f"Guardian evaluation error: {exc}",
            entry_id="error-jamf-" + command.device_id,
        ).model_dump())
