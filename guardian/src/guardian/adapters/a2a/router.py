"""
A2A Task Delegation Governance Router

Evaluates agent-to-agent task delegations through Guardian.
"""

from __future__ import annotations

import logging

from fastapi import APIRouter, HTTPException
from fastapi.responses import JSONResponse

from guardian.adapters.a2a.mapper import A2ATaskMapper
from guardian.adapters.a2a.models import A2ATaskDelegation, A2AEvaluation
from guardian.circuit_breaker.breaker import CircuitBreaker
from guardian.models.action_request import DecisionOutcome

logger = logging.getLogger(__name__)

router = APIRouter(prefix="/v1/a2a", tags=["a2a"])

_pipeline = None
_mapper = A2ATaskMapper()
_circuit_breaker = None


def configure(pipeline, circuit_breaker: CircuitBreaker | None = None) -> None:
    global _pipeline, _circuit_breaker
    _pipeline = pipeline
    _circuit_breaker = circuit_breaker


@router.post("/evaluate-delegation")
async def evaluate_delegation(delegation: A2ATaskDelegation) -> JSONResponse:
    """Evaluate an A2A task delegation before the receiver accepts."""
    if _pipeline is None:
        raise HTTPException(503, "Guardian pipeline not initialized")

    try:
        action_request = _mapper.map_delegation(delegation)
        chain_risk = _mapper.chain_risk_level(delegation)

        # Circuit breaker
        if _circuit_breaker:
            cb_allowed, cb_reason = _circuit_breaker.check(
                action_request.actor_name, action_request.requested_action,
            )
            if not cb_allowed:
                return JSONResponse(status_code=403, content=A2AEvaluation(
                    allowed=False, decision="block", risk_score=1.0,
                    explanation=cb_reason or "Circuit breaker tripped",
                    entry_id="cb-a2a",
                    delegation_depth=delegation.delegation_depth,
                    chain_risk=chain_risk,
                    circuit_breaker_tripped=True,
                ).model_dump())

        decision = _pipeline.evaluate(action_request)
        allowed = decision.decision in (
            DecisionOutcome.allow, DecisionOutcome.allow_with_logging,
        )

        logger.info(
            "A2A eval: %s -> %s task=%s depth=%d -> %s (risk=%.2f, chain=%s)",
            delegation.sender_agent_id, delegation.receiver_agent_id,
            delegation.task_type, delegation.delegation_depth,
            "allowed" if allowed else "denied",
            decision.risk_score, chain_risk,
        )

        return JSONResponse(
            status_code=200 if allowed else 403,
            content=A2AEvaluation(
                allowed=allowed,
                decision=decision.decision.value,
                risk_score=decision.risk_score,
                explanation=decision.explanation[:1000],
                entry_id=decision.entry_id,
                delegation_depth=delegation.delegation_depth,
                chain_risk=chain_risk,
            ).model_dump(),
        )

    except Exception as exc:
        logger.error("A2A eval error: %s", exc)
        return JSONResponse(status_code=403, content=A2AEvaluation(
            allowed=False, decision="block", risk_score=1.0,
            explanation=f"Guardian evaluation error: {exc}",
            entry_id="error-a2a",
        ).model_dump())
