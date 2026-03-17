"""
AWS EventBridge Router

Receives CloudTrail events (via EventBridge -> API Gateway -> Guardian)
and evaluates them through the pipeline. Unlike the proxy adapters,
this is post-execution evaluation with quarantine recommendations.

Pattern 3: Event-driven evaluation.
  - The action has already executed in AWS
  - Guardian evaluates and determines if it was anomalous
  - If high-risk, Guardian recommends quarantine (SCP attachment, key disable)
  - The caller (a Lambda or Step Functions workflow) acts on the recommendation
"""

from __future__ import annotations

import logging
from typing import Optional

from fastapi import APIRouter, HTTPException
from fastapi.responses import JSONResponse

from guardian.adapters.aws_eventbridge.mapper import CloudTrailMapper
from guardian.adapters.aws_eventbridge.models import (
    CloudTrailEvent,
    EventBridgeEvaluation,
)
from guardian.circuit_breaker.breaker import CircuitBreaker
from guardian.models.action_request import DecisionOutcome

logger = logging.getLogger(__name__)

router = APIRouter(prefix="/v1/aws", tags=["aws"])

_pipeline = None
_mapper = CloudTrailMapper()
_circuit_breaker = None


def configure(pipeline, circuit_breaker: CircuitBreaker | None = None) -> None:
    global _pipeline, _circuit_breaker
    _pipeline = pipeline
    _circuit_breaker = circuit_breaker


@router.post("/evaluate-event")
async def evaluate_event(event: CloudTrailEvent) -> JSONResponse:
    """
    Evaluate a CloudTrail event against Guardian's behavioral baselines.

    This is post-execution: the action already happened in AWS.
    Guardian's response tells the caller whether to quarantine.
    """
    if _pipeline is None:
        raise HTTPException(503, "Guardian pipeline not initialized")

    try:
        action_request = _mapper.map_event(event)

        # Circuit breaker (tracks velocity even for post-execution)
        cb_tripped = False
        if _circuit_breaker:
            cb_allowed, cb_reason = _circuit_breaker.check(
                action_request.actor_name, action_request.requested_action,
            )
            if not cb_allowed:
                cb_tripped = True
                logger.warning(
                    "AWS circuit breaker tripped: actor=%s event=%s",
                    action_request.actor_name, event.event_name,
                )
                return JSONResponse(content=EventBridgeEvaluation(
                    event_id=event.event_id,
                    allowed=False, decision="block", risk_score=1.0,
                    explanation=cb_reason or "Circuit breaker tripped",
                    entry_id="cb-aws-" + event.event_id,
                    quarantine_recommended=True,
                    quarantine_action="attach_deny_scp",
                ).model_dump())

        decision = _pipeline.evaluate(action_request)

        is_high_risk = decision.decision in (
            DecisionOutcome.block, DecisionOutcome.require_review,
        )
        should_quarantine = is_high_risk and _mapper.should_quarantine(event)

        logger.info(
            "AWS event: actor=%s event=%s -> %s (risk=%.2f, quarantine=%s)",
            action_request.actor_name, event.event_name,
            decision.decision.value, decision.risk_score,
            should_quarantine,
        )

        return JSONResponse(content=EventBridgeEvaluation(
            event_id=event.event_id,
            allowed=decision.decision in (
                DecisionOutcome.allow, DecisionOutcome.allow_with_logging,
            ),
            decision=decision.decision.value,
            risk_score=decision.risk_score,
            explanation=decision.explanation[:1000],
            entry_id=decision.entry_id,
            quarantine_recommended=should_quarantine,
            quarantine_action=_mapper.quarantine_action(event) if should_quarantine else "",
        ).model_dump())

    except Exception as exc:
        logger.error("AWS event evaluation error: %s", exc)
        return JSONResponse(content=EventBridgeEvaluation(
            event_id=event.event_id,
            allowed=False, decision="block", risk_score=1.0,
            explanation=f"Guardian evaluation error: {exc}",
            entry_id="error-aws-" + event.event_id,
            quarantine_recommended=True,
            quarantine_action="notify_security_team",
        ).model_dump())


@router.post("/evaluate-batch")
async def evaluate_batch(events: list[CloudTrailEvent]) -> JSONResponse:
    """Evaluate a batch of CloudTrail events."""
    if _pipeline is None:
        raise HTTPException(503, "Guardian pipeline not initialized")

    results = []
    for event in events:
        try:
            action_request = _mapper.map_event(event)
            decision = _pipeline.evaluate(action_request)

            is_high_risk = decision.decision in (
                DecisionOutcome.block, DecisionOutcome.require_review,
            )
            should_quarantine = is_high_risk and _mapper.should_quarantine(event)

            results.append(EventBridgeEvaluation(
                event_id=event.event_id,
                allowed=decision.decision in (
                    DecisionOutcome.allow, DecisionOutcome.allow_with_logging,
                ),
                decision=decision.decision.value,
                risk_score=decision.risk_score,
                explanation=decision.explanation[:500],
                entry_id=decision.entry_id,
                quarantine_recommended=should_quarantine,
                quarantine_action=_mapper.quarantine_action(event) if should_quarantine else "",
            ))
        except Exception as exc:
            results.append(EventBridgeEvaluation(
                event_id=event.event_id,
                allowed=False, decision="block", risk_score=1.0,
                explanation=f"Error: {exc}",
                entry_id="error-" + event.event_id,
                quarantine_recommended=True,
                quarantine_action="notify_security_team",
            ))

    return JSONResponse(content=[r.model_dump() for r in results])
