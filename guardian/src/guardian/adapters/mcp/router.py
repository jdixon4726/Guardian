"""
MCP Tool Call Governance Router

FastAPI endpoints for evaluating MCP tool calls through Guardian.
Supports both synchronous (proxy) and async (audit) modes.
"""

from __future__ import annotations

import logging

from fastapi import APIRouter, HTTPException
from fastapi.responses import JSONResponse

from guardian.adapters.mcp.mapper import MCPToolCallMapper
from guardian.adapters.mcp.models import MCPToolCall, MCPToolResult
from guardian.circuit_breaker.breaker import CircuitBreaker
from guardian.models.action_request import DecisionOutcome

logger = logging.getLogger(__name__)

router = APIRouter(prefix="/v1/mcp", tags=["mcp"])

_pipeline = None
_mapper = MCPToolCallMapper()
_circuit_breaker = None


def configure(pipeline, circuit_breaker: CircuitBreaker | None = None) -> None:
    global _pipeline, _circuit_breaker
    _pipeline = pipeline
    _circuit_breaker = circuit_breaker


@router.post("/evaluate-tool-call")
async def evaluate_tool_call(tool_call: MCPToolCall) -> JSONResponse:
    """
    Evaluate an MCP tool_call before the tool server processes it.

    This is the synchronous proxy pattern: the agent framework calls
    Guardian instead of the MCP server directly. Guardian evaluates
    and returns allow/deny.
    """
    if _pipeline is None:
        raise HTTPException(503, "Guardian pipeline not initialized")

    try:
        action_request = _mapper.map_tool_call(tool_call)

        # Circuit breaker
        if _circuit_breaker:
            cb_allowed, cb_reason = _circuit_breaker.check(
                action_request.actor_name, action_request.requested_action,
            )
            if not cb_allowed:
                logger.warning(
                    "MCP circuit breaker denied: agent=%s tool=%s",
                    tool_call.agent_id, tool_call.tool_name,
                )
                return JSONResponse(status_code=403, content=MCPToolResult(
                    allowed=False, decision="block", risk_score=1.0,
                    explanation=cb_reason or "Circuit breaker tripped",
                    entry_id="cb-mcp-" + tool_call.tool_name,
                    tool_name=tool_call.tool_name,
                    circuit_breaker_tripped=True,
                ).model_dump())

        decision = _pipeline.evaluate(action_request)

        allowed = decision.decision in (
            DecisionOutcome.allow, DecisionOutcome.allow_with_logging,
        )

        logger.info(
            "MCP eval: agent=%s tool=%s server=%s -> %s (risk=%.2f)",
            tool_call.agent_id, tool_call.tool_name, tool_call.tool_server,
            "allowed" if allowed else "denied", decision.risk_score,
        )

        return JSONResponse(
            status_code=200 if allowed else 403,
            content=MCPToolResult(
                allowed=allowed,
                decision=decision.decision.value,
                risk_score=decision.risk_score,
                explanation=decision.explanation[:1000],
                entry_id=decision.entry_id,
                tool_name=tool_call.tool_name,
            ).model_dump(),
        )

    except Exception as exc:
        logger.error("MCP eval error: tool=%s err=%s", tool_call.tool_name, exc)
        return JSONResponse(status_code=403, content=MCPToolResult(
            allowed=False, decision="block", risk_score=1.0,
            explanation=f"Guardian evaluation error: {exc}",
            entry_id="error-mcp",
            tool_name=tool_call.tool_name,
        ).model_dump())


@router.post("/evaluate-batch")
async def evaluate_batch(tool_calls: list[MCPToolCall]) -> JSONResponse:
    """Evaluate a batch of MCP tool calls."""
    if _pipeline is None:
        raise HTTPException(503, "Guardian pipeline not initialized")

    results = []
    for tc in tool_calls:
        try:
            action_request = _mapper.map_tool_call(tc)

            if _circuit_breaker:
                cb_allowed, cb_reason = _circuit_breaker.check(
                    action_request.actor_name, action_request.requested_action,
                )
                if not cb_allowed:
                    results.append(MCPToolResult(
                        allowed=False, decision="block", risk_score=1.0,
                        explanation=cb_reason or "CB tripped",
                        entry_id="cb-mcp-batch",
                        tool_name=tc.tool_name,
                        circuit_breaker_tripped=True,
                    ))
                    continue

            decision = _pipeline.evaluate(action_request)
            allowed = decision.decision in (
                DecisionOutcome.allow, DecisionOutcome.allow_with_logging,
            )
            results.append(MCPToolResult(
                allowed=allowed,
                decision=decision.decision.value,
                risk_score=decision.risk_score,
                explanation=decision.explanation[:500],
                entry_id=decision.entry_id,
                tool_name=tc.tool_name,
            ))
        except Exception as exc:
            results.append(MCPToolResult(
                allowed=False, decision="block", risk_score=1.0,
                explanation=f"Error: {exc}",
                entry_id="error-mcp-batch",
                tool_name=tc.tool_name,
            ))

    return JSONResponse(content=[r.model_dump() for r in results])
