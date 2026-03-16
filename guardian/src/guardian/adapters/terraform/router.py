"""
Terraform Cloud Run Task Router

FastAPI router implementing the Terraform Cloud run task webhook protocol.

Flow:
  1. TFC POSTs to /v1/terraform/run-task with plan metadata + access token
  2. Guardian acknowledges immediately (TFC expects 200 within 10 seconds)
  3. Guardian fetches the plan JSON, maps to ActionRequests, evaluates each
  4. Guardian POSTs the result back to TFC's callback URL
"""

from __future__ import annotations

import logging

import httpx
from fastapi import APIRouter, BackgroundTasks, HTTPException

from guardian.adapters.terraform.mapper import TerraformPlanMapper
from guardian.adapters.terraform.models import (
    TFCCallbackAttributes,
    TFCCallbackData,
    TFCCallbackPayload,
    TFCRunTaskRequest,
)
from guardian.models.action_request import DecisionOutcome

logger = logging.getLogger(__name__)

router = APIRouter(prefix="/v1/terraform", tags=["terraform"])

# These are injected at startup by app.py
_pipeline = None
_mapper = None


def configure(pipeline, mapper: TerraformPlanMapper) -> None:
    """Called at app startup to inject dependencies."""
    global _pipeline, _mapper
    _pipeline = pipeline
    _mapper = mapper


@router.post("/run-task")
async def run_task(
    request: TFCRunTaskRequest,
    background_tasks: BackgroundTasks,
) -> dict:
    """
    Terraform Cloud run task webhook endpoint.

    Acknowledges immediately and processes the plan asynchronously.
    """
    if _pipeline is None:
        raise HTTPException(503, "Guardian pipeline not initialized")

    background_tasks.add_task(_process_run_task, request)
    return {"status": "acknowledged", "run_id": request.run_id}


async def _process_run_task(request: TFCRunTaskRequest) -> None:
    """Fetch plan, evaluate, and callback to TFC."""
    try:
        # Fetch the plan JSON from Terraform Cloud
        async with httpx.AsyncClient() as client:
            plan_response = await client.get(
                request.plan_json_api_url,
                headers={
                    "Authorization": f"Bearer {request.access_token}",
                    "Content-Type": "application/vnd.api+json",
                },
                timeout=30.0,
            )
            plan_response.raise_for_status()
            plan_json = plan_response.json()

        # Determine actor from the run
        actor_name = request.run_created_by or f"terraform-{request.workspace_name}"

        # Map plan to ActionRequests
        action_requests = _mapper.map_plan(plan_json, actor_name=actor_name)

        if not action_requests:
            await _send_callback(request, "passed", "No resource changes to evaluate.")
            return

        # Evaluate each action request
        decisions = []
        for action_request in action_requests:
            decision = _pipeline.evaluate(action_request)
            decisions.append(decision)

        # Determine overall result
        blocked = [d for d in decisions if d.decision == DecisionOutcome.block]
        reviews = [d for d in decisions if d.decision == DecisionOutcome.require_review]

        if blocked:
            summaries = [
                f"BLOCKED: {d.action_request.requested_action} on "
                f"{d.action_request.target_asset} — {d.explanation[:100]}"
                for d in blocked
            ]
            message = f"Guardian blocked {len(blocked)} action(s):\n" + "\n".join(summaries)
            await _send_callback(request, "failed", message)
        elif reviews:
            summaries = [
                f"REVIEW: {d.action_request.requested_action} on "
                f"{d.action_request.target_asset}"
                for d in reviews
            ]
            message = (
                f"Guardian flagged {len(reviews)} action(s) for review:\n"
                + "\n".join(summaries)
            )
            # Advisory enforcement: pass with warning
            if request.task_result_enforcement_level == "advisory":
                await _send_callback(request, "passed", message)
            else:
                await _send_callback(request, "failed", message)
        else:
            message = f"Guardian approved {len(decisions)} action(s)."
            await _send_callback(request, "passed", message)

    except Exception as exc:
        logger.error("Terraform run task processing failed: %s", exc)
        await _send_callback(
            request, "failed",
            f"Guardian evaluation error: {exc}",
        )


async def _send_callback(
    request: TFCRunTaskRequest, status: str, message: str,
) -> None:
    """Send the result back to Terraform Cloud."""
    payload = TFCCallbackPayload(
        data=TFCCallbackData(
            attributes=TFCCallbackAttributes(
                status=status,
                message=message[:4096],  # TFC message limit
            ),
        ),
    )

    try:
        async with httpx.AsyncClient() as client:
            resp = await client.patch(
                request.task_result_callback_url,
                json=payload.model_dump(),
                headers={
                    "Authorization": f"Bearer {request.access_token}",
                    "Content-Type": "application/vnd.api+json",
                },
                timeout=10.0,
            )
            resp.raise_for_status()
            logger.info("TFC callback sent: status=%s run=%s", status, request.run_id)
    except httpx.HTTPError as exc:
        logger.error("TFC callback failed for run %s: %s", request.run_id, exc)
