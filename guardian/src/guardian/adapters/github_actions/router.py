"""
GitHub Actions Deployment Protection Rule Router

GitHub sends deployment_protection_rule webhook events to Guardian.
Guardian evaluates and POSTs approval/rejection back to GitHub's
callback URL — same async callback pattern as the Terraform adapter.
"""

from __future__ import annotations

import logging

import httpx
from fastapi import APIRouter, BackgroundTasks, HTTPException

from guardian.adapters.github_actions.mapper import GitHubDeploymentMapper
from guardian.adapters.github_actions.models import (
    GitHubDeploymentRequest,
    GitHubDeploymentResponse,
)
from guardian.models.action_request import DecisionOutcome

logger = logging.getLogger(__name__)

router = APIRouter(prefix="/v1/github", tags=["github"])

_pipeline = None
_mapper = GitHubDeploymentMapper()
_github_token = ""


def configure(pipeline, github_token: str = "") -> None:
    global _pipeline, _github_token
    _pipeline = pipeline
    _github_token = github_token


@router.post("/deployment-gate")
async def deployment_gate(
    deployment: GitHubDeploymentRequest,
    background_tasks: BackgroundTasks,
) -> dict:
    """
    GitHub deployment protection rule webhook endpoint.

    Acknowledges immediately and processes asynchronously (GitHub
    expects 200 within 10 seconds, same as Terraform).
    """
    if _pipeline is None:
        raise HTTPException(503, "Guardian pipeline not initialized")

    background_tasks.add_task(_process_deployment, deployment)
    return {"status": "acknowledged", "run_id": deployment.run_id}


async def _process_deployment(deployment: GitHubDeploymentRequest) -> None:
    """Evaluate the deployment and callback to GitHub."""
    try:
        action_request = _mapper.map_deployment(deployment)
        decision = _pipeline.evaluate(action_request)

        allowed = decision.decision in (
            DecisionOutcome.allow, DecisionOutcome.allow_with_logging,
        )

        logger.info(
            "GitHub deploy: actor=%s env=%s repo=%s -> %s (risk=%.2f)",
            deployment.sender_login, deployment.environment,
            deployment.repository_full_name,
            "approved" if allowed else "rejected", decision.risk_score,
        )

        if deployment.deployment_callback_url:
            state = "approved" if allowed else "rejected"
            comment = (
                f"Guardian: {decision.decision.value} (risk: {decision.risk_score:.2f}). "
                f"{decision.explanation[:500]}"
            )
            await _send_callback(deployment.deployment_callback_url, state, comment)

    except Exception as exc:
        logger.error("GitHub deployment processing failed: %s", exc)
        if deployment.deployment_callback_url:
            await _send_callback(
                deployment.deployment_callback_url, "rejected",
                f"Guardian evaluation error: {exc}",
            )


async def _send_callback(callback_url: str, state: str, comment: str) -> None:
    """POST approval/rejection to GitHub's callback URL."""
    if not callback_url:
        return

    payload = {"state": state, "comment": comment[:1000]}

    try:
        headers = {"Accept": "application/vnd.github+json"}
        if _github_token:
            headers["Authorization"] = f"Bearer {_github_token}"

        async with httpx.AsyncClient() as client:
            resp = await client.post(
                callback_url, json=payload, headers=headers, timeout=10.0,
            )
            resp.raise_for_status()
            logger.info("GitHub callback sent: state=%s", state)
    except httpx.HTTPError as exc:
        logger.error("GitHub callback failed: %s", exc)
