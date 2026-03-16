"""
Kubernetes Validating Admission Webhook Router

FastAPI router implementing the K8s admission webhook protocol.
The K8s API server sends AdmissionReview requests; Guardian evaluates
and responds with allow/deny synchronously.

Unlike Terraform (async callback), K8s admission is synchronous —
the API server blocks until Guardian responds.
"""

from __future__ import annotations

import logging

from fastapi import APIRouter, HTTPException

from guardian.adapters.kubernetes.mapper import KubernetesAdmissionMapper
from guardian.adapters.kubernetes.models import (
    AdmissionResponse,
    AdmissionReviewRequest,
    AdmissionReviewResponse,
)
from guardian.models.action_request import DecisionOutcome

logger = logging.getLogger(__name__)

router = APIRouter(prefix="/v1/kubernetes", tags=["kubernetes"])

_pipeline = None
_mapper = KubernetesAdmissionMapper()


def configure(pipeline) -> None:
    """Called at app startup to inject the pipeline."""
    global _pipeline
    _pipeline = pipeline


@router.post("/admit")
def admit(review: AdmissionReviewRequest) -> AdmissionReviewResponse:
    """
    Kubernetes validating admission webhook endpoint.

    Evaluates the admission request through Guardian's pipeline and
    returns an AdmissionReview response. Fail-closed: if Guardian
    encounters an error, the request is denied.
    """
    if _pipeline is None:
        raise HTTPException(503, "Guardian pipeline not initialized")

    uid = review.request.uid

    try:
        # Map K8s admission to Guardian action request
        action_request = _mapper.map_admission(review.request)

        # Evaluate through the full pipeline
        decision = _pipeline.evaluate(action_request)

        # Map Guardian decision to K8s allow/deny
        allowed = decision.decision in (
            DecisionOutcome.allow,
            DecisionOutcome.allow_with_logging,
        )

        status = {}
        if not allowed:
            status = {
                "code": 403,
                "message": (
                    f"Guardian: {decision.decision.value}. "
                    f"{decision.explanation[:500]}"
                ),
            }

        logger.info(
            "K8s admission: uid=%s actor=%s action=%s → %s",
            uid, action_request.actor_name,
            action_request.requested_action,
            "allowed" if allowed else "denied",
        )

        return AdmissionReviewResponse(
            response=AdmissionResponse(
                uid=uid,
                allowed=allowed,
                status=status,
            ),
        )

    except Exception as exc:
        # Fail-closed: deny on error
        logger.error("K8s admission error for uid=%s: %s", uid, exc)
        return AdmissionReviewResponse(
            response=AdmissionResponse(
                uid=uid,
                allowed=False,
                status={
                    "code": 500,
                    "message": f"Guardian evaluation error: {exc}",
                },
            ),
        )
