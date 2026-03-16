"""
Guardian FastAPI Application

Exposes the Guardian evaluation pipeline as an HTTP API.

Endpoints:
  POST /v1/evaluate                     — submit an action request
  GET  /v1/actors/{actor_name}/profile  — actor history, trust, velocity
  GET  /v1/audit/verify                 — verify audit log hash chain
  GET  /v1/health                       — liveness check
"""

from __future__ import annotations

import logging
import os
from pathlib import Path

from fastapi import FastAPI, HTTPException
from fastapi.responses import JSONResponse
from pydantic import BaseModel

from guardian.history.store import ActorProfile
from guardian.models.action_request import ActionRequest, Decision
from guardian.pipeline import GuardianPipeline

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s %(levelname)s %(name)s — %(message)s",
)
logger = logging.getLogger(__name__)

# ── Configuration ────────────────────────────────────────────────────────────

_ROOT = Path(__file__).parent.parent.parent  # src/guardian/api -> project root
CONFIG_DIR = Path(os.getenv("GUARDIAN_CONFIG_DIR", str(_ROOT / "config")))
POLICIES_DIR = Path(os.getenv("GUARDIAN_POLICIES_DIR", str(_ROOT / "policies")))
AUDIT_LOG = Path(os.getenv("GUARDIAN_AUDIT_LOG", str(_ROOT / "audit.jsonl")))

# ── App setup ─────────────────────────────────────────────────────────────────

app = FastAPI(
    title="Guardian",
    description="Action governance engine for automated and AI-driven operational systems.",
    version="0.1.0",
)

_pipeline: GuardianPipeline | None = None


@app.on_event("startup")
def startup() -> None:
    global _pipeline
    logger.info("Loading Guardian pipeline from config: %s", CONFIG_DIR)
    _pipeline = GuardianPipeline.from_config(
        config_dir=CONFIG_DIR,
        policies_dir=POLICIES_DIR,
        audit_log_path=AUDIT_LOG,
    )
    logger.info("Guardian pipeline ready.")


def get_pipeline() -> GuardianPipeline:
    if _pipeline is None:
        raise HTTPException(status_code=503, detail="Pipeline not initialized.")
    return _pipeline


# ── Endpoints ─────────────────────────────────────────────────────────────────

@app.post("/v1/evaluate", response_model=EvaluateResponse)
def evaluate(request: ActionRequest) -> "EvaluateResponse":
    """Submit an action request for governance evaluation."""
    pipeline = get_pipeline()
    decision = pipeline.evaluate(request)
    return EvaluateResponse.from_decision(decision)


@app.get("/v1/audit/verify")
def audit_verify() -> JSONResponse:
    """Verify the audit log hash chain integrity."""
    pipeline = get_pipeline()
    valid, reason = pipeline.audit_logger.verify()
    return JSONResponse(content={"valid": valid, "reason": reason})


@app.get("/v1/actors/{actor_name}/profile", response_model=ActorProfileResponse)
def actor_profile(actor_name: str) -> "ActorProfileResponse":
    """Retrieve an actor's evaluation history, trust level, and velocity."""
    pipeline = get_pipeline()
    profile = pipeline.history_store.get_profile(actor_name)
    return ActorProfileResponse.from_profile(profile)


@app.get("/v1/health")
def health() -> dict:
    return {"status": "ok", "version": "0.1.0"}


# ── Response model ────────────────────────────────────────────────────────────

class EvaluateResponse(BaseModel):
    decision: str
    risk_score: float
    risk_band: str
    policy_matched: str | None
    explanation: str
    safer_alternatives: list[str]
    compliance_tags: list[str]
    entry_id: str
    drift_score: float | None

    @classmethod
    def from_decision(cls, d: Decision) -> "EvaluateResponse":
        score = d.risk_score
        if score <= 0.30:
            band = "low"
        elif score <= 0.60:
            band = "medium"
        elif score <= 0.80:
            band = "high"
        else:
            band = "critical"

        return cls(
            decision=d.decision.value,
            risk_score=d.risk_score,
            risk_band=band,
            policy_matched=d.policy_matched,
            explanation=d.explanation,
            safer_alternatives=d.safer_alternatives,
            compliance_tags=d.compliance_tags,
            entry_id=d.entry_id,
            drift_score=d.drift_score.score if d.drift_score else None,
        )


class ActorProfileResponse(BaseModel):
    actor_name: str
    total_actions: int
    total_blocks: int
    total_reviews: int
    total_allows: int
    prior_privilege_escalations: int
    history_days: int
    trust_level: float
    trust_band: str
    actions_last_hour: int
    actions_last_day: int
    first_seen: str | None
    last_seen: str | None
    top_actions: dict[str, int]

    @classmethod
    def from_profile(cls, p: ActorProfile) -> "ActorProfileResponse":
        if p.trust_level >= 0.7:
            trust_band = "high"
        elif p.trust_level >= 0.4:
            trust_band = "neutral"
        else:
            trust_band = "low"

        return cls(
            actor_name=p.actor_name,
            total_actions=p.total_actions,
            total_blocks=p.total_blocks,
            total_reviews=p.total_reviews,
            total_allows=p.total_allows,
            prior_privilege_escalations=p.prior_privilege_escalations,
            history_days=p.history_days,
            trust_level=p.trust_level,
            trust_band=trust_band,
            actions_last_hour=p.actions_last_hour,
            actions_last_day=p.actions_last_day,
            first_seen=p.first_seen.isoformat() if p.first_seen else None,
            last_seen=p.last_seen.isoformat() if p.last_seen else None,
            top_actions=p.top_actions,
        )
