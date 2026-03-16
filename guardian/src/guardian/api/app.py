"""
Guardian FastAPI Application

Exposes the Guardian evaluation pipeline as an HTTP API.

Endpoints:
  POST /v1/evaluate                     — submit an action request
  GET  /v1/decisions/recent             — recent decisions (queryable)
  GET  /v1/actors/{actor_name}/profile  — actor history, trust, velocity
  GET  /v1/audit/verify                 — verify audit log hash chain
  GET  /v1/health                       — deep health check
"""

from __future__ import annotations

import json
import logging
import os
from datetime import datetime, timezone
from pathlib import Path
from typing import Optional

from fastapi import Depends, FastAPI, HTTPException, Query, Request
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import FileResponse, JSONResponse
from fastapi.staticfiles import StaticFiles
from pydantic import BaseModel, Field

from guardian.history.store import ActorProfile
from guardian.models.action_request import ActionRequest, Decision, DecisionOutcome
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
API_KEY = os.getenv("GUARDIAN_API_KEY", "")  # empty = no auth (dev mode)
SHADOW_MODE = os.getenv("GUARDIAN_SHADOW_MODE", "false").lower() == "true"

# ── App setup ─────────────────────────────────────────────────────────────────

app = FastAPI(
    title="Guardian",
    description="Behavioral governance engine for machine identities.",
    version="0.2.0",
)

app.add_middleware(
    CORSMiddleware,
    allow_origins=os.getenv("GUARDIAN_CORS_ORIGINS", "*").split(","),
    allow_methods=["GET", "POST"],
    allow_headers=["*"],
)

# Serve the dashboard UI
_STATIC_DIR = Path(__file__).parent / "static"
if _STATIC_DIR.exists():
    app.mount("/static", StaticFiles(directory=str(_STATIC_DIR)), name="static")

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
    if SHADOW_MODE:
        logger.info("Guardian running in SHADOW MODE — advisory only, no enforcement")
    logger.info("Guardian pipeline ready.")


def get_pipeline() -> GuardianPipeline:
    if _pipeline is None:
        raise HTTPException(status_code=503, detail="Pipeline not initialized.")
    return _pipeline


def verify_api_key(request: Request) -> None:
    """Verify API key if GUARDIAN_API_KEY is set."""
    if not API_KEY:
        return  # no auth in dev mode
    auth = request.headers.get("Authorization", "")
    if auth != f"Bearer {API_KEY}":
        raise HTTPException(status_code=401, detail="Invalid or missing API key")


# ── Response models (defined before endpoints) ───────────────────────────────

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
    shadow_mode: bool = False
    behavioral_risk: float | None = None
    is_anomalous: bool = False

    @classmethod
    def from_decision(cls, d: Decision, shadow: bool = False) -> "EvaluateResponse":
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
            shadow_mode=shadow,
        )


class DecisionSummary(BaseModel):
    entry_id: str
    actor_name: str
    action: str
    target_asset: str
    decision: str
    risk_score: float
    risk_band: str
    drift_score: float | None
    evaluated_at: str


class RecentDecisionsResponse(BaseModel):
    decisions: list[DecisionSummary]
    total: int
    shadow_mode: bool = False


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


class HealthResponse(BaseModel):
    status: str
    version: str
    shadow_mode: bool
    components: dict[str, str]


# ── Endpoints ─────────────────────────────────────────────────────────────────

@app.post("/v1/evaluate", response_model=EvaluateResponse)
def evaluate(
    request: ActionRequest,
    _auth: None = Depends(verify_api_key),
) -> EvaluateResponse:
    """Submit an action request for governance evaluation."""
    pipeline = get_pipeline()
    decision = pipeline.evaluate(request)

    response = EvaluateResponse.from_decision(decision, shadow=SHADOW_MODE)

    # In shadow mode, override the decision to allow (but log the real decision)
    if SHADOW_MODE and decision.decision != DecisionOutcome.allow:
        logger.info(
            "SHADOW: would have returned %s for %s/%s, returning allow instead",
            decision.decision.value, request.actor_name, request.requested_action,
        )
        response.decision = "allow"
        response.shadow_mode = True

    return response


@app.get("/v1/decisions/recent", response_model=RecentDecisionsResponse)
def recent_decisions(
    limit: int = Query(default=50, ge=1, le=500),
    actor: str | None = Query(default=None),
    decision_filter: str | None = Query(default=None, alias="decision"),
    _auth: None = Depends(verify_api_key),
) -> RecentDecisionsResponse:
    """Retrieve recent decisions from the audit log."""
    pipeline = get_pipeline()
    log_path = pipeline.audit_logger.log_path

    if not log_path.exists():
        return RecentDecisionsResponse(decisions=[], total=0, shadow_mode=SHADOW_MODE)

    # Read the audit log in reverse (most recent first)
    all_lines = []
    with open(log_path, encoding="utf-8") as f:
        all_lines = f.readlines()

    summaries = []
    for line in reversed(all_lines):
        if len(summaries) >= limit:
            break
        line = line.strip()
        if not line:
            continue
        try:
            entry = json.loads(line)
            req = entry.get("action_request", {})

            # Apply filters
            if actor and req.get("actor_name") != actor:
                continue
            if decision_filter and entry.get("decision") != decision_filter:
                continue

            score = entry.get("risk_score", 0.0)
            if score <= 0.30:
                band = "low"
            elif score <= 0.60:
                band = "medium"
            elif score <= 0.80:
                band = "high"
            else:
                band = "critical"

            drift = entry.get("drift_score")
            summaries.append(DecisionSummary(
                entry_id=entry.get("entry_id", ""),
                actor_name=req.get("actor_name", ""),
                action=req.get("requested_action", ""),
                target_asset=req.get("target_asset", ""),
                decision=entry.get("decision", ""),
                risk_score=score,
                risk_band=band,
                drift_score=drift.get("score") if isinstance(drift, dict) else None,
                evaluated_at=entry.get("evaluated_at", ""),
            ))
        except (json.JSONDecodeError, KeyError):
            continue

    return RecentDecisionsResponse(
        decisions=summaries,
        total=len(summaries),
        shadow_mode=SHADOW_MODE,
    )


@app.get("/v1/actors/{actor_name}/profile", response_model=ActorProfileResponse)
def actor_profile(
    actor_name: str,
    _auth: None = Depends(verify_api_key),
) -> ActorProfileResponse:
    """Retrieve an actor's evaluation history, trust level, and velocity."""
    pipeline = get_pipeline()
    profile = pipeline.history_store.get_profile(actor_name)
    return ActorProfileResponse.from_profile(profile)


@app.get("/v1/audit/verify")
def audit_verify(
    _auth: None = Depends(verify_api_key),
) -> JSONResponse:
    """Verify the audit log hash chain integrity."""
    pipeline = get_pipeline()
    valid, reason = pipeline.audit_logger.verify()
    return JSONResponse(content={"valid": valid, "reason": reason})


@app.get("/v1/reconciliation/report")
def reconciliation_report(
    window_minutes: int = Query(default=60, ge=1, le=1440),
    _auth: None = Depends(verify_api_key),
) -> JSONResponse:
    """Run a reconciliation check for the specified time window."""
    pipeline = get_pipeline()
    from guardian.reconciliation.engine import ReconciliationEngine
    engine = ReconciliationEngine([], pipeline.audit_logger.log_path)
    report = engine.reconcile(window_minutes=window_minutes)
    return JSONResponse(content={
        "window_start": report.window_start.isoformat(),
        "window_end": report.window_end.isoformat(),
        "total_external_actions": report.total_external_actions,
        "total_governed": report.total_governed,
        "total_ungoverned": report.total_ungoverned,
        "ungoverned_actions": [
            {
                "actor": a.external_action.actor,
                "action": a.external_action.action,
                "resource": a.external_action.resource,
                "severity": a.severity,
                "explanation": a.explanation,
            }
            for a in report.ungoverned_actions
        ],
    })


@app.get("/", include_in_schema=False)
def dashboard() -> FileResponse:
    """Serve the Guardian dashboard."""
    return FileResponse(str(_STATIC_DIR / "index.html"))


@app.get("/v1/health", response_model=HealthResponse)
def health() -> HealthResponse:
    """Deep health check — verifies all dependencies are operational."""
    components = {}

    # Check pipeline
    if _pipeline is not None:
        components["pipeline"] = "ok"

        # Check audit log writability
        try:
            _pipeline.audit_logger.log_path.parent.exists()
            components["audit_log"] = "ok"
        except Exception:
            components["audit_log"] = "error"

        # Check policy engine
        try:
            _pipeline.policy_engine.health_check()
            components["policy_engine"] = "ok"
        except Exception:
            components["policy_engine"] = "error"

        # Check history store
        try:
            _pipeline.history_store.get_profile("__health_check__")
            components["history_store"] = "ok"
        except Exception:
            components["history_store"] = "error"
    else:
        components["pipeline"] = "not_initialized"

    overall = "ok" if all(v == "ok" for v in components.values()) else "degraded"

    return HealthResponse(
        status=overall,
        version="0.2.0",
        shadow_mode=SHADOW_MODE,
        components=components,
    )
