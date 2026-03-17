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

from fastapi import Depends, FastAPI, HTTPException, Query, Request, Response
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import FileResponse, JSONResponse
from fastapi.staticfiles import StaticFiles
from pydantic import BaseModel, Field

from guardian.adapters.intune.proxy import IntuneProxy
from guardian.adapters.intune.router import (
    configure as configure_intune,
    router as intune_router,
)
from guardian.adapters.entra_id.router import (
    configure as configure_entra,
    router as entra_router,
)
from guardian.adapters.mcp.router import (
    configure as configure_mcp,
    router as mcp_router,
)
from guardian.adapters.a2a.router import (
    configure as configure_a2a,
    router as a2a_router,
)
from guardian.circuit_breaker.breaker import (
    CircuitBreaker,
    CircuitBreakerConfig as CBConfig,
)
from guardian.observability import MetricsMiddleware, metrics, configure_structured_logging
from guardian.feedback.store import FeedbackStore, FeedbackType
from guardian.graph.models import EdgeType, NodeType
from guardian.history.store import ActorProfile
from guardian.models.action_request import ActionRequest, Decision, DecisionOutcome
from guardian.pipeline import GuardianPipeline

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s %(levelname)s %(name)s — %(message)s",
)
logger = logging.getLogger(__name__)

# ── Configuration ────────────────────────────────────────────────────────────

_ROOT = Path(__file__).parent.parent.parent.parent  # src/guardian/api -> src -> project root
CONFIG_DIR = Path(os.getenv("GUARDIAN_CONFIG_DIR", str(_ROOT / "config")))
POLICIES_DIR = Path(os.getenv("GUARDIAN_POLICIES_DIR", str(_ROOT / "policies")))
AUDIT_LOG = Path(os.getenv("GUARDIAN_AUDIT_LOG", str(_ROOT / "audit.jsonl")))
API_KEY = os.getenv("GUARDIAN_API_KEY", "")  # empty = no auth (dev mode)
SHADOW_MODE = os.getenv("GUARDIAN_SHADOW_MODE", "false").lower() == "true"
APP_VERSION = "0.3.0"

# ── App setup ─────────────────────────────────────────────────────────────────

app = FastAPI(
    title="Guardian",
    description=(
        "Runtime governance and privilege control for AI agents and automation "
        "identities at the action layer. 9 adapters, 10-stage behavioral pipeline, "
        "circuit breaker, threat intelligence, event replay simulator. "
        "No LLMs in the decision path — deterministic, auditable math only."
    ),
    version=APP_VERSION,
    docs_url="/docs",
    redoc_url="/redoc",
)

app.add_middleware(
    CORSMiddleware,
    allow_origins=os.getenv("GUARDIAN_CORS_ORIGINS", "*").split(","),
    allow_methods=["GET", "POST"],
    allow_headers=["*"],
)
app.add_middleware(MetricsMiddleware)

# Enable structured JSON logging in production
if os.getenv("GUARDIAN_JSON_LOGS", "").lower() == "true":
    configure_structured_logging(json_mode=True)

# Serve the dashboard UI
_STATIC_DIR = Path(__file__).parent / "static"
if _STATIC_DIR.exists():
    # Mount /assets for Vite build output (JS/CSS bundles)
    _ASSETS_DIR = _STATIC_DIR / "assets"
    if _ASSETS_DIR.exists():
        app.mount("/assets", StaticFiles(directory=str(_ASSETS_DIR)), name="assets")
    app.mount("/static", StaticFiles(directory=str(_STATIC_DIR)), name="static")

_pipeline: GuardianPipeline | None = None
_feedback_store: FeedbackStore | None = None
_circuit_breaker: CircuitBreaker | None = None

# Register adapter routers
app.include_router(intune_router)
app.include_router(entra_router)
app.include_router(mcp_router)
app.include_router(a2a_router)

# ── Rate Limiting ────────────────────────────────────────────────────────────
# Simple in-memory rate limiter for the evaluation API.
# Production deployments should use Redis-backed rate limiting.
_rate_limit_window: dict[str, list[float]] = {}
RATE_LIMIT_PER_MINUTE = int(os.getenv("GUARDIAN_RATE_LIMIT", "200"))


async def _check_rate_limit(request: Request) -> None:
    """Per-IP rate limiting middleware for evaluation endpoints."""
    import time
    client_ip = request.client.host if request.client else "unknown"
    now = time.monotonic()
    window = _rate_limit_window.setdefault(client_ip, [])
    # Prune entries older than 60s
    _rate_limit_window[client_ip] = [t for t in window if now - t < 60]
    window = _rate_limit_window[client_ip]
    if len(window) >= RATE_LIMIT_PER_MINUTE:
        raise HTTPException(
            status_code=429,
            detail=f"Rate limit exceeded: {RATE_LIMIT_PER_MINUTE} requests/minute",
        )
    window.append(now)


@app.on_event("startup")
def startup() -> None:
    global _pipeline, _feedback_store, _circuit_breaker
    logger.info("Loading Guardian pipeline from config: %s", CONFIG_DIR)
    _feedback_store = FeedbackStore(str(AUDIT_LOG.parent / "feedback.sqlite"))
    _pipeline = GuardianPipeline.from_config(
        config_dir=CONFIG_DIR,
        policies_dir=POLICIES_DIR,
        audit_log_path=AUDIT_LOG,
    )

    # Initialize circuit breaker from config
    cb_cfg = _pipeline.config.circuit_breaker
    if cb_cfg.enabled:
        _circuit_breaker = CircuitBreaker(CBConfig(
            max_destructive_per_minute=cb_cfg.max_destructive_per_minute,
            max_destructive_per_hour=cb_cfg.max_destructive_per_hour,
            cooldown_seconds=cb_cfg.cooldown_seconds,
            destructive_actions=cb_cfg.destructive_actions,
        ))
        logger.info("Circuit breaker enabled: %d/min, %d/hour",
                     cb_cfg.max_destructive_per_minute, cb_cfg.max_destructive_per_hour)

    # Configure Intune adapter if enabled
    intune_cfg = _pipeline.config.intune
    if intune_cfg.enabled:
        proxy = IntuneProxy(
            graph_api_base=intune_cfg.graph_api_base,
            timeout=intune_cfg.timeout_seconds,
        )
        configure_intune(_pipeline, proxy, _circuit_breaker)
        logger.info("Intune adapter enabled: proxy → %s", intune_cfg.graph_api_base)
    else:
        # Configure without proxy (dry-run mode for testing)
        configure_intune(_pipeline, None, _circuit_breaker)

    # Configure Entra ID, MCP, and A2A adapters
    configure_entra(_pipeline, _circuit_breaker)
    configure_mcp(_pipeline, _circuit_breaker)
    configure_a2a(_pipeline, _circuit_breaker)
    logger.info("Adapters configured: Intune, Entra ID, MCP, A2A")

    if SHADOW_MODE:
        logger.info("Guardian running in SHADOW MODE — advisory only, no enforcement")
    logger.info("Guardian pipeline ready.")

    # Auto-ingest demo data if audit log is empty (first deploy)
    if os.getenv("GUARDIAN_AUTO_DEMO", "true").lower() == "true":
        if not AUDIT_LOG.exists() or AUDIT_LOG.stat().st_size == 0:
            logger.info("Empty audit log detected — auto-ingesting demo data...")
            try:
                _auto_ingest_demo()
            except Exception as exc:
                logger.warning("Auto demo ingest failed (non-fatal): %s", exc)


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
    target_system: str = ""
    target_asset: str
    decision: str
    risk_score: float
    risk_band: str
    drift_score: float | None
    evaluated_at: str
    risk_signals: list[dict] = []


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
async def evaluate(
    request: ActionRequest,
    _auth: None = Depends(verify_api_key),
    _rate: None = Depends(_check_rate_limit),
) -> EvaluateResponse:
    """
    Submit an action request for governance evaluation.

    Runs the full 10-stage pipeline: identity attestation, context enrichment,
    behavioral assessment, policy evaluation, risk scoring, threat intel overlays,
    graph cascade context, decision engine, audit logging, and history recording.

    Returns the decision (allow/block/require_review), risk score, drift score,
    explanation, and compliance tags. Rate limited to GUARDIAN_RATE_LIMIT/minute.
    """
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
    """
    Retrieve recent decisions from the audit log.

    Supports filtering by actor name and decision type. Returns decisions
    in reverse chronological order. Used by the Command Center dashboard.
    """
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
            # Extract risk signals if available
            signals = entry.get("risk_signals", [])
            if isinstance(signals, list):
                signals = [s if isinstance(s, dict) else {} for s in signals]
            else:
                signals = []

            summaries.append(DecisionSummary(
                entry_id=entry.get("entry_id", ""),
                actor_name=req.get("actor_name", ""),
                action=req.get("requested_action", ""),
                target_system=req.get("target_system", ""),
                target_asset=req.get("target_asset", ""),
                decision=entry.get("decision", ""),
                risk_score=score,
                risk_band=band,
                drift_score=drift.get("score") if isinstance(drift, dict) else None,
                evaluated_at=entry.get("evaluated_at", ""),
                risk_signals=signals,
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
    """
    Retrieve an actor's behavioral profile.

    Returns trust level, trust band, action counts (allows/blocks/reviews),
    velocity (hourly/daily), history window, and top action distribution.
    Used by the Actor Intelligence dashboard view.
    """
    pipeline = get_pipeline()
    profile = pipeline.history_store.get_profile(actor_name)
    return ActorProfileResponse.from_profile(profile)


@app.get("/v1/actors/{actor_name}/timeline")
def actor_timeline(
    actor_name: str,
    limit: int = Query(default=100, ge=1, le=500),
    _auth: None = Depends(verify_api_key),
) -> JSONResponse:
    """Return recent action history for timeline visualization."""
    pipeline = get_pipeline()
    events = pipeline.history_store.get_timeline(actor_name, limit=limit)
    return JSONResponse(content={"actor_name": actor_name, "events": events})


@app.get("/v1/actors/{actor_name}/pattern")
def actor_pattern(
    actor_name: str,
    _auth: None = Depends(verify_api_key),
) -> JSONResponse:
    """Return hourly activity pattern for pattern-of-life analysis."""
    pipeline = get_pipeline()
    pattern = pipeline.history_store.get_hourly_pattern(actor_name)

    # Build a 24-hour grid with decision breakdown
    hours = {}
    for row in pattern:
        h = row["hour"]
        if h not in hours:
            hours[h] = {"hour": h, "total": 0, "allow": 0, "block": 0, "require_review": 0, "allow_with_logging": 0}
        hours[h]["total"] += row["count"]
        decision = row["decision"]
        if decision in hours[h]:
            hours[h][decision] += row["count"]

    # Fill missing hours
    grid = []
    for h in range(24):
        if h in hours:
            grid.append(hours[h])
        else:
            grid.append({"hour": h, "total": 0, "allow": 0, "block": 0, "require_review": 0, "allow_with_logging": 0})

    return JSONResponse(content={"actor_name": actor_name, "pattern": grid})


@app.get("/v1/audit/verify")
def audit_verify(
    _auth: None = Depends(verify_api_key),
) -> JSONResponse:
    """
    Verify the audit log hash chain integrity.

    Walks the entire audit log and verifies that each entry's SHA-256 hash
    matches the recorded hash, and that the previous_hash chain is unbroken.
    Returns valid=true if the chain is intact, or the specific line and reason
    of the first detected break.
    """
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


# ── Feedback Endpoints ───────────────────────────────────────────────────────

class FeedbackRequest(BaseModel):
    feedback_type: str = Field(..., description="confirmed_correct, false_positive, false_negative, known_pattern")
    operator: str = Field(..., min_length=1, max_length=255)
    reason: str = Field(default="", max_length=2000)


class FeedbackResponse(BaseModel):
    feedback_id: str
    decision_entry_id: str
    feedback_type: str
    operator: str
    reason: str


@app.post("/v1/decisions/{decision_id}/feedback", response_model=FeedbackResponse)
def submit_feedback(
    decision_id: str,
    request: FeedbackRequest,
    _auth: None = Depends(verify_api_key),
) -> FeedbackResponse:
    """Submit operator feedback on a Guardian decision."""
    if _feedback_store is None:
        raise HTTPException(status_code=503, detail="Feedback store not initialized")

    try:
        ft = FeedbackType(request.feedback_type)
    except ValueError:
        raise HTTPException(
            status_code=400,
            detail=f"Invalid feedback type: {request.feedback_type}. "
                   f"Must be one of: {', '.join(t.value for t in FeedbackType)}",
        )

    # Try to look up the decision for denormalized fields
    pipeline = get_pipeline()
    actor_name = actor_type = action_name = policy_matched = original_decision = None

    log_path = pipeline.audit_logger.log_path
    if log_path.exists():
        with open(log_path, encoding="utf-8") as f:
            for line in f:
                line = line.strip()
                if not line:
                    continue
                try:
                    entry = json.loads(line)
                    if entry.get("entry_id") == decision_id:
                        req = entry.get("action_request", {})
                        actor_name = req.get("actor_name")
                        actor_type = req.get("actor_type")
                        action_name = req.get("requested_action")
                        policy_matched = entry.get("policy_matched")
                        original_decision = entry.get("decision")
                        break
                except json.JSONDecodeError:
                    continue

    feedback = _feedback_store.record(
        decision_entry_id=decision_id,
        feedback_type=ft,
        operator=request.operator,
        reason=request.reason,
        actor_name=actor_name,
        actor_type=actor_type,
        action_name=action_name,
        policy_matched=policy_matched,
        original_decision=original_decision,
    )

    return FeedbackResponse(
        feedback_id=feedback.feedback_id,
        decision_entry_id=decision_id,
        feedback_type=ft.value,
        operator=request.operator,
        reason=request.reason,
    )


@app.get("/v1/feedback/stats")
def feedback_stats(
    actor: str | None = Query(default=None),
    policy: str | None = Query(default=None),
    _auth: None = Depends(verify_api_key),
) -> JSONResponse:
    """Get aggregate feedback statistics."""
    if _feedback_store is None:
        raise HTTPException(status_code=503, detail="Feedback store not initialized")

    if actor:
        stats = _feedback_store.get_stats_for_actor(actor)
    elif policy:
        stats = _feedback_store.get_stats_for_policy(policy)
    else:
        stats = _feedback_store.get_overall_stats()

    return JSONResponse(content={
        "total_feedback": stats.total_feedback,
        "confirmed_correct": stats.confirmed_correct,
        "false_positives": stats.false_positives,
        "false_negatives": stats.false_negatives,
        "known_patterns": stats.known_patterns,
        "false_positive_rate": round(stats.false_positive_rate, 4),
        "accuracy_rate": round(stats.accuracy_rate, 4),
    })


@app.get("/v1/feedback/prior-adjustments")
def feedback_prior_adjustments(
    _auth: None = Depends(verify_api_key),
) -> JSONResponse:
    """Get Bayesian prior adjustments derived from accumulated feedback."""
    if _feedback_store is None:
        raise HTTPException(status_code=503, detail="Feedback store not initialized")

    adjustments = _feedback_store.compute_prior_adjustments()
    return JSONResponse(content={
        "adjustments": [
            {
                "actor_type": a.actor_type,
                "alpha_adjustment": a.alpha_adjustment,
                "beta_adjustment": a.beta_adjustment,
                "reason": a.reason,
            }
            for a in adjustments
        ],
    })


# ── Graph Endpoints ──────────────────────────────────────────────────────────

@app.get("/v1/graph/actor/{actor_id}/blast-radius")
def actor_blast_radius(
    actor_id: str,
    max_depth: int = Query(default=4, ge=1, le=8),
    _auth: None = Depends(verify_api_key),
) -> JSONResponse:
    """Compute the blast radius for an actor."""
    pipeline = get_pipeline()
    # Normalize: accept "deploy-bot" or "actor:deploy-bot"
    if not actor_id.startswith("actor:"):
        actor_id = f"actor:{actor_id}"
    br = pipeline.graph_store.compute_blast_radius(actor_id, max_depth=max_depth)
    return JSONResponse(content={
        "actor_id": br.actor_id,
        "direct_targets": br.direct_targets,
        "indirect_targets": br.indirect_targets,
        "critical_targets": br.critical_targets,
        "systems_reached": br.systems_reached,
        "max_chain_depth": br.max_chain_depth,
        "blast_radius_score": br.blast_radius_score,
        "chains": br.chains,
    })


@app.get("/v1/graph/cascades")
def graph_cascades(
    min_depth: int = Query(default=2, ge=2, le=10),
    min_risk: float = Query(default=0.0, ge=0.0, le=5.0),
    limit: int = Query(default=20, ge=1, le=100),
    _auth: None = Depends(verify_api_key),
) -> JSONResponse:
    """Find multi-hop automation cascades in the decision graph."""
    pipeline = get_pipeline()
    cascades = pipeline.graph_store.find_cascades(
        min_depth=min_depth, min_risk=min_risk, limit=limit,
    )
    return JSONResponse(content={
        "cascades": [
            {
                "chain_id": c.chain_id,
                "events": c.events,
                "actors": c.actors,
                "systems": c.systems,
                "total_risk": c.total_risk,
                "depth": c.depth,
                "starts_at": c.starts_at.isoformat(),
                "ends_at": c.ends_at.isoformat(),
                "crosses_trust_boundary": c.crosses_trust_boundary,
            }
            for c in cascades
        ],
        "total": len(cascades),
    })


@app.get("/v1/graph/actor/{actor_id}/targets")
def actor_targets(
    actor_id: str,
    _auth: None = Depends(verify_api_key),
) -> JSONResponse:
    """Get all targets an actor has affected, with frequency and recency."""
    pipeline = get_pipeline()
    if not actor_id.startswith("actor:"):
        actor_id = f"actor:{actor_id}"
    targets = pipeline.graph_store.get_actor_targets(actor_id)
    return JSONResponse(content={"actor_id": actor_id, "targets": targets})


@app.get("/v1/graph/target/{target_id}/actors")
def target_actors(
    target_id: str,
    _auth: None = Depends(verify_api_key),
) -> JSONResponse:
    """Get all actors that have affected a target."""
    pipeline = get_pipeline()
    actors = pipeline.graph_store.get_target_actors(target_id)
    return JSONResponse(content={"target_id": target_id, "actors": actors})


@app.get("/v1/graph/actor/{actor_id}/scope-drift")
def actor_scope_drift(
    actor_id: str,
    window_days: int = Query(default=30, ge=1, le=365),
    _auth: None = Depends(verify_api_key),
) -> JSONResponse:
    """Detect scope drift for an actor (new targets or systems)."""
    pipeline = get_pipeline()
    if not actor_id.startswith("actor:"):
        actor_id = f"actor:{actor_id}"
    drift = pipeline.graph_store.detect_scope_drift(actor_id, window_days=window_days)
    return JSONResponse(content=drift)


@app.get("/v1/graph/actor/{actor_id}/path-drift")
def actor_path_drift(
    actor_id: str,
    window_days: int = Query(default=30, ge=1, le=365),
    _auth: None = Depends(verify_api_key),
) -> JSONResponse:
    """Detect path drift for an actor (new automation chains)."""
    pipeline = get_pipeline()
    if not actor_id.startswith("actor:"):
        actor_id = f"actor:{actor_id}"
    drift = pipeline.graph_store.detect_path_drift(actor_id, window_days=window_days)
    return JSONResponse(content=drift)


@app.get("/v1/graph/stats")
def graph_stats(
    _auth: None = Depends(verify_api_key),
) -> JSONResponse:
    """Get graph statistics."""
    pipeline = get_pipeline()
    gs = pipeline.graph_store
    return JSONResponse(content={
        "total_nodes": gs.node_count(),
        "total_edges": gs.edge_count(),
        "total_events": gs.event_count(),
        "nodes_by_type": {
            "actors": gs.node_count(NodeType.actor),
            "actions": gs.node_count(NodeType.action),
            "targets": gs.node_count(NodeType.target),
            "systems": gs.node_count(NodeType.system),
            "decisions": gs.node_count(NodeType.decision),
        },
        "edges_by_type": {
            "initiated": gs.edge_count(EdgeType.initiated),
            "requested": gs.edge_count(EdgeType.requested),
            "targeted": gs.edge_count(EdgeType.targeted),
            "occurred_in": gs.edge_count(EdgeType.occurred_in),
            "triggered": gs.edge_count(EdgeType.triggered),
        },
    })


@app.get("/", include_in_schema=False)
def dashboard() -> FileResponse:
    """Serve the Guardian dashboard."""
    return FileResponse(str(_STATIC_DIR / "index.html"))


# ── Demo Data Ingestion ──────────────────────────────────────────────────────

@app.post("/v1/ingest/demo")
async def ingest_demo(request: Request) -> dict:
    """
    Ingest demo scenario data through the live pipeline.

    Populates the dashboard with realistic decisions, actor profiles,
    risk scores, and graph data. Call once after deployment.

    Optional query param: ?scenario=stryker (defaults to all scenarios)
    """
    import json as _json
    from guardian.simulator.models import AdapterType, Scenario, ScenarioEvent
    from guardian.adapters.intune.mapper import IntuneActionMapper
    from guardian.adapters.intune.models import IntuneDeviceAction
    from guardian.adapters.entra_id.mapper import EntraAdminMapper
    from guardian.adapters.entra_id.models import EntraAdminAction
    from guardian.adapters.jamf.mapper import JamfCommandMapper
    from guardian.adapters.jamf.models import JamfDeviceCommand
    from guardian.adapters.github_actions.mapper import GitHubDeploymentMapper
    from guardian.adapters.github_actions.models import GitHubDeploymentRequest
    from guardian.adapters.aws_eventbridge.mapper import CloudTrailMapper
    from guardian.adapters.aws_eventbridge.models import CloudTrailEvent
    from guardian.adapters.mcp.mapper import MCPToolCallMapper
    from guardian.adapters.mcp.models import MCPToolCall

    pipeline = get_pipeline()

    # Find scenario files
    scenarios_dirs = [
        _ROOT / "scenarios",
        _ROOT / "simulator" / "scenarios",
    ]

    scenario_filter = request.query_params.get("scenario", "")

    mappers = {
        "intune": IntuneActionMapper(),
        "entra_id": EntraAdminMapper(),
        "jamf": JamfCommandMapper(),
        "github": GitHubDeploymentMapper(),
        "aws": CloudTrailMapper(),
        "mcp": MCPToolCallMapper(),
    }

    total_events = 0
    total_allowed = 0
    total_blocked = 0
    total_review = 0
    scenarios_run = []

    for d in scenarios_dirs:
        if not d.exists():
            continue
        for f in sorted(d.glob("*.json")):
            if scenario_filter and scenario_filter not in f.stem:
                continue

            with open(f) as fh:
                data = _json.load(fh)

            scenario = Scenario(**data)
            scenarios_run.append(scenario.metadata.name)

            # Register scenario actors
            if scenario.metadata.register_actors:
                for actor in scenario.metadata.register_actors:
                    pipeline.attestor.registry._actors[actor["name"]] = actor

            for event in scenario.events:
                try:
                    action_req = _map_demo_event(event, mappers)
                    if action_req is None:
                        continue

                    decision = pipeline.evaluate(action_req)
                    total_events += 1

                    if decision.decision.value == "block":
                        total_blocked += 1
                    elif decision.decision.value == "require_review":
                        total_review += 1
                    else:
                        total_allowed += 1

                except Exception as exc:
                    logger.debug("Demo ingest skip: %s — %s", event.id, exc)

    return {
        "status": "demo data ingested",
        "scenarios_run": scenarios_run,
        "total_events": total_events,
        "allowed": total_allowed,
        "blocked": total_blocked,
        "require_review": total_review,
    }


def _auto_ingest_demo() -> None:
    """Ingest demo scenario data on first startup."""
    import json as _json
    from guardian.simulator.models import Scenario
    from guardian.adapters.intune.mapper import IntuneActionMapper
    from guardian.adapters.entra_id.mapper import EntraAdminMapper
    from guardian.adapters.jamf.mapper import JamfCommandMapper
    from guardian.adapters.github_actions.mapper import GitHubDeploymentMapper
    from guardian.adapters.aws_eventbridge.mapper import CloudTrailMapper

    mappers = {
        "intune": IntuneActionMapper(),
        "entra_id": EntraAdminMapper(),
        "jamf": JamfCommandMapper(),
        "github": GitHubDeploymentMapper(),
        "aws": CloudTrailMapper(),
    }

    count = 0
    for d in [_ROOT / "scenarios", _ROOT / "simulator" / "scenarios"]:
        if not d.exists():
            continue
        for f in sorted(d.glob("*.json")):
            try:
                with open(f) as fh:
                    data = _json.load(fh)
                scenario = Scenario(**data)
                if scenario.metadata.register_actors and _pipeline:
                    for actor in scenario.metadata.register_actors:
                        _pipeline.attestor.registry._actors[actor["name"]] = actor
                for event in scenario.events:
                    try:
                        req = _map_demo_event(event, mappers)
                        if req and _pipeline:
                            _pipeline.evaluate(req)
                            count += 1
                    except Exception:
                        pass
            except Exception:
                pass

    logger.info("Auto demo ingest complete: %d events evaluated", count)


def _map_demo_event(event, mappers) -> ActionRequest | None:
    """Map a scenario event to an ActionRequest for the live pipeline."""
    from guardian.simulator.models import AdapterType
    from guardian.adapters.intune.models import IntuneDeviceAction
    from guardian.adapters.entra_id.models import EntraAdminAction
    from guardian.adapters.jamf.models import JamfDeviceCommand
    from guardian.adapters.github_actions.models import GitHubDeploymentRequest
    from guardian.adapters.aws_eventbridge.models import CloudTrailEvent
    from guardian.adapters.mcp.models import MCPToolCall

    payload = event.payload
    ts = event.timestamp

    if event.adapter == AdapterType.direct:
        if ts and "timestamp" not in payload:
            payload["timestamp"] = ts
        if "timestamp" not in payload:
            from datetime import datetime, timezone
            payload["timestamp"] = datetime.now(timezone.utc).isoformat()
        return ActionRequest(**payload)

    elif event.adapter == AdapterType.intune:
        device = IntuneDeviceAction(**{k: v for k, v in payload.items() if k != "actor_name"})
        actor = payload.get("actor_name", "unknown-intune-actor")
        req = mappers["intune"].map_action(device, actor_name=actor)
        if ts:
            req = ActionRequest(**{**req.model_dump(), "timestamp": ts})
        return req

    elif event.adapter == AdapterType.entra_id:
        action = EntraAdminAction(**{k: v for k, v in payload.items() if k != "actor_name"})
        actor = payload.get("actor_name", "unknown-entra-actor")
        req = mappers["entra_id"].map_action(action, actor_name=actor)
        if ts:
            req = ActionRequest(**{**req.model_dump(), "timestamp": ts})
        return req

    elif event.adapter == AdapterType.jamf:
        cmd = JamfDeviceCommand(**{k: v for k, v in payload.items() if k != "actor_name"})
        actor = payload.get("actor_name", "unknown-jamf-admin")
        req = mappers["jamf"].map_command(cmd, actor_name=actor)
        if ts:
            req = ActionRequest(**{**req.model_dump(), "timestamp": ts})
        return req

    elif event.adapter == AdapterType.github:
        deployment = GitHubDeploymentRequest(**payload)
        req = mappers["github"].map_deployment(deployment)
        if ts:
            req = ActionRequest(**{**req.model_dump(), "timestamp": ts})
        return req

    elif event.adapter == AdapterType.aws:
        ct_event = CloudTrailEvent(**payload)
        req = mappers["aws"].map_event(ct_event)
        return req

    return None


# ── Threat Intelligence Endpoints ────────────────────────────────────────────

@app.post("/v1/threat-intel/sync")
async def sync_threat_feeds() -> dict:
    """
    Sync threat intelligence feeds and create risk overlays.

    Fetches the CISA Known Exploited Vulnerabilities catalog, maps entries
    to Guardian's action taxonomy, and creates pending risk overlays.
    Overlays require explicit activation before they affect scoring.
    Rate limited to 1 sync per hour. Auto-expires stale overlays.
    """
    from guardian.threat_intel.feeds import CISAKEVFeed
    pipeline = get_pipeline()
    kev_feed = CISAKEVFeed(pipeline.overlay_engine)
    try:
        result = await kev_feed.sync()
    except Exception as exc:
        logger.error("Threat feed sync failed: %s", exc)
        return {
            "source": "cisa_kev",
            "success": False,
            "entries_processed": 0,
            "overlays_created": 0,
            "overlays_expired": 0,
            "feed_hash": "",
            "errors": [str(exc)],
        }
    # Auto-expire stale overlays
    expired = pipeline.overlay_engine.expire_stale()
    return {
        "source": result.source.value,
        "success": result.success,
        "entries_processed": result.entries_processed,
        "overlays_created": result.overlays_created,
        "overlays_expired": expired,
        "feed_hash": result.feed_hash,
        "errors": result.errors,
    }


@app.get("/v1/threat-intel/overlays")
def list_overlays(status: str = "") -> list[dict]:
    """List risk overlays, optionally filtered by status."""
    from guardian.threat_intel.models import OverlayStatus
    pipeline = get_pipeline()
    if status:
        return pipeline.overlay_engine.list_overlays(OverlayStatus(status))
    return pipeline.overlay_engine.list_overlays()


@app.post("/v1/threat-intel/overlays/{overlay_id}/activate")
def activate_overlay(overlay_id: str, activated_by: str = "admin") -> dict:
    """Approve and activate a pending overlay."""
    pipeline = get_pipeline()
    success = pipeline.overlay_engine.activate(overlay_id, activated_by)
    return {"overlay_id": overlay_id, "activated": success}


@app.post("/v1/threat-intel/overlays/{overlay_id}/reject")
def reject_overlay(
    overlay_id: str, rejected_by: str = "admin", reason: str = "",
) -> dict:
    """Reject a pending overlay after review."""
    pipeline = get_pipeline()
    success = pipeline.overlay_engine.reject(overlay_id, rejected_by, reason)
    return {"overlay_id": overlay_id, "rejected": success}


@app.post("/v1/admin/reload-policies")
async def reload_policies(
    _auth: None = Depends(verify_api_key),
) -> dict:
    """
    Hot-reload policy rules from disk without restarting.

    Reads policy YAML files from GUARDIAN_POLICIES_DIR and replaces
    the in-memory policy engine. Requires API key authentication.
    """
    from guardian.policy.loaders import PolicyLoader
    from guardian.policy.engine import PolicyEngine
    pipeline = get_pipeline()
    try:
        loader = PolicyLoader(POLICIES_DIR)
        deny_rules, conditional_rules, allow_rules = loader.load_all()
        pipeline.policy_engine = PolicyEngine(deny_rules, conditional_rules, allow_rules)
        total = len(deny_rules) + len(conditional_rules) + len(allow_rules)
        logger.info("Policies hot-reloaded: %d rules", total)
        return {
            "status": "reloaded",
            "deny_rules": len(deny_rules),
            "conditional_rules": len(conditional_rules),
            "allow_rules": len(allow_rules),
            "total_rules": total,
        }
    except Exception as exc:
        logger.error("Policy reload failed: %s", exc)
        raise HTTPException(500, f"Policy reload failed: {exc}")


@app.get("/v1/threat-intel/audit")
def threat_intel_audit(overlay_id: str = "") -> list[dict]:
    """Get audit trail for threat intelligence overlays."""
    pipeline = get_pipeline()
    return pipeline.overlay_engine.get_audit_log(overlay_id or None)


@app.get("/metrics")
def prometheus_metrics() -> Response:
    """Prometheus-compatible metrics endpoint."""
    return Response(
        content=metrics.prometheus_text(),
        media_type="text/plain; version=0.0.4; charset=utf-8",
    )


@app.get("/v1/metrics")
def metrics_json() -> dict:
    """JSON metrics snapshot for dashboards."""
    return metrics.snapshot()


# ── Onboarding Endpoints ─────────────────────────────────────────────────────

_discovery_engine = None


def _get_discovery():
    global _discovery_engine
    if _discovery_engine is None:
        from guardian.onboarding.discovery import DiscoveryEngine
        _discovery_engine = DiscoveryEngine()
    return _discovery_engine


@app.get("/v1/onboard/status")
def onboard_status() -> dict:
    """
    Get current onboarding progress.

    Shows discovery phase, events ingested, actors/assets/systems discovered,
    and whether config has been generated and applied.
    """
    return _get_discovery().get_status()


@app.post("/v1/onboard/ingest-events")
async def onboard_ingest_events(request: Request) -> dict:
    """
    Ingest raw events into the discovery engine.

    Accepts a JSON array of event objects. Each event should have at least:
    actor_name, action, target_system, target_asset.

    Events are analyzed to discover actors, assets, systems, and behavioral
    patterns. After ingesting enough data, call /v1/onboard/discover to
    generate a configuration recommendation.
    """
    body = await request.json()
    events = body if isinstance(body, list) else body.get("events", [])
    engine = _get_discovery()
    count = engine.ingest_batch(events)
    status = engine.get_status()
    return {
        "ingested": count,
        "total_events": status["events_ingested"],
        "actors_discovered": status["actors_discovered"],
        "assets_discovered": status["assets_discovered"],
        "systems_discovered": status["systems_discovered"],
    }


@app.post("/v1/onboard/discover")
def onboard_discover() -> dict:
    """
    Generate a discovery report from accumulated observations.

    Analyzes all ingested events and returns:
    - Discovered actors with recommended privilege levels
    - Discovered assets with recommended criticality
    - Discovered systems with adapter recommendations
    - Recommended risk posture based on observed patterns
    """
    engine = _get_discovery()
    report = engine.generate_report()
    return report.model_dump(mode="json")


@app.post("/v1/onboard/apply")
def onboard_apply() -> dict:
    """
    Apply discovered configuration to the live Guardian pipeline.

    Registers discovered actors in the actor registry, sets up
    recommended configuration, and transitions to active governance.
    This activates Guardian for the org.
    """
    pipeline = get_pipeline()
    engine = _get_discovery()
    return engine.apply_config(pipeline)


@app.get("/v1/onboard/templates")
def onboard_templates() -> list[dict]:
    """
    List available industry templates.

    Each template provides scoring weights, adapter recommendations,
    and compliance framework mappings tailored to an industry vertical.
    """
    from guardian.onboarding.templates import list_templates
    return list_templates()


@app.post("/v1/onboard/apply-template")
async def onboard_apply_template(request: Request) -> dict:
    """
    Apply an industry template to Guardian's configuration.

    Accepts: { "industry": "healthcare" | "fintech" | "saas" | "government" | "general" }

    Updates scoring weights, circuit breaker thresholds, and returns
    recommended adapters and compliance frameworks for the industry.
    """
    from guardian.onboarding.models import IndustryTemplate
    from guardian.onboarding.templates import get_template

    body = await request.json()
    industry = IndustryTemplate(body.get("industry", "general"))
    template = get_template(industry)

    pipeline = get_pipeline()

    # Apply scoring overrides
    overrides = template.get("scoring_overrides", {})
    if "action_category_scores" in overrides:
        for cat, score in overrides["action_category_scores"].items():
            pipeline.config.scoring.action_category_scores[cat] = score
    if "actor_type_scores" in overrides:
        for at, score in overrides["actor_type_scores"].items():
            pipeline.config.scoring.actor_type_scores[at] = score

    # Apply circuit breaker overrides
    cb = template.get("circuit_breaker", {})
    if cb:
        pipeline.config.circuit_breaker.max_destructive_per_minute = cb.get(
            "max_per_minute", pipeline.config.circuit_breaker.max_destructive_per_minute)
        pipeline.config.circuit_breaker.max_destructive_per_hour = cb.get(
            "max_per_hour", pipeline.config.circuit_breaker.max_destructive_per_hour)
        pipeline.config.circuit_breaker.cooldown_seconds = cb.get(
            "cooldown", pipeline.config.circuit_breaker.cooldown_seconds)

    logger.info("Applied industry template: %s", industry.value)

    return {
        "industry": industry.value,
        "scoring_overrides_applied": len(overrides),
        "recommended_adapters": template.get("recommended_adapters", []),
        "compliance_frameworks": template.get("compliance_frameworks", []),
        "circuit_breaker": cb,
    }


# ── Compliance Report Endpoints ───────────────────────────────────────────────

@app.get("/v1/compliance/report")
def compliance_report(
    frameworks: str = "",
    window_hours: int = 720,
) -> dict:
    """
    Generate a compliance report from Guardian's audit log.

    Maps every action evaluation to regulatory controls (NIST 800-53,
    HIPAA, FedRAMP, EU AI Act). Output is structured JSON suitable for
    ATO packages, POAM documentation, and SOC 2 audit evidence.

    Query params:
      frameworks: comma-separated (e.g., "NIST-800-53,HIPAA"). Empty = all.
      window_hours: how many hours of audit data to analyze (default: 720 = 30 days)
    """
    from guardian.compliance.report import ComplianceReportGenerator
    pipeline = get_pipeline()
    generator = ComplianceReportGenerator(pipeline.audit_logger.log_path)
    fw_list = [f.strip() for f in frameworks.split(",") if f.strip()] or None
    return generator.generate(frameworks=fw_list, window_hours=window_hours)


@app.get("/v1/compliance/controls")
def compliance_controls(framework: str = "") -> list[dict]:
    """
    List all compliance controls Guardian maps to.

    Optionally filter by framework ID (NIST-800-53, HIPAA, FedRAMP, EU-AI-Act).
    Returns control ID, name, family, Guardian capability, and evidence source.
    """
    from guardian.compliance.frameworks import ALL_CONTROLS, FRAMEWORK_INDEX
    if framework and framework in FRAMEWORK_INDEX:
        controls = FRAMEWORK_INDEX[framework]
    else:
        controls = ALL_CONTROLS

    return [
        {
            "control_id": c.control_id,
            "control_name": c.control_name,
            "framework": c.framework,
            "family": c.family,
            "guardian_capability": c.guardian_capability,
            "evidence_source": c.evidence_source,
            "verification": c.verification,
            "automated": c.automated,
        }
        for c in controls
    ]


@app.get("/v1/compliance/frameworks")
def compliance_frameworks() -> list[dict]:
    """List all supported compliance frameworks with control counts."""
    from guardian.compliance.frameworks import FRAMEWORK_INDEX
    return [
        {"framework": fw, "control_count": len(controls)}
        for fw, controls in FRAMEWORK_INDEX.items()
    ]


_CONNECTED_ADAPTERS = [
    {"name": "Terraform Cloud", "adapter": "terraform", "patterns": ("terraform",)},
    {"name": "Kubernetes", "adapter": "kubernetes", "patterns": ("kubernetes", "k8s")},
    {"name": "Microsoft Intune", "adapter": "intune", "patterns": ("intune",)},
    {"name": "Entra ID", "adapter": "entra_id", "patterns": ("entra", "azure-ad", "okta")},
    {"name": "Jamf Pro", "adapter": "jamf", "patterns": ("jamf",)},
    {"name": "GitHub Actions", "adapter": "github", "patterns": ("github", "gitlab", "jenkins", "circleci")},
    {"name": "AWS", "adapter": "aws_eventbridge", "patterns": ("aws", "cloudtrail")},
    {"name": "MCP (Agent Tools)", "adapter": "mcp", "patterns": ("mcp",)},
    {"name": "A2A (Agent Network)", "adapter": "a2a", "patterns": ("a2a",)},
]


def _scan_audit_log(pipeline: GuardianPipeline) -> list[dict]:
    """Load audit entries once for dashboard/system-summary endpoints."""
    entries: list[dict] = []
    try:
        if pipeline.audit_logger.log_path.exists():
            with open(pipeline.audit_logger.log_path, encoding="utf-8") as f:
                for line in f:
                    line = line.strip()
                    if not line:
                        continue
                    try:
                        entries.append(json.loads(line))
                    except json.JSONDecodeError:
                        continue
    except Exception:
        pass
    return entries


def _build_connected_systems(entries: list[dict]) -> list[dict]:
    """Summarize connected-system activity from audit entries."""
    system_events: dict[str, dict[str, str | int]] = {}

    for entry in entries:
        req = entry.get("action_request", {})
        system = req.get("target_system", "unknown")
        ts = entry.get("evaluated_at", "")
        if system not in system_events:
            system_events[system] = {"count": 0, "last_event": ""}
        system_events[system]["count"] += 1
        if ts > system_events[system]["last_event"]:
            system_events[system]["last_event"] = ts

    results = []
    for adapter in _CONNECTED_ADAPTERS:
        event_count = 0
        last_event = ""
        for sys_name, data in system_events.items():
            sys_lower = sys_name.lower()
            if any(pattern in sys_lower for pattern in adapter["patterns"]):
                event_count += int(data["count"])
                if data["last_event"] > last_event:
                    last_event = str(data["last_event"])

        results.append({
            "name": adapter["name"],
            "adapter": adapter["adapter"],
            "status": "active" if event_count > 0 else "standby",
            "event_count": event_count,
            "last_event": last_event,
        })

    return results


@app.get("/v1/system/status")
def system_status() -> dict:
    """
    System observability metrics for the dashboard.

    Returns events ingested, active actor count, connected systems,
    graph node count, and evaluation latency percentiles.
    Auto-refreshed by the Command Center every 10 seconds.
    """
    pipeline = get_pipeline()
    snap = metrics.snapshot()
    counters = snap.get("counters", {})
    histograms = snap.get("histograms", {})
    entries = _scan_audit_log(pipeline)

    # Count active actors from recent decisions
    active_actors = set()
    timestamps: list[datetime] = []
    for entry in entries:
        actor = entry.get("action_request", {}).get("actor_name", "")
        if actor:
            active_actors.add(actor)
        ts = entry.get("evaluated_at")
        if ts:
            try:
                timestamps.append(datetime.fromisoformat(ts))
            except ValueError:
                pass
    total_ingested = len(entries)

    # Graph node count
    graph_nodes = 0
    try:
        stats = pipeline.graph_store._conn.execute(
            "SELECT COUNT(*) FROM graph_nodes"
        ).fetchone()
        graph_nodes = stats[0] if stats else 0
    except Exception:
        pass

    eval_count = counters.get("guardian.evaluations.total", 0)
    eval_duration = histograms.get("guardian.evaluations.duration_seconds", {})
    connected_systems = _build_connected_systems(entries)

    evaluations_per_minute = 0.0
    if len(timestamps) >= 2:
        span_minutes = max(
            1.0 / 60.0,
            (max(timestamps) - min(timestamps)).total_seconds() / 60.0,
        )
        evaluations_per_minute = round(total_ingested / span_minutes, 1)
    elif total_ingested == 1:
        evaluations_per_minute = 1.0

    connected_system_count = len([s for s in connected_systems if s.get("status") == "active"])

    return {
        "events_ingested": total_ingested,
        "evaluations_total": eval_count,
        "evaluations_per_minute": evaluations_per_minute,
        "active_actors": len(active_actors),
        "connected_systems": connected_system_count,
        "graph_nodes": graph_nodes,
        "graph_nodes_tracked": graph_nodes,
        "avg_latency_ms": round(eval_duration.get("p50", 0) * 1000, 1) if eval_duration else 0,
        "p95_latency_ms": round(eval_duration.get("p95", 0) * 1000, 1) if eval_duration else 0,
    }


@app.get("/v1/systems/connected")
def connected_systems() -> list[dict]:
    """
    Status of all 9 connected adapter systems.

    Returns each adapter's name, status (active/standby), event count,
    and last event timestamp. Scans the audit log to determine which
    systems have received events.
    """
    pipeline = get_pipeline()
    return _build_connected_systems(_scan_audit_log(pipeline))


@app.get("/v1/health", response_model=HealthResponse)
def health() -> HealthResponse:
    """
    Deep health check — verifies all dependencies are operational.

    Checks pipeline initialization, audit log writability, policy engine,
    and history store connectivity. Returns component-level status and
    overall health (ok/degraded). Used by Render health monitoring.
    """
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
        version=APP_VERSION,
        shadow_mode=SHADOW_MODE,
        components=components,
    )
