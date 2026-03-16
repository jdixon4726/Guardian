"""
Behavioral Intelligence Engine

Guardian's core differentiator. Consolidates drift detection, trust level
computation, velocity tracking, Bayesian confidence scoring, peer group
analysis, and multi-dimensional anomaly detection into a single
BehavioralAssessment.

This assessment is computed BEFORE policy evaluation and passed to the policy
provider as additional context — so even OPA/Rego rules can leverage
Guardian's behavioral intelligence.
"""

from __future__ import annotations

import logging
from dataclasses import dataclass, field
from datetime import datetime, timezone

from guardian.behavioral.anomaly import AnomalyAssessment, MultiDimensionalAnomalyScorer
from guardian.behavioral.confidence import BayesianConfidenceScorer, ConfidenceEstimate
from guardian.behavioral.peer_groups import PeerGroupAssessment, PeerGroupEngine
from guardian.config.model import GuardianConfig
from guardian.drift.baseline import BaselineStore
from guardian.drift.engine import DriftDetectionEngine
from guardian.enrichment.context import EnrichedContext
from guardian.history.store import ActorHistoryStore
from guardian.models.action_request import DriftScore, RiskSignal
from guardian.scoring.engine import action_scorer, actor_scorer

logger = logging.getLogger(__name__)


@dataclass
class BehavioralAssessment:
    """
    The consolidated output of Guardian's behavioral intelligence.

    This is the core value proposition — the answer to "is this normal?"
    that no policy engine (OPA, Sentinel, SCPs) can provide.
    """
    trust_level: float              # [0.0, 1.0] — computed from action history
    drift_score: DriftScore         # composite drift with z-score and JS divergence
    velocity_hourly: int            # actions in the last hour
    velocity_daily: int             # actions in the last 24 hours
    behavioral_risk: float          # [0.0, 1.0] — composite behavioral risk
    signals: list[RiskSignal] = field(default_factory=list)
    is_anomalous: bool = False      # True if model breach threshold crossed
    confidence: ConfidenceEstimate | None = None
    peer_assessment: PeerGroupAssessment | None = None
    anomaly_assessment: AnomalyAssessment | None = None

    def to_policy_context(self) -> dict:
        """
        Flatten to a dict for injection into policy evaluation context.

        This allows OPA/Rego rules to write conditions like:
          deny if input.behavioral_risk > 0.8
          deny if input.is_anomalous
          deny if input.trust_level < 0.3
          deny if input.confidence_width > 0.4
        """
        ctx = {
            "trust_level": self.trust_level,
            "drift_score": self.drift_score.score,
            "drift_alert": self.drift_score.alert_triggered,
            "velocity_hourly": self.velocity_hourly,
            "velocity_daily": self.velocity_daily,
            "behavioral_risk": self.behavioral_risk,
            "is_anomalous": self.is_anomalous,
        }
        if self.confidence:
            ctx["confidence"] = self.confidence.confidence
            ctx["confidence_width"] = self.confidence.width
        if self.peer_assessment:
            ctx["peer_z_score"] = self.peer_assessment.z_score_vs_peers
            ctx["is_peer_anomaly"] = self.peer_assessment.is_peer_anomaly
        if self.anomaly_assessment:
            ctx["anomalous_dimensions"] = self.anomaly_assessment.anomalous_dimensions
            ctx["is_model_breach"] = self.anomaly_assessment.is_model_breach
        return ctx


class BehavioralIntelligenceEngine:
    """
    Computes a BehavioralAssessment for each action request.

    Orchestrates all behavioral intelligence components:
      - Drift detection (z-score, JS divergence, regularity)
      - Trust level (from actor history store)
      - Velocity tracking (actions per hour/day)
      - Bayesian confidence scoring (wide-then-narrow intervals)
      - Peer group analysis (cold-start inheritance, peer anomaly)
      - Multi-dimensional anomaly scoring (composite model breaches)
    """

    def __init__(
        self,
        drift_engine: DriftDetectionEngine,
        history_store: ActorHistoryStore,
        baseline_store: BaselineStore | None = None,
        config: GuardianConfig | None = None,
    ):
        self.drift_engine = drift_engine
        self.history_store = history_store
        self.cfg = config or GuardianConfig()
        self.confidence_scorer = BayesianConfidenceScorer()
        self.anomaly_scorer = MultiDimensionalAnomalyScorer(breach_threshold=2)
        self.peer_engine = PeerGroupEngine(baseline_store) if baseline_store else None

    def assess(
        self, context: EnrichedContext,
    ) -> BehavioralAssessment:
        """
        Produce a full behavioral assessment for the current request.

        This is called BEFORE policy evaluation so the assessment
        can be passed to the policy provider as additional context.
        """
        request = context.request
        signals: list[RiskSignal] = []

        # ── Preliminary risk (action + actor scorers only) ──
        action_result = action_scorer(context, self.cfg.scoring)
        actor_result = actor_scorer(context, self.cfg.scoring)
        prelim_risk = (
            action_result.score * 0.55
            + actor_result.score * 0.45
        )

        # ── Drift detection ──
        drift = self.drift_engine.evaluate(
            actor_name=request.actor_name,
            action_type=request.requested_action,
            current_risk=prelim_risk,
            timestamp=request.timestamp,
        )

        if drift.alert_triggered:
            signals.append(RiskSignal(
                source="behavioral",
                description=drift.explanation or "Drift alert triggered",
                contribution=drift.score * 0.5,
            ))

        # ── Trust and velocity from enriched context ──
        trust = context.actor_history.trust_level
        hourly = context.actor_history.actions_last_hour
        daily = context.actor_history.actions_last_day

        if trust < 0.3:
            signals.append(RiskSignal(
                source="behavioral",
                description=f"Low trust actor ({trust:.2f})",
                contribution=0.15,
            ))

        if hourly > self.cfg.scoring.velocity_hourly_extreme:
            signals.append(RiskSignal(
                source="behavioral",
                description=f"Extreme velocity: {hourly} actions/hour",
                contribution=0.25,
            ))
        elif hourly > self.cfg.scoring.velocity_hourly_high:
            signals.append(RiskSignal(
                source="behavioral",
                description=f"High velocity: {hourly} actions/hour",
                contribution=0.15,
            ))

        # ── Bayesian confidence scoring ──
        history = context.actor_history
        risky_count = history.total_blocks + history.total_reviews
        normal_count = history.total_allows
        confidence = self.confidence_scorer.estimate(
            actor_type=request.actor_type.value,
            risky_count=risky_count,
            normal_count=normal_count,
        )

        if confidence.is_uncertain:
            signals.append(RiskSignal(
                source="behavioral",
                description=(
                    f"Low confidence estimate (width={confidence.width:.2f}, "
                    f"{confidence.observations} observations) — "
                    "treating conservatively"
                ),
                contribution=0.05,
            ))

        # ── Peer group analysis ──
        peer_assessment = None
        peer_z = None
        if self.peer_engine:
            peer_assessment = self.peer_engine.assess(
                request.actor_name, prelim_risk,
            )
            if peer_assessment:
                peer_z = peer_assessment.z_score_vs_peers
                if peer_assessment.is_peer_anomaly:
                    signals.append(RiskSignal(
                        source="behavioral",
                        description=(
                            f"Anomalous vs peer group '{peer_assessment.group_id}' "
                            f"({peer_assessment.z_score_vs_peers:+.2f}σ)"
                        ),
                        contribution=0.10,
                    ))

        # ── Multi-dimensional anomaly scoring ──
        anomaly = self.anomaly_scorer.score(
            level_drift_z=drift.level_drift_z,
            pattern_drift_js=drift.pattern_drift_js,
            velocity_hourly=hourly,
            velocity_daily=daily,
            trust_level=trust,
            risk_score=prelim_risk,
            peer_z_score=peer_z,
            confidence=confidence.confidence,
        )

        if anomaly.is_model_breach:
            signals.append(RiskSignal(
                source="behavioral",
                description=anomaly.explanation,
                contribution=anomaly.composite_score * 0.3,
            ))

        # ── Composite behavioral risk ──
        trust_risk = max(0.0, 0.5 - trust) * 0.3
        drift_risk = drift.score * 0.3
        velocity_risk = min(0.15, (hourly / 100.0) * 0.15)
        anomaly_risk = anomaly.composite_score * 0.15
        confidence_penalty = (1.0 - confidence.confidence) * 0.10
        behavioral_risk = round(
            min(1.0, trust_risk + drift_risk + velocity_risk + anomaly_risk + confidence_penalty),
            3,
        )

        # ── Anomaly determination (model breach = the primary trigger) ──
        is_anomalous = anomaly.is_model_breach

        assessment = BehavioralAssessment(
            trust_level=trust,
            drift_score=drift,
            velocity_hourly=hourly,
            velocity_daily=daily,
            behavioral_risk=behavioral_risk,
            signals=signals,
            is_anomalous=is_anomalous,
            confidence=confidence,
            peer_assessment=peer_assessment,
            anomaly_assessment=anomaly,
        )

        logger.info(
            "Behavioral: actor=%s trust=%.2f drift=%.3f velocity=%d/hr "
            "confidence=%.2f anomaly_dims=%d/%d breach=%s behavioral_risk=%.3f",
            request.actor_name, trust, drift.score, hourly,
            confidence.confidence, anomaly.anomalous_dimensions,
            len(anomaly.dimensions), anomaly.is_model_breach,
            behavioral_risk,
        )

        return assessment
