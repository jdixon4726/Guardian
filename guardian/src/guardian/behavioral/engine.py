"""
Behavioral Intelligence Engine

Guardian's core differentiator. Consolidates drift detection, trust level
computation, and velocity tracking into a single BehavioralAssessment that
answers the question: "Is this request normal for this actor, right now?"

This assessment is computed BEFORE policy evaluation and passed to the policy
provider as additional context — so even OPA/Rego rules can leverage
Guardian's behavioral intelligence.
"""

from __future__ import annotations

import logging
from dataclasses import dataclass, field
from datetime import datetime, timezone

from guardian.config.model import GuardianConfig
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
    is_anomalous: bool = False      # True if any behavioral signal crosses alert threshold

    def to_policy_context(self) -> dict:
        """
        Flatten to a dict for injection into policy evaluation context.

        This allows OPA/Rego rules to write conditions like:
          deny if input.behavioral_risk > 0.8
          deny if input.is_anomalous
          deny if input.trust_level < 0.3
        """
        return {
            "trust_level": self.trust_level,
            "drift_score": self.drift_score.score,
            "drift_alert": self.drift_score.alert_triggered,
            "velocity_hourly": self.velocity_hourly,
            "velocity_daily": self.velocity_daily,
            "behavioral_risk": self.behavioral_risk,
            "is_anomalous": self.is_anomalous,
        }


class BehavioralIntelligenceEngine:
    """
    Computes a BehavioralAssessment for each action request.

    Orchestrates:
      - Drift detection (z-score, JS divergence, regularity)
      - Trust level (from actor history store)
      - Velocity tracking (actions per hour/day)
      - Preliminary risk scoring (action + actor scorers only)
    """

    def __init__(
        self,
        drift_engine: DriftDetectionEngine,
        history_store: ActorHistoryStore,
        config: GuardianConfig | None = None,
    ):
        self.drift_engine = drift_engine
        self.history_store = history_store
        self.cfg = config or GuardianConfig()

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

        # Preliminary risk from action + actor scorers (before context/drift)
        action_result = action_scorer(context, self.cfg.scoring)
        actor_result = actor_scorer(context, self.cfg.scoring)
        prelim_risk = (
            action_result.score * 0.55
            + actor_result.score * 0.45
        )

        # Drift detection
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

        # Trust and velocity from enriched context (already populated by history store)
        trust = context.actor_history.trust_level
        hourly = context.actor_history.actions_last_hour
        daily = context.actor_history.actions_last_day

        # Trust signals
        if trust < 0.3:
            signals.append(RiskSignal(
                source="behavioral",
                description=f"Low trust actor ({trust:.2f})",
                contribution=0.15,
            ))

        # Velocity signals
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

        # Composite behavioral risk
        trust_risk = max(0.0, 0.5 - trust) * 0.4  # low trust → higher risk
        drift_risk = drift.score * 0.4
        velocity_risk = min(0.2, (hourly / 100.0) * 0.2)
        behavioral_risk = round(min(1.0, trust_risk + drift_risk + velocity_risk), 3)

        # Anomaly determination
        is_anomalous = (
            drift.alert_triggered
            or trust < 0.3
            or hourly > self.cfg.scoring.velocity_hourly_extreme
        )

        assessment = BehavioralAssessment(
            trust_level=trust,
            drift_score=drift,
            velocity_hourly=hourly,
            velocity_daily=daily,
            behavioral_risk=behavioral_risk,
            signals=signals,
            is_anomalous=is_anomalous,
        )

        logger.info(
            "Behavioral assessment: actor=%s trust=%.2f drift=%.3f "
            "velocity=%d/hr behavioral_risk=%.3f anomalous=%s",
            request.actor_name, trust, drift.score,
            hourly, behavioral_risk, is_anomalous,
        )

        return assessment
