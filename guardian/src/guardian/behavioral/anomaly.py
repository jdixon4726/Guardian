"""
Multi-Dimensional Anomaly Scoring with Composite Model Breaches

Inspired by Darktrace's approach: anomalies are scored across multiple
independent dimensions simultaneously. A "model breach" requires multiple
dimensions to fire — a single anomalous signal is not enough to escalate.

Dimensions scored:
  1. Level drift      — is the risk score unusual for this actor?
  2. Pattern drift    — is the action type unusual for this actor?
  3. Velocity         — is the action rate unusual?
  4. Temporal         — is the timing unusual for this actor?
  5. Trust deviation  — is this action inconsistent with the actor's trust level?
  6. Peer deviation   — is this unusual even for the actor's peer group?

Composite breach threshold:
  An anomaly alert requires at least N dimensions to independently
  flag as anomalous. This dramatically reduces false positives while
  maintaining sensitivity to real threats.
"""

from __future__ import annotations

import logging
from dataclasses import dataclass, field
from datetime import datetime, timezone

logger = logging.getLogger(__name__)

# Default: require 2 of 6 dimensions to trigger a model breach
DEFAULT_BREACH_THRESHOLD = 2


@dataclass
class DimensionScore:
    """Score for a single anomaly dimension."""
    name: str
    score: float           # [0.0, 1.0] — normalized anomaly score
    is_anomalous: bool     # True if this dimension exceeds its threshold
    detail: str = ""       # human-readable explanation


@dataclass
class AnomalyAssessment:
    """
    Multi-dimensional anomaly assessment.

    A model breach occurs when enough independent dimensions flag as
    anomalous simultaneously. This is Darktrace's key false-positive
    reduction mechanism applied to machine identity governance.
    """
    dimensions: list[DimensionScore] = field(default_factory=list)
    composite_score: float = 0.0       # weighted combination of all dimensions
    anomalous_dimensions: int = 0      # how many dimensions flagged
    breach_threshold: int = DEFAULT_BREACH_THRESHOLD
    is_model_breach: bool = False      # True if enough dimensions fired
    confidence: float = 0.0            # [0.0, 1.0] — Bayesian confidence
    explanation: str = ""

    @property
    def breach_ratio(self) -> float:
        """Fraction of dimensions that flagged (0.0 to 1.0)."""
        if not self.dimensions:
            return 0.0
        return self.anomalous_dimensions / len(self.dimensions)


class MultiDimensionalAnomalyScorer:
    """
    Scores anomalies across multiple independent dimensions and determines
    whether a composite model breach has occurred.
    """

    def __init__(self, breach_threshold: int = DEFAULT_BREACH_THRESHOLD):
        self.breach_threshold = breach_threshold

    def score(
        self,
        level_drift_z: float,
        pattern_drift_js: float,
        velocity_hourly: int,
        velocity_daily: int,
        trust_level: float,
        risk_score: float,
        peer_z_score: float | None = None,
        is_outside_normal_hours: bool = False,
        confidence: float = 0.5,
    ) -> AnomalyAssessment:
        """
        Compute a multi-dimensional anomaly assessment.

        Each dimension is scored independently. A model breach requires
        breach_threshold dimensions to flag simultaneously.
        """
        dimensions: list[DimensionScore] = []

        # Dimension 1: Level drift
        z_abs = abs(level_drift_z)
        level_anomalous = z_abs > 2.5
        dimensions.append(DimensionScore(
            name="level_drift",
            score=min(1.0, z_abs / 4.0),
            is_anomalous=level_anomalous,
            detail=f"Risk level {level_drift_z:+.2f}σ from baseline" if z_abs > 1.0 else "Normal range",
        ))

        # Dimension 2: Pattern drift
        pattern_anomalous = pattern_drift_js > 0.35
        dimensions.append(DimensionScore(
            name="pattern_drift",
            score=min(1.0, pattern_drift_js / 0.5),
            is_anomalous=pattern_anomalous,
            detail=f"Action pattern divergence: {pattern_drift_js:.3f}" if pattern_drift_js > 0.1 else "Normal pattern",
        ))

        # Dimension 3: Velocity
        velocity_anomalous = velocity_hourly > 50 or velocity_daily > 500
        velocity_score = min(1.0, velocity_hourly / 100.0)
        dimensions.append(DimensionScore(
            name="velocity",
            score=velocity_score,
            is_anomalous=velocity_anomalous,
            detail=f"{velocity_hourly}/hr, {velocity_daily}/day" if velocity_hourly > 10 else "Normal rate",
        ))

        # Dimension 4: Temporal
        temporal_anomalous = is_outside_normal_hours
        dimensions.append(DimensionScore(
            name="temporal",
            score=0.6 if is_outside_normal_hours else 0.0,
            is_anomalous=temporal_anomalous,
            detail="Action outside normal operating hours" if is_outside_normal_hours else "Within normal hours",
        ))

        # Dimension 5: Trust deviation
        # High-risk action from low-trust actor, or action inconsistent with trust
        trust_risk_gap = max(0.0, risk_score - trust_level)
        trust_anomalous = trust_risk_gap > 0.5
        dimensions.append(DimensionScore(
            name="trust_deviation",
            score=min(1.0, trust_risk_gap),
            is_anomalous=trust_anomalous,
            detail=f"Risk ({risk_score:.2f}) exceeds trust ({trust_level:.2f}) by {trust_risk_gap:.2f}" if trust_risk_gap > 0.2 else "Consistent with trust level",
        ))

        # Dimension 6: Peer deviation
        if peer_z_score is not None:
            peer_abs = abs(peer_z_score)
            peer_anomalous = peer_abs > 2.0
            dimensions.append(DimensionScore(
                name="peer_deviation",
                score=min(1.0, peer_abs / 3.0),
                is_anomalous=peer_anomalous,
                detail=f"{peer_z_score:+.2f}σ from peer group" if peer_abs > 1.0 else "Normal for peer group",
            ))

        # Composite scoring
        anomalous_count = sum(1 for d in dimensions if d.is_anomalous)
        weights = {
            "level_drift": 0.25,
            "pattern_drift": 0.20,
            "velocity": 0.15,
            "temporal": 0.10,
            "trust_deviation": 0.20,
            "peer_deviation": 0.10,
        }
        composite = sum(
            d.score * weights.get(d.name, 0.1) for d in dimensions
        )
        composite = round(min(1.0, composite), 4)

        # Model breach determination
        is_breach = anomalous_count >= self.breach_threshold

        # Build explanation
        if is_breach:
            flagged = [d for d in dimensions if d.is_anomalous]
            parts = [f"{d.name}: {d.detail}" for d in flagged]
            explanation = (
                f"MODEL BREACH: {anomalous_count}/{len(dimensions)} dimensions "
                f"flagged ({', '.join(d.name for d in flagged)}). "
                + "; ".join(parts)
            )
        elif anomalous_count > 0:
            flagged = [d for d in dimensions if d.is_anomalous]
            explanation = (
                f"Elevated: {anomalous_count}/{len(dimensions)} dimension(s) flagged "
                f"(need {self.breach_threshold} for breach). "
                + "; ".join(f"{d.name}: {d.detail}" for d in flagged)
            )
        else:
            explanation = "All dimensions within normal parameters."

        return AnomalyAssessment(
            dimensions=dimensions,
            composite_score=composite,
            anomalous_dimensions=anomalous_count,
            breach_threshold=self.breach_threshold,
            is_model_breach=is_breach,
            confidence=confidence,
            explanation=explanation,
        )
