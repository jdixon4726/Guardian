"""
Drift Detection Engine

Computes a composite DriftScore from two independent signals:

  1. Level Drift (z-score):  How far is the current action's risk score
     from the actor's rolling mean?  |z| > 2.0 is significant.

  2. Pattern Drift (Jensen-Shannon divergence):  How different is the actor's
     recent action-type distribution from their baseline distribution?
     JS divergence is bounded [0, 1]; values > 0.3 are notable.

Additionally, regularity detection flags actors with suspiciously low
behavioral variance (coefficient of variation < 0.1), which may indicate
automation masquerading as human or compromised accounts running scripts.

The composite drift score feeds into the Context Scorer in the Risk Scoring
Engine, amplifying risk when behavioral anomalies are detected.
"""

from __future__ import annotations

import logging
import math
from datetime import datetime, timezone

from guardian.config.model import DriftConfig
from guardian.drift.baseline import ActorBaseline, BaselineStore
from guardian.models.action_request import DriftScore

logger = logging.getLogger(__name__)

# Default thresholds (used when no config provided, and for backward compat imports)
_DEFAULT_DRIFT = DriftConfig()
Z_SCORE_ALERT_THRESHOLD = _DEFAULT_DRIFT.z_score_alert_threshold
Z_SCORE_WARN_THRESHOLD = _DEFAULT_DRIFT.z_score_warn_threshold
JS_ALERT_THRESHOLD = _DEFAULT_DRIFT.js_alert_threshold
JS_WARN_THRESHOLD = _DEFAULT_DRIFT.js_warn_threshold
REGULARITY_THRESHOLD = _DEFAULT_DRIFT.regularity_threshold
MIN_OBSERVATIONS = _DEFAULT_DRIFT.min_observations


def _jensen_shannon_divergence(p: dict[str, float], q: dict[str, float]) -> float:
    """
    Compute Jensen-Shannon divergence between two discrete distributions.
    Returns a value in [0, 1]. Uses log base 2.

    p and q are dicts mapping action_type -> probability.
    Missing keys in either distribution are treated as 0.
    """
    all_keys = set(p) | set(q)
    if not all_keys:
        return 0.0

    # Build aligned vectors with small epsilon to avoid log(0)
    eps = 1e-10
    p_vec = [p.get(k, 0.0) + eps for k in all_keys]
    q_vec = [q.get(k, 0.0) + eps for k in all_keys]

    # Normalize after adding epsilon
    p_sum = sum(p_vec)
    q_sum = sum(q_vec)
    p_vec = [x / p_sum for x in p_vec]
    q_vec = [x / q_sum for x in q_vec]

    # M = midpoint distribution
    m_vec = [(pi + qi) / 2.0 for pi, qi in zip(p_vec, q_vec)]

    # JS = 0.5 * KL(P||M) + 0.5 * KL(Q||M)
    def kl(a: list[float], b: list[float]) -> float:
        return sum(ai * math.log2(ai / bi) for ai, bi in zip(a, b))

    js = 0.5 * kl(p_vec, m_vec) + 0.5 * kl(q_vec, m_vec)
    return min(1.0, max(0.0, js))


def _compute_level_drift_z(
    current_risk: float, baseline: ActorBaseline
) -> float:
    """Compute z-score of current risk against baseline mean.

    When stddev is near-zero (highly regular actor), any meaningful deviation
    from the mean is treated as extreme drift. We use a minimum stddev floor
    to avoid division-by-zero while still producing large z-scores.
    """
    if not baseline.has_baseline:
        return 0.0
    # Floor stddev so near-zero-variance actors still produce
    # meaningful z-scores when risk deviates from the mean.
    effective_stddev = max(baseline.stddev_risk, _DEFAULT_DRIFT.stddev_floor)
    return (current_risk - baseline.mean_risk) / effective_stddev


def _compute_pattern_drift(
    current_action: str, baseline: ActorBaseline
) -> float:
    """
    Compute JS divergence between baseline action distribution and a
    distribution that includes the current action as the sole new observation.

    This measures how surprising the current action type is relative to
    the actor's established behavioral pattern.
    """
    if not baseline.has_baseline or not baseline.action_distribution:
        return 0.0

    # Build a "current" distribution: the baseline + 1 new observation
    # weighted to emphasize the new action
    current_dist = dict(baseline.action_distribution)
    n = baseline.observation_count
    weight = 1.0 / (n + 1)

    # Scale baseline distribution down, add new observation
    adjusted: dict[str, float] = {}
    for k, v in current_dist.items():
        adjusted[k] = v * (n / (n + 1))
    adjusted[current_action] = adjusted.get(current_action, 0.0) + weight

    return _jensen_shannon_divergence(baseline.action_distribution, adjusted)


class DriftDetectionEngine:
    """
    Evaluates behavioral drift for a given actor and action.

    Requires a BaselineStore with precomputed baselines. The engine is
    stateless — all state lives in the store.
    """

    def __init__(self, baseline_store: BaselineStore,
                 config: DriftConfig | None = None):
        self.store = baseline_store
        self.cfg = config or DriftConfig()

    def evaluate(
        self,
        actor_name: str,
        action_type: str,
        current_risk: float,
        timestamp: datetime | None = None,
    ) -> DriftScore:
        """
        Compute drift score for a single action evaluation.

        Records the observation and returns the drift assessment.
        """
        if timestamp is None:
            timestamp = datetime.now(timezone.utc)

        baseline = self.store.get_baseline(actor_name)

        cfg = self.cfg

        if not baseline.has_baseline:
            # Not enough history — record and return neutral
            self.store.record_observation(
                actor_name, action_type, current_risk, timestamp
            )
            return DriftScore(
                score=0.0,
                level_drift_z=0.0,
                pattern_drift_js=0.0,
                baseline_days=baseline.baseline_days,
                alert_triggered=False,
                explanation=(
                    f"Insufficient baseline for actor '{actor_name}' "
                    f"({baseline.observation_count}/{cfg.min_observations} observations). "
                    "Drift detection inactive."
                ),
            )

        # Compute drift signals
        z_score = _compute_level_drift_z(current_risk, baseline)
        js_divergence = _compute_pattern_drift(action_type, baseline)

        # Regularity detection
        regularity_flag = baseline.variance_score < cfg.regularity_threshold

        # Composite drift score: weighted combination
        # z-score component: normalized to [0, 1] using sigmoid-like mapping
        z_abs = abs(z_score)
        z_component = min(1.0, z_abs / 4.0)  # z=4 maps to 1.0

        # JS component already in [0, 1]
        js_component = min(1.0, js_divergence / 0.5)  # 0.5 JS maps to 1.0

        # Regularity bonus: adds to score if actor is suspiciously regular
        regularity_bonus = 0.15 if regularity_flag else 0.0

        composite = min(1.0, (z_component * 0.50) + (js_component * 0.35) + regularity_bonus)
        composite = round(composite, 4)

        # Alert determination
        alert = (
            z_abs >= cfg.z_score_alert_threshold
            or js_divergence >= cfg.js_alert_threshold
            or (regularity_flag and z_abs >= cfg.z_score_warn_threshold)
        )

        # Build explanation
        explanation_parts = []

        if z_abs >= cfg.z_score_alert_threshold:
            direction = "above" if z_score > 0 else "below"
            explanation_parts.append(
                f"Risk level {z_score:+.2f}σ {direction} baseline mean "
                f"({baseline.mean_risk:.3f} ± {baseline.stddev_risk:.3f})"
            )
        elif z_abs >= cfg.z_score_warn_threshold:
            explanation_parts.append(
                f"Risk level elevated at {z_score:+.2f}σ from baseline"
            )

        if js_divergence >= cfg.js_alert_threshold:
            explanation_parts.append(
                f"Action pattern divergence {js_divergence:.3f} — "
                "significant deviation from established behavior"
            )
        elif js_divergence >= cfg.js_warn_threshold:
            explanation_parts.append(
                f"Action pattern divergence {js_divergence:.3f} — "
                "moderate deviation from baseline"
            )

        if regularity_flag:
            explanation_parts.append(
                f"Suspiciously regular behavior detected "
                f"(variance score {baseline.variance_score:.3f})"
            )

        if not explanation_parts:
            explanation_parts.append(
                f"Actor '{actor_name}' behavior within normal parameters "
                f"(z={z_score:+.2f}, JS={js_divergence:.3f})"
            )

        explanation = "; ".join(explanation_parts)

        # Record observation after scoring
        self.store.record_observation(
            actor_name, action_type, current_risk, timestamp
        )

        logger.info(
            "Drift: actor=%s z=%.2f js=%.3f regularity=%s composite=%.3f alert=%s",
            actor_name, z_score, js_divergence, regularity_flag, composite, alert,
        )

        return DriftScore(
            score=composite,
            level_drift_z=round(z_score, 4),
            pattern_drift_js=round(js_divergence, 4),
            baseline_days=baseline.baseline_days,
            alert_triggered=alert,
            explanation=explanation,
        )
