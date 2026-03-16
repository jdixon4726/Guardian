"""
Bayesian Confidence Scoring

Inspired by Darktrace's approach: each actor starts with wide confidence
intervals that narrow as observations accumulate. This prevents both
over-alerting on new actors (false positives) and under-alerting on
established actors (missed anomalies).

The confidence model uses a Beta distribution as the conjugate prior for
binomial outcomes (risky vs. normal actions). As observations accumulate,
the posterior distribution narrows, producing increasingly precise risk
estimates.

Key properties:
  - New actors: wide intervals → conservative decisions (require_review)
  - Established actors: narrow intervals → precise anomaly detection
  - Confidence explicitly quantified → included in explanations
"""

from __future__ import annotations

import logging
import math
from dataclasses import dataclass

logger = logging.getLogger(__name__)


@dataclass
class ConfidenceEstimate:
    """
    Bayesian confidence estimate for an actor's risk level.

    mean: expected risk level (point estimate)
    lower: lower bound of credible interval
    upper: upper bound of credible interval
    width: interval width (upper - lower) — wide = uncertain
    observations: number of observations backing this estimate
    confidence: [0.0, 1.0] — how much to trust this estimate
    """
    mean: float
    lower: float
    upper: float
    width: float
    observations: int
    confidence: float

    @property
    def is_precise(self) -> bool:
        """True if we have enough data for narrow intervals."""
        return self.width < 0.2 and self.observations >= 20

    @property
    def is_uncertain(self) -> bool:
        """True if intervals are still wide (new or sparse actor)."""
        return self.width > 0.4 or self.observations < 5


class BayesianConfidenceScorer:
    """
    Computes confidence-weighted risk estimates using Beta-Binomial updating.

    The Beta distribution models our belief about an actor's "risk rate":
      - alpha = count of risky observations + prior
      - beta = count of normal observations + prior

    Prior selection:
      - AI agents: alpha=3, beta=3 (neutral prior, moderate uncertainty)
      - Automation: alpha=2, beta=4 (slightly optimistic — automation is usually safe)
      - Human: alpha=2, beta=5 (more optimistic — humans are typically authorized)

    As observations accumulate, the posterior concentrates around the
    true risk rate, and the credible interval narrows.
    """

    # Default priors by actor type (alpha, beta)
    _PRIORS = {
        "ai_agent": (3.0, 3.0),
        "automation": (2.0, 4.0),
        "human": (2.0, 5.0),
    }

    def __init__(self, priors: dict[str, tuple[float, float]] | None = None):
        self._priors = priors or self._PRIORS

    def estimate(
        self,
        actor_type: str,
        risky_count: int,
        normal_count: int,
        credible_interval: float = 0.90,
    ) -> ConfidenceEstimate:
        """
        Compute a Bayesian confidence estimate for an actor's risk level.

        risky_count: number of actions that received block or require_review
        normal_count: number of actions that received allow or allow_with_logging
        credible_interval: width of the credible interval (default 90%)
        """
        prior_alpha, prior_beta = self._priors.get(actor_type, (2.0, 4.0))

        alpha = prior_alpha + risky_count
        beta = prior_beta + normal_count
        total_obs = risky_count + normal_count

        # Posterior mean
        mean = alpha / (alpha + beta)

        # Credible interval using Beta distribution quantiles
        # Approximation using normal approximation to Beta for large counts
        # For small counts, use the exact Beta quantile (via regularized incomplete beta)
        lower, upper = self._credible_interval(alpha, beta, credible_interval)
        width = upper - lower

        # Confidence: how much to trust this estimate
        # Scales from 0 (no observations) to 1 (many observations)
        # Uses a logistic curve: confidence = 1 - 1/(1 + obs/10)
        confidence = 1.0 - 1.0 / (1.0 + total_obs / 10.0)

        return ConfidenceEstimate(
            mean=round(mean, 4),
            lower=round(lower, 4),
            upper=round(upper, 4),
            width=round(width, 4),
            observations=total_obs,
            confidence=round(confidence, 4),
        )

    def _credible_interval(
        self, alpha: float, beta: float, level: float,
    ) -> tuple[float, float]:
        """
        Approximate credible interval for Beta(alpha, beta).

        Uses the normal approximation: mean ± z * sqrt(var).
        Accurate for alpha, beta > 2.
        """
        mean = alpha / (alpha + beta)
        var = (alpha * beta) / ((alpha + beta) ** 2 * (alpha + beta + 1))
        std = math.sqrt(var)

        # z-score for the credible interval
        # 90% → 1.645, 95% → 1.96, 99% → 2.576
        tail = (1.0 - level) / 2.0
        z = self._probit(1.0 - tail)

        lower = max(0.0, mean - z * std)
        upper = min(1.0, mean + z * std)
        return lower, upper

    @staticmethod
    def _probit(p: float) -> float:
        """Approximate inverse normal CDF (probit function)."""
        # Rational approximation (Abramowitz and Stegun 26.2.23)
        if p <= 0.0:
            return -4.0
        if p >= 1.0:
            return 4.0
        if p == 0.5:
            return 0.0

        if p > 0.5:
            return -BayesianConfidenceScorer._probit(1.0 - p)

        t = math.sqrt(-2.0 * math.log(p))
        c0, c1, c2 = 2.515517, 0.802853, 0.010328
        d1, d2, d3 = 1.432788, 0.189269, 0.001308
        return -(t - (c0 + c1 * t + c2 * t * t) / (1 + d1 * t + d2 * t * t + d3 * t * t * t))
