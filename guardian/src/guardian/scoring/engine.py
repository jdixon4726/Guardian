"""
Risk Scoring Engine

Computes a [0.0, 1.0] risk score from four independent scorers.
Each scorer returns a (score, signals) tuple.
Signals are human-readable strings passed to the Explanation Layer.

All action categories, weights, and thresholds are loaded from
GuardianConfig at startup. Defaults match the original hardcoded values.
"""

from __future__ import annotations

import logging
from dataclasses import dataclass

from guardian.config.model import GuardianConfig, ScoringConfig
from guardian.enrichment.context import EnrichedContext
from guardian.models.action_request import (
    ActorType,
    PrivilegeLevel,
    RiskSignal,
    SensitivityLevel,
)

logger = logging.getLogger(__name__)

# Default config used by module-level scorer functions (for backward compat)
_DEFAULT_CONFIG = ScoringConfig()


@dataclass
class ScorerResult:
    score: float
    signals: list[RiskSignal]


def _resolve_action_category(
    action: str, cfg: ScoringConfig,
) -> tuple[str | None, float]:
    """Find which category an action belongs to. Returns (category, score)."""
    for category, actions in cfg.action_categories.items():
        if action in actions:
            return category, cfg.action_category_scores.get(
                category, cfg.baseline_action_score,
            )
    return None, cfg.baseline_action_score


_CATEGORY_LABELS = {
    "destructive": "Destructive action '{action}' — highest risk category",
    "security_control": "Security control modification '{action}' — direct attack surface",
    "privilege": "Privilege modification action '{action}'",
    "data_exfil": "Data export/exfiltration action '{action}'",
    "moderate": "Infrastructure modification action '{action}'",
}


def action_scorer(
    context: EnrichedContext, cfg: ScoringConfig = _DEFAULT_CONFIG,
) -> ScorerResult:
    """Score based on the type and destructiveness of the requested action."""
    action = context.request.requested_action
    signals = []

    category, score = _resolve_action_category(action, cfg)

    if category is not None:
        label = _CATEGORY_LABELS.get(
            category, f"Action category '{category}': '{{action}}'",
        ).format(action=action)
        signals.append(RiskSignal(
            source="action_scorer",
            description=label,
            contribution=round(score - cfg.baseline_action_score, 2),
        ))
    else:
        score = cfg.baseline_action_score
        signals.append(RiskSignal(
            source="action_scorer",
            description=f"Unknown action '{action}' — applying baseline risk",
            contribution=0.00,
        ))

    # Elevated privilege on any action adds risk
    if context.request.privilege_level == PrivilegeLevel.elevated:
        score = min(1.0, score + 0.10)
        signals.append(RiskSignal(
            source="action_scorer",
            description="Elevated privilege level requested",
            contribution=0.10,
        ))
    elif context.request.privilege_level == PrivilegeLevel.admin:
        score = min(1.0, score + 0.20)
        signals.append(RiskSignal(
            source="action_scorer",
            description="Admin privilege level requested",
            contribution=0.20,
        ))

    return ScorerResult(score=round(score, 3), signals=signals)


def actor_scorer(
    context: EnrichedContext, cfg: ScoringConfig = _DEFAULT_CONFIG,
) -> ScorerResult:
    """Score based on actor type, trust level, and history."""
    signals = []

    actor_type = context.request.actor_type
    score = cfg.actor_type_scores.get(actor_type.value, 0.20)

    type_labels = {
        ActorType.ai_agent: "Actor type is AI agent — elevated inherent risk for privileged actions",
        ActorType.automation: "Actor type is automation account",
        ActorType.human: "Actor type is human operator",
    }
    signals.append(RiskSignal(
        source="actor_scorer",
        description=type_labels.get(actor_type, f"Actor type: {actor_type.value}"),
        contribution=round(score - 0.20, 2),
    ))

    # History signals
    history = context.actor_history
    if history.total_blocks > 5:
        score = min(1.0, score + 0.15)
        signals.append(RiskSignal(
            source="actor_scorer",
            description=f"Actor has {history.total_blocks} prior blocks in history",
            contribution=0.15,
        ))

    if history.prior_privilege_escalations > 0:
        score = min(1.0, score + 0.10)
        signals.append(RiskSignal(
            source="actor_scorer",
            description=(
                f"Actor has {history.prior_privilege_escalations} prior privilege "
                "escalation(s) in history"
            ),
            contribution=0.10,
        ))

    # Trust level signals — low trust increases risk, high trust reduces it
    trust = history.trust_level
    if trust < 0.3:
        addition = 0.15
        score = min(1.0, score + addition)
        signals.append(RiskSignal(
            source="actor_scorer",
            description=f"Low trust level ({trust:.2f}) — actor has history of blocks or reviews",
            contribution=addition,
        ))
    elif trust < 0.5 and history.total_actions >= 10:
        addition = 0.05
        score = min(1.0, score + addition)
        signals.append(RiskSignal(
            source="actor_scorer",
            description=f"Below-average trust level ({trust:.2f})",
            contribution=addition,
        ))
    elif trust > 0.7 and history.total_actions >= 10:
        reduction = -0.10
        score = max(0.0, score + reduction)
        signals.append(RiskSignal(
            source="actor_scorer",
            description=f"High trust level ({trust:.2f}) — established actor with clean history",
            contribution=reduction,
        ))

    return ScorerResult(score=round(score, 3), signals=signals)


def asset_scorer(
    context: EnrichedContext, cfg: ScoringConfig = _DEFAULT_CONFIG,
) -> ScorerResult:
    """Score based on asset criticality and sensitivity classification."""
    signals = []

    criticality_score = cfg.criticality_weights.get(context.asset.criticality, 0.3)
    sensitivity_score = cfg.sensitivity_weights.get(
        context.request.sensitivity_level.value, 0.2,
    )
    score = (criticality_score * 0.5) + (sensitivity_score * 0.5)

    signals.append(RiskSignal(
        source="asset_scorer",
        description=(
            f"Asset criticality '{context.asset.criticality}' "
            f"× sensitivity '{context.request.sensitivity_level.value}'"
        ),
        contribution=round(score, 3),
    ))

    if not context.asset.found:
        score = min(1.0, score + 0.15)
        signals.append(RiskSignal(
            source="asset_scorer",
            description="Asset not found in catalog — unknown assets carry additional risk",
            contribution=0.15,
        ))

    return ScorerResult(score=round(score, 3), signals=signals)


def context_scorer(
    context: EnrichedContext,
    drift_score: float = 0.0,
    cfg: ScoringConfig = _DEFAULT_CONFIG,
) -> ScorerResult:
    """Score based on maintenance window, action velocity, and behavioral drift."""
    signals = []
    score = 0.3  # baseline outside window

    if context.maintenance_window.in_window:
        score = 0.10
        signals.append(RiskSignal(
            source="context_scorer",
            description=(
                f"Active maintenance window '{context.maintenance_window.window_id}' — "
                "risk reduced"
            ),
            contribution=-0.20,
        ))
    else:
        signals.append(RiskSignal(
            source="context_scorer",
            description="No active maintenance window for target system",
            contribution=0.10,
        ))

    # Velocity signals — high action rates indicate automation bursts or compromise
    hourly = context.actor_history.actions_last_hour
    daily = context.actor_history.actions_last_day

    if hourly > cfg.velocity_hourly_extreme:
        addition = 0.25
        score = min(1.0, score + addition)
        signals.append(RiskSignal(
            source="context_scorer",
            description=f"Extreme hourly velocity: {hourly} actions in last hour",
            contribution=addition,
        ))
    elif hourly > cfg.velocity_hourly_high:
        addition = 0.15
        score = min(1.0, score + addition)
        signals.append(RiskSignal(
            source="context_scorer",
            description=f"High hourly velocity: {hourly} actions in last hour",
            contribution=addition,
        ))

    if daily > cfg.velocity_daily_high:
        addition = 0.10
        score = min(1.0, score + addition)
        signals.append(RiskSignal(
            source="context_scorer",
            description=f"High daily velocity: {daily} actions in last 24 hours",
            contribution=addition,
        ))

    # Drift signals
    if drift_score > 0.5:
        addition = min(0.40, drift_score * 0.5)
        score = min(1.0, score + addition)
        signals.append(RiskSignal(
            source="context_scorer",
            description=(
                f"Behavioral drift score {drift_score:.2f} — actor behavior "
                "deviating from established baseline"
            ),
            contribution=round(addition, 3),
        ))
    elif drift_score > 0.2:
        signals.append(RiskSignal(
            source="context_scorer",
            description=f"Behavioral drift score {drift_score:.2f} — within normal range",
            contribution=0.0,
        ))

    return ScorerResult(score=round(score, 3), signals=signals)


class RiskScoringEngine:
    """
    Combines the four scorers into a weighted composite risk score.

    Accepts a ScoringConfig for all tunables. Defaults match the
    original hardcoded values when no config is provided.
    """

    def __init__(self, config: ScoringConfig | None = None):
        self.cfg = config or ScoringConfig()
        self.weights = self.cfg.weights

    def score(self, context: EnrichedContext,
              drift_score: float = 0.0) -> tuple[float, list[RiskSignal]]:
        results = {
            "action": action_scorer(context, self.cfg),
            "actor": actor_scorer(context, self.cfg),
            "asset": asset_scorer(context, self.cfg),
            "context": context_scorer(context, drift_score, self.cfg),
        }

        weighted = sum(
            results[key].score * self.weights[key]
            for key in self.weights
        )
        final = round(min(1.0, max(0.0, weighted)), 3)

        all_signals = [
            signal
            for key in ("action", "actor", "asset", "context")
            for signal in results[key].signals
        ]

        logger.debug(
            "Risk scores: action=%.3f actor=%.3f asset=%.3f context=%.3f → composite=%.3f",
            results["action"].score, results["actor"].score,
            results["asset"].score, results["context"].score, final,
        )
        return final, all_signals
