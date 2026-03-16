"""
Risk Scoring Engine

Computes a [0.0, 1.0] risk score from four independent scorers.
Each scorer returns a (score, signals) tuple.
Signals are human-readable strings passed to the Explanation Layer.

Scorer weights:
  action_scorer:  0.30
  actor_scorer:   0.25
  asset_scorer:   0.25
  context_scorer: 0.20
"""

from __future__ import annotations

import logging
from dataclasses import dataclass

from guardian.enrichment.context import EnrichedContext
from guardian.models.action_request import (
    ActorType,
    PrivilegeLevel,
    RiskSignal,
    SensitivityLevel,
)

logger = logging.getLogger(__name__)

# Actions grouped by risk category
_DESTRUCTIVE_ACTIONS = {
    "delete_resource", "destroy_infrastructure", "drop_database",
    "wipe_storage", "terminate_instances", "delete_vpc",
}
_SECURITY_CONTROL_ACTIONS = {
    "disable_endpoint_protection", "disable_antivirus", "disable_edr",
    "modify_security_policy", "remove_security_tool", "disable_firewall",
}
_PRIVILEGE_ACTIONS = {
    "modify_iam_role", "escalate_privileges", "grant_admin_access",
    "add_user_to_group", "create_service_account",
}
_DATA_EXFIL_ACTIONS = {
    "export_data", "download_pii", "copy_database", "backup_to_external",
}
_MODERATE_ACTIONS = {
    "modify_firewall_rule", "modify_security_group", "update_network_acl",
    "change_configuration", "restart_service",
}

_CRITICALITY_WEIGHTS = {
    "low": 0.1,
    "medium": 0.3,
    "high": 0.6,
    "critical": 0.9,
}

_SENSITIVITY_WEIGHTS = {
    SensitivityLevel.public: 0.0,
    SensitivityLevel.internal: 0.2,
    SensitivityLevel.confidential: 0.6,
    SensitivityLevel.high: 0.7,
    SensitivityLevel.restricted: 0.9,
}


@dataclass
class ScorerResult:
    score: float
    signals: list[RiskSignal]


def action_scorer(context: EnrichedContext) -> ScorerResult:
    """Score based on the type and destructiveness of the requested action."""
    action = context.request.requested_action
    signals = []
    score = 0.2  # baseline

    if action in _DESTRUCTIVE_ACTIONS:
        score = 0.90
        signals.append(RiskSignal(
            source="action_scorer",
            description=f"Destructive action '{action}' — highest risk category",
            contribution=0.70,
        ))
    elif action in _SECURITY_CONTROL_ACTIONS:
        score = 0.85
        signals.append(RiskSignal(
            source="action_scorer",
            description=f"Security control modification '{action}' — direct attack surface",
            contribution=0.65,
        ))
    elif action in _PRIVILEGE_ACTIONS:
        score = 0.70
        signals.append(RiskSignal(
            source="action_scorer",
            description=f"Privilege modification action '{action}'",
            contribution=0.50,
        ))
    elif action in _DATA_EXFIL_ACTIONS:
        score = 0.75
        signals.append(RiskSignal(
            source="action_scorer",
            description=f"Data export/exfiltration action '{action}'",
            contribution=0.55,
        ))
    elif action in _MODERATE_ACTIONS:
        score = 0.45
        signals.append(RiskSignal(
            source="action_scorer",
            description=f"Infrastructure modification action '{action}'",
            contribution=0.25,
        ))
    else:
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


def actor_scorer(context: EnrichedContext) -> ScorerResult:
    """Score based on actor type, trust level, and history."""
    signals = []
    score = 0.2

    actor_type = context.request.actor_type

    if actor_type == ActorType.ai_agent:
        score = 0.55
        signals.append(RiskSignal(
            source="actor_scorer",
            description="Actor type is AI agent — elevated inherent risk for privileged actions",
            contribution=0.35,
        ))
    elif actor_type == ActorType.automation:
        score = 0.35
        signals.append(RiskSignal(
            source="actor_scorer",
            description="Actor type is automation account",
            contribution=0.15,
        ))
    else:
        score = 0.20
        signals.append(RiskSignal(
            source="actor_scorer",
            description="Actor type is human operator",
            contribution=0.00,
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


def asset_scorer(context: EnrichedContext) -> ScorerResult:
    """Score based on asset criticality and sensitivity classification."""
    signals = []

    criticality_score = _CRITICALITY_WEIGHTS.get(context.asset.criticality, 0.3)
    sensitivity_score = _SENSITIVITY_WEIGHTS.get(context.request.sensitivity_level, 0.2)
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


def context_scorer(context: EnrichedContext,
                   drift_score: float = 0.0) -> ScorerResult:
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

    if hourly > 50:
        addition = 0.25
        score = min(1.0, score + addition)
        signals.append(RiskSignal(
            source="context_scorer",
            description=f"Extreme hourly velocity: {hourly} actions in last hour",
            contribution=addition,
        ))
    elif hourly > 20:
        addition = 0.15
        score = min(1.0, score + addition)
        signals.append(RiskSignal(
            source="context_scorer",
            description=f"High hourly velocity: {hourly} actions in last hour",
            contribution=addition,
        ))

    if daily > 200:
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

    Weights: action=0.30, actor=0.25, asset=0.25, context=0.20
    """

    WEIGHTS = {
        "action": 0.30,
        "actor": 0.25,
        "asset": 0.25,
        "context": 0.20,
    }

    def score(self, context: EnrichedContext,
              drift_score: float = 0.0) -> tuple[float, list[RiskSignal]]:
        results = {
            "action": action_scorer(context),
            "actor": actor_scorer(context),
            "asset": asset_scorer(context),
            "context": context_scorer(context, drift_score),
        }

        weighted = sum(
            results[key].score * self.WEIGHTS[key]
            for key in self.WEIGHTS
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
