"""
Graph Builder — converts Guardian Decision objects into graph events.

Hooks into the pipeline after audit logging to populate the decision graph.
Handles triggered_by inference for cascade detection.
"""

from __future__ import annotations

import logging
from typing import Any

from guardian.config.model import ScoringConfig
from guardian.graph.models import DecisionEvent
from guardian.graph.store import GraphStore
from guardian.models.action_request import Decision

logger = logging.getLogger(__name__)


def _classify_action(action_name: str, scoring_config: ScoringConfig | None = None) -> str:
    """Classify an action into a family based on config or heuristics."""
    if scoring_config:
        for category, actions in scoring_config.action_categories.items():
            if action_name in actions:
                return category

    # Heuristic fallback
    lower = action_name.lower()
    if any(w in lower for w in ("delete", "destroy", "remove", "drop")):
        return "destructive"
    if any(w in lower for w in ("create", "provision", "deploy", "apply")):
        return "infrastructure_change"
    if any(w in lower for w in ("iam", "role", "policy", "permission")):
        return "privilege_escalation"
    if any(w in lower for w in ("config", "modify", "update", "change")):
        return "configuration_change"
    return "operational"


class GraphBuilder:
    """
    Translates Guardian Decisions into graph events.
    Call record_decision() after each pipeline evaluation.
    """

    def __init__(
        self,
        store: GraphStore,
        cascade_window_seconds: int = 300,
        scoring_config: ScoringConfig | None = None,
    ):
        self.store = store
        self.cascade_window = cascade_window_seconds
        self._scoring_config = scoring_config

    def record_decision(
        self,
        decision: Decision,
        trust_score: float = 0.5,
        is_anomalous: bool = False,
    ) -> DecisionEvent:
        """
        Record a Decision in the graph.
        Infers triggered_by from temporal proximity and system correlation.
        Returns the DecisionEvent for further processing.
        """
        req = decision.action_request

        event = DecisionEvent.from_decision(
            decision=decision,
            action_family=_classify_action(req.requested_action, self._scoring_config),
            trust_score=trust_score,
            is_anomalous=is_anomalous,
        )

        # Infer cascade link
        triggered_by = self.store.infer_triggered_by(
            event, window_seconds=self.cascade_window
        )
        if triggered_by:
            event.triggered_by_event_id = triggered_by
            logger.info(
                "Cascade detected: %s triggered by %s",
                event.event_id, triggered_by,
            )

        # Record in graph
        self.store.record_event(event)

        return event
