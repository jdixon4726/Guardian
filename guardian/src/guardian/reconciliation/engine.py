"""
Action Reconciliation Engine

Detects infrastructure actions that occurred WITHOUT flowing through Guardian.
Compares external activity logs (CloudTrail, Azure Activity Log, K8s audit)
against Guardian's audit log to find ungovernaned actions.

This is the defense against Guardian bypass: even if someone skips the
governance gate and performs an action directly, the reconciliation engine
detects it after the fact and raises an alert.

The reconciliation runs periodically (e.g., every 5 minutes) and produces
ReconciliationReport objects listing ungoverned actions.
"""

from __future__ import annotations

import logging
from abc import ABC, abstractmethod
from dataclasses import dataclass, field
from datetime import datetime, timedelta, timezone
from typing import Optional

logger = logging.getLogger(__name__)


@dataclass
class ExternalAction:
    """An infrastructure action observed in an external activity log."""
    source: str                    # "cloudtrail", "azure_activity", "k8s_audit"
    actor: str                     # the principal who performed the action
    action: str                    # the action performed
    resource: str                  # the resource affected
    timestamp: datetime
    event_id: str                  # unique ID from the source system
    raw: dict = field(default_factory=dict)


@dataclass
class UngovernedAction:
    """An action found in external logs with no matching Guardian decision."""
    external_action: ExternalAction
    severity: str = "medium"       # "low", "medium", "high", "critical"
    explanation: str = ""


@dataclass
class ReconciliationReport:
    """Result of a reconciliation run."""
    window_start: datetime
    window_end: datetime
    total_external_actions: int
    total_governed: int
    total_ungoverned: int
    ungoverned_actions: list[UngovernedAction] = field(default_factory=list)
    reconciled_at: datetime = field(default_factory=lambda: datetime.now(timezone.utc))


class ExternalActivitySource(ABC):
    """
    Interface for external activity log sources.

    Each cloud/platform provides an implementation that fetches recent
    actions within a time window.
    """

    @abstractmethod
    def fetch_actions(
        self, start: datetime, end: datetime,
    ) -> list[ExternalAction]:
        """Fetch all actions within the time window."""
        ...

    @abstractmethod
    def source_name(self) -> str:
        """Return the name of this source (e.g., 'cloudtrail')."""
        ...


class ReconciliationEngine:
    """
    Compares external activity logs against Guardian's audit log to
    detect ungoverned infrastructure actions.
    """

    def __init__(
        self,
        activity_sources: list[ExternalActivitySource],
        audit_log_path: "Path | None" = None,
    ):
        self._sources = activity_sources
        self._audit_log_path = audit_log_path
        self._governed_keys: set[str] = set()

    def load_governed_actions(
        self, start: datetime, end: datetime,
    ) -> set[str]:
        """
        Load Guardian-governed actions from the audit log for the time window.

        Returns a set of reconciliation keys (actor:action:resource) that
        have corresponding Guardian decisions.
        """
        import json
        keys = set()

        if self._audit_log_path is None or not self._audit_log_path.exists():
            return keys

        start_iso = start.isoformat()
        end_iso = end.isoformat()

        with open(self._audit_log_path, encoding="utf-8") as f:
            for line in f:
                line = line.strip()
                if not line:
                    continue
                try:
                    entry = json.loads(line)
                    ts = entry.get("evaluated_at", "")
                    if start_iso <= ts <= end_iso:
                        req = entry.get("action_request", {})
                        key = _reconciliation_key(
                            actor=req.get("actor_name", ""),
                            action=req.get("requested_action", ""),
                            resource=req.get("target_asset", ""),
                        )
                        keys.add(key)
                except (json.JSONDecodeError, KeyError):
                    continue

        return keys

    def reconcile(
        self,
        window_minutes: int = 5,
        at: datetime | None = None,
    ) -> ReconciliationReport:
        """
        Run a reconciliation for the specified time window.

        Fetches external actions, compares against Guardian's audit log,
        and returns a report of ungoverned actions.
        """
        end = at or datetime.now(timezone.utc)
        start = end - timedelta(minutes=window_minutes)

        # Load all Guardian-governed actions in this window
        governed = self.load_governed_actions(start, end)

        # Fetch all external actions
        all_external: list[ExternalAction] = []
        for source in self._sources:
            try:
                actions = source.fetch_actions(start, end)
                all_external.extend(actions)
            except Exception as exc:
                logger.error(
                    "Reconciliation: failed to fetch from %s: %s",
                    source.source_name(), exc,
                )

        # Find ungoverned actions
        ungoverned = []
        for action in all_external:
            key = _reconciliation_key(
                actor=action.actor,
                action=action.action,
                resource=action.resource,
            )
            if key not in governed:
                severity = _assess_severity(action)
                ungoverned.append(UngovernedAction(
                    external_action=action,
                    severity=severity,
                    explanation=(
                        f"Action '{action.action}' on '{action.resource}' by "
                        f"'{action.actor}' was performed without Guardian governance "
                        f"(source: {action.source})"
                    ),
                ))

        total_governed = len(all_external) - len(ungoverned)

        if ungoverned:
            logger.warning(
                "Reconciliation: %d ungoverned action(s) detected in %d-minute window",
                len(ungoverned), window_minutes,
            )
        else:
            logger.info(
                "Reconciliation: all %d action(s) governed in %d-minute window",
                len(all_external), window_minutes,
            )

        return ReconciliationReport(
            window_start=start,
            window_end=end,
            total_external_actions=len(all_external),
            total_governed=total_governed,
            total_ungoverned=len(ungoverned),
            ungoverned_actions=ungoverned,
        )


def _reconciliation_key(actor: str, action: str, resource: str) -> str:
    """Produce a normalized key for matching external actions to Guardian decisions."""
    return f"{actor.lower().strip()}:{action.lower().strip()}:{resource.lower().strip()}"


def _assess_severity(action: ExternalAction) -> str:
    """Determine the severity of an ungoverned action."""
    high_risk_actions = {
        "DeleteSecurityGroup", "DeleteRole", "PutRolePolicy",
        "DeleteBucket", "StopInstances", "TerminateInstances",
        "DeleteDBInstance", "ModifySecurityGroup",
    }
    critical_actions = {
        "CreateUser", "AttachUserPolicy", "PutUserPolicy",
        "CreateAccessKey", "DeleteTrail", "StopLogging",
    }

    if action.action in critical_actions:
        return "critical"
    if action.action in high_risk_actions:
        return "high"
    if "delete" in action.action.lower() or "remove" in action.action.lower():
        return "high"
    if "iam" in action.resource.lower() or "security" in action.action.lower():
        return "medium"
    return "low"
