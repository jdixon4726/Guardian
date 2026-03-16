"""
External Activity Sources for Reconciliation

Implementations of ExternalActivitySource for common cloud platforms.
These fetch recent infrastructure actions from cloud audit logs to
compare against Guardian's governed action log.
"""

from __future__ import annotations

import json
import logging
from datetime import datetime, timezone
from pathlib import Path

from guardian.reconciliation.engine import ExternalAction, ExternalActivitySource

logger = logging.getLogger(__name__)


class CloudTrailFileSource(ExternalActivitySource):
    """
    Read CloudTrail events from a local JSON file (exported or synced).

    In production, this would be replaced with an SQS consumer reading
    from a CloudTrail trail's S3 bucket or SNS topic. The file-based
    implementation enables testing and local development.

    Expected format: JSON file with {"Records": [...]} or newline-delimited
    JSON with one event per line.
    """

    def __init__(self, events_path: Path):
        self._path = events_path

    def source_name(self) -> str:
        return "cloudtrail"

    def fetch_actions(
        self, start: datetime, end: datetime,
    ) -> list[ExternalAction]:
        if not self._path.exists():
            return []

        raw_events = self._load_events()
        actions = []

        for event in raw_events:
            ts = self._parse_timestamp(event)
            if ts is None or ts < start or ts > end:
                continue

            actions.append(ExternalAction(
                source="cloudtrail",
                actor=self._extract_actor(event),
                action=event.get("eventName", "unknown"),
                resource=self._extract_resource(event),
                timestamp=ts,
                event_id=event.get("eventID", ""),
                raw=event,
            ))

        return actions

    def _load_events(self) -> list[dict]:
        """Load events from JSON file (Records array or newline-delimited)."""
        text = self._path.read_text(encoding="utf-8").strip()
        if not text:
            return []

        # Try Records array format first
        try:
            data = json.loads(text)
            if isinstance(data, dict) and "Records" in data:
                return data["Records"]
            if isinstance(data, list):
                return data
        except json.JSONDecodeError:
            pass

        # Try newline-delimited JSON
        events = []
        for line in text.split("\n"):
            line = line.strip()
            if line:
                try:
                    events.append(json.loads(line))
                except json.JSONDecodeError:
                    continue
        return events

    def _parse_timestamp(self, event: dict) -> datetime | None:
        ts_str = event.get("eventTime")
        if not ts_str:
            return None
        try:
            return datetime.fromisoformat(ts_str.replace("Z", "+00:00"))
        except (ValueError, TypeError):
            return None

    def _extract_actor(self, event: dict) -> str:
        identity = event.get("userIdentity", {})
        # Try principal ID, then ARN, then username
        principal = identity.get("principalId", "")
        if ":" in principal:
            return principal.split(":")[-1]  # role session name
        arn = identity.get("arn", "")
        if arn:
            return arn.split("/")[-1]
        return identity.get("userName", "unknown")

    def _extract_resource(self, event: dict) -> str:
        resources = event.get("resources", [])
        if resources:
            return resources[0].get("ARN", resources[0].get("accountId", "unknown"))
        # Fall back to request parameters
        params = event.get("requestParameters", {})
        if isinstance(params, dict):
            for key in ("groupId", "roleName", "bucketName",
                       "instanceId", "dbInstanceIdentifier", "functionName"):
                if key in params:
                    return str(params[key])
        return event.get("eventSource", "unknown")


class AzureActivityLogSource(ExternalActivitySource):
    """
    Read Azure Activity Log events from a local JSON file.

    In production, this would consume from an Event Hub connected
    to the Azure Activity Log diagnostic setting.
    """

    def __init__(self, events_path: Path):
        self._path = events_path

    def source_name(self) -> str:
        return "azure_activity"

    def fetch_actions(
        self, start: datetime, end: datetime,
    ) -> list[ExternalAction]:
        if not self._path.exists():
            return []

        try:
            data = json.loads(self._path.read_text(encoding="utf-8"))
            events = data if isinstance(data, list) else data.get("value", [])
        except (json.JSONDecodeError, KeyError):
            return []

        actions = []
        for event in events:
            ts_str = event.get("eventTimestamp") or event.get("submissionTimestamp")
            if not ts_str:
                continue
            try:
                ts = datetime.fromisoformat(ts_str.replace("Z", "+00:00"))
            except (ValueError, TypeError):
                continue

            if ts < start or ts > end:
                continue

            caller = event.get("caller", "unknown")
            operation = event.get("operationName", {})
            if isinstance(operation, dict):
                operation = operation.get("value", "unknown")

            resource_id = event.get("resourceId", "unknown")

            actions.append(ExternalAction(
                source="azure_activity",
                actor=caller,
                action=operation,
                resource=resource_id,
                timestamp=ts,
                event_id=event.get("eventDataId", ""),
                raw=event,
            ))

        return actions
