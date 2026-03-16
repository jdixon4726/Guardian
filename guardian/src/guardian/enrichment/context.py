"""
Context Enrichment

Assembles the full EnrichedContext object from three data sources:
  - Asset Catalog (criticality, sensitivity, owner)
  - Maintenance Window Store (is the current time within a window?)
  - Actor History Store (recent action counts, prior blocks)

All three sources are queried before evaluation proceeds.
The enriched context is the input to all downstream pipeline stages.
"""

from __future__ import annotations

import logging
from dataclasses import dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from typing import Optional

import yaml

from guardian.attestation.attestor import AttestationResult
from guardian.models.action_request import ActionRequest, SensitivityLevel

logger = logging.getLogger(__name__)


@dataclass
class AssetContext:
    asset_id: str
    criticality: str = "medium"   # low | medium | high | critical
    sensitivity: str = "internal"
    owner: Optional[str] = None
    tags: list[str] = field(default_factory=list)
    found: bool = False


@dataclass
class MaintenanceWindowContext:
    system: str
    in_window: bool = False
    window_id: Optional[str] = None
    window_description: Optional[str] = None


@dataclass
class ActorHistoryContext:
    actor_name: str
    total_actions: int = 0
    total_blocks: int = 0
    total_reviews: int = 0
    total_allows: int = 0
    prior_privilege_escalations: int = 0
    history_days: int = 0


@dataclass
class EnrichedContext:
    """Full context assembled for policy and scoring evaluation."""
    request: ActionRequest
    attestation: AttestationResult
    asset: AssetContext
    maintenance_window: MaintenanceWindowContext
    actor_history: ActorHistoryContext
    enriched_at: datetime = field(default_factory=lambda: datetime.now(timezone.utc))

    def to_policy_context(self) -> dict:
        """Flatten to a dict for policy rule condition matching."""
        return {
            "actor_name": self.request.actor_name,
            "actor_type": self.request.actor_type.value,
            "actor_status": "active",  # Attested — terminated would have been blocked already
            "requested_action": self.request.requested_action,
            "target_system": self.request.target_system,
            "target_asset": self.request.target_asset,
            "privilege_level": self.request.privilege_level.value,
            "sensitivity_level": self.request.sensitivity_level.value,
            "asset_criticality": self.asset.criticality,
            "in_maintenance_window": self.maintenance_window.in_window,
        }


class AssetCatalog:
    def __init__(self, catalog_path: Path):
        self._assets: dict[str, dict] = {}
        data = yaml.safe_load(catalog_path.read_text())
        for asset in data.get("assets", []):
            self._assets[asset["id"]] = asset
        logger.info("Asset catalog loaded: %d assets", len(self._assets))

    def get(self, asset_id: str) -> AssetContext:
        record = self._assets.get(asset_id)
        if record is None:
            return AssetContext(asset_id=asset_id, found=False)
        return AssetContext(
            asset_id=asset_id,
            criticality=record.get("criticality", "medium"),
            sensitivity=record.get("sensitivity", "internal"),
            owner=record.get("owner"),
            tags=record.get("tags", []),
            found=True,
        )


class MaintenanceWindowStore:
    def __init__(self, windows_path: Path):
        self._windows: list[dict] = []
        data = yaml.safe_load(windows_path.read_text())
        self._windows = data.get("windows", [])
        logger.info("Maintenance window store loaded: %d windows", len(self._windows))

    def check(self, system: str, at: datetime) -> MaintenanceWindowContext:
        for window in self._windows:
            if window["system"] != system:
                continue
            if window.get("schedule") is None:
                return MaintenanceWindowContext(system=system, in_window=False,
                                                window_id=window["id"],
                                                window_description=window.get("description"))
            if self._is_in_window(window, at):
                return MaintenanceWindowContext(
                    system=system,
                    in_window=True,
                    window_id=window["id"],
                    window_description=window.get("description"),
                )
        return MaintenanceWindowContext(system=system, in_window=False)

    def _is_in_window(self, window: dict, at: datetime) -> bool:
        """
        Check if `at` falls within the maintenance window.
        Parses cron expression: "minute hour day_of_month month day_of_week"
        """
        try:
            schedule = window["schedule"]
            duration_hours = window.get("duration_hours", 0)
            parts = schedule.split()
            if len(parts) != 5:
                return False

            _, hour, _, _, day_of_week = parts

            # Check day of week (0=Sunday, 6=Saturday in cron; Python: 0=Monday, 6=Sunday)
            if day_of_week != "*":
                cron_dow = int(day_of_week)
                # Convert cron DOW (0=Sun, 6=Sat) to Python isoweekday (1=Mon, 7=Sun)
                python_dow = 7 if cron_dow == 0 else cron_dow
                if at.isoweekday() != python_dow:
                    return False

            # Check hour range
            if hour != "*":
                window_start = int(hour)
                window_end = window_start + duration_hours
                if not (window_start <= at.hour < window_end):
                    return False

            return True
        except (ValueError, IndexError):
            return False


class ContextEnricher:
    """Assembles EnrichedContext from all available data sources."""

    def __init__(self, asset_catalog: AssetCatalog,
                 window_store: MaintenanceWindowStore):
        self.asset_catalog = asset_catalog
        self.window_store = window_store

    def enrich(self, request: ActionRequest,
               attestation: AttestationResult) -> EnrichedContext:
        asset = self.asset_catalog.get(request.target_asset)
        window = self.window_store.check(request.target_system, request.timestamp)

        # Actor history is loaded from the store if available; stub for Phase 1
        actor_history = ActorHistoryContext(actor_name=request.actor_name)

        logger.debug(
            "Context enriched: asset=%s criticality=%s in_window=%s",
            asset.asset_id, asset.criticality, window.in_window,
        )
        return EnrichedContext(
            request=request,
            attestation=attestation,
            asset=asset,
            maintenance_window=window,
            actor_history=actor_history,
        )
