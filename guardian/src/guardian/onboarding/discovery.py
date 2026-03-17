"""
Discovery Engine — Auto-detect actors, assets, and systems from event streams.

Ingests raw events (CloudTrail, Azure Activity Log, K8s audit, etc.),
extracts identity/asset/system information, and builds a configuration
recommendation for the org.

The engine is stateful — it accumulates observations over time and
produces increasingly accurate recommendations as it sees more data.
"""

from __future__ import annotations

import logging
import sqlite3
import threading
from collections import Counter, defaultdict
from datetime import datetime, timedelta, timezone

from guardian.onboarding.models import (
    DiscoveredActor,
    DiscoveredAsset,
    DiscoveredSystem,
    DiscoveryReport,
    OnboardingPhase,
    RiskPosture,
)

logger = logging.getLogger(__name__)

# Known adapter-to-system mappings
_ADAPTER_SYSTEMS = {
    "terraform": ["terraform-cloud", "terraform"],
    "kubernetes": ["k8s"],
    "intune": ["intune-device-management", "intune"],
    "entra_id": ["entra-id"],
    "jamf": ["jamf-pro", "jamf"],
    "github": ["github"],
    "aws_eventbridge": ["aws-iam", "aws-ec2", "aws-s3", "aws-rds", "aws-kms",
                         "aws-lambda", "aws-cloudtrail", "aws-guardduty"],
    "mcp": ["mcp-server", "mcp"],
    "a2a": ["a2a-agent-network", "a2a"],
}

# Actor name patterns → type inference
_ACTOR_TYPE_PATTERNS = {
    "ai_agent": ["ai-", "agent-", "mcp-", "a2a-", "openclaw-", "crewai-", "langchain-"],
    "automation": ["terraform-", "deploy-", "github-", "argocd-", "k8s-", "jenkins-",
                   "aws-role-", "svc-", "bot-", "ci-", "cd-", "pipeline-"],
}

# Privilege inference from action names
_ADMIN_ACTIONS = {
    "grant_admin_access", "modify_iam_role", "escalate_privileges",
    "create_service_account", "disable_endpoint_protection",
    "disable_firewall", "drop_database", "wipe_device",
}

_ELEVATED_ACTIONS = {
    "destroy_infrastructure", "terminate_instances", "delete_resource",
    "modify_security_policy", "modify_firewall_rule", "export_data",
    "retire_device", "delete_device",
}


class DiscoveryEngine:
    """
    Accumulates observations from event streams and produces
    a discovery report with recommended configuration.

    Thread-safe. Can ingest events from multiple adapters concurrently.
    """

    def __init__(self, db_path: str = ":memory:"):
        self._conn = sqlite3.connect(db_path, check_same_thread=False)
        self._conn.row_factory = sqlite3.Row
        self._conn.execute("PRAGMA journal_mode=WAL")
        self._create_tables()
        self._lock = threading.Lock()
        self._observation_start: datetime | None = None
        self._phase = OnboardingPhase.not_started

    def _create_tables(self) -> None:
        self._conn.executescript("""
            CREATE TABLE IF NOT EXISTS discovered_events (
                id              INTEGER PRIMARY KEY AUTOINCREMENT,
                actor_name      TEXT NOT NULL,
                actor_type      TEXT NOT NULL DEFAULT 'automation',
                action          TEXT NOT NULL,
                target_system   TEXT NOT NULL,
                target_asset    TEXT NOT NULL,
                privilege_level TEXT NOT NULL DEFAULT 'standard',
                sensitivity     TEXT NOT NULL DEFAULT 'internal',
                source          TEXT NOT NULL DEFAULT '',
                timestamp       TEXT NOT NULL,
                ingested_at     TEXT NOT NULL DEFAULT (datetime('now'))
            );
            CREATE INDEX IF NOT EXISTS idx_disc_actor ON discovered_events(actor_name);
            CREATE INDEX IF NOT EXISTS idx_disc_system ON discovered_events(target_system);
            CREATE INDEX IF NOT EXISTS idx_disc_asset ON discovered_events(target_asset);
        """)

    def ingest_event(
        self,
        actor_name: str,
        actor_type: str = "",
        action: str = "",
        target_system: str = "",
        target_asset: str = "",
        privilege_level: str = "standard",
        sensitivity: str = "internal",
        source: str = "",
        timestamp: str = "",
    ) -> None:
        """Ingest a single event into the discovery engine."""
        if not self._observation_start:
            self._observation_start = datetime.now(timezone.utc)
            self._phase = OnboardingPhase.discovering

        # Auto-detect actor type from name patterns
        if not actor_type:
            actor_type = self._infer_actor_type(actor_name)

        ts = timestamp or datetime.now(timezone.utc).isoformat()

        with self._lock:
            self._conn.execute("""
                INSERT INTO discovered_events
                    (actor_name, actor_type, action, target_system, target_asset,
                     privilege_level, sensitivity, source, timestamp)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
            """, (actor_name, actor_type, action, target_system, target_asset,
                  privilege_level, sensitivity, source, ts))
            self._conn.commit()

    def ingest_batch(self, events: list[dict]) -> int:
        """Ingest a batch of events. Returns count ingested."""
        count = 0
        for event in events:
            try:
                self.ingest_event(**event)
                count += 1
            except Exception as exc:
                logger.debug("Discovery ingest skip: %s", exc)
        return count

    def generate_report(self) -> DiscoveryReport:
        """Generate a discovery report from accumulated observations."""
        with self._lock:
            total = self._conn.execute("SELECT COUNT(*) FROM discovered_events").fetchone()[0]

            if total == 0:
                return DiscoveryReport(phase=self._phase)

            # Observation window
            hours = 0.0
            if self._observation_start:
                hours = (datetime.now(timezone.utc) - self._observation_start).total_seconds() / 3600

            actors = self._discover_actors()
            assets = self._discover_assets()
            systems = self._discover_systems()
            risk_posture = self._recommend_risk_posture(actors, assets)
            adapters = self._recommend_adapters(systems)

            self._phase = OnboardingPhase.ready

            return DiscoveryReport(
                phase=self._phase,
                observation_hours=round(hours, 1),
                total_events_ingested=total,
                actors=actors,
                assets=assets,
                systems=systems,
                recommended_risk_posture=risk_posture,
                recommended_adapters=adapters,
            )

    def get_status(self) -> dict:
        """Quick status check without full report generation."""
        with self._lock:
            total = self._conn.execute("SELECT COUNT(*) FROM discovered_events").fetchone()[0]
            actors = self._conn.execute("SELECT COUNT(DISTINCT actor_name) FROM discovered_events").fetchone()[0]
            assets = self._conn.execute("SELECT COUNT(DISTINCT target_asset) FROM discovered_events").fetchone()[0]
            systems = self._conn.execute("SELECT COUNT(DISTINCT target_system) FROM discovered_events").fetchone()[0]

        hours = 0.0
        if self._observation_start:
            hours = (datetime.now(timezone.utc) - self._observation_start).total_seconds() / 3600

        return {
            "phase": self._phase.value,
            "cloud_connected": total > 0,
            "events_ingested": total,
            "actors_discovered": actors,
            "assets_discovered": assets,
            "systems_discovered": systems,
            "observation_started": self._observation_start.isoformat() if self._observation_start else "",
            "observation_hours": round(hours, 1),
            "config_generated": self._phase in (OnboardingPhase.ready, OnboardingPhase.active),
            "config_applied": self._phase == OnboardingPhase.active,
        }

    def apply_config(self, pipeline) -> dict:
        """
        Apply discovered configuration to the live Guardian pipeline.

        Registers discovered actors, updates asset catalog metadata,
        and transitions to active governance.
        """
        report = self.generate_report()

        actors_registered = 0
        for actor in report.actors:
            try:
                pipeline.attestor.registry._actors[actor.name] = {
                    "name": actor.name,
                    "type": actor.actor_type,
                    "max_privilege_level": actor.recommended_max_privilege,
                    "status": "active",
                }
                actors_registered += 1
            except Exception:
                pass

        self._phase = OnboardingPhase.active

        return {
            "phase": self._phase.value,
            "actors_registered": actors_registered,
            "systems_discovered": len(report.systems),
            "assets_discovered": len(report.assets),
            "recommended_risk_posture": report.recommended_risk_posture.value,
            "recommended_adapters": report.recommended_adapters,
        }

    # ── Internal discovery methods ───────────────────────────────────

    def _discover_actors(self) -> list[DiscoveredActor]:
        rows = self._conn.execute("""
            SELECT actor_name, actor_type,
                   COUNT(*) as event_count,
                   MIN(timestamp) as first_seen,
                   MAX(timestamp) as last_seen,
                   GROUP_CONCAT(DISTINCT action) as actions,
                   GROUP_CONCAT(DISTINCT target_system) as systems,
                   GROUP_CONCAT(DISTINCT source) as sources
            FROM discovered_events
            GROUP BY actor_name
            ORDER BY event_count DESC
        """).fetchall()

        actors = []
        for r in rows:
            actions = (r["actions"] or "").split(",")
            max_priv = "standard"
            if any(a in _ADMIN_ACTIONS for a in actions):
                max_priv = "admin"
            elif any(a in _ELEVATED_ACTIONS for a in actions):
                max_priv = "elevated"

            actors.append(DiscoveredActor(
                name=r["actor_name"],
                actor_type=r["actor_type"],
                source=(r["sources"] or "").split(",")[0],
                event_count=r["event_count"],
                first_seen=r["first_seen"],
                last_seen=r["last_seen"],
                actions_observed=actions[:20],
                systems_observed=(r["systems"] or "").split(",")[:10],
                max_privilege_observed=max_priv,
                recommended_max_privilege=max_priv,
            ))

        return actors

    def _discover_assets(self) -> list[DiscoveredAsset]:
        rows = self._conn.execute("""
            SELECT target_asset, target_system,
                   COUNT(*) as event_count,
                   COUNT(DISTINCT actor_name) as actor_count,
                   SUM(CASE WHEN privilege_level IN ('admin', 'elevated') THEN 1 ELSE 0 END) as priv_count
            FROM discovered_events
            GROUP BY target_asset
            ORDER BY event_count DESC
            LIMIT 200
        """).fetchall()

        assets = []
        for r in rows:
            # Infer criticality from access patterns
            criticality = "medium"
            sensitivity = "internal"
            if r["priv_count"] > 5 or r["actor_count"] > 10:
                criticality = "critical"
                sensitivity = "restricted"
            elif r["priv_count"] > 2 or r["actor_count"] > 5:
                criticality = "high"
                sensitivity = "high"

            assets.append(DiscoveredAsset(
                asset_id=r["target_asset"],
                name=r["target_asset"],
                system=r["target_system"],
                event_count=r["event_count"],
                actor_count=r["actor_count"],
                privileged_access_count=r["priv_count"],
                recommended_criticality=criticality,
                recommended_sensitivity=sensitivity,
            ))

        return assets

    def _discover_systems(self) -> list[DiscoveredSystem]:
        rows = self._conn.execute("""
            SELECT target_system,
                   COUNT(*) as event_count,
                   COUNT(DISTINCT actor_name) as actor_count
            FROM discovered_events
            GROUP BY target_system
            ORDER BY event_count DESC
        """).fetchall()

        systems = []
        for r in rows:
            sys_id = r["target_system"]
            adapter = ""
            has_adapter = False

            for adapter_name, system_patterns in _ADAPTER_SYSTEMS.items():
                if any(p in sys_id.lower() for p in system_patterns):
                    adapter = adapter_name
                    has_adapter = True
                    break

            systems.append(DiscoveredSystem(
                system_id=sys_id,
                name=sys_id,
                event_count=r["event_count"],
                actor_count=r["actor_count"],
                adapter_available=has_adapter,
                recommended_adapter=adapter,
            ))

        return systems

    def _recommend_risk_posture(
        self, actors: list[DiscoveredActor], assets: list[DiscoveredAsset],
    ) -> RiskPosture:
        """Recommend risk posture based on what we observed."""
        admin_actors = sum(1 for a in actors if a.max_privilege_observed == "admin")
        critical_assets = sum(1 for a in assets if a.recommended_criticality == "critical")

        if critical_assets > 10 or admin_actors > 5:
            return RiskPosture.conservative
        if critical_assets > 3 or admin_actors > 2:
            return RiskPosture.moderate
        return RiskPosture.permissive

    def _recommend_adapters(self, systems: list[DiscoveredSystem]) -> list[str]:
        """Recommend which adapters to enable based on discovered systems."""
        adapters = set()
        for s in systems:
            if s.recommended_adapter:
                adapters.add(s.recommended_adapter)
        return sorted(adapters)

    @staticmethod
    def _infer_actor_type(name: str) -> str:
        lower = name.lower()
        for actor_type, patterns in _ACTOR_TYPE_PATTERNS.items():
            if any(lower.startswith(p) for p in patterns):
                return actor_type
        return "human"
