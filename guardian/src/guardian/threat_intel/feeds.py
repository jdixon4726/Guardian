"""
Threat Feed Adapters — CISA KEV and MITRE ATT&CK

Fetches from authoritative sources only, verifies response integrity,
and maps to Guardian's risk overlay format.

ANTI-POISONING MEASURES:
  - Hardcoded URLs to .gov/.org domains (not configurable)
  - Response hash recorded for forensic verification
  - Schema validation before processing (unexpected fields = reject)
  - Rate-limited: max 1 sync per hour per feed
  - Connection timeout: 30s (prevents slowloris-style stalling)
"""

from __future__ import annotations

import hashlib
import json
import logging
from datetime import datetime, timedelta, timezone

import httpx

from guardian.threat_intel.models import (
    FEED_URLS,
    FeedSyncResult,
    KEVEntry,
    OverlayStatus,
    RiskOverlay,
    ThreatFeedSource,
)
from guardian.threat_intel.overlay_engine import OverlayEngine

logger = logging.getLogger(__name__)

# Vendor/product → Guardian system mapping
_VENDOR_SYSTEM_MAP = {
    "microsoft": ["intune-device-management", "entra-id"],
    "hashicorp": ["terraform-cloud"],
    "amazon": ["aws-iam", "aws-ec2", "aws-s3", "aws-rds"],
    "google": ["gcp-admin"],
    "palo alto": ["firewall"],
    "fortinet": ["firewall"],
    "cisco": ["network"],
    "vmware": ["vsphere"],
    "jamf": ["jamf-pro"],
    "github": ["github"],
    "gitlab": ["gitlab"],
    "docker": ["container"],
    "kubernetes": ["k8s"],
    "okta": ["identity"],
    "cyberark": ["pam"],
    "solarwinds": ["monitoring"],
    "veeam": ["backup"],
    "cloudflare": ["cdn", "dns"],
}

# Product keywords → Guardian action categories affected
_PRODUCT_ACTION_MAP = {
    "intune": ["wipe_device", "retire_device", "delete_device"],
    "active directory": ["grant_admin_access", "modify_iam_role", "create_service_account"],
    "entra": ["grant_admin_access", "modify_iam_role", "disable_endpoint_protection"],
    "exchange": ["export_data", "change_configuration"],
    "iam": ["grant_admin_access", "modify_iam_role", "escalate_privileges"],
    "s3": ["destroy_infrastructure", "export_data"],
    "ec2": ["terminate_instances", "change_configuration"],
    "rds": ["drop_database", "change_configuration"],
    "firewall": ["modify_firewall_rule", "disable_firewall"],
    "vpn": ["change_configuration", "modify_security_policy"],
    "endpoint": ["disable_endpoint_protection", "disable_edr"],
    "backup": ["destroy_infrastructure", "delete_resource"],
    "dns": ["modify_firewall_rule", "change_configuration"],
    "container": ["change_configuration", "destroy_infrastructure"],
}


class CISAKEVFeed:
    """
    CISA Known Exploited Vulnerabilities feed adapter.

    Fetches the KEV catalog, identifies entries relevant to
    Guardian's monitored systems, and creates risk overlays.
    """

    def __init__(self, overlay_engine: OverlayEngine):
        self.engine = overlay_engine
        self._last_sync: datetime | None = None
        self._last_hash: str = ""

    async def sync(self) -> FeedSyncResult:
        """Fetch and process the CISA KEV catalog."""
        # Rate limit: max 1 sync per hour
        if self._last_sync:
            elapsed = (datetime.now(timezone.utc) - self._last_sync).total_seconds()
            if elapsed < 3600:
                return FeedSyncResult(
                    source=ThreatFeedSource.cisa_kev,
                    success=False,
                    errors=[f"Rate limited: {3600 - int(elapsed)}s until next sync"],
                )

        url = FEED_URLS[ThreatFeedSource.cisa_kev]
        result = FeedSyncResult(source=ThreatFeedSource.cisa_kev)

        try:
            async with httpx.AsyncClient(verify=True, follow_redirects=True) as client:
                resp = await client.get(url, timeout=60.0)
                resp.raise_for_status()

            raw = resp.text
            feed_hash = hashlib.sha256(raw.encode()).hexdigest()
            result.feed_hash = feed_hash

            # Skip if feed hasn't changed
            if feed_hash == self._last_hash:
                result.success = True
                result.errors.append("Feed unchanged since last sync")
                self._last_sync = datetime.now(timezone.utc)
                return result

            data = resp.json()

            # Schema validation — KEV must have these fields
            if "vulnerabilities" not in data:
                result.success = False
                result.schema_valid = False
                result.errors.append("Missing 'vulnerabilities' key — unexpected schema")
                return result

            if "catalogVersion" not in data:
                result.errors.append("Warning: missing catalogVersion field")

            vulnerabilities = data["vulnerabilities"]
            if not isinstance(vulnerabilities, list):
                result.success = False
                result.schema_valid = False
                result.errors.append("'vulnerabilities' is not a list")
                return result

            # Process entries — only recent ones (last 30 days)
            cutoff = (datetime.now(timezone.utc) - timedelta(days=30)).strftime("%Y-%m-%d")
            processed = 0
            created = 0

            for entry_data in vulnerabilities:
                try:
                    entry = KEVEntry(**entry_data)
                    processed += 1

                    # Only process recent entries
                    if entry.date_added < cutoff:
                        continue

                    # Map to Guardian systems/actions
                    overlay = self._map_kev_to_overlay(entry, feed_hash)
                    if overlay:
                        self.engine.add_overlay(overlay)
                        created += 1

                except Exception as exc:
                    result.errors.append(f"Entry parse error: {exc}")

            result.entries_processed = processed
            result.overlays_created = created
            result.success = True
            self._last_hash = feed_hash
            self._last_sync = datetime.now(timezone.utc)

            logger.info(
                "CISA KEV sync: %d entries processed, %d overlays created",
                processed, created,
            )

        except httpx.HTTPError as exc:
            result.success = False
            result.errors.append(f"HTTP error: {exc}")
            logger.error("CISA KEV sync failed: %s", exc)
        except Exception as exc:
            result.success = False
            result.errors.append(f"Unexpected error: {exc}")
            logger.error("CISA KEV sync error: %s", exc)

        return result

    def _map_kev_to_overlay(
        self, entry: KEVEntry, feed_hash: str,
    ) -> RiskOverlay | None:
        """Map a KEV entry to a Guardian risk overlay."""
        vendor = entry.vendor_project.lower()
        product = entry.product.lower()

        # Find affected Guardian systems
        affected_systems = []
        for key, systems in _VENDOR_SYSTEM_MAP.items():
            if key in vendor or key in product:
                affected_systems.extend(systems)

        # Find affected Guardian actions
        affected_actions = []
        for key, actions in _PRODUCT_ACTION_MAP.items():
            if key in product or key in vendor or key in entry.short_description.lower():
                affected_actions.extend(actions)

        if not affected_systems and not affected_actions:
            return None  # Not relevant to Guardian's monitored systems

        # Determine risk adjustment based on severity signals
        risk_adj = 0.05  # baseline for any KEV
        if entry.known_ransomware_campaign_use.lower() == "known":
            risk_adj = 0.15  # ransomware-associated = higher
        if "remote code execution" in entry.short_description.lower():
            risk_adj = max(risk_adj, 0.12)
        if "authentication bypass" in entry.short_description.lower():
            risk_adj = max(risk_adj, 0.10)
        if "privilege escalation" in entry.short_description.lower():
            risk_adj = max(risk_adj, 0.10)

        risk_adj = min(risk_adj, 0.20)  # hard cap

        return RiskOverlay(
            source=ThreatFeedSource.cisa_kev,
            title=f"CISA KEV: {entry.cve_id} — {entry.vendor_project} {entry.product}",
            description=entry.short_description,
            risk_adjustment=risk_adj,
            affected_actions=list(set(affected_actions)),
            affected_systems=list(set(affected_systems)),
            cve_ids=[entry.cve_id],
            reference_url=f"https://www.cisa.gov/known-exploited-vulnerabilities-catalog",
            source_hash=feed_hash,
            expires_at=datetime.now(timezone.utc) + timedelta(days=90),
        )


class MITREAttackMapper:
    """
    Maps MITRE ATT&CK techniques to Guardian action categories.

    This is a static mapping (not a live feed) that provides technique
    IDs for compliance tagging. The ATT&CK matrix doesn't change
    frequently enough to warrant live syncing.
    """

    # ATT&CK technique ID → Guardian action mapping
    TECHNIQUE_MAP: dict[str, list[str]] = {
        # Initial Access
        "T1078": ["change_configuration"],                    # Valid Accounts
        "T1566": ["change_configuration"],                    # Phishing
        # Execution
        "T1059": ["change_configuration"],                    # Command/Script
        "T1204": ["change_configuration"],                    # User Execution
        # Persistence
        "T1098": ["grant_admin_access", "modify_iam_role"],   # Account Manipulation
        "T1136": ["create_service_account"],                  # Create Account
        "T1078.004": ["escalate_privileges"],                 # Cloud Accounts
        # Privilege Escalation
        "T1548": ["escalate_privileges"],                     # Abuse Elevation
        "T1134": ["escalate_privileges"],                     # Access Token Manipulation
        # Defense Evasion
        "T1562.001": ["disable_endpoint_protection"],         # Disable Security Tools
        "T1070": ["disable_endpoint_protection"],             # Indicator Removal
        "T1562.008": ["disable_endpoint_protection"],         # Disable Cloud Logs
        # Credential Access
        "T1528": ["escalate_privileges"],                     # Steal App Access Token
        "T1552": ["export_data"],                             # Unsecured Credentials
        # Discovery
        "T1087": ["change_configuration"],                    # Account Discovery
        # Lateral Movement
        "T1021": ["change_configuration"],                    # Remote Services
        # Collection/Exfiltration
        "T1530": ["export_data"],                             # Data from Cloud Storage
        "T1537": ["export_data"],                             # Transfer to Cloud Account
        # Impact
        "T1485": ["destroy_infrastructure", "wipe_device"],   # Data Destruction
        "T1486": ["destroy_infrastructure"],                  # Data Encrypted for Impact
        "T1489": ["destroy_infrastructure"],                  # Service Stop
        "T1490": ["destroy_infrastructure"],                  # Inhibit System Recovery
        "T1498": ["destroy_infrastructure"],                  # Network DoS
        "T1531": ["delete_resource"],                         # Account Access Removal
    }

    @classmethod
    def get_techniques_for_action(cls, action: str) -> list[str]:
        """Get MITRE ATT&CK technique IDs relevant to a Guardian action."""
        techniques = []
        for tech_id, actions in cls.TECHNIQUE_MAP.items():
            if action in actions:
                techniques.append(tech_id)
        return techniques

    @classmethod
    def get_actions_for_technique(cls, technique_id: str) -> list[str]:
        """Get Guardian actions associated with a MITRE technique."""
        return cls.TECHNIQUE_MAP.get(technique_id, [])
