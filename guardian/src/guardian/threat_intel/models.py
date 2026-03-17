"""
Threat Intelligence data models.

Every model enforces integrity constraints that prevent
feed poisoning from affecting Guardian's decision path.
"""

from __future__ import annotations

from datetime import datetime, timezone
from enum import Enum
from uuid import uuid4

from pydantic import BaseModel, Field, field_validator


class ThreatFeedSource(str, Enum):
    """Authoritative sources only — no third-party aggregators."""
    cisa_kev = "cisa_kev"           # CISA Known Exploited Vulnerabilities
    mitre_attack = "mitre_attack"   # MITRE ATT&CK framework
    nvd = "nvd"                     # NIST National Vulnerability Database
    manual = "manual"               # Human-entered by security team


# Trusted feed URLs — hardcoded, not configurable.
# If an attacker can modify these, they already own the Guardian process.
FEED_URLS = {
    ThreatFeedSource.cisa_kev: "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json",
    ThreatFeedSource.mitre_attack: "https://raw.githubusercontent.com/mitre/cti/master/enterprise-attack/enterprise-attack.json",
}


class OverlayStatus(str, Enum):
    """Lifecycle states for risk overlays."""
    pending = "pending"         # Created from feed, awaiting review
    active = "active"           # Approved and affecting scoring
    expired = "expired"         # Past expiration date
    rejected = "rejected"       # Human reviewed and rejected
    superseded = "superseded"   # Replaced by a newer overlay


class RiskOverlay(BaseModel):
    """
    A temporary risk adjustment driven by threat intelligence.

    SECURITY CONSTRAINTS:
      - risk_adjustment is capped at [0.0, 0.20] — feeds can only
        ELEVATE risk, never reduce it, and by at most 0.20.
      - source must be an authoritative ThreatFeedSource.
      - expires_at is mandatory — overlays don't live forever.
      - source_hash records the SHA-256 of the feed data that
        produced this overlay, for forensic verification.
    """
    overlay_id: str = Field(default_factory=lambda: str(uuid4()))
    source: ThreatFeedSource
    status: OverlayStatus = OverlayStatus.pending

    # What this overlay affects
    affected_actions: list[str] = Field(default_factory=list)
    affected_systems: list[str] = Field(default_factory=list)
    affected_actors: list[str] = Field(default_factory=list)

    # Risk adjustment (ONLY positive — feeds cannot lower risk)
    risk_adjustment: float = Field(ge=0.0, le=0.20)

    # Context
    title: str                          # human-readable title
    description: str = ""               # what the threat is
    cve_ids: list[str] = Field(default_factory=list)
    mitre_techniques: list[str] = Field(default_factory=list)
    reference_url: str = ""             # link to advisory

    # Integrity
    source_hash: str = ""               # SHA-256 of feed data that produced this
    source_fetched_at: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))

    # Lifecycle
    created_at: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))
    expires_at: datetime                # mandatory expiration
    activated_at: datetime | None = None
    activated_by: str = ""              # who approved it
    rejected_at: datetime | None = None
    rejected_by: str = ""
    rejection_reason: str = ""

    @field_validator("risk_adjustment")
    @classmethod
    def risk_cannot_be_negative(cls, v: float) -> float:
        """Feeds can ONLY elevate risk. This is a security invariant."""
        if v < 0:
            raise ValueError("Risk overlays cannot reduce risk (anti-poisoning constraint)")
        return min(v, 0.20)  # Hard cap even if validator passes

    @field_validator("source")
    @classmethod
    def must_be_authoritative(cls, v: ThreatFeedSource) -> ThreatFeedSource:
        """Only authoritative sources can create overlays."""
        if v not in ThreatFeedSource:
            raise ValueError(f"Unknown feed source: {v}")
        return v


class FeedSyncResult(BaseModel):
    """Result of syncing a threat feed."""
    source: ThreatFeedSource
    success: bool
    fetched_at: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))
    entries_processed: int = 0
    overlays_created: int = 0
    overlays_updated: int = 0
    errors: list[str] = Field(default_factory=list)
    feed_hash: str = ""                 # SHA-256 of the raw feed response
    schema_valid: bool = True


class KEVEntry(BaseModel):
    """A single CISA KEV entry."""
    cve_id: str = Field(alias="cveID", default="")
    vendor_project: str = Field(alias="vendorProject", default="")
    product: str = ""
    vulnerability_name: str = Field(alias="vulnerabilityName", default="")
    date_added: str = Field(alias="dateAdded", default="")
    short_description: str = Field(alias="shortDescription", default="")
    required_action: str = Field(alias="requiredAction", default="")
    due_date: str = Field(alias="dueDate", default="")
    known_ransomware_campaign_use: str = Field(alias="knownRansomwareCampaignUse", default="")

    model_config = {"populate_by_name": True}
