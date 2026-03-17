"""
Guardian Threat Intelligence — Adaptive Risk from Authoritative Sources

Consumes threat feeds (CISA KEV, MITRE ATT&CK) and produces risk overlays
that the scoring engine uses to adjust risk based on current threat landscape.

SECURITY DESIGN PRINCIPLES (anti-poisoning):

  1. AUTHORITATIVE SOURCES ONLY — CISA (.gov), MITRE (.org), NVD (.gov).
     No third-party aggregators, no community feeds, no social media.

  2. INTEGRITY VERIFICATION — TLS certificate pinning for feed URLs.
     Feed responses are hash-verified against known-good schemas.
     Unexpected schema changes trigger alerts, not silent acceptance.

  3. OVERLAYS, NOT OVERWRITES — Feed data produces advisory risk overlays
     that sit alongside static policy. Overlays cannot lower risk below
     the base score (feeds can only ELEVATE risk, never REDUCE it).
     This prevents an attacker from using feed manipulation to blind Guardian.

  4. BOUNDED IMPACT — A single feed update can raise risk by at most 0.20.
     No single external input can cause a block on its own. The behavioral
     engine, policy rules, and static scoring still dominate.

  5. HUMAN REVIEW GATE — Overlays start as "pending" and become "active"
     only after human confirmation OR after a configurable auto-promote
     delay (default: 24 hours). Critical overlays require explicit approval.

  6. FULL AUDIT TRAIL — Every overlay creation, activation, expiration,
     and rejection is logged with source, timestamp, and hash of the
     source data that produced it.

  7. NO LLMs — Feed data is mapped to Guardian's taxonomy via deterministic
     keyword/pattern matching. No natural language interpretation.
"""

from guardian.threat_intel.models import (
    ThreatFeedSource,
    RiskOverlay,
    OverlayStatus,
    FeedSyncResult,
)
from guardian.threat_intel.overlay_engine import OverlayEngine

__all__ = [
    "ThreatFeedSource",
    "RiskOverlay",
    "OverlayStatus",
    "FeedSyncResult",
    "OverlayEngine",
]
