"""
Unit tests for Threat Intelligence — overlay engine, feed mapping,
and anti-poisoning defenses.
"""

from __future__ import annotations

from datetime import datetime, timedelta, timezone

import pytest
from pydantic import ValidationError

from guardian.threat_intel.models import (
    KEVEntry,
    OverlayStatus,
    RiskOverlay,
    ThreatFeedSource,
)
from guardian.threat_intel.overlay_engine import MAX_COMBINED_OVERLAY, OverlayEngine
from guardian.threat_intel.feeds import CISAKEVFeed, MITREAttackMapper


def _now():
    return datetime.now(timezone.utc)


def _make_overlay(
    risk_adj: float = 0.10,
    actions: list[str] | None = None,
    systems: list[str] | None = None,
    status: OverlayStatus = OverlayStatus.active,
) -> RiskOverlay:
    return RiskOverlay(
        source=ThreatFeedSource.cisa_kev,
        status=status,
        title="Test overlay",
        risk_adjustment=risk_adj,
        affected_actions=actions or [],
        affected_systems=systems or [],
        expires_at=_now() + timedelta(days=30),
    )


# ── Anti-Poisoning Tests ────────────────────────────────────────────────────

class TestAntiPoisoning:
    """
    Tests that verify Guardian cannot be tricked by malicious feed data.
    These are the most critical tests in this module.
    """

    def test_negative_risk_adjustment_rejected(self):
        """Feeds CANNOT reduce risk. This is the core anti-poisoning invariant."""
        with pytest.raises(ValidationError):
            RiskOverlay(
                source=ThreatFeedSource.cisa_kev,
                title="Evil overlay that lowers risk",
                risk_adjustment=-0.10,  # MUST be rejected
                expires_at=_now() + timedelta(days=30),
            )

    def test_risk_adjustment_capped_at_020(self):
        """No single overlay can raise risk by more than 0.20."""
        overlay = RiskOverlay(
            source=ThreatFeedSource.cisa_kev,
            title="Massive risk overlay",
            risk_adjustment=0.20,  # at cap
            expires_at=_now() + timedelta(days=30),
        )
        assert overlay.risk_adjustment == 0.20

    def test_risk_adjustment_above_020_clamped(self):
        """Values above 0.20 are clamped by the validator."""
        with pytest.raises(ValidationError):
            RiskOverlay(
                source=ThreatFeedSource.cisa_kev,
                title="Overcap overlay",
                risk_adjustment=0.50,  # above hard limit
                expires_at=_now() + timedelta(days=30),
            )

    def test_combined_overlays_capped(self):
        """Multiple overlays combined cannot exceed MAX_COMBINED_OVERLAY."""
        engine = OverlayEngine()
        # Add 5 overlays each at 0.15 = 0.75 total uncapped
        for i in range(5):
            overlay = _make_overlay(risk_adj=0.15)
            engine.add_overlay(overlay)
            engine.activate(overlay.overlay_id)

        adj, titles = engine.get_adjustment()
        assert adj <= MAX_COMBINED_OVERLAY  # 0.30 cap
        assert adj == MAX_COMBINED_OVERLAY

    def test_pending_overlays_do_not_affect_scoring(self):
        """Overlays must be activated before they affect risk."""
        engine = OverlayEngine()
        overlay = _make_overlay(risk_adj=0.15, status=OverlayStatus.pending)
        engine.add_overlay(overlay)

        adj, titles = engine.get_adjustment()
        assert adj == 0.0
        assert len(titles) == 0

    def test_expired_overlays_do_not_affect_scoring(self):
        """Expired overlays must not affect risk."""
        engine = OverlayEngine()
        overlay = RiskOverlay(
            source=ThreatFeedSource.cisa_kev,
            status=OverlayStatus.active,
            title="Expired overlay",
            risk_adjustment=0.15,
            expires_at=_now() - timedelta(days=1),  # already expired
        )
        engine.add_overlay(overlay)
        engine.expire_stale()

        adj, _ = engine.get_adjustment()
        assert adj == 0.0

    def test_rejected_overlays_do_not_affect_scoring(self):
        """Rejected overlays never affect risk."""
        engine = OverlayEngine()
        overlay = _make_overlay(status=OverlayStatus.pending)
        engine.add_overlay(overlay)
        engine.reject(overlay.overlay_id, "security-admin", "Looks suspicious")

        adj, _ = engine.get_adjustment()
        assert adj == 0.0


# ── Overlay Engine Tests ─────────────────────────────────────────────────────

class TestOverlayEngine:
    @pytest.fixture
    def engine(self):
        return OverlayEngine()

    def test_add_and_list(self, engine):
        overlay = _make_overlay(status=OverlayStatus.pending)
        engine.add_overlay(overlay)
        overlays = engine.list_overlays()
        assert len(overlays) == 1
        assert overlays[0]["title"] == "Test overlay"

    def test_activate_overlay(self, engine):
        overlay = _make_overlay(status=OverlayStatus.pending)
        engine.add_overlay(overlay)
        success = engine.activate(overlay.overlay_id, "admin@corp.com")
        assert success is True

        adj, _ = engine.get_adjustment()
        assert adj == 0.10

    def test_cannot_activate_rejected(self, engine):
        overlay = _make_overlay(status=OverlayStatus.pending)
        engine.add_overlay(overlay)
        engine.reject(overlay.overlay_id, "admin")
        success = engine.activate(overlay.overlay_id)
        assert success is False

    def test_action_filtering(self, engine):
        overlay = _make_overlay(
            risk_adj=0.10,
            actions=["wipe_device", "delete_device"],
        )
        engine.add_overlay(overlay)
        engine.activate(overlay.overlay_id)

        # Matching action
        adj, _ = engine.get_adjustment(action="wipe_device")
        assert adj == 0.10

        # Non-matching action
        adj, _ = engine.get_adjustment(action="change_configuration")
        assert adj == 0.0

    def test_system_filtering(self, engine):
        overlay = _make_overlay(
            risk_adj=0.12,
            systems=["intune"],
        )
        engine.add_overlay(overlay)
        engine.activate(overlay.overlay_id)

        adj, _ = engine.get_adjustment(system="intune-device-management")
        assert adj == 0.12

        adj, _ = engine.get_adjustment(system="aws-ec2")
        assert adj == 0.0

    def test_audit_trail(self, engine):
        overlay = _make_overlay(status=OverlayStatus.pending)
        engine.add_overlay(overlay)
        engine.activate(overlay.overlay_id, "admin@corp.com")

        audit = engine.get_audit_log(overlay.overlay_id)
        assert len(audit) == 2  # created + activated
        actions = [a["action"] for a in audit]
        assert "created" in actions
        assert "activated" in actions

    def test_expire_stale_overlays(self, engine):
        overlay = RiskOverlay(
            source=ThreatFeedSource.cisa_kev,
            status=OverlayStatus.active,
            title="Soon expired",
            risk_adjustment=0.10,
            expires_at=_now() - timedelta(hours=1),
        )
        engine.add_overlay(overlay)
        expired = engine.expire_stale()
        assert expired == 1

    def test_filter_by_status(self, engine):
        for i in range(3):
            engine.add_overlay(_make_overlay(status=OverlayStatus.pending))
        for i in range(2):
            o = _make_overlay(status=OverlayStatus.pending)
            engine.add_overlay(o)
            engine.activate(o.overlay_id)

        pending = engine.list_overlays(OverlayStatus.pending)
        active = engine.list_overlays(OverlayStatus.active)
        assert len(pending) == 3
        assert len(active) == 2


# ── KEV Feed Mapping Tests ───────────────────────────────────────────────────

class TestCISAKEVMapping:
    def test_maps_microsoft_intune_kev(self):
        engine = OverlayEngine()
        feed = CISAKEVFeed(engine)
        entry = KEVEntry(
            cveID="CVE-2026-12345",
            vendorProject="Microsoft",
            product="Intune",
            vulnerabilityName="Intune Remote Wipe Bypass",
            shortDescription="Allows unauthenticated remote wipe of managed devices",
            dateAdded=_now().strftime("%Y-%m-%d"),
            knownRansomwareCampaignUse="Known",
        )
        overlay = feed._map_kev_to_overlay(entry, "testhash")
        assert overlay is not None
        assert "intune" in str(overlay.affected_systems).lower()
        assert overlay.risk_adjustment == 0.15  # ransomware-associated
        assert "CVE-2026-12345" in overlay.cve_ids

    def test_maps_aws_iam_kev(self):
        engine = OverlayEngine()
        feed = CISAKEVFeed(engine)
        entry = KEVEntry(
            cveID="CVE-2026-99999",
            vendorProject="Amazon",
            product="IAM",
            vulnerabilityName="IAM Privilege Escalation",
            shortDescription="Allows privilege escalation via role assumption",
            dateAdded=_now().strftime("%Y-%m-%d"),
            knownRansomwareCampaignUse="Unknown",
        )
        overlay = feed._map_kev_to_overlay(entry, "testhash")
        assert overlay is not None
        assert any("aws" in s for s in overlay.affected_systems)
        assert "escalate_privileges" in overlay.affected_actions

    def test_ignores_irrelevant_kev(self):
        engine = OverlayEngine()
        feed = CISAKEVFeed(engine)
        entry = KEVEntry(
            cveID="CVE-2026-00001",
            vendorProject="SomeObscureVendor",
            product="SomeObscureProduct",
            vulnerabilityName="Buffer overflow",
            shortDescription="Local buffer overflow in obscure desktop app",
            dateAdded=_now().strftime("%Y-%m-%d"),
        )
        overlay = feed._map_kev_to_overlay(entry, "testhash")
        assert overlay is None  # not relevant to Guardian's systems

    def test_ransomware_kev_gets_higher_risk(self):
        engine = OverlayEngine()
        feed = CISAKEVFeed(engine)
        ransomware = KEVEntry(
            cveID="CVE-2026-RANSOM",
            vendorProject="Veeam",
            product="Backup",
            vulnerabilityName="Veeam RCE",
            shortDescription="Remote code execution in backup management",
            dateAdded=_now().strftime("%Y-%m-%d"),
            knownRansomwareCampaignUse="Known",
        )
        no_ransom = KEVEntry(
            cveID="CVE-2026-NORANSOM",
            vendorProject="Veeam",
            product="Backup",
            vulnerabilityName="Veeam Info Disclosure",
            shortDescription="Information disclosure in backup logs",
            dateAdded=_now().strftime("%Y-%m-%d"),
            knownRansomwareCampaignUse="Unknown",
        )
        o1 = feed._map_kev_to_overlay(ransomware, "h1")
        o2 = feed._map_kev_to_overlay(no_ransom, "h2")
        assert o1 is not None and o2 is not None
        assert o1.risk_adjustment > o2.risk_adjustment


# ── MITRE ATT&CK Mapper Tests ───────────────────────────────────────────────

class TestMITREMapper:
    def test_destruction_techniques(self):
        techniques = MITREAttackMapper.get_techniques_for_action("destroy_infrastructure")
        assert "T1485" in techniques  # Data Destruction
        assert "T1486" in techniques  # Data Encrypted for Impact

    def test_privilege_escalation_techniques(self):
        techniques = MITREAttackMapper.get_techniques_for_action("escalate_privileges")
        assert "T1548" in techniques  # Abuse Elevation

    def test_actions_for_technique(self):
        actions = MITREAttackMapper.get_actions_for_technique("T1562.001")
        assert "disable_endpoint_protection" in actions

    def test_unknown_technique_returns_empty(self):
        actions = MITREAttackMapper.get_actions_for_technique("T9999")
        assert actions == []

    def test_wipe_device_maps_to_destruction(self):
        techniques = MITREAttackMapper.get_techniques_for_action("wipe_device")
        assert "T1485" in techniques
