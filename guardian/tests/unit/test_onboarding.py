"""
Unit tests for the onboarding discovery engine and industry templates.
"""

from __future__ import annotations

import pytest

from guardian.onboarding.discovery import DiscoveryEngine
from guardian.onboarding.models import (
    IndustryTemplate,
    OnboardingPhase,
    RiskPosture,
)
from guardian.onboarding.templates import get_template, list_templates


class TestDiscoveryEngine:
    @pytest.fixture
    def engine(self):
        return DiscoveryEngine()

    def test_initial_status_is_not_started(self, engine):
        status = engine.get_status()
        assert status["phase"] == "not_started"
        assert status["events_ingested"] == 0

    def test_ingest_single_event(self, engine):
        engine.ingest_event(
            actor_name="deploy-bot",
            action="change_configuration",
            target_system="aws-ec2",
            target_asset="prod/ec2/web",
        )
        status = engine.get_status()
        assert status["events_ingested"] == 1
        assert status["phase"] == "discovering"

    def test_ingest_batch(self, engine):
        events = [
            {"actor_name": "actor-1", "action": "change_configuration",
             "target_system": "aws-ec2", "target_asset": "asset-1"},
            {"actor_name": "actor-2", "action": "destroy_infrastructure",
             "target_system": "aws-rds", "target_asset": "asset-2"},
            {"actor_name": "actor-1", "action": "modify_firewall_rule",
             "target_system": "aws-vpc", "target_asset": "asset-3"},
        ]
        count = engine.ingest_batch(events)
        assert count == 3
        assert engine.get_status()["actors_discovered"] == 2

    def test_discover_actors(self, engine):
        for i in range(5):
            engine.ingest_event(
                actor_name="deploy-bot",
                action="change_configuration",
                target_system="aws-ec2",
                target_asset=f"asset-{i}",
            )
        engine.ingest_event(
            actor_name="admin-user",
            action="grant_admin_access",
            target_system="aws-iam",
            target_asset="role-admin",
        )

        report = engine.generate_report()
        assert len(report.actors) == 2

        # deploy-bot should be automation type
        deploy = next(a for a in report.actors if a.name == "deploy-bot")
        assert deploy.actor_type == "automation"
        assert deploy.event_count == 5

        # admin-user should be human with admin privilege
        admin = next(a for a in report.actors if a.name == "admin-user")
        assert admin.recommended_max_privilege == "admin"

    def test_discover_assets(self, engine):
        # Multiple actors touching same asset = higher criticality
        for actor in ["actor-1", "actor-2", "actor-3", "actor-4", "actor-5", "actor-6"]:
            engine.ingest_event(
                actor_name=actor,
                action="change_configuration",
                target_system="aws-rds",
                target_asset="prod-db-primary",
                privilege_level="elevated",
            )

        report = engine.generate_report()
        db_asset = next(a for a in report.assets if a.asset_id == "prod-db-primary")
        assert db_asset.actor_count == 6
        assert db_asset.recommended_criticality in ("critical", "high")

    def test_discover_systems(self, engine):
        engine.ingest_event(actor_name="tf-bot", action="change_configuration",
                           target_system="terraform-cloud", target_asset="ws-prod")
        engine.ingest_event(actor_name="k8s-bot", action="change_configuration",
                           target_system="k8s-prod", target_asset="deploy/web")
        engine.ingest_event(actor_name="gh-bot", action="change_configuration",
                           target_system="github", target_asset="repo/main")

        report = engine.generate_report()
        system_ids = {s.system_id for s in report.systems}
        assert "terraform-cloud" in system_ids
        assert "k8s-prod" in system_ids
        assert "github" in system_ids

        # Check adapter recommendations
        tf = next(s for s in report.systems if s.system_id == "terraform-cloud")
        assert tf.adapter_available is True
        assert tf.recommended_adapter == "terraform"

    def test_actor_type_inference(self, engine):
        engine.ingest_event(actor_name="ai-remediation-bot", action="change_configuration",
                           target_system="test", target_asset="test")
        engine.ingest_event(actor_name="terraform-prod-runner", action="change_configuration",
                           target_system="test", target_asset="test")
        engine.ingest_event(actor_name="alice.chen", action="change_configuration",
                           target_system="test", target_asset="test")

        report = engine.generate_report()
        ai = next(a for a in report.actors if a.name == "ai-remediation-bot")
        tf = next(a for a in report.actors if a.name == "terraform-prod-runner")
        human = next(a for a in report.actors if a.name == "alice.chen")

        assert ai.actor_type == "ai_agent"
        assert tf.actor_type == "automation"
        assert human.actor_type == "human"

    def test_risk_posture_recommendation(self, engine):
        # Many admin actions + many actors = conservative
        for i in range(10):
            engine.ingest_event(
                actor_name=f"admin-{i}",
                action="grant_admin_access",
                target_system="aws-iam",
                target_asset=f"role-{i}",
                privilege_level="admin",
            )
        report = engine.generate_report()
        assert report.recommended_risk_posture == RiskPosture.conservative

    def test_report_phase_transitions(self, engine):
        assert engine.get_status()["phase"] == "not_started"

        engine.ingest_event(actor_name="bot", action="test",
                           target_system="test", target_asset="test")
        assert engine.get_status()["phase"] == "discovering"

        engine.generate_report()
        assert engine.get_status()["phase"] == "ready"

    def test_empty_report(self, engine):
        report = engine.generate_report()
        assert report.total_events_ingested == 0
        assert len(report.actors) == 0


class TestIndustryTemplates:
    def test_list_all_templates(self):
        templates = list_templates()
        assert len(templates) == 6
        names = {t["industry"] for t in templates}
        assert "healthcare" in names
        assert "gov_healthcare" in names
        assert "fintech" in names
        assert "saas" in names

    def test_healthcare_template(self):
        t = get_template(IndustryTemplate.healthcare)
        scores = t["scoring_overrides"]["action_category_scores"]
        assert scores["destructive"] == 0.95  # higher than default
        assert scores["data_exfil"] == 0.90   # PHI protection
        assert "HIPAA" in t["compliance_frameworks"]
        assert "intune" in t["recommended_adapters"]

    def test_fintech_template(self):
        t = get_template(IndustryTemplate.fintech)
        scores = t["scoring_overrides"]["action_category_scores"]
        assert scores["data_exfil"] == 0.95   # financial data priority
        assert "PCI-DSS" in t["compliance_frameworks"]

    def test_saas_template_higher_velocity(self):
        t = get_template(IndustryTemplate.saas)
        scores = t["scoring_overrides"]
        assert scores.get("velocity_hourly_extreme", 100) >= 100  # CI/CD tolerant
        assert "mcp" in t["recommended_adapters"]  # AI agent support

    def test_government_strictest(self):
        t = get_template(IndustryTemplate.government)
        cb = t["circuit_breaker"]
        assert cb["max_per_minute"] <= 3  # very conservative
        assert "FedRAMP" in t["compliance_frameworks"]

    def test_general_template_empty_overrides(self):
        t = get_template(IndustryTemplate.general)
        assert t["scoring_overrides"] == {}  # uses defaults
