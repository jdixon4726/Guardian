"""
Terraform Plan Replay Integration Tests

Replays real Terraform plan JSON fixtures through the full Guardian pipeline
(mapper → pipeline → decision) and verifies expected outcomes.

These tests validate that Guardian produces correct governance decisions
for realistic infrastructure changes.
"""

from __future__ import annotations

import json
from datetime import datetime, timezone
from pathlib import Path

import pytest

from guardian.adapters.terraform.mapper import TerraformPlanMapper
from guardian.models.action_request import DecisionOutcome, SensitivityLevel, PrivilegeLevel
from guardian.pipeline import GuardianPipeline

FIXTURES = Path(__file__).parent.parent / "fixtures" / "terraform"
ROOT = Path(__file__).parent.parent.parent
CONFIG = ROOT / "config"
POLICIES = ROOT / "policies"
AUDIT = ROOT / "tests" / "test-replay-audit.jsonl"


@pytest.fixture(scope="module")
def mapper():
    return TerraformPlanMapper.from_config(CONFIG / "terraform-mappings.yaml")


@pytest.fixture(scope="module")
def pipeline():
    AUDIT.parent.mkdir(parents=True, exist_ok=True)
    if AUDIT.exists():
        AUDIT.unlink()
    return GuardianPipeline.from_config(CONFIG, POLICIES, AUDIT)


def _load_plan(name: str) -> dict:
    return json.loads((FIXTURES / name).read_text(encoding="utf-8"))


class TestSimplePlanReplay:
    """Replay a routine plan: SG update + instance resize."""

    def test_maps_correct_number_of_requests(self, mapper):
        plan = _load_plan("simple-plan.json")
        requests = mapper.map_plan(plan, actor_name="deploy-bot-prod")
        assert len(requests) == 2

    def test_security_group_update_mapped_correctly(self, mapper):
        plan = _load_plan("simple-plan.json")
        requests = mapper.map_plan(plan, actor_name="deploy-bot-prod")
        sg_req = [r for r in requests if "security_group" in r.target_asset][0]
        assert sg_req.requested_action == "modify_firewall_rule"
        assert sg_req.sensitivity_level == SensitivityLevel.high

    def test_full_pipeline_evaluation(self, mapper, pipeline):
        plan = _load_plan("simple-plan.json")
        requests = mapper.map_plan(plan, actor_name="deploy-bot-prod")
        for req in requests:
            decision = pipeline.evaluate(req)
            # Routine changes should not be blocked
            assert decision.decision != DecisionOutcome.block, (
                f"Routine change unexpectedly blocked: {req.requested_action} "
                f"on {req.target_asset}. Explanation: {decision.explanation}"
            )
            assert decision.entry_hash is not None


class TestDestructivePlanReplay:
    """Replay a destructive plan: DB delete + IAM role create + SG delete."""

    def test_maps_three_requests(self, mapper):
        plan = _load_plan("destructive-plan.json")
        requests = mapper.map_plan(plan, actor_name="deploy-bot-prod")
        assert len(requests) == 3

    def test_db_delete_is_destructive(self, mapper):
        plan = _load_plan("destructive-plan.json")
        requests = mapper.map_plan(plan, actor_name="deploy-bot-prod")
        db_req = [r for r in requests if "db_instance" in r.target_asset][0]
        assert db_req.requested_action == "destroy_infrastructure"
        assert db_req.privilege_level == PrivilegeLevel.elevated

    def test_iam_create_is_admin_privilege(self, mapper):
        plan = _load_plan("destructive-plan.json")
        requests = mapper.map_plan(plan, actor_name="deploy-bot-prod")
        iam_req = [r for r in requests if "iam_role" in r.target_asset][0]
        assert iam_req.requested_action == "modify_iam_role"
        assert iam_req.privilege_level == PrivilegeLevel.admin

    def test_destructive_actions_get_elevated_decisions(self, mapper, pipeline):
        """Destructive actions should result in require_review or block."""
        plan = _load_plan("destructive-plan.json")
        requests = mapper.map_plan(plan, actor_name="deploy-bot-prod")

        decisions = []
        for req in requests:
            decision = pipeline.evaluate(req)
            decisions.append(decision)

        # At least one destructive action should not be simply allowed
        outcomes = {d.decision for d in decisions}
        assert outcomes != {DecisionOutcome.allow}, (
            "Destructive plan should not be fully allowed without escalation"
        )


class TestNoopPlanReplay:
    """Replay a no-op plan — no resource changes."""

    def test_noop_produces_no_requests(self, mapper):
        plan = _load_plan("noop-plan.json")
        requests = mapper.map_plan(plan, actor_name="deploy-bot-prod")
        assert len(requests) == 0


class TestK8sAdmissionMapper:
    """Test the K8s admission mapper directly."""

    def test_pod_create(self):
        from guardian.adapters.kubernetes.mapper import KubernetesAdmissionMapper
        from guardian.adapters.kubernetes.models import (
            AdmissionRequest,
            AdmissionRequestResource,
            AdmissionRequestUser,
            AdmissionRequestObject,
        )

        mapper = KubernetesAdmissionMapper()
        req = mapper.map_admission(AdmissionRequest(
            uid="test-uid",
            resource=AdmissionRequestResource(group="", version="v1", resource="pods"),
            namespace="production",
            operation="CREATE",
            userInfo=AdmissionRequestUser(
                username="system:serviceaccount:production:deploy-bot",
                groups=["system:serviceaccounts"],
            ),
            object=AdmissionRequestObject(
                metadata={"name": "web-app-v2"},
                kind="Pod",
            ),
        ))

        assert req.actor_name == "k8s-production-deploy-bot"
        assert req.requested_action == "change_configuration"
        assert req.target_asset == "production/pods/web-app-v2"

    def test_clusterrole_create_is_admin(self):
        from guardian.adapters.kubernetes.mapper import KubernetesAdmissionMapper
        from guardian.adapters.kubernetes.models import (
            AdmissionRequest,
            AdmissionRequestResource,
            AdmissionRequestUser,
            AdmissionRequestObject,
        )

        mapper = KubernetesAdmissionMapper()
        req = mapper.map_admission(AdmissionRequest(
            uid="test-uid-2",
            resource=AdmissionRequestResource(
                group="rbac.authorization.k8s.io",
                version="v1",
                resource="clusterroles",
            ),
            namespace="kube-system",
            operation="CREATE",
            userInfo=AdmissionRequestUser(username="admin@company.com"),
            object=AdmissionRequestObject(
                metadata={"name": "super-admin"},
                kind="ClusterRole",
            ),
        ))

        assert req.requested_action == "modify_iam_role"
        assert req.privilege_level == PrivilegeLevel.admin
        assert req.sensitivity_level == SensitivityLevel.restricted

    def test_network_policy_delete_is_disable_firewall(self):
        from guardian.adapters.kubernetes.mapper import KubernetesAdmissionMapper
        from guardian.adapters.kubernetes.models import (
            AdmissionRequest,
            AdmissionRequestResource,
            AdmissionRequestUser,
        )

        mapper = KubernetesAdmissionMapper()
        req = mapper.map_admission(AdmissionRequest(
            uid="test-uid-3",
            resource=AdmissionRequestResource(
                group="networking.k8s.io",
                version="v1",
                resource="networkpolicies",
            ),
            namespace="production",
            operation="DELETE",
            userInfo=AdmissionRequestUser(username="ops-bot"),
        ))

        assert req.requested_action == "disable_firewall"
