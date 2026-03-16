"""
Unit tests for the Terraform Plan → ActionRequest mapper.
"""

from datetime import datetime, timezone
from pathlib import Path

import pytest

from guardian.adapters.terraform.mapper import (
    ResourceMapping,
    TerraformPlanMapper,
)
from guardian.models.action_request import ActorType, PrivilegeLevel, SensitivityLevel


@pytest.fixture
def mapper():
    """Mapper with typical AWS mappings."""
    return TerraformPlanMapper(mappings=[
        ResourceMapping("aws_security_group*", "modify_firewall_rule", "high", "aws-vpc"),
        ResourceMapping("aws_iam_role*", "modify_iam_role", "restricted", "aws-iam"),
        ResourceMapping("aws_iam_policy*", "modify_iam_role", "restricted", "aws-iam"),
        ResourceMapping("aws_db_instance*", "change_configuration", "restricted", "rds-prod"),
        ResourceMapping("aws_instance*", "change_configuration", "high", "ec2"),
    ])


def _make_plan(resource_changes: list[dict]) -> dict:
    """Build a minimal Terraform plan JSON."""
    return {"resource_changes": resource_changes}


def _change(address: str, resource_type: str, actions: list[str]) -> dict:
    return {
        "address": address,
        "type": resource_type,
        "change": {"actions": actions},
    }


class TestResourceMapping:
    def test_glob_matching(self):
        m = ResourceMapping("aws_security_group*", "modify_firewall_rule", "high", "aws-vpc")
        assert m.matches("aws_security_group")
        assert m.matches("aws_security_group_rule")
        assert not m.matches("aws_iam_role")

    def test_exact_matching(self):
        m = ResourceMapping("aws_instance", "change_configuration", "high", "ec2")
        assert m.matches("aws_instance")
        assert not m.matches("aws_instance_something")


class TestPlanMapping:
    def test_empty_plan_produces_no_requests(self, mapper):
        plan = _make_plan([])
        requests = mapper.map_plan(plan, actor_name="deploy-bot")
        assert requests == []

    def test_noop_changes_skipped(self, mapper):
        plan = _make_plan([
            _change("aws_instance.web", "aws_instance", ["no-op"]),
        ])
        requests = mapper.map_plan(plan, actor_name="deploy-bot")
        assert requests == []

    def test_security_group_update_maps_correctly(self, mapper):
        plan = _make_plan([
            _change("aws_security_group.main", "aws_security_group", ["update"]),
        ])
        requests = mapper.map_plan(plan, actor_name="deploy-bot")
        assert len(requests) == 1
        r = requests[0]
        assert r.requested_action == "modify_firewall_rule"
        assert r.sensitivity_level == SensitivityLevel.high
        assert r.target_system == "aws-vpc"
        assert r.target_asset == "aws_security_group.main"

    def test_iam_role_create_maps_to_admin_privilege(self, mapper):
        plan = _make_plan([
            _change("aws_iam_role.deploy", "aws_iam_role", ["create"]),
        ])
        requests = mapper.map_plan(plan, actor_name="deploy-bot")
        assert len(requests) == 1
        r = requests[0]
        assert r.requested_action == "modify_iam_role"
        assert r.privilege_level == PrivilegeLevel.admin
        assert r.sensitivity_level == SensitivityLevel.restricted

    def test_delete_maps_to_destroy(self, mapper):
        plan = _make_plan([
            _change("aws_instance.web", "aws_instance", ["delete"]),
        ])
        requests = mapper.map_plan(plan, actor_name="deploy-bot")
        assert len(requests) == 1
        r = requests[0]
        assert r.requested_action == "destroy_infrastructure"
        assert r.privilege_level == PrivilegeLevel.elevated

    def test_replace_action_treated_as_delete(self, mapper):
        """A create+delete (replace) should map to destroy."""
        plan = _make_plan([
            _change("aws_db_instance.primary", "aws_db_instance", ["create", "delete"]),
        ])
        requests = mapper.map_plan(plan, actor_name="deploy-bot")
        assert len(requests) == 1
        # delete present → destroy_infrastructure
        assert requests[0].requested_action == "destroy_infrastructure"

    def test_unknown_resource_uses_defaults(self, mapper):
        plan = _make_plan([
            _change("random_pet.name", "random_pet", ["create"]),
        ])
        requests = mapper.map_plan(plan, actor_name="deploy-bot")
        assert len(requests) == 1
        r = requests[0]
        assert r.requested_action == "change_configuration"
        assert r.sensitivity_level == SensitivityLevel.internal

    def test_multiple_changes_produce_multiple_requests(self, mapper):
        plan = _make_plan([
            _change("aws_security_group.web", "aws_security_group", ["update"]),
            _change("aws_iam_role.deploy", "aws_iam_role", ["create"]),
            _change("aws_instance.app", "aws_instance", ["update"]),
        ])
        requests = mapper.map_plan(plan, actor_name="deploy-bot")
        assert len(requests) == 3

    def test_actor_name_propagated(self, mapper):
        plan = _make_plan([
            _change("aws_instance.x", "aws_instance", ["create"]),
        ])
        requests = mapper.map_plan(plan, actor_name="ci-bot-prod")
        assert requests[0].actor_name == "ci-bot-prod"

    def test_actor_type_defaults_to_automation(self, mapper):
        plan = _make_plan([
            _change("aws_instance.x", "aws_instance", ["create"]),
        ])
        requests = mapper.map_plan(plan, actor_name="bot")
        assert requests[0].actor_type == ActorType.automation

    def test_timestamp_propagated(self, mapper):
        ts = datetime(2026, 1, 15, 12, 0, 0, tzinfo=timezone.utc)
        plan = _make_plan([
            _change("aws_instance.x", "aws_instance", ["create"]),
        ])
        requests = mapper.map_plan(plan, actor_name="bot", timestamp=ts)
        assert requests[0].timestamp == ts


class TestConfigLoading:
    def test_loads_from_real_config(self):
        config_path = Path(__file__).parent.parent.parent / "config" / "terraform-mappings.yaml"
        if config_path.exists():
            mapper = TerraformPlanMapper.from_config(config_path)
            assert len(mapper.mappings) > 0

    def test_missing_config_returns_empty_mapper(self, tmp_path):
        mapper = TerraformPlanMapper.from_config(tmp_path / "nonexistent.yaml")
        assert mapper.mappings == []
