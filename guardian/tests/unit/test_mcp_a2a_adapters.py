"""
Unit tests for MCP and A2A adapters.
"""

from __future__ import annotations

import pytest

from guardian.adapters.mcp.mapper import MCPToolCallMapper
from guardian.adapters.mcp.models import MCPToolCall
from guardian.adapters.a2a.mapper import A2ATaskMapper
from guardian.adapters.a2a.models import A2ATaskDelegation
from guardian.models.action_request import ActorType, PrivilegeLevel, SensitivityLevel


# ── MCP Mapper ───────────────────────────────────────────────────────────────

class TestMCPToolCallMapper:
    @pytest.fixture
    def mapper(self):
        return MCPToolCallMapper()

    def test_shell_execution_is_admin_restricted(self, mapper):
        tc = MCPToolCall(tool_name="bash", agent_id="agent-1", agent_framework="openclaw")
        request = mapper.map_tool_call(tc)
        assert request.sensitivity_level == SensitivityLevel.restricted
        assert request.privilege_level == PrivilegeLevel.admin
        assert request.actor_type == ActorType.ai_agent
        assert "HIGH_RISK_TOOL" in request.business_context

    def test_delete_tool_is_destructive(self, mapper):
        tc = MCPToolCall(tool_name="delete_file", agent_id="agent-1")
        request = mapper.map_tool_call(tc)
        assert request.requested_action == "destroy_infrastructure"
        assert request.sensitivity_level == SensitivityLevel.restricted

    def test_read_tool_is_low_risk(self, mapper):
        tc = MCPToolCall(tool_name="read_file", agent_id="agent-1")
        request = mapper.map_tool_call(tc)
        assert request.sensitivity_level == SensitivityLevel.internal
        assert request.privilege_level == PrivilegeLevel.standard

    def test_credential_access_is_admin(self, mapper):
        tc = MCPToolCall(tool_name="vault_get_secret", agent_id="agent-1")
        request = mapper.map_tool_call(tc)
        assert request.requested_action == "escalate_privileges"
        assert request.privilege_level == PrivilegeLevel.admin

    def test_dangerous_args_elevate_risk(self, mapper):
        tc = MCPToolCall(
            tool_name="run_command",
            agent_id="agent-1",
            arguments={"command": "rm -rf /"},
        )
        request = mapper.map_tool_call(tc)
        assert request.sensitivity_level == SensitivityLevel.restricted
        assert "DANGEROUS_ARGUMENTS_DETECTED" in request.business_context

    def test_actor_name_from_agent_id(self, mapper):
        tc = MCPToolCall(tool_name="read_file", agent_id="my-agent", agent_framework="crewai")
        request = mapper.map_tool_call(tc)
        assert request.actor_name == "crewai-my-agent"

    def test_actor_name_fallback(self, mapper):
        tc = MCPToolCall(tool_name="read_file", session_id="sess-123")
        request = mapper.map_tool_call(tc)
        assert "sess-123" in request.actor_name

    def test_delegation_noted_in_context(self, mapper):
        tc = MCPToolCall(
            tool_name="query", agent_id="child-agent",
            parent_agent_id="parent-agent",
        )
        request = mapper.map_tool_call(tc)
        assert "delegated_from=parent-agent" in request.business_context

    def test_secret_args_redacted(self, mapper):
        tc = MCPToolCall(
            tool_name="api_call",
            agent_id="agent-1",
            arguments={"url": "https://api.com", "api_key": "sk-supersecret123"},
        )
        request = mapper.map_tool_call(tc)
        assert "sk-supersecret123" not in request.business_context
        assert "REDACTED" in request.business_context

    def test_http_request_is_export(self, mapper):
        tc = MCPToolCall(tool_name="http_request", agent_id="agent-1")
        request = mapper.map_tool_call(tc)
        assert request.requested_action == "export_data"

    def test_email_tool_is_export(self, mapper):
        tc = MCPToolCall(tool_name="send_email", agent_id="agent-1")
        request = mapper.map_tool_call(tc)
        assert request.requested_action == "export_data"

    def test_unknown_tool_gets_moderate_risk(self, mapper):
        tc = MCPToolCall(tool_name="totally_new_tool_xyz", agent_id="agent-1")
        request = mapper.map_tool_call(tc)
        assert request.sensitivity_level == SensitivityLevel.internal
        assert request.privilege_level == PrivilegeLevel.standard

    def test_resource_uri_in_target(self, mapper):
        tc = MCPToolCall(
            tool_name="read_file", agent_id="agent-1",
            resource_uri="file:///etc/passwd",
        )
        request = mapper.map_tool_call(tc)
        assert "file:///etc/passwd" in request.target_asset


# ── A2A Mapper ───────────────────────────────────────────────────────────────

class TestA2ATaskMapper:
    @pytest.fixture
    def mapper(self):
        return A2ATaskMapper()

    def test_basic_delegation(self, mapper):
        d = A2ATaskDelegation(
            sender_agent_id="agent-a",
            receiver_agent_id="agent-b",
            task_type="data_query",
        )
        request = mapper.map_delegation(d)
        assert request.actor_name == "a2a-agent-a"
        assert request.actor_type == ActorType.ai_agent
        assert request.target_system == "a2a-agent-network"
        assert "agent-b" in request.target_asset

    def test_high_risk_task_type(self, mapper):
        d = A2ATaskDelegation(
            sender_agent_id="agent-a",
            receiver_agent_id="agent-b",
            task_type="deploy",
        )
        request = mapper.map_delegation(d)
        assert request.sensitivity_level == SensitivityLevel.high
        assert request.privilege_level == PrivilegeLevel.elevated

    def test_deep_delegation_chain_escalates(self, mapper):
        d = A2ATaskDelegation(
            sender_agent_id="agent-d",
            receiver_agent_id="agent-e",
            task_type="data_query",
            delegation_depth=5,
            delegation_chain=["agent-a", "agent-b", "agent-c", "agent-d"],
        )
        request = mapper.map_delegation(d)
        assert request.sensitivity_level == SensitivityLevel.restricted
        assert request.privilege_level == PrivilegeLevel.admin
        assert "DEEP_DELEGATION_CHAIN" in request.business_context

    def test_privileged_permissions_escalate(self, mapper):
        d = A2ATaskDelegation(
            sender_agent_id="agent-a",
            receiver_agent_id="agent-b",
            task_type="code_review",
            requested_permissions=["admin", "delete"],
        )
        request = mapper.map_delegation(d)
        assert request.privilege_level == PrivilegeLevel.admin

    def test_chain_risk_levels(self, mapper):
        low = A2ATaskDelegation(sender_agent_id="a", receiver_agent_id="b", delegation_depth=0)
        assert mapper.chain_risk_level(low) == "low"

        medium = A2ATaskDelegation(sender_agent_id="a", receiver_agent_id="b", delegation_depth=2)
        assert mapper.chain_risk_level(medium) == "medium"

        high = A2ATaskDelegation(sender_agent_id="a", receiver_agent_id="b", delegation_depth=4)
        assert mapper.chain_risk_level(high) == "high"

        critical = A2ATaskDelegation(
            sender_agent_id="a", receiver_agent_id="b",
            delegation_depth=6,
        )
        assert mapper.chain_risk_level(critical) == "critical"

    def test_context_includes_chain(self, mapper):
        d = A2ATaskDelegation(
            sender_agent_id="agent-c",
            receiver_agent_id="agent-d",
            delegation_chain=["agent-a", "agent-b", "agent-c"],
            original_requester="user@corp.com",
        )
        request = mapper.map_delegation(d)
        assert "origin=user@corp.com" in request.business_context

    def test_context_includes_tools(self, mapper):
        d = A2ATaskDelegation(
            sender_agent_id="a", receiver_agent_id="b",
            requested_tools=["bash", "http_request"],
        )
        request = mapper.map_delegation(d)
        assert "tools=bash,http_request" in request.business_context


# ── Observability ────────────────────────────────────────────────────────────

class TestMetrics:
    def test_metrics_counter(self):
        from guardian.observability import MetricsStore
        m = MetricsStore()
        m.inc("test.counter")
        m.inc("test.counter")
        assert m.snapshot()["counters"]["test.counter"] == 2

    def test_metrics_gauge(self):
        from guardian.observability import MetricsStore
        m = MetricsStore()
        m.gauge("test.gauge", 42.5)
        assert m.snapshot()["gauges"]["test.gauge"] == 42.5

    def test_metrics_histogram(self):
        from guardian.observability import MetricsStore
        m = MetricsStore()
        for i in range(100):
            m.observe("test.hist", float(i))
        snap = m.snapshot()
        assert snap["histograms"]["test.hist"]["count"] == 100
        assert snap["histograms"]["test.hist"]["p50"] == 50.0

    def test_prometheus_text_format(self):
        from guardian.observability import MetricsStore
        m = MetricsStore()
        m.inc("guardian.requests.total", 42)
        text = m.prometheus_text()
        assert "guardian_requests_total 42" in text
        assert "# TYPE guardian_requests_total counter" in text

    def test_structured_json_formatter(self):
        from guardian.observability import StructuredJSONFormatter
        import json
        fmt = StructuredJSONFormatter()
        record = logging.LogRecord(
            name="test", level=logging.INFO, pathname="", lineno=0,
            msg="test message", args=(), exc_info=None,
        )
        output = fmt.format(record)
        parsed = json.loads(output)
        assert parsed["message"] == "test message"
        assert parsed["level"] == "INFO"
        assert "timestamp" in parsed


import logging
