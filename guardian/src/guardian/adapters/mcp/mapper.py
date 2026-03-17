"""
MCP Tool Call -> ActionRequest Mapper

Maps MCP tool invocations to Guardian's action taxonomy.
Tool names and argument patterns determine the risk classification.

Key insight: we don't need to know what every tool does — we classify
based on the tool's observable characteristics (name patterns, argument
patterns, resource types) and the agent's behavioral history.
"""

from __future__ import annotations

import logging
from datetime import datetime, timezone

from guardian.adapters.mcp.models import MCPToolCall
from guardian.models.action_request import (
    ActionRequest as GuardianActionRequest,
    ActorType,
    PrivilegeLevel,
    SensitivityLevel,
)

logger = logging.getLogger(__name__)

# Tool name patterns -> risk classification
# More specific patterns take priority
_TOOL_RISK_PATTERNS: list[tuple[list[str], dict]] = [
    # Destructive / dangerous tools
    (["delete", "remove", "destroy", "drop", "wipe", "purge", "truncate"], {
        "action": "destroy_infrastructure",
        "sensitivity": SensitivityLevel.restricted,
        "privilege": PrivilegeLevel.admin,
    }),
    # File system write operations
    (["write_file", "create_file", "edit_file", "patch_file", "overwrite"], {
        "action": "change_configuration",
        "sensitivity": SensitivityLevel.high,
        "privilege": PrivilegeLevel.elevated,
    }),
    # Code execution
    (["execute", "run_command", "shell", "bash", "exec", "eval", "subprocess"], {
        "action": "change_configuration",
        "sensitivity": SensitivityLevel.restricted,
        "privilege": PrivilegeLevel.admin,
    }),
    # Network / HTTP calls
    (["http_request", "fetch", "curl", "api_call", "webhook", "send_request"], {
        "action": "export_data",
        "sensitivity": SensitivityLevel.high,
        "privilege": PrivilegeLevel.elevated,
    }),
    # Database operations
    (["query", "sql", "database", "db_execute", "insert", "update"], {
        "action": "change_configuration",
        "sensitivity": SensitivityLevel.high,
        "privilege": PrivilegeLevel.elevated,
    }),
    # Credential / secret access
    (["secret", "credential", "password", "token", "key", "vault"], {
        "action": "escalate_privileges",
        "sensitivity": SensitivityLevel.restricted,
        "privilege": PrivilegeLevel.admin,
    }),
    # Email / messaging (external communication)
    (["send_email", "send_message", "slack", "teams", "notify", "publish"], {
        "action": "export_data",
        "sensitivity": SensitivityLevel.high,
        "privilege": PrivilegeLevel.elevated,
    }),
    # IAM / auth operations
    (["create_user", "grant", "permission", "role", "access", "iam"], {
        "action": "grant_admin_access",
        "sensitivity": SensitivityLevel.restricted,
        "privilege": PrivilegeLevel.admin,
    }),
    # Read operations (lowest risk)
    (["read", "get", "list", "search", "find", "query", "fetch_data"], {
        "action": "change_configuration",
        "sensitivity": SensitivityLevel.internal,
        "privilege": PrivilegeLevel.standard,
    }),
]

# Argument patterns that elevate risk regardless of tool name
_DANGEROUS_ARG_PATTERNS = [
    "rm -rf", "DROP TABLE", "DELETE FROM", "--force",
    "sudo", "chmod 777", "curl | bash", "eval(",
]

# Tools that should always be flagged
_HIGH_RISK_TOOLS = {
    "bash", "shell", "execute_command", "run_terminal_command",
    "computer_use", "browser_use",
}


class MCPToolCallMapper:
    """Maps MCP tool calls to Guardian ActionRequests."""

    def map_tool_call(
        self,
        tool_call: MCPToolCall,
        actor_name: str | None = None,
    ) -> GuardianActionRequest:
        # Resolve actor
        resolved_actor = actor_name or self._resolve_actor(tool_call)

        # Resolve actor type
        actor_type = ActorType.ai_agent  # MCP calls are always from agents

        # Classify the tool call
        mapping = self._classify_tool(tool_call)

        # Check for dangerous argument patterns
        if self._has_dangerous_args(tool_call):
            mapping["sensitivity"] = SensitivityLevel.restricted
            mapping["privilege"] = PrivilegeLevel.admin

        # Build target
        target_system = tool_call.tool_server or "mcp-server"
        target_asset = f"mcp/{tool_call.tool_name}"
        if tool_call.resource_uri:
            target_asset = f"mcp/{tool_call.tool_name}/{tool_call.resource_uri}"

        # Build context
        context_parts = [
            f"MCP tool_call: {tool_call.tool_name}",
        ]
        if tool_call.agent_framework:
            context_parts.append(f"framework={tool_call.agent_framework}")
        if tool_call.parent_agent_id:
            context_parts.append(f"delegated_from={tool_call.parent_agent_id}")
        if tool_call.tool_name in _HIGH_RISK_TOOLS:
            context_parts.append("HIGH_RISK_TOOL")
        if self._has_dangerous_args(tool_call):
            context_parts.append("DANGEROUS_ARGUMENTS_DETECTED")

        # Summarize arguments (truncated, no secrets)
        arg_summary = self._safe_arg_summary(tool_call.arguments)
        if arg_summary:
            context_parts.append(f"args={arg_summary}")

        return GuardianActionRequest(
            actor_name=resolved_actor,
            actor_type=actor_type,
            requested_action=mapping["action"],
            target_system=target_system,
            target_asset=target_asset,
            privilege_level=mapping["privilege"],
            sensitivity_level=mapping["sensitivity"],
            business_context="; ".join(context_parts),
            timestamp=datetime.now(timezone.utc),
        )

    def _resolve_actor(self, tool_call: MCPToolCall) -> str:
        """Derive actor name from MCP context."""
        if tool_call.agent_id:
            prefix = tool_call.agent_framework or "mcp"
            return f"{prefix}-{tool_call.agent_id}"
        return f"mcp-unknown-agent-{tool_call.session_id or 'nosession'}"

    def _classify_tool(self, tool_call: MCPToolCall) -> dict:
        """Classify a tool call based on name patterns."""
        tool_lower = tool_call.tool_name.lower()

        # Check high-risk tools first
        if tool_lower in _HIGH_RISK_TOOLS:
            return {
                "action": "change_configuration",
                "sensitivity": SensitivityLevel.restricted,
                "privilege": PrivilegeLevel.admin,
            }

        # Check patterns
        for patterns, mapping in _TOOL_RISK_PATTERNS:
            if any(p in tool_lower for p in patterns):
                return dict(mapping)

        # Default: moderate risk for unknown tools
        return {
            "action": "change_configuration",
            "sensitivity": SensitivityLevel.internal,
            "privilege": PrivilegeLevel.standard,
        }

    def _has_dangerous_args(self, tool_call: MCPToolCall) -> bool:
        """Check if tool arguments contain dangerous patterns."""
        args_str = str(tool_call.arguments).lower()
        return any(pattern.lower() in args_str for pattern in _DANGEROUS_ARG_PATTERNS)

    def _safe_arg_summary(self, arguments: dict, max_len: int = 200) -> str:
        """Summarize arguments without exposing secrets."""
        if not arguments:
            return ""
        safe = {}
        for k, v in arguments.items():
            k_lower = k.lower()
            if any(s in k_lower for s in ("secret", "password", "token", "key", "credential")):
                safe[k] = "[REDACTED]"
            elif isinstance(v, str) and len(v) > 50:
                safe[k] = v[:47] + "..."
            else:
                safe[k] = v
        summary = str(safe)
        return summary[:max_len] if len(summary) > max_len else summary
