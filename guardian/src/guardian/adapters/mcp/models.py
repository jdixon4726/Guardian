"""
MCP Adapter models.

Models the MCP tool_call and tool_result messages that Guardian
intercepts at the protocol layer.
"""

from __future__ import annotations

from pydantic import BaseModel, Field


class MCPToolCall(BaseModel):
    """
    An MCP tool_call message intercepted by Guardian.

    Represents an AI agent requesting to invoke a tool via MCP.
    Guardian evaluates this before the tool server processes it.
    """
    # MCP message envelope
    message_id: str = ""
    method: str = "tools/call"              # MCP method

    # Tool identification
    tool_name: str = Field(..., min_length=1)
    tool_server: str = ""                   # MCP server name/URI

    # Agent context
    agent_id: str = ""                      # agent identity
    agent_framework: str = ""               # crewai, langgraph, autogen, openclaw, etc.
    session_id: str = ""                    # conversation/session ID
    parent_agent_id: str = ""               # if delegated from another agent

    # Tool call parameters
    arguments: dict = Field(default_factory=dict)

    # Optional: resource context from MCP
    resource_uri: str = ""                  # MCP resource being accessed
    resource_mime_type: str = ""


class MCPToolResult(BaseModel):
    """MCP tool_result — returned after Guardian evaluation."""
    allowed: bool
    decision: str
    risk_score: float
    explanation: str
    entry_id: str
    tool_name: str = ""
    # If allowed and proxy mode, the original tool result is included
    tool_output: dict | str | None = None
    circuit_breaker_tripped: bool = False


class MCPAgentIdentity(BaseModel):
    """Identity of the MCP agent making the tool call."""
    agent_id: str
    agent_framework: str = ""
    agent_name: str = ""
    agent_owner: str = ""
    session_id: str = ""
    # Trust context
    is_delegated: bool = False              # agent was invoked by another agent
    delegation_chain: list[str] = Field(default_factory=list)  # parent agent chain
    tool_permissions: list[str] = Field(default_factory=list)  # allowed tools
