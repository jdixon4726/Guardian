"""
MCP (Model Context Protocol) Adapter — Agent-to-Tool Governance

Intercepts MCP tool_call messages from AI agents, evaluates through
Guardian's pipeline before the tool executes, and returns allow/deny.

MCP is the emerging standard (Anthropic, Linux Foundation AAIF) for
agent-to-tool communication. By sitting at this protocol layer,
Guardian governs every tool invocation regardless of which agent
framework (CrewAI, LangGraph, AutoGen, OpenClaw) initiated it.

Integration patterns:
  1. MCP Proxy — Guardian sits between agent and MCP server
  2. MCP Middleware — Guardian registers as an MCP middleware/interceptor
  3. MCP Audit — Guardian consumes MCP tool_call events post-execution
"""
