"""
A2A (Agent-to-Agent) Protocol Adapter — Agent Delegation Governance

Intercepts A2A task delegation messages between AI agents.
Evaluates whether Agent A should be allowed to delegate a task
to Agent B, tracking the delegation chain for cascade analysis.

A2A is Google's protocol (now under Linux Foundation AAIF) for
agent-to-agent communication. Guardian governs the trust boundary
between agents — preventing unauthorized delegation, privilege
escalation through delegation chains, and cascading failures.
"""
