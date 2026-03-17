"""
A2A Adapter models.

Models the A2A protocol messages: task delegation, status updates,
and agent discovery that Guardian intercepts.
"""

from __future__ import annotations

from pydantic import BaseModel, Field


class A2ATaskDelegation(BaseModel):
    """
    An A2A task delegation message.

    Represents one agent asking another agent to perform a task.
    Guardian evaluates this before the receiving agent accepts.
    """
    # Message envelope
    message_id: str = ""
    method: str = "tasks/send"

    # Sender (delegating agent)
    sender_agent_id: str = Field(..., min_length=1)
    sender_agent_name: str = ""
    sender_agent_url: str = ""

    # Receiver (delegated-to agent)
    receiver_agent_id: str = Field(..., min_length=1)
    receiver_agent_name: str = ""
    receiver_agent_url: str = ""
    receiver_capabilities: list[str] = Field(default_factory=list)

    # Task details
    task_id: str = ""
    task_type: str = ""                     # e.g., "code_review", "deploy", "data_query"
    task_description: str = ""
    task_input: dict = Field(default_factory=dict)

    # Delegation chain context
    delegation_depth: int = 0               # how many hops from the original human request
    delegation_chain: list[str] = Field(default_factory=list)  # ordered list of agent IDs
    original_requester: str = ""            # the human/system that started the chain

    # Permissions requested
    requested_permissions: list[str] = Field(default_factory=list)
    requested_tools: list[str] = Field(default_factory=list)


class A2AEvaluation(BaseModel):
    """Guardian's evaluation of an A2A delegation."""
    allowed: bool
    decision: str
    risk_score: float
    explanation: str
    entry_id: str
    delegation_depth: int = 0
    chain_risk: str = ""                    # "low", "medium", "high", "critical"
    circuit_breaker_tripped: bool = False
