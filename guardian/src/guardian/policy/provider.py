"""
Policy Provider Protocol

Defines the interface that any policy evaluation backend must implement.
The built-in PolicyEngine and the OPA adapter both satisfy this protocol.

Using a Protocol (structural subtyping) means external policy providers
don't need to import or inherit from Guardian's base class.
"""

from __future__ import annotations

from typing import Protocol, runtime_checkable

from guardian.policy.engine import PolicyVerdict


@runtime_checkable
class PolicyProvider(Protocol):
    """Interface for policy evaluation backends."""

    def evaluate(self, context: dict) -> PolicyVerdict:
        """Evaluate a policy context and return a verdict."""
        ...

    def health_check(self) -> bool:
        """Return True if the provider is operational."""
        ...
