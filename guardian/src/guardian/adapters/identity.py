"""
Adapter-Derived Actor Identity

Prevents actor spoofing by deriving the actor identity from the authenticated
session rather than trusting the caller's claim. Each adapter resolves the
actor identity from platform-specific authentication context.

This is a critical security boundary: the actor_name in an ActionRequest
should come from the adapter (which knows the authenticated principal),
not from the request payload (which can be forged).
"""

from __future__ import annotations

import logging
from abc import ABC, abstractmethod
from dataclasses import dataclass
from typing import Optional

logger = logging.getLogger(__name__)


@dataclass
class ResolvedIdentity:
    """Actor identity as resolved from the adapter's authentication context."""
    actor_name: str
    actor_source: str              # e.g., "terraform_workspace", "k8s_serviceaccount"
    authenticated: bool = True     # False if identity could not be verified
    raw_principal: str = ""        # the original principal string from the platform
    confidence: float = 1.0        # [0.0, 1.0] — how confident the adapter is


class IdentityResolver(ABC):
    """
    Interface for adapter-specific identity resolution.

    Each adapter implements this to extract actor identity from its
    platform's authentication mechanism.
    """

    @abstractmethod
    def resolve(self, request_context: dict) -> ResolvedIdentity:
        """
        Resolve actor identity from the request's authentication context.

        The request_context contains platform-specific fields:
          - Terraform: workspace_name, run_created_by, organization_name
          - Kubernetes: serviceaccount, namespace, pod_name
          - GitHub: app_installation_id, sender_login
        """
        ...


class TerraformIdentityResolver(IdentityResolver):
    """
    Resolve actor identity from Terraform Cloud run task context.

    Identity is derived from the workspace service account and the
    user who triggered the run. The workspace name is used as the
    primary actor identity since it represents the automation context.
    """

    def resolve(self, request_context: dict) -> ResolvedIdentity:
        workspace = request_context.get("workspace_name", "")
        org = request_context.get("organization_name", "")
        triggered_by = request_context.get("run_created_by", "")

        if workspace:
            actor_name = f"terraform-{org}-{workspace}" if org else f"terraform-{workspace}"
        elif triggered_by:
            actor_name = triggered_by
        else:
            return ResolvedIdentity(
                actor_name="unknown-terraform-actor",
                actor_source="terraform_workspace",
                authenticated=False,
                confidence=0.0,
            )

        return ResolvedIdentity(
            actor_name=actor_name,
            actor_source="terraform_workspace",
            authenticated=True,
            raw_principal=f"workspace={workspace} triggered_by={triggered_by}",
            confidence=1.0 if workspace else 0.7,
        )


class KubernetesIdentityResolver(IdentityResolver):
    """
    Resolve actor identity from Kubernetes admission webhook context.

    Identity comes from the authenticated ServiceAccount in the
    AdmissionReview request.
    """

    def resolve(self, request_context: dict) -> ResolvedIdentity:
        sa = request_context.get("service_account", "")
        namespace = request_context.get("namespace", "")
        username = request_context.get("username", "")

        if sa and namespace:
            actor_name = f"k8s-{namespace}-{sa}"
        elif username:
            actor_name = username
        else:
            return ResolvedIdentity(
                actor_name="unknown-k8s-actor",
                actor_source="k8s_serviceaccount",
                authenticated=False,
                confidence=0.0,
            )

        return ResolvedIdentity(
            actor_name=actor_name,
            actor_source="k8s_serviceaccount",
            authenticated=True,
            raw_principal=f"sa={sa} ns={namespace} user={username}",
            confidence=1.0 if sa else 0.5,
        )


class DirectIdentityResolver(IdentityResolver):
    """
    Pass-through resolver for the direct /v1/evaluate API.

    Trusts the caller's claimed identity but marks it as lower confidence.
    In production, this should be replaced with mTLS or JWT-based resolution.
    """

    def resolve(self, request_context: dict) -> ResolvedIdentity:
        actor_name = request_context.get("actor_name", "")
        if not actor_name:
            return ResolvedIdentity(
                actor_name="unknown",
                actor_source="direct_api",
                authenticated=False,
                confidence=0.0,
            )

        return ResolvedIdentity(
            actor_name=actor_name,
            actor_source="direct_api",
            authenticated=True,
            raw_principal=actor_name,
            confidence=0.5,  # caller-asserted, not adapter-verified
        )
