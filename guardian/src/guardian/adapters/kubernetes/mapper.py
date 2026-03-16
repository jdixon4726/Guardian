"""
Kubernetes AdmissionReview → ActionRequest Mapper

Converts Kubernetes admission webhook requests into Guardian ActionRequests.
Maps K8s resource types, operations, and security-sensitive fields to
Guardian's action taxonomy.
"""

from __future__ import annotations

import logging
from datetime import datetime, timezone

from guardian.adapters.kubernetes.models import AdmissionRequest
from guardian.models.action_request import (
    ActionRequest as GuardianActionRequest,
    ActorType,
    PrivilegeLevel,
    SensitivityLevel,
)

logger = logging.getLogger(__name__)

# K8s resource → Guardian action mapping
_RESOURCE_ACTION_MAP = {
    ("", "pods", "CREATE"): "change_configuration",
    ("", "pods", "DELETE"): "destroy_infrastructure",
    ("", "secrets", "CREATE"): "change_configuration",
    ("", "secrets", "UPDATE"): "modify_security_policy",
    ("", "secrets", "DELETE"): "destroy_infrastructure",
    ("", "configmaps", "UPDATE"): "change_configuration",
    ("", "services", "CREATE"): "change_configuration",
    ("", "services", "DELETE"): "destroy_infrastructure",
    ("apps", "deployments", "CREATE"): "change_configuration",
    ("apps", "deployments", "UPDATE"): "change_configuration",
    ("apps", "deployments", "DELETE"): "destroy_infrastructure",
    ("rbac.authorization.k8s.io", "clusterroles", "CREATE"): "modify_iam_role",
    ("rbac.authorization.k8s.io", "clusterroles", "UPDATE"): "modify_iam_role",
    ("rbac.authorization.k8s.io", "clusterrolebindings", "CREATE"): "grant_admin_access",
    ("rbac.authorization.k8s.io", "clusterrolebindings", "UPDATE"): "grant_admin_access",
    ("rbac.authorization.k8s.io", "roles", "CREATE"): "modify_iam_role",
    ("rbac.authorization.k8s.io", "roles", "UPDATE"): "modify_iam_role",
    ("rbac.authorization.k8s.io", "rolebindings", "CREATE"): "add_user_to_group",
    ("networking.k8s.io", "networkpolicies", "CREATE"): "modify_firewall_rule",
    ("networking.k8s.io", "networkpolicies", "UPDATE"): "modify_firewall_rule",
    ("networking.k8s.io", "networkpolicies", "DELETE"): "disable_firewall",
}

# Sensitive namespaces
_SENSITIVE_NAMESPACES = {"kube-system", "kube-public", "istio-system", "cert-manager"}


class KubernetesAdmissionMapper:
    """Maps K8s AdmissionReview requests to Guardian ActionRequests."""

    def map_admission(
        self, admission: AdmissionRequest,
    ) -> GuardianActionRequest:
        """Convert a K8s admission request to a Guardian ActionRequest."""
        resource = admission.resource
        operation = admission.operation

        # Resolve actor identity from K8s user info
        username = admission.userInfo.username
        groups = admission.userInfo.groups
        actor_name = self._resolve_actor(username, admission.namespace)
        actor_type = self._resolve_actor_type(username, groups)

        # Resolve Guardian action
        key = (resource.group, resource.resource, operation)
        action = _RESOURCE_ACTION_MAP.get(key, "change_configuration")

        # Override to destroy for all DELETEs not explicitly mapped
        if operation == "DELETE" and action == "change_configuration":
            action = "destroy_infrastructure"

        # Resolve sensitivity and privilege
        sensitivity = self._resolve_sensitivity(admission)
        privilege = self._resolve_privilege(admission, action)

        # Build target asset identifier
        obj_meta = {}
        if admission.object:
            obj_meta = admission.object.metadata
        name = obj_meta.get("name", "unknown")
        target_asset = f"{admission.namespace}/{resource.resource}/{name}"

        return GuardianActionRequest(
            actor_name=actor_name,
            actor_type=actor_type,
            requested_action=action,
            target_system=f"k8s-{admission.namespace}",
            target_asset=target_asset,
            privilege_level=privilege,
            sensitivity_level=sensitivity,
            business_context=(
                f"K8s {operation} {resource.resource} "
                f"in namespace {admission.namespace}"
            ),
            timestamp=datetime.now(timezone.utc),
        )

    def _resolve_actor(self, username: str, namespace: str) -> str:
        """Derive actor name from K8s username."""
        if username.startswith("system:serviceaccount:"):
            # system:serviceaccount:namespace:name → k8s-namespace-name
            parts = username.split(":")
            if len(parts) >= 4:
                return f"k8s-{parts[2]}-{parts[3]}"
        return username or "unknown-k8s-actor"

    def _resolve_actor_type(self, username: str, groups: list[str]) -> ActorType:
        if username.startswith("system:serviceaccount:"):
            return ActorType.automation
        if "system:masters" in groups:
            return ActorType.human  # admin user
        return ActorType.human

    def _resolve_sensitivity(self, admission: AdmissionRequest) -> SensitivityLevel:
        resource = admission.resource.resource
        if admission.namespace in _SENSITIVE_NAMESPACES:
            return SensitivityLevel.restricted
        if resource in ("secrets", "clusterroles", "clusterrolebindings"):
            return SensitivityLevel.restricted
        if resource in ("roles", "rolebindings", "networkpolicies"):
            return SensitivityLevel.high
        return SensitivityLevel.internal

    def _resolve_privilege(
        self, admission: AdmissionRequest, action: str,
    ) -> PrivilegeLevel:
        if action in ("modify_iam_role", "grant_admin_access"):
            return PrivilegeLevel.admin
        if admission.namespace in _SENSITIVE_NAMESPACES:
            return PrivilegeLevel.elevated
        if admission.operation == "DELETE":
            return PrivilegeLevel.elevated
        return PrivilegeLevel.standard
