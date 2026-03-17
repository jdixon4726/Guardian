"""
Intune Graph API Proxy

Forwards allowed device management actions to the real Microsoft Graph API.
Blocked actions are never forwarded — the caller gets Guardian's deny response.

This is the enforcement mechanism. Unlike K8s (admission webhook) or
Terraform (callback), Intune has no pre-execution hook. Guardian IS
the enforcement point.
"""

from __future__ import annotations

import logging
from dataclasses import dataclass

import httpx

logger = logging.getLogger(__name__)

GRAPH_API_BASE = "https://graph.microsoft.com/v1.0"

# Graph API endpoints for device actions
_ACTION_ENDPOINTS: dict[str, str] = {
    "wipe": "/deviceManagement/managedDevices/{device_id}/wipe",
    "retire": "/deviceManagement/managedDevices/{device_id}/retire",
    "delete": "/deviceManagement/managedDevices/{device_id}",
    "resetPasscode": "/deviceManagement/managedDevices/{device_id}/resetPasscode",
    "disableLostMode": "/deviceManagement/managedDevices/{device_id}/disableLostMode",
    "remoteLock": "/deviceManagement/managedDevices/{device_id}/remoteLock",
    "shutDown": "/deviceManagement/managedDevices/{device_id}/shutDown",
    "rebootNow": "/deviceManagement/managedDevices/{device_id}/rebootNow",
    "syncDevice": "/deviceManagement/managedDevices/{device_id}/syncDevice",
}

# HTTP method per action (most are POST, delete is DELETE)
_ACTION_METHODS: dict[str, str] = {
    "delete": "DELETE",
}


@dataclass
class ProxyResult:
    """Result of forwarding an action to the real Graph API."""
    status_code: int
    body: dict | str
    forwarded: bool = True


class IntuneProxy:
    """
    Forwards allowed actions to Microsoft Graph API.

    The caller's original Bearer token is passed through — Guardian
    never stores or caches Azure AD tokens.
    """

    def __init__(self, graph_api_base: str = GRAPH_API_BASE, timeout: float = 30.0):
        self.graph_api_base = graph_api_base.rstrip("/")
        self.timeout = timeout

    async def forward(
        self,
        device_id: str,
        action: str,
        authorization: str,
        body: dict | None = None,
    ) -> ProxyResult:
        """
        Forward an allowed action to the real Graph API.

        Args:
            device_id: Intune managed device ID
            action: Graph action name (wipe, retire, etc.)
            authorization: Full Authorization header (Bearer ...)
            body: Optional request body for the action
        """
        endpoint_template = _ACTION_ENDPOINTS.get(action)
        if not endpoint_template:
            return ProxyResult(
                status_code=400,
                body={"error": f"Unknown action: {action}"},
                forwarded=False,
            )

        url = self.graph_api_base + endpoint_template.format(device_id=device_id)
        method = _ACTION_METHODS.get(action, "POST")

        headers = {
            "Authorization": authorization,
            "Content-Type": "application/json",
        }

        try:
            async with httpx.AsyncClient() as client:
                if method == "DELETE":
                    resp = await client.delete(url, headers=headers, timeout=self.timeout)
                else:
                    resp = await client.post(
                        url, headers=headers, json=body or {}, timeout=self.timeout,
                    )

                # Graph API returns 204 on success for most device actions
                try:
                    resp_body = resp.json() if resp.content else {}
                except Exception:
                    resp_body = resp.text

                return ProxyResult(
                    status_code=resp.status_code,
                    body=resp_body,
                )

        except httpx.TimeoutException:
            logger.error("Graph API timeout for %s on device %s", action, device_id)
            return ProxyResult(status_code=504, body={"error": "Graph API timeout"})
        except httpx.HTTPError as exc:
            logger.error("Graph API error for %s on device %s: %s", action, device_id, exc)
            return ProxyResult(
                status_code=502,
                body={"error": f"Graph API error: {exc}"},
            )
