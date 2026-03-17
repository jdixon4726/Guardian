"""
Guardian SDK — Typed Python client for the Guardian API.

Usage:
    from guardian_sdk import GuardianClient

    client = GuardianClient("https://guardian.example.com", api_key="...")

    # Evaluate an action
    decision = client.evaluate(
        actor_name="deploy-bot",
        actor_type="automation",
        action="destroy_infrastructure",
        target_system="aws-ec2",
        target_asset="prod-vpc",
    )
    print(decision.decision)     # "block"
    print(decision.risk_score)   # 0.87
    print(decision.explanation)  # "Destructive action..."

    # Check actor profile
    profile = client.get_actor_profile("deploy-bot")
    print(profile.trust_level)   # 0.72

    # Evaluate MCP tool call
    result = client.evaluate_mcp_tool_call(
        tool_name="bash",
        agent_id="my-agent",
        agent_framework="crewai",
        arguments={"command": "ls -la"},
    )
"""

from __future__ import annotations

import time
from dataclasses import dataclass, field
from datetime import datetime
from typing import Any

import httpx


@dataclass
class Decision:
    """Guardian evaluation decision."""
    decision: str              # allow, allow_with_logging, require_review, block
    risk_score: float
    risk_band: str             # low, medium, high, critical
    explanation: str
    entry_id: str
    policy_matched: str | None = None
    drift_score: float | None = None
    safer_alternatives: list[str] = field(default_factory=list)
    compliance_tags: list[str] = field(default_factory=list)
    shadow_mode: bool = False
    behavioral_risk: float | None = None
    is_anomalous: bool = False

    @property
    def allowed(self) -> bool:
        return self.decision in ("allow", "allow_with_logging")

    @property
    def blocked(self) -> bool:
        return self.decision == "block"


@dataclass
class ActorProfile:
    """Actor behavioral profile from Guardian."""
    actor_name: str
    trust_level: float = 0.5
    trust_band: str = "neutral"
    total_actions: int = 0
    total_allows: int = 0
    total_reviews: int = 0
    total_blocks: int = 0
    actions_last_hour: int = 0
    actions_last_day: int = 0
    history_days: int = 0
    first_seen: str | None = None
    last_seen: str | None = None
    top_actions: dict[str, int] = field(default_factory=dict)


@dataclass
class MCPToolResult:
    """Result of MCP tool call evaluation."""
    allowed: bool
    decision: str
    risk_score: float
    explanation: str
    entry_id: str
    tool_name: str = ""
    circuit_breaker_tripped: bool = False


@dataclass
class HealthStatus:
    """Guardian system health."""
    status: str
    version: str
    shadow_mode: bool
    components: dict[str, str] = field(default_factory=dict)


class GuardianError(Exception):
    """Raised when the Guardian API returns an error."""
    def __init__(self, status_code: int, detail: str):
        self.status_code = status_code
        self.detail = detail
        super().__init__(f"Guardian API error {status_code}: {detail}")


class GuardianClient:
    """
    Typed Python client for the Guardian API.

    Handles authentication, retries, and response parsing.

    Args:
        base_url: Guardian API base URL (e.g., "https://guardian.example.com")
        api_key: API key for Bearer authentication (optional in dev mode)
        timeout: Request timeout in seconds (default: 30)
        max_retries: Number of retries on transient failures (default: 3)
    """

    def __init__(
        self,
        base_url: str,
        api_key: str = "",
        timeout: float = 30.0,
        max_retries: int = 3,
    ):
        self.base_url = base_url.rstrip("/")
        self.api_key = api_key
        self.timeout = timeout
        self.max_retries = max_retries

    def _headers(self) -> dict[str, str]:
        headers = {"Content-Type": "application/json"}
        if self.api_key:
            headers["Authorization"] = f"Bearer {self.api_key}"
        return headers

    def _request(self, method: str, path: str, **kwargs) -> dict:
        """Make an HTTP request with retry logic."""
        url = f"{self.base_url}{path}"
        headers = self._headers()

        for attempt in range(self.max_retries):
            try:
                with httpx.Client(timeout=self.timeout) as client:
                    if method == "GET":
                        resp = client.get(url, headers=headers, params=kwargs.get("params"))
                    elif method == "POST":
                        resp = client.post(url, headers=headers, json=kwargs.get("json"))
                    else:
                        raise ValueError(f"Unsupported method: {method}")

                    if resp.status_code == 429:
                        # Rate limited — wait and retry
                        wait = min(2 ** attempt, 10)
                        time.sleep(wait)
                        continue

                    if resp.status_code >= 400:
                        raise GuardianError(resp.status_code, resp.text)

                    return resp.json()

            except httpx.TimeoutException:
                if attempt == self.max_retries - 1:
                    raise
                time.sleep(1)
            except httpx.ConnectError:
                if attempt == self.max_retries - 1:
                    raise
                time.sleep(2 ** attempt)

        raise GuardianError(0, "Max retries exceeded")

    # ── Core evaluation ──────────────────────────────────────────────

    def evaluate(
        self,
        actor_name: str,
        actor_type: str = "automation",
        action: str = "change_configuration",
        target_system: str = "unknown",
        target_asset: str = "unknown",
        privilege_level: str = "standard",
        sensitivity_level: str = "internal",
        business_context: str = "",
        timestamp: str | None = None,
    ) -> Decision:
        """
        Submit an action request for governance evaluation.

        Returns a Decision with the verdict, risk score, explanation,
        and compliance tags.
        """
        from datetime import datetime, timezone
        payload = {
            "actor_name": actor_name,
            "actor_type": actor_type,
            "requested_action": action,
            "target_system": target_system,
            "target_asset": target_asset,
            "privilege_level": privilege_level,
            "sensitivity_level": sensitivity_level,
            "business_context": business_context,
            "timestamp": timestamp or datetime.now(timezone.utc).isoformat(),
        }
        data = self._request("POST", "/v1/evaluate", json=payload)
        return Decision(**{k: v for k, v in data.items() if k in Decision.__dataclass_fields__})

    # ── Actor intelligence ───────────────────────────────────────────

    def get_actor_profile(self, actor_name: str) -> ActorProfile:
        """Get an actor's behavioral profile, trust level, and velocity."""
        data = self._request("GET", f"/v1/actors/{actor_name}/profile")
        return ActorProfile(**{k: v for k, v in data.items() if k in ActorProfile.__dataclass_fields__})

    # ── MCP tool call governance ─────────────────────────────────────

    def evaluate_mcp_tool_call(
        self,
        tool_name: str,
        agent_id: str = "",
        agent_framework: str = "",
        session_id: str = "",
        arguments: dict | None = None,
        resource_uri: str = "",
    ) -> MCPToolResult:
        """
        Evaluate an MCP tool call before the tool server processes it.

        Use this to gate AI agent tool invocations through Guardian.
        """
        payload = {
            "tool_name": tool_name,
            "agent_id": agent_id,
            "agent_framework": agent_framework,
            "session_id": session_id,
            "arguments": arguments or {},
            "resource_uri": resource_uri,
        }
        data = self._request("POST", "/v1/mcp/evaluate-tool-call", json=payload)
        return MCPToolResult(**{k: v for k, v in data.items() if k in MCPToolResult.__dataclass_fields__})

    # ── Threat intelligence ──────────────────────────────────────────

    def sync_threat_feeds(self) -> dict:
        """Sync CISA KEV threat feed and create risk overlays."""
        return self._request("POST", "/v1/threat-intel/sync", json={})

    def list_overlays(self, status: str = "") -> list[dict]:
        """List threat intelligence risk overlays."""
        params = {"status": status} if status else None
        return self._request("GET", "/v1/threat-intel/overlays", params=params)

    def activate_overlay(self, overlay_id: str) -> dict:
        """Approve and activate a pending risk overlay."""
        return self._request("POST", f"/v1/threat-intel/overlays/{overlay_id}/activate", json={})

    # ── System status ────────────────────────────────────────────────

    def health(self) -> HealthStatus:
        """Check Guardian system health."""
        data = self._request("GET", "/v1/health")
        return HealthStatus(**{k: v for k, v in data.items() if k in HealthStatus.__dataclass_fields__})

    def system_status(self) -> dict:
        """Get system observability metrics."""
        return self._request("GET", "/v1/system/status")

    def connected_systems(self) -> list[dict]:
        """Get status of all connected adapter systems."""
        return self._request("GET", "/v1/systems/connected")

    # ── Convenience ──────────────────────────────────────────────────

    def is_healthy(self) -> bool:
        """Quick health check — returns True if Guardian is operational."""
        try:
            h = self.health()
            return h.status == "ok"
        except Exception:
            return False
