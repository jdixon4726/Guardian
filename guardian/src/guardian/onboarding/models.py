"""
Onboarding data models.
"""

from __future__ import annotations

from datetime import datetime, timezone
from enum import Enum

from pydantic import BaseModel, Field


class CloudProvider(str, Enum):
    aws = "aws"
    azure = "azure"
    gcp = "gcp"


class OnboardingPhase(str, Enum):
    not_started = "not_started"
    connecting = "connecting"       # cloud accounts being connected
    discovering = "discovering"     # passive observation in progress
    ready = "ready"                 # discovery complete, config generated
    active = "active"               # config applied, governance running


class RiskPosture(str, Enum):
    conservative = "conservative"   # block most, require review on everything
    moderate = "moderate"           # balanced — default
    permissive = "permissive"       # allow with logging, block only deny rules


class IndustryTemplate(str, Enum):
    healthcare = "healthcare"
    fintech = "fintech"
    saas = "saas"
    government = "government"
    general = "general"


class DiscoveredActor(BaseModel):
    """An actor discovered from event streams."""
    name: str
    actor_type: str = "automation"  # human, automation, ai_agent
    source: str = ""                # where discovered: cloudtrail, entra_id, k8s, etc.
    event_count: int = 0
    first_seen: str = ""
    last_seen: str = ""
    actions_observed: list[str] = Field(default_factory=list)
    systems_observed: list[str] = Field(default_factory=list)
    max_privilege_observed: str = "standard"
    recommended_max_privilege: str = "standard"


class DiscoveredAsset(BaseModel):
    """An asset discovered from event streams."""
    asset_id: str
    name: str = ""
    system: str = ""
    event_count: int = 0
    actor_count: int = 0            # how many actors touch this
    privileged_access_count: int = 0 # how many privileged actions target it
    recommended_criticality: str = "medium"
    recommended_sensitivity: str = "internal"


class DiscoveredSystem(BaseModel):
    """A system/platform discovered from event streams."""
    system_id: str
    name: str = ""
    event_count: int = 0
    actor_count: int = 0
    adapter_available: bool = False  # does Guardian have an adapter for this?
    recommended_adapter: str = ""


class DiscoveryReport(BaseModel):
    """Complete discovery report after observation period."""
    phase: OnboardingPhase = OnboardingPhase.not_started
    observation_hours: float = 0
    total_events_ingested: int = 0
    actors: list[DiscoveredActor] = Field(default_factory=list)
    assets: list[DiscoveredAsset] = Field(default_factory=list)
    systems: list[DiscoveredSystem] = Field(default_factory=list)
    recommended_risk_posture: RiskPosture = RiskPosture.moderate
    recommended_adapters: list[str] = Field(default_factory=list)
    generated_at: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))


class OnboardingStatus(BaseModel):
    """Current onboarding progress."""
    phase: OnboardingPhase
    cloud_connected: bool = False
    events_ingested: int = 0
    actors_discovered: int = 0
    assets_discovered: int = 0
    systems_discovered: int = 0
    observation_started: str = ""
    observation_hours: float = 0
    config_generated: bool = False
    config_applied: bool = False
