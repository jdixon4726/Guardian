"""
Guardian Configuration Model

Pydantic models for all tunable parameters. Every hardcoded constant in the
scoring, drift, trust, and decision engines is externalized here. Defaults
match the original hardcoded values so existing behavior is preserved when
no guardian.yaml is provided.
"""

from __future__ import annotations

from pydantic import BaseModel, Field


class ScoringConfig(BaseModel):
    """Weights and action category definitions for the Risk Scoring Engine."""

    weights: dict[str, float] = Field(default_factory=lambda: {
        "action": 0.30,
        "actor": 0.25,
        "asset": 0.25,
        "context": 0.20,
    })

    action_categories: dict[str, list[str]] = Field(default_factory=lambda: {
        "destructive": [
            "delete_resource", "destroy_infrastructure", "drop_database",
            "wipe_storage", "terminate_instances", "delete_vpc",
            "wipe_device", "retire_device", "delete_device",
        ],
        "security_control": [
            "disable_endpoint_protection", "disable_antivirus", "disable_edr",
            "modify_security_policy", "remove_security_tool", "disable_firewall",
        ],
        "privilege": [
            "modify_iam_role", "escalate_privileges", "grant_admin_access",
            "add_user_to_group", "create_service_account",
        ],
        "data_exfil": [
            "export_data", "download_pii", "copy_database", "backup_to_external",
        ],
        "moderate": [
            "modify_firewall_rule", "modify_security_group", "update_network_acl",
            "change_configuration", "restart_service",
        ],
    })

    action_category_scores: dict[str, float] = Field(default_factory=lambda: {
        "destructive": 0.90,
        "security_control": 0.85,
        "privilege": 0.70,
        "data_exfil": 0.75,
        "moderate": 0.45,
    })

    baseline_action_score: float = 0.20

    # Actor type baseline scores
    actor_type_scores: dict[str, float] = Field(default_factory=lambda: {
        "ai_agent": 0.55,
        "automation": 0.35,
        "human": 0.20,
    })

    # Criticality and sensitivity weights for asset scoring
    criticality_weights: dict[str, float] = Field(default_factory=lambda: {
        "low": 0.1, "medium": 0.3, "high": 0.6, "critical": 0.9,
    })

    sensitivity_weights: dict[str, float] = Field(default_factory=lambda: {
        "public": 0.0, "internal": 0.2, "confidential": 0.6,
        "high": 0.7, "restricted": 0.9,
    })

    # Velocity thresholds for context scoring
    velocity_hourly_extreme: int = 50
    velocity_hourly_high: int = 20
    velocity_daily_high: int = 200


class TrustConfig(BaseModel):
    """Parameters for the actor trust level model."""

    min_actions: int = 10
    block_penalty: float = 0.05
    review_penalty: float = 0.02
    allow_bonus: float = 0.005
    window_days: int = 30


class DriftConfig(BaseModel):
    """Thresholds for the Drift Detection Engine."""

    z_score_alert_threshold: float = 2.5
    z_score_warn_threshold: float = 2.0
    js_alert_threshold: float = 0.35
    js_warn_threshold: float = 0.20
    regularity_threshold: float = 0.10
    min_observations: int = 5
    stddev_floor: float = 0.01


class DecisionConfig(BaseModel):
    """Risk band thresholds for the Decision Engine."""

    low_max: float = 0.30
    medium_max: float = 0.60
    high_max: float = 0.80


class PolicyProviderConfig(BaseModel):
    """Configuration for the policy evaluation provider."""

    provider: str = "builtin"      # "builtin" or "opa"
    opa_url: str | None = None
    opa_policy_path: str = "guardian/evaluate"
    opa_timeout_seconds: float = 5.0
    opa_fallback: str = "block"    # "block" or "builtin"


class CircuitBreakerConfig(BaseModel):
    """Configuration for the per-actor circuit breaker."""

    enabled: bool = True
    max_destructive_per_minute: int = 5
    max_destructive_per_hour: int = 20
    cooldown_seconds: int = 300
    destructive_actions: list[str] = Field(default_factory=lambda: [
        "destroy_infrastructure", "delete_resource", "drop_database",
        "wipe_storage", "terminate_instances", "delete_vpc",
        "wipe_device", "retire_device", "delete_device",
        "remote_wipe", "factory_reset",
    ])


class IntuneAdapterConfig(BaseModel):
    """Configuration for the Intune proxy adapter."""

    enabled: bool = False
    graph_api_base: str = "https://graph.microsoft.com/v1.0"
    timeout_seconds: float = 30.0
    intercepted_actions: list[str] = Field(default_factory=lambda: [
        "wipe", "retire", "delete", "resetPasscode",
    ])
    passthrough_actions: list[str] = Field(default_factory=lambda: [
        "syncDevice", "rebootNow",
    ])


class GuardianConfig(BaseModel):
    """Master configuration for the Guardian engine."""

    scoring: ScoringConfig = Field(default_factory=ScoringConfig)
    trust: TrustConfig = Field(default_factory=TrustConfig)
    drift: DriftConfig = Field(default_factory=DriftConfig)
    decision: DecisionConfig = Field(default_factory=DecisionConfig)
    policy: PolicyProviderConfig = Field(default_factory=PolicyProviderConfig)
    circuit_breaker: CircuitBreakerConfig = Field(default_factory=CircuitBreakerConfig)
    intune: IntuneAdapterConfig = Field(default_factory=IntuneAdapterConfig)
