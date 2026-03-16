"""
Archetype Baselines — pre-built behavioral profiles for common machine actors.

Solves the cold-start problem: new actors immediately inherit a behavioral
profile from their archetype, providing day-one detection capability instead
of waiting 30 days for baselines to build.

Each archetype defines:
  - Expected action families (what this actor type normally does)
  - Expected velocity bands (how often this actor type normally acts)
  - Expected systems (what platforms this actor type normally touches)
  - Expected time patterns (when this actor type normally operates)
  - Risk tolerance (how sensitive anomaly detection should be)
  - Bayesian priors (alpha, beta for confidence scoring)
"""

from __future__ import annotations

from dataclasses import dataclass, field


@dataclass
class ArchetypeBaseline:
    """Pre-built behavioral archetype for a class of machine actors."""
    archetype_id: str
    name: str
    description: str
    actor_type: str                         # automation | ai_agent | human

    # Expected behavior
    expected_action_families: list[str]
    expected_systems: list[str]
    expected_velocity_band: str             # low | medium | high | burst
    expected_hours: tuple[int, int]         # (start_hour, end_hour) UTC — (0, 24) = any time

    # Risk parameters
    risk_tolerance: float                   # [0.0, 1.0] — lower = more sensitive
    drift_sensitivity: float                # multiplier on drift thresholds
    bayesian_prior: tuple[float, float]     # (alpha, beta) for BayesianConfidenceScorer

    # Matching criteria (how to assign this archetype to an actor)
    name_patterns: list[str] = field(default_factory=list)  # glob patterns for actor_name
    system_patterns: list[str] = field(default_factory=list)  # systems this archetype operates in

    @property
    def velocity_range(self) -> tuple[int, int]:
        """Expected hourly action range for this archetype."""
        bands = {
            "low": (0, 5),
            "medium": (5, 50),
            "high": (50, 500),
            "burst": (0, 1000),   # burst actors have unpredictable velocity
        }
        return bands.get(self.expected_velocity_band, (0, 50))


# ── Built-in archetypes ──────────────────────────────────────────────────────

TERRAFORM_RUNNER = ArchetypeBaseline(
    archetype_id="archetype:terraform-runner",
    name="Terraform Cloud Runner",
    description="Standard IaC automation that plans and applies infrastructure changes. "
                "Operates in bursts during deployment windows. Touches cloud provider resources.",
    actor_type="automation",
    expected_action_families=["infrastructure_change", "configuration_change"],
    expected_systems=["terraform-cloud", "aws", "azure", "gcp"],
    expected_velocity_band="burst",
    expected_hours=(0, 24),  # runs any time (triggered by CI)
    risk_tolerance=0.5,
    drift_sensitivity=1.0,
    bayesian_prior=(2.0, 4.0),  # slightly optimistic
    name_patterns=["terraform*", "tf-*", "*-terraform", "tfc-*"],
    system_patterns=["terraform-cloud", "terraform"],
)

GITHUB_ACTIONS_BOT = ArchetypeBaseline(
    archetype_id="archetype:github-actions",
    name="GitHub Actions Bot",
    description="CI/CD automation triggered by code pushes, PRs, and schedules. "
                "High velocity during work hours. Primarily triggers downstream automation.",
    actor_type="automation",
    expected_action_families=["infrastructure_change", "configuration_change", "operational"],
    expected_systems=["github", "github-actions"],
    expected_velocity_band="high",
    expected_hours=(6, 22),  # primarily during work hours
    risk_tolerance=0.4,
    drift_sensitivity=1.0,
    bayesian_prior=(2.0, 5.0),  # optimistic — CI bots are well-understood
    name_patterns=["github-actions*", "gha-*", "ci-*", "*-ci"],
    system_patterns=["github", "github-actions"],
)

ARGOCD_CONTROLLER = ArchetypeBaseline(
    archetype_id="archetype:argocd",
    name="ArgoCD Controller",
    description="GitOps continuous delivery controller. Syncs desired state from git to Kubernetes. "
                "Steady velocity, primarily targets K8s resources.",
    actor_type="automation",
    expected_action_families=["infrastructure_change", "configuration_change"],
    expected_systems=["kubernetes", "k8s", "argocd"],
    expected_velocity_band="medium",
    expected_hours=(0, 24),  # continuous sync
    risk_tolerance=0.5,
    drift_sensitivity=0.8,  # ArgoCD has natural variation
    bayesian_prior=(2.0, 5.0),
    name_patterns=["argocd*", "argo-*", "*-argocd"],
    system_patterns=["kubernetes", "k8s", "argocd"],
)

DATADOG_AGENT = ArchetypeBaseline(
    archetype_id="archetype:datadog-agent",
    name="Datadog Agent",
    description="Monitoring and observability agent. Primarily read operations and metric collection. "
                "Very high velocity, extremely regular patterns.",
    actor_type="automation",
    expected_action_families=["operational", "read_access"],
    expected_systems=["datadog", "monitoring"],
    expected_velocity_band="high",
    expected_hours=(0, 24),  # always running
    risk_tolerance=0.7,  # monitoring agents are low-risk
    drift_sensitivity=1.2,  # high regularity expected — detect deviations
    bayesian_prior=(1.0, 6.0),  # very optimistic
    name_patterns=["datadog*", "dd-*", "*-monitoring", "prometheus*", "grafana*"],
    system_patterns=["datadog", "monitoring", "prometheus", "grafana"],
)

K8S_CONTROLLER = ArchetypeBaseline(
    archetype_id="archetype:k8s-controller",
    name="Kubernetes Controller",
    description="Native K8s controller (HPA, VPA, ingress controller, cert-manager). "
                "Reacts to cluster state changes. Moderate velocity, targets K8s resources.",
    actor_type="automation",
    expected_action_families=["infrastructure_change", "configuration_change"],
    expected_systems=["kubernetes", "k8s"],
    expected_velocity_band="medium",
    expected_hours=(0, 24),
    risk_tolerance=0.5,
    drift_sensitivity=1.0,
    bayesian_prior=(2.0, 4.0),
    name_patterns=["k8s-*", "*-controller", "hpa-*", "cert-manager*", "ingress-*"],
    system_patterns=["kubernetes", "k8s"],
)

AI_AGENT_GENERAL = ArchetypeBaseline(
    archetype_id="archetype:ai-agent",
    name="AI Agent (General)",
    description="LLM-powered automation agent. Unpredictable action patterns. "
                "Highest risk category — requires maximum scrutiny.",
    actor_type="ai_agent",
    expected_action_families=[],  # AI agents can do anything
    expected_systems=[],          # AI agents can touch any system
    expected_velocity_band="burst",
    expected_hours=(0, 24),
    risk_tolerance=0.2,   # very sensitive — AI agents get maximum scrutiny
    drift_sensitivity=1.5,  # amplify drift detection
    bayesian_prior=(3.0, 3.0),  # neutral — no assumptions about safety
    name_patterns=["ai-*", "*-agent", "llm-*", "copilot-*", "auto-*"],
    system_patterns=[],  # matches any system
)


# ── All built-in archetypes ──────────────────────────────────────────────────

BUILTIN_ARCHETYPES: list[ArchetypeBaseline] = [
    TERRAFORM_RUNNER,
    GITHUB_ACTIONS_BOT,
    ARGOCD_CONTROLLER,
    DATADOG_AGENT,
    K8S_CONTROLLER,
    AI_AGENT_GENERAL,
]


def match_archetype(
    actor_name: str,
    actor_type: str,
    system: str | None = None,
    archetypes: list[ArchetypeBaseline] | None = None,
) -> ArchetypeBaseline | None:
    """
    Match an actor to the best archetype based on name patterns and system.

    Returns the best matching archetype, or None if no match.
    Prefers name pattern matches over system matches.
    """
    import fnmatch

    candidates = archetypes or BUILTIN_ARCHETYPES
    best_match: ArchetypeBaseline | None = None
    best_score = 0

    for archetype in candidates:
        score = 0

        # Name pattern match (strongest signal)
        for pattern in archetype.name_patterns:
            if fnmatch.fnmatch(actor_name.lower(), pattern.lower()):
                score += 3
                break

        # Actor type match
        if archetype.actor_type == actor_type:
            score += 1

        # System match
        if system and archetype.system_patterns:
            for sp in archetype.system_patterns:
                if fnmatch.fnmatch(system.lower(), sp.lower()):
                    score += 2
                    break

        if score > best_score:
            best_score = score
            best_match = archetype

    # Require at least a name or system match (score >= 2)
    if best_score >= 2:
        return best_match
    return None
