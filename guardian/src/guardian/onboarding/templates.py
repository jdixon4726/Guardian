"""
Industry Templates — Pre-configured risk postures for common verticals.

Each template provides scoring weight overrides, policy presets,
and adapter recommendations specific to the industry.
"""

from __future__ import annotations

from guardian.onboarding.models import IndustryTemplate


# Scoring weight overrides per industry
INDUSTRY_SCORING = {
    IndustryTemplate.healthcare: {
        "action_category_scores": {
            "destructive": 0.95,
            "security_control": 0.90,
            "data_exfil": 0.90,
            "privilege": 0.75,
            "moderate": 0.50,
        },
        "actor_type_scores": {
            "ai_agent": 0.65,
            "automation": 0.40,
            "human": 0.20,
        },
        "velocity_hourly_extreme": 30,
        "velocity_hourly_high": 15,
    },
    IndustryTemplate.gov_healthcare: {
        "action_category_scores": {
            "destructive": 0.98,        # maximum — patient safety
            "security_control": 0.95,   # federal + healthcare requirement
            "data_exfil": 0.95,         # PHI + government data
            "privilege": 0.85,          # strict IAM governance
            "moderate": 0.55,
        },
        "actor_type_scores": {
            "ai_agent": 0.70,           # highest scrutiny — federal AI oversight
            "automation": 0.45,
            "human": 0.25,
        },
        "velocity_hourly_extreme": 20,  # very conservative
        "velocity_hourly_high": 10,
    },
    IndustryTemplate.fintech: {
        "action_category_scores": {
            "destructive": 0.90,
            "security_control": 0.85,
            "data_exfil": 0.95,         # financial data is highest priority
            "privilege": 0.80,          # IAM changes are critical in fintech
            "moderate": 0.45,
        },
        "actor_type_scores": {
            "ai_agent": 0.60,
            "automation": 0.35,
            "human": 0.25,              # slightly higher — insider threat concern
        },
    },
    IndustryTemplate.saas: {
        "action_category_scores": {
            "destructive": 0.85,        # slightly lower — faster iteration expected
            "security_control": 0.80,
            "data_exfil": 0.80,
            "privilege": 0.65,
            "moderate": 0.40,
        },
        "actor_type_scores": {
            "ai_agent": 0.55,
            "automation": 0.30,         # lower — heavy automation expected
            "human": 0.20,
        },
        "velocity_hourly_extreme": 100, # higher — CI/CD pipelines are fast
        "velocity_hourly_high": 40,
    },
    IndustryTemplate.government: {
        "action_category_scores": {
            "destructive": 0.95,
            "security_control": 0.95,
            "data_exfil": 0.95,
            "privilege": 0.85,
            "moderate": 0.55,
        },
        "actor_type_scores": {
            "ai_agent": 0.70,           # highest scrutiny
            "automation": 0.45,
            "human": 0.25,
        },
        "velocity_hourly_extreme": 20,  # very conservative
        "velocity_hourly_high": 10,
    },
    IndustryTemplate.general: {},  # use defaults
}

# Recommended adapters per industry
INDUSTRY_ADAPTERS = {
    IndustryTemplate.healthcare: [
        "intune", "entra_id", "aws_eventbridge", "terraform",
    ],
    IndustryTemplate.gov_healthcare: [
        "intune", "entra_id", "aws_eventbridge", "terraform", "kubernetes", "jamf",
    ],
    IndustryTemplate.fintech: [
        "aws_eventbridge", "terraform", "kubernetes", "github",
    ],
    IndustryTemplate.saas: [
        "github", "terraform", "kubernetes", "mcp", "a2a",
    ],
    IndustryTemplate.government: [
        "aws_eventbridge", "entra_id", "terraform", "kubernetes",
    ],
    IndustryTemplate.general: [
        "terraform", "kubernetes", "github",
    ],
}

# Compliance frameworks per industry
INDUSTRY_COMPLIANCE = {
    IndustryTemplate.healthcare: ["HIPAA", "NIST-800-53", "SOC2"],
    IndustryTemplate.gov_healthcare: ["HIPAA", "NIST-800-53", "FedRAMP", "FISMA", "CMMC", "SOC2"],
    IndustryTemplate.fintech: ["PCI-DSS", "SOC2", "SOX", "NIST-CSF"],
    IndustryTemplate.saas: ["SOC2", "ISO-27001", "GDPR"],
    IndustryTemplate.government: ["FedRAMP", "NIST-800-53", "FISMA", "CMMC"],
    IndustryTemplate.general: ["SOC2", "NIST-CSF"],
}

# Circuit breaker presets
INDUSTRY_CIRCUIT_BREAKER = {
    IndustryTemplate.healthcare: {"max_per_minute": 3, "max_per_hour": 10, "cooldown": 600},
    IndustryTemplate.gov_healthcare: {"max_per_minute": 2, "max_per_hour": 6, "cooldown": 900},
    IndustryTemplate.fintech: {"max_per_minute": 3, "max_per_hour": 15, "cooldown": 600},
    IndustryTemplate.saas: {"max_per_minute": 10, "max_per_hour": 50, "cooldown": 180},
    IndustryTemplate.government: {"max_per_minute": 2, "max_per_hour": 8, "cooldown": 900},
    IndustryTemplate.general: {"max_per_minute": 5, "max_per_hour": 20, "cooldown": 300},
}


def get_template(industry: IndustryTemplate) -> dict:
    """Get complete configuration template for an industry."""
    return {
        "industry": industry.value,
        "scoring_overrides": INDUSTRY_SCORING.get(industry, {}),
        "recommended_adapters": INDUSTRY_ADAPTERS.get(industry, []),
        "compliance_frameworks": INDUSTRY_COMPLIANCE.get(industry, []),
        "circuit_breaker": INDUSTRY_CIRCUIT_BREAKER.get(industry, {}),
    }


def list_templates() -> list[dict]:
    """List all available industry templates."""
    return [
        {
            "industry": t.value,
            "adapters": INDUSTRY_ADAPTERS.get(t, []),
            "compliance": INDUSTRY_COMPLIANCE.get(t, []),
        }
        for t in IndustryTemplate
    ]
