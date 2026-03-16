"""
Guardian Pipeline

Wires all evaluation stages into a single evaluate() call.
This is the main entry point for all action request evaluation.

Stage order:
  1. Identity Attestation  — fail fast on unknown/terminated/spoofing actors
  2. Context Enrichment    — asset, window, history signals
  3. Drift Detection       — behavioral baseline comparison (stub in Phase 1)
  4. Policy Engine         — deny → conditional → allow evaluation
  5. Risk Scoring Engine   — composite signal scoring
  6. Decision Engine       — policy × risk → final decision
  7. Audit Logger          — write tamper-evident entry
"""

from __future__ import annotations

import logging
from pathlib import Path

from guardian.attestation.attestor import ActorRegistry, IdentityAttestor
from guardian.audit.logger import AuditLogger
from guardian.decision.engine import DecisionEngine
from guardian.enrichment.context import AssetCatalog, ContextEnricher, MaintenanceWindowStore
from guardian.models.action_request import (
    ActionRequest,
    Decision,
    DecisionOutcome,
    DriftScore,
    RiskSignal,
)
from guardian.policy.engine import PolicyEngine
from guardian.policy.loaders import PolicyLoader
from guardian.scoring.engine import RiskScoringEngine

logger = logging.getLogger(__name__)


class GuardianPipeline:
    """
    The full Guardian evaluation pipeline.
    Constructed once at startup, then evaluate() is called per request.
    """

    def __init__(
        self,
        actor_registry: ActorRegistry,
        asset_catalog: AssetCatalog,
        window_store: MaintenanceWindowStore,
        policy_engine: PolicyEngine,
        audit_logger: AuditLogger,
    ):
        self.attestor = IdentityAttestor(actor_registry)
        self.enricher = ContextEnricher(asset_catalog, window_store)
        self.policy_engine = policy_engine
        self.risk_engine = RiskScoringEngine()
        self.decision_engine = DecisionEngine()
        self.audit_logger = audit_logger

    def evaluate(self, request: ActionRequest) -> Decision:
        logger.info(
            "Evaluating: actor=%s action=%s asset=%s",
            request.actor_name, request.requested_action, request.target_asset,
        )

        # Stage 1: Identity Attestation
        attestation = self.attestor.attest(request)
        if not attestation.success:
            decision = Decision(
                action_request=request,
                decision=DecisionOutcome.block,
                risk_score=1.0,
                explanation=attestation.failure_explanation or "Identity attestation failed.",
                compliance_tags=["NIST-IA-2", "NIST-AC-2"],
            )
            return self.audit_logger.write(decision)

        # Stage 2: Context Enrichment
        context = self.enricher.enrich(request, attestation)

        # Stage 3: Drift Detection (Phase 1 stub — returns neutral score)
        drift = DriftScore(
            score=0.0,
            level_drift_z=0.0,
            pattern_drift_js=0.0,
            baseline_days=0,
            alert_triggered=False,
            explanation="Drift detection not yet active (Phase 2.5).",
        )

        # Stage 4: Policy Engine
        policy_context = context.to_policy_context()
        policy_verdict = self.policy_engine.evaluate(policy_context)

        # Stage 5: Risk Scoring
        risk_score, risk_signals = self.risk_engine.score(context, drift_score=drift.score)

        # Stage 6: Decision Engine
        risk_signals_summary = "; ".join(
            s.description for s in risk_signals if abs(s.contribution) > 0.05
        )
        result = self.decision_engine.decide(
            policy_verdict=policy_verdict,
            risk_score=risk_score,
            policy_explanation=policy_verdict.explanation,
            risk_signals_summary=risk_signals_summary,
        )

        # Compliance tags
        compliance_tags = ["NIST-AU-2", "NIST-AU-12"]
        if result.outcome == DecisionOutcome.block:
            compliance_tags += ["NIST-AC-3"]
        if "privilege" in request.requested_action:
            compliance_tags += ["NIST-AC-6", "CIS-5.4"]

        decision = Decision(
            action_request=request,
            decision=result.outcome,
            risk_score=risk_score,
            drift_score=drift,
            policy_matched=policy_verdict.rule_id,
            risk_signals=risk_signals,
            explanation=result.explanation,
            safer_alternatives=result.safer_alternatives,
            compliance_tags=compliance_tags,
        )

        # Stage 7: Audit Log
        return self.audit_logger.write(decision)

    @classmethod
    def from_config(cls, config_dir: Path, policies_dir: Path,
                    audit_log_path: Path) -> "GuardianPipeline":
        """
        Construct a GuardianPipeline from directory paths.
        Raises RuntimeError on any invalid configuration.
        """
        actor_registry = ActorRegistry(config_dir / "actor-registry.yaml")
        asset_catalog = AssetCatalog(config_dir / "asset-catalog.yaml")
        window_store = MaintenanceWindowStore(config_dir / "maintenance-windows.yaml")

        loader = PolicyLoader(policies_dir)
        deny_rules, conditional_rules, allow_rules = loader.load_all()
        policy_engine = PolicyEngine(deny_rules, conditional_rules, allow_rules)

        audit_logger = AuditLogger(audit_log_path)

        return cls(
            actor_registry=actor_registry,
            asset_catalog=asset_catalog,
            window_store=window_store,
            policy_engine=policy_engine,
            audit_logger=audit_logger,
        )
