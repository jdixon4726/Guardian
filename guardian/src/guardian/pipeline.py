"""
Guardian Pipeline

Wires all evaluation stages into a single evaluate() call.
This is the main entry point for all action request evaluation.

Stage order:
  1. Identity Attestation       — fail fast on unknown/terminated/spoofing actors
  2. Context Enrichment         — asset, window, history (trust + velocity) signals
  3. Behavioral Assessment      — drift, trust, velocity → BehavioralAssessment
  4. Policy Evaluation          — via PolicyProvider (built-in or OPA)
  5. Risk Scoring Engine        — composite signal scoring
  6. Decision Engine            — policy × risk → final decision
  7. Audit Logger               — write tamper-evident entry
  8. Actor History Store        — record evaluation for trust and velocity tracking
  9. Alert Publisher            — drift alerts (fire-and-forget)
"""

from __future__ import annotations

import logging
from pathlib import Path

from guardian.attestation.attestor import ActorRegistry, IdentityAttestor
from guardian.audit.logger import AuditLogger
from guardian.behavioral.engine import BehavioralIntelligenceEngine
from guardian.config.loader import load_config
from guardian.config.model import GuardianConfig
from guardian.config.signature import BundleVerifier
from guardian.decision.engine import DecisionEngine
from guardian.drift.alerts import AlertPublisher
from guardian.drift.baseline import BaselineStore
from guardian.drift.engine import DriftDetectionEngine
from guardian.enrichment.context import AssetCatalog, ContextEnricher, MaintenanceWindowStore
from guardian.history.store import ActorHistoryStore
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
        baseline_store: BaselineStore | None = None,
        alert_publisher: AlertPublisher | None = None,
        history_store: ActorHistoryStore | None = None,
        config: GuardianConfig | None = None,
    ):
        cfg = config or GuardianConfig()
        self.config = cfg
        self.history_store = history_store or ActorHistoryStore(trust_config=cfg.trust)
        self.attestor = IdentityAttestor(actor_registry)
        self.enricher = ContextEnricher(asset_catalog, window_store, self.history_store)
        self.policy_engine = policy_engine
        self.risk_engine = RiskScoringEngine(config=cfg.scoring)
        self.decision_engine = DecisionEngine(config=cfg.decision)
        self.audit_logger = audit_logger
        self.baseline_store = baseline_store or BaselineStore()
        self.drift_engine = DriftDetectionEngine(self.baseline_store, config=cfg.drift)
        self.behavioral_engine = BehavioralIntelligenceEngine(
            drift_engine=self.drift_engine,
            history_store=self.history_store,
            config=cfg,
        )
        self.alert_publisher = alert_publisher or AlertPublisher()

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

        # Stage 3: Behavioral Assessment (Guardian's core differentiator)
        assessment = self.behavioral_engine.assess(context)
        drift = assessment.drift_score

        # Stage 4: Policy Evaluation — behavioral context injected
        policy_context = context.to_policy_context()
        policy_context.update(assessment.to_policy_context())
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
        decision = self.audit_logger.write(decision)

        # Stage 8: Record to Actor History Store
        self.history_store.record(
            actor_name=request.actor_name,
            action_type=request.requested_action,
            target_asset=request.target_asset,
            decision=result.outcome.value,
            risk_score=risk_score,
            privilege_level=request.privilege_level.value,
            timestamp=request.timestamp,
        )

        # Stage 9: Drift Alert Publishing (async, fire-and-forget)
        if drift.alert_triggered:
            self.alert_publisher.publish(
                actor_name=request.actor_name,
                action_type=request.requested_action,
                drift_score=drift,
                decision_entry_id=decision.entry_id,
            )

        return decision

    @classmethod
    def from_config(cls, config_dir: Path, policies_dir: Path,
                    audit_log_path: Path,
                    signing_secret: str | None = None,
                    verification_mode: str = "warn") -> "GuardianPipeline":
        """
        Construct a GuardianPipeline from directory paths.
        Loads guardian.yaml for all tunable parameters.
        Verifies config bundle signature if signing_secret is provided.
        Raises RuntimeError on any invalid configuration.
        """
        # Verify config bundle integrity before loading anything
        import os
        secret = signing_secret or os.environ.get("GUARDIAN_SIGNING_SECRET")
        mode = os.environ.get("GUARDIAN_VERIFICATION_MODE", verification_mode)
        verifier = BundleVerifier(secret)
        result = verifier.verify(config_dir, mode=mode)
        if not result.valid:
            raise RuntimeError(
                f"Config bundle verification failed: {result.reason}"
            )
        if result.reason and mode == "warn":
            logger.warning("Config bundle: %s", result.reason)

        # Load master config (defaults if guardian.yaml absent)
        config = load_config(config_dir)

        actor_registry = ActorRegistry(config_dir / "actor-registry.yaml")
        asset_catalog = AssetCatalog(config_dir / "asset-catalog.yaml")
        window_store = MaintenanceWindowStore(config_dir / "maintenance-windows.yaml")

        loader = PolicyLoader(policies_dir)
        deny_rules, conditional_rules, allow_rules = loader.load_all()
        policy_engine = PolicyEngine(deny_rules, conditional_rules, allow_rules)

        audit_logger = AuditLogger(audit_log_path)

        # Drift detection stores
        baseline_db = audit_log_path.parent / "baselines.sqlite"
        baseline_store = BaselineStore(baseline_db)
        alert_log = audit_log_path.parent / "drift-alerts.jsonl"
        alert_publisher = AlertPublisher(alert_log)

        # Actor history store
        history_db = audit_log_path.parent / "actor-history.sqlite"
        history_store = ActorHistoryStore(history_db, trust_config=config.trust)

        return cls(
            actor_registry=actor_registry,
            asset_catalog=asset_catalog,
            window_store=window_store,
            policy_engine=policy_engine,
            audit_logger=audit_logger,
            baseline_store=baseline_store,
            alert_publisher=alert_publisher,
            history_store=history_store,
            config=config,
        )
