"""
Unit tests for the Guardian configuration model and loader.
"""

from pathlib import Path
from tempfile import TemporaryDirectory

import pytest
import yaml

from guardian.config.loader import load_config
from guardian.config.model import GuardianConfig, ScoringConfig, TrustConfig


class TestGuardianConfig:
    def test_defaults_match_original_hardcoded_values(self):
        cfg = GuardianConfig()
        assert cfg.scoring.weights["action"] == 0.30
        assert cfg.scoring.weights["actor"] == 0.25
        assert cfg.scoring.action_category_scores["destructive"] == 0.90
        assert cfg.trust.min_actions == 10
        assert cfg.trust.block_penalty == 0.05
        assert cfg.drift.z_score_alert_threshold == 2.5
        assert cfg.decision.low_max == 0.30

    def test_action_categories_contain_known_actions(self):
        cfg = ScoringConfig()
        all_actions = [a for cat in cfg.action_categories.values() for a in cat]
        assert "disable_endpoint_protection" in all_actions
        assert "modify_iam_role" in all_actions
        assert "delete_resource" in all_actions

    def test_policy_defaults_to_builtin(self):
        cfg = GuardianConfig()
        assert cfg.policy.provider == "builtin"
        assert cfg.policy.opa_url is None


class TestConfigLoader:
    def test_missing_file_returns_defaults(self):
        with TemporaryDirectory() as tmpdir:
            cfg = load_config(Path(tmpdir))
            assert cfg == GuardianConfig()

    def test_empty_file_returns_defaults(self):
        with TemporaryDirectory() as tmpdir:
            (Path(tmpdir) / "guardian.yaml").write_text("")
            cfg = load_config(Path(tmpdir))
            assert cfg == GuardianConfig()

    def test_partial_config_merges_with_defaults(self):
        with TemporaryDirectory() as tmpdir:
            partial = {"trust": {"min_actions": 20, "block_penalty": 0.10}}
            (Path(tmpdir) / "guardian.yaml").write_text(yaml.dump(partial))
            cfg = load_config(Path(tmpdir))
            assert cfg.trust.min_actions == 20
            assert cfg.trust.block_penalty == 0.10
            # Other trust defaults preserved
            assert cfg.trust.allow_bonus == 0.005
            # Scoring defaults preserved
            assert cfg.scoring.weights["action"] == 0.30

    def test_custom_action_categories(self):
        with TemporaryDirectory() as tmpdir:
            custom = {
                "scoring": {
                    "action_categories": {
                        "destructive": ["nuke_everything"],
                        "custom_tier": ["do_something_special"],
                    },
                    "action_category_scores": {
                        "destructive": 0.95,
                        "custom_tier": 0.60,
                    },
                }
            }
            (Path(tmpdir) / "guardian.yaml").write_text(yaml.dump(custom))
            cfg = load_config(Path(tmpdir))
            assert "nuke_everything" in cfg.scoring.action_categories["destructive"]
            assert cfg.scoring.action_category_scores["custom_tier"] == 0.60

    def test_loads_real_config_file(self):
        """Verify the actual config/guardian.yaml loads without error."""
        config_dir = Path(__file__).parent.parent.parent / "config"
        if (config_dir / "guardian.yaml").exists():
            cfg = load_config(config_dir)
            assert cfg.scoring.weights["action"] == 0.30
