"""
Configuration Loader

Loads guardian.yaml from the config directory and validates it against
GuardianConfig. If no guardian.yaml exists, returns defaults that match
the original hardcoded behavior.
"""

from __future__ import annotations

import logging
from pathlib import Path

import yaml

from guardian.config.model import GuardianConfig

logger = logging.getLogger(__name__)


def load_config(config_dir: Path) -> GuardianConfig:
    """Load and validate guardian.yaml, or return defaults if not present."""
    config_path = config_dir / "guardian.yaml"

    if not config_path.exists():
        logger.info("No guardian.yaml found in %s — using defaults", config_dir)
        return GuardianConfig()

    raw = yaml.safe_load(config_path.read_text(encoding="utf-8"))
    if raw is None:
        logger.warning("guardian.yaml is empty — using defaults")
        return GuardianConfig()

    config = GuardianConfig(**raw)
    logger.info("Guardian config loaded from %s", config_path)
    return config
