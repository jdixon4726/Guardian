"""
Policy Bundle Signature Verification

Ensures configuration integrity by verifying a SHA-256 manifest of all
config files against a detached signature. Prevents policy tampering
through compromised deploy pipelines or filesystem access.

Verification modes:
  - "enforce": reject unsigned or tampered bundles (production)
  - "warn": log a warning but continue (staging/development)
  - "off": skip verification entirely (local development only)

The manifest is a deterministic SHA-256 hash of all YAML files in the
config directory, sorted by relative path. This makes it diffable and
independent of filesystem metadata.
"""

from __future__ import annotations

import hashlib
import hmac
import json
import logging
from dataclasses import dataclass
from pathlib import Path

logger = logging.getLogger(__name__)

MANIFEST_FILENAME = "bundle-manifest.json"
SIGNATURE_FILENAME = "bundle.sig"


@dataclass
class VerificationResult:
    valid: bool
    reason: str | None = None
    manifest_hash: str | None = None


class BundleVerifier:
    """
    Verifies the integrity of a configuration bundle.

    Uses HMAC-SHA256 with a shared secret for signature verification.
    For production use, this should be replaced with asymmetric signing
    (GPG/cosign), but HMAC provides the core integrity guarantee with
    zero external dependencies.
    """

    def __init__(self, secret: str | bytes | None = None):
        """
        Initialize with a signing secret.

        The secret should be provided via environment variable
        (GUARDIAN_SIGNING_SECRET), never hardcoded or stored in the
        config directory being verified.
        """
        if isinstance(secret, str):
            secret = secret.encode("utf-8")
        self._secret = secret

    def compute_manifest(self, bundle_dir: Path) -> dict:
        """
        Compute a deterministic manifest of all config files.

        Returns a dict with:
          - files: {relative_path: sha256_hash} for each YAML file
          - manifest_hash: SHA-256 of the concatenated file hashes
        """
        file_hashes = {}
        yaml_files = sorted(bundle_dir.glob("**/*.yaml"))

        for filepath in yaml_files:
            relative = filepath.relative_to(bundle_dir).as_posix()
            content = filepath.read_bytes()
            file_hash = hashlib.sha256(content).hexdigest()
            file_hashes[relative] = file_hash

        # Compute the composite manifest hash
        concatenated = "".join(
            f"{path}:{hash_val}" for path, hash_val in sorted(file_hashes.items())
        )
        manifest_hash = hashlib.sha256(concatenated.encode()).hexdigest()

        return {
            "files": file_hashes,
            "manifest_hash": manifest_hash,
        }

    def sign_manifest(self, manifest_hash: str) -> str:
        """
        Sign a manifest hash with HMAC-SHA256.

        Returns the hex-encoded signature.
        """
        if self._secret is None:
            raise ValueError("No signing secret configured")
        return hmac.new(self._secret, manifest_hash.encode(), hashlib.sha256).hexdigest()

    def verify(self, bundle_dir: Path, mode: str = "enforce") -> VerificationResult:
        """
        Verify a configuration bundle's integrity.

        Modes:
          - "enforce": fail if signature is missing or invalid
          - "warn": log warning but return valid=True
          - "off": skip verification entirely
        """
        if mode == "off":
            return VerificationResult(valid=True, reason="Verification disabled")

        manifest_path = bundle_dir / MANIFEST_FILENAME
        signature_path = bundle_dir / SIGNATURE_FILENAME

        # Check manifest exists
        if not manifest_path.exists():
            msg = f"No {MANIFEST_FILENAME} found in {bundle_dir}"
            if mode == "warn":
                logger.warning("Bundle verification: %s", msg)
                return VerificationResult(valid=True, reason=msg)
            return VerificationResult(valid=False, reason=msg)

        # Check signature exists
        if not signature_path.exists():
            msg = f"No {SIGNATURE_FILENAME} found in {bundle_dir}"
            if mode == "warn":
                logger.warning("Bundle verification: %s", msg)
                return VerificationResult(valid=True, reason=msg)
            return VerificationResult(valid=False, reason=msg)

        if self._secret is None:
            msg = "No signing secret configured (set GUARDIAN_SIGNING_SECRET)"
            if mode == "warn":
                logger.warning("Bundle verification: %s", msg)
                return VerificationResult(valid=True, reason=msg)
            return VerificationResult(valid=False, reason=msg)

        # Load stored manifest
        try:
            stored = json.loads(manifest_path.read_text(encoding="utf-8"))
            stored_hash = stored["manifest_hash"]
        except (json.JSONDecodeError, KeyError) as exc:
            return VerificationResult(
                valid=False,
                reason=f"Invalid manifest file: {exc}",
            )

        # Recompute manifest from current files
        current = self.compute_manifest(bundle_dir)

        # Check file integrity (has any YAML file been modified?)
        if current["manifest_hash"] != stored_hash:
            # Find which files differ
            changed = []
            for path, hash_val in current["files"].items():
                if stored.get("files", {}).get(path) != hash_val:
                    changed.append(path)
            for path in stored.get("files", {}):
                if path not in current["files"]:
                    changed.append(f"{path} (deleted)")

            return VerificationResult(
                valid=False,
                reason=f"Config files modified since signing: {', '.join(changed)}",
                manifest_hash=current["manifest_hash"],
            )

        # Verify signature
        stored_signature = signature_path.read_text(encoding="utf-8").strip()
        expected_signature = self.sign_manifest(stored_hash)

        if not hmac.compare_digest(stored_signature, expected_signature):
            return VerificationResult(
                valid=False,
                reason="Signature verification failed — bundle may be tampered",
                manifest_hash=current["manifest_hash"],
            )

        logger.info("Bundle signature verified: %s", stored_hash[:16])
        return VerificationResult(
            valid=True,
            manifest_hash=current["manifest_hash"],
        )

    def sign_bundle(self, bundle_dir: Path) -> str:
        """
        Sign a config bundle: write manifest and signature files.

        Returns the manifest hash.
        """
        if self._secret is None:
            raise ValueError("No signing secret configured")

        manifest = self.compute_manifest(bundle_dir)

        # Write manifest
        manifest_path = bundle_dir / MANIFEST_FILENAME
        manifest_path.write_text(
            json.dumps(manifest, indent=2, sort_keys=True),
            encoding="utf-8",
        )

        # Write signature
        signature = self.sign_manifest(manifest["manifest_hash"])
        signature_path = bundle_dir / SIGNATURE_FILENAME
        signature_path.write_text(signature, encoding="utf-8")

        logger.info("Bundle signed: %s", manifest["manifest_hash"][:16])
        return manifest["manifest_hash"]
