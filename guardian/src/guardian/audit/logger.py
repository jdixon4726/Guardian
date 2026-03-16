"""
Audit Logger

Writes every Guardian decision to a tamper-evident, append-only audit log.
Each entry includes the SHA-256 hash of the previous entry, forming a hash chain
that can be independently verified.

A broken chain indicates log tampering. The `verify` method detects breaks.

Supports pluggable replication sinks for forwarding entries to immutable
external stores (S3 Object Lock, Azure Immutable Blob, SIEM, etc.).
"""

from __future__ import annotations

import hashlib
import json
import logging
from abc import ABC, abstractmethod
from datetime import datetime
from pathlib import Path
from typing import Optional

from guardian.models.action_request import Decision

logger = logging.getLogger(__name__)

GENESIS_HASH = "0" * 64  # Hash of the non-existent entry before the first entry


class AuditReplicationSink(ABC):
    """
    Interface for audit log replication targets.

    Implementations forward each audit entry to an external immutable store.
    The local hash-chained log detects tampering; replication prevents deletion.
    """

    @abstractmethod
    def replicate(self, entry_json: str, entry_id: str, entry_hash: str) -> bool:
        """
        Forward an audit entry to the external store.

        Returns True if replication succeeded. Failed replications are
        logged but do not block the pipeline — Guardian prioritizes
        availability over replication consistency.
        """
        ...

    @abstractmethod
    def health_check(self) -> bool:
        """Return True if the replication target is reachable."""
        ...


class FileReplicationSink(AuditReplicationSink):
    """Replicate audit entries to a secondary file (e.g., mounted remote volume)."""

    def __init__(self, replica_path: Path):
        self._path = replica_path
        self._path.parent.mkdir(parents=True, exist_ok=True)

    def replicate(self, entry_json: str, entry_id: str, entry_hash: str) -> bool:
        try:
            with open(self._path, "a", encoding="utf-8") as f:
                f.write(entry_json + "\n")
            return True
        except OSError as exc:
            logger.error("Audit replication failed: %s", exc)
            return False

    def health_check(self) -> bool:
        return self._path.parent.exists()


class AuditLogger:
    """
    Append-only audit logger with SHA-256 hash chaining and pluggable replication.

    Thread safety: This implementation uses file-level appends. For concurrent
    writes in production, use a database-backed implementation with row locking.
    """

    def __init__(self, log_path: Path,
                 replication_sinks: list[AuditReplicationSink] | None = None):
        self.log_path = log_path
        self.log_path.parent.mkdir(parents=True, exist_ok=True)
        self._last_hash: str = self._load_last_hash()
        self._sinks = replication_sinks or []
        if self._sinks:
            logger.info("Audit replication configured: %d sink(s)", len(self._sinks))

    def write(self, decision: Decision) -> Decision:
        """
        Write a decision to the audit log.

        Sets previous_hash and entry_hash on the decision before writing.
        Returns the decision with hashes populated.
        """
        decision.previous_hash = self._last_hash
        entry_content = self._serialize_for_hashing(decision)
        decision.entry_hash = hashlib.sha256(entry_content.encode()).hexdigest()

        with open(self.log_path, "a", encoding="utf-8") as f:
            f.write(decision.model_dump_json() + "\n")

        self._last_hash = decision.entry_hash
        logger.debug("Audit entry written: %s hash=%s", decision.entry_id, decision.entry_hash)

        # Replicate to external sinks (best-effort, non-blocking)
        entry_json = decision.model_dump_json()
        for sink in self._sinks:
            try:
                sink.replicate(entry_json, decision.entry_id, decision.entry_hash)
            except Exception as exc:
                logger.error("Audit replication sink error: %s", exc)

        return decision

    def verify(self) -> tuple[bool, Optional[str]]:
        """
        Verify the hash chain integrity of the audit log.

        Returns (True, None) if the chain is intact.
        Returns (False, reason) if a break is detected.
        """
        if not self.log_path.exists():
            return True, None

        previous_hash = GENESIS_HASH
        with open(self.log_path, encoding="utf-8") as f:
            for line_number, line in enumerate(f, start=1):
                line = line.strip()
                if not line:
                    continue
                try:
                    entry = json.loads(line)
                except json.JSONDecodeError:
                    return False, f"Line {line_number}: invalid JSON"

                if entry.get("previous_hash") != previous_hash:
                    return False, (
                        f"Line {line_number}: chain break. "
                        f"Expected previous_hash={previous_hash!r}, "
                        f"got {entry.get('previous_hash')!r}"
                    )

                # Recompute the hash to verify entry integrity
                decision = Decision(**entry)
                decision.entry_hash = None
                content = self._serialize_for_hashing(decision)
                expected_hash = hashlib.sha256(content.encode()).hexdigest()

                if entry.get("entry_hash") != expected_hash:
                    return False, (
                        f"Line {line_number}: entry hash mismatch for entry_id={entry.get('entry_id')!r}"
                    )

                previous_hash = entry["entry_hash"]

        return True, None

    def _serialize_for_hashing(self, decision: Decision) -> str:
        """
        Produce a canonical JSON string for hashing.
        Excludes entry_hash (which is being computed) and previous_hash (already set).
        """
        data = decision.model_dump(exclude={"entry_hash"})
        return json.dumps(data, sort_keys=True, default=str)

    def _load_last_hash(self) -> str:
        """Read the hash of the last entry in the existing log, or genesis hash."""
        if not self.log_path.exists():
            return GENESIS_HASH
        last_hash = GENESIS_HASH
        with open(self.log_path, encoding="utf-8") as f:
            for line in f:
                line = line.strip()
                if not line:
                    continue
                try:
                    entry = json.loads(line)
                    last_hash = entry.get("entry_hash", last_hash)
                except json.JSONDecodeError:
                    pass
        return last_hash
