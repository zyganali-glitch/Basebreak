"""Content-addressed evidence storage and write deduplication.

P-25.05: Implement evidence write deduplication and replay safety.
Stores immutable evidence facts indexed strictly by their SHA-256 content digest.
Deduplicates writes so identical evidence records are never redundantly written,
and verifies SHA-256 integrity upon replay.
"""

from __future__ import annotations

import hashlib
import json
import os
from pathlib import Path
from typing import Any


class EvidenceTamperingError(Exception):
    """Raised when evidence on disk does not match its content digest."""


class EvidenceNotFoundError(Exception):
    """Raised when requested evidence digest cannot be found."""


def compute_evidence_digest(record: dict[str, Any]) -> str:
    """Compute canonical SHA-256 digest of an evidence record."""
    raw = json.dumps(record, sort_keys=True, separators=(",", ":")).encode("utf-8")
    return hashlib.sha256(raw).hexdigest()


class ContentAddressedEvidenceStore:
    """Content-addressed storage engine for evidence records."""

    def __init__(self, store_dir: str | Path) -> None:
        self.store_dir = Path(store_dir)
        self.store_dir.mkdir(parents=True, exist_ok=True)

    def _get_path(self, digest: str) -> Path:
        return self.store_dir / f"{digest}.json"

    def store_evidence(self, record: dict[str, Any]) -> tuple[str, bool]:
        """Store evidence record in content-addressed storage.

        Returns:
            Tuple of (digest, was_newly_written).
            If an identical evidence record exists, returns (digest, False) without writing.
        """
        digest = compute_evidence_digest(record)
        target = self._get_path(digest)

        if target.is_file():
            # Deduplication: already exists on disk
            return digest, False

        tmp = self.store_dir / f"{digest}.tmp.{os.getpid()}"
        with tmp.open("w", encoding="utf-8") as f:
            json.dump(record, f, indent=2, sort_keys=True)
            f.flush()
            os.fsync(f.fileno())

        os.replace(tmp, target)
        return digest, True

    def load_evidence(self, digest: str) -> dict[str, Any]:
        """Load and verify evidence record by digest."""
        target = self._get_path(digest)
        if not target.is_file():
            raise EvidenceNotFoundError(f"Evidence {digest!r} not found at {target}")

        with target.open("r", encoding="utf-8") as f:
            data = json.load(f)

        if not isinstance(data, dict):
            raise EvidenceTamperingError(f"Evidence {digest!r} is not a valid JSON object")

        actual_digest = compute_evidence_digest(data)
        if actual_digest != digest:
            raise EvidenceTamperingError(
                f"Tampered evidence detected! Expected digest {digest!r}, "
                f"but file computed to {actual_digest!r}."
            )

        return data

    def verify_integrity(self, digest: str) -> bool:
        """Verify that stored evidence matches its digest."""
        try:
            self.load_evidence(digest)
            return True
        except (EvidenceTamperingError, EvidenceNotFoundError):
            return False

    def list_digests(self) -> list[str]:
        """List all stored evidence digests."""
        digests: list[str] = []
        for p in self.store_dir.glob("*.json"):
            name = p.name
            if len(name) == 69 and name.endswith(".json"):  # 64 hex chars + .json
                digests.append(name[:-5])
        return sorted(digests)
