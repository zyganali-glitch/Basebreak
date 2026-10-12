"""Idempotency engine and duplicate-run protection.

P-25.04: Implement duplicate-run/idempotency protection.
Binds idempotency keys to canonical request fingerprints, detects conflict
attempts with mismatched payloads, and safely replays existing results.
"""

from __future__ import annotations

import hashlib
import json
import os
import threading
from dataclasses import asdict, dataclass
from enum import Enum
from pathlib import Path
from typing import Any


class IdempotencyKeyConflictError(Exception):
    """Raised when an idempotency key is reused with a conflicting payload."""


class IdempotencyDecision(str, Enum):
    """Action to take based on idempotency evaluation."""

    EXECUTE_NEW = "EXECUTE_NEW"
    RETURN_EXISTING = "RETURN_EXISTING"


@dataclass(frozen=True, slots=True)
class IdempotencyRecord:
    """Persisted idempotency mapping."""

    idempotency_key: str
    request_fingerprint: str
    run_id: str
    created_at: str
    result_summary: dict[str, Any]

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> IdempotencyRecord:
        return cls(
            idempotency_key=data["idempotency_key"],
            request_fingerprint=data["request_fingerprint"],
            run_id=data["run_id"],
            created_at=data["created_at"],
            result_summary=dict(data.get("result_summary", {})),
        )


def compute_request_fingerprint(payload: dict[str, Any]) -> str:
    """Compute canonical SHA-256 fingerprint of request parameters."""
    cleaned = {k: v for k, v in payload.items() if k != "idempotency_key"}
    raw_bytes = json.dumps(cleaned, sort_keys=True, separators=(",", ":")).encode("utf-8")
    return hashlib.sha256(raw_bytes).hexdigest()


class IdempotencyEngine:
    """Thread-safe and durably persisted idempotency coordinator."""

    def __init__(self, journal_file: str | Path) -> None:
        self.journal_file = Path(journal_file)
        self._lock = threading.Lock()
        self._records: dict[str, IdempotencyRecord] = {}
        self._load_journal()

    def _load_journal(self) -> None:
        """Load existing records from disk journal."""
        if not self.journal_file.is_file():
            return
        try:
            with self.journal_file.open("r", encoding="utf-8") as f:
                data = json.load(f)
            if isinstance(data, dict):
                for k, v in data.items():
                    if isinstance(v, dict):
                        self._records[k] = IdempotencyRecord.from_dict(v)
        except Exception:
            pass

    def _flush_journal(self) -> None:
        """Atomically persist records to journal file."""
        self.journal_file.parent.mkdir(parents=True, exist_ok=True)
        tmp = self.journal_file.with_suffix(f".tmp.{os.getpid()}")
        payload = {k: r.to_dict() for k, r in self._records.items()}
        with tmp.open("w", encoding="utf-8") as f:
            json.dump(payload, f, indent=2, sort_keys=True)
            f.flush()
            os.fsync(f.fileno())
        os.replace(tmp, self.journal_file)

    def evaluate_request(
        self,
        idempotency_key: str,
        payload: dict[str, Any],
    ) -> tuple[IdempotencyDecision, IdempotencyRecord | None]:
        """Evaluate incoming request against registered keys.

        Raises:
            IdempotencyKeyConflictError: If key exists with different payload fingerprint.
        """
        fingerprint = compute_request_fingerprint(payload)
        with self._lock:
            record = self._records.get(idempotency_key)
            if record is None:
                return IdempotencyDecision.EXECUTE_NEW, None

            if record.request_fingerprint != fingerprint:
                raise IdempotencyKeyConflictError(
                    f"Idempotency key {idempotency_key!r} was previously registered with "
                    f"fingerprint {record.request_fingerprint!r}, but current payload has "
                    f"fingerprint {fingerprint!r}."
                )

            return IdempotencyDecision.RETURN_EXISTING, record

    def register_completed_run(
        self,
        idempotency_key: str,
        payload: dict[str, Any],
        run_id: str,
        created_at: str,
        result_summary: dict[str, Any],
    ) -> IdempotencyRecord:
        """Register a successfully evaluated or completed run."""
        fingerprint = compute_request_fingerprint(payload)
        record = IdempotencyRecord(
            idempotency_key=idempotency_key,
            request_fingerprint=fingerprint,
            run_id=run_id,
            created_at=created_at,
            result_summary=result_summary,
        )
        with self._lock:
            self._records[idempotency_key] = record
            self._flush_journal()
        return record
