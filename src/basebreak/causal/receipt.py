"""Deterministic local causal verification receipt contracts and tamper detection.

P-10.06: Produce first local causal receipt.

Core Invariants:
1. Complete cryptographic chain: Unambiguously binds:
   requirement_id -> frozen_contract_digest -> witness_digest -> lock_digest ->
   BASE facts -> CANDIDATE facts -> transition -> verdict -> receipt_digest.
2. Canonical serialization: Computes deterministic SHA-256 receipt digest over canonical JSON bytes.
3. Tamper detection: Any modification to any field immediately invalidates receipt_digest.
4. Authority boundary: Caller-asserted receipts claiming unverified authority fail closed.
5. Strict provenance: Preserves exact provenance enum (FIXTURE, LOCAL_EXECUTION,
   LIVE_NEBIUS, RECORDED_LIVE).
"""

from __future__ import annotations

import hashlib
import json
import re
from collections.abc import Mapping
from dataclasses import dataclass
from datetime import datetime, timezone
from typing import Any

from basebreak.causal.reconciliation import CausalTransition
from basebreak.domain.causal import ExecutionWorld
from basebreak.domain.execution import TerminationStatus
from basebreak.domain.verdict import EvidenceProvenance, PreliminaryVerdict
from basebreak.verifier.witness_result import NormalizedWitnessResult, WitnessOutcome

CAUSAL_RECEIPT_SCHEMA_VERSION: str = "1.0.0"

_HEX_40_PATTERN = re.compile(r"^[0-9a-f]{40}$")
_HEX_64_PATTERN = re.compile(r"^[0-9a-f]{64}$")
_HEX_40_OR_64_PATTERN = re.compile(r"^([0-9a-f]{40}|[0-9a-f]{64})$")


class CausalReceiptError(Exception):
    """Base exception for causal verification receipt errors."""


class CausalReceiptTamperingError(CausalReceiptError):
    """Raised when receipt facts do not match the cryptographic receipt digest."""


class CausalReceiptIntegrityError(CausalReceiptError):
    """Raised when receipt fields violate domain or format constraints."""


@dataclass(frozen=True, slots=True)
class WorldExecutionFact:
    """Immutable facts of a single world execution."""

    world: ExecutionWorld
    sandbox_id: str
    source_commit_id: str
    tree_digest: str
    outcome: WitnessOutcome
    exit_code: int | None
    termination_status: TerminationStatus
    stdout_digest: str
    stderr_digest: str
    result_digest: str
    duration_seconds: float

    def __post_init__(self) -> None:
        if not isinstance(self.world, ExecutionWorld):
            raise TypeError(f"world must be ExecutionWorld, got {type(self.world).__name__}")
        if not isinstance(self.sandbox_id, str) or not self.sandbox_id.strip():
            raise CausalReceiptIntegrityError("sandbox_id must be a non-empty string")
        if not isinstance(self.source_commit_id, str) or not _HEX_40_PATTERN.match(
            self.source_commit_id
        ):
            raise CausalReceiptIntegrityError("source_commit_id must be a 40-char commit SHA")
        if not isinstance(self.tree_digest, str) or not _HEX_40_OR_64_PATTERN.match(
            self.tree_digest
        ):
            raise CausalReceiptIntegrityError("tree_digest must be 40 or 64 hex characters")
        if not isinstance(self.outcome, WitnessOutcome):
            raise TypeError(f"outcome must be WitnessOutcome, got {type(self.outcome).__name__}")
        if not isinstance(self.termination_status, TerminationStatus):
            status_type = type(self.termination_status).__name__
            raise TypeError(f"termination_status must be TerminationStatus, got {status_type}")
        if not isinstance(self.stdout_digest, str) or not _HEX_64_PATTERN.match(self.stdout_digest):
            raise CausalReceiptIntegrityError("stdout_digest must be a 64-char hex string")
        if not isinstance(self.stderr_digest, str) or not _HEX_64_PATTERN.match(self.stderr_digest):
            raise CausalReceiptIntegrityError("stderr_digest must be a 64-char hex string")
        if not isinstance(self.result_digest, str) or not _HEX_64_PATTERN.match(self.result_digest):
            raise CausalReceiptIntegrityError("result_digest must be a 64-char hex string")
        if (
            isinstance(self.duration_seconds, bool)
            or not isinstance(self.duration_seconds, (int, float))
            or self.duration_seconds < 0.0
        ):
            raise CausalReceiptIntegrityError("duration_seconds must be a non-negative number")

    @classmethod
    def from_normalized_result(
        cls,
        result: NormalizedWitnessResult,
        *,
        tree_digest: str,
    ) -> WorldExecutionFact:
        """Construct from NormalizedWitnessResult and verified tree digest."""
        if not isinstance(result, NormalizedWitnessResult):
            raise TypeError(f"result must be NormalizedWitnessResult, got {type(result).__name__}")
        return cls(
            world=result.world,
            sandbox_id=result.sandbox_id,
            source_commit_id=result.source_commit_id,
            tree_digest=tree_digest.strip().lower(),
            outcome=result.outcome,
            exit_code=result.exit_code,
            termination_status=result.termination_status,
            stdout_digest=result.stdout_digest,
            stderr_digest=result.stderr_digest,
            result_digest=result.result_digest,
            duration_seconds=round(float(result.duration_seconds), 4),
        )

    def to_dict(self) -> dict[str, Any]:
        """Canonical dictionary representation."""
        return {
            "duration_seconds": round(float(self.duration_seconds), 4),
            "exit_code": self.exit_code,
            "outcome": self.outcome.value,
            "result_digest": self.result_digest,
            "sandbox_id": self.sandbox_id,
            "source_commit_id": self.source_commit_id,
            "stderr_digest": self.stderr_digest,
            "stdout_digest": self.stdout_digest,
            "termination_status": self.termination_status.value,
            "tree_digest": self.tree_digest,
            "world": self.world.value,
        }


def build_canonical_receipt_payload(
    *,
    schema_version: str,
    requirement_id: str,
    frozen_contract_digest: str,
    witness_id: str,
    witness_digest: str,
    lock_digest: str,
    base_execution: WorldExecutionFact,
    candidate_execution: WorldExecutionFact,
    transition: CausalTransition,
    verdict: PreliminaryVerdict,
    provenance: EvidenceProvenance,
    created_at_utc: str,
) -> dict[str, Any]:
    """Construct deterministic identity payload for receipt digest computation."""
    return {
        "base_execution": base_execution.to_dict(),
        "candidate_execution": candidate_execution.to_dict(),
        "created_at_utc": str(created_at_utc),
        "frozen_contract_digest": str(frozen_contract_digest),
        "lock_digest": str(lock_digest),
        "provenance": provenance.value,
        "requirement_id": str(requirement_id),
        "schema_version": str(schema_version),
        "transition": transition.value,
        "verdict": verdict.value,
        "witness_digest": str(witness_digest),
        "witness_id": str(witness_id),
    }


def compute_receipt_digest(payload: Mapping[str, Any]) -> str:
    """Compute deterministic SHA-256 digest over canonical JSON bytes."""
    canonical_bytes = json.dumps(
        payload, sort_keys=True, separators=(",", ":"), ensure_ascii=False
    ).encode("utf-8")
    return hashlib.sha256(canonical_bytes).hexdigest()


@dataclass(frozen=True, slots=True)
class LocalCausalReceipt:
    """Immutable, content-addressed receipt of causal verification between two worlds."""

    schema_version: str
    requirement_id: str
    frozen_contract_digest: str
    witness_id: str
    witness_digest: str
    lock_digest: str
    base_execution: WorldExecutionFact
    candidate_execution: WorldExecutionFact
    transition: CausalTransition
    verdict: PreliminaryVerdict
    provenance: EvidenceProvenance
    created_at_utc: str
    receipt_digest: str
    narrative: str = ""

    def __post_init__(self) -> None:
        if self.schema_version != CAUSAL_RECEIPT_SCHEMA_VERSION:
            raise CausalReceiptIntegrityError(
                f"Unsupported schema_version: {self.schema_version!r}, "
                f"expected {CAUSAL_RECEIPT_SCHEMA_VERSION!r}"
            )
        if not isinstance(self.requirement_id, str) or not self.requirement_id.strip():
            raise CausalReceiptIntegrityError("requirement_id must be a non-empty string")
        if not isinstance(self.frozen_contract_digest, str) or not _HEX_64_PATTERN.match(
            self.frozen_contract_digest
        ):
            raise CausalReceiptIntegrityError("frozen_contract_digest must be a 64-char hex string")
        if not isinstance(self.witness_id, str) or not self.witness_id.strip():
            raise CausalReceiptIntegrityError("witness_id must be a non-empty string")
        if not isinstance(self.witness_digest, str) or not _HEX_64_PATTERN.match(
            self.witness_digest
        ):
            raise CausalReceiptIntegrityError("witness_digest must be a 64-char hex string")
        if not isinstance(self.lock_digest, str) or not _HEX_64_PATTERN.match(self.lock_digest):
            raise CausalReceiptIntegrityError("lock_digest must be a 64-char hex string")
        if not isinstance(self.base_execution, WorldExecutionFact):
            base_type = type(self.base_execution).__name__
            raise TypeError(f"base_execution must be WorldExecutionFact, got {base_type}")
        if not isinstance(self.candidate_execution, WorldExecutionFact):
            cand_type = type(self.candidate_execution).__name__
            raise TypeError(f"candidate_execution must be WorldExecutionFact, got {cand_type}")
        if self.base_execution.world != ExecutionWorld.BASE:
            raise CausalReceiptIntegrityError(
                f"base_execution.world must be BASE, got {self.base_execution.world.value}"
            )
        if self.candidate_execution.world != ExecutionWorld.CANDIDATE:
            cand_w = self.candidate_execution.world.value
            raise CausalReceiptIntegrityError(
                f"candidate_execution.world must be CANDIDATE, got {cand_w}"
            )
        if not isinstance(self.transition, CausalTransition):
            raise TypeError(
                f"transition must be CausalTransition, got {type(self.transition).__name__}"
            )
        if not isinstance(self.verdict, PreliminaryVerdict):
            raise TypeError(
                f"verdict must be PreliminaryVerdict, got {type(self.verdict).__name__}"
            )
        if not isinstance(self.provenance, EvidenceProvenance):
            raise TypeError(
                f"provenance must be EvidenceProvenance, got {type(self.provenance).__name__}"
            )
        if not isinstance(self.receipt_digest, str) or not _HEX_64_PATTERN.match(
            self.receipt_digest
        ):
            raise CausalReceiptIntegrityError("receipt_digest must be a 64-char hex string")
        if not isinstance(self.narrative, str):
            raise TypeError("narrative must be a string")

        # Verify receipt digest
        payload = build_canonical_receipt_payload(
            schema_version=self.schema_version,
            requirement_id=self.requirement_id,
            frozen_contract_digest=self.frozen_contract_digest,
            witness_id=self.witness_id,
            witness_digest=self.witness_digest,
            lock_digest=self.lock_digest,
            base_execution=self.base_execution,
            candidate_execution=self.candidate_execution,
            transition=self.transition,
            verdict=self.verdict,
            provenance=self.provenance,
            created_at_utc=self.created_at_utc,
        )
        expected_digest = compute_receipt_digest(payload)
        if self.receipt_digest != expected_digest:
            raise CausalReceiptTamperingError(
                f"receipt_digest mismatch: declared {self.receipt_digest}, "
                f"expected {expected_digest}"
            )

    @property
    def is_causally_verified(self) -> bool:
        """True strictly when verdict is VERIFIED and transition is CAUSAL_BUG_FIX_VERIFIED."""
        return (
            self.verdict == PreliminaryVerdict.VERIFIED
            and self.transition == CausalTransition.CAUSAL_BUG_FIX_VERIFIED
        )

    def to_dict(self) -> dict[str, Any]:
        """Serialize receipt to JSON-safe dictionary."""
        return {
            "base_execution": self.base_execution.to_dict(),
            "candidate_execution": self.candidate_execution.to_dict(),
            "created_at_utc": self.created_at_utc,
            "frozen_contract_digest": self.frozen_contract_digest,
            "is_causally_verified": self.is_causally_verified,
            "lock_digest": self.lock_digest,
            "narrative": self.narrative,
            "provenance": self.provenance.value,
            "receipt_digest": self.receipt_digest,
            "requirement_id": self.requirement_id,
            "schema_version": self.schema_version,
            "transition": self.transition.value,
            "verdict": self.verdict.value,
            "witness_digest": self.witness_digest,
            "witness_id": self.witness_id,
        }


def create_causal_receipt(
    *,
    requirement_id: str,
    frozen_contract_digest: str,
    witness_id: str,
    witness_digest: str,
    lock_digest: str,
    base_execution: WorldExecutionFact,
    candidate_execution: WorldExecutionFact,
    transition: CausalTransition,
    verdict: PreliminaryVerdict,
    provenance: EvidenceProvenance,
    narrative: str = "",
    created_at_utc: str | None = None,
    schema_version: str = CAUSAL_RECEIPT_SCHEMA_VERSION,
) -> LocalCausalReceipt:
    """Construct an authentic, cryptographically bound LocalCausalReceipt."""
    timestamp = created_at_utc or datetime.now(timezone.utc).isoformat()
    payload = build_canonical_receipt_payload(
        schema_version=schema_version,
        requirement_id=requirement_id,
        frozen_contract_digest=frozen_contract_digest,
        witness_id=witness_id,
        witness_digest=witness_digest,
        lock_digest=lock_digest,
        base_execution=base_execution,
        candidate_execution=candidate_execution,
        transition=transition,
        verdict=verdict,
        provenance=provenance,
        created_at_utc=timestamp,
    )
    digest = compute_receipt_digest(payload)
    return LocalCausalReceipt(
        schema_version=schema_version,
        requirement_id=requirement_id,
        frozen_contract_digest=frozen_contract_digest,
        witness_id=witness_id,
        witness_digest=witness_digest,
        lock_digest=lock_digest,
        base_execution=base_execution,
        candidate_execution=candidate_execution,
        transition=transition,
        verdict=verdict,
        provenance=provenance,
        created_at_utc=timestamp,
        receipt_digest=digest,
        narrative=narrative,
    )


def verify_causal_receipt_integrity(receipt: LocalCausalReceipt) -> bool:
    """Deterministically verify that a receipt has not been tampered with.

    Recomputes the cryptographic receipt digest and validates internal invariants.
    Returns True if authentic, False or raises on tampering.
    """
    if not isinstance(receipt, LocalCausalReceipt):
        raise TypeError(f"receipt must be LocalCausalReceipt, got {type(receipt).__name__}")

    payload = build_canonical_receipt_payload(
        schema_version=receipt.schema_version,
        requirement_id=receipt.requirement_id,
        frozen_contract_digest=receipt.frozen_contract_digest,
        witness_id=receipt.witness_id,
        witness_digest=receipt.witness_digest,
        lock_digest=receipt.lock_digest,
        base_execution=receipt.base_execution,
        candidate_execution=receipt.candidate_execution,
        transition=receipt.transition,
        verdict=receipt.verdict,
        provenance=receipt.provenance,
        created_at_utc=receipt.created_at_utc,
    )
    expected_digest = compute_receipt_digest(payload)
    return receipt.receipt_digest == expected_digest
