"""Immutable witness lock and pre-candidate execution digest preservation.

P-09.06: Preserve witness digest before candidate execution.

Core Invariants:
1. Pre-execution lock: The immutable witness digest must be computed, cryptographically bound,
   and locked before ANY candidate execution takes place.
2. Identical witness enforcement: BASE and CANDIDATE worlds must execute against the
   exact same witness identity and digest.
3. Anti-regeneration defense: Re-generating a witness between BASE and CANDIDATE runs or
   adapting a witness in response to candidate observations is strictly prohibited.
4. Unbroken identity chain: Validates mechanical binding:
   requirement -> frozen_contract_digest -> witness_digest.
"""

from __future__ import annotations

import hashlib
import json
import re
from collections.abc import Mapping
from dataclasses import dataclass
from datetime import datetime, timezone
from typing import Any

from basebreak.compiler.freeze import FrozenContract
from basebreak.verifier.witness_store import SealedWitnessRecord, TrustedWitnessVault

_HEX_40_PATTERN = re.compile(r"^[0-9a-f]{40}$")
_HEX_64_PATTERN = re.compile(r"^[0-9a-f]{64}$")


class WitnessLockError(Exception):
    """Base exception for witness locking and chain of custody errors."""


class WitnessMutationError(WitnessLockError):
    """Raised when a witness has mutated between BASE and CANDIDATE executions."""


class WitnessRebindingError(WitnessLockError):
    """Raised when witness identity is rebound to a different contract or requirement."""


class WitnessLockIntegrityError(WitnessLockError):
    """Raised when lock tamper checks or cryptographic verification fail."""


def build_canonical_witness_lock_payload(
    *,
    witness_id: str,
    witness_digest: str,
    frozen_contract_digest: str,
    requirement_id: str,
    source_commit_id: str,
    artifact_paths: tuple[str, ...],
    artifact_digests: tuple[str, ...],
    locked_at_utc: str,
) -> dict[str, Any]:
    """Construct deterministic payload for witness lock digest computation."""
    return {
        "artifact_digests": list(artifact_digests),
        "artifact_paths": list(artifact_paths),
        "frozen_contract_digest": str(frozen_contract_digest),
        "locked_at_utc": str(locked_at_utc),
        "requirement_id": str(requirement_id),
        "source_commit_id": str(source_commit_id),
        "witness_digest": str(witness_digest),
        "witness_id": str(witness_id),
    }


def compute_lock_digest(payload: Mapping[str, Any]) -> str:
    """Compute deterministic SHA-256 digest over canonical JSON bytes."""
    canonical_bytes = json.dumps(
        payload, sort_keys=True, separators=(",", ":"), ensure_ascii=False
    ).encode("utf-8")
    return hashlib.sha256(canonical_bytes).hexdigest()


@dataclass(frozen=True, slots=True)
class ImmutableWitnessLock:
    """Immutable lock preserving witness identity before candidate execution."""

    witness_id: str
    witness_digest: str
    frozen_contract_digest: str
    requirement_id: str
    source_commit_id: str
    artifact_paths: tuple[str, ...]
    artifact_digests: tuple[str, ...]
    locked_at_utc: str
    lock_digest: str

    def __post_init__(self) -> None:
        if not isinstance(self.witness_id, str) or not self.witness_id.strip():
            raise WitnessLockError("witness_id must be a non-empty string")
        if not isinstance(self.witness_digest, str) or not _HEX_64_PATTERN.match(
            self.witness_digest
        ):
            raise WitnessLockError("witness_digest must be a 64-char hex string")
        if not isinstance(self.frozen_contract_digest, str) or not _HEX_64_PATTERN.match(
            self.frozen_contract_digest
        ):
            raise WitnessLockError("frozen_contract_digest must be a 64-char hex string")
        if not isinstance(self.requirement_id, str) or not self.requirement_id.strip():
            raise WitnessLockError("requirement_id must be a non-empty string")
        if not isinstance(self.source_commit_id, str) or not _HEX_40_PATTERN.match(
            self.source_commit_id
        ):
            raise WitnessLockError("source_commit_id must be a 40-char commit SHA")
        if not isinstance(self.artifact_paths, tuple) or not self.artifact_paths:
            raise WitnessLockError("artifact_paths must be a non-empty tuple")
        if not isinstance(self.artifact_digests, tuple) or len(self.artifact_digests) != len(
            self.artifact_paths
        ):
            raise WitnessLockError("artifact_digests must match artifact_paths length")

        payload = build_canonical_witness_lock_payload(
            witness_id=self.witness_id,
            witness_digest=self.witness_digest,
            frozen_contract_digest=self.frozen_contract_digest,
            requirement_id=self.requirement_id,
            source_commit_id=self.source_commit_id,
            artifact_paths=self.artifact_paths,
            artifact_digests=self.artifact_digests,
            locked_at_utc=self.locked_at_utc,
        )
        expected_lock = compute_lock_digest(payload)
        if self.lock_digest != expected_lock:
            raise WitnessLockIntegrityError(
                f"lock_digest mismatch: declared {self.lock_digest}, expected {expected_lock}"
            )

    def to_dict(self) -> dict[str, Any]:
        return {
            "artifact_digests": list(self.artifact_digests),
            "artifact_paths": list(self.artifact_paths),
            "frozen_contract_digest": self.frozen_contract_digest,
            "lock_digest": self.lock_digest,
            "locked_at_utc": self.locked_at_utc,
            "requirement_id": self.requirement_id,
            "source_commit_id": self.source_commit_id,
            "witness_digest": self.witness_digest,
            "witness_id": self.witness_id,
        }


def create_witness_lock(
    record: SealedWitnessRecord,
    vault: TrustedWitnessVault,
    *,
    locked_at_utc: str | None = None,
) -> ImmutableWitnessLock:
    """Create an ImmutableWitnessLock from an authentic sealed witness record.

    Verifies vault signature and integrity before locking.
    """
    if not isinstance(vault, TrustedWitnessVault):
        raise TypeError(f"vault must be TrustedWitnessVault, got {type(vault).__name__}")
    if not isinstance(record, SealedWitnessRecord):
        raise TypeError(f"record must be SealedWitnessRecord, got {type(record).__name__}")

    # Mechanically verify authentic cryptographic authority
    vault.verify_witness_integrity(record)

    timestamp = locked_at_utc or datetime.now(timezone.utc).isoformat()
    paths = tuple(a.path for a in record.artifacts)
    digests = tuple(a.content_digest for a in record.artifacts)

    payload = build_canonical_witness_lock_payload(
        witness_id=record.witness_id,
        witness_digest=record.seal_digest,
        frozen_contract_digest=record.frozen_contract_digest,
        requirement_id=record.requirement_id,
        source_commit_id=record.source_commit_id,
        artifact_paths=paths,
        artifact_digests=digests,
        locked_at_utc=timestamp,
    )
    lock_digest = compute_lock_digest(payload)

    return ImmutableWitnessLock(
        witness_id=record.witness_id,
        witness_digest=record.seal_digest,
        frozen_contract_digest=record.frozen_contract_digest,
        requirement_id=record.requirement_id,
        source_commit_id=record.source_commit_id,
        artifact_paths=paths,
        artifact_digests=digests,
        locked_at_utc=timestamp,
        lock_digest=lock_digest,
    )


def verify_witness_lock_chain(
    *,
    lock: ImmutableWitnessLock,
    frozen_contract: FrozenContract,
    base_record: SealedWitnessRecord,
    candidate_record: SealedWitnessRecord | None = None,
) -> bool:
    """Verify unbroken chain of custody:

    requirement -> frozen_contract_digest -> witness_digest (BASE == CANDIDATE).
    """
    if not isinstance(lock, ImmutableWitnessLock):
        raise TypeError(f"lock must be ImmutableWitnessLock, got {type(lock).__name__}")
    if not isinstance(frozen_contract, FrozenContract):
        raise TypeError(
            f"frozen_contract must be FrozenContract, got {type(frozen_contract).__name__}"
        )
    if not isinstance(base_record, SealedWitnessRecord):
        raise TypeError(
            f"base_record must be SealedWitnessRecord, got {type(base_record).__name__}"
        )

    # 1. Contract digest match
    if lock.frozen_contract_digest != frozen_contract.contract_digest:
        raise WitnessRebindingError(
            f"Witness lock contract digest {lock.frozen_contract_digest!r} does not match "
            f"frozen contract {frozen_contract.contract_digest!r}"
        )

    # 2. Requirement membership in contract
    contract_req_ids = {r.requirement_id for r in frozen_contract.requirements}
    if lock.requirement_id not in contract_req_ids:
        raise WitnessRebindingError(
            f"Locked requirement {lock.requirement_id!r} not found in frozen contract"
        )

    # 3. Base record matches lock
    if base_record.seal_digest != lock.witness_digest:
        raise WitnessMutationError(
            f"BASE witness seal digest {base_record.seal_digest!r} != {lock.witness_digest!r}"
        )
    if base_record.witness_id != lock.witness_id:
        raise WitnessRebindingError(
            f"BASE witness_id {base_record.witness_id!r} != locked {lock.witness_id!r}"
        )

    # 4. Candidate record (if present) must match EXACT same witness
    if candidate_record is not None:
        if not isinstance(candidate_record, SealedWitnessRecord):
            rec_type = type(candidate_record).__name__
            raise TypeError(f"candidate_record must be SealedWitnessRecord, got {rec_type}")
        if candidate_record.seal_digest != lock.witness_digest:
            raise WitnessMutationError(
                f"CANDIDATE witness seal digest {candidate_record.seal_digest!r} does not match "
                f"locked digest {lock.witness_digest!r}. Witness mutated or regenerated!"
            )
        if candidate_record.seal_digest != base_record.seal_digest:
            raise WitnessMutationError(
                f"CANDIDATE witness seal digest {candidate_record.seal_digest!r} differs from "
                f"BASE witness seal digest {base_record.seal_digest!r}!"
            )
        if candidate_record.witness_id != lock.witness_id:
            raise WitnessRebindingError(
                f"CANDIDATE witness_id {candidate_record.witness_id!r} differs from "
                f"locked ID {lock.witness_id!r}!"
            )

    return True
