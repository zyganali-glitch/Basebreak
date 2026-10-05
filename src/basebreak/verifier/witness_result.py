"""Deterministic witness execution and result normalization contracts.

P-09.04: Add witness determinism/timeout/result normalization.

Core Invariants:
1. Strict outcome taxonomy: PASS, FAIL, ERROR, TIMEOUT, INVALID_PRECONDITION.
   Infrastructure ERROR and TIMEOUT must NEVER collapse into FAIL or PASS.
2. Cryptographic binding: Every result is bound to witness identity, seal digest,
   frozen contract digest, requirement ID, sandbox identity, source commit, and world.
3. Bounded sanitized capture: Standardized bounded secret-safe capture of stdout/stderr
   with cryptographic digests.
4. Deterministic result digest: Canonical serialization of facts computes immutable
   result digest.
5. Zero self-certification: Result record possesses zero causal authority on its own
   (is_authoritative=False).
"""

from __future__ import annotations

import hashlib
import json
import re
from collections.abc import Mapping
from dataclasses import dataclass
from enum import Enum
from typing import Any

from basebreak.domain.causal import ExecutionWorld
from basebreak.domain.execution import SandboxIdentity, TerminationStatus
from basebreak.domain.verdict import EvidenceProvenance
from basebreak.evidence.capture import StreamType, capture_stream

_HEX_40_PATTERN = re.compile(r"^[0-9a-f]{40}$")
_HEX_64_PATTERN = re.compile(r"^[0-9a-f]{64}$")


class WitnessOutcome(str, Enum):
    """Normalized outcome of an independent behavioral witness execution.

    Explicitly separates behavioral outcomes from execution/infrastructure outcomes.
    """

    PASS = "PASS"
    FAIL = "FAIL"
    ERROR = "ERROR"
    TIMEOUT = "TIMEOUT"
    INVALID_PRECONDITION = "INVALID_PRECONDITION"


class WitnessResultError(Exception):
    """Base exception for witness result errors."""


class CollapsedOutcomeError(WitnessResultError):
    """Raised when an execution error or timeout is collapsed into FAIL or PASS."""


@dataclass(frozen=True, slots=True)
class NormalizedWitnessResult:
    """Immutable, cryptographically bound record of a normalized witness execution."""

    witness_id: str
    witness_digest: str
    frozen_contract_digest: str
    requirement_id: str
    sandbox_id: str
    source_commit_id: str
    world: ExecutionWorld
    outcome: WitnessOutcome
    exit_code: int | None
    termination_status: TerminationStatus
    stdout_digest: str
    stderr_digest: str
    stdout_clean: str
    stderr_clean: str
    duration_seconds: float
    provenance: EvidenceProvenance
    result_digest: str
    is_authoritative: bool = False

    def __post_init__(self) -> None:
        if not isinstance(self.witness_id, str) or not self.witness_id.strip():
            raise WitnessResultError("witness_id must be a non-empty string")
        if not isinstance(self.witness_digest, str) or not _HEX_64_PATTERN.match(
            self.witness_digest
        ):
            raise WitnessResultError("witness_digest must be a 64-char hex string")
        if not isinstance(self.frozen_contract_digest, str) or not _HEX_64_PATTERN.match(
            self.frozen_contract_digest
        ):
            raise WitnessResultError("frozen_contract_digest must be a 64-char hex string")
        if not isinstance(self.requirement_id, str) or not self.requirement_id.strip():
            raise WitnessResultError("requirement_id must be a non-empty string")
        if not isinstance(self.sandbox_id, str) or not self.sandbox_id.strip():
            raise WitnessResultError("sandbox_id must be a non-empty string")
        if not isinstance(self.source_commit_id, str) or not _HEX_40_PATTERN.match(
            self.source_commit_id
        ):
            raise WitnessResultError("source_commit_id must be a 40-char commit SHA")
        if not isinstance(self.world, ExecutionWorld):
            raise TypeError("world must be ExecutionWorld")
        if not isinstance(self.outcome, WitnessOutcome):
            raise TypeError("outcome must be WitnessOutcome")
        if not isinstance(self.termination_status, TerminationStatus):
            raise TypeError("termination_status must be TerminationStatus")
        if not isinstance(self.provenance, EvidenceProvenance):
            raise TypeError("provenance must be EvidenceProvenance")

        # Invariant checks: do not collapse ERROR/TIMEOUT into FAIL or PASS
        if self.termination_status == TerminationStatus.TIMED_OUT:
            if self.outcome != WitnessOutcome.TIMEOUT:
                raise CollapsedOutcomeError(
                    f"TIMED_OUT termination status cannot be classified as {self.outcome.value}"
                )
        if self.termination_status in (
            TerminationStatus.FAILED_TO_START,
            TerminationStatus.CANCELLED,
        ):
            if self.outcome not in (WitnessOutcome.ERROR, WitnessOutcome.INVALID_PRECONDITION):
                status_val = self.termination_status.value
                raise CollapsedOutcomeError(
                    f"{status_val} status cannot be classified as {self.outcome.value}"
                )

        if not isinstance(self.stdout_digest, str) or not _HEX_64_PATTERN.match(self.stdout_digest):
            raise WitnessResultError("stdout_digest must be a 64-char hex string")
        if not isinstance(self.stderr_digest, str) or not _HEX_64_PATTERN.match(self.stderr_digest):
            raise WitnessResultError("stderr_digest must be a 64-char hex string")

        if (
            isinstance(self.duration_seconds, bool)
            or not isinstance(self.duration_seconds, (int, float))
            or self.duration_seconds < 0.0
        ):
            raise WitnessResultError("duration_seconds must be a non-negative number")

        if not isinstance(self.result_digest, str) or not _HEX_64_PATTERN.match(self.result_digest):
            raise WitnessResultError("result_digest must be a 64-char hex string")

        if self.is_authoritative is not False:
            raise WitnessResultError("is_authoritative must be strictly False")

        # Re-verify deterministic result digest
        payload = build_canonical_witness_result_payload(
            witness_id=self.witness_id,
            witness_digest=self.witness_digest,
            frozen_contract_digest=self.frozen_contract_digest,
            requirement_id=self.requirement_id,
            sandbox_id=self.sandbox_id,
            source_commit_id=self.source_commit_id,
            world=self.world,
            outcome=self.outcome,
            exit_code=self.exit_code,
            termination_status=self.termination_status,
            stdout_digest=self.stdout_digest,
            stderr_digest=self.stderr_digest,
            duration_seconds=self.duration_seconds,
            provenance=self.provenance,
        )
        expected_digest = compute_result_digest(payload)
        if self.result_digest != expected_digest:
            raise WitnessResultError(
                f"result_digest mismatch: declared {self.result_digest}, computed {expected_digest}"
            )

    def to_dict(self) -> dict[str, Any]:
        return {
            "duration_seconds": self.duration_seconds,
            "exit_code": self.exit_code,
            "frozen_contract_digest": self.frozen_contract_digest,
            "is_authoritative": self.is_authoritative,
            "outcome": self.outcome.value,
            "provenance": self.provenance.value,
            "requirement_id": self.requirement_id,
            "result_digest": self.result_digest,
            "sandbox_id": self.sandbox_id,
            "source_commit_id": self.source_commit_id,
            "stderr_clean": self.stderr_clean,
            "stderr_digest": self.stderr_digest,
            "stdout_clean": self.stdout_clean,
            "stdout_digest": self.stdout_digest,
            "termination_status": self.termination_status.value,
            "witness_digest": self.witness_digest,
            "witness_id": self.witness_id,
            "world": self.world.value,
        }


def build_canonical_witness_result_payload(
    *,
    witness_id: str,
    witness_digest: str,
    frozen_contract_digest: str,
    requirement_id: str,
    sandbox_id: str,
    source_commit_id: str,
    world: ExecutionWorld,
    outcome: WitnessOutcome,
    exit_code: int | None,
    termination_status: TerminationStatus,
    stdout_digest: str,
    stderr_digest: str,
    duration_seconds: float,
    provenance: EvidenceProvenance,
) -> dict[str, Any]:
    """Construct deterministic payload for result digest computation."""
    return {
        "duration_seconds": round(float(duration_seconds), 4),
        "exit_code": exit_code,
        "frozen_contract_digest": str(frozen_contract_digest),
        "outcome": outcome.value,
        "provenance": provenance.value,
        "requirement_id": str(requirement_id),
        "sandbox_id": str(sandbox_id),
        "source_commit_id": str(source_commit_id),
        "stderr_digest": str(stderr_digest),
        "stdout_digest": str(stdout_digest),
        "termination_status": termination_status.value,
        "witness_digest": str(witness_digest),
        "witness_id": str(witness_id),
        "world": world.value,
    }


def compute_result_digest(payload: Mapping[str, Any]) -> str:
    """Compute deterministic SHA-256 digest over canonical JSON bytes."""
    canonical_bytes = json.dumps(
        payload, sort_keys=True, separators=(",", ":"), ensure_ascii=False
    ).encode("utf-8")
    return hashlib.sha256(canonical_bytes).hexdigest()


def normalize_witness_execution(
    *,
    witness_id: str,
    witness_digest: str,
    frozen_contract_digest: str,
    requirement_id: str,
    sandbox_identity: SandboxIdentity,
    source_commit_id: str,
    world: ExecutionWorld,
    status: TerminationStatus,
    exit_code: int | None,
    stdout_raw: str | bytes,
    stderr_raw: str | bytes,
    duration_seconds: float,
    provenance: EvidenceProvenance,
    max_output_bytes: int = 65536,
    is_precondition_valid: bool = True,
    precondition_failure_reason: str = "",
) -> NormalizedWitnessResult:
    """Normalize raw execution facts into deterministic NormalizedWitnessResult."""
    if not isinstance(sandbox_identity, SandboxIdentity):
        raise TypeError(
            f"sandbox_identity must be SandboxIdentity, got {type(sandbox_identity).__name__}"
        )
    if not isinstance(world, ExecutionWorld):
        raise TypeError(f"world must be ExecutionWorld, got {type(world).__name__}")
    if not isinstance(status, TerminationStatus):
        raise TypeError(f"status must be TerminationStatus, got {type(status).__name__}")
    if not isinstance(provenance, EvidenceProvenance):
        raise TypeError(f"provenance must be EvidenceProvenance, got {type(provenance).__name__}")

    # Standardized capture of stdout & stderr
    stdout_stream = capture_stream(stdout_raw, StreamType.STDOUT, max_bytes=max_output_bytes)
    stderr_stream = capture_stream(stderr_raw, StreamType.STDERR, max_bytes=max_output_bytes)

    # Determine outcome without collapsing errors
    combined_output = (stdout_stream.sanitized_text + "\n" + stderr_stream.sanitized_text).lower()

    if status == TerminationStatus.TIMED_OUT:
        outcome = WitnessOutcome.TIMEOUT
    elif status in (TerminationStatus.CANCELLED, TerminationStatus.FAILED_TO_START):
        outcome = WitnessOutcome.ERROR
    elif not is_precondition_valid:
        outcome = WitnessOutcome.INVALID_PRECONDITION
    elif status == TerminationStatus.COMPLETED:
        if exit_code == 0:
            # Check for skipped / 0 tests collected
            if "collected 0 items" in combined_output or "no tests ran" in combined_output:
                outcome = WitnessOutcome.INVALID_PRECONDITION
            else:
                outcome = WitnessOutcome.PASS
        elif exit_code == 1:
            # Standard pytest exit code 1 means tests ran and at least one test failed
            # Check if it was an import error or syntax error before test collection
            if "modulenotfounderror" in combined_output or "importerror" in combined_output:
                outcome = WitnessOutcome.INVALID_PRECONDITION
            elif "syntaxerror" in combined_output:
                outcome = WitnessOutcome.ERROR
            else:
                outcome = WitnessOutcome.FAIL
        elif exit_code in (2, 3, 4):
            # Pytest exit codes: 2 (interrupted), 3 (internal error), 4 (usage error)
            outcome = WitnessOutcome.ERROR
        elif exit_code == 5:
            # Pytest exit code 5: no tests collected
            outcome = WitnessOutcome.INVALID_PRECONDITION
        else:
            # Generic non-zero exit code: check if behavioral failure is evident
            if "assertionerror" in combined_output or "fail" in combined_output:
                outcome = WitnessOutcome.FAIL
            else:
                outcome = WitnessOutcome.ERROR
    else:
        outcome = WitnessOutcome.ERROR

    payload = build_canonical_witness_result_payload(
        witness_id=witness_id,
        witness_digest=witness_digest,
        frozen_contract_digest=frozen_contract_digest,
        requirement_id=requirement_id,
        sandbox_id=sandbox_identity.sandbox_id,
        source_commit_id=source_commit_id,
        world=world,
        outcome=outcome,
        exit_code=exit_code,
        termination_status=status,
        stdout_digest=stdout_stream.full_digest.value,
        stderr_digest=stderr_stream.full_digest.value,
        duration_seconds=duration_seconds,
        provenance=provenance,
    )
    res_digest = compute_result_digest(payload)

    return NormalizedWitnessResult(
        witness_id=witness_id,
        witness_digest=witness_digest,
        frozen_contract_digest=frozen_contract_digest,
        requirement_id=requirement_id,
        sandbox_id=sandbox_identity.sandbox_id,
        source_commit_id=source_commit_id,
        world=world,
        outcome=outcome,
        exit_code=exit_code,
        termination_status=status,
        stdout_digest=stdout_stream.full_digest.value,
        stderr_digest=stderr_stream.full_digest.value,
        stdout_clean=stdout_stream.sanitized_text,
        stderr_clean=stderr_stream.sanitized_text,
        duration_seconds=duration_seconds,
        provenance=provenance,
        result_digest=res_digest,
        is_authoritative=False,
    )
