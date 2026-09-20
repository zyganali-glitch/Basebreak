"""Run and evidence append model with immutable identifiers.

Implements provider-neutral deterministic append-only fact history.
Enforces immutable run identity, independent evidence identity, candidate/source
binding, tamper-evident fact digests, and prevents evidence rebinding or mutation.
"""

from __future__ import annotations

import json
import re
from dataclasses import dataclass
from typing import Any

from basebreak.domain.causal import CandidateIdentity, CausalBinding
from basebreak.domain.execution import ExecutionCommand, ExecutionResult
from basebreak.domain.serialization import to_dict
from basebreak.domain.verdict import EvidenceProvenance
from basebreak.evidence.artifact import (
    ArtifactDigest,
    ArtifactReference,
    compute_bytes_digest,
)

_IDENTIFIER_REGEX = re.compile(r"^[a-zA-Z0-9_\-]+$")


class EvidenceError(Exception):
    """Base exception for evidence store errors."""


class EvidenceConflictError(EvidenceError):
    """Raised when appending a duplicate evidence ID with conflicting contents."""


class EvidenceRebindingError(EvidenceError):
    """Raised when evidence is illegally rebound across runs or candidates."""


class EvidenceSequenceError(EvidenceError):
    """Raised when an evidence record violates per-run sequence continuity or monotonicity."""


def _validate_clean_identifier(value: str, field_name: str) -> None:
    if not isinstance(value, str):
        raise TypeError(f"{field_name} must be a str, got {type(value).__name__}")
    if not value.strip():
        raise ValueError(f"{field_name} cannot be empty or whitespace only")
    if value.strip() != value:
        raise ValueError(f"{field_name} cannot contain leading or trailing whitespace")
    if "refs/" in value or "heads/" in value or "refs\\" in value:
        raise ValueError(f"{field_name} cannot be a git ref: {value!r}")
    if "/" in value or "\\" in value or ":" in value:
        raise ValueError(f"{field_name} cannot be a path: {value!r}")
    if not _IDENTIFIER_REGEX.match(value):
        raise ValueError(
            f"{field_name} must contain only alphanumeric characters, "
            f"dashes, and underscores: {value!r}"
        )


@dataclass(frozen=True)
class RunIdentity:
    """Immutable identifier for an execution run.

    Explicitly rejects mutable workspace paths and branch names.
    """

    run_id: str

    def __post_init__(self) -> None:
        _validate_clean_identifier(self.run_id, "run_id")


@dataclass(frozen=True)
class EvidenceIdentity:
    """Immutable identifier for an individual evidence item."""

    evidence_id: str

    def __post_init__(self) -> None:
        _validate_clean_identifier(self.evidence_id, "evidence_id")


def authoritative_candidate_payload(candidate: CandidateIdentity | None) -> dict[str, Any] | None:
    """Extract authoritative identity facts of a candidate, excluding prose/RequestedRef."""
    if candidate is None:
        return None
    return {
        "candidate_id": candidate.candidate_id,
        "patch_digest": candidate.patch_digest,
        "source": {
            "locator": candidate.source.locator,
            "resolved_commit_id": candidate.source.resolved_commit_id,
            "subpath": candidate.source.subpath,
        },
    }


def authoritative_candidate_equals(
    a: CandidateIdentity | None, b: CandidateIdentity | None
) -> bool:
    """Check whether two candidate identities share identical authoritative identity facts."""
    if a is None or b is None:
        return a is b
    return (
        a.candidate_id == b.candidate_id
        and a.patch_digest == b.patch_digest
        and a.source.locator == b.source.locator
        and a.source.resolved_commit_id == b.source.resolved_commit_id
        and a.source.subpath == b.source.subpath
    )


def _compute_record_fact_digest(
    evidence_id: EvidenceIdentity,
    run_id: RunIdentity,
    sequence_number: int,
    provenance: EvidenceProvenance,
    candidate: CandidateIdentity | None,
    causal_binding: CausalBinding | None,
    command: ExecutionCommand | None,
    result: ExecutionResult | None,
    artifacts: tuple[ArtifactReference, ...],
    recorded_at_epoch_ms: int,
) -> ArtifactDigest:
    """Compute cryptographic digest covering all factual fields of an evidence record."""
    facts = {
        "artifacts": [art.to_dict() for art in artifacts],
        "candidate": authoritative_candidate_payload(candidate),
        "causal_binding": causal_binding.binding_digest if causal_binding is not None else None,
        "command": to_dict(command) if command is not None else None,
        "evidence_id": evidence_id.evidence_id,
        "provenance": provenance.value,
        "recorded_at_epoch_ms": recorded_at_epoch_ms,
        "result": to_dict(result) if result is not None else None,
        "run_id": run_id.run_id,
        "sequence_number": sequence_number,
    }
    raw_json = json.dumps(facts, sort_keys=True, separators=(",", ":"), ensure_ascii=False)
    return compute_bytes_digest(raw_json.encode("utf-8"))


@dataclass(frozen=True)
class EvidenceRecord:
    """Immutable record of an observed evidence fact.

    Binds evidence to its exact run, candidate, command, result, and content-addressed artifacts.
    Enforces tamper-evident fact digests.
    """

    evidence_id: EvidenceIdentity
    run_id: RunIdentity
    sequence_number: int
    provenance: EvidenceProvenance
    candidate: CandidateIdentity | None = None
    causal_binding: CausalBinding | None = None
    command: ExecutionCommand | None = None
    result: ExecutionResult | None = None
    artifacts: tuple[ArtifactReference, ...] = ()
    recorded_at_epoch_ms: int = 0
    fact_digest: ArtifactDigest | None = None

    def __post_init__(self) -> None:
        if not isinstance(self.evidence_id, EvidenceIdentity):
            raise TypeError(
                f"evidence_id must be an EvidenceIdentity, got {type(self.evidence_id).__name__}"
            )
        if not isinstance(self.run_id, RunIdentity):
            raise TypeError(f"run_id must be a RunIdentity, got {type(self.run_id).__name__}")
        if isinstance(self.sequence_number, bool) or not isinstance(self.sequence_number, int):
            raise TypeError(
                f"sequence_number must be an int (not bool), "
                f"got {type(self.sequence_number).__name__}"
            )
        if self.sequence_number < 0:
            raise ValueError(f"sequence_number must be non-negative, got {self.sequence_number}")
        if not isinstance(self.provenance, EvidenceProvenance):
            raise TypeError(
                f"provenance must be an EvidenceProvenance, got {type(self.provenance).__name__}"
            )
        if self.candidate is not None and not isinstance(self.candidate, CandidateIdentity):
            raise TypeError(
                f"candidate must be CandidateIdentity or None, got {type(self.candidate).__name__}"
            )
        if self.causal_binding is not None and not isinstance(self.causal_binding, CausalBinding):
            raise TypeError(
                f"causal_binding must be CausalBinding or None, "
                f"got {type(self.causal_binding).__name__}"
            )
        if self.candidate is not None and self.causal_binding is not None:
            if not authoritative_candidate_equals(self.candidate, self.causal_binding.candidate):
                raise ValueError(
                    f"Candidate mismatch: record candidate '{self.candidate.candidate_id}' "
                    f"does not match causal_binding candidate "
                    f"'{self.causal_binding.candidate.candidate_id}'"
                )
        if self.command is not None and not isinstance(self.command, ExecutionCommand):
            raise TypeError(
                f"command must be ExecutionCommand or None, got {type(self.command).__name__}"
            )
        if self.result is not None and not isinstance(self.result, ExecutionResult):
            raise TypeError(
                f"result must be ExecutionResult or None, got {type(self.result).__name__}"
            )
        if not isinstance(self.artifacts, tuple):
            raise TypeError(f"artifacts must be a tuple, got {type(self.artifacts).__name__}")
        for idx, art in enumerate(self.artifacts):
            if not isinstance(art, ArtifactReference):
                raise TypeError(
                    f"artifact at index {idx} must be an ArtifactReference, "
                    f"got {type(art).__name__}"
                )
        if isinstance(self.recorded_at_epoch_ms, bool) or not isinstance(
            self.recorded_at_epoch_ms, int
        ):
            raise TypeError(
                f"recorded_at_epoch_ms must be an int (not bool), "
                f"got {type(self.recorded_at_epoch_ms).__name__}"
            )
        if self.recorded_at_epoch_ms < 0:
            raise ValueError(
                f"recorded_at_epoch_ms must be non-negative, got {self.recorded_at_epoch_ms}"
            )

        computed = _compute_record_fact_digest(
            evidence_id=self.evidence_id,
            run_id=self.run_id,
            sequence_number=self.sequence_number,
            provenance=self.provenance,
            candidate=self.candidate,
            causal_binding=self.causal_binding,
            command=self.command,
            result=self.result,
            artifacts=self.artifacts,
            recorded_at_epoch_ms=self.recorded_at_epoch_ms,
        )

        if self.fact_digest is None:
            object.__setattr__(self, "fact_digest", computed)
        elif self.fact_digest != computed:
            raise ValueError(
                f"EvidenceRecord fact digest mismatch: declared {self.fact_digest.value} "
                f"does not match computed {computed.value}"
            )

    @property
    def effective_candidate(self) -> CandidateIdentity | None:
        """Derive effective candidate from direct candidate or causal_binding."""
        if self.candidate is not None:
            return self.candidate
        if self.causal_binding is not None:
            return self.causal_binding.candidate
        return None

    def to_dict(self) -> dict[str, Any]:
        """Serialize evidence record facts to a dictionary."""
        return {
            "artifacts": [art.to_dict() for art in self.artifacts],
            "candidate": to_dict(self.candidate) if self.candidate is not None else None,
            "causal_binding": (
                to_dict(self.causal_binding) if self.causal_binding is not None else None
            ),
            "command": to_dict(self.command) if self.command is not None else None,
            "evidence_id": self.evidence_id.evidence_id,
            "fact_digest": self.fact_digest.to_dict() if self.fact_digest is not None else None,
            "provenance": self.provenance.value,
            "recorded_at_epoch_ms": self.recorded_at_epoch_ms,
            "result": to_dict(self.result) if self.result is not None else None,
            "run_id": self.run_id.run_id,
            "sequence_number": self.sequence_number,
        }


class EvidenceStore:
    """In-memory append-only fact history store.

    Enforces:
    - append-only semantics (no in-place modification or replacement);
    - duplicate identity detection (idempotent if identical, conflict error if differing);
    - candidate and run boundary preservation (no cross-run or cross-candidate rebinding);
    - per-run deterministic sequence continuity and monotonicity (starts at 0, no gaps/dups);
    - deterministic retrieval order.
    """

    def __init__(
        self,
        run_id: RunIdentity | None = None,
        candidate: CandidateIdentity | None = None,
    ) -> None:
        if run_id is not None and not isinstance(run_id, RunIdentity):
            raise TypeError(f"run_id must be RunIdentity or None, got {type(run_id).__name__}")
        if candidate is not None and not isinstance(candidate, CandidateIdentity):
            raise TypeError(
                f"candidate must be CandidateIdentity or None, got {type(candidate).__name__}"
            )
        self._run_id = run_id
        self._candidate = candidate
        self._records: list[EvidenceRecord] = []
        self._by_id: dict[str, EvidenceRecord] = {}
        self._run_next_sequence: dict[str, int] = {}

    @property
    def run_id(self) -> RunIdentity | None:
        return self._run_id

    @property
    def candidate(self) -> CandidateIdentity | None:
        return self._candidate

    def append(self, record: EvidenceRecord) -> None:
        """Append a new evidence record.

        Raises:
            TypeError: if record is not an EvidenceRecord.
            EvidenceRebindingError: if record violates store run or candidate binding.
            EvidenceConflictError: if record with same evidence_id has conflicting contents.
            EvidenceSequenceError: if record violates per-run sequence continuity.
        """
        if not isinstance(record, EvidenceRecord):
            raise TypeError(f"record must be an EvidenceRecord, got {type(record).__name__}")

        if self._run_id is not None and record.run_id != self._run_id:
            raise EvidenceRebindingError(
                f"Cannot append evidence for run '{record.run_id.run_id}' "
                f"to store bound to run '{self._run_id.run_id}'"
            )

        if self._candidate is not None:
            effective = record.effective_candidate
            if effective is None:
                raise EvidenceRebindingError(
                    f"Cannot append un-bound candidate evidence to store bound to candidate "
                    f"'{self._candidate.candidate_id}'"
                )
            if not authoritative_candidate_equals(effective, self._candidate):
                raise EvidenceRebindingError(
                    f"Cannot append evidence for candidate '{effective.candidate_id}' "
                    f"to store bound to candidate '{self._candidate.candidate_id}'"
                )

        ev_id = record.evidence_id.evidence_id
        if ev_id in self._by_id:
            existing = self._by_id[ev_id]
            if existing.fact_digest is not None and existing.fact_digest == record.fact_digest:
                # Idempotent append: preserves sequence state without advancing
                return
            if existing.provenance != record.provenance:
                raise EvidenceConflictError(
                    f"Duplicate evidence ID '{ev_id}' with conflicting contents: "
                    f"conflicting provenance (existing '{existing.provenance.value}' "
                    f"vs new '{record.provenance.value}')"
                )
            existing_d = existing.fact_digest.value if existing.fact_digest else "none"
            new_d = record.fact_digest.value if record.fact_digest else "none"
            raise EvidenceConflictError(
                f"Duplicate evidence ID '{ev_id}' with conflicting contents. "
                f"Existing digest: {existing_d}, New digest: {new_d}"
            )

        run_key = record.run_id.run_id
        expected_seq = self._run_next_sequence.get(run_key, 0)
        if record.sequence_number != expected_seq:
            raise EvidenceSequenceError(
                f"Invalid sequence_number {record.sequence_number} for run '{run_key}'. "
                f"Expected sequence_number {expected_seq}."
            )

        self._run_next_sequence[run_key] = expected_seq + 1
        self._records.append(record)
        self._by_id[ev_id] = record

    def get(self, evidence_id: EvidenceIdentity | str) -> EvidenceRecord | None:
        """Retrieve an evidence record by identity."""
        key = evidence_id.evidence_id if isinstance(evidence_id, EvidenceIdentity) else evidence_id
        return self._by_id.get(key)

    def get_for_run(self, run_id: RunIdentity | str) -> tuple[EvidenceRecord, ...]:
        """Retrieve all records for a specific run in deterministic sequence order."""
        key = run_id.run_id if isinstance(run_id, RunIdentity) else run_id
        matching = [r for r in self._records if r.run_id.run_id == key]
        return tuple(sorted(matching, key=lambda r: r.sequence_number))

    def all_records(self) -> tuple[EvidenceRecord, ...]:
        """Retrieve all recorded facts in deterministic append sequence order."""
        return tuple(self._records)

    def __len__(self) -> int:
        return len(self._records)
