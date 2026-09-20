"""Deterministic verdict-input snapshot binding.

Implements provider-neutral immutable snapshots of deterministic facts considered
by verifiers. Guarantees that a verdict can only be evaluated against an immutable,
cryptographically bound set of candidate, run, requirement, and evidence facts.
"""

from __future__ import annotations

import json
from dataclasses import dataclass
from typing import Any

from basebreak.domain.causal import CandidateIdentity, CausalBinding
from basebreak.domain.serialization import to_dict
from basebreak.evidence.append_model import (
    EvidenceConflictError,
    EvidenceRebindingError,
    EvidenceRecord,
    EvidenceSequenceError,
    EvidenceStore,
    RunIdentity,
    _validate_clean_identifier,
    authoritative_candidate_equals,
    authoritative_candidate_payload,
)
from basebreak.evidence.artifact import ArtifactDigest, compute_bytes_digest


def _compute_snapshot_digest(
    candidate: CandidateIdentity,
    run_id: RunIdentity,
    requirement_id: str,
    causal_binding: CausalBinding | None,
    records: tuple[EvidenceRecord, ...],
    schema_version: str,
) -> ArtifactDigest:
    """Compute deterministic cryptographic digest of all authoritative snapshot facts.

    Explicitly excludes non-authoritative prose (such as description).
    """
    authoritative_facts: dict[str, Any] = {
        "candidate": authoritative_candidate_payload(candidate),
        "causal_binding": causal_binding.binding_digest if causal_binding is not None else None,
        "records": [
            {
                "artifacts": [art.to_dict() for art in rec.artifacts],
                "command": to_dict(rec.command) if rec.command is not None else None,
                "evidence_id": rec.evidence_id.evidence_id,
                "fact_digest": rec.fact_digest.value if rec.fact_digest is not None else None,
                "provenance": rec.provenance.value,
                "result": to_dict(rec.result) if rec.result is not None else None,
                "sequence_number": rec.sequence_number,
            }
            for rec in records
        ],
        "requirement_id": requirement_id,
        "run_id": run_id.run_id,
        "schema_version": schema_version,
    }
    canonical_json = json.dumps(
        authoritative_facts, sort_keys=True, separators=(",", ":"), ensure_ascii=False
    )
    return compute_bytes_digest(canonical_json.encode("utf-8"))


@dataclass(frozen=True)
class VerdictInputSnapshot:
    """Immutable bound snapshot of deterministic evidence facts provided as verdict input.

    Binds:
    - candidate identity;
    - run identity;
    - requirement identity;
    - optional causal binding;
    - ordered sequence of evidence records;
    - cryptographic snapshot digest computed from canonical facts.

    Non-authoritative description prose does not alter the cryptographic digest.
    """

    candidate: CandidateIdentity
    run_id: RunIdentity
    requirement_id: str
    records: tuple[EvidenceRecord, ...]
    causal_binding: CausalBinding | None = None
    description: str = ""
    schema_version: str = "1.0"
    snapshot_digest: ArtifactDigest | None = None

    def __post_init__(self) -> None:
        if not isinstance(self.candidate, CandidateIdentity):
            raise TypeError(
                f"candidate must be CandidateIdentity, got {type(self.candidate).__name__}"
            )
        if not isinstance(self.run_id, RunIdentity):
            raise TypeError(f"run_id must be RunIdentity, got {type(self.run_id).__name__}")
        _validate_clean_identifier(self.requirement_id, "requirement_id")

        if self.causal_binding is not None:
            if not isinstance(self.causal_binding, CausalBinding):
                raise TypeError(
                    f"causal_binding must be CausalBinding or None, "
                    f"got {type(self.causal_binding).__name__}"
                )
            if not authoritative_candidate_equals(self.causal_binding.candidate, self.candidate):
                raise ValueError(
                    f"Causal binding candidate '{self.causal_binding.candidate.candidate_id}' "
                    f"does not match snapshot candidate '{self.candidate.candidate_id}'"
                )
            if self.causal_binding.requirement_id != self.requirement_id:
                raise ValueError(
                    f"Causal binding requirement_id '{self.causal_binding.requirement_id}' "
                    f"does not match snapshot requirement_id '{self.requirement_id}'"
                )

        if not isinstance(self.records, tuple):
            raise TypeError(f"records must be a tuple, got {type(self.records).__name__}")
        if not isinstance(self.description, str):
            raise TypeError(f"description must be a str, got {type(self.description).__name__}")
        if not isinstance(self.schema_version, str):
            raise TypeError(
                f"schema_version must be a str, got {type(self.schema_version).__name__}"
            )
        if self.snapshot_digest is not None and not isinstance(
            self.snapshot_digest, ArtifactDigest
        ):
            raise TypeError(
                f"snapshot_digest must be ArtifactDigest or None, "
                f"got {type(self.snapshot_digest).__name__}"
            )

        # Reject empty snapshot unconditionally
        if len(self.records) == 0:
            raise ValueError(
                "VerdictInputSnapshot requires at least one evidence record; "
                "empty records tuple rejected"
            )

        # Validate each record and enforce cross-run, cross-candidate, and sequence continuity
        seen_evidence_ids: set[str] = set()
        last_seq = -1
        for idx, rec in enumerate(self.records):
            if not isinstance(rec, EvidenceRecord):
                raise TypeError(
                    f"record at index {idx} must be an EvidenceRecord, got {type(rec).__name__}"
                )
            ev_id = rec.evidence_id.evidence_id
            if ev_id in seen_evidence_ids:
                raise EvidenceConflictError(
                    f"Duplicate evidence identity '{ev_id}' within snapshot"
                )
            seen_evidence_ids.add(ev_id)

            if rec.run_id != self.run_id:
                raise EvidenceRebindingError(
                    f"Cross-run evidence rejected: record '{ev_id}' "
                    f"has run '{rec.run_id.run_id}', expected '{self.run_id.run_id}'"
                )
            effective = rec.effective_candidate
            if effective is None:
                raise EvidenceRebindingError(
                    f"Candidate-unbound evidence rejected: record '{ev_id}' "
                    "has neither candidate nor causal_binding candidate, but snapshot is bound to "
                    f"candidate '{self.candidate.candidate_id}'"
                )
            if not authoritative_candidate_equals(effective, self.candidate):
                expected_cid = self.candidate.candidate_id
                raise EvidenceRebindingError(
                    f"Cross-candidate evidence rejected: record '{ev_id}' "
                    f"has candidate '{effective.candidate_id}', expected '{expected_cid}'"
                )
            if rec.sequence_number <= last_seq:
                raise EvidenceSequenceError(
                    f"Evidence record sequence out of order or duplicate at index {idx}: "
                    f"sequence_number {rec.sequence_number} <= previous {last_seq}"
                )
            last_seq = rec.sequence_number

        computed = _compute_snapshot_digest(
            candidate=self.candidate,
            run_id=self.run_id,
            requirement_id=self.requirement_id,
            causal_binding=self.causal_binding,
            records=self.records,
            schema_version=self.schema_version,
        )

        if self.snapshot_digest is None:
            object.__setattr__(self, "snapshot_digest", computed)
        elif self.snapshot_digest != computed:
            raise ValueError(
                f"Snapshot digest mismatch: declared {self.snapshot_digest.value} "
                f"does not match computed {computed.value}"
            )

    @classmethod
    def from_store(
        cls,
        store: EvidenceStore,
        requirement_id: str,
        causal_binding: CausalBinding | None = None,
        description: str = "",
    ) -> VerdictInputSnapshot:
        """Create a VerdictInputSnapshot from an EvidenceStore."""
        if store.run_id is None:
            raise ValueError("EvidenceStore must be bound to a run_id to create snapshot")
        if store.candidate is None:
            raise ValueError("EvidenceStore must be bound to a candidate to create snapshot")
        return cls(
            candidate=store.candidate,
            run_id=store.run_id,
            requirement_id=requirement_id,
            records=store.all_records(),
            causal_binding=causal_binding,
            description=description,
        )

    def to_dict(self) -> dict[str, Any]:
        """Serialize snapshot to dictionary."""
        return {
            "candidate": to_dict(self.candidate),
            "causal_binding": (
                to_dict(self.causal_binding) if self.causal_binding is not None else None
            ),
            "description": self.description,
            "records": [rec.to_dict() for rec in self.records],
            "requirement_id": self.requirement_id,
            "run_id": self.run_id.run_id,
            "schema_version": self.schema_version,
            "snapshot_digest": (
                self.snapshot_digest.to_dict() if self.snapshot_digest is not None else None
            ),
        }
