"""Repaired candidate lineage and cryptographic identity contracts.

P-14.04: Create repaired candidate with new exact hash.

Core Invariants:
1. Exact immutable state: Repaired candidate binds a NEW unique candidate identity,
   NEW patch digest, and NEW tree digest.
2. Anti-reuse laws:
   - Reusing old candidate ID fails closed (CandidateIdentityReuseError).
   - Unchanged patch or tree presented as repaired fails closed (UnchangedCandidateError).
3. Cryptographic lineage chain:
   candidate_n -> feedback_n -> context_n -> candidate_n+1
   Lineage unambiguously binds parent candidate facts, feedback digest, repair context digest,
   and repaired candidate facts.
4. Historical preservation: Historical candidate evidence is never overwritten.
5. Zero verdict authority: is_authoritative = False strictly enforced.
"""

from __future__ import annotations

import hashlib
import json
import re
from collections.abc import Mapping
from dataclasses import dataclass
from typing import Any

from basebreak.builder.capture import CandidateSnapshot
from basebreak.domain.source import SourceIdentity
from basebreak.repair.context import (
    BuilderRepairContextEnvelope,
    verify_builder_repair_context_integrity,
)
from basebreak.repair.feedback import RepairFeedbackError

REPAIR_LINEAGE_SCHEMA_VERSION: str = "1.0.0"

_HEX_40_OR_64_PATTERN = re.compile(r"^([0-9a-f]{40}|[0-9a-f]{64})$")
_HEX_64_PATTERN = re.compile(r"^[0-9a-f]{64}$")


class CandidateLineageError(RepairFeedbackError):
    """Base exception for candidate lineage errors."""


class CandidateIdentityReuseError(CandidateLineageError):
    """Raised when repaired candidate reuses parent candidate ID."""


class UnchangedCandidateError(CandidateLineageError):
    """Raised when repaired candidate has identical patch or tree as parent."""


class CandidateLineageMismatchError(CandidateLineageError):
    """Raised when candidate facts do not match context or lineage specifications."""


class CandidateLineageTamperingError(CandidateLineageError):
    """Raised when lineage record facts do not match cryptographic digest."""


def _validate_non_empty_str(val: str, field_name: str) -> None:
    if not isinstance(val, str):
        raise TypeError(f"{field_name} must be str, got {type(val).__name__}")
    if not val.strip():
        raise CandidateLineageError(f"{field_name} must not be empty or whitespace-only")


def _validate_hex_digest(digest: str, field_name: str, allow_40: bool = False) -> None:
    _validate_non_empty_str(digest, field_name)
    pat = _HEX_40_OR_64_PATTERN if allow_40 else _HEX_64_PATTERN
    if not pat.match(digest):
        expected = "40 or 64" if allow_40 else "64"
        raise CandidateLineageError(
            f"{field_name} must be a {expected} hex character string, got {digest!r}"
        )


@dataclass(frozen=True, slots=True)
class CandidateLineageRecord:
    """Immutable record tracking candidate progression across repair rounds."""

    lineage_id: str
    parent_candidate_id: str
    parent_tree_digest: str
    parent_patch_digest: str
    repaired_candidate_id: str
    repaired_tree_digest: str
    repaired_patch_digest: str
    repair_feedback_digest: str
    repair_context_digest: str
    repair_round: int
    source_identity: SourceIdentity
    lineage_digest: str
    builder_execution_identity: str | None = None
    schema_version: str = REPAIR_LINEAGE_SCHEMA_VERSION
    is_authoritative: bool = False

    def __post_init__(self) -> None:
        _validate_non_empty_str(self.lineage_id, "lineage_id")
        _validate_non_empty_str(self.parent_candidate_id, "parent_candidate_id")
        _validate_hex_digest(self.parent_tree_digest, "parent_tree_digest", allow_40=True)
        _validate_hex_digest(self.parent_patch_digest, "parent_patch_digest")
        _validate_non_empty_str(self.repaired_candidate_id, "repaired_candidate_id")
        _validate_hex_digest(self.repaired_tree_digest, "repaired_tree_digest", allow_40=True)
        _validate_hex_digest(self.repaired_patch_digest, "repaired_patch_digest")
        _validate_hex_digest(self.repair_feedback_digest, "repair_feedback_digest")
        _validate_hex_digest(self.repair_context_digest, "repair_context_digest")

        if not isinstance(self.repair_round, int) or self.repair_round < 1:
            raise CandidateLineageError(
                f"repair_round must be positive integer, got {self.repair_round!r}"
            )
        if not isinstance(self.source_identity, SourceIdentity):
            raise TypeError(
                f"source_identity must be SourceIdentity, got {type(self.source_identity).__name__}"
            )

        _validate_hex_digest(self.lineage_digest, "lineage_digest")

        # 1. Anti-reuse rules: candidate ID must not be reused
        if self.repaired_candidate_id == self.parent_candidate_id:
            raise CandidateIdentityReuseError(
                f"Repaired candidate cannot reuse parent candidate ID {self.parent_candidate_id!r}"
            )

        # 2. Anti-stagnation rules: patch and tree must not be identical to parent
        if self.repaired_patch_digest == self.parent_patch_digest:
            raise UnchangedCandidateError(
                f"Repaired patch digest {self.repaired_patch_digest!r} is identical to parent; "
                "unchanged patch cannot masquerade as repaired candidate"
            )
        if self.repaired_tree_digest.lower() == self.parent_tree_digest.lower():
            raise UnchangedCandidateError(
                f"Repaired tree digest {self.repaired_tree_digest!r} is identical to parent tree; "
                "unchanged tree cannot masquerade as repaired candidate"
            )

        # 3. Zero authority
        if self.is_authoritative:
            raise CandidateLineageError("CandidateLineageRecord cannot have is_authoritative=True")


@dataclass(frozen=True, slots=True)
class RepairedCandidateSnapshot:
    """Repaired candidate snapshot paired with authentic provenance and lineage."""

    candidate: CandidateSnapshot
    lineage: CandidateLineageRecord
    is_authoritative: bool = False

    def __post_init__(self) -> None:
        if not isinstance(self.candidate, CandidateSnapshot):
            raise TypeError(
                f"candidate must be CandidateSnapshot, got {type(self.candidate).__name__}"
            )
        if not isinstance(self.lineage, CandidateLineageRecord):
            raise TypeError(
                f"lineage must be CandidateLineageRecord, got {type(self.lineage).__name__}"
            )

        # Verify candidate matches lineage facts
        if self.candidate.candidate_id != self.lineage.repaired_candidate_id:
            raise CandidateLineageMismatchError(
                f"Candidate ID {self.candidate.candidate_id!r} does not match lineage "
                f"repaired_candidate_id {self.lineage.repaired_candidate_id!r}"
            )
        if (
            self.candidate.candidate_tree_digest.lower()
            != self.lineage.repaired_tree_digest.lower()
        ):
            raise CandidateLineageMismatchError(
                f"Candidate tree digest {self.candidate.candidate_tree_digest!r} does not match "
                f"lineage repaired_tree_digest {self.lineage.repaired_tree_digest!r}"
            )
        if self.candidate.patch_digest != self.lineage.repaired_patch_digest:
            raise CandidateLineageMismatchError(
                f"Candidate patch digest {self.candidate.patch_digest!r} does not match "
                f"lineage repaired_patch_digest {self.lineage.repaired_patch_digest!r}"
            )
        if self.candidate.source_identity != self.lineage.source_identity:
            raise CandidateLineageMismatchError(
                "Candidate source_identity does not match lineage source_identity"
            )

        if self.is_authoritative or self.candidate.is_authoritative:
            raise CandidateLineageError("Repaired candidate cannot claim verdict authority")

    @property
    def repaired_candidate_id(self) -> str:
        """Convenience property for candidate ID."""
        return self.candidate.candidate_id

    @property
    def repaired_patch(self) -> str:
        """Convenience property for patch text."""
        return self.candidate.patch_text

    @property
    def repaired_patch_digest(self) -> str:
        """Convenience property for patch digest."""
        return self.candidate.patch_digest

    @property
    def repaired_tree_digest(self) -> str:
        """Convenience property for candidate tree digest."""
        return self.candidate.candidate_tree_digest

    @property
    def source_identity(self) -> SourceIdentity:
        """Convenience property for source identity."""
        return self.candidate.source_identity


def build_canonical_lineage_payload(
    *,
    schema_version: str,
    lineage_id: str,
    parent_candidate_id: str,
    parent_tree_digest: str,
    parent_patch_digest: str,
    repaired_candidate_id: str,
    repaired_tree_digest: str,
    repaired_patch_digest: str,
    repair_feedback_digest: str,
    repair_context_digest: str,
    repair_round: int,
    source_identity: SourceIdentity,
    builder_execution_identity: str | None = None,
    is_authoritative: bool = False,
) -> dict[str, Any]:
    """Construct deterministic dictionary payload for lineage record hashing."""
    return {
        "builder_execution_identity": builder_execution_identity,
        "is_authoritative": is_authoritative,
        "lineage_id": lineage_id,
        "parent_candidate_id": parent_candidate_id,
        "parent_patch_digest": parent_patch_digest,
        "parent_tree_digest": parent_tree_digest.lower(),
        "repair_context_digest": repair_context_digest,
        "repair_feedback_digest": repair_feedback_digest,
        "repair_round": repair_round,
        "repaired_candidate_id": repaired_candidate_id,
        "repaired_patch_digest": repaired_patch_digest,
        "repaired_tree_digest": repaired_tree_digest.lower(),
        "schema_version": schema_version,
        "source_identity": {
            "locator": source_identity.locator,
            "resolved_commit_id": source_identity.resolved_commit_id,
            "subpath": source_identity.subpath,
        },
    }


def compute_lineage_digest(payload: Mapping[str, Any]) -> str:
    """Compute deterministic SHA-256 digest from canonical JSON representation."""
    canonical_json = json.dumps(
        payload,
        ensure_ascii=False,
        sort_keys=True,
        separators=(",", ":"),
    )
    return hashlib.sha256(canonical_json.encode("utf-8")).hexdigest()


def create_candidate_lineage_record(
    *,
    lineage_id: str,
    context: BuilderRepairContextEnvelope,
    repaired_candidate_id: str,
    repaired_tree_digest: str,
    repaired_patch_digest: str,
    builder_execution_identity: str | None = None,
) -> CandidateLineageRecord:
    """Construct an immutable CandidateLineageRecord bound to repair context."""
    # Verify context integrity first
    verify_builder_repair_context_integrity(context)

    payload = build_canonical_lineage_payload(
        schema_version=REPAIR_LINEAGE_SCHEMA_VERSION,
        lineage_id=lineage_id,
        parent_candidate_id=context.parent_candidate_id,
        parent_tree_digest=context.parent_candidate_tree_digest,
        parent_patch_digest=context.parent_patch_digest,
        repaired_candidate_id=repaired_candidate_id,
        repaired_tree_digest=repaired_tree_digest,
        repaired_patch_digest=repaired_patch_digest,
        repair_feedback_digest=context.repair_feedback.feedback_digest,
        repair_context_digest=context.repair_context_digest,
        repair_round=context.repair_round,
        source_identity=context.source_identity,
        builder_execution_identity=builder_execution_identity,
        is_authoritative=False,
    )
    digest = compute_lineage_digest(payload)

    return CandidateLineageRecord(
        lineage_id=lineage_id,
        parent_candidate_id=context.parent_candidate_id,
        parent_tree_digest=context.parent_candidate_tree_digest,
        parent_patch_digest=context.parent_patch_digest,
        repaired_candidate_id=repaired_candidate_id,
        repaired_tree_digest=repaired_tree_digest,
        repaired_patch_digest=repaired_patch_digest,
        repair_feedback_digest=context.repair_feedback.feedback_digest,
        repair_context_digest=context.repair_context_digest,
        repair_round=context.repair_round,
        source_identity=context.source_identity,
        lineage_digest=digest,
        builder_execution_identity=builder_execution_identity,
        schema_version=REPAIR_LINEAGE_SCHEMA_VERSION,
        is_authoritative=False,
    )


def verify_candidate_lineage_integrity(lineage: CandidateLineageRecord) -> bool:
    """Verify cryptographic integrity of CandidateLineageRecord."""
    if lineage.is_authoritative:
        raise CandidateLineageError("CandidateLineageRecord cannot have is_authoritative=True")

    payload = build_canonical_lineage_payload(
        schema_version=lineage.schema_version,
        lineage_id=lineage.lineage_id,
        parent_candidate_id=lineage.parent_candidate_id,
        parent_tree_digest=lineage.parent_tree_digest,
        parent_patch_digest=lineage.parent_patch_digest,
        repaired_candidate_id=lineage.repaired_candidate_id,
        repaired_tree_digest=lineage.repaired_tree_digest,
        repaired_patch_digest=lineage.repaired_patch_digest,
        repair_feedback_digest=lineage.repair_feedback_digest,
        repair_context_digest=lineage.repair_context_digest,
        repair_round=lineage.repair_round,
        source_identity=lineage.source_identity,
        builder_execution_identity=lineage.builder_execution_identity,
        is_authoritative=lineage.is_authoritative,
    )
    computed = compute_lineage_digest(payload)
    if lineage.lineage_digest != computed:
        raise CandidateLineageTamperingError(
            f"Lineage digest mismatch: recorded {lineage.lineage_digest!r} != computed {computed!r}"
        )
    return True
