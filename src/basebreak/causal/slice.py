"""Deterministic domain contracts for causal-slice scope and non-formal-proof disclaimer.

P-12.01: Define causal-slice scope and non-formal-proof disclaimer.

Basebreak Thesis:
"If the patch matters, the base must break."

P-12 extends that thesis by answering a bounded empirical question:
Which tested subset of the candidate change appears necessary for the observed
behavior under the exact frozen contract and sealed witness?

It MUST NOT claim:
- mathematical minimality
- global necessity
- absence of alternative sufficient subsets
- correctness for untested inputs
- semantic equivalence beyond tested behavior
- universal causation
- formal verification.

Authority Boundaries:
The causal slice possesses ZERO independent verdict authority:
- is_authoritative = False
- grants_pass = False
- is_causally_verified = False
A causal-slice artifact must never upgrade an unverified candidate into VERIFIED.
"""

from __future__ import annotations

import hashlib
import json
import re
from collections.abc import Mapping, Sequence
from dataclasses import dataclass, field
from datetime import datetime, timezone
from enum import Enum
from typing import Any

from basebreak.builder.capture import CandidateSnapshot
from basebreak.causal.subtraction import SubtractionStrategyType
from basebreak.domain.verdict import EvidenceProvenance
from basebreak.verifier.witness_result import WitnessOutcome

CAUSAL_SLICE_SCHEMA_VERSION: str = "1.0.0"
CANONICAL_DISCLAIMER_VERSION: str = "1.0.0"

CANONICAL_DISCLAIMER_TEXT: str = (
    "A minimal causal slice is an empirical result under a specific frozen contract, "
    "sealed witness, candidate state, and tested execution environment. "
    "It does NOT prove: mathematical minimality, global necessity, absence of "
    "alternative sufficient subsets, correctness for untested inputs, semantic "
    "equivalence beyond tested behavior, universal causation, or formal verification."
)

PROHIBITED_CERTAINTY_TERMS: tuple[str, ...] = (
    "mathematically minimal",
    "formally proven",
    "universally necessary",
    "formal proof",
    "global minimality proven",
    "absolute minimal patch",
    "globally minimal patch",
    "mathematical proof of minimal code",
)

PREFERRED_TERMINOLOGY: tuple[str, ...] = (
    "tested necessary subset",
    "witness-relative",
    "bounded causal slice",
    "empirical necessity under witness",
)

_HEX_40_PATTERN = re.compile(r"^[0-9a-f]{40}$")
_HEX_64_PATTERN = re.compile(r"^[0-9a-f]{64}$")
_HEX_40_OR_64_PATTERN = re.compile(r"^([0-9a-f]{40}|[0-9a-f]{64})$")


# --- Exceptions ---


class CausalSliceError(Exception):
    """Base exception for all causal slice and scope errors."""


class SliceAuthorityError(CausalSliceError):
    """Raised when caller, model, or artifact attempts to assert fake authority or certification."""


class SliceScopeTamperingError(CausalSliceError):
    """Raised when scope, slice, or execution digests are tampered or corrupted."""


class SliceIdentityMismatchError(CausalSliceError):
    """Raised when candidate identity, tree, patch, contract, or witness digests do not match."""


class DisclaimerMissingError(CausalSliceError):
    """Raised when the mandatory non-formal-proof disclaimer is missing or omitted."""


class DisclaimerViolationError(CausalSliceError):
    """Raised when disclaimer guarantees or flags are violated (e.g. claiming proof)."""


class InvalidSubsetError(CausalSliceError):
    """Raised when a tested patch subset is empty, malformed, or invalid."""


class IncompleteSearchAuthorityError(CausalSliceError):
    """Raised when incomplete or heuristic search attempts to claim global minimality."""


class ProhibitedTerminologyError(CausalSliceError):
    """Raised when prohibited marketing or certainty terminology is used."""


# --- Enums ---


class CausalSliceStatus(str, Enum):
    """Empirical status of the tested causal slice."""

    TESTED_NECESSARY_SUBSET = "TESTED_NECESSARY_SUBSET"
    INCONCLUSIVE_INTERACTION = "INCONCLUSIVE_INTERACTION"
    INCONCLUSIVE_INCOMPLETE = "INCONCLUSIVE_INCOMPLETE"
    INVALID_SUBSET = "INVALID_SUBSET"


class SliceSearchCompleteness(str, Enum):
    """Completeness level of the slice search traversal."""

    BOUNDED_GREEDY = "BOUNDED_GREEDY"
    BOUNDED_HEURISTIC = "BOUNDED_HEURISTIC"
    EXHAUSTIVE_BOUNDED = "EXHAUSTIVE_BOUNDED"
    PARTIAL_ABORTED = "PARTIAL_ABORTED"


# --- Validation Helpers ---


def _validate_hex_digest(digest: str, field_name: str, length: int | tuple[int, ...] = 64) -> None:
    """Validate a lowercase hexadecimal digest string."""
    if not isinstance(digest, str):
        raise TypeError(f"{field_name} must be a string, got {type(digest).__name__}")
    if digest.strip() != digest:
        raise ValueError(f"{field_name} must not contain leading or trailing whitespace")
    lengths = (length,) if isinstance(length, int) else length
    if len(digest) not in lengths:
        raise ValueError(
            f"{field_name} must be {lengths} hex chars, got {len(digest)} chars: {digest!r}"
        )
    if not re.fullmatch(r"^[0-9a-f]+$", digest):
        raise ValueError(f"{field_name} must consist of lowercase hex chars [0-9a-f]: {digest!r}")


def _validate_non_empty_identifier(val: str, field_name: str) -> None:
    """Validate a non-empty stripped identifier."""
    if not isinstance(val, str):
        raise TypeError(f"{field_name} must be a string, got {type(val).__name__}")
    if not val.strip():
        raise ValueError(f"{field_name} must not be empty or whitespace")
    if val.strip() != val:
        raise ValueError(f"{field_name} must not contain leading or trailing whitespace")


def validate_no_prohibited_terms(text: str, context: str = "") -> None:
    """Check text for prohibited certainty/marketing terminology."""
    if not isinstance(text, str):
        return
    lower_text = text.lower()
    for term in PROHIBITED_CERTAINTY_TERMS:
        if term in lower_text:
            ctx_msg = f" in {context}" if context else ""
            raise ProhibitedTerminologyError(
                f"Prohibited terminology {term!r} found{ctx_msg}. "
                "Basebreak causal slices are empirical results and must not claim "
                "mathematical minimality, formal program proof, or universal necessity. "
                f"Prefer: {list(PREFERRED_TERMINOLOGY)}"
            )


# --- Disclaimer Dataclass ---


@dataclass(frozen=True, slots=True)
class NonFormalProofDisclaimer:
    """Mandatory machine-readable and human-readable non-formal-proof disclaimer.

    Guarantees:
    - Explicitly declares that the slice is an empirical result under a specific
      frozen contract and sealed witness.
    - Explicitly disclaims mathematical proof, global minimality, universal necessity,
      correctness for untested inputs, semantic equivalence, and formal verification.
    - All capability flags must strictly remain False. Setting any to True fails closed.
    """

    statement: str = CANONICAL_DISCLAIMER_TEXT
    disclaimer_version: str = CANONICAL_DISCLAIMER_VERSION
    is_mathematical_proof: bool = False
    is_globally_minimal: bool = False
    is_universally_necessary: bool = False
    guarantees_untested_inputs: bool = False
    guarantees_semantic_equivalence: bool = False
    is_formal_verification: bool = False

    def __post_init__(self) -> None:
        if self.is_mathematical_proof is not False:
            raise DisclaimerViolationError(
                "NonFormalProofDisclaimer cannot claim mathematical proof: "
                "is_mathematical_proof must be False"
            )
        if self.is_globally_minimal is not False:
            raise DisclaimerViolationError(
                "NonFormalProofDisclaimer cannot claim global minimality: "
                "is_globally_minimal must be False"
            )
        if self.is_universally_necessary is not False:
            raise DisclaimerViolationError(
                "NonFormalProofDisclaimer cannot claim universal necessity: "
                "is_universally_necessary must be False"
            )
        if self.guarantees_untested_inputs is not False:
            raise DisclaimerViolationError(
                "NonFormalProofDisclaimer cannot guarantee untested inputs: "
                "guarantees_untested_inputs must be False"
            )
        if self.guarantees_semantic_equivalence is not False:
            raise DisclaimerViolationError(
                "NonFormalProofDisclaimer cannot guarantee semantic equivalence: "
                "guarantees_semantic_equivalence must be False"
            )
        if self.is_formal_verification is not False:
            raise DisclaimerViolationError(
                "NonFormalProofDisclaimer cannot claim formal verification: "
                "is_formal_verification must be False"
            )

        if not isinstance(self.statement, str) or not self.statement.strip():
            raise DisclaimerMissingError("statement must be a non-empty string")
        if not isinstance(self.disclaimer_version, str) or not self.disclaimer_version.strip():
            raise DisclaimerMissingError("disclaimer_version must be a non-empty string")

        lower = self.statement.lower()
        if (
            "not prove" not in lower
            and "does not claim" not in lower
            and "empirical result" not in lower
        ):
            raise DisclaimerViolationError(
                "Disclaimer statement must explicitly state that the slice does not "
                "prove formal or minimal properties"
            )

    def to_dict(self) -> dict[str, Any]:
        """Serialize disclaimer to a dictionary."""
        return {
            "disclaimer_version": self.disclaimer_version,
            "guarantees_semantic_equivalence": self.guarantees_semantic_equivalence,
            "guarantees_untested_inputs": self.guarantees_untested_inputs,
            "is_formal_verification": self.is_formal_verification,
            "is_globally_minimal": self.is_globally_minimal,
            "is_mathematical_proof": self.is_mathematical_proof,
            "is_universally_necessary": self.is_universally_necessary,
            "statement": self.statement,
        }

    @classmethod
    def from_dict(cls, data: Mapping[str, Any]) -> NonFormalProofDisclaimer:
        """Deserialize disclaimer with fail-closed validation."""
        if not isinstance(data, Mapping):
            raise DisclaimerMissingError(
                f"Expected mapping for disclaimer, got {type(data).__name__}"
            )
        statement = data.get("statement")
        if not isinstance(statement, str) or not statement.strip():
            raise DisclaimerMissingError("Disclaimer statement is missing or empty")
        version = data.get("disclaimer_version", CANONICAL_DISCLAIMER_VERSION)

        for bool_field in (
            "is_mathematical_proof",
            "is_globally_minimal",
            "is_universally_necessary",
            "guarantees_untested_inputs",
            "guarantees_semantic_equivalence",
            "is_formal_verification",
        ):
            if data.get(bool_field) is True:
                raise DisclaimerViolationError(
                    f"Disclaimer cannot have {bool_field}=True in serialized data"
                )

        return cls(
            statement=statement,
            disclaimer_version=str(version),
            is_mathematical_proof=False,
            is_globally_minimal=False,
            is_universally_necessary=False,
            guarantees_untested_inputs=False,
            guarantees_semantic_equivalence=False,
            is_formal_verification=False,
        )


def create_canonical_disclaimer() -> NonFormalProofDisclaimer:
    """Create the canonical non-formal-proof disclaimer."""
    return NonFormalProofDisclaimer(
        statement=CANONICAL_DISCLAIMER_TEXT,
        disclaimer_version=CANONICAL_DISCLAIMER_VERSION,
        is_mathematical_proof=False,
        is_globally_minimal=False,
        is_universally_necessary=False,
        guarantees_untested_inputs=False,
        guarantees_semantic_equivalence=False,
        is_formal_verification=False,
    )


# --- Tested Patch Subset ---


@dataclass(frozen=True, slots=True)
class TestedPatchSubset:
    """Deterministic record of a candidate patch subset tested under witness.

    Binds:
    - retained_files and retained_hunk_ids: patch elements retained in the slice.
    - subtracted_files and subtracted_hunk_ids: patch elements subtracted in counterfactual run.
    - retained_patch_digest: SHA-256 of the unified diff containing only retained changes.
    - subtracted_delta_digest: SHA-256 of the delta that was subtracted.
    - is_authoritative: strictly False.
    - grants_pass: strictly False.
    - is_causally_verified: strictly False.
    """

    __test__ = False

    subset_id: str
    strategy_type: SubtractionStrategyType
    retained_files: tuple[str, ...]
    retained_hunk_ids: tuple[str, ...]
    subtracted_files: tuple[str, ...]
    subtracted_hunk_ids: tuple[str, ...]
    retained_patch_digest: str
    subtracted_delta_digest: str
    is_empty: bool = False
    is_authoritative: bool = False
    grants_pass: bool = False
    is_causally_verified: bool = False

    def __post_init__(self) -> None:
        if self.is_authoritative is not False:
            raise SliceAuthorityError(
                "TestedPatchSubset cannot assert authority: is_authoritative must be False"
            )
        if self.grants_pass is not False:
            raise SliceAuthorityError(
                "TestedPatchSubset cannot grant pass: grants_pass must be False"
            )
        if self.is_causally_verified is not False:
            raise SliceAuthorityError(
                "TestedPatchSubset cannot assert verification: is_causally_verified must be False"
            )

        _validate_non_empty_identifier(self.subset_id, "subset_id")
        if not isinstance(self.strategy_type, SubtractionStrategyType):
            strat_name = type(self.strategy_type).__name__
            raise TypeError(f"strategy_type must be SubtractionStrategyType, got {strat_name}")

        if not isinstance(self.retained_files, tuple):
            if isinstance(self.retained_files, Sequence):
                object.__setattr__(
                    self, "retained_files", tuple(str(f) for f in self.retained_files)
                )
            else:
                raise TypeError("retained_files must be a sequence of strings")

        if not isinstance(self.retained_hunk_ids, tuple):
            if isinstance(self.retained_hunk_ids, Sequence):
                object.__setattr__(
                    self, "retained_hunk_ids", tuple(str(h) for h in self.retained_hunk_ids)
                )
            else:
                raise TypeError("retained_hunk_ids must be a sequence of strings")

        if not isinstance(self.subtracted_files, tuple):
            if isinstance(self.subtracted_files, Sequence):
                object.__setattr__(
                    self, "subtracted_files", tuple(str(f) for f in self.subtracted_files)
                )
            else:
                raise TypeError("subtracted_files must be a sequence of strings")

        if not isinstance(self.subtracted_hunk_ids, tuple):
            if isinstance(self.subtracted_hunk_ids, Sequence):
                object.__setattr__(
                    self, "subtracted_hunk_ids", tuple(str(h) for h in self.subtracted_hunk_ids)
                )
            else:
                raise TypeError("subtracted_hunk_ids must be a sequence of strings")

        _validate_hex_digest(self.retained_patch_digest, "retained_patch_digest", 64)
        _validate_hex_digest(self.subtracted_delta_digest, "subtracted_delta_digest", 64)

        if self.is_empty is True:
            raise InvalidSubsetError("TestedPatchSubset cannot have is_empty=True")

        if not self.retained_files and not self.retained_hunk_ids:
            raise InvalidSubsetError(
                "TestedPatchSubset must have at least one retained file or hunk"
            )

    def to_dict(self) -> dict[str, Any]:
        """Serialize TestedPatchSubset to a dictionary."""
        return {
            "grants_pass": self.grants_pass,
            "is_authoritative": self.is_authoritative,
            "is_causally_verified": self.is_causally_verified,
            "is_empty": self.is_empty,
            "retained_files": list(self.retained_files),
            "retained_hunk_ids": list(self.retained_hunk_ids),
            "retained_patch_digest": self.retained_patch_digest,
            "strategy_type": self.strategy_type.value,
            "subset_id": self.subset_id,
            "subtracted_delta_digest": self.subtracted_delta_digest,
            "subtracted_files": list(self.subtracted_files),
            "subtracted_hunk_ids": list(self.subtracted_hunk_ids),
        }

    @classmethod
    def from_dict(cls, data: Mapping[str, Any]) -> TestedPatchSubset:
        """Deserialize TestedPatchSubset from a dictionary."""
        if not isinstance(data, Mapping):
            raise InvalidSubsetError(
                f"Expected mapping for TestedPatchSubset, got {type(data).__name__}"
            )
        try:
            strat_raw = data["strategy_type"]
            strategy_type = (
                strat_raw
                if isinstance(strat_raw, SubtractionStrategyType)
                else SubtractionStrategyType(str(strat_raw))
            )
            return cls(
                subset_id=str(data["subset_id"]),
                strategy_type=strategy_type,
                retained_files=tuple(str(f) for f in data.get("retained_files", ())),
                retained_hunk_ids=tuple(str(h) for h in data.get("retained_hunk_ids", ())),
                subtracted_files=tuple(str(f) for f in data.get("subtracted_files", ())),
                subtracted_hunk_ids=tuple(str(h) for h in data.get("subtracted_hunk_ids", ())),
                retained_patch_digest=str(data["retained_patch_digest"]),
                subtracted_delta_digest=str(data["subtracted_delta_digest"]),
                is_empty=bool(data.get("is_empty", False)),
                is_authoritative=bool(data.get("is_authoritative", False)),
                grants_pass=bool(data.get("grants_pass", False)),
                is_causally_verified=bool(data.get("is_causally_verified", False)),
            )
        except (KeyError, ValueError, TypeError) as exc:
            raise InvalidSubsetError(f"Failed to deserialize TestedPatchSubset: {exc}") from exc


# --- Model Proposal ---


@dataclass(frozen=True, slots=True)
class ModelSliceProposal:
    """Untrusted model proposal for slice minimization or subset ranking.

    Possesses ZERO authority over causal verdict or minimality:
    - is_authoritative = False
    - grants_pass = False
    - is_causally_verified = False
    - claims_minimality = False
    """

    proposed_retained_files: tuple[str, ...] = ()
    proposed_retained_hunks: tuple[str, ...] = ()
    proposed_subtracted_files: tuple[str, ...] = ()
    proposed_subtracted_hunks: tuple[str, ...] = ()
    model_confidence: float | None = None
    model_reasoning: str = ""
    is_authoritative: bool = False
    grants_pass: bool = False
    is_causally_verified: bool = False
    claims_minimality: bool = False

    def __post_init__(self) -> None:
        if self.is_authoritative is not False:
            raise SliceAuthorityError(
                "ModelSliceProposal cannot assert authority: is_authoritative must be False"
            )
        if self.grants_pass is not False:
            raise SliceAuthorityError(
                "ModelSliceProposal cannot grant pass: grants_pass must be False"
            )
        if self.is_causally_verified is not False:
            raise SliceAuthorityError(
                "ModelSliceProposal cannot assert verification: is_causally_verified must be False"
            )
        if self.claims_minimality is not False:
            raise SliceAuthorityError(
                "ModelSliceProposal cannot claim minimality: claims_minimality must be False"
            )

        if self.model_confidence is not None:
            if isinstance(self.model_confidence, bool) or not isinstance(
                self.model_confidence, (int, float)
            ):
                raise TypeError("model_confidence must be a float or None")
            if not (0.0 <= float(self.model_confidence) <= 1.0):
                raise ValueError(
                    f"model_confidence must be between 0.0 and 1.0, got {self.model_confidence}"
                )

        if not isinstance(self.model_reasoning, str):
            raise TypeError("model_reasoning must be a string")


# --- Causal Slice Scope ---


@dataclass(frozen=True, slots=True)
class CausalSliceScope:
    """Provider-neutral deterministic domain contract for causal-slice scope.

    Mechanically binds to:
    - exact candidate identity (candidate_id, source locator, commit_id, subpath)
    - exact candidate tree digest
    - exact candidate patch digest
    - exact frozen contract digest
    - exact sealed witness digest
    - exact requirement identifier
    - exact counterfactual / subtraction identity from P-11 (counterfactual_id, delta_digest)
    - exact execution evidence / receipt digest
    - evidence provenance
    - mandatory non-formal-proof disclaimer

    Guarantees:
    - is_authoritative: strictly False
    - grants_pass: strictly False
    - is_causally_verified: strictly False
    """

    candidate_id: str
    source_locator: str
    source_commit_id: str
    source_subpath: str
    candidate_tree_digest: str
    candidate_patch_digest: str
    frozen_contract_digest: str
    sealed_witness_digest: str
    requirement_id: str
    provenance: EvidenceProvenance
    disclaimer: NonFormalProofDisclaimer = field(default_factory=create_canonical_disclaimer)
    counterfactual_id: str | None = None
    delta_digest: str | None = None
    receipt_digest: str | None = None
    is_authoritative: bool = False
    grants_pass: bool = False
    is_causally_verified: bool = False

    def __post_init__(self) -> None:
        if self.is_authoritative is not False:
            raise SliceAuthorityError(
                "CausalSliceScope cannot assert authority: is_authoritative must be False"
            )
        if self.grants_pass is not False:
            raise SliceAuthorityError(
                "CausalSliceScope cannot grant pass: grants_pass must be False"
            )
        if self.is_causally_verified is not False:
            raise SliceAuthorityError(
                "CausalSliceScope cannot assert verification: is_causally_verified must be False"
            )

        _validate_non_empty_identifier(self.candidate_id, "candidate_id")
        _validate_non_empty_identifier(self.source_locator, "source_locator")
        _validate_hex_digest(self.source_commit_id, "source_commit_id", 40)
        _validate_hex_digest(self.candidate_tree_digest, "candidate_tree_digest", (40, 64))
        _validate_hex_digest(self.candidate_patch_digest, "candidate_patch_digest", 64)
        _validate_hex_digest(self.frozen_contract_digest, "frozen_contract_digest", 64)
        _validate_hex_digest(self.sealed_witness_digest, "sealed_witness_digest", 64)
        _validate_non_empty_identifier(self.requirement_id, "requirement_id")

        if not isinstance(self.provenance, EvidenceProvenance):
            raise TypeError(
                f"provenance must be EvidenceProvenance, got {type(self.provenance).__name__}"
            )

        if not isinstance(self.disclaimer, NonFormalProofDisclaimer):
            raise DisclaimerMissingError(
                f"disclaimer must be NonFormalProofDisclaimer, got {type(self.disclaimer).__name__}"
            )

        if self.counterfactual_id is not None:
            _validate_non_empty_identifier(self.counterfactual_id, "counterfactual_id")
        if self.delta_digest is not None:
            _validate_hex_digest(self.delta_digest, "delta_digest", 64)
        if self.receipt_digest is not None:
            _validate_hex_digest(self.receipt_digest, "receipt_digest", 64)

    @property
    def scope_digest(self) -> str:
        """Deterministic SHA-256 digest of bound immutable scope facts."""
        payload = {
            "candidate_id": self.candidate_id,
            "candidate_patch_digest": self.candidate_patch_digest,
            "candidate_tree_digest": self.candidate_tree_digest,
            "counterfactual_id": self.counterfactual_id,
            "delta_digest": self.delta_digest,
            "disclaimer_version": self.disclaimer.disclaimer_version,
            "frozen_contract_digest": self.frozen_contract_digest,
            "provenance": self.provenance.value,
            "receipt_digest": self.receipt_digest,
            "requirement_id": self.requirement_id,
            "sealed_witness_digest": self.sealed_witness_digest,
            "source_commit_id": self.source_commit_id,
            "source_locator": self.source_locator,
            "source_subpath": self.source_subpath,
        }
        canonical_bytes = json.dumps(
            payload, sort_keys=True, separators=(",", ":"), ensure_ascii=False
        ).encode("utf-8")
        return hashlib.sha256(canonical_bytes).hexdigest()

    def to_dict(self) -> dict[str, Any]:
        """Serialize CausalSliceScope to a dictionary."""
        return {
            "candidate_id": self.candidate_id,
            "candidate_patch_digest": self.candidate_patch_digest,
            "candidate_tree_digest": self.candidate_tree_digest,
            "counterfactual_id": self.counterfactual_id,
            "delta_digest": self.delta_digest,
            "disclaimer": self.disclaimer.to_dict(),
            "frozen_contract_digest": self.frozen_contract_digest,
            "grants_pass": self.grants_pass,
            "is_authoritative": self.is_authoritative,
            "is_causally_verified": self.is_causally_verified,
            "provenance": self.provenance.value,
            "receipt_digest": self.receipt_digest,
            "requirement_id": self.requirement_id,
            "scope_digest": self.scope_digest,
            "sealed_witness_digest": self.sealed_witness_digest,
            "source_commit_id": self.source_commit_id,
            "source_locator": self.source_locator,
            "source_subpath": self.source_subpath,
        }

    @classmethod
    def from_dict(cls, data: Mapping[str, Any]) -> CausalSliceScope:
        """Deserialize CausalSliceScope from a dictionary."""
        if not isinstance(data, Mapping):
            raise SliceScopeTamperingError(
                f"Expected mapping for CausalSliceScope, got {type(data).__name__}"
            )
        try:
            disclaimer_data = data.get("disclaimer")
            if disclaimer_data is None:
                raise DisclaimerMissingError("disclaimer is required in CausalSliceScope")
            disclaimer = NonFormalProofDisclaimer.from_dict(disclaimer_data)

            raw_prov = data["provenance"]
            provenance = (
                raw_prov
                if isinstance(raw_prov, EvidenceProvenance)
                else EvidenceProvenance(str(raw_prov))
            )

            expected_digest = data.get("scope_digest")
            scope = cls(
                candidate_id=str(data["candidate_id"]),
                source_locator=str(data["source_locator"]),
                source_commit_id=str(data["source_commit_id"]),
                source_subpath=str(data.get("source_subpath", "")),
                candidate_tree_digest=str(data["candidate_tree_digest"]),
                candidate_patch_digest=str(data["candidate_patch_digest"]),
                frozen_contract_digest=str(data["frozen_contract_digest"]),
                sealed_witness_digest=str(data["sealed_witness_digest"]),
                requirement_id=str(data["requirement_id"]),
                provenance=provenance,
                disclaimer=disclaimer,
                counterfactual_id=(
                    str(data["counterfactual_id"]) if data.get("counterfactual_id") else None
                ),
                delta_digest=str(data["delta_digest"]) if data.get("delta_digest") else None,
                receipt_digest=(
                    str(data["receipt_digest"]) if data.get("receipt_digest") else None
                ),
                is_authoritative=bool(data.get("is_authoritative", False)),
                grants_pass=bool(data.get("grants_pass", False)),
                is_causally_verified=bool(data.get("is_causally_verified", False)),
            )
            if expected_digest and scope.scope_digest != expected_digest:
                raise SliceScopeTamperingError(
                    f"scope_digest mismatch: expected {expected_digest}, "
                    f"computed {scope.scope_digest}"
                )
            return scope
        except (KeyError, ValueError, TypeError) as exc:
            if isinstance(
                exc,
                (
                    DisclaimerMissingError,
                    DisclaimerViolationError,
                    SliceAuthorityError,
                    SliceScopeTamperingError,
                ),
            ):
                raise
            raise SliceScopeTamperingError(
                f"Failed to deserialize CausalSliceScope: {exc}"
            ) from exc


def create_causal_slice_scope(
    *,
    snapshot: CandidateSnapshot,
    frozen_contract_digest: str,
    sealed_witness_digest: str,
    requirement_id: str,
    counterfactual_id: str | None = None,
    delta_digest: str | None = None,
    receipt_digest: str | None = None,
    provenance: EvidenceProvenance = EvidenceProvenance.LOCAL_EXECUTION,
    disclaimer: NonFormalProofDisclaimer | None = None,
) -> CausalSliceScope:
    """Construct a CausalSliceScope from a CandidateSnapshot with strict identity binding."""
    if not isinstance(snapshot, CandidateSnapshot):
        raise TypeError(f"snapshot must be CandidateSnapshot, got {type(snapshot).__name__}")

    # Enforce exact identity match with snapshot
    if snapshot.frozen_contract_digest != frozen_contract_digest:
        raise SliceIdentityMismatchError(
            f"frozen_contract_digest mismatch: snapshot has {snapshot.frozen_contract_digest}, "
            f"provided {frozen_contract_digest}"
        )

    return CausalSliceScope(
        candidate_id=snapshot.candidate_id,
        source_locator=snapshot.source_identity.locator,
        source_commit_id=snapshot.source_identity.revision.commit_id,
        source_subpath=snapshot.source_identity.subpath or "",
        candidate_tree_digest=snapshot.candidate_tree_digest,
        candidate_patch_digest=snapshot.patch_digest,
        frozen_contract_digest=frozen_contract_digest,
        sealed_witness_digest=sealed_witness_digest,
        requirement_id=requirement_id,
        provenance=provenance,
        disclaimer=disclaimer or create_canonical_disclaimer(),
        counterfactual_id=counterfactual_id,
        delta_digest=delta_digest,
        receipt_digest=receipt_digest,
        is_authoritative=False,
        grants_pass=False,
        is_causally_verified=False,
    )


# --- Scope Rules ---


class CausalSliceScopeRules:
    """Codified scope and authority rules for Minimal Causal Slice (P-12).

    Rule Summary:
    1. Inputs: Minimizer may only inspect untrusted candidate patch text,
       candidate hunks/files, frozen contract digest/requirements, sealed
       witness digest (opaque black-box), and execution evidence receipts.
       Hidden verifier implementations, untrusted caller authority assertions,
       and unredacted secrets are strictly forbidden.
    2. Immutable Identities: candidate_id, source_identity (locator, commit_id,
       subpath), base commit, candidate_tree_digest, frozen_contract_digest,
       sealed_witness_digest, requirement_id must remain strictly fixed.
    3. Varying Surface: candidate patch subset only.
    4. Prohibited Variations: frozen contract, sealed witness, requirement identity,
       source identity, base state, and verdict semantics may NOT vary.
    5. Valid Tested Subset: Syntactically valid, non-overlapping subset of candidate
       patch hunks/files that applies cleanly to clean base tree without modifying
       protected surfaces or violating secret policy, executed against identical witness.
    6. Invalid/Inconclusive Evidence: Application failure, merge conflicts, protected
       surface collisions, unredacted secrets, non-deterministic execution, TIMEOUT,
       execution ERROR, or missing execution evidence.
    7. Interacting Hunks & Non-Monotonic Behavior: Hunks may interact non-monotonically.
       Empirical necessity of a tested subset under a witness does NOT prove global
       minimality or uniqueness among the 2^N potential subsets.
    8. Zero Model Authority: Model proposals, confidence scores, ranking, and reasoning
       possess zero deterministic verdict authority.
    9. Anti-Collapse Invariant: ERROR and TIMEOUT represent execution failures/aborts
       and cannot count as behavioral witness FAIL.
    10. Incomplete Search: Heuristic, greedy, or bounded searches explore a polynomial
        fraction of exponential subset space and cannot claim global minimality.
    """

    ALLOWED_VARYING_INPUTS: tuple[str, ...] = ("candidate_patch_subset",)
    IMMUTABLE_IDENTITIES: tuple[str, ...] = (
        "candidate_id",
        "source_locator",
        "source_commit_id",
        "source_subpath",
        "candidate_tree_digest",
        "frozen_contract_digest",
        "sealed_witness_digest",
        "requirement_id",
    )

    @classmethod
    def validate_immutable_identities_match(
        cls, scope_a: CausalSliceScope, scope_b: CausalSliceScope
    ) -> None:
        """Verify that immutable identities have remained strictly fixed across runs."""
        for field_name in cls.IMMUTABLE_IDENTITIES:
            val_a = getattr(scope_a, field_name)
            val_b = getattr(scope_b, field_name)
            if val_a != val_b:
                raise SliceIdentityMismatchError(
                    f"Immutable identity {field_name!r} varied: {val_a!r} != {val_b!r}"
                )

    @classmethod
    def validate_execution_outcome_not_error_or_timeout(
        cls, outcome: WitnessOutcome, context: str = ""
    ) -> None:
        """Enforce anti-collapse invariant: ERROR and TIMEOUT cannot count as behavioral FAIL."""
        if outcome in (WitnessOutcome.TIMEOUT, WitnessOutcome.ERROR):
            ctx_msg = f" in {context}" if context else ""
            raise SliceScopeTamperingError(
                f"Execution outcome {outcome.value}{ctx_msg} represents an execution failure/abort "
                "and cannot masquerade as behavioral witness FAIL."
            )

    @classmethod
    def validate_completeness_and_claims(
        cls, completeness: SliceSearchCompleteness, claims_global_minimality: bool
    ) -> None:
        """Enforce that search cannot claim global minimality."""
        if claims_global_minimality:
            raise IncompleteSearchAuthorityError(
                f"Search with completeness={completeness.value} cannot claim global minimality. "
                "Basebreak minimal causal slices are bounded empirical results, not mathematical "
                "proofs of minimal code."
            )


# --- Bounded Causal Slice ---


def compute_slice_digest(payload: Mapping[str, Any]) -> str:
    """Compute deterministic SHA-256 digest of canonical slice payload."""
    canonical_bytes = json.dumps(
        payload, sort_keys=True, separators=(",", ":"), ensure_ascii=False
    ).encode("utf-8")
    return hashlib.sha256(canonical_bytes).hexdigest()


@dataclass(frozen=True, slots=True)
class BoundedCausalSlice:
    """Authentic, deterministic artifact representing a bounded causal slice.

    Guarantees:
    - Binds to exact CausalSliceScope and TestedPatchSubset.
    - Zero verdict authority: is_authoritative = False, grants_pass = False,
      is_causally_verified = False.
    - Mandatory non-formal-proof disclaimer cannot be omitted.
    - Cannot claim global minimality: claims_global_minimality must be False.
    - Any tampering with slice fields or digests invalidates slice integrity.
    """

    slice_id: str
    scope: CausalSliceScope
    tested_subset: TestedPatchSubset
    status: CausalSliceStatus
    completeness: SliceSearchCompleteness
    summary_label: str
    disclaimer: NonFormalProofDisclaimer
    slice_digest: str
    created_at_utc: str
    schema_version: str = CAUSAL_SLICE_SCHEMA_VERSION
    is_authoritative: bool = False
    grants_pass: bool = False
    is_causally_verified: bool = False
    claims_global_minimality: bool = False

    def __post_init__(self) -> None:
        if self.is_authoritative is not False:
            raise SliceAuthorityError(
                "BoundedCausalSlice cannot assert authority: is_authoritative must be False"
            )
        if self.grants_pass is not False:
            raise SliceAuthorityError(
                "BoundedCausalSlice cannot grant pass: grants_pass must be False"
            )
        if self.is_causally_verified is not False:
            raise SliceAuthorityError(
                "BoundedCausalSlice cannot assert verification: is_causally_verified must be False"
            )
        if self.claims_global_minimality is not False:
            raise IncompleteSearchAuthorityError(
                "BoundedCausalSlice cannot claim global minimality: "
                "claims_global_minimality must be False"
            )

        _validate_non_empty_identifier(self.slice_id, "slice_id")
        if not isinstance(self.scope, CausalSliceScope):
            raise TypeError(f"scope must be CausalSliceScope, got {type(self.scope).__name__}")
        if not isinstance(self.tested_subset, TestedPatchSubset):
            raise TypeError(
                f"tested_subset must be TestedPatchSubset, got {type(self.tested_subset).__name__}"
            )
        if not isinstance(self.status, CausalSliceStatus):
            raise TypeError(f"status must be CausalSliceStatus, got {type(self.status).__name__}")
        if not isinstance(self.completeness, SliceSearchCompleteness):
            comp_name = type(self.completeness).__name__
            raise TypeError(f"completeness must be SliceSearchCompleteness, got {comp_name}")
        if not isinstance(self.disclaimer, NonFormalProofDisclaimer):
            raise DisclaimerMissingError(
                f"disclaimer must be NonFormalProofDisclaimer, got {type(self.disclaimer).__name__}"
            )

        _validate_hex_digest(self.slice_digest, "slice_digest", 64)
        validate_no_prohibited_terms(self.summary_label, "summary_label")

        # Consistency binding: if scope carries delta_digest, tested_subset must match
        if (
            self.scope.delta_digest is not None
            and self.tested_subset.subtracted_delta_digest != self.scope.delta_digest
        ):
            raise SliceIdentityMismatchError(
                f"subtracted_delta_digest mismatch: scope has {self.scope.delta_digest}, "
                f"tested_subset has {self.tested_subset.subtracted_delta_digest}"
            )

        # Verify cryptographic integrity
        payload = self._build_payload()
        computed = compute_slice_digest(payload)
        if self.slice_digest != computed:
            raise SliceScopeTamperingError(
                f"slice_digest mismatch: expected {self.slice_digest}, computed {computed}"
            )

    def _build_payload(self) -> dict[str, Any]:
        """Build canonical dictionary payload for digest computation."""
        return {
            "completeness": self.completeness.value,
            "created_at_utc": self.created_at_utc,
            "disclaimer": self.disclaimer.to_dict(),
            "schema_version": self.schema_version,
            "scope": self.scope.to_dict(),
            "slice_id": self.slice_id,
            "status": self.status.value,
            "summary_label": self.summary_label,
            "tested_subset": self.tested_subset.to_dict(),
        }

    def to_dict(self) -> dict[str, Any]:
        """Serialize BoundedCausalSlice to a dictionary with mandatory disclaimer."""
        payload = self._build_payload()
        payload["claims_global_minimality"] = self.claims_global_minimality
        payload["grants_pass"] = self.grants_pass
        payload["is_authoritative"] = self.is_authoritative
        payload["is_causally_verified"] = self.is_causally_verified
        payload["slice_digest"] = self.slice_digest
        return payload

    def to_json(self) -> str:
        """Canonical JSON serialization."""
        return json.dumps(self.to_dict(), sort_keys=True, indent=2)

    @classmethod
    def from_dict(cls, data: Mapping[str, Any]) -> BoundedCausalSlice:
        """Deserialize BoundedCausalSlice with fail-closed validation."""
        if not isinstance(data, Mapping):
            raise SliceScopeTamperingError(
                f"Expected mapping for BoundedCausalSlice, got {type(data).__name__}"
            )

        disclaimer_data = data.get("disclaimer")
        if disclaimer_data is None:
            raise DisclaimerMissingError(
                "The mandatory non-formal-proof disclaimer cannot be omitted from "
                "serialized slice representation"
            )
        disclaimer = NonFormalProofDisclaimer.from_dict(disclaimer_data)

        if data.get("is_authoritative") is True:
            raise SliceAuthorityError("is_authoritative cannot be True in serialized slice")
        if data.get("grants_pass") is True:
            raise SliceAuthorityError("grants_pass cannot be True in serialized slice")
        if data.get("is_causally_verified") is True:
            raise SliceAuthorityError("is_causally_verified cannot be True in serialized slice")
        if data.get("claims_global_minimality") is True:
            raise IncompleteSearchAuthorityError(
                "claims_global_minimality cannot be True in serialized slice"
            )

        try:
            scope = CausalSliceScope.from_dict(data["scope"])
            tested_subset = TestedPatchSubset.from_dict(data["tested_subset"])
            raw_status = data["status"]
            status = (
                raw_status
                if isinstance(raw_status, CausalSliceStatus)
                else CausalSliceStatus(str(raw_status))
            )
            raw_comp = data["completeness"]
            completeness = (
                raw_comp
                if isinstance(raw_comp, SliceSearchCompleteness)
                else SliceSearchCompleteness(str(raw_comp))
            )

            return cls(
                slice_id=str(data["slice_id"]),
                scope=scope,
                tested_subset=tested_subset,
                status=status,
                completeness=completeness,
                summary_label=str(data["summary_label"]),
                disclaimer=disclaimer,
                slice_digest=str(data["slice_digest"]),
                created_at_utc=str(data["created_at_utc"]),
                schema_version=str(data.get("schema_version", CAUSAL_SLICE_SCHEMA_VERSION)),
                is_authoritative=False,
                grants_pass=False,
                is_causally_verified=False,
                claims_global_minimality=False,
            )
        except (KeyError, ValueError, TypeError) as exc:
            if isinstance(
                exc,
                (
                    CausalSliceError,
                    DisclaimerMissingError,
                    DisclaimerViolationError,
                    SliceAuthorityError,
                    SliceScopeTamperingError,
                    IncompleteSearchAuthorityError,
                ),
            ):
                raise
            raise SliceScopeTamperingError(
                f"Failed to deserialize BoundedCausalSlice: {exc}"
            ) from exc

    @classmethod
    def from_json(cls, json_str: str) -> BoundedCausalSlice:
        """Deserialize BoundedCausalSlice from a JSON string."""
        if not isinstance(json_str, str):
            raise TypeError("json_str must be a string")
        try:
            data = json.loads(json_str)
        except json.JSONDecodeError as exc:
            raise SliceScopeTamperingError(f"Invalid JSON for BoundedCausalSlice: {exc}") from exc
        return cls.from_dict(data)

    def render_markdown(self) -> str:
        """Render human-readable markdown representation prominently featuring the disclaimer."""
        ret_files = ", ".join(self.tested_subset.retained_files) or "None"
        ret_hunks = ", ".join(self.tested_subset.retained_hunk_ids) or "None"
        sub_files = ", ".join(self.tested_subset.subtracted_files) or "None"
        sub_hunks = ", ".join(self.tested_subset.subtracted_hunk_ids) or "None"

        n_sub_hunks = len(self.tested_subset.subtracted_hunk_ids)
        lines = [
            f"# Basebreak Bounded Causal Slice: `{self.slice_id}`",
            "",
            "> Thesis: *If the patch matters, the base must break.*",
            "",
            "## Summary",
            f"- **Status**: `{self.status.value}`",
            f"- **Search Completeness**: `{self.completeness.value}`",
            f"- **Label**: {self.summary_label}",
            f"- **Slice Digest**: `{self.slice_digest}`",
            f"- **Created At**: `{self.created_at_utc}`",
            "",
            "## Authority Boundary",
            "- **Authoritative**: `False`",
            "- **Grants Pass**: `False`",
            "- **Causally Verified**: `False`",
            "- **Claims Global Minimality**: `False`",
            "",
            "## Bound Identities",
            f"- **Candidate ID**: `{self.scope.candidate_id}`",
            f"- **Source Commit**: `{self.scope.source_commit_id}`",
            f"- **Candidate Patch Digest**: `{self.scope.candidate_patch_digest}`",
            f"- **Frozen Contract Digest**: `{self.scope.frozen_contract_digest}`",
            f"- **Sealed Witness Digest**: `{self.scope.sealed_witness_digest}`",
            f"- **Counterfactual ID**: `{self.scope.counterfactual_id or 'N/A'}`",
            f"- **Subtracted Delta Digest**: `{self.scope.delta_digest or 'N/A'}`",
            "",
            "## Tested Patch Subset",
            f"- **Subset ID**: `{self.tested_subset.subset_id}`",
            f"- **Strategy**: `{self.tested_subset.strategy_type.value}`",
            f"- **Retained Files ({len(self.tested_subset.retained_files)})**: {ret_files}",
            f"- **Retained Hunk IDs ({len(self.tested_subset.retained_hunk_ids)})**: {ret_hunks}",
            f"- **Subtracted Files ({len(self.tested_subset.subtracted_files)})**: {sub_files}",
            f"- **Subtracted Hunk IDs ({n_sub_hunks})**: {sub_hunks}",
            f"- **Retained Patch Digest**: `{self.tested_subset.retained_patch_digest}`",
            f"- **Subtracted Delta Digest**: `{self.tested_subset.subtracted_delta_digest}`",
            "",
            "## Non-Formal-Proof Disclaimer",
            f"> **Notice**: {self.disclaimer.statement}",
            "",
            "### Disclaimed Properties",
            "- **Mathematical Program Proof**: Disclaimed (`False`)",
            "- **Global Minimality**: Disclaimed (`False`)",
            "- **Universal Necessity**: Disclaimed (`False`)",
            "- **Untested Input Guarantees**: Disclaimed (`False`)",
            "- **Semantic Equivalence Beyond Witness**: Disclaimed (`False`)",
            "- **Formal Verification**: Disclaimed (`False`)",
        ]
        return "\n".join(lines)


def create_bounded_causal_slice(
    *,
    slice_id: str,
    scope: CausalSliceScope,
    tested_subset: TestedPatchSubset,
    status: CausalSliceStatus = CausalSliceStatus.TESTED_NECESSARY_SUBSET,
    completeness: SliceSearchCompleteness = SliceSearchCompleteness.BOUNDED_GREEDY,
    summary_label: str = "tested necessary subset under witness",
    disclaimer: NonFormalProofDisclaimer | None = None,
    created_at_utc: str | None = None,
) -> BoundedCausalSlice:
    """Factory creating an authentic, digest-bound BoundedCausalSlice."""
    timestamp = created_at_utc or datetime.now(timezone.utc).isoformat()
    disc = disclaimer or scope.disclaimer or create_canonical_disclaimer()

    payload = {
        "completeness": completeness.value,
        "created_at_utc": timestamp,
        "disclaimer": disc.to_dict(),
        "schema_version": CAUSAL_SLICE_SCHEMA_VERSION,
        "scope": scope.to_dict(),
        "slice_id": slice_id,
        "status": status.value,
        "summary_label": summary_label,
        "tested_subset": tested_subset.to_dict(),
    }
    digest = compute_slice_digest(payload)

    return BoundedCausalSlice(
        slice_id=slice_id,
        scope=scope,
        tested_subset=tested_subset,
        status=status,
        completeness=completeness,
        summary_label=summary_label,
        disclaimer=disc,
        slice_digest=digest,
        created_at_utc=timestamp,
        schema_version=CAUSAL_SLICE_SCHEMA_VERSION,
        is_authoritative=False,
        grants_pass=False,
        is_causally_verified=False,
        claims_global_minimality=False,
    )


def verify_slice_integrity(slice_artifact: BoundedCausalSlice) -> bool:
    """Deterministically verify that a causal slice artifact has not been tampered with."""
    if not isinstance(slice_artifact, BoundedCausalSlice):
        return False
    if slice_artifact.is_authoritative is not False:
        return False
    if slice_artifact.grants_pass is not False:
        return False
    if slice_artifact.is_causally_verified is not False:
        return False
    if slice_artifact.claims_global_minimality is not False:
        return False
    try:
        payload = slice_artifact._build_payload()
        computed = compute_slice_digest(payload)
        return computed == slice_artifact.slice_digest
    except Exception:
        return False
