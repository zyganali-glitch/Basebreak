"""Minimum trusted inputs and context envelope visible to Verifier.

P-08.01: Define minimum trusted inputs visible to Verifier.

Core Invariants:
1. Narrow verifier input contract: Verifier receives only mechanically required
   authoritative inputs (source identity, frozen contract, execution policy,
   and sealed witness references).
2. Explicit input classification: Inputs are strictly classified as TRUSTED_CONTROL
   versus UNTRUSTED_CANDIDATE data.
3. Zero Builder authority: Builder summaries, Builder reasoning, Builder proposals,
   mutable Builder workspace paths, and Builder self-reported pass/verification
   claims possess ZERO verifier authority and are rejected with deny-by-default checks.
4. Unpinned source rejection: Source identity must be pinned to an immutable commit SHA.
   Mutable branch names or unpinned refs fail closed.
5. Deterministic serialization & cryptographic digest: The verifier context envelope
   binds all facts into a canonical SHA-256 context digest.
6. Provider neutrality: Zero adapter imports, zero provider-specific identifiers.
"""

from __future__ import annotations

import hashlib
import json
import re
from collections.abc import Mapping, Sequence
from dataclasses import dataclass
from enum import Enum
from typing import Any

from basebreak.compiler.freeze import FrozenContract
from basebreak.domain.causal import CandidateIdentity
from basebreak.domain.source import CommitRevision, SourceIdentity

VERIFIER_CONTEXT_SCHEMA_VERSION: str = "1.0.0"
_HEX_40_OR_64_PATTERN = re.compile(r"^([0-9a-f]{40}|[0-9a-f]{64})$")
_HEX_40_PATTERN = re.compile(r"^[0-9a-f]{40}$")
_HEX_64_PATTERN = re.compile(r"^[0-9a-f]{64}$")

AUTHORITY_SMUGGLING_KEYS: frozenset[str] = frozenset(
    {
        "is_verified",
        "is_authoritative",
        "passes_all_tests",
        "claims_pass",
        "verdict",
        "verification_result",
    }
)

FORBIDDEN_BUILDER_KEYS: frozenset[str] = frozenset(
    {
        "builder_summary",
        "builder_reasoning",
        "builder_proposal",
        "builder_proposals",
        "builder_thoughts",
        "builder_workspace",
        "builder_workspace_path",
        "builder_sandbox_id",
        "builder_tests",
        "builder_claims",
    }
)


class VerifierInputClassification(str, Enum):
    """Explicit classification of verifier inputs by trust domain."""

    TRUSTED_CONTROL = "TRUSTED_CONTROL"
    UNTRUSTED_CANDIDATE = "UNTRUSTED_CANDIDATE"
    FORBIDDEN_BUILDER_DATA = "FORBIDDEN_BUILDER_DATA"


class VerifierContextError(Exception):
    """Base exception for all Verifier context errors."""


class UntrustedBuilderInputError(VerifierContextError):
    """Raised when Builder-authored prose, proposals, or claims are passed to Verifier."""


class BuilderAuthoritySmugglingError(VerifierContextError):
    """Raised when an input attempts to smuggle self-certification or pass authority."""


class MutableWorkspacePathError(VerifierContextError):
    """Raised when a mutable workspace path is passed as a trusted verifier input."""


class UnpinnedSourceError(VerifierContextError):
    """Raised when source identity is unpinned or references a mutable revision."""


class VerifierDigestMismatchError(VerifierContextError):
    """Raised when verifier context digest does not match canonical recomputed digest."""


@dataclass(frozen=True, slots=True)
class VerifierExecutionPolicy:
    """Bounded, immutable execution limits for Verifier runs.

    Classified as TRUSTED_CONTROL.
    """

    timeout_seconds: int = 120
    memory_mb: int = 1024
    network_disabled: bool = True
    max_output_bytes: int = 65536

    def __post_init__(self) -> None:
        if (
            isinstance(self.timeout_seconds, bool)
            or not isinstance(self.timeout_seconds, int)
            or self.timeout_seconds <= 0
        ):
            raise VerifierContextError("timeout_seconds must be a positive integer")
        if (
            isinstance(self.memory_mb, bool)
            or not isinstance(self.memory_mb, int)
            or self.memory_mb <= 0
        ):
            raise VerifierContextError("memory_mb must be a positive integer")
        if not isinstance(self.network_disabled, bool):
            raise VerifierContextError("network_disabled must be a boolean")
        if (
            isinstance(self.max_output_bytes, bool)
            or not isinstance(self.max_output_bytes, int)
            or self.max_output_bytes <= 0
        ):
            raise VerifierContextError("max_output_bytes must be a positive integer")

    def to_dict(self) -> dict[str, Any]:
        """Canonical dictionary representation."""
        return {
            "max_output_bytes": self.max_output_bytes,
            "memory_mb": self.memory_mb,
            "network_disabled": self.network_disabled,
            "timeout_seconds": self.timeout_seconds,
        }

    @classmethod
    def from_dict(cls, data: Mapping[str, Any]) -> VerifierExecutionPolicy:
        """Construct from dictionary with validation."""
        if not isinstance(data, Mapping):
            raise TypeError(f"Expected mapping, got {type(data).__name__}")
        return cls(
            max_output_bytes=int(data.get("max_output_bytes", 65536)),
            memory_mb=int(data.get("memory_mb", 1024)),
            network_disabled=bool(data.get("network_disabled", True)),
            timeout_seconds=int(data.get("timeout_seconds", 120)),
        )


def build_canonical_verifier_context_payload(
    *,
    schema_version: str,
    frozen_contract_digest: str,
    source_locator: str,
    source_commit_id: str,
    source_subpath: str | None,
    execution_policy: VerifierExecutionPolicy,
    candidate_id: str | None,
    candidate_patch_digest: str | None,
    candidate_tree_digest: str | None,
    sealed_witness_references: Sequence[str],
) -> dict[str, Any]:
    """Construct deterministic identity payload for verifier context digest computation."""
    sorted_witnesses = sorted(str(w) for w in sealed_witness_references)
    return {
        "candidate": (
            {
                "candidate_id": candidate_id,
                "patch_digest": candidate_patch_digest,
                "tree_digest": candidate_tree_digest,
            }
            if candidate_id is not None
            else None
        ),
        "execution_policy": execution_policy.to_dict(),
        "frozen_contract_digest": str(frozen_contract_digest),
        "schema_version": str(schema_version),
        "sealed_witness_references": sorted_witnesses,
        "source": {
            "commit_id": str(source_commit_id),
            "locator": str(source_locator),
            "subpath": source_subpath,
        },
    }


def compute_verifier_context_digest(payload: Mapping[str, Any]) -> str:
    """Compute deterministic SHA-256 digest over canonical JSON bytes."""
    canonical_bytes = json.dumps(
        payload, sort_keys=True, separators=(",", ":"), ensure_ascii=False
    ).encode("utf-8")
    return hashlib.sha256(canonical_bytes).hexdigest()


@dataclass(frozen=True, slots=True)
class VerifierContextEnvelope:
    """The authoritative minimal Verifier input envelope.

    Classifies and isolates trusted control materials from untrusted candidate data.
    Mechanically blocks Builder summaries, reasoning, and mutable workspace inheritance.
    """

    schema_version: str
    frozen_contract: FrozenContract
    source_identity: SourceIdentity
    execution_policy: VerifierExecutionPolicy
    candidate_identity: CandidateIdentity | None
    candidate_patch_text: str | None
    candidate_tree_digest: str | None
    sealed_witness_references: tuple[str, ...]
    context_digest: str

    def __post_init__(self) -> None:
        # 1. Schema version
        if self.schema_version != VERIFIER_CONTEXT_SCHEMA_VERSION:
            raise VerifierContextError(
                f"Unsupported schema_version: {self.schema_version!r}, "
                f"expected {VERIFIER_CONTEXT_SCHEMA_VERSION!r}"
            )

        # 2. Frozen contract validation (TRUSTED_CONTROL)
        if not isinstance(self.frozen_contract, FrozenContract):
            raise TypeError(
                f"frozen_contract must be FrozenContract, got {type(self.frozen_contract).__name__}"
            )

        # 3. Source identity validation (TRUSTED_CONTROL)
        if not isinstance(self.source_identity, SourceIdentity):
            raise TypeError(
                f"source_identity must be SourceIdentity, got {type(self.source_identity).__name__}"
            )

        # Enforce pinned commit SHA
        if not isinstance(self.source_identity.revision, CommitRevision):
            rev_type = type(self.source_identity.revision).__name__
            raise UnpinnedSourceError(f"source_identity must use CommitRevision, got {rev_type}")
        commit_sha = self.source_identity.resolved_commit_id
        if not _HEX_40_PATTERN.match(commit_sha):
            raise UnpinnedSourceError(
                f"source_identity resolved_commit_id must be a 40-character hex commit SHA, "
                f"got {commit_sha!r}"
            )

        # 4. Execution policy (TRUSTED_CONTROL)
        if not isinstance(self.execution_policy, VerifierExecutionPolicy):
            raise TypeError(
                f"execution_policy must be VerifierExecutionPolicy, "
                f"got {type(self.execution_policy).__name__}"
            )

        # 5. Sealed witness references (TRUSTED_CONTROL)
        if not isinstance(self.sealed_witness_references, tuple):
            if isinstance(self.sealed_witness_references, Sequence):
                object.__setattr__(
                    self, "sealed_witness_references", tuple(self.sealed_witness_references)
                )
            else:
                raise TypeError(
                    f"sealed_witness_references must be a sequence of strings, "
                    f"got {type(self.sealed_witness_references).__name__}"
                )
        for idx, ref in enumerate(self.sealed_witness_references):
            if not isinstance(ref, str) or not ref.strip():
                raise VerifierContextError(
                    f"sealed_witness_reference at index {idx} must be a non-empty string"
                )

        # Canonical sort for witness references
        refs_list = list(self.sealed_witness_references)
        if refs_list != sorted(refs_list):
            raise VerifierContextError("sealed_witness_references must be canonically sorted")
        if len(refs_list) != len(set(refs_list)):
            raise VerifierContextError("Duplicate sealed_witness_references detected")

        # 6. Candidate data validation (UNTRUSTED_CANDIDATE)
        if self.candidate_identity is not None:
            if not isinstance(self.candidate_identity, CandidateIdentity):
                raise TypeError(
                    f"candidate_identity must be CandidateIdentity, "
                    f"got {type(self.candidate_identity).__name__}"
                )
            cand_commit = self.candidate_identity.source.resolved_commit_id
            trusted_commit = self.source_identity.resolved_commit_id
            if cand_commit != trusted_commit:
                raise VerifierContextError(
                    f"candidate_identity source commit ({cand_commit}) "
                    f"does not match trusted source commit ({trusted_commit})"
                )

            # Tree digest validation
            if self.candidate_tree_digest is not None:
                if not isinstance(
                    self.candidate_tree_digest, str
                ) or not _HEX_40_OR_64_PATTERN.match(self.candidate_tree_digest):
                    raise VerifierContextError(
                        f"candidate_tree_digest must be 40 or 64 hex chars, "
                        f"got {self.candidate_tree_digest!r}"
                    )

            # Patch text validation
            if self.candidate_patch_text is not None:
                if not isinstance(self.candidate_patch_text, str):
                    raise TypeError("candidate_patch_text must be a string")
                if self.candidate_identity.patch_digest is not None:
                    actual_patch_digest = hashlib.sha256(
                        self.candidate_patch_text.encode("utf-8")
                    ).hexdigest()
                    claimed_digest = self.candidate_identity.patch_digest
                    if actual_patch_digest != claimed_digest:
                        raise VerifierContextError(
                            f"candidate_patch_text digest ({actual_patch_digest}) does not match "
                            f"candidate_identity.patch_digest ({claimed_digest})"
                        )
        else:
            if self.candidate_patch_text is not None or self.candidate_tree_digest is not None:
                raise VerifierContextError(
                    "candidate_patch_text and candidate_tree_digest must be None when "
                    "candidate_identity is None"
                )

        # 7. Context digest verification
        if not isinstance(self.context_digest, str) or not _HEX_64_PATTERN.match(
            self.context_digest
        ):
            raise VerifierContextError(
                f"context_digest must be a 64-char hex string, got {self.context_digest!r}"
            )

        payload = build_canonical_verifier_context_payload(
            schema_version=self.schema_version,
            frozen_contract_digest=self.frozen_contract.contract_digest,
            source_locator=self.source_identity.locator,
            source_commit_id=self.source_identity.resolved_commit_id,
            source_subpath=self.source_identity.subpath,
            execution_policy=self.execution_policy,
            candidate_id=(
                self.candidate_identity.candidate_id if self.candidate_identity else None
            ),
            candidate_patch_digest=(
                self.candidate_identity.patch_digest if self.candidate_identity else None
            ),
            candidate_tree_digest=self.candidate_tree_digest,
            sealed_witness_references=self.sealed_witness_references,
        )
        expected_digest = compute_verifier_context_digest(payload)
        if self.context_digest != expected_digest:
            raise VerifierDigestMismatchError(
                f"verifier context_digest mismatch: declared {self.context_digest}, "
                f"recomputed {expected_digest}"
            )

    @classmethod
    def create(
        cls,
        *,
        frozen_contract: FrozenContract,
        source_identity: SourceIdentity,
        execution_policy: VerifierExecutionPolicy | None = None,
        candidate_identity: CandidateIdentity | None = None,
        candidate_patch_text: str | None = None,
        candidate_tree_digest: str | None = None,
        sealed_witness_references: Sequence[str] = (),
        schema_version: str = VERIFIER_CONTEXT_SCHEMA_VERSION,
        **forbidden_kwargs: Any,
    ) -> VerifierContextEnvelope:
        """Construct an authoritative VerifierContextEnvelope with deny-by-default checks."""
        # Check forbidden builder data smuggling
        for k in forbidden_kwargs:
            if k in AUTHORITY_SMUGGLING_KEYS:
                raise BuilderAuthoritySmugglingError(
                    f"Forbidden authority smuggling attempt in verifier context: {k!r}"
                )
            if k in FORBIDDEN_BUILDER_KEYS or "builder" in k.lower():
                raise UntrustedBuilderInputError(
                    f"Forbidden builder input detected in verifier context: {k!r}"
                )
            raise VerifierContextError(f"Unexpected argument in verifier context creation: {k!r}")

        if not isinstance(source_identity, SourceIdentity):
            raise TypeError(
                f"source_identity must be SourceIdentity, got {type(source_identity).__name__}"
            )
        if not isinstance(source_identity.revision, CommitRevision):
            rev_type = type(source_identity.revision).__name__
            raise UnpinnedSourceError(f"source_identity must use CommitRevision, got {rev_type}")

        policy = execution_policy or VerifierExecutionPolicy()
        sorted_refs = tuple(sorted(str(r) for r in sealed_witness_references))

        payload = build_canonical_verifier_context_payload(
            schema_version=schema_version,
            frozen_contract_digest=frozen_contract.contract_digest,
            source_locator=source_identity.locator,
            source_commit_id=source_identity.resolved_commit_id,
            source_subpath=source_identity.subpath,
            execution_policy=policy,
            candidate_id=candidate_identity.candidate_id if candidate_identity else None,
            candidate_patch_digest=candidate_identity.patch_digest if candidate_identity else None,
            candidate_tree_digest=candidate_tree_digest,
            sealed_witness_references=sorted_refs,
        )
        digest = compute_verifier_context_digest(payload)

        return cls(
            schema_version=schema_version,
            frozen_contract=frozen_contract,
            source_identity=source_identity,
            execution_policy=policy,
            candidate_identity=candidate_identity,
            candidate_patch_text=candidate_patch_text,
            candidate_tree_digest=candidate_tree_digest,
            sealed_witness_references=sorted_refs,
            context_digest=digest,
        )

    def get_input_classifications(self) -> dict[str, VerifierInputClassification]:
        """Return explicit trust domain classification of each envelope field."""
        return {
            "schema_version": VerifierInputClassification.TRUSTED_CONTROL,
            "frozen_contract": VerifierInputClassification.TRUSTED_CONTROL,
            "source_identity": VerifierInputClassification.TRUSTED_CONTROL,
            "execution_policy": VerifierInputClassification.TRUSTED_CONTROL,
            "sealed_witness_references": VerifierInputClassification.TRUSTED_CONTROL,
            "context_digest": VerifierInputClassification.TRUSTED_CONTROL,
            "candidate_identity": VerifierInputClassification.UNTRUSTED_CANDIDATE,
            "candidate_patch_text": VerifierInputClassification.UNTRUSTED_CANDIDATE,
            "candidate_tree_digest": VerifierInputClassification.UNTRUSTED_CANDIDATE,
        }

    @property
    def is_candidate_verification(self) -> bool:
        """True if envelope carries candidate data to verify."""
        return self.candidate_identity is not None

    @property
    def frozen_contract_digest(self) -> str:
        """Deterministic SHA-256 digest of the bound FrozenContract."""
        return self.frozen_contract.contract_digest

    @property
    def source_commit_id(self) -> str:
        """Pinned 40-character commit SHA of the trusted source."""
        return self.source_identity.resolved_commit_id

    def to_dict(self) -> dict[str, Any]:
        """Serialize envelope to JSON-safe dictionary."""
        return {
            "candidate": (
                {
                    "candidate_id": self.candidate_identity.candidate_id,
                    "patch_digest": self.candidate_identity.patch_digest,
                    "patch_text": self.candidate_patch_text,
                    "tree_digest": self.candidate_tree_digest,
                }
                if self.candidate_identity
                else None
            ),
            "context_digest": self.context_digest,
            "execution_policy": self.execution_policy.to_dict(),
            "frozen_contract_digest": self.frozen_contract.contract_digest,
            "schema_version": self.schema_version,
            "sealed_witness_references": list(self.sealed_witness_references),
            "source": {
                "commit_id": self.source_identity.resolved_commit_id,
                "locator": self.source_identity.locator,
                "subpath": self.source_identity.subpath,
            },
        }
