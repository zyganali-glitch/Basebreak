"""Sealed witness storage, deterministic integrity, and vault authority contracts.

P-08.03: Implement sealed witness storage/integrity contract.

Core Invariants:
1. Deterministic witness identity: Every witness artifact and record carries an exact
   cryptographic SHA-256 digest computed over canonical byte representation.
2. Immutable fail-closed integrity: Any mutation, tampering, or mismatch in content,
   path, or digest fails closed immediately.
3. Trust boundary & Zero Builder authority: Caller-created dataclass instances or
   flags (is_sealed=True, is_verified=True) possess ZERO authority. Authority resides
   strictly in cryptographic verification against trusted runtime vault signatures.
4. Path safety: Witness artifact paths are strictly repository-relative and normalized;
   path traversal, root escape, and protected-surface collisions fail closed.
5. Credential safety: Witness artifacts are mechanically scanned for secrets and credentials;
   secret-bearing content is rejected with non-leaking exceptions.
6. Provider neutrality: Zero adapter imports, zero provider-specific identifiers.
"""

from __future__ import annotations

import hashlib
import hmac
import json
import os
import re
from collections.abc import Mapping, Sequence
from dataclasses import dataclass
from datetime import datetime, timezone
from typing import Any

from basebreak.domain.causal import ExecutionWorld
from basebreak.domain.execution import TerminationStatus
from basebreak.domain.verdict import EvidenceProvenance, PreliminaryVerdict
from basebreak.security.protected_surfaces import (
    PathSecurityError,
    PathTraversalError,
    ProtectedSurfaceManifest,
    get_canonical_basebreak_protected_manifest,
    is_path_protected,
    normalize_repo_path,
)
from basebreak.security.secret_policy import contains_secret
from basebreak.verifier.witness_result import WitnessOutcome

_HEX_40_PATTERN = re.compile(r"^[0-9a-f]{40}$")
_HEX_64_PATTERN = re.compile(r"^[0-9a-f]{64}$")
_HEX_64_TO_512_PATTERN = re.compile(r"^[0-9a-f]{64,512}$")


# --- Exceptions ---


class WitnessIntegrityError(Exception):
    """Base exception for all witness integrity and sealing errors."""


class WitnessPathSecurityError(WitnessIntegrityError):
    """Raised when a witness artifact path attempts traversal or is malformed."""


class WitnessProtectedSurfaceCollisionError(WitnessIntegrityError):
    """Raised when a witness artifact collides with a protected governance surface."""


class WitnessSecretError(WitnessIntegrityError):
    """Raised when witness artifact content contains secrets or credentials."""


class WitnessTamperingError(WitnessIntegrityError):
    """Raised when witness artifact or record digest does not match actual contents."""


class UntrustedWitnessAuthorityError(WitnessIntegrityError):
    """Raised when a witness record lacks authentic sealing from trusted vault authority."""


# --- Data Records ---


@dataclass(frozen=True, slots=True)
class WitnessArtifact:
    """An individual immutable file belonging to a sealed witness verification suite.

    Attributes:
        path: Normalized repository-relative path where artifact is placed.
        content: Verbatim text of the witness file.
        content_digest: 64-character lowercase hexadecimal SHA-256 digest of content bytes.
        byte_size: Length in UTF-8 bytes.
    """

    path: str
    content: str
    content_digest: str
    byte_size: int

    def __post_init__(self) -> None:
        if not isinstance(self.path, str):
            raise TypeError("path must be a string")
        if not isinstance(self.content, str):
            raise TypeError("content must be a string")
        if not isinstance(self.content_digest, str) or not _HEX_64_PATTERN.match(
            self.content_digest
        ):
            raise WitnessTamperingError(
                f"content_digest must be a 64-char hex string, got {self.content_digest!r}"
            )
        if (
            isinstance(self.byte_size, bool)
            or not isinstance(self.byte_size, int)
            or self.byte_size < 0
        ):
            raise TypeError("byte_size must be a non-negative integer")

        # 1. Path safety and normalization
        try:
            norm_path = normalize_repo_path(self.path)
        except (PathTraversalError, PathSecurityError) as exc:
            raise WitnessPathSecurityError(f"Witness path safety violation: {exc}") from exc

        if norm_path != self.path:
            raise WitnessPathSecurityError(
                f"Witness path must be already normalized: {self.path!r} != {norm_path!r}"
            )

        # 2. Protected surface collision check
        manifest = get_canonical_basebreak_protected_manifest()
        if is_path_protected(norm_path, manifest):
            raise WitnessProtectedSurfaceCollisionError(
                f"Witness artifact path {norm_path!r} collides with protected governance surface"
            )

        # 3. Secret scan
        if contains_secret(self.content):
            raise WitnessSecretError(
                f"Witness artifact at {norm_path!r} contains credentials or secret-shaped content"
            )

        # 4. Digest and byte size verification
        encoded = self.content.encode("utf-8")
        if len(encoded) != self.byte_size:
            raise WitnessTamperingError(
                f"byte_size mismatch: declared {self.byte_size}, actual {len(encoded)}"
            )
        computed_digest = hashlib.sha256(encoded).hexdigest()
        if self.content_digest != computed_digest:
            raise WitnessTamperingError(
                f"content_digest mismatch for {self.path}: declared {self.content_digest}, "
                f"computed {computed_digest}"
            )

    @classmethod
    def from_text(
        cls,
        path: str,
        content: str,
        *,
        manifest: ProtectedSurfaceManifest | None = None,
    ) -> WitnessArtifact:
        """Construct a validated WitnessArtifact from path and text content."""
        if not isinstance(path, str):
            raise TypeError("path must be a string")
        if not isinstance(content, str):
            raise TypeError("content must be a string")

        try:
            norm_path = normalize_repo_path(path)
        except (PathTraversalError, PathSecurityError) as exc:
            raise WitnessPathSecurityError(f"Witness path safety violation: {exc}") from exc

        if norm_path != path:
            raise WitnessPathSecurityError(
                f"Witness path must be already normalized without relative components: {path!r}"
            )

        active_manifest = manifest or get_canonical_basebreak_protected_manifest()
        if is_path_protected(norm_path, active_manifest):
            raise WitnessProtectedSurfaceCollisionError(
                f"Witness artifact path {norm_path!r} collides with protected governance surface"
            )

        if contains_secret(content):
            raise WitnessSecretError(
                f"Witness artifact at {norm_path!r} contains credentials or secret-shaped content"
            )

        encoded = content.encode("utf-8")
        digest = hashlib.sha256(encoded).hexdigest()
        return cls(
            path=norm_path,
            content=content,
            content_digest=digest,
            byte_size=len(encoded),
        )

    def to_dict(self) -> dict[str, Any]:
        """Serialize artifact to JSON-safe dictionary."""
        return {
            "byte_size": self.byte_size,
            "content": self.content,
            "content_digest": self.content_digest,
            "path": self.path,
        }


def build_canonical_witness_identity_payload(
    *,
    witness_id: str,
    requirement_id: str,
    frozen_contract_digest: str,
    source_commit_id: str,
    artifacts: Sequence[WitnessArtifact],
    created_at_utc: str,
) -> dict[str, Any]:
    """Construct deterministic identity payload for witness seal computation."""
    sorted_artifacts = sorted(
        [
            {
                "byte_size": a.byte_size,
                "content_digest": a.content_digest,
                "path": a.path,
            }
            for a in artifacts
        ],
        key=lambda x: str(x["path"]),
    )
    return {
        "artifacts": sorted_artifacts,
        "created_at_utc": str(created_at_utc),
        "frozen_contract_digest": str(frozen_contract_digest),
        "requirement_id": str(requirement_id),
        "source_commit_id": str(source_commit_id),
        "witness_id": str(witness_id),
    }


def compute_seal_digest(payload: Mapping[str, Any]) -> str:
    """Compute deterministic SHA-256 digest over canonical JSON bytes."""
    canonical_bytes = json.dumps(
        payload, sort_keys=True, separators=(",", ":"), ensure_ascii=False
    ).encode("utf-8")
    return hashlib.sha256(canonical_bytes).hexdigest()


@dataclass(frozen=True, slots=True)
class SealedWitnessRecord:
    """An immutable sealed witness record bound to requirements and frozen contract.

    Possesses ZERO authority on its own; authority must be validated by TrustedWitnessVault.
    """

    witness_id: str
    requirement_id: str
    frozen_contract_digest: str
    source_commit_id: str
    artifacts: tuple[WitnessArtifact, ...]
    seal_digest: str
    created_at_utc: str
    vault_signature: str
    is_sealed: bool = True

    def __post_init__(self) -> None:
        if not isinstance(self.witness_id, str) or not self.witness_id.strip():
            raise WitnessIntegrityError("witness_id must be a non-empty string")
        if not isinstance(self.requirement_id, str) or not self.requirement_id.strip():
            raise WitnessIntegrityError("requirement_id must be a non-empty string")
        if not isinstance(self.frozen_contract_digest, str) or not _HEX_64_PATTERN.match(
            self.frozen_contract_digest
        ):
            raise WitnessIntegrityError("frozen_contract_digest must be a 64-char hex string")
        if not isinstance(self.source_commit_id, str) or not _HEX_40_PATTERN.match(
            self.source_commit_id
        ):
            raise WitnessIntegrityError("source_commit_id must be a 40-char commit SHA")

        if not isinstance(self.artifacts, tuple):
            if isinstance(self.artifacts, Sequence):
                object.__setattr__(self, "artifacts", tuple(self.artifacts))
            else:
                raise TypeError("artifacts must be a sequence of WitnessArtifact")

        if not self.artifacts:
            raise WitnessIntegrityError("Sealed witness record must have at least one artifact")

        for idx, art in enumerate(self.artifacts):
            if not isinstance(art, WitnessArtifact):
                raise TypeError(
                    f"artifact at index {idx} must be WitnessArtifact, got {type(art).__name__}"
                )

        # Canonical ordering and duplicate path check
        paths = [a.path for a in self.artifacts]
        if paths != sorted(paths):
            raise WitnessIntegrityError("artifacts must be canonically sorted by path")
        if len(paths) != len(set(paths)):
            raise WitnessIntegrityError(
                "Duplicate artifact paths detected in sealed witness record"
            )

        if not isinstance(self.seal_digest, str) or not _HEX_64_PATTERN.match(self.seal_digest):
            raise WitnessIntegrityError("seal_digest must be a 64-char hex string")
        if not isinstance(self.created_at_utc, str) or not self.created_at_utc.strip():
            raise WitnessIntegrityError("created_at_utc must be a non-empty string")
        if not isinstance(self.vault_signature, str) or not _HEX_64_PATTERN.match(
            self.vault_signature
        ):
            raise WitnessIntegrityError("vault_signature must be a 64-char hex string")

        # Verify seal digest computation
        payload = build_canonical_witness_identity_payload(
            witness_id=self.witness_id,
            requirement_id=self.requirement_id,
            frozen_contract_digest=self.frozen_contract_digest,
            source_commit_id=self.source_commit_id,
            artifacts=self.artifacts,
            created_at_utc=self.created_at_utc,
        )
        expected_seal = compute_seal_digest(payload)
        if self.seal_digest != expected_seal:
            raise WitnessTamperingError(
                f"seal_digest mismatch: declared {self.seal_digest}, expected {expected_seal}"
            )

    def to_dict(self) -> dict[str, Any]:
        """Serialize sealed witness record to dictionary."""
        return {
            "artifacts": [a.to_dict() for a in self.artifacts],
            "created_at_utc": self.created_at_utc,
            "frozen_contract_digest": self.frozen_contract_digest,
            "is_sealed": self.is_sealed,
            "requirement_id": self.requirement_id,
            "seal_digest": self.seal_digest,
            "source_commit_id": self.source_commit_id,
            "vault_signature": self.vault_signature,
            "witness_id": self.witness_id,
        }


def build_canonical_execution_attestation_payload(
    *,
    requirement_id: str,
    frozen_contract_digest: str,
    witness_id: str,
    witness_digest: str,
    source_commit_id: str,
    candidate_tree_digest: str | None = None,
    base_outcome: WitnessOutcome | None = None,
    candidate_outcome: WitnessOutcome | None = None,
    counterfactual_outcome: WitnessOutcome | None = None,
    transition: Any = None,
    verdict: PreliminaryVerdict = PreliminaryVerdict.VERIFIED,
    provenance: EvidenceProvenance = EvidenceProvenance.LOCAL_EXECUTION,
    created_at_utc: str = "",
    issuer_id: str = "",
    execution_origin: str = "",
    execution_command: Sequence[str] | str = "",
    base_sandbox_id: str = "",
    candidate_sandbox_id: str = "",
    counterfactual_sandbox_id: str | None = None,
    base_exit_code: int | None = None,
    candidate_exit_code: int | None = None,
    counterfactual_exit_code: int | None = None,
    base_termination_status: TerminationStatus | str | None = None,
    candidate_termination_status: TerminationStatus | str | None = None,
    counterfactual_termination_status: TerminationStatus | str | None = None,
    base_result_digest: str = "",
    candidate_result_digest: str = "",
    counterfactual_result_digest: str | None = None,
    base_stdout_digest: str = "",
    base_stderr_digest: str = "",
    candidate_stdout_digest: str = "",
    candidate_stderr_digest: str = "",
    counterfactual_stdout_digest: str | None = None,
    counterfactual_stderr_digest: str | None = None,
    base_tree_digest: str = "",
    counterfactual_tree_digest: str | None = None,
) -> dict[str, Any]:
    """Construct deterministic payload for execution attestation digest computation."""
    trans_val = transition.value if hasattr(transition, "value") else str(transition)
    cmd_str = (
        " ".join(str(c) for c in execution_command)
        if isinstance(execution_command, (list, tuple))
        else str(execution_command or "").strip()
    )
    b_term = (
        base_termination_status.value
        if base_termination_status is not None and hasattr(base_termination_status, "value")
        else (str(base_termination_status) if base_termination_status is not None else None)
    )
    c_term = (
        candidate_termination_status.value
        if candidate_termination_status is not None
        and hasattr(candidate_termination_status, "value")
        else (
            str(candidate_termination_status) if candidate_termination_status is not None else None
        )
    )
    cf_term = (
        counterfactual_termination_status.value
        if counterfactual_termination_status is not None
        and hasattr(counterfactual_termination_status, "value")
        else (
            str(counterfactual_termination_status)
            if counterfactual_termination_status is not None
            else None
        )
    )

    payload: dict[str, Any] = {
        "base_exit_code": base_exit_code,
        "base_outcome": base_outcome.value if base_outcome is not None else None,
        "base_result_digest": str(base_result_digest or "").strip().lower(),
        "base_sandbox_id": str(base_sandbox_id or "").strip(),
        "base_stderr_digest": str(base_stderr_digest or "").strip().lower(),
        "base_stdout_digest": str(base_stdout_digest or "").strip().lower(),
        "base_termination_status": b_term,
        "base_tree_digest": str(base_tree_digest or "").strip().lower(),
        "candidate_exit_code": candidate_exit_code,
        "candidate_outcome": candidate_outcome.value if candidate_outcome is not None else None,
        "candidate_result_digest": str(candidate_result_digest or "").strip().lower(),
        "candidate_sandbox_id": str(candidate_sandbox_id or "").strip(),
        "candidate_stderr_digest": str(candidate_stderr_digest or "").strip().lower(),
        "candidate_stdout_digest": str(candidate_stdout_digest or "").strip().lower(),
        "candidate_termination_status": c_term,
        "candidate_tree_digest": str(candidate_tree_digest or "").strip().lower(),
        "counterfactual_exit_code": counterfactual_exit_code,
        "counterfactual_outcome": (
            counterfactual_outcome.value if counterfactual_outcome is not None else None
        ),
        "counterfactual_result_digest": (
            str(counterfactual_result_digest or "").strip().lower()
            if counterfactual_result_digest is not None
            else None
        ),
        "counterfactual_sandbox_id": (
            str(counterfactual_sandbox_id or "").strip()
            if counterfactual_sandbox_id is not None
            else None
        ),
        "counterfactual_stderr_digest": (
            str(counterfactual_stderr_digest or "").strip().lower()
            if counterfactual_stderr_digest is not None
            else None
        ),
        "counterfactual_stdout_digest": (
            str(counterfactual_stdout_digest or "").strip().lower()
            if counterfactual_stdout_digest is not None
            else None
        ),
        "counterfactual_termination_status": cf_term,
        "counterfactual_tree_digest": (
            str(counterfactual_tree_digest or "").strip().lower()
            if counterfactual_tree_digest is not None
            else None
        ),
        "created_at_utc": str(created_at_utc).strip(),
        "execution_command": cmd_str,
        "frozen_contract_digest": str(frozen_contract_digest).strip().lower(),
        "provenance": provenance.value,
        "requirement_id": str(requirement_id).strip(),
        "source_commit_id": str(source_commit_id).strip().lower(),
        "transition": str(trans_val),
        "verdict": verdict.value,
        "witness_digest": str(witness_digest).strip().lower(),
        "witness_id": str(witness_id).strip(),
    }
    if issuer_id:
        payload["issuer_id"] = str(issuer_id).strip()
    if execution_origin:
        payload["execution_origin"] = str(execution_origin).strip()
    return payload


def compute_attestation_digest(payload: Mapping[str, Any]) -> str:
    """Compute deterministic SHA-256 digest over canonical JSON bytes."""
    canonical_bytes = json.dumps(
        payload, sort_keys=True, separators=(",", ":"), ensure_ascii=False
    ).encode("utf-8")
    return hashlib.sha256(canonical_bytes).hexdigest()


@dataclass(frozen=True, slots=True)
class VerifierExecutionAttestation:
    """Cryptographic attestation certifying verifier-side execution authority.

    Possesses authority strictly when validated by TrustedWitnessVault or
    the trusted verifier authority bridge.
    """

    requirement_id: str
    frozen_contract_digest: str
    witness_id: str
    witness_digest: str
    source_commit_id: str
    candidate_tree_digest: str
    base_outcome: WitnessOutcome | None
    candidate_outcome: WitnessOutcome | None
    transition: Any
    verdict: PreliminaryVerdict
    provenance: EvidenceProvenance
    attestation_digest: str
    vault_signature: str
    created_at_utc: str
    is_authoritative: bool = True
    counterfactual_outcome: WitnessOutcome | None = None
    issuer_id: str = ""
    execution_origin: str = ""
    execution_command: str = ""
    base_sandbox_id: str = ""
    candidate_sandbox_id: str = ""
    counterfactual_sandbox_id: str | None = None
    base_exit_code: int | None = None
    candidate_exit_code: int | None = None
    counterfactual_exit_code: int | None = None
    base_termination_status: str | None = None
    candidate_termination_status: str | None = None
    counterfactual_termination_status: str | None = None
    base_result_digest: str = ""
    candidate_result_digest: str = ""
    counterfactual_result_digest: str | None = None
    base_stdout_digest: str = ""
    base_stderr_digest: str = ""
    candidate_stdout_digest: str = ""
    candidate_stderr_digest: str = ""
    counterfactual_stdout_digest: str | None = None
    counterfactual_stderr_digest: str | None = None
    base_tree_digest: str = ""
    counterfactual_tree_digest: str | None = None

    def __post_init__(self) -> None:
        if not isinstance(self.requirement_id, str) or not self.requirement_id.strip():
            raise WitnessIntegrityError("requirement_id must be a non-empty string")
        if not isinstance(self.frozen_contract_digest, str) or not _HEX_64_PATTERN.match(
            self.frozen_contract_digest
        ):
            raise WitnessIntegrityError("frozen_contract_digest must be a 64-char hex string")
        if not isinstance(self.witness_id, str) or not self.witness_id.strip():
            raise WitnessIntegrityError("witness_id must be a non-empty string")
        if not isinstance(self.witness_digest, str) or not _HEX_64_PATTERN.match(
            self.witness_digest
        ):
            raise WitnessIntegrityError("witness_digest must be a 64-char hex string")
        if not isinstance(self.source_commit_id, str) or not _HEX_40_PATTERN.match(
            self.source_commit_id
        ):
            raise WitnessIntegrityError("source_commit_id must be a 40-char commit SHA")
        if not isinstance(self.candidate_tree_digest, str) or not (
            _HEX_40_PATTERN.match(self.candidate_tree_digest)
            or _HEX_64_PATTERN.match(self.candidate_tree_digest)
        ):
            raise WitnessIntegrityError("candidate_tree_digest must be 40 or 64 hex chars")
        trans_str = (
            self.transition.value if hasattr(self.transition, "value") else str(self.transition)
        )
        if not trans_str or not trans_str.strip():
            raise WitnessIntegrityError("transition must be a non-empty string or CausalTransition")
        if not isinstance(self.verdict, PreliminaryVerdict):
            raise TypeError("verdict must be PreliminaryVerdict")
        if not isinstance(self.provenance, EvidenceProvenance):
            raise TypeError("provenance must be EvidenceProvenance")
        if not isinstance(self.attestation_digest, str) or not _HEX_64_PATTERN.match(
            self.attestation_digest
        ):
            raise WitnessIntegrityError("attestation_digest must be a 64-char hex string")
        if not isinstance(self.vault_signature, str) or not _HEX_64_TO_512_PATTERN.match(
            self.vault_signature
        ):
            raise WitnessIntegrityError("vault_signature must be a 64- to 512-char hex string")

    def to_dict(self) -> dict[str, Any]:
        """Serialize attestation to JSON-safe dictionary."""
        trans_val = (
            self.transition.value if hasattr(self.transition, "value") else str(self.transition)
        )
        data = {
            "attestation_digest": self.attestation_digest,
            "base_exit_code": self.base_exit_code,
            "base_outcome": self.base_outcome.value if self.base_outcome is not None else None,
            "base_result_digest": self.base_result_digest,
            "base_sandbox_id": self.base_sandbox_id,
            "base_stderr_digest": self.base_stderr_digest,
            "base_stdout_digest": self.base_stdout_digest,
            "base_termination_status": self.base_termination_status,
            "base_tree_digest": self.base_tree_digest,
            "candidate_exit_code": self.candidate_exit_code,
            "candidate_outcome": (
                self.candidate_outcome.value if self.candidate_outcome is not None else None
            ),
            "candidate_result_digest": self.candidate_result_digest,
            "candidate_sandbox_id": self.candidate_sandbox_id,
            "candidate_stderr_digest": self.candidate_stderr_digest,
            "candidate_stdout_digest": self.candidate_stdout_digest,
            "candidate_termination_status": self.candidate_termination_status,
            "candidate_tree_digest": self.candidate_tree_digest,
            "counterfactual_exit_code": self.counterfactual_exit_code,
            "counterfactual_outcome": (
                self.counterfactual_outcome.value
                if self.counterfactual_outcome is not None
                else None
            ),
            "counterfactual_result_digest": self.counterfactual_result_digest,
            "counterfactual_sandbox_id": self.counterfactual_sandbox_id,
            "counterfactual_stderr_digest": self.counterfactual_stderr_digest,
            "counterfactual_stdout_digest": self.counterfactual_stdout_digest,
            "counterfactual_termination_status": self.counterfactual_termination_status,
            "counterfactual_tree_digest": self.counterfactual_tree_digest,
            "created_at_utc": self.created_at_utc,
            "execution_command": self.execution_command,
            "frozen_contract_digest": self.frozen_contract_digest,
            "is_authoritative": self.is_authoritative,
            "provenance": self.provenance.value,
            "requirement_id": self.requirement_id,
            "source_commit_id": self.source_commit_id,
            "transition": str(trans_val),
            "vault_signature": self.vault_signature,
            "verdict": self.verdict.value,
            "witness_digest": self.witness_digest,
            "witness_id": self.witness_id,
        }
        if self.issuer_id:
            data["issuer_id"] = self.issuer_id
        if self.execution_origin:
            data["execution_origin"] = self.execution_origin
        return data


@dataclass(frozen=True, slots=True)
class VerifierObservedExecutionRecord:
    """An immutable record of an execution observation witnessed by the authorized verifier runtime.

    Binds the observed execution fact directly to:
    - requirement_id
    - frozen_contract_digest
    - witness_id and sealed witness_digest
    - source_commit_id
    - candidate_tree_digest
    - sandbox_id
    - world (BASE, CANDIDATE, COUNTERFACTUAL)
    - command
    - exit_code
    - termination_status
    - stdout/stderr/result digests
    - outcome (WitnessOutcome)
    - provenance (EvidenceProvenance)
    """

    witness_id: str
    witness_digest: str
    requirement_id: str
    frozen_contract_digest: str
    source_commit_id: str
    candidate_tree_digest: str
    sandbox_id: str
    world: ExecutionWorld
    command: tuple[str, ...] | str
    exit_code: int | None
    termination_status: TerminationStatus
    stdout_digest: str
    stderr_digest: str
    result_digest: str
    outcome: WitnessOutcome
    provenance: EvidenceProvenance
    observed_at_utc: str


# --- Trusted Witness Vault ---


class TrustedWitnessVault:
    """The authoritative runtime vault for sealing and validating witness integrity.

    Establishes cryptographic trust boundary:
    Records created outside this vault cannot claim verified authority.
    """

    def __init__(self, vault_secret: bytes | None = None) -> None:
        object.__setattr__(self, "_initialized", False)
        self._vault_secret: bytes = vault_secret or os.urandom(32)
        self._registered_seals: dict[str, tuple[str, str]] = {}
        self._records: dict[str, SealedWitnessRecord] = {}
        self._registered_executions: dict[str, VerifierExecutionAttestation] = {}
        self._observed_executions: dict[tuple[str, str], VerifierObservedExecutionRecord] = {}
        self._authorized_provenances: frozenset[EvidenceProvenance] = frozenset()
        self._bound_engine: Any | None = None
        self._initialized: bool = True

    def __setattr__(self, name: str, value: Any) -> None:
        if getattr(self, "_initialized", False):
            if name in (
                "_authorized_provenances",
                "authorized_provenances",
                "_vault_secret",
                "is_authoritative_root",
            ):
                raise UntrustedWitnessAuthorityError(
                    f"Direct mutation or substitution of {name} is strictly prohibited"
                )
        super().__setattr__(name, value)

    @property
    def is_authoritative_root(self) -> bool:
        """Return True if this vault is an authorized verifier execution authority root."""
        return bool(self._authorized_provenances)

    @property
    def authorized_provenances(self) -> frozenset[EvidenceProvenance]:
        """Return the frozenset of authorized EvidenceProvenance scopes for this vault."""
        return self._authorized_provenances

    def _authorize_verifier_runtime(
        self,
        runtime: Any,
        provenance: EvidenceProvenance,
    ) -> None:
        """Authorize this vault for a specific provenance based on authentic verifier runtime.

        Production authority must originate at the genuine verifier runtime boundary.
        Mock/simulated or caller-created runtimes cannot obtain LOCAL_EXECUTION
        or LIVE_NEBIUS authority.
        """
        if runtime is None:
            raise UntrustedWitnessAuthorityError("runtime cannot be None")

        from basebreak.causal.engine import CausalExecutionEngine

        if not isinstance(runtime, CausalExecutionEngine):
            raise UntrustedWitnessAuthorityError(
                f"runtime must be an authentic CausalExecutionEngine instance, "
                f"got {type(runtime).__name__}"
            )

        if not isinstance(provenance, EvidenceProvenance):
            raise TypeError(
                f"provenance must be EvidenceProvenance, got {type(provenance).__name__}"
            )

        if provenance in (
            EvidenceProvenance.LIVE_NEBIUS,
            EvidenceProvenance.LOCAL_EXECUTION,
            EvidenceProvenance.RECORDED_LIVE,
        ):
            raise UntrustedWitnessAuthorityError(
                f"In-process vault cannot be granted production execution authority "
                f"({provenance.value}); production authority cannot be issued from "
                f"in-process runtime objects"
            )
        elif provenance == EvidenceProvenance.FIXTURE:
            object.__setattr__(
                self,
                "_authorized_provenances",
                self._authorized_provenances | {EvidenceProvenance.FIXTURE},
            )
        else:
            raise UntrustedWitnessAuthorityError(
                f"Provenance scope {provenance.value} cannot be authorized through verifier runtime"
            )

        object.__setattr__(self, "_bound_engine", runtime)

    def _authorize_as_engine_root(self, engine: Any) -> None:
        """Authorize vault root bound to an execution engine, inspecting runtime provenance."""
        from basebreak.causal.engine import CausalExecutionEngine

        if not isinstance(engine, CausalExecutionEngine):
            raise UntrustedWitnessAuthorityError(
                f"Direct production authorization through _authorize_as_engine_root() rejected: "
                f"expected authentic CausalExecutionEngine, got {type(engine).__name__}"
            )
        prov = getattr(engine, "provenance", EvidenceProvenance.FIXTURE)
        self._authorize_verifier_runtime(engine, prov)

    @classmethod
    def create_authorized_vault(
        cls,
        vault_secret: bytes | None = None,
        *,
        fixture_only: bool = True,
    ) -> TrustedWitnessVault:
        """Create a vault explicitly authorized strictly for FIXTURE-scoped verification.

        Test-only authority factory strictly incapable of certifying real
        LOCAL_EXECUTION or LIVE_NEBIUS evidence.
        """
        vault = cls(vault_secret=vault_secret)
        object.__setattr__(
            vault, "_authorized_provenances", frozenset({EvidenceProvenance.FIXTURE})
        )
        return vault

    def record_observed_execution(
        self,
        *,
        witness_id: str,
        witness_digest: str,
        requirement_id: str,
        frozen_contract_digest: str,
        source_commit_id: str,
        candidate_tree_digest: str,
        sandbox_id: str,
        world: ExecutionWorld,
        command: Sequence[str] | str = (),
        exit_code: int | None,
        termination_status: TerminationStatus,
        stdout_digest: str,
        stderr_digest: str,
        result_digest: str,
        outcome: WitnessOutcome,
        provenance: EvidenceProvenance,
        observed_at_utc: str | None = None,
    ) -> VerifierObservedExecutionRecord:
        """Record an execution observation independently witnessed by the verifier runtime."""
        clean_wid = str(witness_id).strip()
        if not clean_wid:
            raise WitnessIntegrityError("witness_id must not be empty")

        if provenance in (
            EvidenceProvenance.LOCAL_EXECUTION,
            EvidenceProvenance.LIVE_NEBIUS,
            EvidenceProvenance.RECORDED_LIVE,
        ):
            raise UntrustedWitnessAuthorityError(
                f"Caller-originated record_observed_execution() for production "
                f"provenance ({provenance.value}) is strictly prohibited; production observations "
                f"cannot be minted through in-process method invocation"
            )

        if provenance not in self._authorized_provenances:
            raise UntrustedWitnessAuthorityError(
                f"Vault is not authorized to record execution observations for {provenance.value}; "
                f"authorized scopes: {[p.value for p in self._authorized_provenances]}"
            )

        sealed_record = self._records.get(clean_wid)
        if sealed_record is None:
            raise UntrustedWitnessAuthorityError(
                f"Witness ID {clean_wid!r} must be sealed in the trusted vault "
                "before recording observations"
            )

        self.verify_witness_integrity(sealed_record)

        if sealed_record.seal_digest.lower() != witness_digest.lower():
            raise WitnessTamperingError(
                f"witness_digest mismatch for {clean_wid}: declared {witness_digest}, "
                f"sealed {sealed_record.seal_digest}"
            )
        if sealed_record.requirement_id != requirement_id:
            raise WitnessIntegrityError(
                f"requirement_id mismatch: declared {requirement_id}, "
                f"sealed {sealed_record.requirement_id}"
            )
        if sealed_record.frozen_contract_digest.lower() != frozen_contract_digest.lower():
            raise WitnessIntegrityError("frozen_contract_digest mismatch")
        if sealed_record.source_commit_id.lower() != source_commit_id.lower():
            raise WitnessIntegrityError("source_commit_id mismatch")

        if not isinstance(outcome, WitnessOutcome):
            raise TypeError(f"outcome must be WitnessOutcome, got {type(outcome).__name__}")
        if not isinstance(world, ExecutionWorld):
            raise TypeError(f"world must be ExecutionWorld, got {type(world).__name__}")
        if not isinstance(provenance, EvidenceProvenance):
            raise TypeError(
                f"provenance must be EvidenceProvenance, got {type(provenance).__name__}"
            )

        cmd_tuple = tuple(command) if isinstance(command, (list, tuple)) else str(command)
        timestamp = observed_at_utc or datetime.now(timezone.utc).isoformat()

        obs_record = VerifierObservedExecutionRecord(
            witness_id=clean_wid,
            witness_digest=sealed_record.seal_digest,
            requirement_id=requirement_id,
            frozen_contract_digest=frozen_contract_digest,
            source_commit_id=source_commit_id,
            candidate_tree_digest=candidate_tree_digest,
            sandbox_id=sandbox_id,
            world=world,
            command=cmd_tuple,
            exit_code=exit_code,
            termination_status=termination_status,
            stdout_digest=stdout_digest,
            stderr_digest=stderr_digest,
            result_digest=result_digest,
            outcome=outcome,
            provenance=provenance,
            observed_at_utc=timestamp,
        )

        world_str = world.value if hasattr(world, "value") else str(world)
        self._observed_executions[(clean_wid, world_str)] = obs_record
        return obs_record

    def seal_witness(
        self,
        *,
        witness_id: str,
        requirement_id: str,
        frozen_contract_digest: str,
        source_commit_id: str,
        artifacts: Sequence[WitnessArtifact],
        created_at_utc: str | None = None,
    ) -> SealedWitnessRecord:
        """Seal witness artifacts and record cryptographic authority in vault."""
        clean_wid = str(witness_id).strip()
        if not clean_wid:
            raise WitnessIntegrityError("witness_id must not be empty")
        if clean_wid in self._records:
            raise WitnessIntegrityError(f"Witness ID {clean_wid!r} is already sealed in this vault")

        timestamp = created_at_utc or datetime.now(timezone.utc).isoformat()
        sorted_artifacts = tuple(sorted(artifacts, key=lambda a: a.path))

        payload = build_canonical_witness_identity_payload(
            witness_id=clean_wid,
            requirement_id=requirement_id,
            frozen_contract_digest=frozen_contract_digest,
            source_commit_id=source_commit_id,
            artifacts=sorted_artifacts,
            created_at_utc=timestamp,
        )
        seal_digest = compute_seal_digest(payload)
        vault_sig = hmac.new(
            self._vault_secret, seal_digest.encode("utf-8"), hashlib.sha256
        ).hexdigest()

        record = SealedWitnessRecord(
            witness_id=clean_wid,
            requirement_id=requirement_id,
            frozen_contract_digest=frozen_contract_digest,
            source_commit_id=source_commit_id,
            artifacts=sorted_artifacts,
            seal_digest=seal_digest,
            created_at_utc=timestamp,
            vault_signature=vault_sig,
            is_sealed=True,
        )

        self._registered_seals[clean_wid] = (seal_digest, vault_sig)
        self._records[clean_wid] = record
        return record

    def verify_witness_integrity(self, record: SealedWitnessRecord) -> bool:
        """Mechanically verify the authentic cryptographic integrity of a witness record.

        Fail-closed rules:
        1. Reject non-SealedWitnessRecord types.
        2. Re-verify all artifact digests and byte sizes.
        3. Re-verify protected surfaces and secret policies.
        4. Recompute seal digest from canonical payload.
        5. Verify authentic cryptographic HMAC signature against vault secret.
        6. Verify registration presence in trusted registry.
        """
        if not isinstance(record, SealedWitnessRecord):
            raise UntrustedWitnessAuthorityError(
                f"Expected SealedWitnessRecord, got {type(record).__name__}"
            )

        # 1. Check registration presence
        reg = self._registered_seals.get(record.witness_id)
        if reg is None:
            raise UntrustedWitnessAuthorityError(
                f"Witness ID {record.witness_id!r} was not sealed by this trusted vault"
            )

        registered_digest, registered_sig = reg

        # 2. Re-verify HMAC signature
        expected_sig = hmac.new(
            self._vault_secret, record.seal_digest.encode("utf-8"), hashlib.sha256
        ).hexdigest()
        if not hmac.compare_digest(record.vault_signature, expected_sig):
            raise UntrustedWitnessAuthorityError(
                f"Witness {record.witness_id!r} carries invalid or forged vault signature"
            )

        if not hmac.compare_digest(record.vault_signature, registered_sig):
            raise UntrustedWitnessAuthorityError(
                "Witness signature does not match registered authority"
            )

        # 3. Re-verify seal digest
        if record.seal_digest != registered_digest:
            raise WitnessTamperingError(
                f"Witness seal digest {record.seal_digest!r} does not match registered digest"
            )

        payload = build_canonical_witness_identity_payload(
            witness_id=record.witness_id,
            requirement_id=record.requirement_id,
            frozen_contract_digest=record.frozen_contract_digest,
            source_commit_id=record.source_commit_id,
            artifacts=record.artifacts,
            created_at_utc=record.created_at_utc,
        )
        recomputed_seal = compute_seal_digest(payload)
        if recomputed_seal != record.seal_digest:
            raise WitnessTamperingError(
                "Witness seal digest recomputation failed: artifacts or metadata tampered"
            )

        # 4. Re-verify artifacts
        for art in record.artifacts:
            # Recheck secret policy
            if contains_secret(art.content):
                raise WitnessSecretError(f"Witness artifact at {art.path!r} contains credentials")
            # Recheck digest
            computed = hashlib.sha256(art.content.encode("utf-8")).hexdigest()
            if art.content_digest != computed:
                raise WitnessTamperingError(
                    f"Artifact {art.path!r} content digest has been tampered"
                )

        return True

    def get_witness(self, witness_id: str) -> SealedWitnessRecord:
        """Look up a sealed witness record and verify its integrity before returning."""
        record = self._records.get(witness_id)
        if record is None:
            raise KeyError(f"Witness ID {witness_id!r} not found in trusted vault")
        self.verify_witness_integrity(record)
        return record

    def list_sealed_witness_ids(self) -> tuple[str, ...]:
        """Return canonically sorted tuple of sealed witness IDs in vault."""
        return tuple(sorted(self._records.keys()))

    def attest_execution(
        self,
        *,
        witness_id: str,
        requirement_id: str,
        frozen_contract_digest: str,
        source_commit_id: str,
        candidate_tree_digest: str | None = None,
        witness_digest: str | None = None,
        witness_artifacts: Sequence[WitnessArtifact] | None = None,
        base_execution: Any | None = None,
        candidate_execution: Any | None = None,
        counterfactual_execution: Any | None = None,
        base_outcome: WitnessOutcome | None = None,
        candidate_outcome: WitnessOutcome | None = None,
        counterfactual_outcome: WitnessOutcome | None = None,
        transition: Any,
        verdict: PreliminaryVerdict,
        provenance: EvidenceProvenance,
        created_at_utc: str | None = None,
    ) -> VerifierExecutionAttestation:
        """Record and cryptographically attest genuine verifier-side execution.

        Fail-closed authority invariants:
        1. Authority Root: Vault must be authorized for the specified evidence provenance.
           Caller-owned fresh vaults or fixture-scoped vaults possess zero authority
           to attest production execution.
        2. Sealed Witness Mandatory: Witness must be previously sealed in this vault.
           Caller-supplied witness_digest without sealed record is strictly rejected.
        3. Real Execution Records Mandatory: base_execution and candidate_execution
           records observed by verifier execution are required. Directly supplying
           outcomes without execution records is strictly rejected.
        4. Verifier Pre-Observation Mandatory: Pre-existing execution records observed
           and recorded by the verifier runtime before attestation are required.
           Direct registration of caller claims without prior verifier observation
           is strictly prohibited.
        5. Factual Consistency: Caller-supplied facts and outcomes must match
           pre-recorded verifier observations.
        """
        # 1. Authority root check
        if provenance in (
            EvidenceProvenance.LOCAL_EXECUTION,
            EvidenceProvenance.LIVE_NEBIUS,
            EvidenceProvenance.RECORDED_LIVE,
        ):
            raise UntrustedWitnessAuthorityError(
                f"Vault is not authorized to attest execution for {provenance.value}; "
                f"in-process vault cannot attest execution for production provenance"
            )
        if provenance not in self._authorized_provenances:
            raise UntrustedWitnessAuthorityError(
                f"Vault is not authorized to attest execution for {provenance.value}; "
                "caller-owned vault or fixture-scoped vault cannot attest production execution"
            )

        clean_wid = str(witness_id).strip()
        if not clean_wid:
            raise WitnessIntegrityError("witness_id must not be empty")

        # 2. Sealed witness check
        record = self._records.get(clean_wid)
        if record is None:
            if witness_artifacts is not None:
                record = self.seal_witness(
                    witness_id=clean_wid,
                    requirement_id=requirement_id,
                    frozen_contract_digest=frozen_contract_digest,
                    source_commit_id=source_commit_id,
                    artifacts=witness_artifacts,
                )
                effective_witness_digest = record.seal_digest
            else:
                raise UntrustedWitnessAuthorityError(
                    f"Witness ID {clean_wid!r} must be sealed in the trusted vault "
                    "before execution attestation"
                )
        else:
            self.verify_witness_integrity(record)
            if record.requirement_id != requirement_id:
                raise WitnessIntegrityError(
                    f"Witness requirement {record.requirement_id!r} does not match "
                    f"{requirement_id!r}"
                )
            if record.frozen_contract_digest.lower() != frozen_contract_digest.lower():
                raise WitnessIntegrityError(
                    "Witness contract digest does not match execution context"
                )
            if record.source_commit_id.lower() != source_commit_id.lower():
                raise WitnessIntegrityError(
                    "Witness source commit does not match execution context"
                )
            if witness_digest is not None and witness_digest.lower() != record.seal_digest.lower():
                raise WitnessIntegrityError("witness_digest does not match sealed record")
            effective_witness_digest = record.seal_digest

        # 3. Verifier execution records check
        if base_execution is None or candidate_execution is None:
            raise UntrustedWitnessAuthorityError(
                "attest_execution requires verifier execution records (base_execution and "
                "candidate_execution); direct outcome specification without verifier "
                "execution records is prohibited"
            )

        # 4. Mandatory prior observation lookup (Defect B)
        obs_base = self._observed_executions.get((clean_wid, "BASE"))
        obs_cand = self._observed_executions.get((clean_wid, "CANDIDATE"))
        if obs_base is None or obs_cand is None:
            raise UntrustedWitnessAuthorityError(
                "attest_execution requires pre-existing verifier-observed execution records; "
                "direct registration of caller-supplied execution claims without prior "
                "verifier observation is prohibited"
            )

        obs_cf = None
        if counterfactual_execution is not None or counterfactual_outcome is not None:
            obs_cf = self._observed_executions.get((clean_wid, "COUNTERFACTUAL"))
            if obs_cf is None:
                raise UntrustedWitnessAuthorityError(
                    "attest_execution requires pre-existing verifier-observed execution record "
                    "for COUNTERFACTUAL"
                )

        b_outcome = getattr(base_execution, "outcome", None)
        c_outcome = getattr(candidate_execution, "outcome", None)
        cf_outcome = (
            getattr(counterfactual_execution, "outcome", None)
            if counterfactual_execution is not None
            else None
        )

        if b_outcome is None or not isinstance(b_outcome, WitnessOutcome):
            raise UntrustedWitnessAuthorityError(
                "base_execution must contain a valid WitnessOutcome"
            )
        if c_outcome is None or not isinstance(c_outcome, WitnessOutcome):
            raise UntrustedWitnessAuthorityError(
                "candidate_execution must contain a valid WitnessOutcome"
            )
        if counterfactual_execution is not None and (
            cf_outcome is None or not isinstance(cf_outcome, WitnessOutcome)
        ):
            raise UntrustedWitnessAuthorityError(
                "counterfactual_execution must contain a valid WitnessOutcome"
            )

        # Cross-check base_execution against obs_base
        if b_outcome != obs_base.outcome:
            raise WitnessTamperingError(
                f"Caller-supplied base_execution outcome ({b_outcome}) conflicts with "
                f"observed outcome ({obs_base.outcome})"
            )
        if getattr(base_execution, "sandbox_id", None) != obs_base.sandbox_id:
            raise WitnessTamperingError(
                "base_execution sandbox_id does not match observed execution"
            )
        if getattr(base_execution, "result_digest", None) != obs_base.result_digest:
            raise WitnessTamperingError(
                "base_execution result_digest does not match observed execution"
            )
        if (
            getattr(base_execution, "source_commit_id", "").lower()
            != obs_base.source_commit_id.lower()
        ):
            raise WitnessTamperingError(
                "base_execution source_commit_id does not match observed execution"
            )
        if obs_base.provenance != provenance:
            raise WitnessTamperingError(
                f"Observed base provenance ({obs_base.provenance.value}) does not match "
                f"attestation provenance ({provenance.value})"
            )

        # Cross-check candidate_execution against obs_cand
        if c_outcome != obs_cand.outcome:
            raise WitnessTamperingError(
                f"Caller-supplied candidate_execution outcome ({c_outcome}) conflicts with "
                f"observed outcome ({obs_cand.outcome})"
            )
        if getattr(candidate_execution, "sandbox_id", None) != obs_cand.sandbox_id:
            raise WitnessTamperingError(
                "candidate_execution sandbox_id does not match observed execution"
            )
        if getattr(candidate_execution, "result_digest", None) != obs_cand.result_digest:
            raise WitnessTamperingError(
                "candidate_execution result_digest does not match observed execution"
            )
        if (
            getattr(candidate_execution, "tree_digest", "").lower()
            != obs_cand.candidate_tree_digest.lower()
        ):
            raise WitnessTamperingError(
                "candidate_execution tree_digest does not match observed execution"
            )
        if obs_cand.provenance != provenance:
            raise WitnessTamperingError(
                f"Observed candidate provenance ({obs_cand.provenance.value}) does not match "
                f"attestation provenance ({provenance.value})"
            )

        # Cross-check counterfactual_execution against obs_cf
        if counterfactual_execution is not None and obs_cf is not None:
            if cf_outcome != obs_cf.outcome:
                raise WitnessTamperingError(
                    f"Caller-supplied counterfactual_execution outcome ({cf_outcome}) "
                    f"conflicts with observed outcome ({obs_cf.outcome})"
                )
            if getattr(counterfactual_execution, "sandbox_id", None) != obs_cf.sandbox_id:
                raise WitnessTamperingError(
                    "counterfactual_execution sandbox_id does not match observed execution"
                )
            if getattr(counterfactual_execution, "result_digest", None) != obs_cf.result_digest:
                raise WitnessTamperingError(
                    "counterfactual_execution result_digest does not match observed execution"
                )
            if obs_cf.provenance != provenance:
                raise WitnessTamperingError(
                    "Observed counterfactual provenance does not match attestation provenance"
                )

        # Outcome integrity check against explicitly supplied outcomes
        if base_outcome is not None and base_outcome != b_outcome:
            raise WitnessTamperingError(
                f"Caller-supplied base_outcome ({base_outcome}) conflicts with "
                f"base_execution outcome ({b_outcome})"
            )
        if candidate_outcome is not None and candidate_outcome != c_outcome:
            raise WitnessTamperingError(
                f"Caller-supplied candidate_outcome ({candidate_outcome}) conflicts with "
                f"candidate_execution outcome ({c_outcome})"
            )
        if counterfactual_outcome is not None and counterfactual_outcome != cf_outcome:
            raise WitnessTamperingError(
                f"Caller-supplied counterfactual_outcome ({counterfactual_outcome}) conflicts with "
                f"counterfactual_execution outcome ({cf_outcome})"
            )

        # 5. Build canonical payload and sign
        timestamp = created_at_utc or datetime.now(timezone.utc).isoformat()

        b_sbx = getattr(base_execution, "sandbox_id", "") or (
            obs_base.sandbox_id if obs_base else ""
        )
        c_sbx = getattr(candidate_execution, "sandbox_id", "") or (
            obs_cand.sandbox_id if obs_cand else ""
        )
        cf_sbx = getattr(counterfactual_execution, "sandbox_id", None) or (
            obs_cf.sandbox_id if obs_cf else None
        )

        b_cmd = obs_base.command if obs_base else ""
        c_cmd = obs_cand.command if obs_cand else ""
        eff_cmd = b_cmd or c_cmd or ""

        b_exit = (
            getattr(base_execution, "exit_code", None)
            if base_execution is not None
            else (obs_base.exit_code if obs_base else None)
        )
        c_exit = (
            getattr(candidate_execution, "exit_code", None)
            if candidate_execution is not None
            else (obs_cand.exit_code if obs_cand else None)
        )
        cf_exit = (
            getattr(counterfactual_execution, "exit_code", None)
            if counterfactual_execution is not None
            else (obs_cf.exit_code if obs_cf else None)
        )

        b_term = (
            getattr(base_execution, "termination_status", None)
            if base_execution is not None
            else (obs_base.termination_status if obs_base else None)
        )
        c_term = (
            getattr(candidate_execution, "termination_status", None)
            if candidate_execution is not None
            else (obs_cand.termination_status if obs_cand else None)
        )
        cf_term = (
            getattr(counterfactual_execution, "termination_status", None)
            if counterfactual_execution is not None
            else (obs_cf.termination_status if obs_cf else None)
        )

        b_res_dig = (
            getattr(base_execution, "result_digest", "")
            if base_execution is not None
            else (obs_base.result_digest if obs_base else "")
        )
        c_res_dig = (
            getattr(candidate_execution, "result_digest", "")
            if candidate_execution is not None
            else (obs_cand.result_digest if obs_cand else "")
        )
        cf_res_dig = (
            getattr(counterfactual_execution, "result_digest", None)
            if counterfactual_execution is not None
            else (obs_cf.result_digest if obs_cf else None)
        )

        b_out_dig = (
            getattr(base_execution, "stdout_digest", "")
            if base_execution is not None
            else (obs_base.stdout_digest if obs_base else "")
        )
        b_err_dig = (
            getattr(base_execution, "stderr_digest", "")
            if base_execution is not None
            else (obs_base.stderr_digest if obs_base else "")
        )
        c_out_dig = (
            getattr(candidate_execution, "stdout_digest", "")
            if candidate_execution is not None
            else (obs_cand.stdout_digest if obs_cand else "")
        )
        c_err_dig = (
            getattr(candidate_execution, "stderr_digest", "")
            if candidate_execution is not None
            else (obs_cand.stderr_digest if obs_cand else "")
        )
        cf_out_dig = (
            getattr(counterfactual_execution, "stdout_digest", None)
            if counterfactual_execution is not None
            else (obs_cf.stdout_digest if obs_cf else None)
        )
        cf_err_dig = (
            getattr(counterfactual_execution, "stderr_digest", None)
            if counterfactual_execution is not None
            else (obs_cf.stderr_digest if obs_cf else None)
        )

        b_tree = getattr(base_execution, "tree_digest", "") if base_execution is not None else ""
        cf_tree = (
            getattr(counterfactual_execution, "tree_digest", None)
            if counterfactual_execution is not None
            else None
        )

        payload = build_canonical_execution_attestation_payload(
            requirement_id=requirement_id,
            frozen_contract_digest=frozen_contract_digest,
            witness_id=clean_wid,
            witness_digest=effective_witness_digest,
            source_commit_id=source_commit_id,
            candidate_tree_digest=candidate_tree_digest,
            base_outcome=b_outcome,
            candidate_outcome=c_outcome,
            counterfactual_outcome=cf_outcome,
            transition=transition,
            verdict=verdict,
            provenance=provenance,
            created_at_utc=timestamp,
            execution_command=eff_cmd,
            base_sandbox_id=b_sbx,
            candidate_sandbox_id=c_sbx,
            counterfactual_sandbox_id=cf_sbx,
            base_exit_code=b_exit,
            candidate_exit_code=c_exit,
            counterfactual_exit_code=cf_exit,
            base_termination_status=b_term,
            candidate_termination_status=c_term,
            counterfactual_termination_status=cf_term,
            base_result_digest=b_res_dig,
            candidate_result_digest=c_res_dig,
            counterfactual_result_digest=cf_res_dig,
            base_stdout_digest=b_out_dig,
            base_stderr_digest=b_err_dig,
            candidate_stdout_digest=c_out_dig,
            candidate_stderr_digest=c_err_dig,
            counterfactual_stdout_digest=cf_out_dig,
            counterfactual_stderr_digest=cf_err_dig,
            base_tree_digest=b_tree,
            counterfactual_tree_digest=cf_tree,
        )
        att_digest = compute_attestation_digest(payload)
        vault_sig = hmac.new(
            self._vault_secret, att_digest.encode("utf-8"), hashlib.sha256
        ).hexdigest()

        attestation = VerifierExecutionAttestation(
            requirement_id=requirement_id,
            frozen_contract_digest=frozen_contract_digest,
            witness_id=clean_wid,
            witness_digest=effective_witness_digest,
            source_commit_id=source_commit_id,
            candidate_tree_digest=candidate_tree_digest or "",
            base_outcome=b_outcome,
            candidate_outcome=c_outcome,
            counterfactual_outcome=cf_outcome,
            transition=transition,
            verdict=verdict,
            provenance=provenance,
            attestation_digest=att_digest,
            vault_signature=vault_sig,
            created_at_utc=timestamp,
            is_authoritative=True,
            execution_command=(
                " ".join(str(c) for c in eff_cmd)
                if isinstance(eff_cmd, (list, tuple))
                else str(eff_cmd or "").strip()
            ),
            base_sandbox_id=b_sbx,
            candidate_sandbox_id=c_sbx,
            counterfactual_sandbox_id=cf_sbx,
            base_exit_code=b_exit,
            candidate_exit_code=c_exit,
            counterfactual_exit_code=cf_exit,
            base_termination_status=(
                b_term.value
                if b_term is not None and hasattr(b_term, "value")
                else (str(b_term) if b_term else None)
            ),
            candidate_termination_status=(
                c_term.value
                if c_term is not None and hasattr(c_term, "value")
                else (str(c_term) if c_term else None)
            ),
            counterfactual_termination_status=(
                cf_term.value
                if cf_term is not None and hasattr(cf_term, "value")
                else (str(cf_term) if cf_term else None)
            ),
            base_result_digest=b_res_dig,
            candidate_result_digest=c_res_dig,
            counterfactual_result_digest=cf_res_dig,
            base_stdout_digest=b_out_dig,
            base_stderr_digest=b_err_dig,
            candidate_stdout_digest=c_out_dig,
            candidate_stderr_digest=c_err_dig,
            counterfactual_stdout_digest=cf_out_dig,
            counterfactual_stderr_digest=cf_err_dig,
            base_tree_digest=b_tree,
            counterfactual_tree_digest=cf_tree,
        )

        self._registered_executions[requirement_id] = attestation
        return attestation

    def verify_execution_authority(
        self,
        *,
        receipt_or_attestation: VerifierExecutionAttestation | Any | None = None,
        receipt: Any | None = None,
        expected_requirement_id: str | None = None,
        expected_contract_digest: str | None = None,
        expected_source_commit_id: str | None = None,
        expected_candidate_tree_digest: str | None = None,
        requirement_id: str | None = None,
        frozen_contract_digest: str | None = None,
        source_commit_id: str | None = None,
        candidate_tree_digest: str | None = None,
        witness_id: str | None = None,
        base_execution: Any | None = None,
        candidate_execution: Any | None = None,
        counterfactual_execution: Any | None = None,
        transition: Any | None = None,
        verdict: PreliminaryVerdict | None = None,
        provenance: EvidenceProvenance | None = None,
        attestation: VerifierExecutionAttestation | None = None,
    ) -> bool:
        """Mechanically verify that reported execution facts carry genuine vault authority.

        Fail-closed rules:
        1. Authority Root: Vault must be authorized for the specified provenance.
        2. Attestation Present: Must be a genuine VerifierExecutionAttestation.
        3. Registered Execution: Must be actually registered in this vault.
        4. HMAC Signature: Must match vault private secret.
        5. Attestation Digest: Recomputed payload must match attestation digest.
        6. Sealed Witness: Witness must be sealed in this vault with matching digests.
        7. Observed Executions: Pre-existing verifier-observed executions are mandatory.
        8. Context Bindings: requirement_id, contract_digest, source_commit, tree match.
        9. Exact Provenance Equality: Attestation provenance must exactly match expected
           provenance and receipt provenance. Promotion is strictly rejected.
        10. Receipt Cross-Binding: No claim-to-attestation drift or tampering permitted.
        """
        # 1. Authority root check
        if not self._authorized_provenances:
            return False
        if provenance is not None and provenance not in self._authorized_provenances:
            return False

        # 2. Extract attestation and receipt
        lookup_id = requirement_id or expected_requirement_id or ""
        is_att = isinstance(receipt_or_attestation, VerifierExecutionAttestation)
        effective_receipt: Any | None = (
            receipt if receipt is not None else (receipt_or_attestation if not is_att else None)
        )
        receipt = effective_receipt
        att: VerifierExecutionAttestation | None = None

        if isinstance(receipt_or_attestation, VerifierExecutionAttestation):
            att = receipt_or_attestation
        elif receipt is not None:
            att = getattr(receipt, "attestation", None)

        if att is None:
            att = attestation or self._registered_executions.get(lookup_id)

        if att is None or not isinstance(att, VerifierExecutionAttestation):
            return False

        # Production execution claims (LOCAL_EXECUTION, LIVE_NEBIUS, RECORDED_LIVE)
        # are independently verified against the trusted verifier authority root.
        # Direct in-process vault mutation cannot confer production authority.
        if att.provenance in (
            EvidenceProvenance.LOCAL_EXECUTION,
            EvidenceProvenance.LIVE_NEBIUS,
            EvidenceProvenance.RECORDED_LIVE,
        ):
            from basebreak.verifier.trust_bridge import verify_trusted_production_evidence

            return verify_trusted_production_evidence(
                receipt=receipt,
                attestation=att,
                expected_requirement_id=expected_requirement_id,
                expected_contract_digest=expected_contract_digest,
                expected_provenance=provenance,
                verifier_authority=self,
            )

        if att.provenance not in self._authorized_provenances:
            return False

        # 3. Check actual registration in vault
        reg = self._registered_executions.get(att.requirement_id)
        if reg is None:
            return False
        if not hmac.compare_digest(att.vault_signature, reg.vault_signature):
            return False
        if att.attestation_digest != reg.attestation_digest:
            return False

        # 4. HMAC signature verification against this vault's private secret
        expected_sig = hmac.new(
            self._vault_secret, att.attestation_digest.encode("utf-8"), hashlib.sha256
        ).hexdigest()
        if not hmac.compare_digest(att.vault_signature, expected_sig):
            return False

        # 5. Recompute attestation digest from canonical payload
        payload = build_canonical_execution_attestation_payload(
            requirement_id=att.requirement_id,
            frozen_contract_digest=att.frozen_contract_digest,
            witness_id=att.witness_id,
            witness_digest=att.witness_digest,
            source_commit_id=att.source_commit_id,
            candidate_tree_digest=att.candidate_tree_digest,
            base_outcome=att.base_outcome,
            candidate_outcome=att.candidate_outcome,
            counterfactual_outcome=att.counterfactual_outcome,
            transition=att.transition,
            verdict=att.verdict,
            provenance=att.provenance,
            created_at_utc=att.created_at_utc,
            issuer_id=att.issuer_id,
            execution_origin=att.execution_origin,
            execution_command=att.execution_command,
            base_sandbox_id=att.base_sandbox_id,
            candidate_sandbox_id=att.candidate_sandbox_id,
            counterfactual_sandbox_id=att.counterfactual_sandbox_id,
            base_exit_code=att.base_exit_code,
            candidate_exit_code=att.candidate_exit_code,
            counterfactual_exit_code=att.counterfactual_exit_code,
            base_termination_status=att.base_termination_status,
            candidate_termination_status=att.candidate_termination_status,
            counterfactual_termination_status=att.counterfactual_termination_status,
            base_result_digest=att.base_result_digest,
            candidate_result_digest=att.candidate_result_digest,
            counterfactual_result_digest=att.counterfactual_result_digest,
            base_stdout_digest=att.base_stdout_digest,
            base_stderr_digest=att.base_stderr_digest,
            candidate_stdout_digest=att.candidate_stdout_digest,
            candidate_stderr_digest=att.candidate_stderr_digest,
            counterfactual_stdout_digest=att.counterfactual_stdout_digest,
            counterfactual_stderr_digest=att.counterfactual_stderr_digest,
            base_tree_digest=att.base_tree_digest,
            counterfactual_tree_digest=att.counterfactual_tree_digest,
        )
        if att.attestation_digest != compute_attestation_digest(payload):
            return False

        # 6. Check sealed witness in vault
        rec = self._records.get(att.witness_id)
        if rec is None:
            return False
        if att.witness_digest.lower() != rec.seal_digest.lower():
            return False
        if att.requirement_id != rec.requirement_id:
            return False
        if att.frozen_contract_digest.lower() != rec.frozen_contract_digest.lower():
            return False
        if att.source_commit_id.lower() != rec.source_commit_id.lower():
            return False

        # 7. Check observed executions in vault (MANDATORY prior observation)
        obs_base = self._observed_executions.get((att.witness_id, "BASE"))
        obs_cand = self._observed_executions.get((att.witness_id, "CANDIDATE"))
        if obs_base is None or obs_cand is None:
            return False
        if obs_base.outcome != att.base_outcome:
            return False
        if obs_cand.outcome != att.candidate_outcome:
            return False
        if obs_base.provenance != att.provenance:
            return False
        if obs_cand.provenance != att.provenance:
            return False

        if att.counterfactual_outcome is not None:
            obs_cf = self._observed_executions.get((att.witness_id, "COUNTERFACTUAL"))
            if obs_cf is None:
                return False
            if obs_cf.outcome != att.counterfactual_outcome:
                return False
            if obs_cf.provenance != att.provenance:
                return False

        # 8. Check factual bindings against execution context
        req_id = expected_requirement_id or requirement_id
        if req_id and att.requirement_id != req_id:
            return False

        cd = expected_contract_digest or frozen_contract_digest
        if cd and att.frozen_contract_digest.lower() != cd.lower():
            return False

        sc = expected_source_commit_id or source_commit_id
        if sc and att.source_commit_id.lower() != sc.lower():
            return False

        ct = expected_candidate_tree_digest or candidate_tree_digest
        if ct and att.candidate_tree_digest.lower() != ct.lower():
            return False

        if witness_id and att.witness_id != str(witness_id).strip():
            return False

        # Check transition if specified
        if transition is not None:
            trans_val = transition.value if hasattr(transition, "value") else str(transition)
            att_t = att.transition
            att_trans = att_t.value if hasattr(att_t, "value") else str(att_t)
            if att_trans != trans_val:
                return False

        # Check verdict
        if verdict is not None:
            v_val = verdict.value if hasattr(verdict, "value") else str(verdict)
            att_v = att.verdict.value if hasattr(att.verdict, "value") else str(att.verdict)
            if att_v != v_val:
                return False
        else:
            att_v = att.verdict.value if hasattr(att.verdict, "value") else str(att.verdict)
            if att_v != "VERIFIED":
                return False

        # Check outcomes if execution objects provided
        if base_execution is not None:
            b_out = getattr(base_execution, "outcome", base_execution)
            if att.base_outcome != b_out:
                return False
        if candidate_execution is not None:
            c_out = getattr(candidate_execution, "outcome", candidate_execution)
            if att.candidate_outcome != c_out:
                return False
        if counterfactual_execution is not None:
            cf_out = getattr(counterfactual_execution, "outcome", counterfactual_execution)
            if att.counterfactual_outcome != cf_out:
                return False

        # 9. Exact provenance equality check
        if provenance is not None:
            p_val = (
                provenance
                if isinstance(provenance, EvidenceProvenance)
                else EvidenceProvenance(str(provenance))
            )
            if att.provenance != p_val:
                return False

        # 10. Exact cross-binding with receipt
        if receipt is not None:
            # Requirement binding
            r_req = getattr(receipt, "requirement_id", None)
            if r_req is not None and r_req != att.requirement_id:
                return False

            # Contract binding
            r_cd = getattr(receipt, "frozen_contract_digest", None)
            if r_cd is not None and r_cd.lower() != att.frozen_contract_digest.lower():
                return False

            # Witness binding
            r_wid = getattr(receipt, "witness_id", None)
            if r_wid is not None and r_wid != att.witness_id:
                return False
            r_wdig = getattr(receipt, "witness_digest", None)
            if r_wdig is not None and r_wdig.lower() != att.witness_digest.lower():
                return False

            # Exact provenance equality
            r_prov = getattr(receipt, "provenance", None)
            if r_prov is not None:
                r_p = (
                    r_prov
                    if isinstance(r_prov, EvidenceProvenance)
                    else EvidenceProvenance(str(r_prov))
                )
                if r_p != att.provenance:
                    return False

            # Transition equality
            r_trans = getattr(receipt, "transition", None)
            if r_trans is not None:
                r_t_str = r_trans.value if hasattr(r_trans, "value") else str(r_trans)
                a_t_str = (
                    att.transition.value
                    if hasattr(att.transition, "value")
                    else str(att.transition)
                )
                if r_t_str != a_t_str:
                    return False

            # Verdict equality
            r_verd = getattr(receipt, "verdict", None)
            if r_verd is not None:
                r_v_str = r_verd.value if hasattr(r_verd, "value") else str(r_verd)
                a_v_str = att.verdict.value if hasattr(att.verdict, "value") else str(att.verdict)
                if r_v_str != a_v_str:
                    return False

            # Source commit equality
            r_sc = getattr(receipt, "source_commit_id", None)
            if (
                r_sc is None
                and hasattr(receipt, "base_execution")
                and receipt.base_execution is not None
            ):
                r_sc = getattr(receipt.base_execution, "source_commit_id", None)
            if r_sc and r_sc.lower() != att.source_commit_id.lower():
                return False

            # Candidate tree equality
            r_ct = getattr(receipt, "candidate_tree_digest", None)
            if (
                r_ct is None
                and hasattr(receipt, "candidate_execution")
                and receipt.candidate_execution is not None
            ):
                r_ct = getattr(receipt.candidate_execution, "tree_digest", None)
            if (
                r_ct
                and att.candidate_tree_digest
                and r_ct.lower() != att.candidate_tree_digest.lower()
            ):
                return False

            # Outcomes and execution facts cross-bindings
            r_base = getattr(receipt, "base_execution", None)
            if r_base is not None:
                if getattr(r_base, "outcome", None) != att.base_outcome:
                    return False
                if getattr(r_base, "sandbox_id", None) != obs_base.sandbox_id:
                    return False
                if getattr(r_base, "result_digest", None) != obs_base.result_digest:
                    return False

            r_cand = getattr(receipt, "candidate_execution", None)
            if r_cand is not None:
                if getattr(r_cand, "outcome", None) != att.candidate_outcome:
                    return False
                if getattr(r_cand, "sandbox_id", None) != obs_cand.sandbox_id:
                    return False
                if getattr(r_cand, "result_digest", None) != obs_cand.result_digest:
                    return False

            r_cf = getattr(receipt, "counterfactual_execution", None)
            if r_cf is not None and att.counterfactual_outcome is not None:
                obs_cf_record = self._observed_executions.get((att.witness_id, "COUNTERFACTUAL"))
                if obs_cf_record is None:
                    return False
                if getattr(r_cf, "outcome", None) != att.counterfactual_outcome:
                    return False
                if getattr(r_cf, "sandbox_id", None) != obs_cf_record.sandbox_id:
                    return False
                if getattr(r_cf, "result_digest", None) != obs_cf_record.result_digest:
                    return False
            if r_cf is None and att.counterfactual_outcome is not None:
                return False

        return True

    def get_attestation(self, requirement_id: str) -> VerifierExecutionAttestation:
        """Look up an execution attestation by requirement ID."""
        att = self._registered_executions.get(requirement_id)
        if att is None:
            raise KeyError(
                f"No execution attestation registered for requirement {requirement_id!r}"
            )
        return att

    def list_attested_requirement_ids(self) -> tuple[str, ...]:
        """Return canonically sorted tuple of requirement IDs with registered attestations."""
        return tuple(sorted(self._registered_executions.keys()))


__all__ = [
    "SealedWitnessRecord",
    "TrustedWitnessVault",
    "UntrustedWitnessAuthorityError",
    "VerifierExecutionAttestation",
    "WitnessArtifact",
    "WitnessIntegrityError",
    "WitnessPathSecurityError",
    "WitnessProtectedSurfaceCollisionError",
    "WitnessSecretError",
    "WitnessTamperingError",
    "build_canonical_execution_attestation_payload",
    "build_canonical_witness_identity_payload",
    "compute_attestation_digest",
    "compute_seal_digest",
]
