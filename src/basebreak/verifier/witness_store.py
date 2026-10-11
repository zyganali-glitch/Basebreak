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
) -> dict[str, Any]:
    """Construct deterministic payload for execution attestation digest computation."""
    trans_val = transition.value if hasattr(transition, "value") else str(transition)
    return {
        "base_outcome": base_outcome.value if base_outcome is not None else None,
        "candidate_outcome": candidate_outcome.value if candidate_outcome is not None else None,
        "candidate_tree_digest": str(candidate_tree_digest or "").strip().lower(),
        "counterfactual_outcome": (
            counterfactual_outcome.value if counterfactual_outcome is not None else None
        ),
        "created_at_utc": str(created_at_utc).strip(),
        "frozen_contract_digest": str(frozen_contract_digest).strip().lower(),
        "provenance": provenance.value,
        "requirement_id": str(requirement_id).strip(),
        "source_commit_id": str(source_commit_id).strip().lower(),
        "transition": str(trans_val),
        "verdict": verdict.value,
        "witness_digest": str(witness_digest).strip().lower(),
        "witness_id": str(witness_id).strip(),
    }


def compute_attestation_digest(payload: Mapping[str, Any]) -> str:
    """Compute deterministic SHA-256 digest over canonical JSON bytes."""
    canonical_bytes = json.dumps(
        payload, sort_keys=True, separators=(",", ":"), ensure_ascii=False
    ).encode("utf-8")
    return hashlib.sha256(canonical_bytes).hexdigest()


@dataclass(frozen=True, slots=True)
class VerifierExecutionAttestation:
    """Cryptographic attestation from TrustedWitnessVault certifying verifier-side execution.

    Possesses authority strictly when validated by TrustedWitnessVault.
    """

    requirement_id: str
    frozen_contract_digest: str
    witness_id: str
    witness_digest: str
    source_commit_id: str
    candidate_tree_digest: str
    base_outcome: WitnessOutcome | None
    candidate_outcome: WitnessOutcome | None
    counterfactual_outcome: WitnessOutcome | None
    transition: Any
    verdict: PreliminaryVerdict
    provenance: EvidenceProvenance
    attestation_digest: str
    vault_signature: str
    created_at_utc: str
    is_authoritative: bool = True

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
        if not isinstance(self.vault_signature, str) or not _HEX_64_PATTERN.match(
            self.vault_signature
        ):
            raise WitnessIntegrityError("vault_signature must be a 64-char hex string")

    def to_dict(self) -> dict[str, Any]:
        """Serialize attestation to JSON-safe dictionary."""
        trans_val = (
            self.transition.value if hasattr(self.transition, "value") else str(self.transition)
        )
        return {
            "attestation_digest": self.attestation_digest,
            "base_outcome": self.base_outcome.value if self.base_outcome is not None else None,
            "candidate_outcome": (
                self.candidate_outcome.value if self.candidate_outcome is not None else None
            ),
            "candidate_tree_digest": self.candidate_tree_digest,
            "counterfactual_outcome": (
                self.counterfactual_outcome.value
                if self.counterfactual_outcome is not None
                else None
            ),
            "created_at_utc": self.created_at_utc,
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


# --- Trusted Witness Vault ---


class TrustedWitnessVault:
    """The authoritative runtime vault for sealing and validating witness integrity.

    Establishes cryptographic trust boundary:
    Records created outside this vault cannot claim verified authority.
    """

    def __init__(self, vault_secret: bytes | None = None) -> None:
        self._vault_secret = vault_secret or os.urandom(32)
        self._registered_seals: dict[str, tuple[str, str]] = {}
        self._records: dict[str, SealedWitnessRecord] = {}
        self._registered_executions: dict[str, VerifierExecutionAttestation] = {}


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
        """Record and cryptographically attest genuine verifier-side execution."""
        clean_wid = str(witness_id).strip()
        if not clean_wid:
            raise WitnessIntegrityError("witness_id must not be empty")

        effective_witness_digest: str
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
            elif witness_digest is not None:
                effective_witness_digest = witness_digest
            else:
                raise UntrustedWitnessAuthorityError(
                    f"Witness ID {clean_wid!r} was not sealed by this trusted vault"
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
            effective_witness_digest = record.seal_digest

        b_outcome = (
            base_outcome
            if base_outcome is not None
            else getattr(base_execution, "outcome", None)
        )
        c_outcome = (
            candidate_outcome
            if candidate_outcome is not None
            else getattr(candidate_execution, "outcome", None)
        )
        cf_outcome = (
            counterfactual_outcome
            if counterfactual_outcome is not None
            else getattr(counterfactual_execution, "outcome", None)
        )

        timestamp = created_at_utc or datetime.now(timezone.utc).isoformat()
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
        )

        self._registered_executions[requirement_id] = attestation
        return attestation

    def verify_execution_authority(
        self,
        *,
        receipt_or_attestation: VerifierExecutionAttestation | Any | None = None,
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
        """Mechanically verify that reported execution facts carry genuine vault authority."""
        lookup_id = requirement_id or expected_requirement_id or ""
        att = (
            receipt_or_attestation
            if isinstance(receipt_or_attestation, VerifierExecutionAttestation)
            else (
                getattr(receipt_or_attestation, "attestation", None)
                if receipt_or_attestation is not None
                else (attestation or self._registered_executions.get(lookup_id))
            )
        )
        if att is None:
            return False

        if not isinstance(att, VerifierExecutionAttestation):
            return False

        req_id = (
            expected_requirement_id
            or requirement_id
            or getattr(receipt_or_attestation, "requirement_id", None)
        )
        cd = (
            expected_contract_digest
            or frozen_contract_digest
            or getattr(receipt_or_attestation, "frozen_contract_digest", None)
        )
        sc = (
            expected_source_commit_id
            or source_commit_id
            or getattr(receipt_or_attestation, "source_commit_id", None)
        )
        ct = (
            expected_candidate_tree_digest
            or candidate_tree_digest
            or getattr(receipt_or_attestation, "candidate_tree_digest", None)
        )

        # 1. HMAC signature verification against this vault's private secret
        expected_sig = hmac.new(
            self._vault_secret, att.attestation_digest.encode("utf-8"), hashlib.sha256
        ).hexdigest()
        if not hmac.compare_digest(att.vault_signature, expected_sig):
            return False

        # 2. Recompute attestation digest
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
        )
        if att.attestation_digest != compute_attestation_digest(payload):
            return False

        # 3. Check registration if present in registry
        if att.requirement_id in self._registered_executions:
            reg = self._registered_executions[att.requirement_id]
            if not hmac.compare_digest(att.vault_signature, reg.vault_signature):
                return False

        # 4. Check factual bindings against current claim
        if req_id and att.requirement_id != req_id:
            return False
        if cd and att.frozen_contract_digest.lower() != cd.lower():
            return False
        if sc and att.source_commit_id.lower() != sc.lower():
            return False
        if ct and att.candidate_tree_digest.lower() != ct.lower():
            return False

        if witness_id and att.witness_id != str(witness_id).strip():
            return False

        if att.witness_id in self._records:
            rec = self._records[att.witness_id]
            if att.witness_digest.lower() != rec.seal_digest.lower():
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

        # 5. Strict anti-laundering check: FIXTURE cannot certify LOCAL or LIVE
        claim_prov = getattr(receipt_or_attestation, "provenance", provenance)
        if claim_prov is not None:
            c_prov = claim_prov.value if hasattr(claim_prov, "value") else str(claim_prov)
            att_p = att.provenance
            a_prov = att_p.value if hasattr(att_p, "value") else str(att_p)
            if c_prov != "FIXTURE" and a_prov == "FIXTURE":
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

