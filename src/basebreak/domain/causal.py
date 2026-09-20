"""Witness, candidate, counterfactual, and causal binding domain contracts.

Defines provider-neutral immutable abstractions binding engineering requirements,
independent witnesses, exact candidates, and execution worlds.
"""

from __future__ import annotations

import hashlib
from dataclasses import dataclass
from enum import Enum

from basebreak.domain.source import SourceIdentity

_HEX_CHARS = frozenset("0123456789abcdef")


def _validate_hex_digest(digest: str, field_name: str) -> None:
    """Validate a 40 or 64 character lowercase hexadecimal digest."""
    if not isinstance(digest, str):
        tname = type(digest).__name__
        raise TypeError(f"{field_name} must be a string, got {tname}")
    if not digest:
        raise ValueError(f"{field_name} must not be empty")
    if digest.strip() != digest:
        raise ValueError(f"{field_name} must not contain leading or trailing whitespace")
    if len(digest) not in (40, 64):
        raise ValueError(
            f"{field_name} must be a 40 or 64-character hexadecimal string, "
            f"got {digest!r} (length {len(digest)})"
        )
    if not set(digest).issubset(_HEX_CHARS):
        raise ValueError(
            f"{field_name} must consist strictly of lowercase hexadecimal characters [0-9a-f], "
            f"got {digest!r}"
        )


def _validate_identifier(value: str, field_name: str) -> None:
    """Validate a non-empty stripped identifier string."""
    if not isinstance(value, str):
        tname = type(value).__name__
        raise TypeError(f"{field_name} must be a string, got {tname}")
    cleaned = value.strip()
    if not cleaned:
        raise ValueError(f"{field_name} must not be empty")
    if cleaned != value:
        raise ValueError(f"{field_name} must not contain leading or trailing whitespace")


@dataclass(frozen=True, slots=True)
class WitnessIdentity:
    """Immutable witness identity.

    Identifies an independent witness (behavioral check/test) by an explicit identifier
    and cryptographic digest of its contents/logic. Mutable names or prose cannot substitute
    for witness identity. Witness identity remains distinct from runtime result/verdict.
    """

    witness_id: str
    digest: str
    description: str = ""

    def __post_init__(self) -> None:
        _validate_identifier(self.witness_id, "witness_id")
        _validate_hex_digest(self.digest, "digest")
        if not isinstance(self.description, str):
            tname = type(self.description).__name__
            raise TypeError(f"description must be a string, got {tname}")

    def __str__(self) -> str:
        return f"{self.witness_id}@{self.digest[:8]}"


@dataclass(frozen=True, slots=True)
class CandidateIdentity:
    """Immutable candidate identity bound to exact source identity and revision.

    Reuses SourceIdentity and CommitRevision to ensure evidence authoritatively binds
    to exact resolved commits rather than mutable branch names, workspace paths, or
    Builder prose.
    """

    candidate_id: str
    source: SourceIdentity
    patch_digest: str | None = None
    description: str = ""

    def __post_init__(self) -> None:
        _validate_identifier(self.candidate_id, "candidate_id")
        if not isinstance(self.source, SourceIdentity):
            tname = type(self.source).__name__
            raise TypeError(f"source must be an instance of SourceIdentity, got {tname}")
        if self.patch_digest is not None:
            _validate_hex_digest(self.patch_digest, "patch_digest")
        if not isinstance(self.description, str):
            tname = type(self.description).__name__
            raise TypeError(f"description must be a string, got {tname}")

    @property
    def resolved_commit_id(self) -> str:
        """Authoritative resolved commit identity of the candidate."""
        return self.source.resolved_commit_id

    def __str__(self) -> str:
        return f"{self.candidate_id} ({self.source.locator}@{self.resolved_commit_id[:8]})"


class ExecutionWorld(str, Enum):
    """Canonical execution worlds for causal verification.

    Explicitly distinguishes the trusted baseline, candidate patch, and counterfactual
    perturbation runs. These worlds must never collapse into an ambiguous string or boolean.
    """

    BASE = "BASE"
    CANDIDATE = "CANDIDATE"
    COUNTERFACTUAL = "COUNTERFACTUAL"


@dataclass(frozen=True, slots=True)
class CounterfactualIdentity:
    """Immutable counterfactual identity distinct from candidate identity.

    Identifies a counterfactual world (e.g. candidate with relevant patch delta removed)
    relative to a specific candidate, without assuming git revert, checkpoint, or snapshot
    mechanisms.
    """

    counterfactual_id: str
    target_candidate: CandidateIdentity
    delta_digest: str | None = None
    description: str = ""

    def __post_init__(self) -> None:
        _validate_identifier(self.counterfactual_id, "counterfactual_id")
        if not isinstance(self.target_candidate, CandidateIdentity):
            tname = type(self.target_candidate).__name__
            raise TypeError(f"target_candidate must be CandidateIdentity, got {tname}")
        if self.delta_digest is not None:
            _validate_hex_digest(self.delta_digest, "delta_digest")
        if not isinstance(self.description, str):
            tname = type(self.description).__name__
            raise TypeError(f"description must be a string, got {tname}")

    def __str__(self) -> str:
        return f"{self.counterfactual_id} (target: {self.target_candidate.candidate_id})"


@dataclass(frozen=True, slots=True)
class CausalBinding:
    """Deterministic causal binding between acceptance requirement, witness, worlds, and sources.

    Binds:
    - requirement_id: immutable requirement identifier
    - witness: immutable WitnessIdentity
    - base_source: trusted BASE SourceIdentity
    - candidate: exact CANDIDATE CandidateIdentity
    - world: explicit ExecutionWorld
    - counterfactual: CounterfactualIdentity when world is COUNTERFACTUAL; None otherwise

    Enforces that:
    - world == COUNTERFACTUAL requires a non-None counterfactual targeting candidate;
    - world != COUNTERFACTUAL forbids counterfactual from being attached;
    - exact types are strictly checked;
    - candidate/source substitution is observable and rejected.
    """

    requirement_id: str
    witness: WitnessIdentity
    base_source: SourceIdentity
    candidate: CandidateIdentity
    world: ExecutionWorld
    counterfactual: CounterfactualIdentity | None = None

    def __post_init__(self) -> None:
        _validate_identifier(self.requirement_id, "requirement_id")
        if not isinstance(self.witness, WitnessIdentity):
            tname = type(self.witness).__name__
            raise TypeError(f"witness must be WitnessIdentity, got {tname}")
        if not isinstance(self.base_source, SourceIdentity):
            tname = type(self.base_source).__name__
            raise TypeError(f"base_source must be SourceIdentity, got {tname}")
        if not isinstance(self.candidate, CandidateIdentity):
            tname = type(self.candidate).__name__
            raise TypeError(f"candidate must be CandidateIdentity, got {tname}")
        if not isinstance(self.world, ExecutionWorld):
            tname = type(self.world).__name__
            raise TypeError(f"world must be ExecutionWorld, got {tname}")

        if self.world == ExecutionWorld.COUNTERFACTUAL:
            if self.counterfactual is None:
                raise ValueError(
                    "counterfactual identity is required when execution world is COUNTERFACTUAL"
                )
            if not isinstance(self.counterfactual, CounterfactualIdentity):
                tname = type(self.counterfactual).__name__
                raise TypeError(f"counterfactual must be CounterfactualIdentity, got {tname}")
            if self.counterfactual.target_candidate != self.candidate:
                raise ValueError(
                    "counterfactual.target_candidate must match candidate in causal binding"
                )
        else:
            if self.counterfactual is not None:
                raise ValueError(
                    f"counterfactual must be None when execution world is {self.world.value}"
                )

    @property
    def binding_digest(self) -> str:
        """Deterministic SHA-256 fingerprint of the bound immutable causal facts."""
        hasher = hashlib.sha256()
        hasher.update(self.requirement_id.encode("utf-8"))
        hasher.update(b":")
        hasher.update(self.witness.witness_id.encode("utf-8"))
        hasher.update(b":")
        hasher.update(self.witness.digest.encode("utf-8"))
        hasher.update(b":")
        hasher.update(self.base_source.locator.encode("utf-8"))
        hasher.update(b":")
        hasher.update(self.base_source.resolved_commit_id.encode("utf-8"))
        hasher.update(b":")
        hasher.update(self.candidate.candidate_id.encode("utf-8"))
        hasher.update(b":")
        hasher.update(self.candidate.source.locator.encode("utf-8"))
        hasher.update(b":")
        hasher.update(self.candidate.source.resolved_commit_id.encode("utf-8"))
        hasher.update(b":")
        hasher.update((self.candidate.patch_digest or "").encode("utf-8"))
        hasher.update(b":")
        hasher.update(self.world.value.encode("utf-8"))
        hasher.update(b":")
        cf_id = self.counterfactual.counterfactual_id if self.counterfactual else ""
        hasher.update(cf_id.encode("utf-8"))
        return hasher.hexdigest()
