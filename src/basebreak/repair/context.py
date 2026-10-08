"""Fresh controlled Builder repair context contracts and envelopes.

P-14.03: Re-enter Builder in fresh/controlled repair context.

Core Invariants:
1. Strict separation: Builder repair context is decoupled from verifier sandbox and
   workspace state. Passing verifier workspace paths or verifier state fails closed.
2. Narrow input boundary: Repair context carries only:
   - authoritative contract digest & requirement identity
   - exact parent candidate identity, tree digest, patch digest, and patch text
   - bounded sanitized SafeRepairFeedback
   - permitted edit paths (non-protected, non-verifier)
   - repair round and budget bounds
3. Feedback-to-candidate binding: Repair feedback must match parent candidate ID,
   requirement ID, change class, and repair round; mismatched or foreign feedback fails closed.
4. Cryptographic context digest: canonical SHA-256 context digest binds all repair inputs.
5. Zero verdict authority: is_authoritative = False strictly enforced.
"""

from __future__ import annotations

import hashlib
import json
import re
from collections.abc import Mapping, Sequence
from dataclasses import dataclass
from typing import Any

from basebreak.domain.semantics import ChangeClass
from basebreak.domain.source import SourceIdentity
from basebreak.evidence.artifact import compute_bytes_digest
from basebreak.repair.feedback import (
    RepairFeedbackError,
    SafeRepairFeedback,
    verify_repair_feedback_integrity,
)
from basebreak.repair.sanitizer import (
    VERIFIER_INTERNAL_PATH_PATTERNS,
)
from basebreak.security.protected_surfaces import (
    get_canonical_basebreak_protected_manifest,
    is_path_protected,
    normalize_repo_path,
)
from basebreak.security.secret_policy import contains_secret

BUILDER_REPAIR_CONTEXT_SCHEMA_VERSION: str = "1.0.0"

_HEX_40_OR_64_PATTERN = re.compile(r"^([0-9a-f]{40}|[0-9a-f]{64})$")
_HEX_64_PATTERN = re.compile(r"^[0-9a-f]{64}$")


class BuilderRepairContextError(RepairFeedbackError):
    """Base exception for Builder repair context errors."""


class RepairContextMismatchedCandidateError(BuilderRepairContextError):
    """Raised when feedback candidate ID does not match parent candidate ID."""


class RepairContextMismatchedContractError(BuilderRepairContextError):
    """Raised when feedback requirement or contract facts do not match context."""


class RepairContextBudgetExceededError(BuilderRepairContextError):
    """Raised when repair round exceeds max repair rounds."""


class RepairContextProtectedSurfaceError(BuilderRepairContextError):
    """Raised when permitted paths include protected or verifier surfaces."""


class VerifierStateLeakError(BuilderRepairContextError):
    """Raised when verifier internal state or workspace paths are leaked into repair context."""


class RepairContextTamperingError(BuilderRepairContextError):
    """Raised when repair context facts do not match the cryptographic context digest."""


def _validate_non_empty_str(val: str, field_name: str) -> None:
    if not isinstance(val, str):
        raise TypeError(f"{field_name} must be str, got {type(val).__name__}")
    if not val.strip():
        raise BuilderRepairContextError(f"{field_name} must not be empty or whitespace-only")


def _validate_hex_digest(digest: str, field_name: str, allow_40: bool = False) -> None:
    _validate_non_empty_str(digest, field_name)
    pat = _HEX_40_OR_64_PATTERN if allow_40 else _HEX_64_PATTERN
    if not pat.match(digest):
        expected = "40 or 64" if allow_40 else "64"
        raise BuilderRepairContextError(
            f"{field_name} must be a {expected} hex character string, got {digest!r}"
        )


@dataclass(frozen=True, slots=True)
class BuilderRepairContextEnvelope:
    """Deterministic context envelope provided to Builder for a fresh repair attempt."""

    repair_context_id: str
    parent_candidate_id: str
    parent_candidate_tree_digest: str
    parent_patch_digest: str
    parent_patch_text: str
    source_identity: SourceIdentity
    frozen_contract_digest: str
    requirement_id: str
    change_class: ChangeClass
    repair_feedback: SafeRepairFeedback
    permitted_paths: tuple[str, ...]
    repair_round: int
    max_repair_rounds: int
    repair_context_digest: str
    schema_version: str = BUILDER_REPAIR_CONTEXT_SCHEMA_VERSION
    is_authoritative: bool = False

    def __post_init__(self) -> None:
        _validate_non_empty_str(self.repair_context_id, "repair_context_id")
        _validate_non_empty_str(self.parent_candidate_id, "parent_candidate_id")
        _validate_hex_digest(
            self.parent_candidate_tree_digest, "parent_candidate_tree_digest", allow_40=True
        )
        _validate_hex_digest(self.parent_patch_digest, "parent_patch_digest")
        if not isinstance(self.parent_patch_text, str):
            raise TypeError(
                f"parent_patch_text must be str, got {type(self.parent_patch_text).__name__}"
            )
        if not isinstance(self.source_identity, SourceIdentity):
            raise TypeError(
                f"source_identity must be SourceIdentity, got {type(self.source_identity).__name__}"
            )
        _validate_hex_digest(self.frozen_contract_digest, "frozen_contract_digest")
        _validate_non_empty_str(self.requirement_id, "requirement_id")
        if not isinstance(self.change_class, ChangeClass):
            raise TypeError(
                f"change_class must be ChangeClass, got {type(self.change_class).__name__}"
            )
        if not isinstance(self.repair_feedback, SafeRepairFeedback):
            fb_type = type(self.repair_feedback).__name__
            raise TypeError(f"repair_feedback must be SafeRepairFeedback, got {fb_type}")

        if not isinstance(self.permitted_paths, tuple):
            if isinstance(self.permitted_paths, Sequence):
                object.__setattr__(self, "permitted_paths", tuple(self.permitted_paths))
            else:
                p_type = type(self.permitted_paths).__name__
                raise TypeError(f"permitted_paths must be a sequence of strings, got {p_type}")

        if not self.permitted_paths:
            raise BuilderRepairContextError("permitted_paths must not be empty")

        if not isinstance(self.repair_round, int) or self.repair_round < 1:
            raise BuilderRepairContextError(
                f"repair_round must be a positive integer, got {self.repair_round!r}"
            )
        if not isinstance(self.max_repair_rounds, int) or self.max_repair_rounds < 1:
            raise BuilderRepairContextError(
                f"max_repair_rounds must be a positive integer, got {self.max_repair_rounds!r}"
            )
        if self.repair_round > self.max_repair_rounds:
            cur = self.repair_round
            max_r = self.max_repair_rounds
            raise RepairContextBudgetExceededError(
                f"repair_round {cur} exceeds max_repair_rounds {max_r}"
            )

        _validate_hex_digest(self.repair_context_digest, "repair_context_digest")

        # 1. Feedback-to-candidate consistency checks
        if self.repair_feedback.candidate_id != self.parent_candidate_id:
            raise RepairContextMismatchedCandidateError(
                f"Feedback candidate ID {self.repair_feedback.candidate_id!r} does not match "
                f"parent candidate ID {self.parent_candidate_id!r}"
            )
        if self.repair_feedback.requirement_id != self.requirement_id:
            raise RepairContextMismatchedContractError(
                f"Feedback requirement ID {self.repair_feedback.requirement_id!r} does not match "
                f"context requirement ID {self.requirement_id!r}"
            )
        if self.repair_feedback.change_class != self.change_class:
            raise RepairContextMismatchedContractError(
                f"Feedback change class {self.repair_feedback.change_class.value} does not match "
                f"context change class {self.change_class.value}"
            )
        if self.repair_feedback.feedback_round != self.repair_round:
            raise RepairContextMismatchedContractError(
                f"Feedback round {self.repair_feedback.feedback_round} does not match "
                f"context repair round {self.repair_round}"
            )

        # 2. Patch digest verification
        computed_patch_digest = compute_bytes_digest(self.parent_patch_text.encode("utf-8")).value
        if self.parent_patch_digest != computed_patch_digest:
            raise BuilderRepairContextError(
                f"parent_patch_digest {self.parent_patch_digest!r} does not match "
                f"computed digest of parent_patch_text {computed_patch_digest!r}"
            )

        # 3. Secret checks in patch text
        if contains_secret(self.parent_patch_text):
            raise BuilderRepairContextError("parent_patch_text contains forbidden secret")

        # 4. Verifier state leakage checks
        for pat in VERIFIER_INTERNAL_PATH_PATTERNS:
            if pat.search(self.parent_patch_text):
                leak_msg = (
                    "Verifier internal path found in candidate patch text; "
                    "verifier workspace state leaked"
                )
                raise VerifierStateLeakError(leak_msg)
            for path in self.permitted_paths:
                if pat.search(path):
                    raise VerifierStateLeakError(
                        f"Verifier internal path found in permitted_paths: {path!r}"
                    )

        # 5. Protected surface validation for permitted paths
        manifest = get_canonical_basebreak_protected_manifest()
        for path in self.permitted_paths:
            normalized = normalize_repo_path(path)
            if is_path_protected(normalized, manifest):
                raise RepairContextProtectedSurfaceError(
                    f"Permitted path {path!r} touches protected surface {normalized!r}"
                )

        # 6. Zero authority enforcement
        if self.is_authoritative:
            raise BuilderRepairContextError(
                "BuilderRepairContextEnvelope cannot have is_authoritative=True"
            )


def build_canonical_repair_context_payload(
    *,
    schema_version: str,
    repair_context_id: str,
    parent_candidate_id: str,
    parent_candidate_tree_digest: str,
    parent_patch_digest: str,
    source_identity: SourceIdentity,
    frozen_contract_digest: str,
    requirement_id: str,
    change_class: ChangeClass,
    repair_feedback_digest: str,
    permitted_paths: tuple[str, ...],
    repair_round: int,
    max_repair_rounds: int,
    is_authoritative: bool = False,
) -> dict[str, Any]:
    """Construct deterministic payload dictionary for repair context hashing."""
    return {
        "change_class": change_class.value,
        "frozen_contract_digest": frozen_contract_digest,
        "is_authoritative": is_authoritative,
        "max_repair_rounds": max_repair_rounds,
        "parent_candidate_id": parent_candidate_id,
        "parent_candidate_tree_digest": parent_candidate_tree_digest,
        "parent_patch_digest": parent_patch_digest,
        "permitted_paths": sorted(permitted_paths),
        "repair_context_id": repair_context_id,
        "repair_feedback_digest": repair_feedback_digest,
        "repair_round": repair_round,
        "requirement_id": requirement_id,
        "schema_version": schema_version,
        "source_identity": {
            "locator": source_identity.locator,
            "resolved_commit_id": source_identity.resolved_commit_id,
            "subpath": source_identity.subpath,
        },
    }


def compute_repair_context_digest(payload: Mapping[str, Any]) -> str:
    """Compute deterministic SHA-256 digest from canonical JSON representation."""
    canonical_json = json.dumps(
        payload,
        ensure_ascii=False,
        sort_keys=True,
        separators=(",", ":"),
    )
    return hashlib.sha256(canonical_json.encode("utf-8")).hexdigest()


def create_builder_repair_context(
    *,
    repair_context_id: str,
    parent_candidate_id: str,
    parent_candidate_tree_digest: str,
    parent_patch_digest: str,
    parent_patch_text: str,
    source_identity: SourceIdentity,
    frozen_contract_digest: str,
    requirement_id: str,
    change_class: ChangeClass,
    repair_feedback: SafeRepairFeedback,
    permitted_paths: Sequence[str],
    repair_round: int,
    max_repair_rounds: int,
) -> BuilderRepairContextEnvelope:
    """Deterministic factory constructing BuilderRepairContextEnvelope with verified digest."""
    # Verify feedback integrity before binding into context
    verify_repair_feedback_integrity(repair_feedback)

    sorted_paths = tuple(sorted(permitted_paths))

    payload = build_canonical_repair_context_payload(
        schema_version=BUILDER_REPAIR_CONTEXT_SCHEMA_VERSION,
        repair_context_id=repair_context_id,
        parent_candidate_id=parent_candidate_id,
        parent_candidate_tree_digest=parent_candidate_tree_digest,
        parent_patch_digest=parent_patch_digest,
        source_identity=source_identity,
        frozen_contract_digest=frozen_contract_digest,
        requirement_id=requirement_id,
        change_class=change_class,
        repair_feedback_digest=repair_feedback.feedback_digest,
        permitted_paths=sorted_paths,
        repair_round=repair_round,
        max_repair_rounds=max_repair_rounds,
        is_authoritative=False,
    )
    digest = compute_repair_context_digest(payload)

    return BuilderRepairContextEnvelope(
        repair_context_id=repair_context_id,
        parent_candidate_id=parent_candidate_id,
        parent_candidate_tree_digest=parent_candidate_tree_digest,
        parent_patch_digest=parent_patch_digest,
        parent_patch_text=parent_patch_text,
        source_identity=source_identity,
        frozen_contract_digest=frozen_contract_digest,
        requirement_id=requirement_id,
        change_class=change_class,
        repair_feedback=repair_feedback,
        permitted_paths=sorted_paths,
        repair_round=repair_round,
        max_repair_rounds=max_repair_rounds,
        repair_context_digest=digest,
        schema_version=BUILDER_REPAIR_CONTEXT_SCHEMA_VERSION,
        is_authoritative=False,
    )


def verify_builder_repair_context_integrity(context: BuilderRepairContextEnvelope) -> bool:
    """Verify cryptographic integrity of BuilderRepairContextEnvelope."""
    if context.is_authoritative:
        raise BuilderRepairContextError(
            "BuilderRepairContextEnvelope cannot have is_authoritative=True"
        )

    payload = build_canonical_repair_context_payload(
        schema_version=context.schema_version,
        repair_context_id=context.repair_context_id,
        parent_candidate_id=context.parent_candidate_id,
        parent_candidate_tree_digest=context.parent_candidate_tree_digest,
        parent_patch_digest=context.parent_patch_digest,
        source_identity=context.source_identity,
        frozen_contract_digest=context.frozen_contract_digest,
        requirement_id=context.requirement_id,
        change_class=context.change_class,
        repair_feedback_digest=context.repair_feedback.feedback_digest,
        permitted_paths=context.permitted_paths,
        repair_round=context.repair_round,
        max_repair_rounds=context.max_repair_rounds,
        is_authoritative=context.is_authoritative,
    )
    computed_digest = compute_repair_context_digest(payload)
    if context.repair_context_digest != computed_digest:
        raise RepairContextTamperingError(
            f"Repair context digest mismatch: recorded {context.repair_context_digest!r} "
            f"!= computed {computed_digest!r}"
        )
    return True
