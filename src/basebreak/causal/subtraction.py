"""Candidate-delta subtraction strategies and counterfactual planning contracts.

P-11.01: Define safe candidate-delta subtraction strategies.

Defines the bounded deterministic strategies by which Basebreak constructs a
counterfactual candidate for the third execution run without allowing a model
to control the causal verdict.

Invariants Enforced:
1. Builder cannot certify itself: zero self-certification across all subtraction contracts.
2. Model prose has zero verdict authority: proposals and typed structures possess zero
   verification or authority weight.
3. Counterfactual origin: must originate from the exact verified candidate and exact
   captured patch.
4. Cryptographic chain continuity: identical frozen contract digest and sealed witness
   digest must survive unchanged.
5. Non-mutation of base and candidate: counterfactual construction never mutates BASE
   or verified CANDIDATE in place.
6. Fail-closed against invalid subtraction: ambiguous, unsupported, empty, or malformed
   subtractions raise explicit typed errors.
7. Protected surfaces, secrets, and repository identity remain strictly enforced.
8. Provider neutrality: zero provider-specific or adapter imports.
"""

from __future__ import annotations

import re
from collections.abc import Mapping, Sequence
from dataclasses import dataclass
from enum import Enum
from typing import Any

from basebreak.builder.capture import CandidateSnapshot
from basebreak.domain.causal import CandidateIdentity, CounterfactualIdentity
from basebreak.domain.source import (
    CommitRevision,
    SourceIdentity,
    _validate_subpath,
)
from basebreak.evidence.artifact import compute_bytes_digest
from basebreak.security.protected_surfaces import (
    ProtectedSurfaceViolation,
    get_canonical_basebreak_protected_manifest,
    normalize_repo_path,
    validate_diff,
)
from basebreak.security.secret_policy import (
    SecretPersistenceError,
    validate_no_secrets,
)

_HEX_64_PATTERN = re.compile(r"^[0-9a-f]{64}$")
_HEX_40_OR_64_PATTERN = re.compile(r"^([0-9a-f]{40}|[0-9a-f]{64})$")
_HUNK_HEADER_PATTERN = re.compile(
    r"^@@ -(?P<old_start>\d+)(?:,(?P<old_length>\d+))? "
    r"\+(?P<new_start>\d+)(?:,(?P<new_length>\d+))? @@(?P<heading>.*)$"
)


# --- Exceptions ---


class CandidateSubtractionError(Exception):
    """Base exception for all candidate-delta subtraction failures."""


class InvalidSubtractionError(CandidateSubtractionError):
    """Raised when patch formatting or subtraction input is malformed or invalid."""


class UnsupportedStrategyError(CandidateSubtractionError):
    """Raised when the requested subtraction strategy or target is unsupported."""


class AmbiguousSubtractionError(CandidateSubtractionError):
    """Raised when delta subtraction is ambiguous, overlapping, or cannot be cleanly separated."""


class EmptySubtractionError(CandidateSubtractionError):
    """Raised when subtraction would remove zero changes (no-op)."""


class CandidateIdentityMismatchError(CandidateSubtractionError):
    """Raised when candidate identity, source commit, or patch digest fails verification."""


class ProtectedSurfaceSubtractionError(CandidateSubtractionError):
    """Raised when candidate patch or delta touches or mutates a protected surface."""


class SecretPolicySubtractionError(CandidateSubtractionError):
    """Raised when candidate patch or delta contains unredacted credentials or secrets."""


class DigestTamperingError(CandidateSubtractionError):
    """Raised when frozen contract or sealed witness digest is tampered or invalid."""


class CallerAuthorityError(CandidateSubtractionError):
    """Raised when caller or model attempts to assert fake authority or certification."""


# --- Strategy Taxonomy ---


class SubtractionStrategyType(str, Enum):
    """Bounded deterministic candidate-delta subtraction strategy taxonomy.

    FULL_PATCH_REVERT: Reverts the entirety of the candidate patch.
    FILE_LEVEL_REVERT: Reverts changes to an explicitly identified set of files.
    HUNK_LEVEL_REVERT: Reverts explicitly identified non-overlapping hunks within files.
    """

    FULL_PATCH_REVERT = "FULL_PATCH_REVERT"
    FILE_LEVEL_REVERT = "FILE_LEVEL_REVERT"
    HUNK_LEVEL_REVERT = "HUNK_LEVEL_REVERT"


# --- Data Records ---


@dataclass(frozen=True, slots=True)
class ParsedDiffHunk:
    """Deterministic representation of a single unified diff hunk."""

    file_path: str
    hunk_index: int
    old_start: int
    old_length: int
    new_start: int
    new_length: int
    header: str
    lines: tuple[str, ...]
    hunk_digest: str
    hunk_id: str
    heading: str = ""

    def __post_init__(self) -> None:
        if not isinstance(self.file_path, str) or not self.file_path.strip():
            raise InvalidSubtractionError("file_path must be a non-empty string")
        if self.file_path != normalize_repo_path(self.file_path):
            raise InvalidSubtractionError(f"file_path is not normalized: {self.file_path!r}")
        if not isinstance(self.hunk_index, int) or self.hunk_index < 0:
            raise InvalidSubtractionError("hunk_index must be a non-negative integer")
        if not isinstance(self.old_start, int) or self.old_start < 0:
            raise InvalidSubtractionError("old_start must be a non-negative integer")
        if not isinstance(self.old_length, int) or self.old_length < 0:
            raise InvalidSubtractionError("old_length must be a non-negative integer")
        if not isinstance(self.new_start, int) or self.new_start < 0:
            raise InvalidSubtractionError("new_start must be a non-negative integer")
        if not isinstance(self.new_length, int) or self.new_length < 0:
            raise InvalidSubtractionError("new_length must be a non-negative integer")
        if not isinstance(self.hunk_digest, str) or not _HEX_64_PATTERN.match(self.hunk_digest):
            raise InvalidSubtractionError(
                f"hunk_digest must be a 64 hex char string: {self.hunk_digest!r}"
            )
        if not isinstance(self.hunk_id, str) or not self.hunk_id.strip():
            raise InvalidSubtractionError("hunk_id must be a non-empty string")

    @property
    def added_lines(self) -> tuple[str, ...]:
        """Lines added by this hunk (starting with '+')."""
        return tuple(
            line for line in self.lines if line.startswith("+") and not line.startswith("+++")
        )

    @property
    def removed_lines(self) -> tuple[str, ...]:
        """Lines removed by this hunk (starting with '-')."""
        return tuple(
            line for line in self.lines if line.startswith("-") and not line.startswith("---")
        )

    @property
    def context_lines(self) -> tuple[str, ...]:
        """Context lines in this hunk (starting with ' ')."""
        return tuple(line for line in self.lines if line.startswith(" "))


@dataclass(frozen=True, slots=True)
class ParsedFileDiff:
    """Deterministic representation of a unified diff targeting a single file."""

    file_path: str
    old_path: str | None
    headers: tuple[str, ...]
    hunks: tuple[ParsedDiffHunk, ...]
    file_digest: str
    raw_diff_text: str
    is_new_file: bool = False
    is_deleted_file: bool = False
    is_renamed: bool = False

    def __post_init__(self) -> None:
        if not isinstance(self.file_path, str) or not self.file_path.strip():
            raise InvalidSubtractionError("file_path must be a non-empty string")
        if self.file_path != normalize_repo_path(self.file_path):
            raise InvalidSubtractionError(f"file_path is not normalized: {self.file_path!r}")
        if not isinstance(self.hunks, tuple):
            if isinstance(self.hunks, Sequence):
                object.__setattr__(self, "hunks", tuple(self.hunks))
            else:
                raise TypeError("hunks must be a sequence of ParsedDiffHunk")
        for h in self.hunks:
            if not isinstance(h, ParsedDiffHunk):
                raise TypeError(f"hunks entry must be ParsedDiffHunk, got {type(h).__name__}")
        if not isinstance(self.file_digest, str) or not _HEX_64_PATTERN.match(self.file_digest):
            raise InvalidSubtractionError(
                f"file_digest must be a 64 hex char string: {self.file_digest!r}"
            )


@dataclass(frozen=True, slots=True)
class ParsedCandidatePatch:
    """Deterministic representation of an entire parsed candidate patch."""

    raw_patch_text: str
    patch_digest: str
    files: tuple[ParsedFileDiff, ...]

    def __post_init__(self) -> None:
        if not isinstance(self.raw_patch_text, str):
            raise TypeError("raw_patch_text must be str")
        if not isinstance(self.patch_digest, str) or not _HEX_64_PATTERN.match(self.patch_digest):
            raise InvalidSubtractionError(
                f"patch_digest must be a 64 hex char string: {self.patch_digest!r}"
            )
        computed = compute_bytes_digest(self.raw_patch_text.encode("utf-8")).value
        if self.patch_digest != computed:
            raise InvalidSubtractionError(
                f"patch_digest {self.patch_digest!r} does not match computed SHA-256 {computed!r}"
            )
        if not isinstance(self.files, tuple):
            if isinstance(self.files, Sequence):
                object.__setattr__(self, "files", tuple(self.files))
            else:
                raise TypeError("files must be a sequence of ParsedFileDiff")
        for f in self.files:
            if not isinstance(f, ParsedFileDiff):
                raise TypeError(f"files entry must be ParsedFileDiff, got {type(f).__name__}")

    @property
    def total_files_count(self) -> int:
        return len(self.files)

    @property
    def total_hunks_count(self) -> int:
        return sum(len(f.hunks) for f in self.files)

    @property
    def file_paths(self) -> tuple[str, ...]:
        return tuple(f.file_path for f in self.files)

    def get_file(self, path: str) -> ParsedFileDiff | None:
        norm = normalize_repo_path(path)
        for f in self.files:
            if f.file_path == norm:
                return f
        return None

    def get_hunk(self, hunk_id: str) -> ParsedDiffHunk | None:
        """Find a parsed hunk matching exact hunk_id or exact 64-char hunk_digest."""
        for f in self.files:
            for h in f.hunks:
                if h.hunk_id == hunk_id or h.hunk_digest == hunk_id:
                    return h
        return None


@dataclass(frozen=True, slots=True)
class SubtractionRequest:
    """Caller-provided specification of a candidate-delta subtraction strategy.

    Invariants:
    - Zero caller authority: is_authoritative, grants_pass, and is_causally_verified
      must be strictly False.
    - Strategy must be one of the bounded SubtractionStrategyType enum values.
    """

    strategy_type: SubtractionStrategyType
    target_files: tuple[str, ...] = ()
    target_hunk_ids: tuple[str, ...] = ()
    is_authoritative: bool = False
    grants_pass: bool = False
    is_causally_verified: bool = False
    description: str = ""

    def __post_init__(self) -> None:
        if self.is_authoritative is not False:
            raise CallerAuthorityError(
                "SubtractionRequest cannot assert authority: is_authoritative must be False"
            )
        if self.grants_pass is not False:
            raise CallerAuthorityError(
                "SubtractionRequest cannot grant pass: grants_pass must be False"
            )
        if self.is_causally_verified is not False:
            raise CallerAuthorityError(
                "SubtractionRequest cannot assert verification: is_causally_verified must be False"
            )
        if not isinstance(self.strategy_type, SubtractionStrategyType):
            tname = type(self.strategy_type).__name__
            raise TypeError(f"strategy_type must be SubtractionStrategyType, got {tname}")
        if not isinstance(self.target_files, tuple):
            if isinstance(self.target_files, Sequence):
                object.__setattr__(self, "target_files", tuple(self.target_files))
            else:
                raise TypeError("target_files must be a sequence of strings")
        if not isinstance(self.target_hunk_ids, tuple):
            if isinstance(self.target_hunk_ids, Sequence):
                object.__setattr__(self, "target_hunk_ids", tuple(self.target_hunk_ids))
            else:
                raise TypeError("target_hunk_ids must be a sequence of strings")


@dataclass(frozen=True, slots=True)
class CounterfactualDeltaPlan:
    """Immutable plan for constructing a counterfactual candidate via delta subtraction.

    Guarantees:
    - Cryptographically binds source commit, candidate tree, candidate patch,
      frozen contract, and sealed witness.
    - Captures exact subtracted delta text, residual counterfactual patch text,
      and reverse delta text.
    - Possesses ZERO verification authority: is_authoritative, is_causally_verified,
      and grants_pass are strictly False.
    """

    counterfactual_id: str
    strategy_type: SubtractionStrategyType
    target_candidate_id: str
    target_candidate_patch_digest: str
    source_commit_id: str
    candidate_tree_digest: str
    frozen_contract_digest: str
    sealed_witness_digest: str
    subtracted_delta_text: str
    subtracted_delta_digest: str
    counterfactual_patch_text: str
    counterfactual_patch_digest: str
    reverse_delta_text: str
    reverse_delta_digest: str
    subtracted_files: tuple[str, ...]
    subtracted_hunk_ids: tuple[str, ...]
    source_locator: str | None = None
    source_subpath: str | None = None
    is_authoritative: bool = False
    is_causally_verified: bool = False
    grants_pass: bool = False
    description: str = ""

    def __post_init__(self) -> None:
        if self.is_authoritative is not False:
            raise CallerAuthorityError(
                "CounterfactualDeltaPlan is_authoritative must be strictly False"
            )
        if self.is_causally_verified is not False:
            raise CallerAuthorityError(
                "CounterfactualDeltaPlan is_causally_verified must be strictly False"
            )
        if self.grants_pass is not False:
            raise CallerAuthorityError("CounterfactualDeltaPlan grants_pass must be strictly False")

        if not isinstance(self.counterfactual_id, str) or not self.counterfactual_id.strip():
            raise InvalidSubtractionError("counterfactual_id must be a non-empty string")
        if not isinstance(self.strategy_type, SubtractionStrategyType):
            tname = type(self.strategy_type).__name__
            raise TypeError(f"strategy_type must be SubtractionStrategyType, got {tname}")
        if not isinstance(self.target_candidate_id, str) or not self.target_candidate_id.strip():
            raise CandidateIdentityMismatchError("target_candidate_id must be a non-empty string")

        for name, val in [
            ("target_candidate_patch_digest", self.target_candidate_patch_digest),
            ("frozen_contract_digest", self.frozen_contract_digest),
            ("sealed_witness_digest", self.sealed_witness_digest),
            ("subtracted_delta_digest", self.subtracted_delta_digest),
            ("counterfactual_patch_digest", self.counterfactual_patch_digest),
            ("reverse_delta_digest", self.reverse_delta_digest),
        ]:
            if not isinstance(val, str) or not _HEX_64_PATTERN.match(val):
                raise DigestTamperingError(
                    f"{name} must be a 64 hex char lowercase string: {val!r}"
                )

        for name, val in [
            ("source_commit_id", self.source_commit_id),
            ("candidate_tree_digest", self.candidate_tree_digest),
        ]:
            if not isinstance(val, str) or not _HEX_40_OR_64_PATTERN.match(val):
                raise CandidateIdentityMismatchError(
                    f"{name} must be a 40 or 64 hex char string: {val!r}"
                )

        if self.source_locator is not None:
            if not isinstance(self.source_locator, str):
                tname = type(self.source_locator).__name__
                raise TypeError(f"source_locator must be a string or None, got {tname}")
            if self.source_subpath is not None and not isinstance(self.source_subpath, str):
                tname = type(self.source_subpath).__name__
                raise TypeError(f"source_subpath must be a string or None, got {tname}")
            try:
                SourceIdentity(
                    locator=self.source_locator,
                    revision=CommitRevision(self.source_commit_id),
                    subpath=self.source_subpath,
                )
            except (ValueError, TypeError) as exc:
                raise CandidateIdentityMismatchError(
                    f"Invalid canonical source identity: {exc}"
                ) from exc
        elif self.source_subpath is not None:
            if not isinstance(self.source_subpath, str):
                tname = type(self.source_subpath).__name__
                raise TypeError(f"source_subpath must be a string or None, got {tname}")
            try:
                _validate_subpath(self.source_subpath)
            except (ValueError, TypeError) as exc:
                raise CandidateIdentityMismatchError(f"Invalid source_subpath: {exc}") from exc

        # Validate cryptographic digests of derived delta texts
        sub_comp = compute_bytes_digest(self.subtracted_delta_text.encode("utf-8")).value
        if self.subtracted_delta_digest != sub_comp:
            raise DigestTamperingError(
                f"subtracted_delta_digest {self.subtracted_delta_digest!r} "
                f"does not match computed {sub_comp!r}"
            )

        cf_comp = compute_bytes_digest(self.counterfactual_patch_text.encode("utf-8")).value
        if self.counterfactual_patch_digest != cf_comp:
            raise DigestTamperingError(
                f"counterfactual_patch_digest {self.counterfactual_patch_digest!r} "
                f"does not match computed {cf_comp!r}"
            )

        rev_comp = compute_bytes_digest(self.reverse_delta_text.encode("utf-8")).value
        if self.reverse_delta_digest != rev_comp:
            raise DigestTamperingError(
                f"reverse_delta_digest {self.reverse_delta_digest!r} "
                f"does not match computed {rev_comp!r}"
            )

        # Ensure normalized, sorted lists of files and hunks
        for attr in ("subtracted_files", "subtracted_hunk_ids"):
            val_seq = getattr(self, attr)
            if not isinstance(val_seq, tuple):
                if isinstance(val_seq, Sequence):
                    val_seq = tuple(val_seq)
                    object.__setattr__(self, attr, val_seq)
                else:
                    raise TypeError(f"{attr} must be a sequence of strings")
            if list(val_seq) != sorted(val_seq):
                raise InvalidSubtractionError(
                    f"{attr} must be in deterministic sorted order: {val_seq}"
                )

    def to_counterfactual_identity(self, candidate: CandidateIdentity) -> CounterfactualIdentity:
        """Derive authoritative domain CounterfactualIdentity bound to the exact candidate."""
        if not isinstance(candidate, CandidateIdentity):
            raise TypeError(f"candidate must be CandidateIdentity, got {type(candidate).__name__}")
        if candidate.candidate_id != self.target_candidate_id:
            raise CandidateIdentityMismatchError(
                f"Candidate candidate_id {candidate.candidate_id!r} does not match "
                f"plan target_candidate_id {self.target_candidate_id!r}"
            )
        if candidate.patch_digest != self.target_candidate_patch_digest:
            raise CandidateIdentityMismatchError(
                f"Candidate patch_digest {candidate.patch_digest!r} does not match "
                f"plan target_candidate_patch_digest {self.target_candidate_patch_digest!r}"
            )
        if candidate.resolved_commit_id != self.source_commit_id:
            raise CandidateIdentityMismatchError(
                f"Candidate resolved_commit_id {candidate.resolved_commit_id!r} does not match "
                f"plan source_commit_id {self.source_commit_id!r}"
            )
        if self.source_locator is not None and candidate.source.locator != self.source_locator:
            raise CandidateIdentityMismatchError(
                f"Candidate source locator {candidate.source.locator!r} does not match "
                f"plan source_locator {self.source_locator!r}"
            )
        if self.source_locator is not None and candidate.source.subpath != self.source_subpath:
            raise CandidateIdentityMismatchError(
                f"Candidate source subpath {candidate.source.subpath!r} does not match "
                f"plan source_subpath {self.source_subpath!r}"
            )
        if (
            self.source_locator is None
            and self.source_subpath is not None
            and candidate.source.subpath != self.source_subpath
        ):
            raise CandidateIdentityMismatchError(
                f"Candidate source subpath {candidate.source.subpath!r} does not match "
                f"plan source_subpath {self.source_subpath!r}"
            )
        return CounterfactualIdentity(
            counterfactual_id=self.counterfactual_id,
            target_candidate=candidate,
            delta_digest=self.subtracted_delta_digest,
            description=f"Counterfactual perturbation via {self.strategy_type.value}",
        )

    def to_dict(self) -> dict[str, Any]:
        """Serialize plan to dictionary."""
        return {
            "counterfactual_id": self.counterfactual_id,
            "strategy_type": self.strategy_type.value,
            "target_candidate_id": self.target_candidate_id,
            "target_candidate_patch_digest": self.target_candidate_patch_digest,
            "source_commit_id": self.source_commit_id,
            "source_locator": self.source_locator,
            "source_subpath": self.source_subpath,
            "candidate_tree_digest": self.candidate_tree_digest,
            "frozen_contract_digest": self.frozen_contract_digest,
            "sealed_witness_digest": self.sealed_witness_digest,
            "subtracted_delta_digest": self.subtracted_delta_digest,
            "subtracted_delta_text": self.subtracted_delta_text,
            "counterfactual_patch_digest": self.counterfactual_patch_digest,
            "counterfactual_patch_text": self.counterfactual_patch_text,
            "reverse_delta_digest": self.reverse_delta_digest,
            "reverse_delta_text": self.reverse_delta_text,
            "subtracted_files": list(self.subtracted_files),
            "subtracted_hunk_ids": list(self.subtracted_hunk_ids),
            "is_authoritative": self.is_authoritative,
            "is_causally_verified": self.is_causally_verified,
            "grants_pass": self.grants_pass,
            "description": self.description,
        }

    @classmethod
    def from_dict(cls, data: Mapping[str, Any]) -> CounterfactualDeltaPlan:
        """Deserialize plan from dictionary with strict authority validation."""
        if not isinstance(data, Mapping):
            raise InvalidSubtractionError(f"Expected mapping, got {type(data).__name__}")
        if data.get("is_authoritative") is True:
            raise CallerAuthorityError(
                "CounterfactualDeltaPlan is_authoritative must be strictly False"
            )
        if data.get("is_causally_verified") is True:
            raise CallerAuthorityError(
                "CounterfactualDeltaPlan is_causally_verified must be strictly False"
            )
        if data.get("grants_pass") is True:
            raise CallerAuthorityError("CounterfactualDeltaPlan grants_pass must be strictly False")

        try:
            raw_locator = data.get("source_locator")
            source_locator = str(raw_locator) if raw_locator is not None else None
            raw_subpath = data.get("source_subpath")
            source_subpath = str(raw_subpath) if raw_subpath is not None else None

            return cls(
                counterfactual_id=str(data["counterfactual_id"]),
                strategy_type=SubtractionStrategyType(str(data["strategy_type"])),
                target_candidate_id=str(data["target_candidate_id"]),
                target_candidate_patch_digest=str(data["target_candidate_patch_digest"]),
                source_commit_id=str(data["source_commit_id"]),
                candidate_tree_digest=str(data["candidate_tree_digest"]),
                frozen_contract_digest=str(data["frozen_contract_digest"]),
                sealed_witness_digest=str(data["sealed_witness_digest"]),
                subtracted_delta_text=str(data["subtracted_delta_text"]),
                subtracted_delta_digest=str(data["subtracted_delta_digest"]),
                counterfactual_patch_text=str(data["counterfactual_patch_text"]),
                counterfactual_patch_digest=str(data["counterfactual_patch_digest"]),
                reverse_delta_text=str(data["reverse_delta_text"]),
                reverse_delta_digest=str(data["reverse_delta_digest"]),
                subtracted_files=tuple(str(x) for x in data.get("subtracted_files", ())),
                subtracted_hunk_ids=tuple(str(x) for x in data.get("subtracted_hunk_ids", ())),
                source_locator=source_locator,
                source_subpath=source_subpath,
                is_authoritative=False,
                is_causally_verified=False,
                grants_pass=False,
                description=str(data.get("description", "")),
            )
        except (KeyError, ValueError, TypeError) as exc:
            raise InvalidSubtractionError(
                f"Failed to deserialize CounterfactualDeltaPlan: {exc}"
            ) from exc


# --- Unified Diff Parser & Inverter ---


def parse_candidate_patch(patch_text: str) -> ParsedCandidatePatch:
    """Parse candidate unified diff into deterministic structured files and hunks.

    Fails closed on malformed diff syntax, truncated lines, or inconsistent line counts.
    """
    if not isinstance(patch_text, str):
        raise TypeError(f"patch_text must be str, got {type(patch_text).__name__}")
    if not patch_text.strip():
        raise EmptySubtractionError("Candidate patch text is empty or only whitespace")

    computed_digest = compute_bytes_digest(patch_text.encode("utf-8")).value
    lines = patch_text.splitlines(keepends=True)

    file_diffs: list[ParsedFileDiff] = []
    i = 0
    n = len(lines)

    while i < n:
        line = lines[i]
        if not line.startswith("diff --git "):
            i += 1
            continue

        file_start_idx = i
        header_lines: list[str] = [line]
        parts = line.strip().split()
        if len(parts) < 4:
            raise InvalidSubtractionError(f"Malformed git diff header: {line.strip()!r}")

        old_token = parts[2]
        new_token = parts[3]
        old_path = old_token[2:] if old_token.startswith("a/") else old_token
        new_path = new_token[2:] if new_token.startswith("b/") else new_token

        is_new_file = False
        is_deleted_file = False
        is_renamed = False

        i += 1
        while i < n and not lines[i].startswith("@@ ") and not lines[i].startswith("diff --git "):
            subline = lines[i]
            header_lines.append(subline)
            if subline.startswith("new file mode "):
                is_new_file = True
            elif subline.startswith("deleted file mode "):
                is_deleted_file = True
            elif subline.startswith("rename from ") or subline.startswith("rename to "):
                is_renamed = True
            elif subline.startswith("--- "):
                p = subline[4:].strip()
                if p == "/dev/null":
                    is_new_file = True
            elif subline.startswith("+++ "):
                p = subline[4:].strip()
                if p == "/dev/null":
                    is_deleted_file = True
            i += 1

        target_file_path = old_path if is_deleted_file else new_path
        norm_path = normalize_repo_path(target_file_path)

        # Parse hunks for this file
        hunks: list[ParsedDiffHunk] = []
        hunk_idx = 0

        while i < n and lines[i].startswith("@@ "):
            hunk_header_line = lines[i]
            m = _HUNK_HEADER_PATTERN.match(hunk_header_line.strip())
            if not m:
                raise InvalidSubtractionError(
                    f"Malformed hunk header: {hunk_header_line.strip()!r}"
                )

            old_start = int(m.group("old_start"))
            old_len = int(m.group("old_length")) if m.group("old_length") is not None else 1
            new_start = int(m.group("new_start"))
            new_len = int(m.group("new_length")) if m.group("new_length") is not None else 1

            i += 1
            hunk_lines: list[str] = []
            while (
                i < n and not lines[i].startswith("@@ ") and not lines[i].startswith("diff --git ")
            ):
                hunk_line = lines[i]
                if not (
                    hunk_line.startswith("+")
                    or hunk_line.startswith("-")
                    or hunk_line.startswith(" ")
                    or hunk_line.startswith("\\")
                    or hunk_line == "\n"
                    or hunk_line == "\r\n"
                ):
                    raise InvalidSubtractionError(f"Malformed hunk line: {hunk_line!r}")
                hunk_lines.append(hunk_line)
                i += 1

            # Validate line counts in hunk
            rem_count = sum(1 for hl in hunk_lines if hl.startswith("-"))
            add_count = sum(1 for hl in hunk_lines if hl.startswith("+"))
            ctx_count = sum(1 for hl in hunk_lines if hl.startswith(" "))

            # Line count verification against hunk header
            expected_old = old_len
            actual_old = rem_count + ctx_count
            expected_new = new_len
            actual_new = add_count + ctx_count

            if actual_old != expected_old or actual_new != expected_new:
                raise InvalidSubtractionError(
                    f"Hunk line count mismatch in {norm_path} hunk {hunk_idx}: "
                    f"expected old={expected_old}, actual={actual_old}; "
                    f"expected new={expected_new}, actual={actual_new}"
                )

            hunk_raw = hunk_header_line + "".join(hunk_lines)
            hunk_digest = compute_bytes_digest(hunk_raw.encode("utf-8")).value
            hunk_id = f"{norm_path}#hunk-{hunk_idx}@{hunk_digest[:12]}"

            heading_str = m.group("heading") or ""
            hunk_record = ParsedDiffHunk(
                file_path=norm_path,
                hunk_index=hunk_idx,
                old_start=old_start,
                old_length=old_len,
                new_start=new_start,
                new_length=new_len,
                header=hunk_header_line,
                lines=tuple(hunk_lines),
                hunk_digest=hunk_digest,
                hunk_id=hunk_id,
                heading=heading_str,
            )
            hunks.append(hunk_record)
            hunk_idx += 1

        file_end_idx = i
        raw_file_text = "".join(lines[file_start_idx:file_end_idx])
        file_digest = compute_bytes_digest(raw_file_text.encode("utf-8")).value

        file_diffs.append(
            ParsedFileDiff(
                file_path=norm_path,
                old_path=old_path,
                headers=tuple(header_lines),
                hunks=tuple(hunks),
                file_digest=file_digest,
                raw_diff_text=raw_file_text,
                is_new_file=is_new_file,
                is_deleted_file=is_deleted_file,
                is_renamed=is_renamed,
            )
        )

    if not file_diffs:
        raise InvalidSubtractionError("No valid file diffs found in candidate patch text")

    return ParsedCandidatePatch(
        raw_patch_text=patch_text,
        patch_digest=computed_digest,
        files=tuple(file_diffs),
    )


def invert_patch(diff_text: str) -> str:
    """Invert unified diff text by swapping additions/deletions and coordinates."""
    if not diff_text:
        return ""

    parsed = parse_candidate_patch(diff_text)
    inverted_chunks: list[str] = []

    for f in parsed.files:
        old_tag = "/dev/null" if f.is_new_file else f"a/{f.file_path}"
        new_tag = "/dev/null" if f.is_deleted_file else f"b/{f.file_path}"

        # Swapped headers
        inv_old_tag = new_tag
        inv_new_tag = old_tag

        inverted_chunks.append(f"diff --git {inv_old_tag} {inv_new_tag}\n")
        inverted_chunks.append(f"--- {inv_old_tag}\n")
        inverted_chunks.append(f"+++ {inv_new_tag}\n")

        for h in f.hunks:
            inv_header = (
                f"@@ -{h.new_start},{h.new_length} +{h.old_start},{h.old_length} @@{h.heading}\n"
            )
            inverted_chunks.append(inv_header)
            for line in h.lines:
                if line.startswith("+") and not line.startswith("+++"):
                    inverted_chunks.append("-" + line[1:])
                elif line.startswith("-") and not line.startswith("---"):
                    inverted_chunks.append("+" + line[1:])
                else:
                    inverted_chunks.append(line)

    return "".join(inverted_chunks)


def _reconstruct_file_diff_with_hunks(
    file_diff: ParsedFileDiff,
    selected_hunks: Sequence[ParsedDiffHunk],
) -> str:
    """Reconstruct a unified diff for a single file containing only selected hunks."""
    if not selected_hunks:
        return ""

    chunks: list[str] = []
    old_tag = (
        "/dev/null"
        if file_diff.is_new_file and len(selected_hunks) == len(file_diff.hunks)
        else f"a/{file_diff.file_path}"
    )
    new_tag = (
        "/dev/null"
        if file_diff.is_deleted_file and len(selected_hunks) == len(file_diff.hunks)
        else f"b/{file_diff.file_path}"
    )

    chunks.append(f"diff --git a/{file_diff.file_path} b/{file_diff.file_path}\n")
    chunks.append(f"--- {old_tag}\n")
    chunks.append(f"+++ {new_tag}\n")

    # Sort hunks by original old_start
    sorted_hunks = sorted(selected_hunks, key=lambda h: h.old_start)

    # Recompute line shifts for retained hunks
    cumulative_shift = 0
    for h in sorted_hunks:
        new_start = h.old_start + cumulative_shift
        header = f"@@ -{h.old_start},{h.old_length} +{new_start},{h.new_length} @@{h.heading}\n"
        chunks.append(header)
        for line in h.lines:
            chunks.append(line)
        hunk_shift = len(h.added_lines) - len(h.removed_lines)
        cumulative_shift += hunk_shift

    return "".join(chunks)


# --- Subtractor Engine ---


class CandidateDeltaSubtractor:
    """Deterministic candidate-delta subtraction engine.

    Enforces:
    1. Zero model authority: model proposals are unprivileged data.
    2. Exact candidate and patch binding: fails closed on digest mismatch.
    3. Immutable contract and witness preservation: frozen digests cannot be altered.
    4. Protected-surface and secret policy enforcement.
    5. Clean-room deterministic subtraction algorithms without heuristics.
    6. Non-mutation of BASE and CANDIDATE.
    """

    @classmethod
    def plan_subtraction(
        cls,
        *,
        candidate_id: str,
        candidate_patch_text: str,
        candidate_patch_digest: str,
        candidate_tree_digest: str,
        source_commit_id: str,
        frozen_contract_digest: str,
        sealed_witness_digest: str,
        request: SubtractionRequest,
        source_locator: str | None = None,
        source_subpath: str | None = None,
        source_identity: SourceIdentity | None = None,
    ) -> CounterfactualDeltaPlan:
        """Construct a deterministic CounterfactualDeltaPlan for the given candidate and request."""
        # 1. Authority Invariant Enforcement
        if not isinstance(request, SubtractionRequest):
            raise TypeError(f"request must be SubtractionRequest, got {type(request).__name__}")
        if request.is_authoritative or request.grants_pass or request.is_causally_verified:
            raise CallerAuthorityError("Caller cannot assert authority or causal pass")

        if source_identity is not None:
            if not isinstance(source_identity, SourceIdentity):
                tname = type(source_identity).__name__
                raise TypeError(f"source_identity must be SourceIdentity, got {tname}")
            if source_identity.resolved_commit_id != source_commit_id:
                raise CandidateIdentityMismatchError(
                    f"source_identity resolved_commit_id {source_identity.resolved_commit_id!r} "
                    f"does not match source_commit_id {source_commit_id!r}"
                )
            if source_locator is not None and source_locator != source_identity.locator:
                raise CandidateIdentityMismatchError(
                    f"source_locator {source_locator!r} does not match "
                    f"source_identity locator {source_identity.locator!r}"
                )
            if source_subpath is not None and source_subpath != source_identity.subpath:
                raise CandidateIdentityMismatchError(
                    f"source_subpath {source_subpath!r} does not match "
                    f"source_identity subpath {source_identity.subpath!r}"
                )
            source_locator = source_identity.locator
            source_subpath = source_identity.subpath

        if source_locator is not None:
            if not isinstance(source_locator, str):
                tname = type(source_locator).__name__
                raise TypeError(f"source_locator must be a string or None, got {tname}")
            if source_subpath is not None and not isinstance(source_subpath, str):
                tname = type(source_subpath).__name__
                raise TypeError(f"source_subpath must be a string or None, got {tname}")
            try:
                SourceIdentity(
                    locator=source_locator,
                    revision=CommitRevision(source_commit_id),
                    subpath=source_subpath,
                )
            except (ValueError, TypeError) as exc:
                raise CandidateIdentityMismatchError(
                    f"Invalid canonical source identity: {exc}"
                ) from exc
        elif source_subpath is not None:
            if not isinstance(source_subpath, str):
                tname = type(source_subpath).__name__
                raise TypeError(f"source_subpath must be a string or None, got {tname}")
            try:
                _validate_subpath(source_subpath)
            except (ValueError, TypeError) as exc:
                raise CandidateIdentityMismatchError(f"Invalid source_subpath: {exc}") from exc

        # 2. Candidate Identity & Digest Invariant Enforcement
        if not isinstance(candidate_id, str) or not candidate_id.strip():
            raise CandidateIdentityMismatchError("candidate_id must be a non-empty string")
        if not isinstance(candidate_patch_text, str):
            raise TypeError("candidate_patch_text must be str")
        if not candidate_patch_text.strip():
            raise EmptySubtractionError("candidate_patch_text cannot be empty")

        if not isinstance(candidate_patch_digest, str) or not _HEX_64_PATTERN.match(
            candidate_patch_digest
        ):
            raise CandidateIdentityMismatchError(
                f"candidate_patch_digest must be a 64 hex char string: {candidate_patch_digest!r}"
            )
        computed_patch_digest = compute_bytes_digest(candidate_patch_text.encode("utf-8")).value
        if candidate_patch_digest != computed_patch_digest:
            raise CandidateIdentityMismatchError(
                f"candidate_patch_digest {candidate_patch_digest!r} does not match "
                f"computed SHA-256 {computed_patch_digest!r}"
            )

        if not isinstance(candidate_tree_digest, str) or not _HEX_40_OR_64_PATTERN.match(
            candidate_tree_digest
        ):
            raise CandidateIdentityMismatchError(
                f"candidate_tree_digest must be 40 or 64 hex chars: {candidate_tree_digest!r}"
            )
        if not isinstance(source_commit_id, str) or not _HEX_40_OR_64_PATTERN.match(
            source_commit_id
        ):
            raise CandidateIdentityMismatchError(
                f"source_commit_id must be 40 or 64 hex chars: {source_commit_id!r}"
            )

        # 3. Contract & Witness Preservation Invariant Enforcement
        if not isinstance(frozen_contract_digest, str) or not _HEX_64_PATTERN.match(
            frozen_contract_digest
        ):
            raise DigestTamperingError(
                f"frozen_contract_digest must be 64 hex chars: {frozen_contract_digest!r}"
            )
        if not isinstance(sealed_witness_digest, str) or not _HEX_64_PATTERN.match(
            sealed_witness_digest
        ):
            raise DigestTamperingError(
                f"sealed_witness_digest must be 64 hex chars: {sealed_witness_digest!r}"
            )

        # 4. Protected Surface & Secret Safety Enforcement on Candidate Patch
        canonical_manifest = get_canonical_basebreak_protected_manifest()
        try:
            validate_diff(candidate_patch_text, canonical_manifest)
        except ProtectedSurfaceViolation as exc:
            raise ProtectedSurfaceSubtractionError(
                f"Candidate patch targets protected surface: {exc}"
            ) from exc

        try:
            validate_no_secrets(candidate_patch_text, path="candidate_patch_text")
        except SecretPersistenceError as exc:
            raise SecretPolicySubtractionError(
                f"Candidate patch contains unredacted secret: {exc}"
            ) from exc

        # 5. Parse Unified Diff
        parsed_patch = parse_candidate_patch(candidate_patch_text)

        subtracted_delta_text: str = ""
        counterfactual_patch_text: str = ""
        subtracted_files: list[str] = []
        subtracted_hunk_ids: list[str] = []

        # 6. Apply Subtraction Strategy
        if request.strategy_type == SubtractionStrategyType.FULL_PATCH_REVERT:
            subtracted_delta_text = candidate_patch_text
            counterfactual_patch_text = ""
            subtracted_files = sorted(parsed_patch.file_paths)
            subtracted_hunk_ids = sorted(h.hunk_id for f in parsed_patch.files for h in f.hunks)

        elif request.strategy_type == SubtractionStrategyType.FILE_LEVEL_REVERT:
            if not request.target_files:
                raise EmptySubtractionError("target_files must not be empty for FILE_LEVEL_REVERT")

            norm_targets = set()
            for tf in request.target_files:
                if not tf or not isinstance(tf, str) or not tf.strip():
                    raise InvalidSubtractionError("target_files entry must be a non-empty string")
                norm_tf = normalize_repo_path(tf)
                if norm_tf not in parsed_patch.file_paths:
                    raise UnsupportedStrategyError(
                        f"Target file {tf!r} ({norm_tf!r}) is not modified in candidate patch"
                    )
                norm_targets.add(norm_tf)

            sub_chunks: list[str] = []
            cf_chunks: list[str] = []

            for f in parsed_patch.files:
                if f.file_path in norm_targets:
                    sub_chunks.append(f.raw_diff_text)
                    subtracted_files.append(f.file_path)
                    subtracted_hunk_ids.extend(h.hunk_id for h in f.hunks)
                else:
                    cf_chunks.append(f.raw_diff_text)

            if not sub_chunks:
                raise EmptySubtractionError("Zero files were matched for subtraction")

            subtracted_delta_text = "".join(sub_chunks)
            counterfactual_patch_text = "".join(cf_chunks)
            subtracted_files = sorted(subtracted_files)
            subtracted_hunk_ids = sorted(subtracted_hunk_ids)

        elif request.strategy_type == SubtractionStrategyType.HUNK_LEVEL_REVERT:
            if not request.target_hunk_ids:
                raise EmptySubtractionError(
                    "target_hunk_ids must not be empty for HUNK_LEVEL_REVERT"
                )

            target_hunk_id_set = set(request.target_hunk_ids)
            for hid in target_hunk_id_set:
                if not parsed_patch.get_hunk(hid):
                    raise UnsupportedStrategyError(
                        f"Target hunk ID {hid!r} is not present in candidate patch"
                    )

            sub_chunks = []
            cf_chunks = []

            for f in parsed_patch.files:
                # Check for overlapping hunks within the file
                sorted_hunks = sorted(f.hunks, key=lambda h: h.old_start)
                for k in range(len(sorted_hunks) - 1):
                    h_curr = sorted_hunks[k]
                    h_next = sorted_hunks[k + 1]
                    if h_curr.old_start + h_curr.old_length > h_next.old_start:
                        raise AmbiguousSubtractionError(
                            f"Overlapping hunks detected in file {f.file_path!r} between "
                            f"{h_curr.hunk_id} and {h_next.hunk_id}"
                        )

                file_sub_hunks: list[ParsedDiffHunk] = []
                file_cf_hunks: list[ParsedDiffHunk] = []

                for h in f.hunks:
                    if h.hunk_id in target_hunk_id_set or h.hunk_digest in target_hunk_id_set:
                        file_sub_hunks.append(h)
                        subtracted_hunk_ids.append(h.hunk_id)
                    else:
                        file_cf_hunks.append(h)

                if file_sub_hunks:
                    subtracted_files.append(f.file_path)
                    sub_diff = _reconstruct_file_diff_with_hunks(f, file_sub_hunks)
                    if sub_diff:
                        sub_chunks.append(sub_diff)

                if file_cf_hunks:
                    cf_diff = _reconstruct_file_diff_with_hunks(f, file_cf_hunks)
                    if cf_diff:
                        cf_chunks.append(cf_diff)

            if not sub_chunks:
                raise EmptySubtractionError("Zero hunks were matched for subtraction")

            subtracted_delta_text = "".join(sub_chunks)
            counterfactual_patch_text = "".join(cf_chunks)
            subtracted_files = sorted(set(subtracted_files))
            subtracted_hunk_ids = sorted(subtracted_hunk_ids)

        else:
            raise UnsupportedStrategyError(
                f"Unsupported subtraction strategy type: {request.strategy_type!r}"
            )

        # 7. Validate that subtraction is non-empty
        if not subtracted_delta_text.strip():
            raise EmptySubtractionError("Subtraction yielded empty subtracted delta (no-op)")

        # 8. Compute Inverted (Reverse) Delta Text
        reverse_delta_text = invert_patch(subtracted_delta_text)

        # 9. Protected Surface & Secret Safety Enforcement on Subtracted Delta & Residual Patch
        try:
            validate_diff(subtracted_delta_text, canonical_manifest)
            if counterfactual_patch_text:
                validate_diff(counterfactual_patch_text, canonical_manifest)
        except ProtectedSurfaceViolation as exc:
            raise ProtectedSurfaceSubtractionError(
                f"Subtraction delta touches protected surface: {exc}"
            ) from exc

        try:
            validate_no_secrets(subtracted_delta_text, path="subtracted_delta_text")
            if counterfactual_patch_text:
                validate_no_secrets(counterfactual_patch_text, path="counterfactual_patch_text")
        except SecretPersistenceError as exc:
            raise SecretPolicySubtractionError(f"Subtraction delta contains secret: {exc}") from exc

        # 10. Compute Authoritative Cryptographic Digests
        sub_digest = compute_bytes_digest(subtracted_delta_text.encode("utf-8")).value
        cf_digest = compute_bytes_digest(counterfactual_patch_text.encode("utf-8")).value
        rev_digest = compute_bytes_digest(reverse_delta_text.encode("utf-8")).value

        cf_id = f"cf-sub-{request.strategy_type.value.lower()[:8]}-{sub_digest[:16]}"

        return CounterfactualDeltaPlan(
            counterfactual_id=cf_id,
            strategy_type=request.strategy_type,
            target_candidate_id=candidate_id,
            target_candidate_patch_digest=candidate_patch_digest,
            source_commit_id=source_commit_id,
            candidate_tree_digest=candidate_tree_digest,
            frozen_contract_digest=frozen_contract_digest,
            sealed_witness_digest=sealed_witness_digest,
            subtracted_delta_text=subtracted_delta_text,
            subtracted_delta_digest=sub_digest,
            counterfactual_patch_text=counterfactual_patch_text,
            counterfactual_patch_digest=cf_digest,
            reverse_delta_text=reverse_delta_text,
            reverse_delta_digest=rev_digest,
            subtracted_files=tuple(subtracted_files),
            subtracted_hunk_ids=tuple(subtracted_hunk_ids),
            source_locator=source_locator,
            source_subpath=source_subpath,
            is_authoritative=False,
            is_causally_verified=False,
            grants_pass=False,
            description=request.description
            or f"Counterfactual delta plan via {request.strategy_type.value}",
        )

    @classmethod
    def plan_from_snapshot(
        cls,
        *,
        candidate_snapshot: CandidateSnapshot,
        sealed_witness_digest: str,
        request: SubtractionRequest,
    ) -> CounterfactualDeltaPlan:
        """Construct CounterfactualDeltaPlan directly from an immutable CandidateSnapshot."""
        if not isinstance(candidate_snapshot, CandidateSnapshot):
            tname = type(candidate_snapshot).__name__
            raise TypeError(f"candidate_snapshot must be CandidateSnapshot, got {tname}")

        return cls.plan_subtraction(
            candidate_id=candidate_snapshot.candidate_id,
            candidate_patch_text=candidate_snapshot.patch_text,
            candidate_patch_digest=candidate_snapshot.patch_digest,
            candidate_tree_digest=candidate_snapshot.candidate_tree_digest,
            source_commit_id=candidate_snapshot.source_identity.resolved_commit_id,
            source_locator=candidate_snapshot.source_identity.locator,
            source_subpath=candidate_snapshot.source_identity.subpath,
            source_identity=candidate_snapshot.source_identity,
            frozen_contract_digest=candidate_snapshot.frozen_contract_digest,
            sealed_witness_digest=sealed_witness_digest,
            request=request,
        )


# Export canonical module-level aliases
plan_candidate_delta_subtraction = CandidateDeltaSubtractor.plan_subtraction
plan_subtraction_from_snapshot = CandidateDeltaSubtractor.plan_from_snapshot

__all__ = [
    "AmbiguousSubtractionError",
    "CallerAuthorityError",
    "CandidateDeltaSubtractor",
    "CandidateIdentityMismatchError",
    "CandidateSubtractionError",
    "CounterfactualDeltaPlan",
    "DigestTamperingError",
    "EmptySubtractionError",
    "InvalidSubtractionError",
    "ParsedCandidatePatch",
    "ParsedDiffHunk",
    "ParsedFileDiff",
    "ProtectedSurfaceSubtractionError",
    "SecretPolicySubtractionError",
    "SubtractionRequest",
    "SubtractionStrategyType",
    "UnsupportedStrategyError",
    "invert_patch",
    "parse_candidate_patch",
    "plan_candidate_delta_subtraction",
    "plan_subtraction_from_snapshot",
]
