"""Protected-surface manifest and diff validation primitives.

Implements provider-neutral deterministic repository path normalization,
immutable protected-surface manifest contracts, change/diff validation,
symlink boundary verification, and rename/move security checks.

Basebreak causal verification treats candidate repositories and patches as
UNTRUSTED. A candidate patch must not be permitted to mutate protected
governance assets, verification contracts, security policies, or evidence schemas.
"""

from __future__ import annotations

import re
import sys
from collections.abc import Iterable, Sequence
from dataclasses import dataclass
from enum import Enum
from typing import Any

# Pattern matching Windows drive prefix (e.g. "C:", "d:/", "c:\")
_WINDOWS_DRIVE_PATTERN = re.compile(r"^[a-zA-Z]:")

# Forbidden path characters (null bytes, newlines, carriage returns, tabs)
_FORBIDDEN_PATH_CHARS_PATTERN = re.compile(r"[\0\r\n\t]")

# Git diff header patterns - strict unquoted syntax
_GIT_DIFF_HEADER = re.compile(r"^diff --git (?P<old>[^\"\s]+) (?P<new>[^\"\s]+)$")
_GIT_RENAME_FROM = re.compile(r"^rename from (?P<path>[^\"\s]+)$")
_GIT_RENAME_TO = re.compile(r"^rename to (?P<path>[^\"\s]+)$")
_GIT_COPY_FROM = re.compile(r"^copy from (?P<path>[^\"\s]+)$")
_GIT_COPY_TO = re.compile(r"^copy to (?P<path>[^\"\s]+)$")
_GIT_NEW_FILE_MODE = re.compile(r"^new file mode (?P<mode>\d{6})$")
_GIT_DELETED_FILE_MODE = re.compile(r"^deleted file mode (?P<mode>\d{6})$")
_GIT_OLD_MODE = re.compile(r"^old mode (?P<mode>\d{6})$")
_GIT_NEW_MODE = re.compile(r"^new mode (?P<mode>\d{6})$")
_GIT_INDEX_LINE = re.compile(r"^index\s+[0-9a-fA-F]+\.\.[0-9a-fA-F]+(?:\s+(?P<mode>\d{6}))?$")
_GIT_SIMILARITY_INDEX = re.compile(r"^(?:dis)?similarity index \d+%$")
_GIT_BINARY_FILES = re.compile(r"^Binary files (?P<old>[^\"\s]+) and (?P<new>[^\"\s]+) differ$")
_DIFF_OLD_HEADER = re.compile(r"^--- (?P<path>[^\"\s]+)$")
_DIFF_NEW_HEADER = re.compile(r"^\+\+\+ (?P<path>[^\"\s]+)$")


def _posix_dirname(path: str) -> str:
    """Return repository-relative directory component of a normalized path."""
    if "/" in path:
        return path.rsplit("/", 1)[0]
    return ""


def _normalize_unicode(text: str) -> str:
    """Normalize string to Unicode NFC form using stdlib unicodedata."""
    mod = sys.modules.get("unicodedata")
    if mod is None:
        mod = __import__("unicodedata")
    return mod.normalize("NFC", text)  # type: ignore[no-any-return]


# --- Exception Hierarchy ---


class ProtectedSurfaceError(Exception):
    """Base exception for protected-surface policy and path security violations."""


class PathSecurityError(ProtectedSurfaceError):
    """Raised when an untrusted repository path fails security normalization."""


class PathTraversalError(PathSecurityError):
    """Raised when an untrusted path attempts directory traversal or root escape."""


class InvalidPathError(PathSecurityError):
    """Raised when an untrusted path is malformed, empty, or contains forbidden characters."""


class DiffParseError(ProtectedSurfaceError):
    """Raised when candidate diff formatting is malformed, unparseable, or ambiguous."""


class ProtectedSurfaceViolation(ProtectedSurfaceError):
    """Raised when a candidate change touches or attempts to bypass a protected surface.

    Carries machine-readable violation findings without leaking raw confidential text.
    """

    def __init__(
        self,
        message: str,
        findings: Sequence[ProtectedSurfaceFinding] = (),
    ) -> None:
        super().__init__(message)
        self.findings: tuple[ProtectedSurfaceFinding, ...] = tuple(findings)


# --- Enums ---


class FileChangeKind(str, Enum):
    """Type of file modification represented by a candidate change record."""

    ADD = "ADD"
    MODIFY = "MODIFY"
    DELETE = "DELETE"
    RENAME = "RENAME"
    SYMLINK = "SYMLINK"


class ProtectedSurfaceViolationKind(str, Enum):
    """Machine-readable taxonomy of protected-surface violations."""

    EXACT_MATCH = "EXACT_MATCH"
    PREFIX_MATCH = "PREFIX_MATCH"
    CASE_FOLD_MATCH = "CASE_FOLD_MATCH"
    PATH_TRAVERSAL = "PATH_TRAVERSAL"
    INVALID_PATH = "INVALID_PATH"
    RENAME_SOURCE_PROTECTED = "RENAME_SOURCE_PROTECTED"
    RENAME_DESTINATION_PROTECTED = "RENAME_DESTINATION_PROTECTED"
    SYMLINK_TARGET_PROTECTED = "SYMLINK_TARGET_PROTECTED"
    SYMLINK_TARGET_TRAVERSAL = "SYMLINK_TARGET_TRAVERSAL"
    SYMLINK_TARGET_AMBIGUOUS = "SYMLINK_TARGET_AMBIGUOUS"


# --- Data Contracts ---


@dataclass(frozen=True, slots=True)
class FileChange:
    """Deterministic representation of a candidate repository file change.

    Attributes:
        path: Repository-relative target path being added, modified, deleted,
            or the destination of a rename/symlink.
        kind: Type of file modification (default: MODIFY).
        old_path: Original repository path for RENAME operations (None otherwise).
        symlink_target: Target path string for SYMLINK operations (None otherwise).
    """

    path: str
    kind: FileChangeKind = FileChangeKind.MODIFY
    old_path: str | None = None
    symlink_target: str | None = None

    def __post_init__(self) -> None:
        if not isinstance(self.path, str):
            raise TypeError(f"path must be a string, got {type(self.path).__name__}")
        if not isinstance(self.kind, FileChangeKind):
            raise TypeError(f"kind must be a FileChangeKind, got {type(self.kind).__name__}")
        if self.kind == FileChangeKind.RENAME:
            if not self.old_path or not isinstance(self.old_path, str):
                raise ValueError("RENAME change must specify a non-empty old_path string")
        elif self.old_path is not None:
            raise ValueError(f"old_path is forbidden for change kind {self.kind.value}")

        if self.kind == FileChangeKind.SYMLINK:
            if not self.symlink_target or not isinstance(self.symlink_target, str):
                raise ValueError("SYMLINK change must specify a non-empty symlink_target string")
        elif self.symlink_target is not None:
            raise ValueError(f"symlink_target is forbidden for change kind {self.kind.value}")

    @classmethod
    def add(cls, path: str) -> FileChange:
        """Create an ADD file change."""
        return cls(path=path, kind=FileChangeKind.ADD)

    @classmethod
    def modify(cls, path: str) -> FileChange:
        """Create a MODIFY file change."""
        return cls(path=path, kind=FileChangeKind.MODIFY)

    @classmethod
    def delete(cls, path: str) -> FileChange:
        """Create a DELETE file change."""
        return cls(path=path, kind=FileChangeKind.DELETE)

    @classmethod
    def rename(cls, old_path: str, new_path: str) -> FileChange:
        """Create a RENAME file change."""
        return cls(path=new_path, kind=FileChangeKind.RENAME, old_path=old_path)

    @classmethod
    def symlink(cls, path: str, symlink_target: str) -> FileChange:
        """Create a SYMLINK file change."""
        return cls(path=path, kind=FileChangeKind.SYMLINK, symlink_target=symlink_target)

    def to_dict(self) -> dict[str, Any]:
        """Serialize change to a JSON-compatible dictionary."""
        return {
            "path": self.path,
            "kind": self.kind.value,
            "old_path": self.old_path,
            "symlink_target": self.symlink_target,
        }


@dataclass(frozen=True, slots=True)
class ProtectedSurfaceMatch:
    """Result of matching a repository path against a protected surface."""

    matched_path: str
    protected_pattern: str
    is_prefix: bool
    is_case_folded: bool


@dataclass(frozen=True, slots=True)
class ProtectedSurfaceFinding:
    """Deterministic, machine-readable finding recording a policy violation."""

    violation_kind: ProtectedSurfaceViolationKind
    path: str
    protected_pattern: str | None = None
    message: str = ""
    old_path: str | None = None
    symlink_target: str | None = None

    def to_dict(self) -> dict[str, Any]:
        """Serialize finding to a JSON-compatible dictionary."""
        return {
            "violation_kind": self.violation_kind.value,
            "path": self.path,
            "protected_pattern": self.protected_pattern,
            "message": self.message,
            "old_path": self.old_path,
            "symlink_target": self.symlink_target,
        }


@dataclass(frozen=True, slots=True)
class ProtectedSurfaceReport:
    """Summary report from checking changes against a protected-surface manifest."""

    is_valid: bool
    violations: tuple[ProtectedSurfaceFinding, ...]
    checked_changes: int

    def to_dict(self) -> dict[str, Any]:
        """Serialize report to a JSON-compatible dictionary."""
        return {
            "is_valid": self.is_valid,
            "checked_changes": self.checked_changes,
            "violations": [v.to_dict() for v in self.violations],
        }


@dataclass(frozen=True, slots=True)
class ProtectedSurfaceManifest:
    """Immutable manifest expressing repository-relative protected surfaces.

    Attributes:
        exact_files: Set of exact normalized repository-relative file paths
            forbidden from mutation.
        directory_prefixes: Set of normalized repository-relative directory
            prefixes whose descendants are forbidden from mutation.
        description: Non-authoritative explanatory description of the manifest.
    """

    exact_files: frozenset[str]
    directory_prefixes: frozenset[str]
    description: str = ""

    def __post_init__(self) -> None:
        if not isinstance(self.description, str):
            raise TypeError(f"description must be a string, got {type(self.description).__name__}")

        # Validate and normalize exact files
        norm_files: set[str] = set()
        for f in self.exact_files:
            if not isinstance(f, str):
                raise TypeError(f"exact_files entry must be a string, got {type(f).__name__}")
            norm = normalize_repo_path(f)
            norm_files.add(norm)

        # Validate and normalize directory prefixes
        norm_prefixes: set[str] = set()
        for p in self.directory_prefixes:
            if not isinstance(p, str):
                raise TypeError(
                    f"directory_prefixes entry must be a string, got {type(p).__name__}"
                )
            cleaned = p.rstrip("/\\")
            if not cleaned:
                raise InvalidPathError("Directory prefix must not be empty or root slash")
            norm = normalize_repo_path(cleaned)
            norm_prefixes.add(norm)

        object.__setattr__(self, "exact_files", frozenset(norm_files))
        object.__setattr__(self, "directory_prefixes", frozenset(norm_prefixes))

    def to_dict(self) -> dict[str, Any]:
        """Serialize manifest to a JSON-compatible dictionary."""
        return {
            "exact_files": sorted(self.exact_files),
            "directory_prefixes": sorted(self.directory_prefixes),
            "description": self.description,
        }

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> ProtectedSurfaceManifest:
        """Deserialize manifest from a dictionary."""
        if not isinstance(data, dict):
            raise TypeError(f"Expected dict, got {type(data).__name__}")
        exact_files = data.get("exact_files", [])
        if not isinstance(exact_files, (list, tuple, set, frozenset)):
            raise TypeError(f"exact_files must be an iterable, got {type(exact_files).__name__}")
        directory_prefixes = data.get("directory_prefixes", [])
        if not isinstance(directory_prefixes, (list, tuple, set, frozenset)):
            raise TypeError(
                f"directory_prefixes must be an iterable, got {type(directory_prefixes).__name__}"
            )
        description = data.get("description", "")
        if not isinstance(description, str):
            raise TypeError(f"description must be a str, got {type(description).__name__}")
        return cls(
            exact_files=frozenset(str(x) for x in exact_files),
            directory_prefixes=frozenset(str(x) for x in directory_prefixes),
            description=description,
        )


# --- Path Normalization ---


def normalize_repo_path(raw_path: str) -> str:
    """Deterministically normalize an untrusted repository-relative path.

    Fail-closed rules:
    1. Reject non-string inputs with TypeError.
    2. Reject null bytes ('\\0') with InvalidPathError.
    3. Reject empty paths and paths with leading or trailing whitespace with InvalidPathError.
    4. Normalize Unicode to canonical NFC form.
    5. Reject Windows drive letter prefixes (e.g. 'C:', 'd:/') with PathTraversalError.
    6. Reject absolute paths starting with '/' or '\\' with PathTraversalError.
    7. Reject home-directory paths starting with '~' with PathTraversalError.
    8. Unify all path separators (convert '\\' to '/').
    9. Collapse redundant separators ('//') and current-directory '.' segments.
    10. Resolve '..' parent segments logically; reject any attempt to traverse
        above the repository root with PathTraversalError.
    11. Reject paths that resolve to empty or bare root with InvalidPathError.

    Returns:
        Canonical forward-slash separated repository-relative path without
        leading, trailing, or redundant slashes.
    """
    if not isinstance(raw_path, str):
        raise TypeError(f"Path must be a string, got {type(raw_path).__name__}")
    if "\0" in raw_path:
        raise InvalidPathError(f"Path contains forbidden null byte: {raw_path!r}")
    if "\r" in raw_path or "\n" in raw_path or "\t" in raw_path:
        raise InvalidPathError(
            f"Path contains forbidden whitespace or control characters: {raw_path!r}"
        )
    if not raw_path:
        raise InvalidPathError("Path must not be empty")
    if raw_path.strip() != raw_path:
        raise InvalidPathError(f"Path contains leading or trailing whitespace: {raw_path!r}")

    # Canonical Unicode NFC normalization
    normalized = _normalize_unicode(raw_path)

    # Absolute path / drive letter / UNC / home checks
    if _WINDOWS_DRIVE_PATTERN.match(normalized):
        raise PathTraversalError(f"Absolute path with drive letter is forbidden: {raw_path!r}")
    if normalized.startswith(("/", "\\")):
        raise PathTraversalError(f"Absolute path starting with slash is forbidden: {raw_path!r}")
    if normalized.startswith("~"):
        raise PathTraversalError(f"Home directory path is forbidden: {raw_path!r}")

    # Treat backslashes as path separators for untrusted/hostile input
    unified = normalized.replace("\\", "/")

    # Process segments logically
    segments = unified.split("/")
    stack: list[str] = []

    for seg in segments:
        if not seg or seg == ".":
            continue
        if seg == "..":
            if not stack:
                raise PathTraversalError(f"Path traverses above repository root: {raw_path!r}")
            stack.pop()
        else:
            stack.append(seg)

    if not stack:
        raise InvalidPathError(f"Path resolves to empty repository root: {raw_path!r}")

    return "/".join(stack)


# --- Protected Matching ---


def match_protected_surface(
    normalized_path: str,
    manifest: ProtectedSurfaceManifest,
) -> ProtectedSurfaceMatch | None:
    """Evaluate whether a normalized path matches any protected surface in manifest.

    Canonical Matching Rules:
    1. Case-sensitive exact match: path equals an exact protected file.
    2. Case-sensitive prefix match: path equals a protected directory or is
       strictly underneath it (path.startswith(prefix + "/")).
    3. Case-folded exact match: path.casefold() equals exact_file.casefold(),
       preventing case-normalization bypass across case-insensitive filesystems.
    4. Case-folded prefix match: path.casefold() is underneath prefix.casefold(),
       preventing case-variant directory bypass.

    Returns:
        ProtectedSurfaceMatch if matched, None otherwise.
    """
    # 1. Case-sensitive exact match
    if normalized_path in manifest.exact_files:
        return ProtectedSurfaceMatch(
            matched_path=normalized_path,
            protected_pattern=normalized_path,
            is_prefix=False,
            is_case_folded=False,
        )

    # 2. Case-sensitive prefix match
    for prefix in manifest.directory_prefixes:
        if normalized_path == prefix or normalized_path.startswith(prefix + "/"):
            return ProtectedSurfaceMatch(
                matched_path=normalized_path,
                protected_pattern=prefix,
                is_prefix=True,
                is_case_folded=False,
            )

    norm_cf = normalized_path.casefold()

    # 3. Case-folded exact match
    for exact in manifest.exact_files:
        if norm_cf == exact.casefold():
            return ProtectedSurfaceMatch(
                matched_path=normalized_path,
                protected_pattern=exact,
                is_prefix=False,
                is_case_folded=True,
            )

    # 4. Case-folded prefix match
    for prefix in manifest.directory_prefixes:
        prefix_cf = prefix.casefold()
        if norm_cf == prefix_cf or norm_cf.startswith(prefix_cf + "/"):
            return ProtectedSurfaceMatch(
                matched_path=normalized_path,
                protected_pattern=prefix,
                is_prefix=True,
                is_case_folded=True,
            )

    return None


def is_path_protected(raw_path: str, manifest: ProtectedSurfaceManifest) -> bool:
    """Return True if raw_path normalizes to or matches a protected surface.

    If raw_path fails normalization, returns False (path security errors are
    handled distinctly by validation functions).
    """
    try:
        norm = normalize_repo_path(raw_path)
    except PathSecurityError:
        return False
    return match_protected_surface(norm, manifest) is not None


def validate_path(raw_path: str, manifest: ProtectedSurfaceManifest) -> str:
    """Validate a single path against path security and protected surfaces.

    Normalizes the path, rejects path security / traversal issues, and
    rejects protected-surface matches with ProtectedSurfaceViolation.

    Returns:
        The normalized repository-relative path if safe and unprotected.
    """
    norm = normalize_repo_path(raw_path)
    match = match_protected_surface(norm, manifest)
    if match is not None:
        vkind = (
            ProtectedSurfaceViolationKind.CASE_FOLD_MATCH
            if match.is_case_folded
            else (
                ProtectedSurfaceViolationKind.PREFIX_MATCH
                if match.is_prefix
                else ProtectedSurfaceViolationKind.EXACT_MATCH
            )
        )
        finding = ProtectedSurfaceFinding(
            violation_kind=vkind,
            path=norm,
            protected_pattern=match.protected_pattern,
            message=(
                f"Path '{norm}' touches protected surface '{match.protected_pattern}' "
                f"[{'prefix' if match.is_prefix else 'exact'}"
                f"{', case-folded' if match.is_case_folded else ''}]"
            ),
        )
        raise ProtectedSurfaceViolation(
            f"Protected surface violation: {finding.message}",
            findings=(finding,),
        )
    return norm


# --- Change & Diff Validation ---


def _check_symlink(
    change: FileChange,
    manifest: ProtectedSurfaceManifest,
) -> list[ProtectedSurfaceFinding]:
    """Conservatively validate a symlink change against traversal and protected surfaces.

    Fail-closed rules:
    - Symlink's own path must normalize safely and not be a protected surface.
    - Symlink target must not be absolute (no '/', '\\', 'C:', '~').
    - Symlink target resolved logically from the symlink's containing directory
      must not traverse above repository root.
    - Symlink target resolved logically must not point to or into a protected surface.
    - If target is empty, contains whitespace or null bytes, reject as invalid/ambiguous.
    """
    findings: list[ProtectedSurfaceFinding] = []

    # 1. Validate symlink's own location in repo
    try:
        norm_path = normalize_repo_path(change.path)
    except PathTraversalError as e:
        findings.append(
            ProtectedSurfaceFinding(
                violation_kind=ProtectedSurfaceViolationKind.PATH_TRAVERSAL,
                path=change.path,
                message=f"Symlink path traverses repository root: {e}",
            )
        )
        return findings
    except InvalidPathError as e:
        findings.append(
            ProtectedSurfaceFinding(
                violation_kind=ProtectedSurfaceViolationKind.INVALID_PATH,
                path=change.path,
                message=f"Symlink path is invalid: {e}",
            )
        )
        return findings

    path_match = match_protected_surface(norm_path, manifest)
    if path_match is not None:
        vkind = (
            ProtectedSurfaceViolationKind.CASE_FOLD_MATCH
            if path_match.is_case_folded
            else (
                ProtectedSurfaceViolationKind.PREFIX_MATCH
                if path_match.is_prefix
                else ProtectedSurfaceViolationKind.EXACT_MATCH
            )
        )
        findings.append(
            ProtectedSurfaceFinding(
                violation_kind=vkind,
                path=norm_path,
                protected_pattern=path_match.protected_pattern,
                message=(f"Symlink creation at protected surface '{path_match.protected_pattern}'"),
            )
        )

    # 2. Validate symlink target
    target = change.symlink_target
    if not isinstance(target, str) or not target:
        findings.append(
            ProtectedSurfaceFinding(
                violation_kind=ProtectedSurfaceViolationKind.SYMLINK_TARGET_AMBIGUOUS,
                path=norm_path,
                symlink_target=str(target) if target is not None else None,
                message="Symlink target must be a non-empty string",
            )
        )
        return findings

    if target.strip() != target or "\0" in target:
        findings.append(
            ProtectedSurfaceFinding(
                violation_kind=ProtectedSurfaceViolationKind.SYMLINK_TARGET_AMBIGUOUS,
                path=norm_path,
                symlink_target=target,
                message="Symlink target contains forbidden whitespace or null bytes",
            )
        )
        return findings

    # Check for absolute symlink target
    target_norm = _normalize_unicode(target)
    if (
        _WINDOWS_DRIVE_PATTERN.match(target_norm)
        or target_norm.startswith(("/", "\\"))
        or target_norm.startswith("~")
    ):
        findings.append(
            ProtectedSurfaceFinding(
                violation_kind=ProtectedSurfaceViolationKind.SYMLINK_TARGET_TRAVERSAL,
                path=norm_path,
                symlink_target=target,
                message=f"Symlink target is absolute or escapes repository root: {target!r}",
            )
        )
        return findings

    # Resolve relative symlink target from symlink's containing directory
    parent_dir = _posix_dirname(norm_path)
    combined = f"{parent_dir}/{target}" if parent_dir else target

    try:
        resolved_target = normalize_repo_path(combined)
    except PathTraversalError as e:
        findings.append(
            ProtectedSurfaceFinding(
                violation_kind=ProtectedSurfaceViolationKind.SYMLINK_TARGET_TRAVERSAL,
                path=norm_path,
                symlink_target=target,
                message=f"Symlink target traverses above repository root: {e}",
            )
        )
        return findings
    except InvalidPathError as e:
        findings.append(
            ProtectedSurfaceFinding(
                violation_kind=ProtectedSurfaceViolationKind.SYMLINK_TARGET_AMBIGUOUS,
                path=norm_path,
                symlink_target=target,
                message=f"Symlink target path is invalid: {e}",
            )
        )
        return findings

    # Check if logically resolved target reaches a protected surface
    target_match = match_protected_surface(resolved_target, manifest)
    if target_match is not None:
        findings.append(
            ProtectedSurfaceFinding(
                violation_kind=ProtectedSurfaceViolationKind.SYMLINK_TARGET_PROTECTED,
                path=norm_path,
                protected_pattern=target_match.protected_pattern,
                symlink_target=target,
                message=(
                    f"Symlink target '{target}' resolves logically to protected surface "
                    f"'{target_match.protected_pattern}' (resolved: '{resolved_target}')"
                ),
            )
        )

    return findings


def _check_rename(
    change: FileChange,
    manifest: ProtectedSurfaceManifest,
) -> list[ProtectedSurfaceFinding]:
    """Validate a RENAME change against path security and protected surfaces.

    Both old_path (source) and path (destination) must be checked:
    - Old path cannot touch a protected surface (cannot move away / replace protected asset).
    - New path cannot touch a protected surface (cannot overwrite protected asset).
    - Neither path may traverse or be malformed.
    """
    findings: list[ProtectedSurfaceFinding] = []
    assert change.old_path is not None

    # Check old_path (source)
    try:
        norm_old = normalize_repo_path(change.old_path)
        match_old = match_protected_surface(norm_old, manifest)
        if match_old is not None:
            findings.append(
                ProtectedSurfaceFinding(
                    violation_kind=ProtectedSurfaceViolationKind.RENAME_SOURCE_PROTECTED,
                    path=change.path,
                    old_path=norm_old,
                    protected_pattern=match_old.protected_pattern,
                    message=(
                        f"Rename source '{norm_old}' touches protected surface "
                        f"'{match_old.protected_pattern}'"
                    ),
                )
            )
    except PathTraversalError as e:
        findings.append(
            ProtectedSurfaceFinding(
                violation_kind=ProtectedSurfaceViolationKind.PATH_TRAVERSAL,
                path=change.old_path,
                message=f"Rename old_path traverses repository root: {e}",
            )
        )
    except InvalidPathError as e:
        findings.append(
            ProtectedSurfaceFinding(
                violation_kind=ProtectedSurfaceViolationKind.INVALID_PATH,
                path=change.old_path,
                message=f"Rename old_path is invalid: {e}",
            )
        )

    # Check path (destination)
    try:
        norm_new = normalize_repo_path(change.path)
        match_new = match_protected_surface(norm_new, manifest)
        if match_new is not None:
            findings.append(
                ProtectedSurfaceFinding(
                    violation_kind=ProtectedSurfaceViolationKind.RENAME_DESTINATION_PROTECTED,
                    path=norm_new,
                    old_path=change.old_path,
                    protected_pattern=match_new.protected_pattern,
                    message=(
                        f"Rename destination '{norm_new}' touches protected surface "
                        f"'{match_new.protected_pattern}'"
                    ),
                )
            )
    except PathTraversalError as e:
        findings.append(
            ProtectedSurfaceFinding(
                violation_kind=ProtectedSurfaceViolationKind.PATH_TRAVERSAL,
                path=change.path,
                message=f"Rename destination traverses repository root: {e}",
            )
        )
    except InvalidPathError as e:
        findings.append(
            ProtectedSurfaceFinding(
                violation_kind=ProtectedSurfaceViolationKind.INVALID_PATH,
                path=change.path,
                message=f"Rename destination is invalid: {e}",
            )
        )

    return findings


def check_change(
    change: FileChange,
    manifest: ProtectedSurfaceManifest,
) -> list[ProtectedSurfaceFinding]:
    """Check a single FileChange against protected surfaces and path security rules.

    Returns:
        List of ProtectedSurfaceFinding records (empty if safe).
    """
    if change.kind == FileChangeKind.SYMLINK:
        return _check_symlink(change, manifest)

    if change.kind == FileChangeKind.RENAME:
        return _check_rename(change, manifest)

    findings: list[ProtectedSurfaceFinding] = []
    try:
        norm_path = normalize_repo_path(change.path)
    except PathTraversalError as e:
        findings.append(
            ProtectedSurfaceFinding(
                violation_kind=ProtectedSurfaceViolationKind.PATH_TRAVERSAL,
                path=change.path,
                message=f"Path traverses repository root: {e}",
            )
        )
        return findings
    except InvalidPathError as e:
        findings.append(
            ProtectedSurfaceFinding(
                violation_kind=ProtectedSurfaceViolationKind.INVALID_PATH,
                path=change.path,
                message=f"Path is invalid: {e}",
            )
        )
        return findings

    match = match_protected_surface(norm_path, manifest)
    if match is not None:
        vkind = (
            ProtectedSurfaceViolationKind.CASE_FOLD_MATCH
            if match.is_case_folded
            else (
                ProtectedSurfaceViolationKind.PREFIX_MATCH
                if match.is_prefix
                else ProtectedSurfaceViolationKind.EXACT_MATCH
            )
        )
        findings.append(
            ProtectedSurfaceFinding(
                violation_kind=vkind,
                path=norm_path,
                protected_pattern=match.protected_pattern,
                message=(
                    f"Mutation [{change.kind.value}] touches protected surface "
                    f"'{match.protected_pattern}' (path: '{norm_path}')"
                ),
            )
        )

    return findings


def check_protected_surfaces(
    changes: Iterable[FileChange | str],
    manifest: ProtectedSurfaceManifest,
) -> ProtectedSurfaceReport:
    """Inspect changes against protected surfaces without raising exceptions.

    Accepts an iterable of FileChange objects or raw path strings (strings are
    treated as FileChange.modify(path)).

    Returns:
        ProtectedSurfaceReport containing machine-readable findings and validation status.
    """
    findings: list[ProtectedSurfaceFinding] = []
    count = 0

    for item in changes:
        count += 1
        if isinstance(item, str):
            change = FileChange.modify(item)
        elif isinstance(item, FileChange):
            change = item
        else:
            raise TypeError(f"Expected FileChange or str, got {type(item).__name__}")
        findings.extend(check_change(change, manifest))

    return ProtectedSurfaceReport(
        is_valid=len(findings) == 0,
        violations=tuple(findings),
        checked_changes=count,
    )


def validate_protected_surfaces(
    changes: Iterable[FileChange | str],
    manifest: ProtectedSurfaceManifest,
) -> ProtectedSurfaceReport:
    """Validate changes against protected surfaces and fail closed on any violation.

    Accepts an iterable of FileChange objects or raw path strings.

    Raises:
        ProtectedSurfaceViolation: If any change violates path security or
            touches a protected surface.

    Returns:
        ProtectedSurfaceReport if all changes are safe and unprotected.
    """
    report = check_protected_surfaces(changes, manifest)
    if not report.is_valid:
        first = report.violations[0]
        raise ProtectedSurfaceViolation(
            f"Protected surface violation [{first.violation_kind.value}]: {first.message} "
            f"({len(report.violations)} total violation(s))",
            findings=report.violations,
        )
    return report


# --- Unified Diff Parser ---


def _strip_git_diff_prefix(path: str) -> str:
    """Strip 'a/' or 'b/' prefix from a git diff path header if present."""
    if path.startswith(("a/", "b/")) and len(path) > 2:
        return path[2:]
    return path


def _skip_hunk_lines(lines: list[str], start_idx: int) -> int:
    """Advance line index past valid hunk lines until next section or EOF.

    Raises DiffParseError if unparseable or malformed content is encountered.
    """
    i = start_idx
    while i < len(lines):
        if lines[i].startswith("diff --git"):
            break
        if lines[i].startswith("---") and (i + 1 < len(lines) and lines[i + 1].startswith("+++")):
            break
        if lines[i].startswith((" ", "+", "-", "\\", "@@")) or lines[i] == "":
            i += 1
        else:
            raise DiffParseError(f"Malformed diff hunk line or unexpected content: {lines[i]!r}")
    return i


def parse_unified_diff_changes(diff_text: str) -> list[FileChange]:
    """Parse candidate file changes from unified diff text.

    Supports standard unified diffs, Git extended diffs (renames, modes,
    mode 120000 symlinks, additions from /dev/null, deletions to /dev/null).

    Fail-closed security invariants:
    - Empty or whitespace-only diff produces 0 changes.
    - Non-empty diff must produce at least one recognized file change or raise DiffParseError.
    - Lines starting with 'diff --git' must strictly match two supported unquoted path tokens,
      or raise DiffParseError.
    - Inside git sections, lines starting with '---' or '+++' must strictly match supported
      unquoted path tokens or '/dev/null', or raise DiffParseError.
    - Quoted path forms and internal whitespace in git path headers are unsupported and
      fail closed with DiffParseError.
    - Every file section must produce exactly one FileChange; malformed sections or headers
      fail closed with DiffParseError without silently skipping sections.
    - Non-git unified diffs must strictly match '---' and '+++' headers; malformed or orphaned
      headers fail closed with DiffParseError.
    """
    if not isinstance(diff_text, str):
        raise TypeError(f"diff_text must be a string, got {type(diff_text).__name__}")

    if not diff_text.strip():
        return []

    lines = [ln.rstrip("\r\n") for ln in diff_text.splitlines()]
    changes: list[FileChange] = []

    i = 0
    while i < len(lines):
        line = lines[i]

        # Ignore empty lines between sections
        if not line.strip():
            i += 1
            continue

        # Case 1: Git diff header: diff --git <old> <new>
        if line.startswith("diff --git"):
            m_git = _GIT_DIFF_HEADER.match(line)
            if not m_git:
                raise DiffParseError(
                    f"Unsupported or malformed git diff header: {line!r}. "
                    "Quoted paths and paths with spaces are not supported."
                )

            raw_old = _strip_git_diff_prefix(m_git.group("old"))
            raw_new = _strip_git_diff_prefix(m_git.group("new"))
            if not raw_old or not raw_new or raw_old in ("a/", "b/") or raw_new in ("a/", "b/"):
                raise DiffParseError(f"Empty path in git diff header: {line!r}")

            i += 1

            new_file_mode: str | None = None
            deleted_file_mode: str | None = None
            _old_mode: str | None = None
            new_mode: str | None = None
            index_mode: str | None = None
            rename_from: str | None = None
            rename_to: str | None = None
            diff_old_header: str | None = None
            diff_new_header: str | None = None

            # Scan extended git headers until next hunk or next file diff
            while i < len(lines) and not lines[i].startswith("diff --git"):
                hdr = lines[i]

                if hdr.startswith("@@ "):
                    # Reached hunk header
                    break

                if hdr.startswith("new file mode "):
                    if m_nfm := _GIT_NEW_FILE_MODE.match(hdr):
                        new_file_mode = m_nfm.group("mode")
                    else:
                        raise DiffParseError(f"Malformed new file mode header: {hdr!r}")
                elif hdr.startswith("deleted file mode "):
                    if m_dfm := _GIT_DELETED_FILE_MODE.match(hdr):
                        deleted_file_mode = m_dfm.group("mode")
                    else:
                        raise DiffParseError(f"Malformed deleted file mode header: {hdr!r}")
                elif hdr.startswith("old mode "):
                    if m_om := _GIT_OLD_MODE.match(hdr):
                        _old_mode = m_om.group("mode")
                    else:
                        raise DiffParseError(f"Malformed old mode header: {hdr!r}")
                elif hdr.startswith("new mode "):
                    if m_nm := _GIT_NEW_MODE.match(hdr):
                        new_mode = m_nm.group("mode")
                    else:
                        raise DiffParseError(f"Malformed new mode header: {hdr!r}")
                elif hdr.startswith("index "):
                    if m_idx := _GIT_INDEX_LINE.match(hdr):
                        index_mode = m_idx.group("mode")
                    else:
                        raise DiffParseError(f"Malformed index line: {hdr!r}")
                elif hdr.startswith("rename from"):
                    if m_rf := _GIT_RENAME_FROM.match(hdr):
                        rename_from = m_rf.group("path")
                    else:
                        raise DiffParseError(
                            f"Unsupported or malformed rename from header: {hdr!r}"
                        )
                elif hdr.startswith("rename to"):
                    if m_rt := _GIT_RENAME_TO.match(hdr):
                        rename_to = m_rt.group("path")
                    else:
                        raise DiffParseError(f"Unsupported or malformed rename to header: {hdr!r}")
                elif hdr.startswith("similarity index ") or hdr.startswith("dissimilarity index "):
                    if not _GIT_SIMILARITY_INDEX.match(hdr):
                        raise DiffParseError(f"Malformed similarity index header: {hdr!r}")
                elif hdr.startswith("copy from"):
                    if not _GIT_COPY_FROM.match(hdr):
                        raise DiffParseError(f"Unsupported or malformed copy from header: {hdr!r}")
                elif hdr.startswith("copy to"):
                    if not _GIT_COPY_TO.match(hdr):
                        raise DiffParseError(f"Unsupported or malformed copy to header: {hdr!r}")
                elif hdr.startswith("---"):
                    if m_do := _DIFF_OLD_HEADER.match(hdr):
                        diff_old_header = m_do.group("path")
                    else:
                        raise DiffParseError(f"Unsupported or malformed --- path header: {hdr!r}")
                elif hdr.startswith("+++"):
                    if m_dn := _DIFF_NEW_HEADER.match(hdr):
                        diff_new_header = m_dn.group("path")
                    else:
                        raise DiffParseError(f"Unsupported or malformed +++ path header: {hdr!r}")
                elif hdr.startswith("Binary files "):
                    if m_bin := _GIT_BINARY_FILES.match(hdr):
                        diff_old_header = m_bin.group("old")
                        diff_new_header = m_bin.group("new")
                    else:
                        raise DiffParseError(
                            f"Unsupported or malformed Binary files header: {hdr!r}"
                        )
                elif (
                    hdr == "GIT binary patch"
                    or hdr.startswith("literal ")
                    or hdr.startswith("delta ")
                    or hdr == r"\ No newline at end of file"
                ):
                    pass
                elif not hdr.strip():
                    pass
                else:
                    raise DiffParseError(
                        f"Unsupported or malformed extended git diff header: {hdr!r}"
                    )

                i += 1

            if (rename_from is None) != (rename_to is None):
                raise DiffParseError(
                    "Incomplete rename in git diff: rename from without rename to or vice versa"
                )

            # 1. Handle deletion (deleted file mode or +++ /dev/null)
            if deleted_file_mode is not None or diff_new_header == "/dev/null":
                clean_old = (
                    _strip_git_diff_prefix(diff_old_header)
                    if diff_old_header and diff_old_header != "/dev/null"
                    else raw_old
                )
                if not clean_old:
                    raise DiffParseError("Empty path for deleted file in git diff")
                changes.append(FileChange.delete(clean_old))
                i = _skip_hunk_lines(lines, i)
                continue

            # 2. Determine resulting file mode
            resulting_mode: str | None = None
            if new_file_mode is not None:
                resulting_mode = new_file_mode
            elif new_mode is not None:
                resulting_mode = new_mode
            elif index_mode is not None:
                resulting_mode = index_mode

            resulting_is_symlink = resulting_mode == "120000"

            # 3. Handle resulting symlink (new, modified target, or converted to symlink)
            if resulting_is_symlink:
                target_path = (
                    _strip_git_diff_prefix(diff_new_header)
                    if diff_new_header and diff_new_header != "/dev/null"
                    else raw_new
                )
                if not target_path:
                    raise DiffParseError("Empty path for symlink in git diff")

                added_targets: list[str] = []
                while i < len(lines):
                    if lines[i].startswith("diff --git"):
                        break
                    if lines[i].startswith("---") and (
                        i + 1 < len(lines) and lines[i + 1].startswith("+++")
                    ):
                        break
                    hunk_line = lines[i]
                    if hunk_line.startswith("+") and not hunk_line.startswith("+++"):
                        added_targets.append(hunk_line[1:])
                    elif not hunk_line.startswith((" ", "-", "\\", "@@")) and hunk_line != "":
                        raise DiffParseError(f"Malformed symlink hunk line: {hunk_line!r}")
                    i += 1

                if len(added_targets) == 1:
                    target = added_targets[0]
                    if not target:
                        raise DiffParseError(
                            f"Empty symlink target for '{target_path}': "
                            "resulting mode is 120000 but added target payload is empty"
                        )
                    changes.append(FileChange.symlink(path=target_path, symlink_target=target))
                    continue
                elif len(added_targets) > 1:
                    raise DiffParseError(
                        f"Malformed symlink diff for '{target_path}': "
                        f"expected exactly 1 target line, found {len(added_targets)}"
                    )
                else:
                    raise DiffParseError(
                        f"Unparseable symlink target for '{target_path}': "
                        "resulting state is mode 120000 but no added target line found in diff"
                    )

            # 4. Handle rename
            if rename_from is not None and rename_to is not None:
                clean_from = _strip_git_diff_prefix(rename_from)
                clean_to = _strip_git_diff_prefix(rename_to)
                if not clean_from or not clean_to:
                    raise DiffParseError("Empty path in rename headers")
                changes.append(FileChange.rename(old_path=clean_from, new_path=clean_to))
                i = _skip_hunk_lines(lines, i)
                continue

            # 5. Handle addition (--- /dev/null +++ b/path or new file mode)
            if diff_old_header == "/dev/null" and diff_new_header:
                clean_new = _strip_git_diff_prefix(diff_new_header)
                if not clean_new:
                    raise DiffParseError("Empty path for added file in git diff")
                changes.append(FileChange.add(clean_new))
                i = _skip_hunk_lines(lines, i)
                continue

            if new_file_mode is not None:
                clean_new = (
                    _strip_git_diff_prefix(diff_new_header)
                    if diff_new_header and diff_new_header != "/dev/null"
                    else raw_new
                )
                if not clean_new:
                    raise DiffParseError("Empty path for added file in git diff")
                changes.append(FileChange.add(clean_new))
                i = _skip_hunk_lines(lines, i)
                continue

            # 6. Handle standard modify
            effective_path = (
                _strip_git_diff_prefix(diff_new_header)
                if diff_new_header and diff_new_header != "/dev/null"
                else raw_new
            )
            if not effective_path:
                raise DiffParseError("Empty path for modified file in git diff")
            changes.append(FileChange.modify(effective_path))
            i = _skip_hunk_lines(lines, i)
            continue

        # Case 2: Non-git unified diff headers: --- a/path \n +++ b/path
        if line.startswith("---"):
            m_old = _DIFF_OLD_HEADER.match(line)
            if not m_old:
                raise DiffParseError(
                    f"Unsupported or malformed --- diff header: {line!r}. "
                    "Quoted paths and paths with spaces are not supported."
                )

            if (i + 1) >= len(lines):
                raise DiffParseError(
                    "Incomplete unified diff: --- header without +++ header at end of diff: "
                    f"{line!r}"
                )

            next_line = lines[i + 1]
            if not next_line.startswith("+++"):
                raise DiffParseError(
                    f"Incomplete unified diff: expected +++ header after ---, got: {next_line!r}"
                )

            m_new = _DIFF_NEW_HEADER.match(next_line)
            if not m_new:
                raise DiffParseError(
                    f"Unsupported or malformed +++ diff header: {next_line!r}. "
                    "Quoted paths and paths with spaces are not supported."
                )

            old_h = m_old.group("path")
            new_h = m_new.group("path")
            i += 2

            if old_h == "/dev/null" and new_h == "/dev/null":
                raise DiffParseError("Invalid diff: both --- and +++ are /dev/null")

            if old_h == "/dev/null":
                path = _strip_git_diff_prefix(new_h)
                if not path:
                    raise DiffParseError("Empty path in +++ header")
                changes.append(FileChange.add(path))
            elif new_h == "/dev/null":
                path = _strip_git_diff_prefix(old_h)
                if not path:
                    raise DiffParseError("Empty path in --- header")
                changes.append(FileChange.delete(path))
            else:
                path = _strip_git_diff_prefix(new_h)
                if not path:
                    raise DiffParseError("Empty path in +++ header")
                changes.append(FileChange.modify(path))

            i = _skip_hunk_lines(lines, i)
            continue

        # Case 3: Orphaned +++ header without preceding ---
        if line.startswith("+++"):
            raise DiffParseError(f"Orphaned or malformed +++ diff header: {line!r}")

        # Case 4: Any other unexpected content outside a recognized section
        raise DiffParseError(f"Unrecognized or unsupported diff content: {line!r}")

    if not changes:
        raise DiffParseError("Non-empty diff text yielded 0 recognized file changes")

    return changes


def validate_diff(
    diff_text: str,
    manifest: ProtectedSurfaceManifest,
) -> ProtectedSurfaceReport:
    """Parse and validate unified diff text against protected surfaces.

    Raises:
        ProtectedSurfaceViolation: If any parsed change violates path security
            or touches a protected surface.

    Returns:
        ProtectedSurfaceReport if all changes in the diff are safe and unprotected.
    """
    changes = parse_unified_diff_changes(diff_text)
    return validate_protected_surfaces(changes, manifest)


# --- Canonical Basebreak Protected Surfaces ---


def get_canonical_basebreak_protected_manifest() -> ProtectedSurfaceManifest:
    """Construct the canonical protected-surface manifest from committed Basebreak truth.

    Surfaces are derived strictly from currently committed governance authority
    without inventing speculative future P-08/P-09 witness paths:

    Exact files:
    - AGENTS.md: Constitutional governance spine and coding-agent laws.
    - plans/BASEBREAK_MASTER_EXECUTION_PLAN.md: Master plan and phase allowlists.
    - docs/SECURITY_BOUNDARY.md: Target-repository threat model & security invariants.
    - docs/DONOR_MANIFEST.md: Donor research pins and clean-room provenance.
    - docs/OPERATOR_REQUIREMENTS.md: Operator billing safeguards & Zero-Cost Law.
    - docs/COMPETITION_FEEDBACK_LOG.md: Verified platform feedback log.

    Directory prefixes:
    - src/basebreak/domain: Frozen provider-neutral domain contracts (P-02 closed).
    - src/basebreak/evidence: Frozen deterministic fact authority & evidence store (P-03 closed).
    - src/basebreak/security: Security policy and redaction primitives.
    """
    return ProtectedSurfaceManifest(
        exact_files=frozenset(
            {
                "AGENTS.md",
                "plans/BASEBREAK_MASTER_EXECUTION_PLAN.md",
                "docs/SECURITY_BOUNDARY.md",
                "docs/DONOR_MANIFEST.md",
                "docs/OPERATOR_REQUIREMENTS.md",
                "docs/COMPETITION_FEEDBACK_LOG.md",
            }
        ),
        directory_prefixes=frozenset(
            {
                "src/basebreak/domain",
                "src/basebreak/evidence",
                "src/basebreak/security",
            }
        ),
        description=(
            "Canonical Basebreak repository protected surfaces derived "
            "from committed governance authority."
        ),
    )
