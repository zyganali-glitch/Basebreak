"""Repository and source identity domain contracts.

Basebreak evidence must always bind to an exact canonical source identity
and exact immutable revision, never merely mutable workspace paths, branch
names, or Builder prose.
"""

from __future__ import annotations

import re
from dataclasses import dataclass

_HEX_CHARS = frozenset("0123456789abcdef")
_WINDOWS_DRIVE_PATTERN = re.compile(r"^[a-zA-Z]:[\\/]")


@dataclass(frozen=True, slots=True)
class CommitRevision:
    """Immutable resolved Git commit revision.

    Authoritatively binds to a resolved 40-character (SHA-1) or 64-character (SHA-256)
    hexadecimal commit identity. Mutable refs (e.g. 'main', 'HEAD', branch names)
    are strictly rejected.
    """

    commit_id: str

    def __post_init__(self) -> None:
        if not isinstance(self.commit_id, str):
            raise TypeError(f"commit_id must be a string, got {type(self.commit_id).__name__}")
        if not self.commit_id:
            raise ValueError("commit_id must not be empty")
        if self.commit_id.strip() != self.commit_id:
            raise ValueError("commit_id must not contain leading or trailing whitespace")
        if len(self.commit_id) not in (40, 64):
            msg = (
                f"commit_id must be a 40 or 64-character hexadecimal string, "
                f"got {self.commit_id!r} (length {len(self.commit_id)})"
            )
            raise ValueError(msg)
        if not set(self.commit_id).issubset(_HEX_CHARS):
            raise ValueError(
                "commit_id must consist strictly of lowercase hexadecimal characters [0-9a-f], "
                f"got {self.commit_id!r}"
            )

    def __str__(self) -> str:
        return self.commit_id


@dataclass(frozen=True, slots=True)
class RequestedRef:
    """Non-authoritative requested human reference for auditability.

    Represents what was requested (e.g., branch name, tag, 'main'), but cannot
    substitute for an authoritative resolved CommitRevision.
    """

    name: str

    def __post_init__(self) -> None:
        if not isinstance(self.name, str):
            raise TypeError(f"name must be a string, got {type(self.name).__name__}")
        cleaned = self.name.strip()
        if not cleaned:
            raise ValueError("Requested ref name must not be empty")
        if cleaned != self.name:
            raise ValueError("Requested ref name must not contain leading or trailing whitespace")

    def __str__(self) -> str:
        return self.name


def _validate_locator(locator: str) -> None:
    """Validate canonical source locator."""
    if not isinstance(locator, str):
        raise TypeError(f"locator must be a string, got {type(locator).__name__}")
    if not locator or not locator.strip():
        raise ValueError("Source locator must not be empty")
    if locator.strip() != locator:
        raise ValueError("Source locator must not contain leading or trailing whitespace")

    # Reject mutable checked-out workspace paths
    if locator.startswith(("./", ".\\", "../", "..\\", "/", "\\", "~")):
        msg = (
            f"Source locator must represent source identity, "
            f"not a mutable workspace path: {locator!r}"
        )
        raise ValueError(msg)
    if _WINDOWS_DRIVE_PATTERN.match(locator):
        raise ValueError(
            f"Source locator must represent source identity, not a local drive path: {locator!r}"
        )
    if "/../" in locator or "\\..\\" in locator or locator.endswith(("/..", "\\..")):
        raise ValueError(f"Source locator must not contain path traversal segments: {locator!r}")

    # Reject embedded credentials/secrets in URLs
    if "://" in locator:
        _, remainder = locator.split("://", 1)
        authority = remainder.split("/", 1)[0]
        if "@" in authority:
            raise ValueError(
                f"Source locator must not contain embedded credentials/secrets: {locator!r}"
            )
    elif "@" in locator:
        # scp-style: user@host:repo (e.g. git@github.com:org/repo.git)
        # Disallow password or token embedded in userinfo: user:pass@...
        userinfo = locator.split("@", 1)[0]
        if ":" in userinfo:
            raise ValueError(
                f"Source locator must not contain embedded credentials/secrets: {locator!r}"
            )


def _validate_subpath(subpath: str | None) -> None:
    """Validate optional repository-relative subpath."""
    if subpath is None:
        return
    if not isinstance(subpath, str):
        raise TypeError(f"subpath must be a string or None, got {type(subpath).__name__}")
    if not subpath.strip():
        raise ValueError("Subpath must not be empty if specified")
    if subpath.strip() != subpath:
        raise ValueError("Subpath must not contain leading or trailing whitespace")
    if subpath.startswith(("/", "\\", "./", ".\\", "../", "..\\")):
        msg = f"Subpath must be repository-relative and not start with slash or prefix: {subpath!r}"
        raise ValueError(msg)
    if "/../" in subpath or "\\..\\" in subpath or subpath.endswith(("/..", "\\..")):
        raise ValueError(f"Subpath must not contain path traversal: {subpath!r}")


@dataclass(frozen=True, slots=True)
class SourceIdentity:
    """Canonical repository/source identity bound to an immutable resolved revision.

    Combines a canonical source locator, an authoritative resolved CommitRevision,
    an optional repository-relative subpath, and an optional non-authoritative requested ref.
    """

    locator: str
    revision: CommitRevision
    subpath: str | None = None
    requested_ref: RequestedRef | None = None

    def __post_init__(self) -> None:
        _validate_locator(self.locator)
        if not isinstance(self.revision, CommitRevision):
            rev_type = type(self.revision).__name__
            raise TypeError(f"revision must be an instance of CommitRevision, got {rev_type}")
        _validate_subpath(self.subpath)
        if self.requested_ref is not None and not isinstance(self.requested_ref, RequestedRef):
            ref_type = type(self.requested_ref).__name__
            raise TypeError(f"requested_ref must be RequestedRef or None, got {ref_type}")

    @property
    def resolved_commit_id(self) -> str:
        """Authoritative resolved hexadecimal commit identity."""
        return self.revision.commit_id
