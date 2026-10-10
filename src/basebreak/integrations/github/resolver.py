"""Remote ref resolution and moving-ref race protection.

P-20.02: Resolves symbolic refs to immutable 40-char commit SHAs and detects
remote ref modifications during verification to prevent moving-target races.
"""

from __future__ import annotations

import re
import subprocess
from typing import Callable

_HEX_40_PATTERN = re.compile(r"^[0-9a-fA-F]{40}$")


class RefResolutionError(Exception):
    """Raised when a git reference cannot be resolved to a commit SHA."""


class MovingRefRaceError(Exception):
    """Raised when a remote ref moves during verification, invalidating the proof baseline."""


class GitHubRefResolver:
    """Resolves and monitors remote git references."""

    def __init__(
        self,
        git_ls_remote_fn: Callable[[str, str], str] | None = None,
    ) -> None:
        """Initialize resolver.

        Args:
            git_ls_remote_fn: Optional callable taking (remote_url, ref) -> 40-char commit SHA.
                If omitted, runs `git ls-remote`.
        """
        self._ls_remote_fn = git_ls_remote_fn or self._default_ls_remote

    @staticmethod
    def _default_ls_remote(remote_url: str, ref: str) -> str:
        """Execute git ls-remote to resolve ref to commit SHA."""
        try:
            cmd = ["git", "ls-remote", remote_url, ref]
            out = subprocess.check_output(cmd, stderr=subprocess.PIPE, text=True, timeout=15)
            lines = [line.strip() for line in out.strip().splitlines() if line.strip()]
            if not lines:
                raise RefResolutionError(f"No remote ref matching '{ref}' found at {remote_url}")

            # Grab first matching SHA
            first_sha = lines[0].split()[0]
            if not _HEX_40_PATTERN.match(first_sha):
                raise RefResolutionError(f"Invalid SHA returned by git ls-remote: {first_sha}")
            return first_sha.lower()
        except subprocess.CalledProcessError as exc:
            raise RefResolutionError(f"git ls-remote failed: {exc.stderr}") from exc
        except (subprocess.TimeoutExpired, FileNotFoundError) as exc:
            raise RefResolutionError(f"git command execution failed: {exc}") from exc

    def resolve_ref(self, remote_url: str, ref_or_sha: str) -> str:
        """Resolve a symbolic ref or commit SHA into an immutable 40-char commit SHA."""
        if not ref_or_sha or not ref_or_sha.strip():
            raise RefResolutionError("Ref cannot be empty")

        clean_ref = ref_or_sha.strip()
        # If it's already a 40-char hex commit SHA, return it directly pinned
        if _HEX_40_PATTERN.match(clean_ref):
            return clean_ref.lower()

        # Otherwise resolve via git ls-remote
        return self._ls_remote_fn(remote_url, clean_ref)

    def verify_ref_unmoved(
        self,
        remote_url: str,
        symbolic_ref: str,
        expected_sha: str,
    ) -> None:
        """Verify that symbolic ref has not moved since verification began.

        Raises:
            MovingRefRaceError: If remote ref has moved to a different commit.
        """
        current_sha = self.resolve_ref(remote_url, symbolic_ref)
        if current_sha.lower() != expected_sha.lower():
            raise MovingRefRaceError(
                f"Moving ref race detected for '{symbolic_ref}' at {remote_url}! "
                f"Baseline SHA was {expected_sha.lower()}, but remote has moved "
                f"to {current_sha.lower()}. Verification invalidated."
            )
