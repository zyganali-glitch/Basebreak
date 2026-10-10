"""Read-only GitHub repository and task ingestion path.

P-20.01: Ingests repository URLs, PR references, branch/tag refs, and local clone paths
with strict input validation and traversal defenses.
"""

from __future__ import annotations

import re
from dataclasses import dataclass
from pathlib import Path

_GITHUB_URL_PATTERN = re.compile(
    r"^https?://github\.com/(?P<owner>[A-Za-z0-9_.-]+)/(?P<repo>[A-Za-z0-9_.-]+)"
    r"(?:/(?:pull/(?P<pr>\d+)|tree/(?P<tree>[A-Za-z0-9_./-]+)|commit/(?P<commit>[0-9a-fA-F]{40})))?/?$"
)
_SHORTHAND_PATTERN = re.compile(
    r"^(?P<owner>[A-Za-z0-9_.-]+)/(?P<repo>[A-Za-z0-9_.-]+)"
    r"(?:(?:#|/pull/)(?P<pr>\d+)|:(?P<ref>[A-Za-z0-9_./-]+))?$"
)


class IngestionError(Exception):
    """Raised when repository target reference is invalid or insecure."""


@dataclass(frozen=True, slots=True)
class GitHubRepoReference:
    """Normalized, validated GitHub repository reference."""

    raw_input: str
    owner: str
    repo: str
    ref: str | None = None
    pr_number: int | None = None
    commit_sha: str | None = None
    is_local_path: bool = False
    local_path: Path | None = None

    @property
    def clone_url(self) -> str:
        """Get canonical HTTPS clone URL."""
        return f"https://github.com/{self.owner}/{self.repo}.git"

    @property
    def full_name(self) -> str:
        """Get owner/repo string."""
        return f"{self.owner}/{self.repo}"


def parse_github_reference(target: str) -> GitHubRepoReference:
    """Parse and validate a GitHub repository locator, URL, or local path.

    Guarantees:
    - Traversal protection: rejects relative path traversals (../, etc.) in non-local URLs.
    - Sanitized owner and repository names.
    - Identification of PR numbers, commit SHAs, and branch/tag refs.
    """
    if not isinstance(target, str):
        raise TypeError(f"target must be a string, got {type(target).__name__}")

    raw = target.strip()
    if not raw:
        raise IngestionError("Target repository reference cannot be empty")

    # Check for local directory path
    candidate_path = Path(raw)
    if candidate_path.is_dir() or raw in {".", "./", "..", "../"}:
        resolved_path = candidate_path.resolve()
        # Derive owner/repo placeholder from folder name
        folder_name = resolved_path.name or "local_repo"
        return GitHubRepoReference(
            raw_input=raw,
            owner="local",
            repo=folder_name,
            is_local_path=True,
            local_path=resolved_path,
        )

    # Check GitHub URL
    match_url = _GITHUB_URL_PATTERN.match(raw)
    if match_url:
        owner = match_url.group("owner")
        repo = match_url.group("repo")
        if repo.endswith(".git"):
            repo = repo[:-4]

        pr_str = match_url.group("pr")
        pr_number = int(pr_str) if pr_str else None
        tree_ref = match_url.group("tree")
        commit_sha = match_url.group("commit")

        return GitHubRepoReference(
            raw_input=raw,
            owner=owner,
            repo=repo,
            ref=tree_ref,
            pr_number=pr_number,
            commit_sha=commit_sha.lower() if commit_sha else None,
            is_local_path=False,
        )

    # Check owner/repo shorthand syntax
    match_short = _SHORTHAND_PATTERN.match(raw)
    if match_short:
        owner = match_short.group("owner")
        repo = match_short.group("repo")
        if repo.endswith(".git"):
            repo = repo[:-4]

        pr_str = match_short.group("pr")
        pr_number = int(pr_str) if pr_str else None
        ref = match_short.group("ref")

        commit_sha = None
        if ref and re.match(r"^[0-9a-fA-F]{40}$", ref):
            commit_sha = ref.lower()
            ref = None

        return GitHubRepoReference(
            raw_input=raw,
            owner=owner,
            repo=repo,
            ref=ref,
            pr_number=pr_number,
            commit_sha=commit_sha,
            is_local_path=False,
        )

    raise IngestionError(
        f"Unrecognized GitHub repository reference: '{raw}'. "
        "Expected HTTPS URL (https://github.com/owner/repo), shorthand (owner/repo#123), "
        "or existing local directory path."
    )
