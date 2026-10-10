"""Mutation boundary and human authority enforcement for GitHub actions.

P-20.04 & P-20.05:
- Strictly prevents unauthorized external network mutations (PR comments, draft PRs).
- Enforces human operator authority token requirement for irreversible GitHub actions.
- Fails closed with UnauthorizedMutationError.
- Supports dry-run preview mode by default.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any

from basebreak.integrations.github.ingestion import GitHubRepoReference
from basebreak.security.secret_policy import redact_text


class UnauthorizedMutationError(Exception):
    """Raised when external GitHub mutation is attempted without verified human authority."""


@dataclass(frozen=True, slots=True)
class MutationPreview:
    """Safe dry-run preview of a proposed GitHub mutation."""

    repo: str
    action: str  # "post_pr_comment", "create_draft_pr"
    target_pr: int | None
    comment_body_excerpt: str
    is_dry_run: bool
    requires_human_token: bool


class GitHubMutationBoundary:
    """Guards external GitHub actions behind human authority and dry-run boundaries."""

    def __init__(
        self,
        allow_github_mutation: bool = False,
        human_authority_token: str | None = None,
    ) -> None:
        self.allow_github_mutation = allow_github_mutation
        self.human_authority_token = human_authority_token

    def execute_post_pr_comment(
        self,
        repo_ref: GitHubRepoReference,
        comment_body: str,
        dry_run: bool = True,
    ) -> dict[str, Any]:
        """Post a PR comment or return a safe dry-run preview.

        Raises:
            UnauthorizedMutationError: If mutation flag is False or human authority token is absent.
        """
        # Redact any secrets before proposing or previewing
        safe_body, _ = redact_text(comment_body)

        if dry_run or not self.allow_github_mutation:
            # Return dry-run preview
            return {
                "status": "DRY_RUN_PREVIEW",
                "repo": repo_ref.full_name,
                "pr_number": repo_ref.pr_number,
                "comment_preview": safe_body[:200] + ("..." if len(safe_body) > 200 else ""),
                "mutation_performed": False,
                "message": (
                    "Dry-run mode active. No external GitHub mutation was performed. "
                    "External mutation requires explicit operator opt-in and valid authority token."
                ),
            }

        if not self.human_authority_token:
            raise UnauthorizedMutationError(
                "Human operator authority token is required to request GitHub mutations."
            )

        if len(self.human_authority_token.strip()) < 16:
            raise UnauthorizedMutationError(
                "Human authority token does not meet minimum entropy requirements (min 16 chars)."
            )

        # External mutation is strictly disabled in this runtime environment.
        # Under Zero-Cost Law and security boundaries, no unconfirmed live external mutation
        # is permitted, and arbitrary string length cannot authorize or prove external action.
        raise UnauthorizedMutationError(
            "External GitHub write operations (PR comments, draft PRs, merges) are strictly "
            "disabled in this runtime environment. No external mutations may be performed."
        )
