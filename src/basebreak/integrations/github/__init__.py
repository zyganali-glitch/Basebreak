"""GitHub integration package for Basebreak."""

from __future__ import annotations

from basebreak.integrations.github.ingestion import (
    GitHubRepoReference,
    IngestionError,
    parse_github_reference,
)
from basebreak.integrations.github.mutation_boundary import (
    GitHubMutationBoundary,
    MutationPreview,
    UnauthorizedMutationError,
)
from basebreak.integrations.github.resolver import (
    GitHubRefResolver,
    MovingRefRaceError,
    RefResolutionError,
)
from basebreak.integrations.github.review_artifact import generate_pr_review_comment

__all__ = [
    "GitHubMutationBoundary",
    "GitHubRefResolver",
    "GitHubRepoReference",
    "IngestionError",
    "MovingRefRaceError",
    "MutationPreview",
    "RefResolutionError",
    "UnauthorizedMutationError",
    "generate_pr_review_comment",
    "parse_github_reference",
]
