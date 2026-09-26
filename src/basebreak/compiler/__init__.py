"""Basebreak Contract Compiler package.

Converts untrusted natural-language engineering tasks into machine-verifiable,
reviewable verification contracts.
"""

from __future__ import annotations

from basebreak.compiler.ingestion import (
    DEFAULT_MAX_TASK_BYTES,
    MIN_TASK_NON_WHITESPACE_CHARS,
    EmptyTaskInputError,
    InvalidTaskContentError,
    NormalizedTask,
    TaskIngestionError,
    TaskSizeLimitExceededError,
    ingest_task,
    normalize_task_text,
)
from basebreak.compiler.requirements import (
    DEFAULT_PROPOSAL_MAX_TOKENS,
    DEFAULT_REQUIREMENTS_MODEL,
    InvalidModelConfigurationError,
    MalformedModelOutputError,
    NemotronRequirementProposer,
    ProposedRequirement,
    RequirementProposalError,
    RequirementProposalResult,
    UnsupportedCitationError,
    parse_and_validate_requirements,
)

__all__ = [
    "DEFAULT_MAX_TASK_BYTES",
    "DEFAULT_PROPOSAL_MAX_TOKENS",
    "DEFAULT_REQUIREMENTS_MODEL",
    "EmptyTaskInputError",
    "InvalidModelConfigurationError",
    "InvalidTaskContentError",
    "MalformedModelOutputError",
    "MIN_TASK_NON_WHITESPACE_CHARS",
    "NemotronRequirementProposer",
    "NormalizedTask",
    "ProposedRequirement",
    "RequirementProposalError",
    "RequirementProposalResult",
    "TaskIngestionError",
    "TaskSizeLimitExceededError",
    "UnsupportedCitationError",
    "ingest_task",
    "normalize_task_text",
    "parse_and_validate_requirements",
]
