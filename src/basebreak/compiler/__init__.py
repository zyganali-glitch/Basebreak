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
from basebreak.compiler.semantics import (
    DEFAULT_SEMANTICS_MAX_TOKENS,
    DEFAULT_SEMANTICS_MODEL,
    AmbiguousSemanticsError,
    CertaintyLevel,
    ChangeSemanticsClassification,
    InvalidChangeClassError,
    MalformedClassificationOutputError,
    NemotronSemanticsClassifier,
    SemanticsClassificationError,
    classify_semantics_deterministically,
    parse_and_validate_classification,
)

__all__ = [
    "AmbiguousSemanticsError",
    "CertaintyLevel",
    "ChangeSemanticsClassification",
    "DEFAULT_MAX_TASK_BYTES",
    "DEFAULT_PROPOSAL_MAX_TOKENS",
    "DEFAULT_REQUIREMENTS_MODEL",
    "DEFAULT_SEMANTICS_MAX_TOKENS",
    "DEFAULT_SEMANTICS_MODEL",
    "EmptyTaskInputError",
    "InvalidChangeClassError",
    "InvalidModelConfigurationError",
    "InvalidTaskContentError",
    "MalformedClassificationOutputError",
    "MalformedModelOutputError",
    "MIN_TASK_NON_WHITESPACE_CHARS",
    "NemotronRequirementProposer",
    "NemotronSemanticsClassifier",
    "NormalizedTask",
    "ProposedRequirement",
    "RequirementProposalError",
    "RequirementProposalResult",
    "SemanticsClassificationError",
    "TaskIngestionError",
    "TaskSizeLimitExceededError",
    "UnsupportedCitationError",
    "classify_semantics_deterministically",
    "ingest_task",
    "normalize_task_text",
    "parse_and_validate_classification",
    "parse_and_validate_requirements",
]
