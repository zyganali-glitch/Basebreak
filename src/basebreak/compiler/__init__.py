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

__all__ = [
    "DEFAULT_MAX_TASK_BYTES",
    "MIN_TASK_NON_WHITESPACE_CHARS",
    "EmptyTaskInputError",
    "InvalidTaskContentError",
    "NormalizedTask",
    "TaskIngestionError",
    "TaskSizeLimitExceededError",
    "ingest_task",
    "normalize_task_text",
]
