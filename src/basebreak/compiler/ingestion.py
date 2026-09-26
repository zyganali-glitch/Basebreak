"""Deterministic task ingestion and normalization for the Contract Compiler.

P-06.01: Defines deterministic ingestion for raw engineering-task text.
Preserves original raw task text while producing an authoritative, deterministically
normalized textual representation with cryptographic digests, bounded input ceilings,
and strict rejection of empty, meaningless, or dangerous inputs.
"""

from __future__ import annotations

import hashlib
import json
import re
import unicodedata
from collections.abc import Mapping
from dataclasses import dataclass
from typing import Any

from basebreak.security.secret_policy import redact_log_text

# Default operational ceiling for raw task input in bytes (64 KiB)
DEFAULT_MAX_TASK_BYTES: int = 65_536

# Minimum non-whitespace characters required for meaningful task input
MIN_TASK_NON_WHITESPACE_CHARS: int = 3

# Dangerous Unicode bidirectional override control characters (Trojan Source)
BIDI_OVERRIDE_CHARS: frozenset[str] = frozenset(
    {
        "\u202a",  # Left-to-Right Embedding (LRE)
        "\u202b",  # Right-to-Left Embedding (RLE)
        "\u202c",  # Pop Directional Formatting (PDF)
        "\u202d",  # Left-to-Right Override (LRO)
        "\u202e",  # Right-to-Left Override (RLO)
        "\u2066",  # Left-to-Right Isolate (LRI)
        "\u2067",  # Right-to-Left Isolate (RLI)
        "\u2068",  # First Strong Isolate (FSI)
        "\u2069",  # Pop Directional Isolate (PDI)
    }
)


class TaskIngestionError(Exception):
    """Base exception for task ingestion and normalization errors."""


class TaskSizeLimitExceededError(TaskIngestionError):
    """Raised when raw task input exceeds the maximum permitted byte size."""


class EmptyTaskInputError(TaskIngestionError):
    """Raised when task input is empty or contains only whitespace."""


class InvalidTaskContentError(TaskIngestionError):
    """Raised when task input contains forbidden characters or lacks meaningful content."""


@dataclass(frozen=True, slots=True)
class NormalizedTask:
    """Authoritative normalized representation of an ingested engineering task.

    Carries both the untouched original raw text and the deterministically normalized
    text along with their cryptographic digests and structural dimensions.
    """

    raw_text: str
    normalized_text: str
    task_digest: str
    raw_digest: str
    byte_length: int
    character_count: int
    line_count: int
    metadata: dict[str, str]

    def __post_init__(self) -> None:
        if not isinstance(self.raw_text, str):
            raise TypeError(f"raw_text must be str, got {type(self.raw_text).__name__}")
        if not isinstance(self.normalized_text, str):
            raise TypeError(
                f"normalized_text must be str, got {type(self.normalized_text).__name__}"
            )
        if not isinstance(self.task_digest, str):
            raise TypeError(f"task_digest must be str, got {type(self.task_digest).__name__}")
        if not isinstance(self.raw_digest, str):
            raise TypeError(f"raw_digest must be str, got {type(self.raw_digest).__name__}")
        if not isinstance(self.byte_length, int) or isinstance(self.byte_length, bool):
            raise TypeError(f"byte_length must be int, got {type(self.byte_length).__name__}")
        if not isinstance(self.character_count, int) or isinstance(self.character_count, bool):
            raise TypeError(
                f"character_count must be int, got {type(self.character_count).__name__}"
            )
        if not isinstance(self.line_count, int) or isinstance(self.line_count, bool):
            raise TypeError(f"line_count must be int, got {type(self.line_count).__name__}")
        if not isinstance(self.metadata, dict):
            raise TypeError(f"metadata must be dict, got {type(self.metadata).__name__}")

        # Validate cryptographic digests
        expected_raw_digest = hashlib.sha256(self.raw_text.encode("utf-8")).hexdigest()
        if self.raw_digest != expected_raw_digest:
            raise ValueError(
                f"raw_digest mismatch: expected {expected_raw_digest}, got {self.raw_digest}"
            )

        expected_task_digest = hashlib.sha256(self.normalized_text.encode("utf-8")).hexdigest()
        if self.task_digest != expected_task_digest:
            raise ValueError(
                f"task_digest mismatch: expected {expected_task_digest}, got {self.task_digest}"
            )

        # Validate structural dimensions
        expected_bytes = len(self.normalized_text.encode("utf-8"))
        if self.byte_length != expected_bytes:
            raise ValueError(
                f"byte_length mismatch: expected {expected_bytes}, got {self.byte_length}"
            )

        expected_chars = len(self.normalized_text)
        if self.character_count != expected_chars:
            raise ValueError(
                f"character_count mismatch: expected {expected_chars}, got {self.character_count}"
            )

        expected_lines = len(self.normalized_text.splitlines()) if self.normalized_text else 0
        if self.line_count != expected_lines:
            raise ValueError(
                f"line_count mismatch: expected {expected_lines}, got {self.line_count}"
            )

    def safe_summary(self, max_chars: int = 120) -> str:
        """Return a secret-redacted brief summary for safe logging and display."""
        snippet = self.normalized_text[:max_chars]
        if len(self.normalized_text) > max_chars:
            snippet += "..."
        return redact_log_text(snippet)

    def __repr__(self) -> str:
        """Deterministic secret-safe representation without leaking raw task text."""
        return (
            f"NormalizedTask(task_digest={self.task_digest[:16]}..., "
            f"chars={self.character_count}, lines={self.line_count}, "
            f"bytes={self.byte_length})"
        )

    def to_dict(self) -> dict[str, Any]:
        """Serialize normalized task to a deterministic JSON-serializable dictionary."""
        return {
            "raw_text": self.raw_text,
            "normalized_text": self.normalized_text,
            "task_digest": self.task_digest,
            "raw_digest": self.raw_digest,
            "byte_length": self.byte_length,
            "character_count": self.character_count,
            "line_count": self.line_count,
            "metadata": dict(sorted(self.metadata.items())),
        }

    def to_canonical_bytes(self) -> bytes:
        """Serialize normalized task into deterministic canonical bytes."""
        return json.dumps(
            self.to_dict(), sort_keys=True, separators=(",", ":"), ensure_ascii=False
        ).encode("utf-8")

    @classmethod
    def from_dict(cls, data: Mapping[str, Any]) -> NormalizedTask:
        """Construct NormalizedTask from a dictionary with strict validation."""
        required_keys = {
            "raw_text",
            "normalized_text",
            "task_digest",
            "raw_digest",
            "byte_length",
            "character_count",
            "line_count",
            "metadata",
        }
        missing = required_keys - set(data.keys())
        if missing:
            raise ValueError(f"Missing required fields for NormalizedTask: {sorted(missing)}")

        raw_metadata = data["metadata"]
        if not isinstance(raw_metadata, Mapping):
            raise TypeError(f"metadata must be a mapping, got {type(raw_metadata).__name__}")
        validated_metadata: dict[str, str] = {}
        for k, v in raw_metadata.items():
            if not isinstance(k, str) or not isinstance(v, str):
                raise TypeError("metadata keys and values must be strings")
            validated_metadata[k] = v

        return cls(
            raw_text=data["raw_text"],
            normalized_text=data["normalized_text"],
            task_digest=data["task_digest"],
            raw_digest=data["raw_digest"],
            byte_length=data["byte_length"],
            character_count=data["character_count"],
            line_count=data["line_count"],
            metadata=validated_metadata,
        )


def normalize_task_text(raw_text: str) -> str:
    """Deterministically normalize raw engineering-task text.

    Normalization algorithm:
    1. Reject null bytes and Unicode bidirectional override characters.
    2. Strip leading UTF-8 Byte Order Mark (BOM).
    3. Normalize to Unicode NFC composition form.
    4. Normalize all line breaks (CRLF, CR, line/paragraph separators) to LF (`\n`).
    5. Expand tabs to 4 spaces for uniform indentation.
    6. For each line:
       - Strip trailing horizontal whitespace.
       - Preserve leading indentation spaces.
       - Collapse multiple consecutive horizontal spaces within line content to a single space.
    7. Collapse multiple consecutive blank lines to at most one empty line (`\n\n`).
    8. Strip leading and trailing whitespace/newlines of the whole document.
    9. Verify meaningful content (non-empty, minimum readable character count).

    Returns:
        Authoritative normalized text.

    Raises:
        InvalidTaskContentError: If forbidden characters or insufficient content is present.
        EmptyTaskInputError: If text is empty or whitespace-only.
    """
    if not isinstance(raw_text, str):
        raise TypeError(f"raw_text must be str, got {type(raw_text).__name__}")

    # Check for forbidden control characters
    if "\x00" in raw_text:
        raise InvalidTaskContentError("Task text contains forbidden null byte")

    # Check for dangerous Unicode bidirectional override characters (Trojan Source)
    for ch in BIDI_OVERRIDE_CHARS:
        if ch in raw_text:
            raise InvalidTaskContentError(
                "Task text contains dangerous Unicode bidirectional override characters"
            )

    # Strip leading UTF-8 BOM if present
    text = raw_text.lstrip("\ufeff")

    # Canonical Unicode NFC normalization
    text = unicodedata.normalize("NFC", text)

    # Line break normalization: convert all newline variants to \n
    text = text.replace("\r\n", "\n")
    text = text.replace("\r", "\n")
    text = text.replace("\u2028", "\n")  # Unicode Line Separator
    text = text.replace("\u2029", "\n")  # Unicode Paragraph Separator

    # Process line-by-line
    lines = text.split("\n")
    normalized_lines: list[str] = []
    for line in lines:
        # Expand tabs to 4 spaces
        line = line.replace("\t", "    ")
        # Strip trailing horizontal whitespace
        line = line.rstrip(" \t")
        if not line:
            normalized_lines.append("")
            continue

        # Extract leading indentation
        stripped_left = line.lstrip(" ")
        indent_len = len(line) - len(stripped_left)
        indent = " " * indent_len

        # Collapse multiple horizontal spaces in content to a single space
        collapsed_content = re.sub(r"[ ]{2,}", " ", stripped_left)
        normalized_lines.append(f"{indent}{collapsed_content}")

    # Rejoin lines
    rejoined = "\n".join(normalized_lines)

    # Collapse sequences of 2+ blank lines (3+ newlines) to at most 1 blank line (\n\n)
    rejoined = re.sub(r"\n{3,}", "\n\n", rejoined)

    # Strip leading and trailing whitespace/newlines of the whole document
    result = rejoined.strip()

    # Reject empty or whitespace-only
    if not result:
        raise EmptyTaskInputError("Task text is empty or contains only whitespace")

    # Verify meaningful character content
    non_ws_chars = len(re.sub(r"\s+", "", result))
    if non_ws_chars < MIN_TASK_NON_WHITESPACE_CHARS:
        raise InvalidTaskContentError(
            f"Task text contains insufficient meaningful content "
            f"({non_ws_chars} non-whitespace chars, minimum {MIN_TASK_NON_WHITESPACE_CHARS})"
        )

    return result


def ingest_task(
    raw_input: str | bytes,
    *,
    max_bytes: int = DEFAULT_MAX_TASK_BYTES,
    metadata: Mapping[str, str] | None = None,
) -> NormalizedTask:
    """Deterministically ingest and normalize raw task text.

    Args:
        raw_input: Raw task text as string or UTF-8 encoded bytes.
        max_bytes: Maximum allowed byte size for raw input (default 65,536).
        metadata: Optional string-to-string metadata dictionary.

    Returns:
        NormalizedTask: Immutable normalized task contract.

    Raises:
        TypeError: If input is not str or bytes, or max_bytes is invalid.
        TaskSizeLimitExceededError: If input exceeds max_bytes.
        InvalidTaskContentError: If input cannot be decoded as UTF-8 or contains forbidden chars.
        EmptyTaskInputError: If input is empty or whitespace-only.
    """
    if isinstance(raw_input, bytes):
        raw_bytes = raw_input
        try:
            raw_text = raw_bytes.decode("utf-8")
        except UnicodeDecodeError as exc:
            raise InvalidTaskContentError(
                f"Task input bytes could not be decoded as UTF-8: {exc}"
            ) from exc
    elif isinstance(raw_input, str):
        raw_text = raw_input
        raw_bytes = raw_text.encode("utf-8")
    else:
        raise TypeError(f"raw_input must be str or bytes, got {type(raw_input).__name__}")

    if not isinstance(max_bytes, int) or isinstance(max_bytes, bool) or max_bytes <= 0:
        raise TypeError(f"max_bytes must be a positive integer, got {max_bytes!r}")

    # Enforce bounded task size ceiling
    if len(raw_bytes) > max_bytes:
        raise TaskSizeLimitExceededError(
            f"Raw task input size ({len(raw_bytes)} bytes) exceeds "
            f"configured maximum ceiling ({max_bytes} bytes)"
        )

    # Deterministically normalize text
    normalized_text = normalize_task_text(raw_text)

    # Compute deterministic digests
    raw_digest = hashlib.sha256(raw_bytes).hexdigest()
    norm_bytes = normalized_text.encode("utf-8")
    task_digest = hashlib.sha256(norm_bytes).hexdigest()

    # Validate metadata
    valid_metadata: dict[str, str] = {}
    if metadata is not None:
        if not isinstance(metadata, Mapping):
            raise TypeError(f"metadata must be a mapping, got {type(metadata).__name__}")
        for k, v in metadata.items():
            if not isinstance(k, str) or not isinstance(v, str):
                raise TypeError("metadata keys and values must be strings")
            valid_metadata[k] = v

    return NormalizedTask(
        raw_text=raw_text,
        normalized_text=normalized_text,
        task_digest=task_digest,
        raw_digest=raw_digest,
        byte_length=len(norm_bytes),
        character_count=len(normalized_text),
        line_count=len(normalized_text.splitlines()),
        metadata=valid_metadata,
    )
