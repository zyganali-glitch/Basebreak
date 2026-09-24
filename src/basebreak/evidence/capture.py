"""Bounded sanitized stdout and stderr execution output capture.

Implements provider-neutral deterministic execution-output capture primitives.
Preserves raw stdout/stderr stream separation, computes full-content cryptographic
digests regardless of truncation, enforces deterministic byte bounds, and applies
bounded secret sanitization without merging streams.
"""

from __future__ import annotations

from dataclasses import dataclass
from enum import Enum
from typing import Any

from basebreak.evidence.artifact import ArtifactDigest, compute_bytes_digest
from basebreak.security.secret_policy import redact_text

DEFAULT_MAX_CAPTURE_BYTES: int = 65536  # 64 KiB default bound


class StreamType(str, Enum):
    """Execution stream type."""

    STDOUT = "stdout"
    STDERR = "stderr"


def sanitize_text(text: str) -> tuple[str, bool]:
    """Apply deterministic secret sanitization to text.

    Delegates to the canonical Basebreak secret policy (P-04.02).

    Returns:
        tuple of (sanitized_text, is_sanitized).
    """
    if not isinstance(text, str):
        raise TypeError(f"text must be a str, got {type(text).__name__}")
    return redact_text(text)


@dataclass(frozen=True)
class CapturedStream:
    """Bounded, sanitized capture of an individual execution stream.

    Maintains the full cryptographic digest of the complete original bytes
    to ensure tamper evidence even when output exceeds retention limits.
    """

    stream_type: StreamType
    full_digest: ArtifactDigest
    original_byte_length: int
    is_truncated: bool
    max_bytes: int
    retained_bytes: bytes
    retained_text: str
    sanitized_text: str
    is_sanitized: bool

    def __post_init__(self) -> None:
        if not isinstance(self.stream_type, StreamType):
            raise TypeError(
                f"stream_type must be StreamType, got {type(self.stream_type).__name__}"
            )
        if not isinstance(self.full_digest, ArtifactDigest):
            raise TypeError(
                f"full_digest must be ArtifactDigest, got {type(self.full_digest).__name__}"
            )
        if isinstance(self.original_byte_length, bool) or not isinstance(
            self.original_byte_length, int
        ):
            raise TypeError(
                f"original_byte_length must be an int (not bool), "
                f"got {type(self.original_byte_length).__name__}"
            )
        if self.original_byte_length < 0:
            raise ValueError(
                f"original_byte_length must be non-negative, got {self.original_byte_length}"
            )
        if not isinstance(self.is_truncated, bool):
            raise TypeError(f"is_truncated must be a bool, got {type(self.is_truncated).__name__}")
        if isinstance(self.max_bytes, bool) or not isinstance(self.max_bytes, int):
            raise TypeError(
                f"max_bytes must be an int (not bool), got {type(self.max_bytes).__name__}"
            )
        if self.max_bytes <= 0:
            raise ValueError(f"max_bytes must be strictly positive, got {self.max_bytes}")
        if not isinstance(self.retained_bytes, bytes):
            raise TypeError(
                f"retained_bytes must be bytes, got {type(self.retained_bytes).__name__}"
            )
        if len(self.retained_bytes) > self.max_bytes:
            raise ValueError(
                f"retained_bytes length ({len(self.retained_bytes)}) "
                f"exceeds max_bytes ({self.max_bytes})"
            )
        if not isinstance(self.retained_text, str):
            raise TypeError(f"retained_text must be a str, got {type(self.retained_text).__name__}")
        if not isinstance(self.sanitized_text, str):
            raise TypeError(
                f"sanitized_text must be a str, got {type(self.sanitized_text).__name__}"
            )
        if not isinstance(self.is_sanitized, bool):
            raise TypeError(f"is_sanitized must be a bool, got {type(self.is_sanitized).__name__}")
        if self.full_digest.byte_length != self.original_byte_length:
            raise ValueError(
                f"full_digest.byte_length ({self.full_digest.byte_length}) "
                f"does not match original_byte_length ({self.original_byte_length})"
            )
        if self.retained_text != self.retained_bytes.decode("utf-8", errors="replace"):
            raise ValueError(
                "retained_text does not match retained_bytes decoded with utf-8 (replace)"
            )
        if self.sanitized_text != self.retained_text:
            raise ValueError(
                f"sanitized_text must equal retained_text, got {self.sanitized_text!r} "
                f"vs {self.retained_text!r}"
            )
        _, contains_secret = sanitize_text(self.retained_text)
        if contains_secret:
            raise ValueError("retained_text contains unsanitized secret material")

    def to_dict(self) -> dict[str, Any]:
        """Serialize captured stream facts to dictionary."""
        return {
            "full_digest": self.full_digest.to_dict(),
            "is_sanitized": self.is_sanitized,
            "is_truncated": self.is_truncated,
            "max_bytes": self.max_bytes,
            "original_byte_length": self.original_byte_length,
            "retained_text": self.retained_text,
            "sanitized_text": self.sanitized_text,
            "stream_type": self.stream_type.value,
        }


@dataclass(frozen=True)
class CapturedOutput:
    """Distinct bounded capture of stdout and stderr streams.

    Never merges stdout and stderr.
    """

    stdout: CapturedStream
    stderr: CapturedStream

    def __post_init__(self) -> None:
        if not isinstance(self.stdout, CapturedStream):
            raise TypeError(f"stdout must be CapturedStream, got {type(self.stdout).__name__}")
        if self.stdout.stream_type != StreamType.STDOUT:
            raise ValueError(f"stdout must have stream_type STDOUT, got {self.stdout.stream_type}")
        if not isinstance(self.stderr, CapturedStream):
            raise TypeError(f"stderr must be CapturedStream, got {type(self.stderr).__name__}")
        if self.stderr.stream_type != StreamType.STDERR:
            raise ValueError(f"stderr must have stream_type STDERR, got {self.stderr.stream_type}")

    @property
    def is_truncated(self) -> bool:
        """Return True if either stdout or stderr was truncated."""
        return self.stdout.is_truncated or self.stderr.is_truncated

    @property
    def is_sanitized(self) -> bool:
        """Return True if any secret pattern was redacted in stdout or stderr."""
        return self.stdout.is_sanitized or self.stderr.is_sanitized

    def to_dict(self) -> dict[str, Any]:
        """Serialize captured output facts to dictionary."""
        return {
            "stderr": self.stderr.to_dict(),
            "stdout": self.stdout.to_dict(),
        }


def capture_stream(
    raw: bytes | str,
    stream_type: StreamType,
    max_bytes: int = DEFAULT_MAX_CAPTURE_BYTES,
) -> CapturedStream:
    """Capture, bound, and sanitize an execution stream.

    Computes full cryptographic digest of the complete original input bytes.
    Preserves original length and bounds retained excerpt.
    """
    if isinstance(raw, str):
        raw_bytes = raw.encode("utf-8")
    elif isinstance(raw, (bytes, bytearray)):
        raw_bytes = bytes(raw)
    else:
        raise TypeError(f"raw must be bytes or str, got {type(raw).__name__}")

    if not isinstance(stream_type, StreamType):
        raise TypeError(f"stream_type must be StreamType, got {type(stream_type).__name__}")
    if isinstance(max_bytes, bool) or not isinstance(max_bytes, int):
        raise TypeError(f"max_bytes must be an int (not bool), got {type(max_bytes).__name__}")
    if max_bytes <= 0:
        raise ValueError(f"max_bytes must be strictly positive, got {max_bytes}")

    # Full digest and length computed from EXACT original raw bytes
    full_digest = compute_bytes_digest(raw_bytes)
    original_byte_length = len(raw_bytes)

    # Decode raw bytes deterministically (replace errors preserve continuity without dropping)
    full_text = raw_bytes.decode("utf-8", errors="replace")

    # Sanitize BEFORE bounding/truncation so secrets crossing the retention boundary do not leak
    sanitized_full_text, is_sanitized = sanitize_text(full_text)

    # Retained content must never contain raw secrets
    if is_sanitized:
        sanitized_bytes = sanitized_full_text.encode("utf-8")
        retained_bytes = sanitized_bytes[:max_bytes]
        retained_text = retained_bytes.decode("utf-8", errors="replace")
        is_truncated = (original_byte_length > max_bytes) or (len(sanitized_bytes) > max_bytes)
    else:
        retained_bytes = raw_bytes[:max_bytes]
        retained_text = retained_bytes.decode("utf-8", errors="replace")
        is_truncated = original_byte_length > max_bytes

    return CapturedStream(
        stream_type=stream_type,
        full_digest=full_digest,
        original_byte_length=original_byte_length,
        is_truncated=is_truncated,
        max_bytes=max_bytes,
        retained_bytes=retained_bytes,
        retained_text=retained_text,
        sanitized_text=retained_text,
        is_sanitized=is_sanitized,
    )


def capture_output(
    raw_stdout: bytes | str,
    raw_stderr: bytes | str,
    max_bytes: int = DEFAULT_MAX_CAPTURE_BYTES,
) -> CapturedOutput:
    """Capture both stdout and stderr with distinct stream identities and bounded limits."""
    captured_stdout = capture_stream(raw_stdout, StreamType.STDOUT, max_bytes=max_bytes)
    captured_stderr = capture_stream(raw_stderr, StreamType.STDERR, max_bytes=max_bytes)
    return CapturedOutput(stdout=captured_stdout, stderr=captured_stderr)
