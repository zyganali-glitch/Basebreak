"""Tests for bounded sanitized stdout/stderr capture with digests (P-03.03)."""

from __future__ import annotations

import hashlib

import pytest

from basebreak.evidence.artifact import compute_bytes_digest
from basebreak.evidence.capture import (
    CapturedOutput,
    StreamType,
    capture_output,
    capture_stream,
    sanitize_text,
)


class TestStreamSeparation:
    def test_stdout_and_stderr_are_distinct(self) -> None:
        out = capture_output("standard output line", "standard error line")
        assert out.stdout.stream_type == StreamType.STDOUT
        assert out.stderr.stream_type == StreamType.STDERR
        assert out.stdout.retained_text == "standard output line"
        assert out.stderr.retained_text == "standard error line"
        assert out.stdout != out.stderr

    def test_captured_output_rejects_wrong_stream_type(self) -> None:
        s1 = capture_stream("out1", StreamType.STDOUT)
        s2 = capture_stream("out2", StreamType.STDOUT)
        with pytest.raises(ValueError, match="stderr must have stream_type STDERR"):
            CapturedOutput(stdout=s1, stderr=s2)


class TestBoundedCapture:
    def test_under_limit_retained_fully(self) -> None:
        data = b"under the limit execution log"
        stream = capture_stream(data, StreamType.STDOUT, max_bytes=100)
        assert not stream.is_truncated
        assert stream.original_byte_length == len(data)
        assert stream.retained_bytes == data
        assert stream.retained_text == data.decode("utf-8")
        assert stream.full_digest == compute_bytes_digest(data)

    def test_over_limit_truncated_deterministically(self) -> None:
        prefix = b"0123456789"
        tail = b"abcdefghij"
        full_data = prefix + tail  # 20 bytes
        stream = capture_stream(full_data, StreamType.STDOUT, max_bytes=10)
        assert stream.is_truncated
        assert stream.original_byte_length == 20
        assert stream.retained_bytes == prefix
        assert len(stream.retained_bytes) == 10
        assert stream.retained_text == prefix.decode("utf-8")
        # Digest must be of the FULL 20 bytes, not just prefix
        assert stream.full_digest == compute_bytes_digest(full_data)

    def test_different_hidden_tails_produce_different_digests(self) -> None:
        prefix = b"common identical prefix " * 4  # 96 bytes
        full_data_1 = prefix + b"secret_tail_one"
        full_data_2 = prefix + b"secret_tail_two"

        stream1 = capture_stream(full_data_1, StreamType.STDOUT, max_bytes=50)
        stream2 = capture_stream(full_data_2, StreamType.STDOUT, max_bytes=50)

        # Retained excerpts are identical
        assert stream1.retained_bytes == stream2.retained_bytes
        assert stream1.retained_text == stream2.retained_text
        assert stream1.is_truncated
        assert stream2.is_truncated

        # Full digests MUST be different
        assert stream1.full_digest != stream2.full_digest
        assert stream1.full_digest.value != stream2.full_digest.value


class TestSanitization:
    def test_bearer_token_sanitization(self) -> None:
        raw = "Connecting with Authorization: Bearer eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9"
        sanitized, is_sanitized = sanitize_text(raw)
        assert is_sanitized
        assert "Bearer [REDACTED]" in sanitized
        assert "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9" not in sanitized

    def test_basic_auth_sanitization(self) -> None:
        raw = "Header Authorization: Basic dXNlcjpzdXBlcnNlY3JldHBhc3M="
        sanitized, is_sanitized = sanitize_text(raw)
        assert is_sanitized
        assert "Basic [REDACTED]" in sanitized
        assert "dXNlcjpzdXBlcnNlY3JldHBhc3M=" not in sanitized

    def test_api_key_assignment_sanitization(self) -> None:
        raw = 'Config: api_key = "secret_api_key_123456"'
        sanitized, is_sanitized = sanitize_text(raw)
        assert is_sanitized
        assert "[REDACTED]" in sanitized
        assert "secret_api_key_123456" not in sanitized

    def test_prefixed_tokens_sanitization(self) -> None:
        raw_sk = "Using key sk-12345678901234567890"
        sanitized_sk, modified_sk = sanitize_text(raw_sk)
        assert modified_sk
        assert "[REDACTED]" in sanitized_sk
        assert "sk-12345678901234567890" not in sanitized_sk

        raw_ghp = "GitHub token ghp_123456789012345678901234567890123456"
        sanitized_ghp, modified_ghp = sanitize_text(raw_ghp)
        assert modified_ghp
        assert "[REDACTED]" in sanitized_ghp
        assert "ghp_123456789012345678901234567890123456" not in sanitized_ghp

    def test_benign_text_is_not_sanitized(self) -> None:
        raw = "All 25 tests passed in 0.45s. Build clean."
        sanitized, is_sanitized = sanitize_text(raw)
        assert not is_sanitized
        assert sanitized == raw


class TestByteAndTextSemantics:
    def test_empty_stream_handled(self) -> None:
        stream = capture_stream(b"", StreamType.STDOUT)
        assert stream.original_byte_length == 0
        assert not stream.is_truncated
        assert not stream.is_sanitized
        assert stream.retained_bytes == b""
        assert stream.retained_text == ""
        assert stream.sanitized_text == ""
        assert stream.full_digest.value == hashlib.sha256(b"").hexdigest()

    def test_non_utf8_bytes_handled_without_exception(self) -> None:
        bad_bytes = b"\x80\x81\x82 invalid utf-8 sequences"
        stream = capture_stream(bad_bytes, StreamType.STDERR)
        assert stream.original_byte_length == len(bad_bytes)
        assert stream.retained_bytes == bad_bytes
        # Replacement characters should be in retained text rather than throwing
        assert "\ufffd" in stream.retained_text

    def test_deterministic_dictionary_serialization(self) -> None:
        out = capture_output("out line", "err line")
        d = out.to_dict()
        assert d["stdout"]["stream_type"] == "stdout"
        assert d["stderr"]["stream_type"] == "stderr"
        assert d["stdout"]["retained_text"] == "out line"
        assert d["stderr"]["retained_text"] == "err line"
        assert "0x" not in d["stdout"]["full_digest"]["value"]


class TestSanitizedCaptureNoRawSecretRetention:
    def test_bearer_token_not_in_any_field(self) -> None:
        token = "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9"
        raw = f"Authorization: Bearer {token}"
        stream = capture_stream(raw, StreamType.STDOUT)
        assert stream.is_sanitized
        assert token.encode("utf-8") not in stream.retained_bytes
        assert token not in stream.retained_text
        assert token not in stream.sanitized_text
        assert "Bearer [REDACTED]" in stream.retained_text
        # Full digest still equals exact original bytes
        assert stream.full_digest == compute_bytes_digest(raw.encode("utf-8"))
        assert stream.original_byte_length == len(raw.encode("utf-8"))

    def test_api_key_not_in_any_field(self) -> None:
        key = "secret_fake_api_key_88888"
        raw = f'config: api_key = "{key}"'
        stream = capture_stream(raw, StreamType.STDERR)
        assert stream.is_sanitized
        assert key.encode("utf-8") not in stream.retained_bytes
        assert key not in stream.retained_text
        assert key not in stream.sanitized_text
        assert "[REDACTED]" in stream.retained_text

    def test_basic_auth_not_in_any_field(self) -> None:
        cred = "dXNlcjpwYXNzd29yZDEyMzQ="
        raw = f"Authorization: Basic {cred}"
        stream = capture_stream(raw, StreamType.STDOUT)
        assert stream.is_sanitized
        assert cred.encode("utf-8") not in stream.retained_bytes
        assert cred not in stream.retained_text
        assert cred not in stream.sanitized_text
        assert "Basic [REDACTED]" in stream.retained_text

    def test_serialized_to_dict_contains_no_original_secret(self) -> None:
        token = "sk-1234567890abcdef1234"
        raw = f"Using API client token: {token}"
        stream = capture_stream(raw, StreamType.STDOUT)
        d = stream.to_dict()
        assert token not in str(d)
        assert token not in d["retained_text"]
        assert token not in d["sanitized_text"]

    def test_secret_spanning_truncation_boundary_cannot_leak_partial_secret(self) -> None:
        prefix = "A" * 44 + " "
        secret_token = "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9"
        raw = f"{prefix}Bearer {secret_token}"
        # max_bytes = 50, secret starts at index 45
        stream = capture_stream(raw, StreamType.STDOUT, max_bytes=50)
        assert stream.is_sanitized
        assert stream.is_truncated
        assert len(stream.retained_bytes) <= 50
        assert secret_token.encode("utf-8") not in stream.retained_bytes
        assert secret_token not in stream.retained_text
        # Even partial characters of secret_token must not appear
        assert secret_token[:10] not in stream.retained_text
        assert stream.full_digest == compute_bytes_digest(raw.encode("utf-8"))
        assert stream.original_byte_length == len(raw.encode("utf-8"))
