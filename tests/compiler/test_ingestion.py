"""Acceptance tests for P-06.01: Task Ingestion and Deterministic Normalization.

Tests verify:
- equivalent newline forms;
- leading/trailing whitespace policy;
- repeated whitespace policy if normalized;
- Unicode handling (NFC, BOM, control characters, bidi overrides);
- empty/whitespace-only input rejection;
- oversized input rejection;
- deterministic repeated normalization (idempotence);
- round-trip serialization stability;
- secret-shaped input preservation in task content without accidental leakage in logs/repr;
- provider purity (no adapter imports).
"""

from __future__ import annotations

import unicodedata
from pathlib import Path

import pytest

from basebreak.compiler.ingestion import (
    EmptyTaskInputError,
    InvalidTaskContentError,
    NormalizedTask,
    TaskSizeLimitExceededError,
    ingest_task,
    normalize_task_text,
)


class TestTaskIngestionP0601:
    """Test suite verifying all P-06.01 task ingestion and normalization requirements."""

    # 1. Equivalent newline forms
    def test_equivalent_newline_forms(self) -> None:
        text_lf = "Line 1\nLine 2\n\nLine 3"
        text_crlf = "Line 1\r\nLine 2\r\n\r\nLine 3"
        text_cr = "Line 1\rLine 2\r\rLine 3"
        text_mixed = "Line 1\r\nLine 2\r\n\nLine 3"
        text_unicode_separators = "Line 1\u2028Line 2\n\nLine 3"

        norm_lf = normalize_task_text(text_lf)
        norm_crlf = normalize_task_text(text_crlf)
        norm_cr = normalize_task_text(text_cr)
        norm_mixed = normalize_task_text(text_mixed)
        norm_uni = normalize_task_text(text_unicode_separators)

        assert norm_lf == "Line 1\nLine 2\n\nLine 3"
        assert norm_crlf == norm_lf
        assert norm_cr == norm_lf
        assert norm_mixed == norm_lf
        assert norm_uni == norm_lf

    # 2. Leading / trailing whitespace policy
    def test_leading_trailing_whitespace_policy(self) -> None:
        raw = "   \n\n\t  Fix the null pointer exception in auth service.   \t\n\n  "
        normalized = normalize_task_text(raw)
        assert normalized == "Fix the null pointer exception in auth service."

        # Per-line trailing whitespace is stripped
        multi_line = "First line with trailing spaces    \nSecond line with trailing tabs\t\t"
        norm_multi = normalize_task_text(multi_line)
        assert norm_multi == "First line with trailing spaces\nSecond line with trailing tabs"

    # 3. Repeated whitespace policy
    def test_repeated_whitespace_policy(self) -> None:
        # Multiple horizontal spaces within unindented line are collapsed to single space
        raw = "Fix    the    severe     latency     issue."
        assert normalize_task_text(raw) == "Fix the severe latency issue."

        # In a multi-line task, indentation is preserved while internal spaces collapse
        indented = "Code block:\n    def    compute(   x,   y   ):\n        return    x   +   y"
        expected = "Code block:\n    def compute( x, y ):\n        return x + y"
        assert normalize_task_text(indented) == expected

        # Sequences of 3+ newlines (2+ blank lines) collapse to 2 newlines (1 blank line)
        excess_blank_lines = "Paragraph 1\n\n\n\n\nParagraph 2"
        assert normalize_task_text(excess_blank_lines) == "Paragraph 1\n\nParagraph 2"

    # 4. Unicode handling (NFC, BOM, control characters, bidi overrides)
    def test_unicode_nfc_and_bom_handling(self) -> None:
        # BOM is stripped
        with_bom = "\ufeffFix unicode encoding issue."
        norm_bom = normalize_task_text(with_bom)
        assert norm_bom == "Fix unicode encoding issue."
        assert not norm_bom.startswith("\ufeff")

        # NFD is normalized to NFC
        decomposed = "cafe\u0301"  # 'e' + combining acute accent (NFD)
        precomposed = "caf\u00e9"  # 'é' (NFC)
        assert unicodedata.is_normalized("NFD", decomposed)
        normalized = normalize_task_text(decomposed)
        assert normalized == precomposed
        assert unicodedata.is_normalized("NFC", normalized)

    def test_unicode_forbidden_characters_rejected(self) -> None:
        # ASCII NUL is strictly rejected
        with pytest.raises(InvalidTaskContentError, match="forbidden null byte"):
            normalize_task_text("Fix issue with \x00 null byte.")

        # Trojan Source Unicode bidi overrides are strictly rejected
        with pytest.raises(InvalidTaskContentError, match="dangerous Unicode bidirectional"):
            normalize_task_text("Fix issue with \u202e reversed text.")

        with pytest.raises(InvalidTaskContentError, match="dangerous Unicode bidirectional"):
            normalize_task_text("Fix issue with \u2066 isolate.")

    # 5. Empty / whitespace-only / meaningless input rejection
    def test_empty_and_whitespace_only_rejection(self) -> None:
        with pytest.raises(EmptyTaskInputError, match="empty or contains only whitespace"):
            normalize_task_text("")

        with pytest.raises(EmptyTaskInputError, match="empty or contains only whitespace"):
            normalize_task_text("    \t\t \n\n\r\n   ")

    def test_insufficient_meaningful_content_rejection(self) -> None:
        # Fewer than MIN_TASK_NON_WHITESPACE_CHARS non-whitespace chars
        with pytest.raises(InvalidTaskContentError, match="insufficient meaningful content"):
            normalize_task_text("   .   ")

        with pytest.raises(InvalidTaskContentError, match="insufficient meaningful content"):
            normalize_task_text("  ok ")

    # 6. Bounded task size / oversized input
    def test_oversized_input_rejection(self) -> None:
        max_bytes = 100
        oversized = "a" * (max_bytes + 1)
        with pytest.raises(TaskSizeLimitExceededError, match="exceeds configured maximum ceiling"):
            ingest_task(oversized, max_bytes=max_bytes)

        # Exact boundary passes
        exact = "a" * max_bytes
        task = ingest_task(exact, max_bytes=max_bytes)
        assert task.character_count == max_bytes

    def test_invalid_max_bytes_type(self) -> None:
        with pytest.raises(TypeError, match="max_bytes must be a positive integer"):
            ingest_task("valid task", max_bytes=-1)

        with pytest.raises(TypeError, match="max_bytes must be a positive integer"):
            ingest_task("valid task", max_bytes=0)

        with pytest.raises(TypeError, match="max_bytes must be a positive integer"):
            ingest_task("valid task", max_bytes="not-an-int")  # type: ignore[arg-type]

    # 7. Deterministic repeated normalization (idempotence)
    def test_idempotent_normalization(self) -> None:
        complex_input = (
            "\ufeff   \r\n\r\n"
            "Feature:   Add   rate limiting   to auth service.\r\n"
            "\r\n\r\n\r\n"
            "Details:\r\n"
            "\t- Limit requests to 100/minute\r\n"
            "\t- Return 429 on limit\r\n\r\n"
        )
        norm_1 = normalize_task_text(complex_input)
        norm_2 = normalize_task_text(norm_1)
        norm_3 = normalize_task_text(norm_2)

        assert norm_1 == norm_2
        assert norm_2 == norm_3

        task_1 = ingest_task(complex_input)
        task_2 = ingest_task(norm_1)
        assert task_1.normalized_text == task_2.normalized_text
        assert task_1.task_digest == task_2.task_digest

    # 8. Round-trip serialization stability
    def test_serialization_round_trip(self) -> None:
        raw = "Fix broken retry executor on 503 response.\nEnsure audit trail is recorded."
        meta = {"author": "engineer@example.com", "priority": "high"}
        task = ingest_task(raw, metadata=meta)

        d = task.to_dict()
        restored = NormalizedTask.from_dict(d)

        assert restored == task
        assert restored.raw_text == task.raw_text
        assert restored.normalized_text == task.normalized_text
        assert restored.task_digest == task.task_digest
        assert restored.raw_digest == task.raw_digest
        assert restored.byte_length == task.byte_length
        assert restored.character_count == task.character_count
        assert restored.line_count == task.line_count
        assert restored.metadata == task.metadata

        # Canonical bytes round trip
        cbytes = task.to_canonical_bytes()
        assert isinstance(cbytes, bytes)
        assert len(cbytes) > 0

    # 9. Tamper detection on NormalizedTask
    def test_tamper_detection(self) -> None:
        raw = "Valid task description"
        task = ingest_task(raw)

        # Forged task_digest
        with pytest.raises(ValueError, match="task_digest mismatch"):
            NormalizedTask(
                raw_text=task.raw_text,
                normalized_text=task.normalized_text,
                task_digest="0" * 64,
                raw_digest=task.raw_digest,
                byte_length=task.byte_length,
                character_count=task.character_count,
                line_count=task.line_count,
                metadata={},
            )

        # Forged raw_digest
        with pytest.raises(ValueError, match="raw_digest mismatch"):
            NormalizedTask(
                raw_text=task.raw_text,
                normalized_text=task.normalized_text,
                task_digest=task.task_digest,
                raw_digest="0" * 64,
                byte_length=task.byte_length,
                character_count=task.character_count,
                line_count=task.line_count,
                metadata={},
            )

        # Forged byte_length
        with pytest.raises(ValueError, match="byte_length mismatch"):
            NormalizedTask(
                raw_text=task.raw_text,
                normalized_text=task.normalized_text,
                task_digest=task.task_digest,
                raw_digest=task.raw_digest,
                byte_length=99999,
                character_count=task.character_count,
                line_count=task.line_count,
                metadata={},
            )

    # 10. Secret-shaped input is treated as task content without accidental leakage in logs/repr
    def test_secret_shaped_input_handling(self) -> None:
        secret = "sk-nebius-secret-token-abcdef1234567890"
        raw_text = f"Fix bug where bearer token {secret} fails parsing in auth header."

        task = ingest_task(raw_text)

        # Secret is preserved in raw and normalized task content
        assert secret in task.raw_text
        assert secret in task.normalized_text

        # Secret is REDACTED in safe_summary
        summary = task.safe_summary()
        assert secret not in summary
        assert "[REDACTED]" in summary

        # Secret is NOT present in NormalizedTask.__repr__
        repr_str = repr(task)
        assert secret not in repr_str
        assert "NormalizedTask(" in repr_str
        assert task.task_digest[:16] in repr_str

    # 11. Bytes input vs string input
    def test_bytes_input_handling(self) -> None:
        text = "Task provided as raw UTF-8 bytes."
        raw_bytes = text.encode("utf-8")

        task_from_bytes = ingest_task(raw_bytes)
        task_from_str = ingest_task(text)

        assert task_from_bytes.raw_text == task_from_str.raw_text
        assert task_from_bytes.normalized_text == task_from_str.normalized_text
        assert task_from_bytes.task_digest == task_from_str.task_digest
        assert task_from_bytes.raw_digest == task_from_str.raw_digest

    def test_invalid_utf8_bytes_rejected(self) -> None:
        invalid_bytes = b"\xff\xfe\x00\x00Invalid"
        with pytest.raises(InvalidTaskContentError, match="could not be decoded as UTF-8"):
            ingest_task(invalid_bytes)

    # 12. Provider purity: compiler/ingestion never imports adapters
    def test_provider_purity_compiler_ingestion(self) -> None:
        compiler_dir = (
            Path(__file__).resolve().parent.parent.parent / "src" / "basebreak" / "compiler"
        )
        for py_file in compiler_dir.glob("**/*.py"):
            text = py_file.read_text(encoding="utf-8")
            assert "basebreak.adapters" not in text, f"Leakage found in {py_file}"
            assert "from .adapters" not in text, f"Leakage found in {py_file}"
