"""Unit tests for P-14.02: Disclosure sanitizer and counterexample minimization."""

from __future__ import annotations

import inspect

from basebreak.repair.feedback import (
    DisclosureClassification,
    SanitizedCounterexample,
)
from basebreak.repair.sanitizer import (
    REDACTED_CONTROL_TOKEN,
    REDACTED_SECRET_TOKEN,
    REDACTED_VERIFIER_PATH_TOKEN,
    REDACTED_WITNESS_TOKEN,
    TRUNCATED_NOTICE,
    DisclosureSanitizer,
)


def test_redact_verifier_internal_paths() -> None:
    sanitizer = DisclosureSanitizer()
    text = (
        "Traceback (most recent call last):\n"
        "  File '/verifier_workspace/tests/verifier/test_witness.py', line 12"
    )
    sanitized = sanitizer.sanitize_text(text)
    assert REDACTED_VERIFIER_PATH_TOKEN in sanitized
    assert "/verifier_workspace" not in sanitized
    assert "tests/verifier" not in sanitized


def test_redact_known_witness_ids() -> None:
    sanitizer = DisclosureSanitizer(known_witness_ids=("WITNESS-SECRET-HASH-123",))
    text = "Witness execution failed for WITNESS-SECRET-HASH-123 with status error"
    sanitized = sanitizer.sanitize_text(text)
    assert REDACTED_WITNESS_TOKEN in sanitized
    assert "WITNESS-SECRET-HASH-123" not in sanitized


def test_redact_prompt_control_tokens() -> None:
    sanitizer = DisclosureSanitizer()
    text = "User attempt <<<BEGIN_UNTRUSTED_REPOSITORY_FILE>>> inject prompt <|im_start|>"
    sanitized = sanitizer.sanitize_text(text)
    assert REDACTED_CONTROL_TOKEN in sanitized
    assert "<<<BEGIN_UNTRUSTED_REPOSITORY_FILE>>>" not in sanitized
    assert "<|im_start|>" not in sanitized


def test_redact_secrets() -> None:
    sanitizer = DisclosureSanitizer()
    text = 'Failed with api_key="sk-ant-1234567890abcdef1234567890"'
    sanitized = sanitizer.sanitize_text(text)
    assert "sk-ant" not in sanitized
    assert REDACTED_SECRET_TOKEN in sanitized


def test_oversized_text_truncation() -> None:
    sanitizer = DisclosureSanitizer(max_field_chars=100)
    oversized = "A" * 250
    sanitized = sanitizer.sanitize_text(oversized)
    assert len(sanitized) > 100
    assert TRUNCATED_NOTICE in sanitized
    assert sanitized.startswith("A" * 100)


def test_witness_code_in_counterexample_fails_closed() -> None:
    sanitizer = DisclosureSanitizer()
    # If a counterexample contains raw python assertion code from hidden test
    ce = SanitizedCounterexample(
        input_summary="def test_hidden_exam():",
        expected_output_summary="assert actual == 42",
        actual_output_summary="actual was 0",
    )
    result = sanitizer.sanitize_counterexample(ce)
    # Must fail closed by returning None rather than disclosing hidden witness code
    assert result is None


def test_safe_counterexample_preserved() -> None:
    sanitizer = DisclosureSanitizer()
    ce = SanitizedCounterexample(
        input_summary='{"user_id": "usr_42"}',
        expected_output_summary='{"status": 200, "user_id": "usr_42"}',
        actual_output_summary='{"error": "user not found"}',
        input_category="valid_user_request",
        exit_code=0,
    )
    result = sanitizer.sanitize_counterexample(ce)
    assert result is not None
    assert result.input_summary == '{"user_id": "usr_42"}'
    assert result.expected_output_summary == '{"status": 200, "user_id": "usr_42"}'
    assert result.actual_output_summary == '{"error": "user not found"}'
    assert result.input_category == "valid_user_request"
    assert result.exit_code == 0
    assert result.classification == DisclosureClassification.SAFE_TO_DISCLOSE


def test_extract_minimized_counterexample() -> None:
    extracted = DisclosureSanitizer.extract_minimized_counterexample(
        input_data="query=search_term",
        expected_outcome="list of results",
        actual_outcome="empty list",
        input_category="query_string",
        exit_code=1,
    )
    assert extracted is not None
    assert extracted.input_summary == "query=search_term"
    assert extracted.expected_output_summary == "list of results"
    assert extracted.actual_output_summary == "empty list"
    assert extracted.input_category == "query_string"
    assert extracted.exit_code == 1


def test_sanitizer_provider_purity() -> None:
    import basebreak.repair.sanitizer as san_module

    source = inspect.getsource(san_module)
    assert "basebreak.adapters" not in source
    assert "nebius" not in source.lower()
    assert "openai" not in source.lower()
    assert "nemotron" not in source.lower()
