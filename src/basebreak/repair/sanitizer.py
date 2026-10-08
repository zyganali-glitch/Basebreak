"""Disclosure sanitizer and counterexample minimization for sealed repair.

P-14.02: Return minimized counterexample without hidden witness disclosure.

Core Invariants:
1. Prevent disclosure of hidden witness code, private assertion logic, verifier filesystem
   paths, vault contents, and secret credentials.
2. Bounded and sanitized feedback: trims oversized text to explicit byte ceilings.
3. Mechanical sanitization: redacts paths matching verifier protected directories,
   known witness identifiers, prompt control tokens, and credential patterns.
4. Fail-closed safety: if a counterexample contains sensitive witness or credential material
   that cannot be safely minimized, emit coarse summary or None rather than leaking evidence.
5. No false statements: sanitizer does not manufacture or invent expected values.
"""

from __future__ import annotations

import re

from basebreak.repair.feedback import (
    DisclosureClassification,
    RepairFeedbackError,
    SanitizedCounterexample,
)
from basebreak.security.secret_policy import contains_secret

MAX_DISCLOSURE_FIELD_CHARS: int = 1024
MAX_DISCLOSURE_TOTAL_CHARS: int = 4096

REDACTED_SECRET_TOKEN: str = "[REDACTED_SECRET]"
REDACTED_VERIFIER_PATH_TOKEN: str = "[REDACTED_VERIFIER_PATH]"
REDACTED_WITNESS_TOKEN: str = "[REDACTED_WITNESS]"
REDACTED_CONTROL_TOKEN: str = "[REDACTED_CONTROL_TOKEN]"
TRUNCATED_NOTICE: str = " [TRUNCATED: length ceiling exceeded]"

VERIFIER_INTERNAL_PATH_PATTERNS: tuple[re.Pattern[str], ...] = (
    re.compile(r"(/verifier_workspace[^\s\"']*)", re.IGNORECASE),
    re.compile(r"((?:src|tests)/basebreak/verifier[^\s\"']*)", re.IGNORECASE),
    re.compile(r"((?:src|tests)/verifier[^\s\"']*)", re.IGNORECASE),
    re.compile(r"(\.sealed_vault[^\s\"']*)", re.IGNORECASE),
    re.compile(r"(\.sealed[^\s\"']*)", re.IGNORECASE),
    re.compile(r"(sealed_witnesses[^\s\"']*)", re.IGNORECASE),
    re.compile(r"(/tmp/verifier[^\s\"']*)", re.IGNORECASE),
)

PROMPT_CONTROL_TOKEN_PATTERNS: tuple[re.Pattern[str], ...] = (
    re.compile(r"<<<BEGIN_UNTRUSTED_REPOSITORY_FILE>>>", re.IGNORECASE),
    re.compile(r"<<<END_UNTRUSTED_REPOSITORY_FILE>>>", re.IGNORECASE),
    re.compile(r"<\|im_start\|>", re.IGNORECASE),
    re.compile(r"<\|im_end\|>", re.IGNORECASE),
    re.compile(r"<\|endoftext\|>", re.IGNORECASE),
)

WITNESS_CODE_MARKER_PATTERNS: tuple[re.Pattern[str], ...] = (
    re.compile(r"(?:def\s+test_[a-zA-Z0-9_]+\s*\([^)]*\)\s*:)", re.IGNORECASE),
    re.compile(r"(?:assert\s+[^\n;]+==[^\n;]+)", re.IGNORECASE),
    re.compile(r"(?:pytest\.raises\s*\([^)]*\))", re.IGNORECASE),
)


class DisclosureSanitizerError(RepairFeedbackError):
    """Base exception for disclosure sanitization errors."""


class UnsafeDisclosureError(DisclosureSanitizerError):
    """Raised when feedback cannot be safely minimized or contains forbidden material."""


class DisclosureSanitizer:
    """Mechanical sanitizer for verifier-emitted repair feedback and counterexamples."""

    def __init__(
        self,
        *,
        known_witness_ids: tuple[str, ...] = (),
        max_field_chars: int = MAX_DISCLOSURE_FIELD_CHARS,
    ) -> None:
        self._known_witness_ids = tuple(wid for wid in known_witness_ids if wid.strip())
        self._max_field_chars = max_field_chars

    def sanitize_text(self, text: str, *, field_name: str = "text") -> str:
        """Sanitize a text field by redacting secrets, verifier paths, and control tokens."""
        if not text:
            return ""

        # 1. Bounded size truncation
        cleaned = text
        if len(cleaned) > self._max_field_chars:
            cleaned = cleaned[: self._max_field_chars] + TRUNCATED_NOTICE

        # 2. Redact verifier internal paths
        for pat in VERIFIER_INTERNAL_PATH_PATTERNS:
            cleaned = pat.sub(REDACTED_VERIFIER_PATH_TOKEN, cleaned)

        # 3. Redact prompt control tokens
        for pat in PROMPT_CONTROL_TOKEN_PATTERNS:
            cleaned = pat.sub(REDACTED_CONTROL_TOKEN, cleaned)

        # 4. Redact known witness identifiers
        for wid in self._known_witness_ids:
            if wid in cleaned:
                cleaned = cleaned.replace(wid, REDACTED_WITNESS_TOKEN)

        # 5. Check and redact secrets
        if contains_secret(cleaned):
            # If contains_secret returns true, attempt pattern-level masking
            # Replace high-entropy or recognizable secret patterns
            cleaned = re.sub(
                r"(?i)(?:api[_-]?key|bearer|token|secret|password|auth)[\s:=]+['\"]?([a-zA-Z0-9_\-]{16,})['\"]?",
                r"key=" + REDACTED_SECRET_TOKEN,
                cleaned,
            )
            # If still flagged as containing a secret, fail closed with replacement
            if contains_secret(cleaned):
                cleaned = REDACTED_SECRET_TOKEN

        # 6. Redact binary or control characters (except newline, tab, carriage return)
        cleaned = "".join(
            ch if ch in ("\n", "\r", "\t") or ord(ch) >= 32 else " " for ch in cleaned
        )

        return cleaned

    def sanitize_stdout_stderr(self, raw_output: str) -> str:
        """Sanitize raw execution stdout/stderr streams."""
        if not raw_output:
            return ""

        # Remove potential witness code markers
        sanitized = self.sanitize_text(raw_output, field_name="raw_output")
        for pat in WITNESS_CODE_MARKER_PATTERNS:
            sanitized = pat.sub(REDACTED_WITNESS_TOKEN, sanitized)

        return sanitized

    def sanitize_counterexample(
        self,
        counterexample: SanitizedCounterexample,
    ) -> SanitizedCounterexample | None:
        """Sanitize a counterexample or return None if it cannot be safely disclosed."""
        # Check if input or expected summary contains raw witness code
        for pat in WITNESS_CODE_MARKER_PATTERNS:
            if pat.search(counterexample.input_summary) or pat.search(
                counterexample.expected_output_summary
            ):
                # Contains raw assertion/witness code: cannot be safely minimized
                return None

        # Sanitize all text fields
        input_sanitized = self.sanitize_text(
            counterexample.input_summary, field_name="input_summary"
        )
        expected_sanitized = self.sanitize_text(
            counterexample.expected_output_summary, field_name="expected_output_summary"
        )
        actual_sanitized = self.sanitize_text(
            counterexample.actual_output_summary, field_name="actual_output_summary"
        )
        category_sanitized = self.sanitize_text(
            counterexample.input_category, field_name="input_category"
        )

        # If any field was entirely replaced by REDACTED_SECRET_TOKEN, drop counterexample
        if (
            input_sanitized == REDACTED_SECRET_TOKEN
            or expected_sanitized == REDACTED_SECRET_TOKEN
            or actual_sanitized == REDACTED_SECRET_TOKEN
        ):
            return None

        return SanitizedCounterexample(
            input_summary=input_sanitized,
            expected_output_summary=expected_sanitized,
            actual_output_summary=actual_sanitized,
            input_category=category_sanitized,
            exit_code=counterexample.exit_code,
            is_sanitized=True,
            classification=DisclosureClassification.SAFE_TO_DISCLOSE,
        )

    @staticmethod
    def extract_minimized_counterexample(
        *,
        input_data: str,
        expected_outcome: str,
        actual_outcome: str,
        input_category: str = "",
        exit_code: int | None = None,
        known_witness_ids: tuple[str, ...] = (),
    ) -> SanitizedCounterexample | None:
        """Extract and mechanically sanitize a minimized counterexample from execution facts."""
        sanitizer = DisclosureSanitizer(known_witness_ids=known_witness_ids)

        # Check if raw input data contains witness code
        for pat in WITNESS_CODE_MARKER_PATTERNS:
            if pat.search(input_data) or pat.search(expected_outcome):
                return None

        # Sanitize parts
        san_input = sanitizer.sanitize_text(input_data)
        san_expected = sanitizer.sanitize_text(expected_outcome)
        san_actual = sanitizer.sanitize_text(actual_outcome)
        san_cat = sanitizer.sanitize_text(input_category)

        if (
            not san_input.strip()
            or not san_expected.strip()
            or not san_actual.strip()
            or san_input == REDACTED_SECRET_TOKEN
            or san_expected == REDACTED_SECRET_TOKEN
            or san_actual == REDACTED_SECRET_TOKEN
        ):
            return None

        return SanitizedCounterexample(
            input_summary=san_input,
            expected_output_summary=san_expected,
            actual_output_summary=san_actual,
            input_category=san_cat,
            exit_code=exit_code,
            is_sanitized=True,
            classification=DisclosureClassification.SAFE_TO_DISCLOSE,
        )
