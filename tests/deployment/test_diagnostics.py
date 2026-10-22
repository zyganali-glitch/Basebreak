"""Adversarial tests for diagnostic observability and sanitization (P-27.06)."""

from __future__ import annotations

import tempfile
from pathlib import Path

from basebreak.deployment.diagnostics import (
    DiagnosticCategory,
    ExecutionDiagnosticRecord,
    WorldDiagnostic,
    classify_execution_diagnostic,
    load_execution_diagnostics,
    record_execution_diagnostics,
    sanitize_diagnostic_excerpt,
)


def test_classify_execution_diagnostic_categories() -> None:
    # PASS
    assert (
        classify_execution_diagnostic(exit_code=0, termination_status="COMPLETED")
        == DiagnosticCategory.PASS
    )

    # TIMEOUT
    assert (
        classify_execution_diagnostic(exit_code=None, termination_status="TIMED_OUT")
        == DiagnosticCategory.TIMEOUT
    )

    # SYNTAX
    assert (
        classify_execution_diagnostic(
            exit_code=2,
            termination_status="COMPLETED",
            stdout='File "vault.py", line 1\n  def foo():\nIndentationError: unexpected indent',
        )
        == DiagnosticCategory.SYNTAX
    )
    assert (
        classify_execution_diagnostic(
            exit_code=1,
            termination_status="COMPLETED",
            stderr="SyntaxError: invalid syntax",
        )
        == DiagnosticCategory.SYNTAX
    )

    # IMPORT
    assert (
        classify_execution_diagnostic(
            exit_code=2,
            termination_status="COMPLETED",
            stdout="ModuleNotFoundError: No module named 'vault'",
        )
        == DiagnosticCategory.IMPORT
    )
    assert (
        classify_execution_diagnostic(
            exit_code=1,
            termination_status="COMPLETED",
            stderr="ImportError: cannot import name 'ResetVault'",
        )
        == DiagnosticCategory.IMPORT
    )

    # COLLECTION
    assert (
        classify_execution_diagnostic(
            exit_code=2,
            termination_status="COMPLETED",
            stdout="ERROR collecting test_vault.py\n1 error during collection",
        )
        == DiagnosticCategory.COLLECTION
    )
    assert (
        classify_execution_diagnostic(
            exit_code=5,
            termination_status="COMPLETED",
            stdout="collected 0 items",
        )
        == DiagnosticCategory.COLLECTION
    )

    # TEST (exit code 1 with test failure)
    assert (
        classify_execution_diagnostic(
            exit_code=1,
            termination_status="COMPLETED",
            stdout="FAILED test_vault.py::test_foo - AssertionError: assert True is False",
        )
        == DiagnosticCategory.TEST
    )

    # INFRASTRUCTURE
    assert (
        classify_execution_diagnostic(exit_code=None, termination_status="FAILED_TO_START")
        == DiagnosticCategory.INFRASTRUCTURE
    )
    assert (
        classify_execution_diagnostic(exit_code=None, termination_status="CANCELLED")
        == DiagnosticCategory.INFRASTRUCTURE
    )


def test_sanitize_diagnostic_excerpt_redacts_secrets_and_witness() -> None:
    raw_text = (
        "Execution failed with token sk-abcdef1234567890abcdef and\n"
        "Authorization Bearer eyJhbGciOiJIUzI1NiIsInR5cCI6...\n"
        "witness path: tests/fixtures/reset_vault/witness/test_single_use_witness.py\n"
        "assert second_res is False\n"
        "Ordinary line that should be kept."
    )
    sanitized = sanitize_diagnostic_excerpt(raw_text, redact_witness=True)
    assert "sk-abcdef1234567890abcdef" not in sanitized
    assert "[REDACTED_KEY]" in sanitized
    assert "Bearer eyJhbGciOiJIUzI1NiIsInR5cCI6" not in sanitized
    assert "[REDACTED_BEARER]" in sanitized
    assert "test_single_use_witness" not in sanitized
    assert "assert second_res" not in sanitized
    assert "[SEALED_WITNESS_REDACTED]" in sanitized
    assert "Ordinary line that should be kept." in sanitized


def test_sanitize_diagnostic_excerpt_truncation() -> None:
    long_text = "A" * 2000
    sanitized = sanitize_diagnostic_excerpt(long_text, max_chars=100)
    assert len(sanitized) <= 150
    assert sanitized.endswith("... [truncated]")
    assert sanitized.startswith("A" * 100)


def test_diagnostic_persistence_and_readback() -> None:
    with tempfile.TemporaryDirectory() as tmp_dir:
        state_dir = Path(tmp_dir)
        world_diag = WorldDiagnostic(
            world="CANDIDATE",
            sandbox_id="sbx-test-123",
            exit_code=2,
            outcome="ERROR",
            diagnostic_category=DiagnosticCategory.SYNTAX,
            stdout_digest="a" * 64,
            stderr_digest="b" * 64,
            safe_stdout_excerpt="IndentationError: unexpected indent",
            safe_stderr_excerpt=None,
        )
        record = ExecutionDiagnosticRecord(
            request_id="req-test-999",
            source_commit_id="c" * 40,
            candidate_patch_digest="d" * 64,
            candidate_tree_digest="e" * 40,
            world_diagnostics=(world_diag,),
            overall_verdict="INCONCLUSIVE",
            created_at_utc="2026-10-22T19:00:00Z",
        )

        saved_path = record_execution_diagnostics(state_dir, record)
        assert saved_path.is_file()

        loaded = load_execution_diagnostics(state_dir, "req-test-999")
        assert loaded is not None
        assert loaded.request_id == "req-test-999"
        assert loaded.source_commit_id == "c" * 40
        assert loaded.candidate_patch_digest == "d" * 64
        assert loaded.candidate_tree_digest == "e" * 40
        assert len(loaded.world_diagnostics) == 1
        assert loaded.world_diagnostics[0].diagnostic_category == DiagnosticCategory.SYNTAX
        assert (
            loaded.world_diagnostics[0].safe_stdout_excerpt == "IndentationError: unexpected indent"
        )

        # Non-existent request returns None
        assert load_execution_diagnostics(state_dir, "non-existent") is None
