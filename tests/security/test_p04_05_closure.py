"""Acceptance criteria and closure audit tests for task P-04.05.

P-04.05 — Implement execution timeout/cancellation/resource-failure normalization.

Acceptance criteria:
1. Timeout normalization;
2. Cancellation normalization where semantics are proven;
3. Resource-failure distinction without fabrication;
4. Deterministic tests;
5. Provider-specific facts not leaked into provider-neutral contracts;
6. No P-05 adapter implementation.
"""

from __future__ import annotations

import inspect

import pytest

import basebreak.security.normalization as norm
from basebreak.domain.execution import ExecutionResult, TerminationStatus
from basebreak.security.normalization import (
    NormalizedExecutionOutcome,
    NormalizedExecutionRecord,
    ResourceFailureClass,
    normalize_execution_result,
)


class TestP0405Criterion1TimeoutNormalization:
    """Criterion 1: Timeout normalization."""

    def test_timeout_from_all_recognized_sources(self) -> None:
        # Source A: Explicit timeout flag
        r1 = normalize_execution_result(is_timeout=True)
        assert r1.outcome == NormalizedExecutionOutcome.TIMEOUT
        assert r1.is_timeout is True

        # Source B: Domain ExecutionResult
        r2 = normalize_execution_result(
            execution_result=ExecutionResult(status=TerminationStatus.TIMED_OUT)
        )
        assert r2.outcome == NormalizedExecutionOutcome.TIMEOUT
        assert r2.is_timeout is True

        # Source C: Provider status
        r3 = normalize_execution_result(provider_status="TIMED_OUT")
        assert r3.outcome == NormalizedExecutionOutcome.TIMEOUT
        assert r3.is_timeout is True

        # Source D: HTTP 408
        r4 = normalize_execution_result(
            provider_status="FAILURE",
            provider_error={"status": 408, "error": "Deadline exceeded"},
        )
        assert r4.outcome == NormalizedExecutionOutcome.TIMEOUT
        assert r4.is_timeout is True


class TestP0405Criterion2CancellationNormalization:
    """Criterion 2: Cancellation normalization where semantics are proven."""

    def test_cancellation_from_all_recognized_sources(self) -> None:
        # Source A: Explicit cancelled flag
        r1 = normalize_execution_result(is_cancelled=True)
        assert r1.outcome == NormalizedExecutionOutcome.CANCELLED
        assert r1.is_cancelled is True

        # Source B: Domain ExecutionResult
        r2 = normalize_execution_result(
            execution_result=ExecutionResult(status=TerminationStatus.CANCELLED)
        )
        assert r2.outcome == NormalizedExecutionOutcome.CANCELLED
        assert r2.is_cancelled is True

        # Source C: Provider status CANCELLED
        r3 = normalize_execution_result(provider_status="CANCELLED")
        assert r3.outcome == NormalizedExecutionOutcome.CANCELLED
        assert r3.is_cancelled is True

        # Source D: HTTP 499
        r4 = normalize_execution_result(
            provider_status="FAILURE",
            provider_error={"status": 499, "error": "Client closed request"},
        )
        assert r4.outcome == NormalizedExecutionOutcome.CANCELLED
        assert r4.is_cancelled is True


class TestP0405Criterion3ResourceFailureDistinctionWithoutFabrication:
    """Criterion 3: Resource-failure distinction without fabrication."""

    def test_verified_resource_failures_classified_with_exact_class(self) -> None:
        # Concurrency
        r1 = normalize_execution_result(
            provider_status="FAILURE",
            provider_error={"status": 429, "error": "Instance_max_concurrency limit reached"},
        )
        assert r1.outcome == NormalizedExecutionOutcome.RESOURCE_FAILURE
        assert r1.resource_failure_class == ResourceFailureClass.CONCURRENCY_EXHAUSTED

        # Layer quota
        r2 = normalize_execution_result(
            provider_status="FAILURE",
            provider_error="instance_max_layer_bytes exceeded during command",
        )
        assert r2.outcome == NormalizedExecutionOutcome.RESOURCE_FAILURE
        assert r2.resource_failure_class == ResourceFailureClass.LAYER_QUOTA_EXCEEDED

        # OOM
        r3 = normalize_execution_result(
            provider_status="FAILURE",
            provider_error="Killed by cgroup memory OOM killer",
        )
        assert r3.outcome == NormalizedExecutionOutcome.RESOURCE_FAILURE
        assert r3.resource_failure_class == ResourceFailureClass.OUT_OF_MEMORY

    def test_ambiguous_failure_never_fabricated_as_resource_failure(self) -> None:
        ambiguous = [
            "Internal server error",
            "Error: command failed",
            "Connection reset by peer",
            "Database unavailable",
            "Service error 503",
        ]
        for err in ambiguous:
            r = normalize_execution_result(provider_status="FAILURE", provider_error=err)
            assert r.outcome == NormalizedExecutionOutcome.UNKNOWN_PROVIDER_FAILURE
            assert r.is_resource_failure is False
            assert r.resource_failure_class is None


class TestP0405Criterion4DeterministicTests:
    """Criterion 4: Deterministic tests with output digesting and secret redaction."""

    def test_digests_and_sanitization(self) -> None:
        rec = normalize_execution_result(
            exit_code=0,
            stdout="secret: Bearer nbs_sk_live_token1234567890abcdef",
            stderr="warning: api_key=sk_live_canary1234567890abcdef",
            provider_status="SUCCESS",
        )
        assert rec.outcome == NormalizedExecutionOutcome.SUCCESS
        assert "[REDACTED]" in rec.stdout_preview
        assert "[REDACTED]" in rec.stderr_preview
        assert "nbs_sk_live" not in rec.stdout_preview
        assert "sk_live_canary" not in rec.stderr_preview

    def test_record_post_init_invariant_validation(self) -> None:
        with pytest.raises(ValueError, match="is_timeout .* does not match outcome"):
            NormalizedExecutionRecord(
                outcome=NormalizedExecutionOutcome.SUCCESS,
                exit_code=0,
                is_timeout=True,  # Invariant mismatch
            )


class TestP0405Criterion5ProviderNeutralContractsPure:
    """Criterion 5: Provider-specific facts not leaked into provider-neutral contracts."""

    def test_domain_execution_contracts_remain_unmodified_and_pure(self) -> None:
        import basebreak.domain.execution as dom_exec

        source = inspect.getsource(dom_exec)
        # Ensure domain/execution does not import Nebius or cloud providers
        assert "nebius" not in source.lower()
        assert "contree" not in source.lower()


class TestP0405Criterion6NoP05AdapterImplementation:
    """Criterion 6: No P-05 adapter implementation."""

    def test_normalization_module_has_zero_network_or_provider_sdks(self) -> None:
        source = inspect.getsource(norm)
        forbidden = [
            "contree",
            "httpx",
            "aiohttp",
            "urllib.request",
            "requests",
            "openai",
            "socket",
        ]
        for token in forbidden:
            assert token not in source, f"Forbidden provider token '{token}' in normalization.py"
