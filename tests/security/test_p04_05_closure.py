"""Acceptance criteria and closure audit tests for task P-04.05.

P-04.05 — Implement execution timeout/cancellation/resource-failure normalization.

Acceptance criteria:
1. Timeout normalization;
2. Cancellation normalization where semantics are proven;
3. Resource-failure distinction without fabrication;
4. Deterministic tests;
5. Provider-specific facts not leaked into provider-neutral contracts;
6. No P-05 adapter implementation;
7. Authoritative-fact conflict detection and fail-closed resolution.
"""

from __future__ import annotations

import inspect
from typing import Any, cast

import pytest

import basebreak.security.normalization as norm
from basebreak.domain.execution import ExecutionResult, TerminationStatus
from basebreak.security.normalization import (
    NormalizationConflictError,
    NormalizedExecutionOutcome,
    NormalizedExecutionRecord,
    ResourceFailureClass,
    normalize_execution_result,
)


class TestP0405Criterion1TimeoutNormalization:
    """Criterion 1: Timeout normalization from authoritative facts."""

    def test_timeout_from_authoritative_sources(self) -> None:
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

    def test_ambiguous_timeout_prose_or_http_408_never_self_promotes(self) -> None:
        # Ambiguous HTTP 408 alone must fail closed as UNKNOWN_PROVIDER_FAILURE
        r3 = normalize_execution_result(
            provider_status="FAILURE",
            provider_error={"status": 408, "error": "Deadline exceeded"},
        )
        assert r3.outcome == NormalizedExecutionOutcome.UNKNOWN_PROVIDER_FAILURE
        assert r3.is_timeout is False

        # Generic timeout string alone must fail closed
        r4 = normalize_execution_result(
            provider_status="FAILURE",
            provider_error="Instance execution timeout exceeded 180s",
        )
        assert r4.outcome == NormalizedExecutionOutcome.UNKNOWN_PROVIDER_FAILURE
        assert r4.is_timeout is False

        # Unproven status string alone must fail closed
        r5 = normalize_execution_result(provider_status="TIMED_OUT")
        assert r5.outcome == NormalizedExecutionOutcome.UNKNOWN_PROVIDER_FAILURE
        assert r5.is_timeout is False


class TestP0405Criterion2CancellationNormalization:
    """Criterion 2: Cancellation normalization from authoritative facts."""

    def test_cancellation_from_authoritative_sources(self) -> None:
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

    def test_ambiguous_cancellation_prose_or_http_499_never_self_promotes(self) -> None:
        # HTTP 499 alone must fail closed
        r3 = normalize_execution_result(
            provider_status="FAILURE",
            provider_error={"status": 499, "error": "Client closed request"},
        )
        assert r3.outcome == NormalizedExecutionOutcome.UNKNOWN_PROVIDER_FAILURE
        assert r3.is_cancelled is False

        # Unproven status string alone must fail closed
        r4 = normalize_execution_result(provider_status="CANCELLED")
        assert r4.outcome == NormalizedExecutionOutcome.UNKNOWN_PROVIDER_FAILURE
        assert r4.is_cancelled is False


class TestP0405Criterion3ResourceFailureDistinctionWithoutFabrication:
    """Criterion 3: Resource-failure distinction without fabrication."""

    def test_verified_resource_failures_classified_with_exact_class(self) -> None:
        # Concurrency
        r1 = normalize_execution_result(
            resource_failure_class=ResourceFailureClass.CONCURRENCY_EXHAUSTED
        )
        assert r1.outcome == NormalizedExecutionOutcome.RESOURCE_FAILURE
        assert r1.resource_failure_class == ResourceFailureClass.CONCURRENCY_EXHAUSTED

        # Layer quota
        r2 = normalize_execution_result(
            resource_failure_class=ResourceFailureClass.LAYER_QUOTA_EXCEEDED
        )
        assert r2.outcome == NormalizedExecutionOutcome.RESOURCE_FAILURE
        assert r2.resource_failure_class == ResourceFailureClass.LAYER_QUOTA_EXCEEDED

        # OOM
        r3 = normalize_execution_result(resource_failure_class=ResourceFailureClass.OUT_OF_MEMORY)
        assert r3.outcome == NormalizedExecutionOutcome.RESOURCE_FAILURE
        assert r3.resource_failure_class == ResourceFailureClass.OUT_OF_MEMORY

    def test_ambiguous_failure_or_generic_prose_never_self_promotes(self) -> None:
        ambiguous = [
            "Internal server error",
            "Error: command failed",
            "Connection reset by peer",
            "Database unavailable",
            "Service error 503",
            "Process killed by cgroup memory OOM killer",
            "instance_max_layer_bytes exceeded during command",
            "Max concurrency limit of 50 reached",
        ]
        for err in ambiguous:
            r = normalize_execution_result(provider_status="FAILURE", provider_error=err)
            assert r.outcome == NormalizedExecutionOutcome.UNKNOWN_PROVIDER_FAILURE
            assert r.is_resource_failure is False
            assert r.resource_failure_class is None

        # HTTP 429 alone must not self-promote
        r_429 = normalize_execution_result(
            provider_status="FAILURE",
            provider_error={"status": 429, "error": "rate limit"},
        )
        assert r_429.outcome == NormalizedExecutionOutcome.UNKNOWN_PROVIDER_FAILURE
        assert r_429.is_resource_failure is False


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


class TestP0405Criterion7AuthoritativeFactConflictFailClosed:
    """Criterion 7: Contradictory authoritative execution facts fail closed deterministically."""

    def test_direct_terminal_facts_conflicts_rejected(self) -> None:
        # 1. timeout + cancelled => conflict error
        with pytest.raises(
            NormalizationConflictError, match="both is_timeout=True and is_cancelled=True"
        ):
            normalize_execution_result(is_timeout=True, is_cancelled=True)

        # 2. timeout + resource_failure_class => conflict error
        with pytest.raises(
            NormalizationConflictError, match="both is_timeout=True and resource_failure_class="
        ):
            normalize_execution_result(
                is_timeout=True,
                resource_failure_class=ResourceFailureClass.OUT_OF_MEMORY,
            )

        # 3. cancelled + resource_failure_class => conflict error
        with pytest.raises(
            NormalizationConflictError, match="both is_cancelled=True and resource_failure_class="
        ):
            normalize_execution_result(
                is_cancelled=True,
                resource_failure_class=ResourceFailureClass.CONCURRENCY_EXHAUSTED,
            )

    def test_domain_execution_result_reconciled_with_explicit_facts(self) -> None:
        # 4. ExecutionResult(TIMED_OUT) + explicit cancelled => conflict
        with pytest.raises(
            NormalizationConflictError, match="status TIMED_OUT but is_cancelled=True"
        ):
            normalize_execution_result(
                execution_result=ExecutionResult(status=TerminationStatus.TIMED_OUT),
                is_cancelled=True,
            )

        # 5. ExecutionResult(CANCELLED) + explicit timeout => conflict
        with pytest.raises(
            NormalizationConflictError, match="status CANCELLED but is_timeout=True"
        ):
            normalize_execution_result(
                execution_result=ExecutionResult(status=TerminationStatus.CANCELLED),
                is_timeout=True,
            )

        # ExecutionResult(TIMED_OUT) + resource_failure_class => conflict
        with pytest.raises(
            NormalizationConflictError, match="status TIMED_OUT but resource_failure_class="
        ):
            normalize_execution_result(
                execution_result=ExecutionResult(status=TerminationStatus.TIMED_OUT),
                resource_failure_class=ResourceFailureClass.OUT_OF_MEMORY,
            )

        # ExecutionResult(CANCELLED) + resource_failure_class => conflict
        with pytest.raises(
            NormalizationConflictError, match="status CANCELLED but resource_failure_class="
        ):
            normalize_execution_result(
                execution_result=ExecutionResult(status=TerminationStatus.CANCELLED),
                resource_failure_class=ResourceFailureClass.OUT_OF_MEMORY,
            )

        # 6. ExecutionResult(COMPLETED, exit_code=0) + timeout => conflict
        with pytest.raises(
            NormalizationConflictError, match="status COMPLETED but is_timeout=True"
        ):
            normalize_execution_result(
                execution_result=ExecutionResult(status=TerminationStatus.COMPLETED, exit_code=0),
                is_timeout=True,
            )

        # 7. ExecutionResult(COMPLETED, exit_code=0) + cancelled => conflict
        with pytest.raises(
            NormalizationConflictError, match="status COMPLETED but is_cancelled=True"
        ):
            normalize_execution_result(
                execution_result=ExecutionResult(status=TerminationStatus.COMPLETED, exit_code=0),
                is_cancelled=True,
            )

        # 8. ExecutionResult(COMPLETED, exit_code=0) + resource failure => conflict
        with pytest.raises(
            NormalizationConflictError, match="status COMPLETED but resource_failure_class="
        ):
            normalize_execution_result(
                execution_result=ExecutionResult(status=TerminationStatus.COMPLETED, exit_code=0),
                resource_failure_class=ResourceFailureClass.OUT_OF_MEMORY,
            )

    def test_duplicate_compatible_facts_accepted(self) -> None:
        # 9. duplicate compatible timeout facts are accepted
        r_timeout = normalize_execution_result(
            execution_result=ExecutionResult(status=TerminationStatus.TIMED_OUT),
            is_timeout=True,
        )
        assert r_timeout.outcome == NormalizedExecutionOutcome.TIMEOUT
        assert r_timeout.is_timeout is True

        # 10. duplicate compatible cancellation facts are accepted
        r_cancelled = normalize_execution_result(
            execution_result=ExecutionResult(status=TerminationStatus.CANCELLED),
            is_cancelled=True,
        )
        assert r_cancelled.outcome == NormalizedExecutionOutcome.CANCELLED
        assert r_cancelled.is_cancelled is True

    def test_record_post_init_resource_failure_invariants(self) -> None:
        # 11. direct NormalizedExecutionRecord: SUCCESS + resource_failure_class => rejected
        with pytest.raises(
            ValueError, match="resource_failure_class must be None when outcome is SUCCESS"
        ):
            NormalizedExecutionRecord(
                outcome=NormalizedExecutionOutcome.SUCCESS,
                exit_code=0,
                resource_failure_class=ResourceFailureClass.OUT_OF_MEMORY,
            )

        # 12. direct NormalizedExecutionRecord: TIMEOUT + resource_failure_class => rejected
        with pytest.raises(
            ValueError, match="resource_failure_class must be None when outcome is TIMEOUT"
        ):
            NormalizedExecutionRecord(
                outcome=NormalizedExecutionOutcome.TIMEOUT,
                is_timeout=True,
                resource_failure_class=ResourceFailureClass.OUT_OF_MEMORY,
            )

        # 13. direct NormalizedExecutionRecord: RESOURCE_FAILURE without class => rejected
        with pytest.raises(
            ValueError,
            match="RESOURCE_FAILURE outcome requires resource_failure_class to be specified",
        ):
            NormalizedExecutionRecord(
                outcome=NormalizedExecutionOutcome.RESOURCE_FAILURE,
                is_resource_failure=True,
                resource_failure_class=None,
            )

        # 14. valid RESOURCE_FAILURE with explicit class remains accepted
        rec = NormalizedExecutionRecord(
            outcome=NormalizedExecutionOutcome.RESOURCE_FAILURE,
            is_resource_failure=True,
            resource_failure_class=ResourceFailureClass.OUT_OF_MEMORY,
        )
        assert rec.outcome == NormalizedExecutionOutcome.RESOURCE_FAILURE
        assert rec.is_resource_failure is True
        assert rec.resource_failure_class == ResourceFailureClass.OUT_OF_MEMORY

        # 15. direct NormalizedExecutionRecord: FAILED_TO_START + resource_failure_class => rejected
        with pytest.raises(
            ValueError, match="resource_failure_class must be None when outcome is FAILED_TO_START"
        ):
            NormalizedExecutionRecord(
                outcome=NormalizedExecutionOutcome.FAILED_TO_START,
                resource_failure_class=ResourceFailureClass.OUT_OF_MEMORY,
            )

        # 16. direct NormalizedExecutionRecord: FAILED_TO_START + is_timeout=True => rejected
        with pytest.raises(ValueError, match="is_timeout .* does not match outcome"):
            NormalizedExecutionRecord(
                outcome=NormalizedExecutionOutcome.FAILED_TO_START,
                is_timeout=True,
            )

        # 17. direct NormalizedExecutionRecord: FAILED_TO_START + is_cancelled=True => rejected
        with pytest.raises(ValueError, match="is_cancelled .* does not match outcome"):
            NormalizedExecutionRecord(
                outcome=NormalizedExecutionOutcome.FAILED_TO_START,
                is_cancelled=True,
            )

        # 18. ExecutionResult(FAILED_TO_START) + conflicting terminal facts fail closed
        with pytest.raises(NormalizationConflictError):
            normalize_execution_result(
                execution_result=ExecutionResult(status=TerminationStatus.FAILED_TO_START),
                is_timeout=True,
            )
        with pytest.raises(NormalizationConflictError):
            normalize_execution_result(
                execution_result=ExecutionResult(status=TerminationStatus.FAILED_TO_START),
                is_cancelled=True,
            )
        with pytest.raises(NormalizationConflictError):
            normalize_execution_result(
                execution_result=ExecutionResult(status=TerminationStatus.FAILED_TO_START),
                resource_failure_class=ResourceFailureClass.OUT_OF_MEMORY,
            )


class TestP0405FailedToStartNormalizationSemanticIntegrity:
    """Acceptance criteria: FAILED_TO_START semantic normalization integrity."""

    def test_failed_to_start_retains_status_and_never_misclassified_as_success_or_nonzero(
        self,
    ) -> None:
        # FAILED_TO_START with exit_code=None
        r_none = normalize_execution_result(
            execution_result=ExecutionResult(status=TerminationStatus.FAILED_TO_START)
        )
        assert r_none.outcome == NormalizedExecutionOutcome.FAILED_TO_START
        assert r_none.exit_code is None
        assert r_none.is_timeout is False
        assert r_none.is_cancelled is False
        assert r_none.is_resource_failure is False

        # FAILED_TO_START with exit_code=0 MUST NOT become SUCCESS
        r_zero = normalize_execution_result(
            execution_result=ExecutionResult(status=TerminationStatus.FAILED_TO_START, exit_code=0)
        )
        assert r_zero.outcome != NormalizedExecutionOutcome.SUCCESS
        assert r_zero.outcome == NormalizedExecutionOutcome.FAILED_TO_START
        assert r_zero.exit_code == 0

        # FAILED_TO_START with exit_code=1 MUST NOT become NONZERO_EXIT
        r_one = normalize_execution_result(
            execution_result=ExecutionResult(status=TerminationStatus.FAILED_TO_START, exit_code=1)
        )
        assert r_one.outcome != NormalizedExecutionOutcome.NONZERO_EXIT
        assert r_one.outcome == NormalizedExecutionOutcome.FAILED_TO_START
        assert r_one.exit_code == 1

        # FAILED_TO_START with exit_code=127
        r_127 = normalize_execution_result(
            execution_result=ExecutionResult(
                status=TerminationStatus.FAILED_TO_START, exit_code=127
            )
        )
        assert r_127.outcome == NormalizedExecutionOutcome.FAILED_TO_START
        assert r_127.exit_code == 127

    def test_failed_to_start_opaque_provider_status_never_overrides_domain_fact(self) -> None:
        r_success = normalize_execution_result(
            execution_result=ExecutionResult(status=TerminationStatus.FAILED_TO_START, exit_code=0),
            provider_status="SUCCESS",
        )
        assert r_success.outcome == NormalizedExecutionOutcome.FAILED_TO_START
        assert r_success.provider_status == "SUCCESS"

        r_completed = normalize_execution_result(
            execution_result=ExecutionResult(status=TerminationStatus.FAILED_TO_START, exit_code=0),
            provider_status="COMPLETED",
        )
        assert r_completed.outcome == NormalizedExecutionOutcome.FAILED_TO_START
        assert r_completed.provider_status == "COMPLETED"

    def test_failed_to_start_exit_code_reconciliation(self) -> None:
        # Matching explicit exit_code is accepted
        r_match = normalize_execution_result(
            execution_result=ExecutionResult(
                status=TerminationStatus.FAILED_TO_START, exit_code=127
            ),
            exit_code=127,
        )
        assert r_match.outcome == NormalizedExecutionOutcome.FAILED_TO_START
        assert r_match.exit_code == 127

        # Conflicting explicit exit_code raises NormalizationConflictError
        with pytest.raises(NormalizationConflictError, match="conflicts with explicit exit_code"):
            normalize_execution_result(
                execution_result=ExecutionResult(
                    status=TerminationStatus.FAILED_TO_START, exit_code=127
                ),
                exit_code=1,
            )

    def test_direct_failed_to_start_record_invariants(self) -> None:
        rec = NormalizedExecutionRecord(
            outcome=NormalizedExecutionOutcome.FAILED_TO_START,
            exit_code=0,
        )
        assert rec.outcome == NormalizedExecutionOutcome.FAILED_TO_START
        assert rec.exit_code == 0
        assert rec.is_timeout is False
        assert rec.is_cancelled is False
        assert rec.is_resource_failure is False
        assert rec.resource_failure_class is None


class TestP0405CompletionAuthority:
    """Acceptance criteria: Authoritative completion resolution without provider override."""

    def test_domain_completed_0_with_provider_status_failed_is_success(self) -> None:
        # 1. ExecutionResult(COMPLETED, 0) + provider_status="FAILED" => SUCCESS
        res = ExecutionResult(status=TerminationStatus.COMPLETED, exit_code=0)
        rec = normalize_execution_result(execution_result=res, provider_status="FAILED")
        assert rec.outcome == NormalizedExecutionOutcome.SUCCESS
        assert rec.exit_code == 0
        assert rec.provider_status == "FAILED"

    def test_domain_completed_2_with_provider_status_failed_is_nonzero_exit(self) -> None:
        # 2. ExecutionResult(COMPLETED, 2) + provider_status="FAILED" => NONZERO_EXIT
        res = ExecutionResult(status=TerminationStatus.COMPLETED, exit_code=2)
        rec = normalize_execution_result(execution_result=res, provider_status="FAILED")
        assert rec.outcome == NormalizedExecutionOutcome.NONZERO_EXIT
        assert rec.exit_code == 2
        assert rec.provider_status == "FAILED"

    def test_domain_completed_0_with_provider_error_text_is_success(self) -> None:
        # 3. ExecutionResult(COMPLETED, 0) + provider_error opaque text => SUCCESS
        res = ExecutionResult(status=TerminationStatus.COMPLETED, exit_code=0)
        rec = normalize_execution_result(
            execution_result=res,
            provider_error="opaque provider diagnostic",
        )
        assert rec.outcome == NormalizedExecutionOutcome.SUCCESS
        assert rec.exit_code == 0
        assert rec.provider_error_message == "opaque provider diagnostic"

    def test_explicit_exit_code_0_with_provider_status_failed_is_success(self) -> None:
        # 4. explicit exit_code=0 + provider_status="FAILED" => SUCCESS
        rec = normalize_execution_result(exit_code=0, provider_status="FAILED")
        assert rec.outcome == NormalizedExecutionOutcome.SUCCESS
        assert rec.exit_code == 0
        assert rec.provider_status == "FAILED"

    def test_explicit_exit_code_3_with_provider_error_text_is_nonzero_exit(self) -> None:
        # 5. explicit exit_code=3 + provider_error opaque text => NONZERO_EXIT
        rec = normalize_execution_result(
            exit_code=3,
            provider_error="opaque provider diagnostic",
        )
        assert rec.outcome == NormalizedExecutionOutcome.NONZERO_EXIT
        assert rec.exit_code == 3
        assert rec.provider_error_message == "opaque provider diagnostic"

    def test_provider_status_success_without_exit_code_fails_closed(self) -> None:
        # 6. provider_status="SUCCESS" without exit_code => UNKNOWN_PROVIDER_FAILURE
        rec = normalize_execution_result(provider_status="SUCCESS")
        assert rec.outcome == NormalizedExecutionOutcome.UNKNOWN_PROVIDER_FAILURE
        assert rec.exit_code is None
        assert rec.provider_status == "SUCCESS"

    def test_provider_status_completed_without_exit_code_fails_closed(self) -> None:
        # 7. provider_status="COMPLETED" without exit_code => UNKNOWN_PROVIDER_FAILURE
        rec = normalize_execution_result(provider_status="COMPLETED")
        assert rec.outcome == NormalizedExecutionOutcome.UNKNOWN_PROVIDER_FAILURE
        assert rec.exit_code is None
        assert rec.provider_status == "COMPLETED"

    def test_provider_error_alone_fails_closed(self) -> None:
        # 8. provider_error alone => UNKNOWN_PROVIDER_FAILURE
        rec = normalize_execution_result(provider_error="opaque provider diagnostic")
        assert rec.outcome == NormalizedExecutionOutcome.UNKNOWN_PROVIDER_FAILURE
        assert rec.exit_code is None
        assert rec.provider_error_message == "opaque provider diagnostic"


class TestP0405ExitCodeTypeIntegrity:
    """Acceptance criteria: Strict exit-code type integrity rejecting bool/str/float."""

    def test_explicit_exit_code_bool_false_rejected(self) -> None:
        # 9. explicit exit_code=False => TypeError
        with pytest.raises(TypeError, match="exit_code must be an integer"):
            normalize_execution_result(exit_code=cast(Any, False))

    def test_explicit_exit_code_bool_true_rejected(self) -> None:
        # 10. explicit exit_code=True => TypeError
        with pytest.raises(TypeError, match="exit_code must be an integer"):
            normalize_execution_result(exit_code=cast(Any, True))

    def test_explicit_exit_code_str_rejected(self) -> None:
        # 11. explicit exit_code="0" => TypeError
        with pytest.raises(TypeError, match="exit_code must be an integer"):
            normalize_execution_result(exit_code=cast(Any, "0"))

    def test_explicit_exit_code_float_rejected(self) -> None:
        # 12. explicit exit_code=1.0 => TypeError
        with pytest.raises(TypeError, match="exit_code must be an integer"):
            normalize_execution_result(exit_code=cast(Any, 1.0))

    def test_execution_result_failed_to_start_bool_exit_code_rejected(self) -> None:
        # 13. ExecutionResult(FAILED_TO_START, exit_code=False) entering normalizer => TypeError
        res = ExecutionResult(status=TerminationStatus.FAILED_TO_START, exit_code=cast(Any, False))
        with pytest.raises(TypeError, match="exit_code must be an integer"):
            normalize_execution_result(execution_result=res)

    def test_execution_result_failed_to_start_str_exit_code_rejected(self) -> None:
        # 14. ExecutionResult(FAILED_TO_START, exit_code="127") entering normalizer => TypeError
        res = ExecutionResult(status=TerminationStatus.FAILED_TO_START, exit_code=cast(Any, "127"))
        with pytest.raises(TypeError, match="exit_code must be an integer"):
            normalize_execution_result(execution_result=res)

    def test_direct_record_failed_to_start_bool_exit_code_rejected(self) -> None:
        # 15. direct record(outcome=FAILED_TO_START, exit_code=False) => TypeError
        with pytest.raises(TypeError, match="exit_code must be an integer"):
            NormalizedExecutionRecord(
                outcome=NormalizedExecutionOutcome.FAILED_TO_START,
                exit_code=cast(Any, False),
            )

    def test_direct_record_unknown_provider_failure_str_exit_code_rejected(self) -> None:
        # 16. direct record(outcome=UNKNOWN_PROVIDER_FAILURE, exit_code="1") => TypeError
        with pytest.raises(TypeError, match="exit_code must be an integer"):
            NormalizedExecutionRecord(
                outcome=NormalizedExecutionOutcome.UNKNOWN_PROVIDER_FAILURE,
                exit_code=cast(Any, "1"),
            )

    def test_direct_record_success_bool_exit_code_rejected(self) -> None:
        with pytest.raises(TypeError, match="exit_code must be an integer"):
            NormalizedExecutionRecord(
                outcome=NormalizedExecutionOutcome.SUCCESS,
                exit_code=cast(Any, False),
            )

    def test_direct_record_nonzero_bool_exit_code_rejected(self) -> None:
        with pytest.raises(TypeError, match="exit_code must be an integer"):
            NormalizedExecutionRecord(
                outcome=NormalizedExecutionOutcome.NONZERO_EXIT,
                exit_code=cast(Any, True),
            )

    def test_reconciliation_rejects_bool_exit_code_against_domain_result(self) -> None:
        res = ExecutionResult(status=TerminationStatus.COMPLETED, exit_code=0)
        with pytest.raises(TypeError, match="exit_code must be an integer"):
            normalize_execution_result(execution_result=res, exit_code=cast(Any, False))

    def test_valid_integer_0_remains_success(self) -> None:
        # 17. valid integer 0 remains SUCCESS
        rec = normalize_execution_result(exit_code=0)
        assert rec.outcome == NormalizedExecutionOutcome.SUCCESS
        assert rec.exit_code == 0
        assert type(rec.exit_code) is int

    def test_valid_integer_nonzero_remains_nonzero_exit(self) -> None:
        # 18. valid integer nonzero remains NONZERO_EXIT
        rec = normalize_execution_result(exit_code=1)
        assert rec.outcome == NormalizedExecutionOutcome.NONZERO_EXIT
        assert rec.exit_code == 1
        assert type(rec.exit_code) is int

    def test_valid_failed_to_start_with_integer_exit_code_remains_failed_to_start(self) -> None:
        # 19. valid FAILED_TO_START + integer exit code remains FAILED_TO_START
        res = ExecutionResult(status=TerminationStatus.FAILED_TO_START, exit_code=127)
        rec = normalize_execution_result(execution_result=res)
        assert rec.outcome == NormalizedExecutionOutcome.FAILED_TO_START
        assert rec.exit_code == 127
        assert type(rec.exit_code) is int
