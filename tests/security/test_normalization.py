"""Unit tests for deterministic execution outcome normalization (P-04.05)."""

from __future__ import annotations

import pytest

from basebreak.domain.execution import ExecutionResult, TerminationStatus
from basebreak.security.normalization import (
    NormalizationConflictError,
    NormalizedExecutionOutcome,
    NormalizedExecutionRecord,
    ResourceFailureClass,
    normalize_execution_result,
)
from basebreak.security.secret_policy import SecretPersistenceError


class TestSuccessfulResult:
    """Verify normalization of successful executions."""

    def test_direct_exit_code_zero_success(self) -> None:
        record = normalize_execution_result(exit_code=0, stdout="BASEBREAK_SANDBOX_OK\n")
        assert record.outcome == NormalizedExecutionOutcome.SUCCESS
        assert record.exit_code == 0
        assert record.stdout_preview == "BASEBREAK_SANDBOX_OK\n"
        assert record.is_timeout is False
        assert record.is_cancelled is False
        assert record.is_resource_failure is False

    def test_domain_execution_result_success(self) -> None:
        res = ExecutionResult(
            status=TerminationStatus.COMPLETED,
            exit_code=0,
            duration_seconds=1.2,
        )
        record = normalize_execution_result(execution_result=res, stdout="all passed")
        assert record.outcome == NormalizedExecutionOutcome.SUCCESS
        assert record.exit_code == 0
        assert record.stdout_preview == "all passed"

    def test_raw_payload_digested_without_becoming_classification_authority(self) -> None:
        # Raw payload is digested for evidence, but exit_code must be passed authoritatively
        payload = {
            "id": "01a0d8ca-28fd-777e-9d32-0907c4cb6f28",
            "status": "SUCCESS",
            "metadata": {
                "result": {
                    "exit_code": 0,
                    "stdout": "BASEBREAK_SANDBOX_OK\n",
                    "stderr": "",
                    "duration": 0.338,
                }
            },
        }
        record = normalize_execution_result(
            exit_code=0,
            stdout="BASEBREAK_SANDBOX_OK\n",
            duration_seconds=0.338,
            raw_payload=payload,
        )
        assert record.outcome == NormalizedExecutionOutcome.SUCCESS
        assert record.exit_code == 0
        assert record.raw_payload_digest is not None


class TestNonzeroExitResult:
    """Verify normalization of process completion with non-zero exit codes."""

    def test_direct_nonzero_exit(self) -> None:
        record = normalize_execution_result(
            exit_code=1, stdout="FAILED tests/test_task.py\n", stderr="AssertionError"
        )
        assert record.outcome == NormalizedExecutionOutcome.NONZERO_EXIT
        assert record.exit_code == 1
        assert record.is_timeout is False
        assert record.is_cancelled is False
        assert record.is_resource_failure is False

    def test_domain_execution_result_nonzero(self) -> None:
        res = ExecutionResult(
            status=TerminationStatus.COMPLETED,
            exit_code=2,
            duration_seconds=0.5,
        )
        record = normalize_execution_result(execution_result=res)
        assert record.outcome == NormalizedExecutionOutcome.NONZERO_EXIT
        assert record.exit_code == 2


class TestTimeoutNormalization:
    """Verify deterministic normalization of timeouts and non-self-promotion."""

    def test_explicit_timeout_flag(self) -> None:
        record = normalize_execution_result(is_timeout=True)
        assert record.outcome == NormalizedExecutionOutcome.TIMEOUT
        assert record.is_timeout is True
        assert record.is_cancelled is False

    def test_domain_execution_result_timed_out(self) -> None:
        res = ExecutionResult(status=TerminationStatus.TIMED_OUT)
        record = normalize_execution_result(execution_result=res)
        assert record.outcome == NormalizedExecutionOutcome.TIMEOUT
        assert record.is_timeout is True

    def test_http_408_alone_fails_closed_as_unknown_provider_failure(self) -> None:
        # HTTP 408 alone MUST NOT self-promote to TIMEOUT without verified adapter
        record = normalize_execution_result(
            provider_status="FAILURE",
            provider_error={"status": 408, "error": "Request timed out"},
        )
        assert record.outcome == NormalizedExecutionOutcome.UNKNOWN_PROVIDER_FAILURE
        assert record.is_timeout is False

    def test_provider_status_timed_out_alone_fails_closed(self) -> None:
        # Unproven provider status string alone MUST NOT self-promote to TIMEOUT
        record = normalize_execution_result(provider_status="TIMED_OUT")
        assert record.outcome == NormalizedExecutionOutcome.UNKNOWN_PROVIDER_FAILURE
        assert record.is_timeout is False

    def test_error_message_deadline_exceeded_alone_fails_closed(self) -> None:
        # Generic deadline/timeout text MUST NOT self-promote to TIMEOUT
        record = normalize_execution_result(
            provider_status="FAILURE",
            provider_error="Instance execution timeout exceeded 180s",
        )
        assert record.outcome == NormalizedExecutionOutcome.UNKNOWN_PROVIDER_FAILURE
        assert record.is_timeout is False


class TestCancellationNormalization:
    """Verify deterministic normalization of cancellations and non-self-promotion."""

    def test_explicit_cancellation_flag(self) -> None:
        record = normalize_execution_result(is_cancelled=True)
        assert record.outcome == NormalizedExecutionOutcome.CANCELLED
        assert record.is_cancelled is True
        assert record.is_timeout is False

    def test_domain_execution_result_cancelled(self) -> None:
        res = ExecutionResult(status=TerminationStatus.CANCELLED)
        record = normalize_execution_result(execution_result=res)
        assert record.outcome == NormalizedExecutionOutcome.CANCELLED
        assert record.is_cancelled is True

    def test_http_499_alone_fails_closed_as_unknown_provider_failure(self) -> None:
        # HTTP 499 alone MUST NOT self-promote to CANCELLED without verified adapter
        record = normalize_execution_result(
            provider_status="FAILURE",
            provider_error={"status": 499, "error": "Client closed request: operation cancelled"},
        )
        assert record.outcome == NormalizedExecutionOutcome.UNKNOWN_PROVIDER_FAILURE
        assert record.is_cancelled is False

    def test_provider_status_cancelled_alone_fails_closed(self) -> None:
        # Unproven provider status string alone MUST NOT self-promote to CANCELLED
        record = normalize_execution_result(provider_status="CANCELLED")
        assert record.outcome == NormalizedExecutionOutcome.UNKNOWN_PROVIDER_FAILURE
        assert record.is_cancelled is False

    def test_cancellation_error_message_alone_fails_closed(self) -> None:
        record = normalize_execution_result(
            provider_status="FAILURE",
            provider_error="Operation cancelled by user",
        )
        assert record.outcome == NormalizedExecutionOutcome.UNKNOWN_PROVIDER_FAILURE
        assert record.is_cancelled is False


class TestResourceFailureNormalization:
    """Verify deterministic identification of verified resource exhaustion."""

    def test_explicit_concurrency_exhausted_class(self) -> None:
        record = normalize_execution_result(
            resource_failure_class=ResourceFailureClass.CONCURRENCY_EXHAUSTED
        )
        assert record.outcome == NormalizedExecutionOutcome.RESOURCE_FAILURE
        assert record.is_resource_failure is True
        assert record.resource_failure_class == ResourceFailureClass.CONCURRENCY_EXHAUSTED

    def test_explicit_layer_quota_exceeded_class(self) -> None:
        record = normalize_execution_result(
            resource_failure_class=ResourceFailureClass.LAYER_QUOTA_EXCEEDED
        )
        assert record.outcome == NormalizedExecutionOutcome.RESOURCE_FAILURE
        assert record.is_resource_failure is True
        assert record.resource_failure_class == ResourceFailureClass.LAYER_QUOTA_EXCEEDED

    def test_explicit_out_of_memory_class(self) -> None:
        record = normalize_execution_result(
            resource_failure_class=ResourceFailureClass.OUT_OF_MEMORY
        )
        assert record.outcome == NormalizedExecutionOutcome.RESOURCE_FAILURE
        assert record.is_resource_failure is True
        assert record.resource_failure_class == ResourceFailureClass.OUT_OF_MEMORY

    def test_http_429_alone_fails_closed_as_unknown_provider_failure(self) -> None:
        # HTTP 429 alone MUST NOT self-promote to CONCURRENCY_EXHAUSTED
        record = normalize_execution_result(
            provider_status="FAILURE",
            provider_error={"status": 429, "error": "Too many requests"},
        )
        assert record.outcome == NormalizedExecutionOutcome.UNKNOWN_PROVIDER_FAILURE
        assert record.is_resource_failure is False
        assert record.resource_failure_class is None

    def test_oom_prose_alone_fails_closed_as_unknown_provider_failure(self) -> None:
        # Free-form OOM text alone MUST NOT self-promote to OUT_OF_MEMORY
        record = normalize_execution_result(
            provider_status="FAILURE",
            provider_error="Process killed by cgroup memory OOM killer",
        )
        assert record.outcome == NormalizedExecutionOutcome.UNKNOWN_PROVIDER_FAILURE
        assert record.is_resource_failure is False
        assert record.resource_failure_class is None

    def test_layer_bytes_prose_alone_fails_closed_as_unknown_provider_failure(self) -> None:
        record = normalize_execution_result(
            provider_status="FAILURE",
            provider_error="instance_max_layer_bytes exceeded during command",
        )
        assert record.outcome == NormalizedExecutionOutcome.UNKNOWN_PROVIDER_FAILURE
        assert record.is_resource_failure is False


class TestFailedToStartNormalization:
    """Verify deterministic normalization of FAILED_TO_START outcomes."""

    def test_failed_to_start_with_exit_code_none(self) -> None:
        res = ExecutionResult(status=TerminationStatus.FAILED_TO_START)
        record = normalize_execution_result(execution_result=res)
        assert record.outcome == NormalizedExecutionOutcome.FAILED_TO_START
        assert record.exit_code is None
        assert record.is_timeout is False
        assert record.is_cancelled is False
        assert record.is_resource_failure is False
        assert record.resource_failure_class is None

    def test_failed_to_start_with_exit_code_zero_not_success(self) -> None:
        res = ExecutionResult(status=TerminationStatus.FAILED_TO_START, exit_code=0)
        record = normalize_execution_result(execution_result=res)
        assert record.outcome != NormalizedExecutionOutcome.SUCCESS
        assert record.outcome == NormalizedExecutionOutcome.FAILED_TO_START
        assert record.exit_code == 0
        assert record.is_timeout is False
        assert record.is_cancelled is False
        assert record.is_resource_failure is False

    def test_failed_to_start_with_exit_code_one_not_nonzero_exit(self) -> None:
        res = ExecutionResult(status=TerminationStatus.FAILED_TO_START, exit_code=1)
        record = normalize_execution_result(execution_result=res)
        assert record.outcome != NormalizedExecutionOutcome.NONZERO_EXIT
        assert record.outcome == NormalizedExecutionOutcome.FAILED_TO_START
        assert record.exit_code == 1
        assert record.is_timeout is False
        assert record.is_cancelled is False
        assert record.is_resource_failure is False

    def test_failed_to_start_with_exit_code_127(self) -> None:
        res = ExecutionResult(status=TerminationStatus.FAILED_TO_START, exit_code=127)
        record = normalize_execution_result(execution_result=res)
        assert record.outcome == NormalizedExecutionOutcome.FAILED_TO_START
        assert record.exit_code == 127

    def test_failed_to_start_with_opaque_provider_status_success(self) -> None:
        res = ExecutionResult(status=TerminationStatus.FAILED_TO_START)
        record = normalize_execution_result(execution_result=res, provider_status="SUCCESS")
        assert record.outcome == NormalizedExecutionOutcome.FAILED_TO_START
        assert record.provider_status == "SUCCESS"

    def test_failed_to_start_with_opaque_provider_status_completed(self) -> None:
        res = ExecutionResult(status=TerminationStatus.FAILED_TO_START, exit_code=0)
        record = normalize_execution_result(execution_result=res, provider_status="COMPLETED")
        assert record.outcome == NormalizedExecutionOutcome.FAILED_TO_START
        assert record.provider_status == "COMPLETED"

    def test_explicit_failed_to_start_flag(self) -> None:
        record = normalize_execution_result(is_failed_to_start=True)
        assert record.outcome == NormalizedExecutionOutcome.FAILED_TO_START
        assert record.is_timeout is False
        assert record.is_cancelled is False
        assert record.is_resource_failure is False


class TestUnknownProviderFailure:
    """Verify that ambiguous or unverified failures fail closed as UNKNOWN_PROVIDER_FAILURE."""

    def test_http_500_internal_error_not_guessed(self) -> None:
        err_dict = {"status": 500, "error": "Internal server error"}
        payload = {
            "id": "op-err-500",
            "status": "FAILURE",
            "error": err_dict,
        }
        record = normalize_execution_result(
            raw_payload=payload,
            provider_error=err_dict,
        )
        assert record.outcome == NormalizedExecutionOutcome.UNKNOWN_PROVIDER_FAILURE
        assert record.is_timeout is False
        assert record.is_resource_failure is False
        assert record.resource_failure_class is None

    def test_http_403_insufficient_permissions(self) -> None:
        record = normalize_execution_result(
            provider_status="FAILURE",
            provider_error={
                "status": 403,
                "error": "Insufficient permissions: spawn or spawn_disposable",
            },
        )
        assert record.outcome == NormalizedExecutionOutcome.UNKNOWN_PROVIDER_FAILURE
        assert record.is_timeout is False
        assert record.is_resource_failure is False

    def test_generic_ambiguous_failure(self) -> None:
        record = normalize_execution_result(
            provider_status="FAILURE",
            provider_error="Instance terminated abnormally",
        )
        assert record.outcome == NormalizedExecutionOutcome.UNKNOWN_PROVIDER_FAILURE
        assert record.is_timeout is False
        assert record.is_resource_failure is False

    def test_empty_raw_payload_alone(self) -> None:
        record = normalize_execution_result(raw_payload={})
        assert record.outcome == NormalizedExecutionOutcome.UNKNOWN_PROVIDER_FAILURE

    def test_raw_payload_without_authoritative_facts_fails_closed(self) -> None:
        payload = {"status": "SUCCESS", "metadata": {"result": {}}}
        record = normalize_execution_result(raw_payload=payload)
        assert record.outcome == NormalizedExecutionOutcome.UNKNOWN_PROVIDER_FAILURE


class TestSecretSanitizationAndPersistence:
    """Verify stdout/stderr sanitization and zero secret persistence."""

    def test_raw_secret_in_stdout_redacted(self) -> None:
        raw_out = "Login ok: Bearer nbs_sk_live_1234567890abcdef12345678"
        record = normalize_execution_result(
            exit_code=0,
            stdout=raw_out,
            provider_status="SUCCESS",
        )
        assert "[REDACTED]" in record.stdout_preview
        assert "nbs_sk_live" not in record.stdout_preview
        # Full digest accurately hashes raw output
        assert record.stdout_digest != ""

    def test_raw_secret_in_provider_error_redacted(self) -> None:
        err = "Request failed for https://user:secretpass123@api.nebius.com"
        record = normalize_execution_result(
            provider_status="FAILURE",
            provider_error=err,
        )
        assert record.provider_error_message is not None
        assert "secretpass123" not in record.provider_error_message

    def test_direct_construction_with_raw_secret_fails_closed(self) -> None:
        with pytest.raises(SecretPersistenceError):
            NormalizedExecutionRecord(
                outcome=NormalizedExecutionOutcome.SUCCESS,
                exit_code=0,
                stdout_preview="Bearer nbs_sk_live_test1234567890abcdef",
            )


class TestStableSerialization:
    """Verify deterministic serialization and content addressing."""

    def test_to_dict_and_canonical_digest(self) -> None:
        record = normalize_execution_result(
            exit_code=0,
            stdout="OK\n",
            duration_seconds=0.5,
            provider_status="SUCCESS",
        )
        d = record.to_dict()
        assert d["outcome"] == "SUCCESS"
        assert d["exit_code"] == 0
        assert d["duration_seconds"] == 0.5
        assert isinstance(d["stdout_digest"], str)

        digest1 = record.canonical_digest()
        digest2 = record.canonical_digest()
        assert digest1 == digest2
        assert len(digest1) == 64


class TestAuthoritativeFactConflictValidation:
    """Verify that contradictory authoritative execution facts fail closed (P-04.05 Repair)."""

    def test_timeout_and_cancelled_conflict(self) -> None:
        with pytest.raises(
            NormalizationConflictError, match="both is_timeout=True and is_cancelled=True"
        ):
            normalize_execution_result(is_timeout=True, is_cancelled=True)

    def test_timeout_and_resource_failure_conflict(self) -> None:
        with pytest.raises(
            NormalizationConflictError, match="both is_timeout=True and resource_failure_class="
        ):
            normalize_execution_result(
                is_timeout=True,
                resource_failure_class=ResourceFailureClass.OUT_OF_MEMORY,
            )

    def test_cancelled_and_resource_failure_conflict(self) -> None:
        with pytest.raises(
            NormalizationConflictError, match="both is_cancelled=True and resource_failure_class="
        ):
            normalize_execution_result(
                is_cancelled=True,
                resource_failure_class=ResourceFailureClass.CONCURRENCY_EXHAUSTED,
            )

    def test_execution_result_timed_out_and_cancelled_conflict(self) -> None:
        with pytest.raises(
            NormalizationConflictError, match="status TIMED_OUT but is_cancelled=True"
        ):
            normalize_execution_result(
                execution_result=ExecutionResult(status=TerminationStatus.TIMED_OUT),
                is_cancelled=True,
            )

    def test_execution_result_cancelled_and_timeout_conflict(self) -> None:
        with pytest.raises(
            NormalizationConflictError, match="status CANCELLED but is_timeout=True"
        ):
            normalize_execution_result(
                execution_result=ExecutionResult(status=TerminationStatus.CANCELLED),
                is_timeout=True,
            )

    def test_execution_result_timed_out_and_resource_failure_conflict(self) -> None:
        with pytest.raises(
            NormalizationConflictError, match="status TIMED_OUT but resource_failure_class="
        ):
            normalize_execution_result(
                execution_result=ExecutionResult(status=TerminationStatus.TIMED_OUT),
                resource_failure_class=ResourceFailureClass.OUT_OF_MEMORY,
            )

    def test_execution_result_cancelled_and_resource_failure_conflict(self) -> None:
        with pytest.raises(
            NormalizationConflictError, match="status CANCELLED but resource_failure_class="
        ):
            normalize_execution_result(
                execution_result=ExecutionResult(status=TerminationStatus.CANCELLED),
                resource_failure_class=ResourceFailureClass.LAYER_QUOTA_EXCEEDED,
            )

    def test_execution_result_completed_exit_0_and_timeout_conflict(self) -> None:
        with pytest.raises(
            NormalizationConflictError, match="status COMPLETED but is_timeout=True"
        ):
            normalize_execution_result(
                execution_result=ExecutionResult(status=TerminationStatus.COMPLETED, exit_code=0),
                is_timeout=True,
            )

    def test_execution_result_completed_exit_0_and_cancelled_conflict(self) -> None:
        with pytest.raises(
            NormalizationConflictError, match="status COMPLETED but is_cancelled=True"
        ):
            normalize_execution_result(
                execution_result=ExecutionResult(status=TerminationStatus.COMPLETED, exit_code=0),
                is_cancelled=True,
            )

    def test_execution_result_completed_exit_0_and_resource_failure_conflict(self) -> None:
        with pytest.raises(
            NormalizationConflictError, match="status COMPLETED but resource_failure_class="
        ):
            normalize_execution_result(
                execution_result=ExecutionResult(status=TerminationStatus.COMPLETED, exit_code=0),
                resource_failure_class=ResourceFailureClass.OUT_OF_MEMORY,
            )

    def test_execution_result_completed_nonzero_exit_and_facts_conflict(self) -> None:
        with pytest.raises(
            NormalizationConflictError, match="status COMPLETED but is_timeout=True"
        ):
            normalize_execution_result(
                execution_result=ExecutionResult(status=TerminationStatus.COMPLETED, exit_code=1),
                is_timeout=True,
            )
        with pytest.raises(
            NormalizationConflictError, match="status COMPLETED but is_cancelled=True"
        ):
            normalize_execution_result(
                execution_result=ExecutionResult(status=TerminationStatus.COMPLETED, exit_code=1),
                is_cancelled=True,
            )
        with pytest.raises(
            NormalizationConflictError, match="status COMPLETED but resource_failure_class="
        ):
            normalize_execution_result(
                execution_result=ExecutionResult(status=TerminationStatus.COMPLETED, exit_code=1),
                resource_failure_class=ResourceFailureClass.OUT_OF_MEMORY,
            )

    def test_execution_result_exit_code_conflict(self) -> None:
        with pytest.raises(NormalizationConflictError, match="conflicts with explicit exit_code"):
            normalize_execution_result(
                execution_result=ExecutionResult(status=TerminationStatus.COMPLETED, exit_code=0),
                exit_code=1,
            )

    def test_duplicate_compatible_timeout_accepted(self) -> None:
        record = normalize_execution_result(
            execution_result=ExecutionResult(status=TerminationStatus.TIMED_OUT),
            is_timeout=True,
        )
        assert record.outcome == NormalizedExecutionOutcome.TIMEOUT
        assert record.is_timeout is True
        assert record.is_cancelled is False
        assert record.is_resource_failure is False

    def test_duplicate_compatible_cancellation_accepted(self) -> None:
        record = normalize_execution_result(
            execution_result=ExecutionResult(status=TerminationStatus.CANCELLED),
            is_cancelled=True,
        )
        assert record.outcome == NormalizedExecutionOutcome.CANCELLED
        assert record.is_cancelled is True
        assert record.is_timeout is False
        assert record.is_resource_failure is False

    def test_failed_to_start_and_timeout_conflict(self) -> None:
        with pytest.raises(
            NormalizationConflictError, match="both is_timeout=True and is_failed_to_start=True"
        ):
            normalize_execution_result(is_timeout=True, is_failed_to_start=True)

    def test_failed_to_start_and_cancelled_conflict(self) -> None:
        with pytest.raises(
            NormalizationConflictError, match="both is_cancelled=True and is_failed_to_start=True"
        ):
            normalize_execution_result(is_cancelled=True, is_failed_to_start=True)

    def test_failed_to_start_and_resource_failure_conflict(self) -> None:
        with pytest.raises(
            NormalizationConflictError,
            match="both is_failed_to_start=True and resource_failure_class=",
        ):
            normalize_execution_result(
                is_failed_to_start=True,
                resource_failure_class=ResourceFailureClass.OUT_OF_MEMORY,
            )

    def test_execution_result_failed_to_start_and_timeout_conflict(self) -> None:
        with pytest.raises(
            NormalizationConflictError, match="status FAILED_TO_START but is_timeout=True"
        ):
            normalize_execution_result(
                execution_result=ExecutionResult(status=TerminationStatus.FAILED_TO_START),
                is_timeout=True,
            )

    def test_execution_result_failed_to_start_and_cancelled_conflict(self) -> None:
        with pytest.raises(
            NormalizationConflictError, match="status FAILED_TO_START but is_cancelled=True"
        ):
            normalize_execution_result(
                execution_result=ExecutionResult(status=TerminationStatus.FAILED_TO_START),
                is_cancelled=True,
            )

    def test_execution_result_failed_to_start_and_resource_failure_conflict(self) -> None:
        with pytest.raises(
            NormalizationConflictError, match="status FAILED_TO_START but resource_failure_class="
        ):
            normalize_execution_result(
                execution_result=ExecutionResult(status=TerminationStatus.FAILED_TO_START),
                resource_failure_class=ResourceFailureClass.OUT_OF_MEMORY,
            )

    def test_execution_result_completed_and_failed_to_start_conflict(self) -> None:
        with pytest.raises(
            NormalizationConflictError, match="status COMPLETED but is_failed_to_start=True"
        ):
            normalize_execution_result(
                execution_result=ExecutionResult(status=TerminationStatus.COMPLETED, exit_code=0),
                is_failed_to_start=True,
            )

    def test_execution_result_timed_out_and_failed_to_start_conflict(self) -> None:
        with pytest.raises(
            NormalizationConflictError, match="status TIMED_OUT but is_failed_to_start=True"
        ):
            normalize_execution_result(
                execution_result=ExecutionResult(status=TerminationStatus.TIMED_OUT),
                is_failed_to_start=True,
            )

    def test_execution_result_cancelled_and_failed_to_start_conflict(self) -> None:
        with pytest.raises(
            NormalizationConflictError, match="status CANCELLED but is_failed_to_start=True"
        ):
            normalize_execution_result(
                execution_result=ExecutionResult(status=TerminationStatus.CANCELLED),
                is_failed_to_start=True,
            )

    def test_failed_to_start_matching_explicit_exit_code_accepted(self) -> None:
        record = normalize_execution_result(
            execution_result=ExecutionResult(
                status=TerminationStatus.FAILED_TO_START, exit_code=127
            ),
            exit_code=127,
        )
        assert record.outcome == NormalizedExecutionOutcome.FAILED_TO_START
        assert record.exit_code == 127

    def test_failed_to_start_conflicting_explicit_exit_code_rejected(self) -> None:
        with pytest.raises(NormalizationConflictError, match="conflicts with explicit exit_code"):
            normalize_execution_result(
                execution_result=ExecutionResult(
                    status=TerminationStatus.FAILED_TO_START, exit_code=127
                ),
                exit_code=1,
            )

    def test_duplicate_compatible_failed_to_start_accepted(self) -> None:
        record = normalize_execution_result(
            execution_result=ExecutionResult(status=TerminationStatus.FAILED_TO_START),
            is_failed_to_start=True,
        )
        assert record.outcome == NormalizedExecutionOutcome.FAILED_TO_START


class TestNormalizedExecutionRecordInvariants:
    """Verify strengthened post-init invariants on NormalizedExecutionRecord."""

    def test_record_success_with_resource_failure_class_rejected(self) -> None:
        with pytest.raises(
            ValueError, match="resource_failure_class must be None when outcome is SUCCESS"
        ):
            NormalizedExecutionRecord(
                outcome=NormalizedExecutionOutcome.SUCCESS,
                exit_code=0,
                resource_failure_class=ResourceFailureClass.OUT_OF_MEMORY,
            )

    def test_record_timeout_with_resource_failure_class_rejected(self) -> None:
        with pytest.raises(
            ValueError, match="resource_failure_class must be None when outcome is TIMEOUT"
        ):
            NormalizedExecutionRecord(
                outcome=NormalizedExecutionOutcome.TIMEOUT,
                is_timeout=True,
                resource_failure_class=ResourceFailureClass.OUT_OF_MEMORY,
            )

    def test_record_cancelled_with_resource_failure_class_rejected(self) -> None:
        with pytest.raises(
            ValueError, match="resource_failure_class must be None when outcome is CANCELLED"
        ):
            NormalizedExecutionRecord(
                outcome=NormalizedExecutionOutcome.CANCELLED,
                is_cancelled=True,
                resource_failure_class=ResourceFailureClass.CONCURRENCY_EXHAUSTED,
            )

    def test_record_nonzero_exit_with_resource_failure_class_rejected(self) -> None:
        with pytest.raises(
            ValueError, match="resource_failure_class must be None when outcome is NONZERO_EXIT"
        ):
            NormalizedExecutionRecord(
                outcome=NormalizedExecutionOutcome.NONZERO_EXIT,
                exit_code=1,
                resource_failure_class=ResourceFailureClass.OUT_OF_MEMORY,
            )

    def test_record_unknown_provider_failure_with_resource_failure_class_rejected(self) -> None:
        with pytest.raises(
            ValueError,
            match="resource_failure_class must be None when outcome is UNKNOWN_PROVIDER_FAILURE",
        ):
            NormalizedExecutionRecord(
                outcome=NormalizedExecutionOutcome.UNKNOWN_PROVIDER_FAILURE,
                resource_failure_class=ResourceFailureClass.OUT_OF_MEMORY,
            )

    def test_record_resource_failure_without_class_rejected(self) -> None:
        with pytest.raises(
            ValueError,
            match="RESOURCE_FAILURE outcome requires resource_failure_class to be specified",
        ):
            NormalizedExecutionRecord(
                outcome=NormalizedExecutionOutcome.RESOURCE_FAILURE,
                is_resource_failure=True,
                resource_failure_class=None,
            )

    def test_record_valid_resource_failure_accepted(self) -> None:
        record = NormalizedExecutionRecord(
            outcome=NormalizedExecutionOutcome.RESOURCE_FAILURE,
            is_resource_failure=True,
            resource_failure_class=ResourceFailureClass.OUT_OF_MEMORY,
        )
        assert record.outcome == NormalizedExecutionOutcome.RESOURCE_FAILURE
        assert record.is_resource_failure is True
        assert record.resource_failure_class == ResourceFailureClass.OUT_OF_MEMORY

    def test_record_failed_to_start_with_resource_failure_class_rejected(self) -> None:
        with pytest.raises(
            ValueError, match="resource_failure_class must be None when outcome is FAILED_TO_START"
        ):
            NormalizedExecutionRecord(
                outcome=NormalizedExecutionOutcome.FAILED_TO_START,
                resource_failure_class=ResourceFailureClass.OUT_OF_MEMORY,
            )

    def test_record_failed_to_start_with_timeout_flag_rejected(self) -> None:
        with pytest.raises(ValueError, match="is_timeout .* does not match outcome"):
            NormalizedExecutionRecord(
                outcome=NormalizedExecutionOutcome.FAILED_TO_START,
                is_timeout=True,
            )

    def test_record_failed_to_start_with_cancelled_flag_rejected(self) -> None:
        with pytest.raises(ValueError, match="is_cancelled .* does not match outcome"):
            NormalizedExecutionRecord(
                outcome=NormalizedExecutionOutcome.FAILED_TO_START,
                is_cancelled=True,
            )

    def test_record_failed_to_start_with_resource_failure_flag_rejected(self) -> None:
        with pytest.raises(ValueError, match="is_resource_failure .* does not match outcome"):
            NormalizedExecutionRecord(
                outcome=NormalizedExecutionOutcome.FAILED_TO_START,
                is_resource_failure=True,
            )

    def test_record_failed_to_start_valid_accepted(self) -> None:
        r1 = NormalizedExecutionRecord(outcome=NormalizedExecutionOutcome.FAILED_TO_START)
        assert r1.outcome == NormalizedExecutionOutcome.FAILED_TO_START
        assert r1.exit_code is None
        assert r1.is_timeout is False
        assert r1.is_cancelled is False
        assert r1.is_resource_failure is False
        assert r1.resource_failure_class is None

        r2 = NormalizedExecutionRecord(
            outcome=NormalizedExecutionOutcome.FAILED_TO_START,
            exit_code=0,
        )
        assert r2.outcome == NormalizedExecutionOutcome.FAILED_TO_START
        assert r2.exit_code == 0

        r3 = NormalizedExecutionRecord(
            outcome=NormalizedExecutionOutcome.FAILED_TO_START,
            exit_code=127,
        )
        assert r3.outcome == NormalizedExecutionOutcome.FAILED_TO_START
        assert r3.exit_code == 127
