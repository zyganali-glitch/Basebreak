"""Unit tests for deterministic execution outcome normalization (P-04.05)."""

from __future__ import annotations

import pytest

from basebreak.domain.execution import ExecutionResult, TerminationStatus
from basebreak.security.normalization import (
    NormalizedExecutionOutcome,
    NormalizedExecutionRecord,
    ResourceFailureClass,
    normalize_execution_result,
)
from basebreak.security.secret_policy import SecretPersistenceError


class TestSuccessfulResult:
    """Verify normalization of successful executions."""

    def test_provider_payload_success(self) -> None:
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
        record = normalize_execution_result(raw_payload=payload)
        assert record.outcome == NormalizedExecutionOutcome.SUCCESS
        assert record.exit_code == 0
        assert record.duration_seconds == 0.338
        assert record.stdout_preview == "BASEBREAK_SANDBOX_OK\n"
        assert record.is_timeout is False
        assert record.is_cancelled is False
        assert record.is_resource_failure is False
        assert record.raw_payload_digest is not None

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


class TestNonzeroExitResult:
    """Verify normalization of process completion with non-zero exit codes."""

    def test_provider_payload_nonzero_exit(self) -> None:
        payload = {
            "id": "01a0d8ce-9ce0-7310-846b-8b556856ce48",
            "status": "SUCCESS",
            "metadata": {
                "result": {
                    "exit_code": 1,
                    "stdout": "FAILED tests/test_task.py\n",
                    "stderr": "AssertionError",
                    "duration": 4.1,
                }
            },
        }
        record = normalize_execution_result(raw_payload=payload)
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
    """Verify deterministic normalization of timeouts."""

    def test_provider_status_timed_out(self) -> None:
        payload = {
            "id": "op-timeout-1",
            "status": "TIMED_OUT",
            "metadata": {"result": {"exit_code": None, "stdout": "", "stderr": ""}},
        }
        record = normalize_execution_result(raw_payload=payload)
        assert record.outcome == NormalizedExecutionOutcome.TIMEOUT
        assert record.is_timeout is True
        assert record.is_cancelled is False

    def test_provider_http_408_error(self) -> None:
        payload = {
            "id": "op-timeout-2",
            "status": "FAILURE",
            "error": {"status": 408, "error": "Request timed out"},
        }
        record = normalize_execution_result(raw_payload=payload)
        assert record.outcome == NormalizedExecutionOutcome.TIMEOUT
        assert record.is_timeout is True

    def test_error_message_indicates_timeout(self) -> None:
        record = normalize_execution_result(
            provider_status="FAILURE",
            provider_error="Instance execution timeout exceeded 180s",
        )
        assert record.outcome == NormalizedExecutionOutcome.TIMEOUT
        assert record.is_timeout is True

    def test_domain_execution_result_timed_out(self) -> None:
        res = ExecutionResult(status=TerminationStatus.TIMED_OUT)
        record = normalize_execution_result(execution_result=res)
        assert record.outcome == NormalizedExecutionOutcome.TIMEOUT
        assert record.is_timeout is True


class TestCancellationNormalization:
    """Verify deterministic normalization of cancellations."""

    def test_provider_status_cancelled(self) -> None:
        payload = {
            "id": "op-cancel-1",
            "status": "CANCELLED",
            "metadata": {"result": None},
        }
        record = normalize_execution_result(raw_payload=payload)
        assert record.outcome == NormalizedExecutionOutcome.CANCELLED
        assert record.is_cancelled is True
        assert record.is_timeout is False

    def test_provider_http_499_error(self) -> None:
        payload = {
            "id": "op-cancel-2",
            "status": "FAILURE",
            "error": {"status": 499, "error": "Client closed request: operation cancelled"},
        }
        record = normalize_execution_result(raw_payload=payload)
        assert record.outcome == NormalizedExecutionOutcome.CANCELLED
        assert record.is_cancelled is True

    def test_domain_execution_result_cancelled(self) -> None:
        res = ExecutionResult(status=TerminationStatus.CANCELLED)
        record = normalize_execution_result(execution_result=res)
        assert record.outcome == NormalizedExecutionOutcome.CANCELLED
        assert record.is_cancelled is True


class TestResourceFailureNormalization:
    """Verify deterministic identification of verified resource exhaustion."""

    def test_concurrency_limit_exhausted(self) -> None:
        payload = {
            "id": "op-rf-1",
            "status": "FAILURE",
            "error": {
                "status": 429,
                "error": "Max concurrency limit of 50 instances reached for project",
            },
        }
        record = normalize_execution_result(raw_payload=payload)
        assert record.outcome == NormalizedExecutionOutcome.RESOURCE_FAILURE
        assert record.is_resource_failure is True
        assert record.resource_failure_class == ResourceFailureClass.CONCURRENCY_EXHAUSTED

    def test_layer_bytes_quota_exceeded(self) -> None:
        payload = {
            "id": "op-rf-2",
            "status": "FAILURE",
            "error": {
                "status": 400,
                "error": "Instance_max_layer_bytes (12884901888) exceeded during execution",
            },
        }
        record = normalize_execution_result(raw_payload=payload)
        assert record.outcome == NormalizedExecutionOutcome.RESOURCE_FAILURE
        assert record.is_resource_failure is True
        assert record.resource_failure_class == ResourceFailureClass.LAYER_QUOTA_EXCEEDED

    def test_out_of_memory_failure(self) -> None:
        record = normalize_execution_result(
            provider_status="FAILURE",
            provider_error="Process killed by cgroup memory OOM killer",
        )
        assert record.outcome == NormalizedExecutionOutcome.RESOURCE_FAILURE
        assert record.is_resource_failure is True
        assert record.resource_failure_class == ResourceFailureClass.OUT_OF_MEMORY


class TestUnknownProviderFailure:
    """Verify that ambiguous or unverified failures fail closed as UNKNOWN_PROVIDER_FAILURE."""

    def test_http_500_internal_error_not_guessed(self) -> None:
        payload = {
            "id": "op-err-500",
            "status": "FAILURE",
            "error": {"status": 500, "error": "Internal server error"},
        }
        record = normalize_execution_result(raw_payload=payload)
        assert record.outcome == NormalizedExecutionOutcome.UNKNOWN_PROVIDER_FAILURE
        assert record.is_timeout is False
        assert record.is_resource_failure is False
        assert record.resource_failure_class is None

    def test_http_403_insufficient_permissions(self) -> None:
        payload = {
            "status": 403,
            "error": "Insufficient permissions: spawn or spawn_disposable",
        }
        record = normalize_execution_result(raw_payload=payload)
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


class TestMalformedAndPartialResults:
    """Verify fail-closed handling of malformed or partial payloads."""

    def test_empty_payload(self) -> None:
        record = normalize_execution_result(raw_payload={})
        assert record.outcome == NormalizedExecutionOutcome.UNKNOWN_PROVIDER_FAILURE

    def test_success_status_missing_exit_code(self) -> None:
        # Incomplete metadata cannot be trusted as SUCCESS
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
