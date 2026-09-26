"""Deterministic unit tests for model and sandbox telemetry normalization.

Provenance: FIXTURE / LOCAL_EXECUTION.
Validates all requirements of P-05.04 without requiring live network credentials.
"""

from __future__ import annotations

import pytest

from basebreak.adapters.nebius import (
    ModelClientResult,
    ModelProviderError,
    NebiusSandboxExecutionResult,
    NormalizedModelTelemetry,
    NormalizedSandboxTelemetry,
    SandboxProviderError,
    TokenUsage,
    format_telemetry_log,
    normalize_model_telemetry,
    normalize_sandbox_telemetry,
)
from basebreak.domain.execution import SandboxIdentity
from basebreak.domain.verdict import EvidenceProvenance


class TestNebiusTelemetryNormalization:
    """Test suite covering P-05.04 telemetry normalization."""

    # 1. Model telemetry normalization from ModelClientResult
    def test_normalize_model_telemetry_from_result(self) -> None:
        result = ModelClientResult(
            configured_model="nvidia/Nemotron-3_5-Lightning",
            returned_model="nvidia/Nemotron-3_5-Lightning",
            content="Hello world",
            usage=TokenUsage(prompt_tokens=15, completion_tokens=8, total_tokens=23),
            duration_seconds=0.456,
            request_id="req-98765",
            finish_reason="stop",
        )

        telemetry = normalize_model_telemetry(
            result,
            provenance=EvidenceProvenance.LIVE_NEBIUS,
        )

        assert isinstance(telemetry, NormalizedModelTelemetry)
        assert telemetry.model == "nvidia/Nemotron-3_5-Lightning"
        assert telemetry.returned_model == "nvidia/Nemotron-3_5-Lightning"
        assert telemetry.request_id == "req-98765"
        assert telemetry.prompt_tokens == 15
        assert telemetry.completion_tokens == 8
        assert telemetry.total_tokens == 23
        assert telemetry.duration_seconds == 0.456
        assert telemetry.finish_reason == "stop"
        assert telemetry.provenance == EvidenceProvenance.LIVE_NEBIUS
        assert telemetry.status_code == 200
        assert telemetry.is_authoritative is False
        assert telemetry.payload_digest != ""

    # 2. Model telemetry from ModelProviderError
    def test_normalize_model_telemetry_from_provider_error(self) -> None:
        err = ModelProviderError(status_code=429, sanitized_message="Rate limit exceeded")
        telemetry = normalize_model_telemetry(
            err,
            provenance=EvidenceProvenance.LOCAL_EXECUTION,
            configured_model="nvidia/Nemotron-3_5-Lightning",
        )

        assert telemetry.status_code == 429
        assert telemetry.sanitized_error == "Rate limit exceeded"
        assert telemetry.provenance == EvidenceProvenance.LOCAL_EXECUTION
        assert telemetry.is_authoritative is False

    # 3. Sandbox telemetry normalization from NebiusSandboxExecutionResult
    def test_normalize_sandbox_telemetry_from_result(self) -> None:
        result = NebiusSandboxExecutionResult(
            sandbox_identity=SandboxIdentity(sandbox_id="sbx-test-123"),
            operation_id="op-sandbox-456",
            exit_code=0,
            stdout="ALL_TESTS_PASS\n",
            stderr="",
            duration_seconds=5.2,
            result_image_uuid="img-uuid-001",
            provider_status="SUCCESS",
            raw_payload={
                "id": "op-sandbox-456",
                "status": "SUCCESS",
                "metadata": {
                    "result": {
                        "exit_code": 0,
                        "cpu_time": 1.45,
                        "memory": 86000000,
                    }
                },
            },
        )

        telemetry = normalize_sandbox_telemetry(
            result,
            provenance=EvidenceProvenance.RECORDED_LIVE,
            image="tag:astral/uv:python3.11-alpine",
            disposable=True,
        )

        assert isinstance(telemetry, NormalizedSandboxTelemetry)
        assert telemetry.operation_id == "op-sandbox-456"
        assert telemetry.sandbox_id == "sbx-test-123"
        assert telemetry.provider_status == "SUCCESS"
        assert telemetry.duration_seconds == 5.2
        assert telemetry.cpu_duration_seconds == 1.45
        assert telemetry.memory_bytes == 86000000
        assert telemetry.provenance == EvidenceProvenance.RECORDED_LIVE
        assert telemetry.is_authoritative is False
        assert telemetry.payload_digest != ""

    # 4. Sandbox telemetry from error
    def test_normalize_sandbox_telemetry_from_provider_error(self) -> None:
        err = SandboxProviderError(status_code=403, sanitized_message="Insufficient permissions")
        telemetry = normalize_sandbox_telemetry(
            err,
            provenance=EvidenceProvenance.FIXTURE,
            sandbox_id="sbx-err",
        )

        assert telemetry.provider_status == "HTTP_403"
        assert telemetry.sanitized_error == "Insufficient permissions"
        assert telemetry.provenance == EvidenceProvenance.FIXTURE

    # 5. Malicious & synthetic secrets in telemetry payloads are redacted
    def test_synthetic_secrets_are_redacted_from_telemetry(self) -> None:
        synthetic_token = "ghp_VERYSECRETGITHUBTOKEN1234567890abcde"
        raw_payload = {
            "id": "req-secret",
            "Authorization": f"Bearer {synthetic_token}",
            "error": f"Failed with {synthetic_token}",
            "project_id": "aiproject-secret-123",
        }

        telemetry = normalize_model_telemetry(
            raw_payload,
            provenance=EvidenceProvenance.LOCAL_EXECUTION,
        )

        # Check sanitized_error
        assert synthetic_token not in (telemetry.sanitized_error or "")
        assert "[REDACTED" in (telemetry.sanitized_error or "")

        # Check log message
        log_line = format_telemetry_log(telemetry)
        assert synthetic_token not in log_line

    # 6. Oversized fields are bounded cleanly
    def test_oversized_strings_are_bounded(self) -> None:
        huge_error = "x" * 5000
        raw_payload = {"id": "req-huge", "error": huge_error}

        telemetry = normalize_model_telemetry(
            raw_payload,
            provenance=EvidenceProvenance.FIXTURE,
        )

        assert telemetry.sanitized_error is not None
        assert len(telemetry.sanitized_error.encode("utf-8")) <= 1200
        assert "[TRUNCATED" in telemetry.sanitized_error

    # 7. Malformed payloads fail safe without raising unhandled exceptions
    def test_malformed_payload_fails_safe(self) -> None:
        telemetry = normalize_model_telemetry(
            "not-a-dict-or-result",
            provenance=EvidenceProvenance.FIXTURE,
        )
        assert isinstance(telemetry, NormalizedModelTelemetry)
        assert telemetry.provenance == EvidenceProvenance.FIXTURE
        assert "Malformed" in (telemetry.sanitized_error or "")

        sbx_telemetry = normalize_sandbox_telemetry(
            12345,
            provenance=EvidenceProvenance.FIXTURE,
        )
        assert isinstance(sbx_telemetry, NormalizedSandboxTelemetry)
        assert sbx_telemetry.provider_status == "MALFORMED_TELEMETRY"

    # 8. Provenance preservation and validation
    def test_provenance_validation_rejects_non_enum(self) -> None:
        with pytest.raises(TypeError, match="instance of EvidenceProvenance"):
            normalize_model_telemetry({}, provenance="LIVE_NEBIUS")  # type: ignore[arg-type]

        with pytest.raises(TypeError, match="instance of EvidenceProvenance"):
            normalize_sandbox_telemetry({}, provenance=None)  # type: ignore[arg-type]

    # 9. Authority separation: telemetry cannot mutate causal facts
    def test_telemetry_authority_separation(self) -> None:
        result = NebiusSandboxExecutionResult(
            sandbox_identity=SandboxIdentity(sandbox_id="sbx-1"),
            operation_id="op-1",
            exit_code=1,  # Exit code 1 is authoritative fact
            stdout="",
            stderr="AssertionError",
            duration_seconds=1.0,
            result_image_uuid=None,
            provider_status="SUCCESS",  # Provider says SUCCESS
        )

        telemetry = normalize_sandbox_telemetry(
            result,
            provenance=EvidenceProvenance.LOCAL_EXECUTION,
        )

        # Telemetry records provider metadata truthfully
        assert telemetry.provider_status == "SUCCESS"
        assert telemetry.is_authoritative is False

        # But normalizing the execution record MUST still follow deterministic fact (exit code 1)
        norm_exec = result.to_normalized_record()
        assert norm_exec.exit_code == 1
        assert norm_exec.outcome.value == "NONZERO_EXIT"
