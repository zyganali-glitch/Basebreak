"""Deterministic unit tests for model and sandbox telemetry normalization.

Provenance: FIXTURE / LOCAL_EXECUTION.
Validates all requirements of P-05.04 without requiring live network credentials.
"""

from __future__ import annotations

from typing import Any

import pytest

from basebreak.adapters.nebius import (
    MAX_COLLECTION_ITEMS,
    MAX_PAYLOAD_DIGEST_BYTES,
    MAX_TELEMETRY_DEPTH,
    MAX_TELEMETRY_STRING_BYTES,
    ModelClientResult,
    ModelProviderError,
    NebiusSandboxExecutionResult,
    NormalizedModelTelemetry,
    NormalizedSandboxTelemetry,
    SandboxProviderError,
    SanitizedPayloadDigest,
    TokenUsage,
    compute_sanitized_payload_digest,
    format_telemetry_log,
    normalize_model_telemetry,
    normalize_sandbox_telemetry,
    sanitize_payload,
)
from basebreak.domain.execution import SandboxIdentity
from basebreak.domain.verdict import EvidenceProvenance
from basebreak.security.secret_policy import find_secret_findings


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

    # A. Payload below the bound has deterministic digest behavior
    def test_payload_below_bound_deterministic_digest(self) -> None:
        payload = {"model": "nvidia/Nemotron-3_5-Lightning", "status": "COMPLETED", "tokens": 100}
        res1 = compute_sanitized_payload_digest(payload)
        res2 = compute_sanitized_payload_digest(payload)

        assert isinstance(res1, SanitizedPayloadDigest)
        assert res1.is_truncated is False
        assert res2.is_truncated is False
        assert res1.digest == res2.digest
        assert len(res1.digest) == 64
        assert res1.byte_count > 0
        assert res1.byte_count < MAX_PAYLOAD_DIGEST_BYTES

        # Tuple unpacking test
        d_val, is_trunc = res1
        assert d_val == res1.digest
        assert is_trunc is False

        tel = normalize_model_telemetry(payload, provenance=EvidenceProvenance.FIXTURE)
        assert tel.payload_truncated is False
        assert tel.payload_digest == res1.digest
        assert tel.to_dict()["payload_truncated"] is False
        assert "[PAYLOAD_TRUNCATED]" not in tel.to_log_message()

    # B. Payload exceeding MAX_PAYLOAD_DIGEST_BYTES is handled within defined bounded policy
    def test_payload_exceeding_max_payload_digest_bytes_bounded(self) -> None:
        # Create a payload whose serialized bytes exceed MAX_PAYLOAD_DIGEST_BYTES (65536)
        large_dict = {f"k_{i:04d}": f"v_{i:04d}" * 20 for i in range(1000)}
        res = compute_sanitized_payload_digest(large_dict)

        assert isinstance(res, SanitizedPayloadDigest)
        assert res.is_truncated is True
        assert len(res.digest) == 64
        assert res.byte_count <= MAX_PAYLOAD_DIGEST_BYTES

        tel = normalize_model_telemetry(large_dict, provenance=EvidenceProvenance.FIXTURE)
        assert tel.payload_truncated is True
        assert tel.payload_digest == res.digest
        assert tel.to_dict()["payload_truncated"] is True
        assert "[PAYLOAD_TRUNCATED]" in tel.to_log_message()

    # C. Very large nested mapping/list input is bounded
    def test_large_nested_mapping_and_list_bounded(self) -> None:
        # keys in mapping exceed MAX_COLLECTION_ITEMS -> clamped
        huge_mapping = {f"k_{i:04d}": i for i in range(MAX_COLLECTION_ITEMS + 100)}
        res_map = compute_sanitized_payload_digest(huge_mapping)
        assert res_map.is_truncated is True

        # items in list exceed MAX_COLLECTION_ITEMS -> clamped
        huge_list = list(range(MAX_COLLECTION_ITEMS + 100))
        res_list = compute_sanitized_payload_digest({"items": huge_list})
        assert res_list.is_truncated is True

    # D. Excessive nesting depth fails safely or is deterministically bounded
    def test_excessive_nesting_depth_and_cycles_bounded(self) -> None:
        # Depth > MAX_TELEMETRY_DEPTH (8)
        cur: dict[str, Any] = {}
        root = cur
        for _ in range(MAX_TELEMETRY_DEPTH + 10):
            nxt: dict[str, Any] = {}
            cur["child"] = nxt
            cur = nxt
        res = compute_sanitized_payload_digest(root)
        assert res.is_truncated is True
        assert len(res.digest) == 64

        # Circular reference
        cyclic: dict[str, Any] = {"name": "cyclic"}
        cyclic["self"] = cyclic
        res_cyc = compute_sanitized_payload_digest(cyclic)
        assert res_cyc.is_truncated is True
        assert len(res_cyc.digest) == 64

    # E. Oversized strings are bounded before durable normalized retention
    def test_oversized_strings_bounded_before_retention(self) -> None:
        oversized = "a" * (MAX_TELEMETRY_STRING_BYTES * 10)
        res = compute_sanitized_payload_digest({"content": oversized})
        assert res.is_truncated is True
        assert len(res.digest) == 64

    # F. Sensitive keys in nested structures remain redacted
    def test_sensitive_keys_in_nested_structures_redacted(self) -> None:
        payload = {
            "meta": {
                "api_key": "my-secret-key-12345",
                "nested": {
                    "authorization": "Bearer token-67890",
                    "safe_field": "public_data",
                },
            },
            "error": "Request failed with api_key=my-secret-key-12345 and token=token-67890",
        }
        sanitized, _ = sanitize_payload(payload)
        assert sanitized["meta"]["api_key"] == "[REDACTED_CREDENTIAL]"
        assert sanitized["meta"]["nested"]["authorization"] == "[REDACTED_CREDENTIAL]"
        assert sanitized["meta"]["nested"]["safe_field"] == "public_data"
        assert "my-secret-key-12345" not in str(sanitized)
        assert "token-67890" not in str(sanitized)

        tel = normalize_model_telemetry(payload, provenance=EvidenceProvenance.LOCAL_EXECUTION)
        tel_dict = tel.to_dict()
        dict_str = str(tel_dict)
        assert "my-secret-key-12345" not in dict_str
        assert "token-67890" not in dict_str
        assert tel.sanitized_error is not None
        assert "my-secret-key-12345" not in tel.sanitized_error
        assert "token-67890" not in tel.sanitized_error

    # G. Synthetic secrets in values remain redacted
    def test_synthetic_secrets_in_values_redacted(self) -> None:
        synthetic_key = "ghp_SYNTHETICSECRETKEY000000000000000000"
        payload = {
            "logs": [
                f"Connection failed: {synthetic_key}",
                {"detail": f"bearer {synthetic_key}"},
            ]
        }
        tel = normalize_sandbox_telemetry(payload, provenance=EvidenceProvenance.LOCAL_EXECUTION)
        assert synthetic_key not in str(tel.to_dict())
        assert synthetic_key not in tel.to_log_message()
        assert synthetic_key not in format_telemetry_log(tel)
        assert find_secret_findings(format_telemetry_log(tel)) == ()

    # H. Malformed/custom object input cannot leak synthetic secrets through __str__/__repr__
    def test_malformed_and_custom_objects_cannot_leak_synthetic_secrets(self) -> None:
        secret1 = "ghp_CUSTOMOBJSECRET1111111111111111111111"
        secret2 = "ghp_REPROBJSECRET22222222222222222222222"

        class SecretStrObject:
            def __str__(self) -> str:
                return f"SecretStrObject(token={secret1})"

        class SecretReprObject:
            def __repr__(self) -> str:
                return f"SecretReprObject(token={secret2})"

        class ExplodingObject:
            def __str__(self) -> str:
                raise RuntimeError("exploding stringify")

            def __repr__(self) -> str:
                raise ValueError("exploding repr")

        # 1. As source in normalize_model_telemetry
        tel_str = normalize_model_telemetry(
            SecretStrObject(), provenance=EvidenceProvenance.FIXTURE
        )
        assert secret1 not in str(tel_str.to_dict())
        assert secret1 not in format_telemetry_log(tel_str)

        tel_repr = normalize_sandbox_telemetry(
            SecretReprObject(), provenance=EvidenceProvenance.FIXTURE
        )
        assert secret2 not in str(tel_repr.to_dict())
        assert secret2 not in format_telemetry_log(tel_repr)

        # 2. Exploding object as source fails safely
        tel_exp = normalize_model_telemetry(
            ExplodingObject(), provenance=EvidenceProvenance.FIXTURE
        )
        assert isinstance(tel_exp, NormalizedModelTelemetry)
        assert "Malformed telemetry source" in (tel_exp.sanitized_error or "")

        # 3. Inside nested payload to compute_sanitized_payload_digest
        nested_payload = {
            "obj1": SecretStrObject(),
            "obj2": SecretReprObject(),
            "obj3": ExplodingObject(),
        }
        digest_res = compute_sanitized_payload_digest(nested_payload)
        assert digest_res.is_truncated is True
        assert len(digest_res.digest) == 64

    # I. Provenance remains unchanged for FIXTURE, LOCAL_EXECUTION, LIVE_NEBIUS, RECORDED_LIVE
    def test_provenance_preservation_all_enums(self) -> None:
        for prov in EvidenceProvenance:
            m = normalize_model_telemetry({"ok": True}, provenance=prov)
            assert m.provenance is prov
            assert m.provenance.value == prov.value
            assert m.to_dict()["provenance"] == prov.value

            s = normalize_sandbox_telemetry({"ok": True}, provenance=prov)
            assert s.provenance is prov
            assert s.provenance.value == prov.value
            assert s.to_dict()["provenance"] == prov.value

    # J. Normalized telemetry remains non-authoritative
    def test_normalized_telemetry_strictly_non_authoritative(self) -> None:
        m = normalize_model_telemetry({}, provenance=EvidenceProvenance.LIVE_NEBIUS)
        s = normalize_sandbox_telemetry({}, provenance=EvidenceProvenance.LIVE_NEBIUS)

        assert m.is_authoritative is False
        assert s.is_authoritative is False
        assert m.to_dict()["is_authoritative"] is False
        assert s.to_dict()["is_authoritative"] is False
