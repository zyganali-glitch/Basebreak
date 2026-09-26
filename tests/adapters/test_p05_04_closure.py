"""Acceptance gate and closure verification suite for P-05.04.

Master Plan Task:
P-05.04 — Implement model/sandbox telemetry normalization with secret-safe logs

Acceptance Criteria:
- model telemetry
- sandbox telemetry
- malicious/error strings containing synthetic secrets
- oversized fields
- malformed payloads
- provenance preservation
- authority separation
- provider purity
- no P-05.05 implementation leakage before commit
"""

from __future__ import annotations

from pathlib import Path
from typing import Any

import pytest

from basebreak.adapters.nebius import (
    MAX_COLLECTION_ITEMS,
    MAX_PAYLOAD_DIGEST_BYTES,
    MAX_TELEMETRY_DEPTH,
    ModelClientResult,
    NebiusSandboxExecutionResult,
    NormalizedModelTelemetry,
    NormalizedSandboxTelemetry,
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


class TestP0504ClosureGate:
    """Acceptance gate test suite for P-05.04 closure."""

    # Gate 1: Model telemetry
    def test_gate_model_telemetry(self) -> None:
        result = ModelClientResult(
            configured_model="nvidia/Nemotron-3_5-Lightning",
            returned_model="nvidia/Nemotron-3_5-Lightning",
            content="test",
            usage=TokenUsage(prompt_tokens=10, completion_tokens=5, total_tokens=15),
            duration_seconds=0.25,
            request_id="req-gate-1",
            finish_reason="stop",
        )
        telemetry = normalize_model_telemetry(result, provenance=EvidenceProvenance.LIVE_NEBIUS)
        assert isinstance(telemetry, NormalizedModelTelemetry)
        assert telemetry.model == "nvidia/Nemotron-3_5-Lightning"
        assert telemetry.prompt_tokens == 10
        assert telemetry.duration_seconds == 0.25
        assert telemetry.provenance == EvidenceProvenance.LIVE_NEBIUS

    # Gate 2: Sandbox telemetry
    def test_gate_sandbox_telemetry(self) -> None:
        exec_res = NebiusSandboxExecutionResult(
            sandbox_identity=SandboxIdentity(sandbox_id="sbx-gate"),
            operation_id="op-gate-sbx",
            exit_code=0,
            stdout="OK",
            stderr="",
            duration_seconds=1.5,
            result_image_uuid=None,
            provider_status="SUCCESS",
            raw_payload={"id": "op-gate-sbx", "status": "SUCCESS"},
        )
        telemetry = normalize_sandbox_telemetry(
            exec_res, provenance=EvidenceProvenance.RECORDED_LIVE
        )
        assert isinstance(telemetry, NormalizedSandboxTelemetry)
        assert telemetry.operation_id == "op-gate-sbx"
        assert telemetry.provider_status == "SUCCESS"
        assert telemetry.provenance == EvidenceProvenance.RECORDED_LIVE

    # Gate 3: Malicious/error strings containing synthetic secrets
    def test_gate_malicious_strings_with_synthetic_secrets(self) -> None:
        secret = "ghp_LEAKEDSECRET99999999999999999999999"
        raw_error_payload = {
            "error": f"Failed with {secret}",
            "Authorization": f"Bearer {secret}",
        }
        telemetry = normalize_model_telemetry(
            raw_error_payload, provenance=EvidenceProvenance.LOCAL_EXECUTION
        )
        assert secret not in str(telemetry.to_dict())
        assert secret not in format_telemetry_log(telemetry)

    # Gate 4: Oversized fields
    def test_gate_oversized_fields(self) -> None:
        huge = "e" * 10000
        telemetry = normalize_sandbox_telemetry(
            {"error": huge}, provenance=EvidenceProvenance.FIXTURE
        )
        assert telemetry.sanitized_error is not None
        assert len(telemetry.sanitized_error) < 2000
        assert "[TRUNCATED" in telemetry.sanitized_error

    # Gate 5: Malformed payloads
    def test_gate_malformed_payloads(self) -> None:
        # None, int, bad structure fail safely without exception
        m_tel = normalize_model_telemetry(None, provenance=EvidenceProvenance.FIXTURE)
        assert isinstance(m_tel, NormalizedModelTelemetry)
        s_tel = normalize_sandbox_telemetry("corrupted", provenance=EvidenceProvenance.FIXTURE)
        assert isinstance(s_tel, NormalizedSandboxTelemetry)

    # Gate 6: Provenance preservation
    def test_gate_provenance_preservation(self) -> None:
        for prov in (
            EvidenceProvenance.FIXTURE,
            EvidenceProvenance.LOCAL_EXECUTION,
            EvidenceProvenance.LIVE_NEBIUS,
            EvidenceProvenance.RECORDED_LIVE,
        ):
            m = normalize_model_telemetry({}, provenance=prov)
            assert m.provenance == prov
            assert m.provenance.value == prov.value

        with pytest.raises(TypeError):
            normalize_model_telemetry({}, provenance="INVALID")  # type: ignore[arg-type]

    # Gate 7: Authority separation
    def test_gate_authority_separation(self) -> None:
        m = normalize_model_telemetry({}, provenance=EvidenceProvenance.FIXTURE)
        s = normalize_sandbox_telemetry({}, provenance=EvidenceProvenance.FIXTURE)
        assert m.is_authoritative is False
        assert s.is_authoritative is False

    # Gate 8: Provider purity
    def test_gate_provider_purity(self) -> None:
        src_root = Path(__file__).resolve().parent.parent.parent / "src" / "basebreak"
        for pkg in ("domain", "evidence", "security"):
            for py_file in (src_root / pkg).glob("**/*.py"):
                text = py_file.read_text(encoding="utf-8")
                assert "basebreak.adapters" not in text
                assert "from .adapters" not in text

    # Gate 9: No P-05.05 leakage
    def test_gate_no_p05_05_leakage(self) -> None:
        tel_file = (
            Path(__file__).resolve().parent.parent.parent
            / "src"
            / "basebreak"
            / "adapters"
            / "nebius"
            / "telemetry.py"
        )
        text = tel_file.read_text(encoding="utf-8")
        assert "RetryPolicy" not in text
        assert "ExponentialBackoff" not in text
        assert "idempotency_key" not in text

    # Gate 10: Payload bounding and MAX_PAYLOAD_DIGEST_BYTES enforcement
    def test_gate_payload_bounding_and_digest_contract(self) -> None:
        # Small payload: not truncated, full digest
        small = {"req_id": "req-1", "tokens": 50}
        d_small = compute_sanitized_payload_digest(small)
        assert isinstance(d_small, SanitizedPayloadDigest)
        assert d_small.is_truncated is False
        assert len(d_small.digest) == 64
        assert d_small.byte_count <= MAX_PAYLOAD_DIGEST_BYTES

        # Huge payload: bounded, explicit payload_truncated=True
        huge = {f"field_{i}": "x" * 200 for i in range(500)}
        d_huge = compute_sanitized_payload_digest(huge)
        assert d_huge.is_truncated is True
        assert len(d_huge.digest) == 64
        assert d_huge.byte_count <= MAX_PAYLOAD_DIGEST_BYTES

        tel = normalize_model_telemetry(huge, provenance=EvidenceProvenance.FIXTURE)
        assert tel.payload_truncated is True
        assert tel.payload_digest == d_huge.digest
        assert tel.to_dict()["payload_truncated"] is True
        assert "[PAYLOAD_TRUNCATED]" in tel.to_log_message()

    # Gate 11: Deep structure and collection bounding
    def test_gate_deep_structure_and_collection_bounding(self) -> None:
        # Depth > MAX_TELEMETRY_DEPTH
        cur: dict[str, Any] = {}
        root = cur
        for _ in range(MAX_TELEMETRY_DEPTH + 10):
            nxt: dict[str, Any] = {}
            cur["node"] = nxt
            cur = nxt

        sanitized, is_trunc = sanitize_payload(root)
        assert is_trunc is True

        # Collection > MAX_COLLECTION_ITEMS
        big_list = list(range(MAX_COLLECTION_ITEMS + 50))
        san_list, trunc_list = sanitize_payload(big_list)
        assert trunc_list is True
        assert len(san_list) == MAX_COLLECTION_ITEMS + 1  # items + marker

    # Gate 12: Malformed/custom object secret safety
    def test_gate_custom_object_secret_safety(self) -> None:
        secret = "ghp_CUSTOMGATE99999999999999999999999"

        class CustomLeaker:
            def __str__(self) -> str:
                return f"Bearer {secret}"

        tel = normalize_model_telemetry(CustomLeaker(), provenance=EvidenceProvenance.FIXTURE)
        assert secret not in str(tel.to_dict())
        assert secret not in format_telemetry_log(tel)
        assert "Malformed telemetry source" in (tel.sanitized_error or "")
