"""Focused tests for the trusted deployed live-verification bridge (P-27.06)."""

from __future__ import annotations

import json
import time
from typing import Any

from basebreak.causal.public_receipt import (
    PublicVerificationReceipt,
    create_public_verification_receipt,
)
from basebreak.cli.config import BasebreakConfig
from basebreak.cli.runner import execute_verification_pipeline
from basebreak.deployment.live_bridge import (
    BRIDGE_REQUEST_SCHEMA_VERSION,
    BridgeExecutionResult,
    TrustedBridgeConfig,
    TrustedVerifierBridge,
    create_receipt_proof,
    sign_bridge_request,
    verify_receipt_proof,
)
from basebreak.domain.verdict import EvidenceProvenance
from basebreak.verifier.trust_bridge import _PrivilegedVerifierSigner


def _build_synthetic_live_receipt() -> PublicVerificationReceipt:
    result = execute_verification_pipeline(
        target="tests/fixtures/demo_target",
        change_class_name="BUG_FIX",
        config=BasebreakConfig(offline_mode=True),
    )
    assert result.receipt is not None
    receipt = result.receipt
    return create_public_verification_receipt(
        frozen_contract_digest=receipt.frozen_contract_digest,
        task_id=receipt.task_id,
        repo_locator=receipt.repo_locator,
        source_commit_id=receipt.source_commit_id,
        candidate_tree_digest=receipt.candidate_tree_digest,
        candidate_patch_digest=receipt.candidate_patch_digest,
        coverage_summary=receipt.coverage_summary,
        executions=receipt.executions,
        witnesses=receipt.witnesses,
        overall_verdict=receipt.overall_verdict,
        provenance=EvidenceProvenance.LIVE_NEBIUS,
        counterfactual=receipt.counterfactual,
        runtime_identities=receipt.runtime_identities,
        timing={
            **receipt.timing,
            "created_at_utc": "2026-10-16T08:00:00+00:00",
        },
        accounting=receipt.accounting,
        not_run_obligations=receipt.not_run_obligations,
        signature_strategy=receipt.signature_strategy,
        signature=receipt.signature,
        disclaimers=receipt.disclaimers,
    )


def _make_request_payload(source_commit_id: str) -> dict[str, Any]:
    return {
        "schema_version": BRIDGE_REQUEST_SCHEMA_VERSION,
        "request_id": "run_bridge_test_001",
        "issued_at_ms": 1_792_137_000_000,
        "deadline_ms": 1_792_137_060_000,
        "receipt_audience": "cloudflare-worker",
        "task_id": "TASK-RESET-VAULT-001",
        "change_class": "BUG_FIX",
        "target": "tests/fixtures/reset_vault",
        "source_commit_id": source_commit_id,
        "frozen_contract_digest": (
            "a1b2c3d4e5f60718293a4b5c6d7e8f90"
            "a1b2c3d4e5f60718293a4b5c6d7e8f90"
        ),
        "max_estimated_cost_usd": 0.25,
    }


def _sign_headers(payload: dict[str, Any], *, secret: str) -> dict[str, str]:
    timestamp = str(int(time.time() * 1000))
    signature = sign_bridge_request(
        shared_secret=secret,
        method="POST",
        path="/internal/live-verifications",
        timestamp=timestamp,
        audience="cloudflare-worker",
        body=payload,
    )
    return {
        "X-Basebreak-Bridge-Timestamp": timestamp,
        "X-Basebreak-Bridge-Audience": "cloudflare-worker",
        "X-Basebreak-Bridge-Signature": signature,
    }


def test_bridge_auth_round_trip_reaches_live_disabled_gate() -> None:
    receipt = _build_synthetic_live_receipt()
    payload = _make_request_payload(receipt.source_commit_id)
    bridge = TrustedVerifierBridge(
        config=TrustedBridgeConfig(
            shared_secret="bridge-secret",
            expected_source_commit=receipt.source_commit_id,
            live_execution_enabled=False,
        )
    )

    status_code, body = bridge.handle_http_request(
        method="POST",
        path="/internal/live-verifications",
        headers=_sign_headers(payload, secret="bridge-secret"),
        raw_body=json_bytes(payload),
    )

    assert status_code == 503
    assert body["status"] == "BLOCKED_LIVE_DISABLED"


def test_bridge_rejects_invalid_signature() -> None:
    receipt = _build_synthetic_live_receipt()
    payload = _make_request_payload(receipt.source_commit_id)
    bridge = TrustedVerifierBridge(
        config=TrustedBridgeConfig(
            shared_secret="bridge-secret",
            expected_source_commit=receipt.source_commit_id,
            live_execution_enabled=True,
            nebius_api_key="configured",
            nebius_project_id="project-123",
        )
    )

    status_code, body = bridge.handle_http_request(
        method="POST",
        path="/internal/live-verifications",
        headers={
            "X-Basebreak-Bridge-Timestamp": "1792137000000",
            "X-Basebreak-Bridge-Audience": "cloudflare-worker",
            "X-Basebreak-Bridge-Signature": "deadbeef",
        },
        raw_body=json_bytes(payload),
    )

    assert status_code == 401
    assert body["status"] == "UNAUTHORIZED"


def test_bridge_blocks_missing_provider_credentials() -> None:
    receipt = _build_synthetic_live_receipt()
    payload = _make_request_payload(receipt.source_commit_id)
    signer, _ = _PrivilegedVerifierSigner.create_ephemeral_pair()
    bridge = TrustedVerifierBridge(
        config=TrustedBridgeConfig(
            shared_secret="bridge-secret",
            expected_source_commit=receipt.source_commit_id,
            live_execution_enabled=True,
        ),
        signer=signer,
    )

    status_code, body = bridge.handle_http_request(
        method="POST",
        path="/internal/live-verifications",
        headers=_sign_headers(payload, secret="bridge-secret"),
        raw_body=json_bytes(payload),
    )

    assert status_code == 503
    assert body["status"] == "BLOCKED_MISSING_PROVIDER_CREDENTIALS"


def test_bridge_rejects_source_substitution() -> None:
    receipt = _build_synthetic_live_receipt()
    payload = _make_request_payload("f" * 40)
    signer, _ = _PrivilegedVerifierSigner.create_ephemeral_pair()
    bridge = TrustedVerifierBridge(
        config=TrustedBridgeConfig(
            shared_secret="bridge-secret",
            expected_source_commit=receipt.source_commit_id,
            live_execution_enabled=True,
            nebius_api_key="configured",
            nebius_project_id="project-123",
        ),
        signer=signer,
    )

    status_code, body = bridge.handle_http_request(
        method="POST",
        path="/internal/live-verifications",
        headers=_sign_headers(payload, secret="bridge-secret"),
        raw_body=json_bytes(payload),
    )

    assert status_code == 400
    assert body["status"] == "INVALID_SOURCE"


def test_bridge_rejects_executor_that_provisions_sandbox_without_receipt() -> None:
    receipt = _build_synthetic_live_receipt()
    payload = _make_request_payload(receipt.source_commit_id)
    signer, _ = _PrivilegedVerifierSigner.create_ephemeral_pair()

    def executor(_: Any) -> BridgeExecutionResult:
        return BridgeExecutionResult(
            status="FAILED",
            error="Sandbox provisioned but no authoritative witness receipt was produced.",
            provider_operation_ids=("op-sbx-only",),
        )

    bridge = TrustedVerifierBridge(
        config=TrustedBridgeConfig(
            shared_secret="bridge-secret",
            expected_source_commit=receipt.source_commit_id,
            live_execution_enabled=True,
            nebius_api_key="configured",
            nebius_project_id="project-123",
        ),
        executor=executor,
        signer=signer,
    )

    status_code, body = bridge.handle_http_request(
        method="POST",
        path="/internal/live-verifications",
        headers=_sign_headers(payload, secret="bridge-secret"),
        raw_body=json_bytes(payload),
    )

    assert status_code == 503
    assert body["status"] == "FAILED"


def test_bridge_preserves_ambiguous_provider_failure() -> None:
    receipt = _build_synthetic_live_receipt()
    payload = _make_request_payload(receipt.source_commit_id)
    signer, _ = _PrivilegedVerifierSigner.create_ephemeral_pair()

    def executor(_: Any) -> BridgeExecutionResult:
        return BridgeExecutionResult(
            status="UNKNOWN_OUTCOME",
            error="Bridge network failure after remote dispatch; outcome is ambiguous.",
            ambiguous_outcome=True,
            provider_operation_ids=("op-ambiguous-1",),
        )

    bridge = TrustedVerifierBridge(
        config=TrustedBridgeConfig(
            shared_secret="bridge-secret",
            expected_source_commit=receipt.source_commit_id,
            live_execution_enabled=True,
            nebius_api_key="configured",
            nebius_project_id="project-123",
        ),
        executor=executor,
        signer=signer,
    )

    status_code, body = bridge.handle_http_request(
        method="POST",
        path="/internal/live-verifications",
        headers=_sign_headers(payload, secret="bridge-secret"),
        raw_body=json_bytes(payload),
    )

    assert status_code == 502
    assert body["status"] == "UNKNOWN_OUTCOME"
    assert body["ambiguous_outcome"] is True


def test_bridge_returns_signed_live_receipt_proof() -> None:
    receipt = _build_synthetic_live_receipt()
    payload = _make_request_payload(receipt.source_commit_id)
    signer, authority = _PrivilegedVerifierSigner.create_ephemeral_pair()

    def executor(_: Any) -> BridgeExecutionResult:
        return BridgeExecutionResult(
            status="COMPLETED",
            receipt=receipt,
            observed_cost_usd=0.042,
            tokens_used=321,
            provider_operation_ids=("op-live-1", "op-live-2"),
        )

    bridge = TrustedVerifierBridge(
        config=TrustedBridgeConfig(
            shared_secret="bridge-secret",
            expected_source_commit=receipt.source_commit_id,
            live_execution_enabled=True,
            nebius_api_key="configured",
            nebius_project_id="project-123",
        ),
        executor=executor,
        signer=signer,
    )

    status_code, body = bridge.handle_http_request(
        method="POST",
        path="/internal/live-verifications",
        headers=_sign_headers(payload, secret="bridge-secret"),
        raw_body=json_bytes(payload),
    )

    assert status_code == 201
    signed_receipt = PublicVerificationReceipt.from_dict(body["receipt"])
    assert verify_receipt_proof(
        signed_receipt,
        body["receipt_proof"],
        modulus=authority.modulus,
        exponent=authority.exponent,
    )


def test_receipt_proof_rejects_builder_forged_mutation() -> None:
    receipt = _build_synthetic_live_receipt()
    signer, authority = _PrivilegedVerifierSigner.create_ephemeral_pair()
    proof = create_receipt_proof(
        receipt,
        signer=signer,
        issuer_id="basebreak:verifier:nebius:worker",
    )
    forged = dict(proof)
    forged["candidate_tree_digest"] = "f" * 40

    assert (
        verify_receipt_proof(
            receipt,
            forged,
            modulus=authority.modulus,
            exponent=authority.exponent,
        )
        is False
    )


def json_bytes(payload: dict[str, Any]) -> bytes:
    return str.encode(json_dumps(payload))


def json_dumps(payload: dict[str, Any]) -> str:
    return json.dumps(payload, sort_keys=True)
