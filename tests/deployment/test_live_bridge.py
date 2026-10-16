"""Focused tests for the trusted deployed live-verification bridge (P-27.06)."""

from __future__ import annotations

import json
import os
import subprocess
import tempfile
import time
from typing import Any

from basebreak.adapters.nebius import DEFAULT_PRIMARY_MODEL, ModelClientResult, TokenUsage
from basebreak.causal.public_receipt import (
    PublicVerificationReceipt,
    create_public_verification_receipt,
)
from basebreak.causal.receipt import WorldExecutionFact, create_causal_triplet_receipt
from basebreak.causal.reconciliation import CausalTransition
from basebreak.cli.config import BasebreakConfig
from basebreak.cli.runner import execute_verification_pipeline
from basebreak.deployment.live_bridge import (
    BRIDGE_REQUEST_SCHEMA_VERSION,
    BridgeExecutionResult,
    BridgeRequest,
    DurableIdempotencyUnavailableError,
    ExecutionIdempotencyStore,
    TrustedBridgeConfig,
    TrustedVerifierBridge,
    create_live_nebius_bridge_executor,
    create_live_nebius_execution_authority_verifier,
    create_receipt_proof,
    sign_bridge_request,
    verify_receipt_proof,
)
from basebreak.domain.causal import ExecutionWorld
from basebreak.domain.execution import TerminationStatus
from basebreak.domain.verdict import EvidenceProvenance, PreliminaryVerdict
from basebreak.verifier.trust_bridge import _PrivilegedVerifierSigner
from basebreak.verifier.witness_result import WitnessOutcome


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
    now_ms = int(time.time() * 1000)
    return {
        "schema_version": BRIDGE_REQUEST_SCHEMA_VERSION,
        "request_id": "run_bridge_test_001",
        "issued_at_ms": now_ms,
        "deadline_ms": now_ms + 60_000,
        "receipt_audience": "cloudflare-worker",
        "task_id": "TASK-RESET-VAULT-001",
        "change_class": "BUG_FIX",
        "target": "tests/fixtures/reset_vault",
        "source_commit_id": source_commit_id,
        "frozen_contract_digest": (
            "93eeeb2cc7eb02a988da3c8a8543ad40b4816608c1452d048ff62ee93702f812"
        ),
        "max_estimated_cost_usd": 0.25,
    }


def _canonical_modulus_signer() -> _PrivilegedVerifierSigner:
    """Signer whose modulus matches the pinned authority but lacks the real key.

    Used to exercise pre-execution gates that require signer compatibility without
    possessing production signing material. It can never produce a valid proof.
    """
    return _PrivilegedVerifierSigner(private_key_d=1)


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
    signer = _canonical_modulus_signer()
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
    signer = _canonical_modulus_signer()
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


def test_bridge_rejects_frozen_contract_substitution() -> None:
    receipt = _build_synthetic_live_receipt()
    payload = _make_request_payload(receipt.source_commit_id)
    payload["frozen_contract_digest"] = "f" * 64
    signer = _canonical_modulus_signer()
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
    assert body["status"] == "INVALID_CONTRACT"


def test_bridge_rejects_executor_that_provisions_sandbox_without_receipt() -> None:
    receipt = _build_synthetic_live_receipt()
    payload = _make_request_payload(receipt.source_commit_id)
    signer = _canonical_modulus_signer()

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
    signer = _canonical_modulus_signer()

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


def test_bridge_rejects_executor_reported_live_receipt_without_independent_authority() -> None:
    receipt = _build_synthetic_live_receipt()
    payload = _make_request_payload(receipt.source_commit_id)
    signer = _canonical_modulus_signer()

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

    assert status_code == 503
    assert body["status"] == "NOT_READY_FOR_DEPLOYMENT"
    assert "Independent live execution authority is not configured" in body["error"]


def test_low_level_receipt_proof_round_trip_for_fixture_receipt() -> None:
    receipt = _build_synthetic_live_receipt()
    signer, authority = _PrivilegedVerifierSigner.create_ephemeral_pair()
    proof = create_receipt_proof(
        receipt,
        signer=signer,
        issuer_id="basebreak:verifier:nebius:worker",
    )

    assert verify_receipt_proof(
        PublicVerificationReceipt.from_dict(receipt.to_dict()),
        proof,
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


def test_live_nebius_executor_downgrades_synthetic_dependencies_to_fixture() -> None:
    """Synthetic model/sandbox/worker dependencies must never yield LIVE_NEBIUS authority.

    The executor still exercises the receipt-building path, but because the
    dependencies are not the canonical Nebius components, provenance is downgraded
    to FIXTURE and the production authority verifier rejects it.
    """
    signer, authority = _PrivilegedVerifierSigner.create_ephemeral_pair()
    verifier = create_live_nebius_execution_authority_verifier()
    source_commit_id = _git_head_commit()
    payload = _make_request_payload(source_commit_id)
    request = BridgeRequest.from_dict(payload)

    sandbox_adapter = _FakeSandboxAdapter()
    worker = _FakeWorker(
        sandbox_adapter=sandbox_adapter,
        receipt=_make_live_local_receipt(source_commit_id=source_commit_id, signer=signer),
    )
    executor = create_live_nebius_bridge_executor(
        config=TrustedBridgeConfig(
            expected_source_commit=source_commit_id,
            nebius_api_key="configured",
            nebius_project_id="project-123",
            source_repo_locator="https://github.com/zyganali-glitch/Basebreak.git",
        ),
        signer=signer,
        verifier_authority=authority,
        model_client=_FakeModelClient(payload),
        sandbox_adapter=sandbox_adapter,
        verifier_worker=worker,
    )

    result = executor(request)
    assert result.status == "COMPLETED"
    assert result.receipt is not None
    assert result.production_grounded is False
    assert result.receipt.provenance == EvidenceProvenance.FIXTURE
    assert result.tokens_used == 18
    assert result.provider_operation_ids == ("op-live-base", "op-live-candidate", "op-live-cf")
    assert result.receipt.source_commit_id == source_commit_id
    assert result.receipt.candidate_patch_digest == (
        "3d5077cdc2b1a3008236ebb3615c70583634eda6db3e34f48fd7f8b332525a38"
    )
    # Estimated/reserved exposure must never masquerade as observed provider cost.
    assert result.observed_cost_usd is None
    assert result.reserved_exposure_usd == 0.25
    assert result.approved_estimate_usd == 0.25
    assert result.cost_provenance == "UNKNOWN"

    ok, error = verifier(request, result)
    assert ok is False
    assert error is not None


def test_authority_verifier_rejects_forged_grounded_synthetic_receipt() -> None:
    """Adversarial: a synthetic three-world receipt can never pass even if it claims grounding.

    This reproduces the DEFECT A attack: fabricated operation IDs plus a
    structurally consistent LIVE_NEBIUS receipt, with ``production_grounded``
    forced True and every reported identity string self-consistent.
    """
    signer, authority = _PrivilegedVerifierSigner.create_ephemeral_pair()
    verifier = create_live_nebius_execution_authority_verifier()
    source_commit_id = _git_head_commit()
    payload = _make_request_payload(source_commit_id)
    request = BridgeRequest.from_dict(payload)

    sandbox_adapter = _FakeSandboxAdapter()
    worker = _FakeWorker(
        sandbox_adapter=sandbox_adapter,
        receipt=_make_live_local_receipt(source_commit_id=source_commit_id, signer=signer),
    )
    executor = create_live_nebius_bridge_executor(
        config=TrustedBridgeConfig(
            expected_source_commit=source_commit_id,
            nebius_api_key="configured",
            nebius_project_id="project-123",
            source_repo_locator="https://github.com/zyganali-glitch/Basebreak.git",
        ),
        signer=signer,
        verifier_authority=authority,
        model_client=_FakeModelClient(payload),
        sandbox_adapter=sandbox_adapter,
        verifier_worker=worker,
    )

    result = executor(request)
    assert result.receipt is not None
    forged = BridgeExecutionResult(
        status="COMPLETED",
        receipt=result.receipt,
        local_receipt=result.local_receipt,
        production_grounded=True,  # attacker-asserted grounding
        provider_operation_ids=("op-synthetic-1", "op-synthetic-2", "op-synthetic-3"),
    )
    ok, error = verifier(request, forged)
    # Synthetic operation IDs are not in the receipt runtime identities.
    assert ok is False
    assert error is not None

    # Even with matching runtime identity strings, a non-canonical attestation
    # cannot satisfy independent production authority.
    synthetic_receipt = _build_receipt_with_operation_identities(
        result.receipt, ("op-synthetic-1", "op-synthetic-2", "op-synthetic-3")
    )
    forged_with_identities = BridgeExecutionResult(
        status="COMPLETED",
        receipt=synthetic_receipt,
        local_receipt=result.local_receipt,
        production_grounded=True,
        provider_operation_ids=("op-synthetic-1", "op-synthetic-2", "op-synthetic-3"),
    )
    ok2, error2 = verifier(request, forged_with_identities)
    assert ok2 is False
    assert error2 is not None


def _build_receipt_with_operation_identities(receipt: Any, operation_ids: tuple[str, ...]) -> Any:
    from basebreak.causal.public_receipt import create_public_verification_receipt

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
        provenance=receipt.provenance,
        counterfactual=receipt.counterfactual,
        runtime_identities=tuple(receipt.runtime_identities)
        + tuple(f"nebius-operation:{op}" for op in operation_ids),
        timing=receipt.timing,
        accounting=receipt.accounting,
        not_run_obligations=receipt.not_run_obligations,
        signature_strategy=receipt.signature_strategy,
        signature=receipt.signature,
        disclaimers=receipt.disclaimers,
    )


def json_bytes(payload: dict[str, Any]) -> bytes:
    return str.encode(json_dumps(payload))


def json_dumps(payload: dict[str, Any]) -> str:
    return json.dumps(payload, sort_keys=True)


def _git_head_commit() -> str:
    result = subprocess.run(
        ["git", "rev-parse", "HEAD"],
        capture_output=True,
        text=True,
        check=True,
    )
    return result.stdout.strip().lower()


class _FakeModelClient:
    def __init__(self, payload: dict[str, Any]) -> None:
        self._payload = payload

    def complete(
        self,
        _: list[Any],
        *,
        max_tokens: int | None = None,
        temperature: float | None = None,
    ) -> ModelClientResult:
        del max_tokens, temperature
        content = (
            "LIVE_ATTESTATION "
            f"request_id={self._payload['request_id']} "
            f"source_commit_id={self._payload['source_commit_id']} "
            f"contract_digest={self._payload['frozen_contract_digest']}"
        )
        return ModelClientResult(
            configured_model=DEFAULT_PRIMARY_MODEL,
            returned_model=DEFAULT_PRIMARY_MODEL,
            content=content,
            finish_reason="stop",
            request_id="model-req-1",
            usage=TokenUsage(prompt_tokens=11, completion_tokens=7, total_tokens=18),
            duration_seconds=0.25,
        )


class _FakeSandboxAdapter:
    def __init__(self) -> None:
        self._ops: list[str] = []

    @property
    def live_operation_ids(self) -> tuple[str, ...]:
        return tuple(self._ops)


class _FakeWorker:
    def __init__(self, *, sandbox_adapter: _FakeSandboxAdapter, receipt: Any) -> None:
        self._sandbox_adapter = sandbox_adapter
        self._receipt = receipt

    def execute_causal_triplet(self, **_: Any) -> Any:
        self._sandbox_adapter._ops.extend(["op-live-base", "op-live-candidate", "op-live-cf"])
        return self._receipt


def _make_live_local_receipt(*, source_commit_id: str, signer: _PrivilegedVerifierSigner) -> Any:
    base_fact = WorldExecutionFact(
        world=ExecutionWorld.BASE,
        sandbox_id="sbx-live-base",
        source_commit_id=source_commit_id,
        tree_digest="1" * 40,
        outcome=WitnessOutcome.FAIL,
        exit_code=1,
        termination_status=TerminationStatus.COMPLETED,
        stdout_digest="2" * 64,
        stderr_digest="3" * 64,
        result_digest="4" * 64,
        duration_seconds=1.0,
    )
    candidate_fact = WorldExecutionFact(
        world=ExecutionWorld.CANDIDATE,
        sandbox_id="sbx-live-candidate",
        source_commit_id=source_commit_id,
        tree_digest="5" * 40,
        outcome=WitnessOutcome.PASS,
        exit_code=0,
        termination_status=TerminationStatus.COMPLETED,
        stdout_digest="6" * 64,
        stderr_digest="7" * 64,
        result_digest="8" * 64,
        duration_seconds=1.1,
    )
    counterfactual_fact = WorldExecutionFact(
        world=ExecutionWorld.COUNTERFACTUAL,
        sandbox_id="sbx-live-cf",
        source_commit_id=source_commit_id,
        tree_digest="9" * 40,
        outcome=WitnessOutcome.FAIL,
        exit_code=1,
        termination_status=TerminationStatus.COMPLETED,
        stdout_digest="a" * 64,
        stderr_digest="b" * 64,
        result_digest="c" * 64,
        duration_seconds=1.2,
    )
    attestation = signer.issue_production_attestation(
        issuer_id="basebreak:verifier:nebius:worker",
        execution_origin="NEBIUS_TOKEN_FACTORY_SANDBOX",
        requirement_id="REQ-RESET-001",
        frozen_contract_digest="93eeeb2cc7eb02a988da3c8a8543ad40b4816608c1452d048ff62ee93702f812",
        witness_id="wit-reset-vault-live-001",
        witness_digest="d" * 64,
        source_commit_id=source_commit_id,
        candidate_tree_digest=candidate_fact.tree_digest,
        base_outcome=base_fact.outcome,
        candidate_outcome=candidate_fact.outcome,
        transition=CausalTransition.CAUSAL_TRIPLET_VERIFIED,
        verdict=PreliminaryVerdict.VERIFIED,
        provenance=EvidenceProvenance.LIVE_NEBIUS,
        execution_command=(
            "python -m pytest tests/fixtures/reset_vault/witness/test_single_use_witness.py -q"
        ),
        base_sandbox_id=base_fact.sandbox_id,
        candidate_sandbox_id=candidate_fact.sandbox_id,
        base_exit_code=base_fact.exit_code,
        candidate_exit_code=candidate_fact.exit_code,
        base_result_digest=base_fact.result_digest,
        candidate_result_digest=candidate_fact.result_digest,
    )
    return create_causal_triplet_receipt(
        requirement_id="REQ-RESET-001",
        frozen_contract_digest="93eeeb2cc7eb02a988da3c8a8543ad40b4816608c1452d048ff62ee93702f812",
        witness_id="wit-reset-vault-live-001",
        witness_digest="d" * 64,
        lock_digest="e" * 64,
        base_execution=base_fact,
        candidate_execution=candidate_fact,
        counterfactual_execution=counterfactual_fact,
        counterfactual_id="cf-live-001",
        delta_digest="f" * 64,
        transition=CausalTransition.CAUSAL_TRIPLET_VERIFIED,
        verdict=PreliminaryVerdict.VERIFIED,
        provenance=EvidenceProvenance.LIVE_NEBIUS,
        narrative="BASE fail, CANDIDATE pass, COUNTERFACTUAL fail.",
        attestation=attestation,
    )


def _bridge_config(
    source_commit_id: str, *, bridge_state_dir: str | None = None
) -> TrustedBridgeConfig:
    return TrustedBridgeConfig(
        shared_secret="bridge-secret",
        expected_source_commit=source_commit_id,
        live_execution_enabled=True,
        nebius_api_key="configured",
        nebius_project_id="project-123",
        bridge_state_dir=bridge_state_dir,
    )


def test_bridge_rejects_expired_request_before_dispatch() -> None:
    receipt = _build_synthetic_live_receipt()
    payload = _make_request_payload(receipt.source_commit_id)
    now_ms = int(time.time() * 1000)
    payload["issued_at_ms"] = now_ms - 120_000
    payload["deadline_ms"] = now_ms - 60_000
    calls = {"n": 0}

    def executor(_: Any) -> BridgeExecutionResult:
        calls["n"] += 1
        return BridgeExecutionResult(status="FAILED", error="must not run")

    bridge = TrustedVerifierBridge(
        config=_bridge_config(receipt.source_commit_id),
        executor=executor,
        signer=_canonical_modulus_signer(),
    )
    status_code, body = bridge.handle_http_request(
        method="POST",
        path="/internal/live-verifications",
        headers=_sign_headers(payload, secret="bridge-secret"),
        raw_body=json_bytes(payload),
    )
    assert status_code == 410
    assert body["status"] == "EXPIRED_REQUEST"
    assert calls["n"] == 0


def test_bridge_rejects_invalid_deadline_window() -> None:
    receipt = _build_synthetic_live_receipt()
    payload = _make_request_payload(receipt.source_commit_id)
    now_ms = int(time.time() * 1000)
    payload["issued_at_ms"] = now_ms
    payload["deadline_ms"] = now_ms  # not strictly after

    bridge = TrustedVerifierBridge(
        config=_bridge_config(receipt.source_commit_id),
        executor=lambda _: BridgeExecutionResult(status="FAILED", error="must not run"),
        signer=_canonical_modulus_signer(),
    )
    status_code, body = bridge.handle_http_request(
        method="POST",
        path="/internal/live-verifications",
        headers=_sign_headers(payload, secret="bridge-secret"),
        raw_body=json_bytes(payload),
    )
    assert status_code == 400
    assert body["status"] == "INVALID_DEADLINE"


def test_bridge_replay_of_accepted_request_never_reexecutes() -> None:
    receipt = _build_synthetic_live_receipt()
    payload = _make_request_payload(receipt.source_commit_id)
    calls = {"n": 0}

    def executor(_: Any) -> BridgeExecutionResult:
        calls["n"] += 1
        return BridgeExecutionResult(status="FAILED", error="deterministic terminal failure")

    bridge = TrustedVerifierBridge(
        config=_bridge_config(receipt.source_commit_id),
        executor=executor,
        signer=_canonical_modulus_signer(),
    )
    first = bridge.handle_http_request(
        method="POST",
        path="/internal/live-verifications",
        headers=_sign_headers(payload, secret="bridge-secret"),
        raw_body=json_bytes(payload),
    )
    second = bridge.handle_http_request(
        method="POST",
        path="/internal/live-verifications",
        headers=_sign_headers(payload, secret="bridge-secret"),
        raw_body=json_bytes(payload),
    )
    assert first[0] == 503
    assert second[0] == 200
    assert second[1].get("replayed") is True
    assert calls["n"] == 1


def test_bridge_unknown_outcome_is_not_auto_retried() -> None:
    receipt = _build_synthetic_live_receipt()
    payload = _make_request_payload(receipt.source_commit_id)
    calls = {"n": 0}

    def executor(_: Any) -> BridgeExecutionResult:
        calls["n"] += 1
        return BridgeExecutionResult(
            status="UNKNOWN_OUTCOME",
            error="ambiguous dispatch",
            ambiguous_outcome=True,
        )

    bridge = TrustedVerifierBridge(
        config=_bridge_config(receipt.source_commit_id),
        executor=executor,
        signer=_canonical_modulus_signer(),
    )
    first = bridge.handle_http_request(
        method="POST",
        path="/internal/live-verifications",
        headers=_sign_headers(payload, secret="bridge-secret"),
        raw_body=json_bytes(payload),
    )
    second = bridge.handle_http_request(
        method="POST",
        path="/internal/live-verifications",
        headers=_sign_headers(payload, secret="bridge-secret"),
        raw_body=json_bytes(payload),
    )
    assert first[0] == 502
    assert first[1]["status"] == "UNKNOWN_OUTCOME"
    assert first[1]["ambiguous_outcome"] is True
    assert second[0] == 502
    assert second[1]["status"] == "UNKNOWN_OUTCOME"
    assert calls["n"] == 1


def test_idempotency_store_blocks_simultaneous_duplicate_claims() -> None:
    with tempfile.TemporaryDirectory() as state_dir:
        store = ExecutionIdempotencyStore(state_dir)
        assert store.begin("dup-request").get("state") == "NEW"
        # A second claim while the first is in progress (interrupted execution)
        # must NOT be granted permission to execute.
        assert store.begin("dup-request").get("state") == "IN_PROGRESS"
        store.complete("dup-request", {"ok": True, "status": "COMPLETED"})
        completed = store.begin("dup-request")
        assert completed.get("state") == "COMPLETED"
        assert completed.get("response") == {"ok": True, "status": "COMPLETED"}


def test_idempotency_store_marks_ambiguous_and_blocks_retry() -> None:
    with tempfile.TemporaryDirectory() as state_dir:
        store = ExecutionIdempotencyStore(state_dir)
        assert store.begin("amb-request").get("state") == "NEW"
        store.mark_ambiguous("amb-request")
        assert store.begin("amb-request").get("state") == "AMBIGUOUS"


def test_bridge_fails_closed_when_durable_store_unavailable() -> None:
    receipt = _build_synthetic_live_receipt()
    payload = _make_request_payload(receipt.source_commit_id)
    handle, blocked_path = tempfile.mkstemp(prefix="basebreak_not_a_dir_")
    os.close(handle)
    try:
        bridge = TrustedVerifierBridge(
            config=_bridge_config(receipt.source_commit_id, bridge_state_dir=blocked_path),
            executor=lambda _: BridgeExecutionResult(status="FAILED", error="must not run"),
            signer=_canonical_modulus_signer(),
        )
        assert bridge.idempotency_store is None
        status_code, body = bridge.handle_http_request(
            method="POST",
            path="/internal/live-verifications",
            headers=_sign_headers(payload, secret="bridge-secret"),
            raw_body=json_bytes(payload),
        )
        assert status_code == 503
        assert body["status"] == "BLOCKED_DURABLE_IDEMPOTENCY_UNAVAILABLE"
    finally:
        os.unlink(blocked_path)


def test_bridge_rejects_incompatible_signing_authority() -> None:
    receipt = _build_synthetic_live_receipt()
    payload = _make_request_payload(receipt.source_commit_id)
    wrong_signer, _ = _PrivilegedVerifierSigner.create_ephemeral_pair()
    calls = {"n": 0}

    def executor(_: Any) -> BridgeExecutionResult:
        calls["n"] += 1
        return BridgeExecutionResult(status="FAILED", error="must not run")

    bridge = TrustedVerifierBridge(
        config=_bridge_config(receipt.source_commit_id),
        executor=executor,
        signer=wrong_signer,
    )
    status_code, body = bridge.handle_http_request(
        method="POST",
        path="/internal/live-verifications",
        headers=_sign_headers(payload, secret="bridge-secret"),
        raw_body=json_bytes(payload),
    )
    assert status_code == 503
    assert body["status"] == "BLOCKED_INCOMPATIBLE_SIGNING_AUTHORITY"
    assert calls["n"] == 0


def test_executor_reports_unknown_cost_not_the_estimate() -> None:
    """DEFECT B: the executor must not substitute the grant cap for observed cost."""
    signer, authority = _PrivilegedVerifierSigner.create_ephemeral_pair()
    source_commit_id = _git_head_commit()
    payload = _make_request_payload(source_commit_id)
    request = BridgeRequest.from_dict(payload)
    sandbox_adapter = _FakeSandboxAdapter()
    worker = _FakeWorker(
        sandbox_adapter=sandbox_adapter,
        receipt=_make_live_local_receipt(source_commit_id=source_commit_id, signer=signer),
    )
    executor = create_live_nebius_bridge_executor(
        config=TrustedBridgeConfig(
            expected_source_commit=source_commit_id,
            nebius_api_key="configured",
            nebius_project_id="project-123",
        ),
        signer=signer,
        verifier_authority=authority,
        model_client=_FakeModelClient(payload),
        sandbox_adapter=sandbox_adapter,
        verifier_worker=worker,
    )
    result = executor(request)
    assert result.observed_cost_usd is None
    assert result.cost_provenance == "UNKNOWN"
    assert result.approved_estimate_usd == payload["max_estimated_cost_usd"]
    assert result.reserved_exposure_usd == payload["max_estimated_cost_usd"]
    assert result.observed_cost_usd != result.approved_estimate_usd


def test_durable_idempotency_store_rejects_unwritable_path() -> None:
    import pytest

    handle, blocked_path = tempfile.mkstemp(prefix="basebreak_not_a_dir_")
    os.close(handle)
    try:
        with pytest.raises(DurableIdempotencyUnavailableError):
            ExecutionIdempotencyStore(blocked_path)
    finally:
        os.unlink(blocked_path)
