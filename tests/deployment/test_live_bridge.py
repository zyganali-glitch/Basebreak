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


def _pinned_modulus_incompatible_signer() -> _PrivilegedVerifierSigner:
    """Signer with the correct pinned public modulus/exponent but a WRONG private exponent.

    It structurally matches the pinned public authority but cannot produce a valid
    signature. Used to prove the signer-compatibility gate validates the actual
    signing operation rather than only public parameters, and can never produce a
    valid proof.
    """
    return _PrivilegedVerifierSigner(private_key_d=1)


def _ephemeral_signer_and_authority() -> tuple[_PrivilegedVerifierSigner, tuple[int, int]]:
    """Ephemeral fixture signer plus its matching (non-production) authority tuple."""
    signer, authority = _PrivilegedVerifierSigner.create_ephemeral_pair()
    return signer, (authority.modulus, authority.exponent)


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
    bridge = TrustedVerifierBridge(
        config=TrustedBridgeConfig(
            shared_secret="bridge-secret",
            expected_source_commit=receipt.source_commit_id,
            live_execution_enabled=True,
        ),
        signer=_ephemeral_signer_and_authority()[0],
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
    bridge = _fixture_bridge(receipt.source_commit_id)

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
    bridge = _fixture_bridge(receipt.source_commit_id)

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

    def executor(_: Any) -> BridgeExecutionResult:
        return BridgeExecutionResult(
            status="FAILED",
            error="Sandbox provisioned but no authoritative witness receipt was produced.",
            provider_operation_ids=("op-sbx-only",),
        )

    bridge = _fixture_bridge(receipt.source_commit_id, executor=executor)

    status_code, body = bridge.handle_http_request(
        method="POST",
        path="/internal/live-verifications",
        headers=_sign_headers(payload, secret="bridge-secret"),
        raw_body=json_bytes(payload),
    )

    assert status_code == 503
    assert body["status"] == "FAILED"
    # The executor may have started chargeable sandbox/provider work even though it
    # failed deterministically, so the response must not claim zero dispatch.
    assert body["provider_dispatched"] is True


def test_bridge_signals_provider_dispatched_for_generation_failure() -> None:
    receipt = _build_synthetic_live_receipt()
    payload = _make_request_payload(receipt.source_commit_id)

    def executor(_: Any) -> BridgeExecutionResult:
        return BridgeExecutionResult(
            status="BLOCKED_CANDIDATE_GENERATION_FAILED",
            error="candidate generation provider failure after dispatch",
            model_call_count=2,
            model_usage_complete=False,
        )

    bridge = _fixture_bridge(receipt.source_commit_id, executor=executor)

    status_code, body = bridge.handle_http_request(
        method="POST",
        path="/internal/live-verifications",
        headers=_sign_headers(payload, secret="bridge-secret"),
        raw_body=json_bytes(payload),
    )

    assert status_code == 503
    assert body["status"] == "BLOCKED_CANDIDATE_GENERATION_FAILED"
    # A dispatched generation call may have incurred unknown cost; the response must
    # not claim zero provider dispatch, and there is no receipt.
    assert body["provider_dispatched"] is True
    assert body["ambiguous_outcome"] is False


def test_bridge_preserves_ambiguous_provider_failure() -> None:
    receipt = _build_synthetic_live_receipt()
    payload = _make_request_payload(receipt.source_commit_id)

    def executor(_: Any) -> BridgeExecutionResult:
        return BridgeExecutionResult(
            status="UNKNOWN_OUTCOME",
            error="Bridge network failure after remote dispatch; outcome is ambiguous.",
            ambiguous_outcome=True,
            provider_operation_ids=("op-ambiguous-1",),
        )

    bridge = _fixture_bridge(receipt.source_commit_id, executor=executor)

    status_code, body = bridge.handle_http_request(
        method="POST",
        path="/internal/live-verifications",
        headers=_sign_headers(payload, secret="bridge-secret"),
        raw_body=json_bytes(payload),
    )

    assert status_code == 502
    assert body["status"] == "UNKNOWN_OUTCOME"
    assert body["ambiguous_outcome"] is True
    assert body["provider_dispatched"] is True


def test_bridge_rejects_executor_reported_live_receipt_without_independent_authority() -> None:
    receipt = _build_synthetic_live_receipt()
    payload = _make_request_payload(receipt.source_commit_id)

    def executor(_: Any) -> BridgeExecutionResult:
        return BridgeExecutionResult(
            status="COMPLETED",
            receipt=receipt,
            observed_cost_usd=0.042,
            tokens_used=321,
            provider_operation_ids=("op-live-1", "op-live-2"),
        )

    bridge = _fixture_bridge(receipt.source_commit_id, executor=executor)

    status_code, body = bridge.handle_http_request(
        method="POST",
        path="/internal/live-verifications",
        headers=_sign_headers(payload, secret="bridge-secret"),
        raw_body=json_bytes(payload),
    )

    assert status_code == 503
    assert body["status"] == "NOT_READY_FOR_DEPLOYMENT"
    assert "Independent live execution authority is not configured" in body["error"]
    assert body["provider_dispatched"] is True


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
    assert result.candidate_origin == "DETERMINISTIC_BRIDGE_FIXTURE"
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


def _fixture_bridge(
    source_commit_id: str,
    *,
    executor: Any | None = None,
    bridge_state_dir: str | None = None,
    allow_ephemeral_test_state: bool | None = None,
    execution_authority_verifier: Any | None = None,
) -> TrustedVerifierBridge:
    """Build a bridge that passes the cryptographic signer gate using an ephemeral keypair.

    The ephemeral authority is injected so the real signer-compatibility proof is
    still exercised without real production key material. Ephemeral idempotency
    state is used only when no durable directory is supplied and the caller does
    not override the flag.
    """
    signer, authority = _ephemeral_signer_and_authority()
    if allow_ephemeral_test_state is None:
        allow_ephemeral_test_state = bridge_state_dir is None
    return TrustedVerifierBridge(
        config=_bridge_config(source_commit_id, bridge_state_dir=bridge_state_dir),
        executor=executor,
        signer=signer,
        signer_authority=authority,
        allow_ephemeral_test_state=allow_ephemeral_test_state,
        execution_authority_verifier=execution_authority_verifier,
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

    bridge = _fixture_bridge(receipt.source_commit_id, executor=executor)
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

    bridge = _fixture_bridge(
        receipt.source_commit_id,
        executor=lambda _: BridgeExecutionResult(status="FAILED", error="must not run"),
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

    bridge = _fixture_bridge(receipt.source_commit_id, executor=executor)
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

    bridge = _fixture_bridge(receipt.source_commit_id, executor=executor)
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
        bridge = _fixture_bridge(
            receipt.source_commit_id,
            executor=lambda _: BridgeExecutionResult(status="FAILED", error="must not run"),
            bridge_state_dir=blocked_path,
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


def test_bridge_rejects_matching_public_params_incompatible_private_exponent() -> None:
    """DEFECT B: correct public modulus/exponent but a wrong private exponent must fail.

    The signer structurally matches the pinned authority, so a public-parameter-only
    check would accept it and allow real provider spending before the Worker rejects
    the resulting signature. The cryptographic signer-compatibility proof must catch it.
    """
    from basebreak.deployment.live_bridge import _signer_matches_canonical_authority

    receipt = _build_synthetic_live_receipt()
    payload = _make_request_payload(receipt.source_commit_id)
    bad_signer = _pinned_modulus_incompatible_signer()
    # Public parameters alone are identical to the pinned authority.
    assert bad_signer.modulus == _PrivilegedVerifierSigner(private_key_d=1).modulus
    # But the actual signing operation is incompatible.
    assert _signer_matches_canonical_authority(bad_signer) is False
    calls = {"n": 0}

    def executor(_: Any) -> BridgeExecutionResult:
        calls["n"] += 1
        return BridgeExecutionResult(status="FAILED", error="must not run")

    bridge = TrustedVerifierBridge(
        config=_bridge_config(receipt.source_commit_id),
        executor=executor,
        signer=bad_signer,
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


# --- DEFECT A: durable idempotency never silently substitutes ephemeral storage ---


def test_production_bridge_fails_closed_without_explicit_durable_state_dir() -> None:
    """A production-shaped bridge with no configured durable state dir must fail closed.

    Ephemeral tempfile storage must never silently stand in for production
    idempotency, so the request is blocked before any chargeable execution.
    """
    receipt = _build_synthetic_live_receipt()
    payload = _make_request_payload(receipt.source_commit_id)
    calls = {"n": 0}

    def executor(_: Any) -> BridgeExecutionResult:
        calls["n"] += 1
        return BridgeExecutionResult(status="FAILED", error="must not run")

    bridge = _fixture_bridge(
        receipt.source_commit_id,
        executor=executor,
        allow_ephemeral_test_state=False,
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
    assert calls["n"] == 0


def test_durable_state_shared_across_restarted_bridge_instances_blocks_replay() -> None:
    """Two independent bridge instances sharing durable state must reject replay."""
    receipt = _build_synthetic_live_receipt()
    payload = _make_request_payload(receipt.source_commit_id)
    calls = {"n": 0}

    def executor(_: Any) -> BridgeExecutionResult:
        calls["n"] += 1
        return BridgeExecutionResult(status="FAILED", error="deterministic terminal failure")

    with tempfile.TemporaryDirectory() as state_dir:
        first_bridge = _fixture_bridge(
            receipt.source_commit_id, executor=executor, bridge_state_dir=state_dir
        )
        first = first_bridge.handle_http_request(
            method="POST",
            path="/internal/live-verifications",
            headers=_sign_headers(payload, secret="bridge-secret"),
            raw_body=json_bytes(payload),
        )
        assert first[0] == 503
        assert calls["n"] == 1

        # Simulate a bridge process restart: a brand new instance on the same
        # persistent state directory.
        restarted_bridge = _fixture_bridge(
            receipt.source_commit_id, executor=executor, bridge_state_dir=state_dir
        )
        replay = restarted_bridge.handle_http_request(
            method="POST",
            path="/internal/live-verifications",
            headers=_sign_headers(payload, secret="bridge-secret"),
            raw_body=json_bytes(payload),
        )
        assert replay[0] == 200
        assert replay[1].get("replayed") is True
        # The restarted process must NOT trigger a second chargeable execution.
        assert calls["n"] == 1


def test_durable_state_rejects_interrupted_write_and_cross_instance_concurrency() -> None:
    """An interrupted claim must not be retried; concurrent claims admit exactly one."""
    with tempfile.TemporaryDirectory() as state_dir:
        first_process = ExecutionIdempotencyStore(state_dir)
        second_process = ExecutionIdempotencyStore(state_dir)

        assert first_process.begin("interrupted-request").get("state") == "NEW"
        # No terminal record was written (interrupted). A restarted process must
        # observe IN_PROGRESS and refuse to execute.
        assert second_process.begin("interrupted-request").get("state") == "IN_PROGRESS"

        assert first_process.begin("concurrent-request").get("state") == "NEW"
        assert second_process.begin("concurrent-request").get("state") == "IN_PROGRESS"


def test_bridge_rejects_replay_of_interrupted_claim_after_restart() -> None:
    """A pre-existing interrupted claim causes the bridge to refuse re-execution."""
    receipt = _build_synthetic_live_receipt()
    payload = _make_request_payload(receipt.source_commit_id)
    calls = {"n": 0}

    def executor(_: Any) -> BridgeExecutionResult:
        calls["n"] += 1
        return BridgeExecutionResult(status="FAILED", error="must not run")

    with tempfile.TemporaryDirectory() as state_dir:
        # Simulate a prior attempt that claimed the request_id then crashed.
        ExecutionIdempotencyStore(state_dir).begin(payload["request_id"])
        bridge = _fixture_bridge(
            receipt.source_commit_id, executor=executor, bridge_state_dir=state_dir
        )
        status_code, body = bridge.handle_http_request(
            method="POST",
            path="/internal/live-verifications",
            headers=_sign_headers(payload, secret="bridge-secret"),
            raw_body=json_bytes(payload),
        )
        assert status_code == 409
        assert body["status"] == "CONCURRENT_DUPLICATE_REQUEST"
        assert body["ambiguous_outcome"] is True
        assert calls["n"] == 0


# --- DEFECT D: canonical provider identity + transport must be positively verified ---


def _canonical_fixture_grounding_components() -> tuple[Any, Any, Any, Any, Any, Any]:
    from basebreak.adapters.nebius import (
        ModelClientConfig,
        NebiusModelClient,
        NebiusSandboxAdapter,
        SandboxClientConfig,
    )
    from basebreak.causal.materializer import CausalRepositoryMaterializer
    from basebreak.verifier.trust_bridge import TrustedVerifierWorker

    signer, authority = _PrivilegedVerifierSigner.create_ephemeral_pair()
    sandbox_adapter = NebiusSandboxAdapter(
        config=SandboxClientConfig(api_key="configured-key", project_id="project-123")
    )
    model_client = NebiusModelClient(
        config=ModelClientConfig(api_key="configured-key", project_id="project-123")
    )
    materializer = CausalRepositoryMaterializer(adapter=sandbox_adapter)
    worker = TrustedVerifierWorker(signer=signer)
    return signer, authority, model_client, sandbox_adapter, materializer, worker


def test_production_grounding_accepts_canonical_components_under_fixture_authority() -> None:
    from basebreak.deployment.live_bridge import _assess_production_grounding

    signer, authority, model_client, sandbox_adapter, materializer, worker = (
        _canonical_fixture_grounding_components()
    )
    grounded, error = _assess_production_grounding(
        signer=signer,
        model_client=model_client,
        sandbox_adapter=sandbox_adapter,
        materializer=materializer,
        worker=worker,
        signer_authority=(authority.modulus, authority.exponent),
    )
    assert grounded is True
    assert error is None


def test_production_grounding_rejects_non_canonical_model_transport() -> None:
    from basebreak.adapters.nebius import (
        ModelClientConfig,
        NebiusModelClient,
        TransportResponse,
    )
    from basebreak.deployment.live_bridge import _assess_production_grounding

    signer, authority, _model_client, sandbox_adapter, materializer, worker = (
        _canonical_fixture_grounding_components()
    )

    def injected_transport(_request: Any, _timeout: float) -> TransportResponse:
        return TransportResponse(status_code=200, body=b"{}", headers={})

    fake_model_client = NebiusModelClient(
        config=ModelClientConfig(api_key="configured-key", project_id="project-123"),
        transport=injected_transport,
    )
    grounded, error = _assess_production_grounding(
        signer=signer,
        model_client=fake_model_client,
        sandbox_adapter=sandbox_adapter,
        materializer=materializer,
        worker=worker,
        signer_authority=(authority.modulus, authority.exponent),
    )
    assert grounded is False
    assert error is not None
    assert "canonical live Nebius transport" in error


def test_production_grounding_rejects_arbitrary_https_model_endpoint() -> None:
    from basebreak.adapters.nebius import ModelClientConfig, NebiusModelClient
    from basebreak.deployment.live_bridge import _assess_production_grounding

    signer, authority, _model_client, sandbox_adapter, materializer, worker = (
        _canonical_fixture_grounding_components()
    )
    arbitrary_model_client = NebiusModelClient(
        config=ModelClientConfig(
            api_key="configured-key",
            project_id="project-123",
            api_base_url="https://arbitrary.example/v1",
        )
    )
    grounded, error = _assess_production_grounding(
        signer=signer,
        model_client=arbitrary_model_client,
        sandbox_adapter=sandbox_adapter,
        materializer=materializer,
        worker=worker,
        signer_authority=(authority.modulus, authority.exponent),
    )
    assert grounded is False
    assert error is not None
    assert "canonical Nebius Token Factory inference endpoint" in error


def test_production_grounding_rejects_non_canonical_sandbox_endpoint() -> None:
    from basebreak.adapters.nebius import NebiusSandboxAdapter, SandboxClientConfig
    from basebreak.causal.materializer import CausalRepositoryMaterializer
    from basebreak.deployment.live_bridge import _assess_production_grounding

    signer, authority, model_client, _sandbox, _materializer, worker = (
        _canonical_fixture_grounding_components()
    )
    arbitrary_sandbox = NebiusSandboxAdapter(
        config=SandboxClientConfig(
            api_key="configured-key",
            project_id="project-123",
            api_base_url="https://arbitrary.example/sandboxes/v1",
        )
    )
    materializer = CausalRepositoryMaterializer(adapter=arbitrary_sandbox)
    grounded, error = _assess_production_grounding(
        signer=signer,
        model_client=model_client,
        sandbox_adapter=arbitrary_sandbox,
        materializer=materializer,
        worker=worker,
        signer_authority=(authority.modulus, authority.exponent),
    )
    assert grounded is False
    assert error is not None
    assert "canonical Nebius Token Factory sandbox endpoint" in error


def test_production_grounding_rejects_pinned_modulus_signer_with_wrong_private_exponent() -> None:
    from basebreak.deployment.live_bridge import _assess_production_grounding

    _signer, authority, model_client, sandbox_adapter, materializer, worker = (
        _canonical_fixture_grounding_components()
    )
    bad_signer = _pinned_modulus_incompatible_signer()
    grounded, error = _assess_production_grounding(
        signer=bad_signer,
        model_client=model_client,
        sandbox_adapter=sandbox_adapter,
        materializer=materializer,
        worker=worker,
        signer_authority=(authority.modulus, authority.exponent),
    )
    # The injected fixture authority does not match the pinned-modulus signer.
    assert grounded is False
    assert error is not None
