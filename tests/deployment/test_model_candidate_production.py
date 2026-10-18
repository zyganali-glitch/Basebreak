"""Offline adversarial tests for genuine model-generated candidate production (P-27.06).

All model/sandbox dependencies are controlled fakes. No provider call is made.
"""

from __future__ import annotations

import dataclasses
import hashlib
import json
import subprocess
import time
from pathlib import Path
from types import SimpleNamespace
from typing import Any

import pytest

import basebreak.deployment.live_bridge as live_bridge
from basebreak.deployment.live_bridge import (
    BridgeRequest,
    BridgeValidationError,
    TrustedBridgeConfig,
    _load_canonical_live_bridge_scenario,
    _reset_vault_candidate_base_files,
    create_live_nebius_bridge_executor,
)
from basebreak.deployment.model_candidate import (
    MODEL_GENERATED_CANDIDATE_ORIGIN,
    ModelCandidateError,
    ModelCandidateIdentityMismatchError,
    ModelCandidateRejectedError,
    assert_candidate_identity,
    build_candidate_generation_messages,
    candidate_generation_identities,
    generate_model_candidate,
    verify_candidate_generation_binding,
)

_REPO_ROOT = Path(__file__).resolve().parents[2]
_VAULT_REL = "tests/fixtures/reset_vault/src/reset_vault/vault.py"
_HEAD = subprocess.run(
    ["git", "-C", str(_REPO_ROOT), "rev-parse", "HEAD"],
    capture_output=True,
    text=True,
    check=True,
).stdout.strip()


class _ScriptedModel:
    """Deterministic fake model client returning a scripted content per call."""

    def __init__(self, responses: list[str]) -> None:
        self._responses = list(responses)
        self.calls = 0

    def complete(
        self,
        _messages: list[Any],
        *,
        max_tokens: int | None = None,
        temperature: float | None = None,
    ) -> Any:
        del max_tokens, temperature
        idx = min(self.calls, len(self._responses) - 1)
        content = self._responses[idx]
        self.calls += 1
        return SimpleNamespace(
            content=content,
            usage=SimpleNamespace(prompt_tokens=8, completion_tokens=4, total_tokens=12),
            returned_model="nebius/fake-model",
            request_id="model-req-fake",
            duration_seconds=0.1,
        )


def _proposal_json(path: str, content: str, action: str = "MODIFY") -> str:
    return json.dumps(
        {
            "plan": {"summary": "s", "reasoning": "r", "steps": ["x"]},
            "proposed_file_actions": [
                {"action": action, "path": path, "content": content, "rationale": "fix"}
            ],
            "proposed_commands": [],
        }
    )


def _gen(client: _ScriptedModel, *, base_files: dict[str, str], allowed: list[str]) -> Any:
    return generate_model_candidate(
        model_client=client,
        task_id="TASK-RESET-VAULT-001",
        requirement_statement="single-use tokens",
        frozen_contract_digest="0" * 64,
        target="tests/fixtures/reset_vault",
        allowed_paths=allowed,
        base_files=base_files,
    )


# --- module: positive ---------------------------------------------------------------


def test_valid_proposal_binds_to_actual_generated_content() -> None:
    base = {"src/x.py": "print(1)\n"}
    client = _ScriptedModel([_proposal_json("src/x.py", "print(2)\n")])
    candidate = _gen(client, base_files=base, allowed=["src/x.py"])
    assert candidate.origin == MODEL_GENERATED_CANDIDATE_ORIGIN
    assert candidate.files_mapping() == {"src/x.py": "print(2)\n"}
    assert candidate.patch_digest == hashlib.sha256(candidate.patch_text.encode()).hexdigest()
    assert "print(2)" in candidate.patch_text
    assert candidate.candidate_id.startswith("cand-model-")
    assert client.calls == 1


# --- module: fail-closed negatives --------------------------------------------------


def test_empty_response_fails_closed() -> None:
    with pytest.raises(ModelCandidateRejectedError):
        _gen(_ScriptedModel([""]), base_files={"src/x.py": "a\n"}, allowed=["src/x.py"])


def test_malformed_response_fails_closed() -> None:
    with pytest.raises(ModelCandidateRejectedError):
        _gen(
            _ScriptedModel(["not json at all"]),
            base_files={"src/x.py": "a\n"},
            allowed=["src/x.py"],
        )


def test_no_change_fails_closed() -> None:
    base = {"src/x.py": "print(1)\n"}
    with pytest.raises(ModelCandidateRejectedError):
        _gen(
            _ScriptedModel([_proposal_json("src/x.py", "print(1)\n")]),
            base_files=base,
            allowed=["src/x.py"],
        )


def test_unauthorized_path_fails_closed() -> None:
    with pytest.raises(ModelCandidateRejectedError):
        _gen(
            _ScriptedModel([_proposal_json("src/evil.py", "x\n")]),
            base_files={"src/x.py": "a\n"},
            allowed=["src/x.py"],
        )


def test_empty_content_fails_closed() -> None:
    with pytest.raises(ModelCandidateRejectedError):
        _gen(
            _ScriptedModel([_proposal_json("src/x.py", "   ")]),
            base_files={"src/x.py": "a\n"},
            allowed=["src/x.py"],
        )


def test_create_existing_file_fails_closed() -> None:
    with pytest.raises(ModelCandidateRejectedError):
        _gen(
            _ScriptedModel([_proposal_json("src/x.py", "new\n", action="CREATE")]),
            base_files={"src/x.py": "a\n"},
            allowed=["src/x.py"],
        )


def test_identity_mismatch_is_detected() -> None:
    candidate = _gen(
        _ScriptedModel([_proposal_json("src/x.py", "print(2)\n")]),
        base_files={"src/x.py": "print(1)\n"},
        allowed=["src/x.py"],
    )
    with pytest.raises(ModelCandidateIdentityMismatchError):
        assert_candidate_identity(candidate, patch_digest="0" * 64, patch_text=candidate.patch_text)


def test_witness_material_is_blocked_in_builder_context() -> None:
    with pytest.raises(ModelCandidateRejectedError):
        build_candidate_generation_messages(
            task_id="T",
            requirement_statement="R",
            frozen_contract_digest="0" * 64,
            target="t",
            base_files={"src/x.py": "# sealed witness material here\n"},
        )


def test_generation_prompt_contains_no_sealed_witness() -> None:
    messages = build_candidate_generation_messages(
        task_id="T",
        requirement_statement="R",
        frozen_contract_digest="0" * 64,
        target="t",
        base_files={"src/x.py": "print(1)\n"},
    )
    blob = " ".join(m["content"] for m in messages)
    assert "sealed" not in blob.lower()
    assert "witness" not in blob.lower()


# --- executor: honest fixture path and grounded fail-closed path --------------------


def _scenario_and_request() -> tuple[Any, BridgeRequest]:
    scenario = _load_canonical_live_bridge_scenario()
    now = int(time.time() * 1000)
    payload = {
        "schema_version": "1.0.0",
        "request_id": "run-model-candidate",
        "issued_at_ms": now,
        "deadline_ms": now + 60_000,
        "receipt_audience": "cloudflare-worker",
        "task_id": scenario.task_id,
        "change_class": scenario.change_class,
        "target": scenario.target,
        "source_commit_id": _HEAD,
        "frozen_contract_digest": scenario.frozen_contract_digest,
        "max_estimated_cost_usd": 0.25,
    }
    return scenario, BridgeRequest.from_dict(payload)


def _identity_content(payload: dict[str, Any]) -> str:
    return (
        "LIVE_ATTESTATION "
        f"request_id={payload['request_id']} "
        f"source_commit_id={payload['source_commit_id']} "
        f"contract_digest={payload['frozen_contract_digest']}"
    )


class _FakeSandboxAdapter:
    @property
    def live_operation_ids(self) -> tuple[str, ...]:
        return ()


def test_grounded_generation_failure_blocks_and_never_falls_back(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    scenario, request = _scenario_and_request()
    monkeypatch.setattr(live_bridge, "_assess_production_grounding", lambda **_: (True, None))

    payload = request.to_dict()
    client = _ScriptedModel([_identity_content(payload)])  # identity probe, never a proposal

    class _WorkerMustNotRun:
        def execute_causal_triplet(self, **_: Any) -> Any:
            raise AssertionError("candidate generation failure must not reach execution")

    executor = create_live_nebius_bridge_executor(
        config=TrustedBridgeConfig(
            expected_source_commit=_HEAD, nebius_api_key="k", nebius_project_id="p"
        ),
        model_client=client,
        sandbox_adapter=_FakeSandboxAdapter(),
        verifier_worker=_WorkerMustNotRun(),
    )
    result = executor(request)
    assert result.status == "BLOCKED_CANDIDATE_GENERATION_FAILED"
    assert result.receipt is None
    assert result.candidate_patch_digest is None
    assert result.candidate_generation is None
    # A failed second call must not erase the exposure of the successful first call.
    assert result.reserved_exposure_usd == 0.25
    assert result.observed_cost_usd is None
    assert result.cost_provenance == "UNKNOWN"
    assert result.tokens_used == 12
    assert result.candidate_origin != MODEL_GENERATED_CANDIDATE_ORIGIN
    assert scenario.candidate_patch_digest not in (result.candidate_patch_digest or "")


def test_grounded_valid_generation_binds_model_candidate(monkeypatch: pytest.MonkeyPatch) -> None:
    scenario, request = _scenario_and_request()
    payload = request.to_dict()
    vault_content = (_REPO_ROOT / _VAULT_REL).read_text(encoding="utf-8")
    proposal = _proposal_json(_VAULT_REL, vault_content + "\n# candidate-from-model\n")

    monkeypatch.setattr(live_bridge, "_assess_production_grounding", lambda **_: (True, None))
    monkeypatch.setattr(live_bridge, "_compute_candidate_tree_digest", lambda **_: "c" * 40)
    captured: dict[str, Any] = {}

    def _fake_build(**kwargs: Any) -> Any:
        captured.update(kwargs)
        return object()

    monkeypatch.setattr(live_bridge, "_build_public_receipt_from_local_receipt", _fake_build)
    client = _ScriptedModel([_identity_content(payload), proposal])

    class _Worker:
        def execute_causal_triplet(self, **_: Any) -> Any:
            return SimpleNamespace()

    executor = create_live_nebius_bridge_executor(
        config=TrustedBridgeConfig(
            expected_source_commit=_HEAD, nebius_api_key="k", nebius_project_id="p"
        ),
        model_client=client,
        sandbox_adapter=_FakeSandboxAdapter(),
        verifier_worker=_Worker(),
    )
    result = executor(request)
    assert result.status == "COMPLETED"
    assert result.candidate_origin == MODEL_GENERATED_CANDIDATE_ORIGIN
    assert result.candidate_generation is not None
    assert result.candidate_generation.provider_request_id == "model-req-fake"
    assert captured["candidate_origin"] == MODEL_GENERATED_CANDIDATE_ORIGIN
    assert captured["candidate_patch_digest"] == result.candidate_patch_digest
    # Bound to genuine model output, never the deterministic fixture digest.
    assert result.candidate_patch_digest != scenario.candidate_patch_digest
    # Both model calls are accounted for (identity probe + candidate generation).
    assert captured["model_call_count"] == 2
    assert captured["model_prompt_tokens"] == 16
    assert captured["model_completion_tokens"] == 8
    assert captured["model_usage_complete"] is True
    assert result.tokens_used == 24
    # Candidate-generation provenance is bound into the receipt identities.
    identity_blob = " ".join(captured["candidate_generation_identities"])
    assert f"response-sha256:{result.candidate_generation.response_digest}" in identity_blob
    assert "candidate-generation:request:model-req-fake" in identity_blob


# --- provenance binding and source attestation --------------------------------------


def _valid_candidate() -> Any:
    return _gen(
        _ScriptedModel([_proposal_json("src/x.py", "print(2)\n")]),
        base_files={"src/x.py": "print(1)\n"},
        allowed=["src/x.py"],
    )


def test_modified_response_is_rejected() -> None:
    candidate = _valid_candidate()
    tampered = dataclasses.replace(candidate, response_text=candidate.response_text + "x")
    with pytest.raises(ModelCandidateIdentityMismatchError):
        verify_candidate_generation_binding(
            tampered, receipt_runtime_identities=candidate_generation_identities(candidate)
        )


def test_modified_proposal_is_rejected() -> None:
    candidate = _valid_candidate()
    tampered = dataclasses.replace(candidate, proposal_digest="0" * 64)
    with pytest.raises(ModelCandidateIdentityMismatchError):
        verify_candidate_generation_binding(
            tampered, receipt_runtime_identities=candidate_generation_identities(candidate)
        )


def test_modified_patch_is_rejected() -> None:
    candidate = _valid_candidate()
    tampered = dataclasses.replace(candidate, patch_text=candidate.patch_text + "\n")
    with pytest.raises(ModelCandidateIdentityMismatchError):
        verify_candidate_generation_binding(
            tampered, receipt_runtime_identities=candidate_generation_identities(candidate)
        )


def test_origin_label_alone_is_not_sufficient() -> None:
    candidate = _valid_candidate()
    relabeled = dataclasses.replace(candidate, origin="ARBITRARY_ORIGIN_LABEL")
    with pytest.raises(ModelCandidateError):
        verify_candidate_generation_binding(
            relabeled, receipt_runtime_identities=candidate_generation_identities(candidate)
        )


def test_identity_probe_metadata_cannot_masquerade_as_generation_evidence() -> None:
    candidate = _valid_candidate()
    probe_only = (
        f"model-request:{candidate.provider_request_id}",
        f"model:{candidate.returned_model}",
        "candidate-origin:" + MODEL_GENERATED_CANDIDATE_ORIGIN,
    )
    with pytest.raises(ModelCandidateError):
        verify_candidate_generation_binding(candidate, receipt_runtime_identities=probe_only)


def test_source_content_is_bound_to_commit() -> None:
    allowed, files = _reset_vault_candidate_base_files(_REPO_ROOT, _HEAD)
    assert allowed == (_VAULT_REL,)
    assert set(files) == {_VAULT_REL}
    with pytest.raises(BridgeValidationError):
        _reset_vault_candidate_base_files(_REPO_ROOT, "0" * 40)
