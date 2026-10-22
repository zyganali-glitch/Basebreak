"""Adversarial tests for candidate pre-execution validation and model-guided repair (P-27.06).

Specifically tests reproduction and repair of the Run 8 and Run 9 invalid snippet defect
(IndentationError / missing ResetVault class), verifying that:
1. Bounded pre-execution validation catches the defect immediately before sandbox execution.
2. The model-guided repair cycle issues a targeted public repair turn without
   leaking sealed witness material.
3. Accounting aggregates token usage across all attempts.
4. Independent verification binds to the final authentic model proposal.
"""

from __future__ import annotations

import json
from pathlib import Path
from types import SimpleNamespace
from typing import Any

import pytest

from basebreak.deployment.model_candidate import (
    MODEL_GENERATED_CANDIDATE_ORIGIN,
    ModelCandidateRejectedError,
    candidate_generation_identities,
    generate_model_candidate,
    validate_candidate_preexecution,
    verify_candidate_generation_binding,
)

_REPO_ROOT = Path(__file__).resolve().parents[2]
_VAULT_REL = "tests/fixtures/reset_vault/src/reset_vault/vault.py"
_BASE_VAULT = (_REPO_ROOT / _VAULT_REL).read_text(encoding="utf-8")


def _proposal_json(path: str, content: str, action: str = "MODIFY") -> str:
    return json.dumps(
        {
            "plan": {"summary": "fix", "reasoning": "r", "steps": ["s"]},
            "proposed_file_actions": [
                {"action": action, "path": path, "content": content, "rationale": "fix"}
            ],
            "proposed_commands": [],
        }
    )


class _ScriptedModel:
    def __init__(self, responses: list[Any]) -> None:
        self._responses = list(responses)
        self.calls = 0
        self.recorded_messages: list[list[dict[str, str]]] = []

    def complete(self, messages: list[dict[str, str]], **_: Any) -> Any:
        self.recorded_messages.append(list(messages))
        idx = min(self.calls, len(self._responses) - 1)
        resp = self._responses[idx]
        self.calls += 1
        return SimpleNamespace(
            content=resp,
            usage=SimpleNamespace(prompt_tokens=100, completion_tokens=50, total_tokens=150),
            returned_model="nvidia/Nemotron-3_5-Lightning",
            request_id=f"chatcmpl-test-{self.calls}",
            duration_seconds=0.2,
            finish_reason="stop",
            has_reasoning_content=False,
        )


def test_validate_candidate_preexecution_catches_run8_run9_indentation_defect() -> None:
    # Exact snippet pattern that caused Run 8 and Run 9 collection errors
    broken_snippet = (
        "    def redeem_reset_token(self, token: str, new_password: str) -> bool:\n"
        "        if token not in self._tokens:\n"
        "            return False\n"
        "        del self._tokens[token]\n"
        "        return True\n"
    )
    is_valid, failed_path, error = validate_candidate_preexecution(
        candidate_files={_VAULT_REL: broken_snippet},
        base_files={_VAULT_REL: _BASE_VAULT},
        target="tests/fixtures/reset_vault",
    )
    assert is_valid is False
    assert failed_path == _VAULT_REL
    assert "IndentationError" in (error or "")


def test_validate_candidate_preexecution_catches_missing_reset_vault_class() -> None:
    # Syntactically valid file, but missing class ResetVault
    code_without_class = "from typing import Any\nclass TokenError(Exception):\n    pass\n"
    is_valid, failed_path, error = validate_candidate_preexecution(
        candidate_files={_VAULT_REL: code_without_class},
        base_files={_VAULT_REL: _BASE_VAULT},
        target="tests/fixtures/reset_vault",
    )
    assert is_valid is False
    assert failed_path == _VAULT_REL
    assert "missing required class(es)" in (error or "")
    assert "ResetVault" in (error or "")


def test_validate_candidate_preexecution_passes_valid_full_file() -> None:
    valid_fix = _BASE_VAULT.replace(
        "        # BUT MISSING in baseline!",
        "        del self._tokens[token]",
    )
    is_valid, failed_path, error = validate_candidate_preexecution(
        candidate_files={_VAULT_REL: valid_fix},
        base_files={_VAULT_REL: _BASE_VAULT},
        target="tests/fixtures/reset_vault",
    )
    assert is_valid is True
    assert failed_path is None
    assert error is None


def test_model_guided_repair_cycle_recovers_from_invalid_first_response() -> None:
    # Call 1: model returns invalid indented snippet (simulating Run 8 / Run 9 failure)
    broken_snippet = (
        "    def redeem_reset_token(self, token: str, new_password: str) -> bool:\n"
        "        del self._tokens[token]\n"
        "        return True\n"
    )
    response_1 = _proposal_json(_VAULT_REL, broken_snippet)

    # Call 2: model receives bounded public error feedback and returns the complete valid file
    valid_fix = _BASE_VAULT.replace(
        "        # BUT MISSING in baseline!",
        "        del self._tokens[token]",
    )
    response_2 = _proposal_json(_VAULT_REL, valid_fix)

    client = _ScriptedModel([response_1, response_2])
    candidate = generate_model_candidate(
        model_client=client,
        task_id="TASK-RESET-VAULT-001",
        requirement_statement="single-use reset tokens",
        frozen_contract_digest="0" * 64,
        target="tests/fixtures/reset_vault",
        allowed_paths=[_VAULT_REL],
        base_files={_VAULT_REL: _BASE_VAULT},
        max_candidate_attempts=3,
    )

    # Verifications:
    # 1. Exactly 2 model calls were made (1 initial + 1 repair turn)
    assert client.calls == 2
    assert candidate.model_call_count == 2
    assert candidate.provider_request_id == "chatcmpl-test-2"
    assert len(candidate.provider_request_ids) == 2
    assert candidate.origin == MODEL_GENERATED_CANDIDATE_ORIGIN

    # 2. Cumulative token accounting is preserved across calls
    assert candidate.generation_prompt_tokens == 200
    assert candidate.generation_completion_tokens == 100
    assert candidate.generation_total_tokens == 300
    assert candidate.generation_duration_seconds == pytest.approx(0.4)

    # 3. Check repair turn prompt: contains public failure, never sealed witness material
    repair_turn_messages = client.recorded_messages[1]
    last_user_message = repair_turn_messages[-1]["content"]
    assert "IndentationError" in last_user_message
    assert "MODIFY" in last_user_message
    assert "COMPLETE, FULL" in last_user_message
    assert "file content from line 1 to EOF" in last_user_message
    assert "witness" not in last_user_message.lower()
    assert "sealed" not in last_user_message.lower()

    # 4. Cryptographic and mechanical derivation binding independently verifies
    verify_candidate_generation_binding(
        candidate,
        receipt_runtime_identities=candidate_generation_identities(candidate),
        allowed_paths=[_VAULT_REL],
        authorized_base_files={_VAULT_REL: _BASE_VAULT},
    )


def test_exhausted_repair_attempts_fails_closed_with_retained_accounting() -> None:
    # Model repeatedly returns invalid snippet
    broken_snippet = "    def broken(): pass\n"
    response_invalid = _proposal_json(_VAULT_REL, broken_snippet)

    client = _ScriptedModel([response_invalid, response_invalid, response_invalid])
    with pytest.raises(ModelCandidateRejectedError) as exc_info:
        generate_model_candidate(
            model_client=client,
            task_id="TASK-RESET-VAULT-001",
            requirement_statement="single-use reset tokens",
            frozen_contract_digest="0" * 64,
            target="tests/fixtures/reset_vault",
            allowed_paths=[_VAULT_REL],
            base_files={_VAULT_REL: _BASE_VAULT},
            max_candidate_attempts=3,
        )

    exc = exc_info.value
    assert client.calls == 3
    assert exc.generation_attempted is True
    assert exc.model_call_count == 3
    assert len(exc.provider_request_ids) == 3
    # Accounting reflects all 3 attempted calls
    assert exc.generation_prompt_tokens == 300
    assert exc.generation_completion_tokens == 150
    assert exc.generation_total_tokens == 450
    assert exc.provider_request_id == "chatcmpl-test-3"


# ==============================================================================
# DEFECT A ADVERSARIAL REGRESSION TESTS: Untrusted Code Isolation (Host Defense)
# ==============================================================================


def test_untrusted_candidate_code_top_level_side_effect_never_executes_on_host() -> None:
    """PROVE DEFECT A FIX: Top-level code from model candidate NEVER runs on host."""
    import sys

    probe_attr = "_DEFECT_A_TEST_TOP_LEVEL_SIDE_EFFECT_PROBE"
    if hasattr(sys, probe_attr):
        delattr(sys, probe_attr)

    malicious_code = (
        "import sys\n"
        f"setattr(sys, '{probe_attr}', True)\n"
        "raise RuntimeError('MALICIOUS_TOP_LEVEL_EXECUTED')\n"
    )

    is_valid, failed_path, error = validate_candidate_preexecution(
        candidate_files={_VAULT_REL: malicious_code},
        base_files={_VAULT_REL: _BASE_VAULT},
        target="tests/fixtures/reset_vault",
    )

    # 1. Host process was NOT affected: probe attribute was never set
    assert not hasattr(sys, probe_attr)
    # 2. No unhandled RuntimeError on host; detected statically as missing ResetVault class
    assert is_valid is False
    assert failed_path == _VAULT_REL
    assert "missing required class(es)" in (error or "")


def test_untrusted_candidate_code_class_body_side_effect_never_executes_on_host() -> None:
    """PROVE DEFECT A FIX: Code in candidate class body NEVER executes on host."""
    import sys

    probe_attr = "_DEFECT_A_TEST_CLASS_BODY_SIDE_EFFECT_PROBE"
    if hasattr(sys, probe_attr):
        delattr(sys, probe_attr)

    malicious_class = (
        "import sys\n"
        "class TokenError(Exception):\n"
        "    pass\n"
        "class ResetVault:\n"
        f"    setattr(sys, '{probe_attr}', True)\n"
        "    def __init__(self) -> None: pass\n"
        "    def set_user_password(self, u: str, p: str) -> None: pass\n"
        "    def get_user_password(self, u: str) -> str: return 'p'\n"
        "    def create_reset_token(self, u: str) -> str: return 'tok'\n"
        "    def redeem_reset_token(self, t: str, p: str) -> bool: return True\n"
    )

    is_valid, failed_path, error = validate_candidate_preexecution(
        candidate_files={_VAULT_REL: malicious_class},
        base_files={_VAULT_REL: _BASE_VAULT},
        target="tests/fixtures/reset_vault",
    )

    # Host process was NOT affected: class body was never executed
    assert not hasattr(sys, probe_attr)
    # Syntactically and structurally valid AST
    assert is_valid is True
    assert failed_path is None
    assert error is None


def test_untrusted_candidate_malicious_import_never_imported_on_host() -> None:
    """PROVE DEFECT A FIX: Untrusted imports are never imported into host Python."""
    import sys

    poison_module = "definitely_nonexistent_poison_module_xyz_12345"
    assert poison_module not in sys.modules

    code_with_bad_import = (
        f"import {poison_module}\n"
        "class TokenError(Exception):\n"
        "    pass\n"
        "class ResetVault:\n"
        "    def __init__(self) -> None: pass\n"
        "    def set_user_password(self, u: str, p: str) -> None: pass\n"
        "    def get_user_password(self, u: str) -> str: return 'p'\n"
        "    def create_reset_token(self, u: str) -> str: return 'tok'\n"
        "    def redeem_reset_token(self, t: str, p: str) -> bool: return True\n"
    )

    is_valid, failed_path, error = validate_candidate_preexecution(
        candidate_files={_VAULT_REL: code_with_bad_import},
        base_files={_VAULT_REL: _BASE_VAULT},
        target="tests/fixtures/reset_vault",
    )

    # Poison module was NEVER imported into sys.modules
    assert poison_module not in sys.modules
    assert is_valid is True
    assert error is None


def test_validate_candidate_preexecution_catches_missing_method_statically() -> None:
    """Static AST check detects missing required methods on classes."""
    # ResetVault class exists, but redeem_reset_token is omitted
    code_missing_method = (
        "class TokenError(Exception):\n"
        "    pass\n"
        "class ResetVault:\n"
        "    def __init__(self) -> None: pass\n"
        "    def set_user_password(self, u: str, p: str) -> None: pass\n"
        "    def get_user_password(self, u: str) -> str: return 'p'\n"
        "    def create_reset_token(self, u: str) -> str: return 'tok'\n"
    )
    is_valid, failed_path, error = validate_candidate_preexecution(
        candidate_files={_VAULT_REL: code_missing_method},
        base_files={_VAULT_REL: _BASE_VAULT},
        target="tests/fixtures/reset_vault",
    )
    assert is_valid is False
    assert failed_path == _VAULT_REL
    assert "missing required method(s)" in (error or "")
    assert "redeem_reset_token" in (error or "")


def test_isolated_sandbox_runner_invoked_when_provided() -> None:
    """Behavioral validation delegates to isolated sandbox runner when provided."""
    valid_fix = _BASE_VAULT.replace(
        "        # BUT MISSING in baseline!",
        "        del self._tokens[token]",
    )

    runner_called = False

    def mock_sandbox_runner(files: Any) -> tuple[bool, str | None]:
        nonlocal runner_called
        runner_called = True
        return False, "mock isolated sandbox test failed"

    is_valid, failed_path, error = validate_candidate_preexecution(
        candidate_files={_VAULT_REL: valid_fix},
        base_files={_VAULT_REL: _BASE_VAULT},
        target="tests/fixtures/reset_vault",
        isolated_sandbox_runner=mock_sandbox_runner,
    )

    assert runner_called is True
    assert is_valid is False
    assert "mock isolated sandbox test failed" in (error or "")


# ==============================================================================
# DEFECT B ADVERSARIAL REGRESSION TESTS: Multi-Call Accounting Parity
# ==============================================================================


def test_multi_call_accounting_and_request_ids_preserved_in_bridge(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """PROVE DEFECT B FIX: Bridge preserves model_call_count > 1 and all request IDs."""
    import subprocess
    import time

    from basebreak.deployment import live_bridge
    from basebreak.deployment.live_bridge import (
        BridgeRequest,
        TrustedBridgeConfig,
        _load_canonical_live_bridge_scenario,
        create_live_nebius_bridge_executor,
    )

    head = subprocess.run(
        ["git", "-C", str(_REPO_ROOT), "rev-parse", "HEAD"],
        capture_output=True,
        text=True,
        check=True,
    ).stdout.strip()

    # Call 1: model returns broken snippet
    broken_snippet = "    def redeem_reset_token(): pass\n"
    resp_1 = _proposal_json(_VAULT_REL, broken_snippet)

    # Call 2: model returns valid full file
    valid_fix = _BASE_VAULT.replace(
        "        # BUT MISSING in baseline!",
        "        del self._tokens[token]",
    )
    resp_2 = _proposal_json(_VAULT_REL, valid_fix)

    class MultiCallModel:
        def __init__(self) -> None:
            self.calls = 0

        def complete(self, messages: Any, **_: Any) -> Any:
            self.calls += 1
            content = resp_1 if self.calls == 1 else resp_2
            return SimpleNamespace(
                content=content,
                usage=SimpleNamespace(prompt_tokens=500, completion_tokens=250, total_tokens=750),
                returned_model="nvidia/Nemotron-3_5-Lightning",
                request_id=f"chatcmpl-multicall-{self.calls}",
                duration_seconds=1.5,
                finish_reason="stop",
                has_reasoning_content=False,
            )

    scenario = _load_canonical_live_bridge_scenario()
    now = int(time.time() * 1000)
    payload = {
        "schema_version": "1.0.0",
        "request_id": "run-multicall-test",
        "issued_at_ms": now,
        "deadline_ms": now + 60_000,
        "receipt_audience": "cloudflare-worker",
        "task_id": scenario.task_id,
        "change_class": scenario.change_class,
        "target": scenario.target,
        "source_commit_id": head,
        "frozen_contract_digest": scenario.frozen_contract_digest,
        "max_estimated_cost_usd": 0.25,
    }
    request = BridgeRequest.from_dict(payload)

    monkeypatch.setattr(live_bridge, "_assess_production_grounding", lambda **_: (True, None))
    monkeypatch.setattr(live_bridge, "_compute_candidate_tree_digest", lambda **_: "c" * 40)

    class _FakeSandboxAdapter:
        @property
        def live_operation_ids(self) -> tuple[str, ...]:
            return ()

    class _Worker:
        def execute_causal_triplet(self, **_: Any) -> Any:
            return SimpleNamespace()

    def _fake_build(**kwargs: Any) -> Any:
        identities = tuple(
            [f"model-calls:{kwargs.get('model_call_count', 0)}"]
            + list(kwargs.get("candidate_generation_identities", ()))
        )
        accounting = SimpleNamespace(
            model_call_count=kwargs.get("model_call_count", 0),
            prompt_tokens=kwargs.get("model_prompt_tokens", 0),
            completion_tokens=kwargs.get("model_completion_tokens", 0),
        )
        return SimpleNamespace(
            accounting=accounting,
            runtime_identities=identities,
        )

    monkeypatch.setattr(live_bridge, "_build_public_receipt_from_local_receipt", _fake_build)

    executor = create_live_nebius_bridge_executor(
        config=TrustedBridgeConfig(
            expected_source_commit=head,
            nebius_api_key="k",
            nebius_project_id="p",
        ),
        model_client=MultiCallModel(),
        sandbox_adapter=_FakeSandboxAdapter(),
        verifier_worker=_Worker(),
    )

    result = executor(request)

    # Verify bridge execution result preserved multi-call facts
    assert result.status == "COMPLETED"
    assert result.model_call_count == 2
    assert result.model_prompt_tokens == 1000
    assert result.model_completion_tokens == 500
    assert result.tokens_used == 1500
    assert result.model_usage_complete is True
    assert result.provider_request_id == "chatcmpl-multicall-2"
    assert result.provider_request_ids == ("chatcmpl-multicall-1", "chatcmpl-multicall-2")

    # Verify public receipt reflects model_call_count == 2
    assert result.receipt is not None
    assert result.receipt.accounting is not None
    assert result.receipt.accounting.model_call_count == 2
    assert result.receipt.accounting.prompt_tokens == 1000
    assert result.receipt.accounting.completion_tokens == 500
    assert "model-calls:2" in result.receipt.runtime_identities
    assert "candidate-generation:request:chatcmpl-multicall-1" in result.receipt.runtime_identities
    assert "candidate-generation:request:chatcmpl-multicall-2" in result.receipt.runtime_identities


def test_three_attempt_repair_cycle_accounting() -> None:
    """PROVE DEFECT B FIX: 3 generation attempts aggregate accounting accurately."""
    broken_1 = "    def bad_indent(): pass\n"
    broken_2 = "class ResetVault:\n    def __init__(self) -> None: pass\n"
    valid_3 = _BASE_VAULT.replace(
        "        # BUT MISSING in baseline!",
        "        del self._tokens[token]",
    )

    responses = [
        _proposal_json(_VAULT_REL, broken_1),
        _proposal_json(_VAULT_REL, broken_2),
        _proposal_json(_VAULT_REL, valid_3),
    ]

    client = _ScriptedModel(responses)
    candidate = generate_model_candidate(
        model_client=client,
        task_id="TASK-RESET-VAULT-001",
        requirement_statement="single-use reset tokens",
        frozen_contract_digest="0" * 64,
        target="tests/fixtures/reset_vault",
        allowed_paths=[_VAULT_REL],
        base_files={_VAULT_REL: _BASE_VAULT},
        max_candidate_attempts=3,
    )

    assert client.calls == 3
    assert candidate.model_call_count == 3
    assert candidate.provider_request_id == "chatcmpl-test-3"
    assert candidate.provider_request_ids == (
        "chatcmpl-test-1",
        "chatcmpl-test-2",
        "chatcmpl-test-3",
    )
    assert candidate.generation_prompt_tokens == 300
    assert candidate.generation_completion_tokens == 150
    assert candidate.generation_total_tokens == 450
