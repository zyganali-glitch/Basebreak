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
    # Accounting reflects all 3 attempted calls
    assert exc.generation_prompt_tokens == 300
    assert exc.generation_completion_tokens == 150
    assert exc.generation_total_tokens == 450
    assert exc.provider_request_id == "chatcmpl-test-3"
