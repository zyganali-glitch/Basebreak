"""Tests for P-09.05: Vacuous witness and invalid precondition defenses.

Verifies:
1. Detection of zero meaningful assertions (VACUOUS_NO_ASSERTIONS).
2. Detection of trivial constant assertions (VACUOUS_TRIVIAL_PASS).
3. Detection of empty test runs / 0 tests collected (VACUOUS_SKIPPED_SUITE).
4. Detection of 100% skipped tests masquerading as PASS.
5. Detection of missing modules / import errors (INVALID_PRECONDITION).
6. Non-vacuous witnesses with real assertions are classified as VALID.
7. Provider purity (zero adapter imports in vacuity).
"""

from __future__ import annotations

import ast
import inspect

from basebreak.domain.causal import ExecutionWorld
from basebreak.domain.execution import SandboxIdentity, TerminationStatus
from basebreak.domain.verdict import EvidenceProvenance
from basebreak.verifier.vacuity import (
    VacuityCheckResult,
    VacuityStatus,
    analyze_artifact_code_vacuity,
    analyze_runtime_execution_vacuity,
)
from basebreak.verifier.witness_result import normalize_witness_execution
from basebreak.verifier.witness_store import WitnessArtifact


def test_detect_zero_assertions() -> None:
    art = WitnessArtifact.from_text(
        path="tests/test_empty.py",
        content="def test_empty():\n    pass\n",
    )
    res = analyze_artifact_code_vacuity([art])
    assert res.status == VacuityStatus.VACUOUS_NO_ASSERTIONS
    assert res.is_vacuous is True
    assert res.grants_verification is False


def test_detect_trivial_constant_assertions() -> None:
    art = WitnessArtifact.from_text(
        path="tests/test_trivial.py",
        content="def test_trivial():\n    assert True\n    assert 1 == 1\n",
    )
    res = analyze_artifact_code_vacuity([art])
    assert res.status == VacuityStatus.VACUOUS_TRIVIAL_PASS
    assert res.is_vacuous is True
    assert res.grants_verification is False


def test_valid_meaningful_assertions() -> None:
    content = (
        "from buffer import check_capacity\n"
        "def test_real():\n"
        "    val = check_capacity(10)\n"
        "    assert val is False\n"
    )
    art = WitnessArtifact.from_text(
        path="tests/test_real.py",
        content=content,
    )
    res = analyze_artifact_code_vacuity([art], expected_target_symbols=("check_capacity",))
    assert res.status == VacuityStatus.VALID
    assert res.is_vacuous is False
    assert res.grants_verification is True
    assert "check_capacity" in res.target_symbols_referenced


def test_runtime_detects_0_tests_collected() -> None:
    sbx = SandboxIdentity(sandbox_id="sbx-01")
    code_check = VacuityCheckResult(
        status=VacuityStatus.VALID,
        is_vacuous=False,
        details="Code ok",
        assertion_count=1,
        target_symbols_referenced=(),
    )

    exec_res = normalize_witness_execution(
        witness_id="wit-01",
        witness_digest="0" * 64,
        frozen_contract_digest="1" * 64,
        requirement_id="REQ-01",
        sandbox_identity=sbx,
        source_commit_id="a" * 40,
        world=ExecutionWorld.CANDIDATE,
        status=TerminationStatus.COMPLETED,
        exit_code=5,
        stdout_raw="collected 0 items\nno tests ran in 0.01s",
        stderr_raw="",
        duration_seconds=0.1,
        provenance=EvidenceProvenance.LOCAL_EXECUTION,
    )

    runtime_check = analyze_runtime_execution_vacuity(exec_res, code_check)
    assert runtime_check.status == VacuityStatus.VACUOUS_SKIPPED_SUITE
    assert runtime_check.is_vacuous is True


def test_runtime_detects_missing_module_precondition() -> None:
    sbx = SandboxIdentity(sandbox_id="sbx-01")
    code_check = VacuityCheckResult(
        status=VacuityStatus.VALID,
        is_vacuous=False,
        details="Code ok",
        assertion_count=1,
        target_symbols_referenced=(),
    )

    exec_res = normalize_witness_execution(
        witness_id="wit-01",
        witness_digest="0" * 64,
        frozen_contract_digest="1" * 64,
        requirement_id="REQ-01",
        sandbox_identity=sbx,
        source_commit_id="a" * 40,
        world=ExecutionWorld.BASE,
        status=TerminationStatus.COMPLETED,
        exit_code=1,
        stdout_raw="ImportError: cannot import name 'target_fn' from 'target_mod'",
        stderr_raw="",
        duration_seconds=0.1,
        provenance=EvidenceProvenance.LOCAL_EXECUTION,
    )

    runtime_check = analyze_runtime_execution_vacuity(exec_res, code_check)
    assert runtime_check.status == VacuityStatus.INVALID_PRECONDITION
    assert runtime_check.is_vacuous is True


def test_vacuity_provider_purity() -> None:
    import basebreak.verifier.vacuity as v_mod

    source = inspect.getsource(v_mod)
    tree = ast.parse(source)
    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            for alias in node.names:
                assert not alias.name.startswith("basebreak.adapters"), (
                    f"vacuity must not import adapters: {alias.name}"
                )
        elif isinstance(node, ast.ImportFrom):
            if node.module:
                assert not node.module.startswith("basebreak.adapters"), (
                    f"vacuity must not import adapters: {node.module}"
                )
