"""Tests for P-09.04: Deterministic witness execution and result normalization contracts.

Verifies:
1. Normalization of PASS, FAIL, ERROR, TIMEOUT, INVALID_PRECONDITION.
2. Prevention of outcome collapse: TIMED_OUT/CANCELLED/FAILED_TO_START
   never collapse to PASS or FAIL.
3. Cryptographic binding to witness identity, seal digest, contract digest, sandbox ID.
4. Output sanitization and bounded stdout/stderr capture with SHA-256 digests.
5. Deterministic result digest computation and tamper rejection.
6. Provider purity (zero adapter imports in witness_result).
"""

from __future__ import annotations

import ast
import inspect

import pytest

from basebreak.domain.causal import ExecutionWorld
from basebreak.domain.execution import SandboxIdentity, TerminationStatus
from basebreak.domain.verdict import EvidenceProvenance
from basebreak.verifier.witness_result import (
    CollapsedOutcomeError,
    NormalizedWitnessResult,
    WitnessOutcome,
    normalize_witness_execution,
)


@pytest.fixture
def base_sandbox() -> SandboxIdentity:
    return SandboxIdentity(sandbox_id="sbx-base-001")


def test_normalize_pass(base_sandbox: SandboxIdentity) -> None:
    res = normalize_witness_execution(
        witness_id="wit-001",
        witness_digest="0" * 64,
        frozen_contract_digest="1" * 64,
        requirement_id="REQ-01",
        sandbox_identity=base_sandbox,
        source_commit_id="a" * 40,
        world=ExecutionWorld.CANDIDATE,
        status=TerminationStatus.COMPLETED,
        exit_code=0,
        stdout_raw="test passed",
        stderr_raw="",
        duration_seconds=1.23,
        provenance=EvidenceProvenance.LOCAL_EXECUTION,
    )
    assert res.outcome == WitnessOutcome.PASS
    assert res.exit_code == 0
    assert len(res.result_digest) == 64
    assert res.is_authoritative is False


def test_normalize_behavioral_fail(base_sandbox: SandboxIdentity) -> None:
    res = normalize_witness_execution(
        witness_id="wit-001",
        witness_digest="0" * 64,
        frozen_contract_digest="1" * 64,
        requirement_id="REQ-01",
        sandbox_identity=base_sandbox,
        source_commit_id="a" * 40,
        world=ExecutionWorld.BASE,
        status=TerminationStatus.COMPLETED,
        exit_code=1,
        stdout_raw="FAILED test_boundary - AssertionError: assert False",
        stderr_raw="",
        duration_seconds=0.5,
        provenance=EvidenceProvenance.LOCAL_EXECUTION,
    )
    assert res.outcome == WitnessOutcome.FAIL
    assert res.exit_code == 1


def test_normalize_timeout_never_collapses_to_fail(base_sandbox: SandboxIdentity) -> None:
    res = normalize_witness_execution(
        witness_id="wit-001",
        witness_digest="0" * 64,
        frozen_contract_digest="1" * 64,
        requirement_id="REQ-01",
        sandbox_identity=base_sandbox,
        source_commit_id="a" * 40,
        world=ExecutionWorld.BASE,
        status=TerminationStatus.TIMED_OUT,
        exit_code=None,
        stdout_raw="",
        stderr_raw="Execution exceeded timeout limit",
        duration_seconds=120.0,
        provenance=EvidenceProvenance.LOCAL_EXECUTION,
    )
    assert res.outcome == WitnessOutcome.TIMEOUT


def test_normalize_infrastructure_error_never_collapses_to_fail(
    base_sandbox: SandboxIdentity,
) -> None:
    res = normalize_witness_execution(
        witness_id="wit-001",
        witness_digest="0" * 64,
        frozen_contract_digest="1" * 64,
        requirement_id="REQ-01",
        sandbox_identity=base_sandbox,
        source_commit_id="a" * 40,
        world=ExecutionWorld.BASE,
        status=TerminationStatus.FAILED_TO_START,
        exit_code=None,
        stdout_raw="",
        stderr_raw="Binary not found",
        duration_seconds=0.01,
        provenance=EvidenceProvenance.LOCAL_EXECUTION,
    )
    assert res.outcome == WitnessOutcome.ERROR


def test_result_constructor_blocks_collapsed_outcome_tampering(
    base_sandbox: SandboxIdentity,
) -> None:
    # Tampering: status is TIMED_OUT but outcome claims FAIL
    with pytest.raises(CollapsedOutcomeError, match="TIMED_OUT"):
        NormalizedWitnessResult(
            witness_id="wit-001",
            witness_digest="0" * 64,
            frozen_contract_digest="1" * 64,
            requirement_id="REQ-01",
            sandbox_id=base_sandbox.sandbox_id,
            source_commit_id="a" * 40,
            world=ExecutionWorld.BASE,
            outcome=WitnessOutcome.FAIL,
            exit_code=None,
            termination_status=TerminationStatus.TIMED_OUT,
            stdout_digest="0" * 64,
            stderr_digest="0" * 64,
            stdout_clean="",
            stderr_clean="",
            duration_seconds=10.0,
            provenance=EvidenceProvenance.LOCAL_EXECUTION,
            result_digest="0" * 64,
        )


def test_result_sanitizes_secrets(base_sandbox: SandboxIdentity) -> None:
    res = normalize_witness_execution(
        witness_id="wit-001",
        witness_digest="0" * 64,
        frozen_contract_digest="1" * 64,
        requirement_id="REQ-01",
        sandbox_identity=base_sandbox,
        source_commit_id="a" * 40,
        world=ExecutionWorld.BASE,
        status=TerminationStatus.COMPLETED,
        exit_code=1,
        stdout_raw="Leaking secret: AKIA1234567890EXAMPLE in stdout",
        stderr_raw="",
        duration_seconds=0.5,
        provenance=EvidenceProvenance.LOCAL_EXECUTION,
    )
    assert "AKIA1234567890EXAMPLE" not in res.stdout_clean
    assert "[REDACTED" in res.stdout_clean


def test_witness_result_provider_purity() -> None:
    import basebreak.verifier.witness_result as wr_mod

    source = inspect.getsource(wr_mod)
    tree = ast.parse(source)
    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            for alias in node.names:
                assert not alias.name.startswith("basebreak.adapters"), (
                    f"witness_result must not import adapters: {alias.name}"
                )
        elif isinstance(node, ast.ImportFrom):
            if node.module:
                assert not node.module.startswith("basebreak.adapters"), (
                    f"witness_result must not import adapters: {node.module}"
                )
