"""Tests for P-15.05: Fail-closed budget admission and exhaustion handling."""

from __future__ import annotations

import pytest

from basebreak.budget.accounting import BudgetLedger, ResourceLimits
from basebreak.budget.depth_policy import (
    VerificationAction,
    resolve_verification_depth,
)
from basebreak.budget.fail_closed import (
    FAIL_CLOSED_SCHEMA_VERSION,
    BudgetGateResult,
    BudgetGateStatus,
    BudgetGateTamperingError,
    InvalidGateInputError,
    handle_budget_exhaustion,
    preflight_budget_admission,
    verify_budget_gate_result_integrity,
)
from basebreak.budget.mandatory_policy import resolve_mandatory_obligations
from basebreak.budget.risk_features import (
    classify_risk,
    extract_risk_features,
)
from basebreak.compiler.semantics import ChangeClass
from basebreak.domain.verdict import PreliminaryVerdict


def test_preflight_admission_success_when_budget_sufficient() -> None:
    """Preflight check must grant ADMITTED when resources satisfy requirements."""
    ledger = BudgetLedger(
        limits=ResourceLimits(
            max_sandbox_executions=10,
            max_verifier_executions=10,
            max_elapsed_seconds=300.0,
        )
    )
    features = extract_risk_features(
        change_class=ChangeClass.BUG_FIX, changed_files=("src/calc.py",)
    )
    classification = classify_risk(features)
    depth = resolve_verification_depth(classification)
    obligations = resolve_mandatory_obligations(classification)

    result = preflight_budget_admission(ledger, depth, obligations)
    assert result.gate_status == BudgetGateStatus.ADMITTED
    assert result.preliminary_verdict == PreliminaryVerdict.INCONCLUSIVE
    assert result.grants_pass is False
    assert result.is_causally_verified is False
    assert len(result.unexecuted_obligations) == 0
    verify_budget_gate_result_integrity(result)


def test_preflight_admission_denied_when_sandboxes_insufficient() -> None:
    """Preflight check must fail closed if sandboxes are insufficient."""
    # Depth requires at least 2 sandboxes, but budget ceiling is 1
    ledger = BudgetLedger(limits=ResourceLimits(max_sandbox_executions=1))
    features = extract_risk_features(
        change_class=ChangeClass.BUG_FIX, changed_files=("src/calc.py",)
    )
    classification = classify_risk(features)
    depth = resolve_verification_depth(classification)
    obligations = resolve_mandatory_obligations(classification)

    result = preflight_budget_admission(ledger, depth, obligations)
    assert result.gate_status == BudgetGateStatus.INSUFFICIENT_RESERVATION
    assert result.preliminary_verdict == PreliminaryVerdict.BLOCKED
    assert result.grants_pass is False
    assert result.is_causally_verified is False
    assert len(result.unexecuted_obligations) >= 2
    assert any("Insufficient sandbox executions" in u.reason for u in result.unexecuted_obligations)
    verify_budget_gate_result_integrity(result)


def test_preflight_admission_denied_when_time_insufficient() -> None:
    """Preflight check must fail closed if remaining elapsed seconds is below requirement."""
    ledger = BudgetLedger(limits=ResourceLimits(max_elapsed_seconds=5.0))
    # Preflight requires min 10.0 seconds
    features = extract_risk_features(
        change_class=ChangeClass.BUG_FIX, changed_files=("src/calc.py",)
    )
    classification = classify_risk(features)
    depth = resolve_verification_depth(classification)
    obligations = resolve_mandatory_obligations(classification)

    result = preflight_budget_admission(ledger, depth, obligations, min_required_seconds=10.0)
    assert result.gate_status == BudgetGateStatus.INSUFFICIENT_RESERVATION
    assert result.preliminary_verdict == PreliminaryVerdict.BLOCKED
    assert any("Insufficient time budget" in u.reason for u in result.unexecuted_obligations)


def test_exhaustion_during_execution_fails_closed() -> None:
    """Resource exhaustion during execution must produce EXHAUSTED and BLOCKED verdict."""
    ledger = BudgetLedger()
    features = extract_risk_features(
        change_class=ChangeClass.BUG_FIX, changed_files=("src/calc.py",)
    )
    classification = classify_risk(features)
    depth = resolve_verification_depth(classification)
    obligations = resolve_mandatory_obligations(classification)

    # Simulate: BASE was executed, but budget exhausted before CANDIDATE could execute
    executed = [VerificationAction.BASE_EXECUTION]
    preserved = ["e" * 64]  # Base execution result digest

    result = handle_budget_exhaustion(
        ledger,
        depth,
        obligations,
        executed_actions=executed,
        preserved_evidence_digests=preserved,
        witness_failure_observed=False,
        exhaustion_detail="Out of sandboxes",
    )

    assert result.gate_status == BudgetGateStatus.EXHAUSTED
    assert result.preliminary_verdict == PreliminaryVerdict.BLOCKED
    assert result.grants_pass is False
    assert result.is_causally_verified is False
    assert result.preserved_evidence_digests == ("e" * 64,)
    assert any(
        u.action == VerificationAction.CANDIDATE_EXECUTION for u in result.unexecuted_obligations
    )
    verify_budget_gate_result_integrity(result)


def test_witness_failure_governs_over_budget_exhaustion() -> None:
    """Witness failure cannot be masked by budget exhaustion (remains CONTRADICTED)."""
    ledger = BudgetLedger()
    features = extract_risk_features(
        change_class=ChangeClass.BUG_FIX, changed_files=("src/calc.py",)
    )
    classification = classify_risk(features)
    depth = resolve_verification_depth(classification)
    obligations = resolve_mandatory_obligations(classification)

    # Base world was executed and unexpectedly passed (witness failed to detect bug on base)
    # Then budget ran out. The verdict MUST be CONTRADICTED, not BLOCKED or INCONCLUSIVE!
    result = handle_budget_exhaustion(
        ledger,
        depth,
        obligations,
        executed_actions=[VerificationAction.BASE_EXECUTION],
        witness_failure_observed=True,  # Failure observed!
        exhaustion_detail="Budget limit reached after BASE pass",
    )

    assert result.gate_status == BudgetGateStatus.CONTRADICTED_WITNESS
    assert result.preliminary_verdict == PreliminaryVerdict.CONTRADICTED
    assert result.grants_pass is False
    assert result.is_causally_verified is False
    assert "witness contradiction" in result.rationale


def test_adversarial_pass_grant_on_rejection_forbidden() -> None:
    """Constructing BudgetGateResult with grants_pass=True on rejection fails closed."""
    with pytest.raises(InvalidGateInputError, match="grants_pass must be False"):
        BudgetGateResult(
            schema_version=FAIL_CLOSED_SCHEMA_VERSION,
            gate_status=BudgetGateStatus.EXHAUSTED,
            preliminary_verdict=PreliminaryVerdict.VERIFIED,  # Malicious
            is_causally_verified=False,
            grants_pass=True,  # Forbidden
            unexecuted_obligations=(),
            preserved_evidence_digests=(),
            rationale="Malicious bypass attempt",
            receipt_digest="0" * 64,
        )


def test_tamper_detection_on_budget_gate_receipt() -> None:
    """Tampering with BudgetGateResult digest must raise BudgetGateTamperingError."""
    ledger = BudgetLedger(limits=ResourceLimits(max_sandbox_executions=1))
    features = extract_risk_features(
        change_class=ChangeClass.BUG_FIX, changed_files=("src/calc.py",)
    )
    classification = classify_risk(features)
    depth = resolve_verification_depth(classification)
    obligations = resolve_mandatory_obligations(classification)

    result = preflight_budget_admission(ledger, depth, obligations)
    tampered = BudgetGateResult(
        schema_version=result.schema_version,
        gate_status=result.gate_status,
        preliminary_verdict=result.preliminary_verdict,
        is_causally_verified=result.is_causally_verified,
        grants_pass=result.grants_pass,
        unexecuted_obligations=result.unexecuted_obligations,
        preserved_evidence_digests=result.preserved_evidence_digests,
        rationale=result.rationale,
        receipt_digest="d" * 64,
    )

    with pytest.raises(BudgetGateTamperingError, match="digest mismatch"):
        verify_budget_gate_result_integrity(tampered)
