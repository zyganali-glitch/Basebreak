"""Unit tests for causal outcome reconciliation and transition taxonomy (P-10.04, P-10.05)."""

from __future__ import annotations

import pytest

from basebreak.causal.reconciliation import (
    CausalTransition,
    reconcile_causal_transition,
)
from basebreak.domain.verdict import PreliminaryVerdict
from basebreak.verifier.vacuity import VacuityCheckResult, VacuityStatus
from basebreak.verifier.witness_result import WitnessOutcome


class TestCausalReconciliation:
    """Validates deterministic reconciliation of two-world outcomes."""

    def test_p10_04_bug_fix_fail_to_pass_is_verified(self) -> None:
        """P-10.04: BASE=FAIL, CANDIDATE=PASS reconciles to CAUSAL_BUG_FIX_VERIFIED."""
        fact = reconcile_causal_transition(
            base_outcome=WitnessOutcome.FAIL,
            candidate_outcome=WitnessOutcome.PASS,
        )
        assert fact.transition == CausalTransition.CAUSAL_BUG_FIX_VERIFIED
        assert fact.verdict == PreliminaryVerdict.VERIFIED
        assert fact.is_causally_verified is True
        assert "causal BUG_FIX verified" in fact.rationale

    def test_p10_05_pass_to_pass_is_unverified_trivial_pass(self) -> None:
        """P-10.05: BASE=PASS, CANDIDATE=PASS reconciles to UNVERIFIED_TRIVIAL_PASS."""
        fact = reconcile_causal_transition(
            base_outcome=WitnessOutcome.PASS,
            candidate_outcome=WitnessOutcome.PASS,
        )
        assert fact.transition == CausalTransition.UNVERIFIED_TRIVIAL_PASS
        assert fact.verdict == PreliminaryVerdict.INCONCLUSIVE
        assert fact.is_causally_verified is False
        assert "not causally necessary" in fact.rationale

    def test_p10_05_fail_to_fail_is_unverified_defect_persists(self) -> None:
        """P-10.05: BASE=FAIL, CANDIDATE=FAIL reconciles to UNVERIFIED_DEFECT_PERSISTS."""
        fact = reconcile_causal_transition(
            base_outcome=WitnessOutcome.FAIL,
            candidate_outcome=WitnessOutcome.FAIL,
        )
        assert fact.transition == CausalTransition.UNVERIFIED_DEFECT_PERSISTS
        assert fact.verdict == PreliminaryVerdict.CONTRADICTED
        assert fact.is_causally_verified is False
        assert "defect persists" in fact.rationale

    def test_p10_05_pass_to_fail_is_unverified_regression(self) -> None:
        """P-10.05: BASE=PASS, CANDIDATE=FAIL reconciles to UNVERIFIED_REGRESSION."""
        fact = reconcile_causal_transition(
            base_outcome=WitnessOutcome.PASS,
            candidate_outcome=WitnessOutcome.FAIL,
        )
        assert fact.transition == CausalTransition.UNVERIFIED_REGRESSION
        assert fact.verdict == PreliminaryVerdict.CONTRADICTED
        assert fact.is_causally_verified is False
        assert "regression observed" in fact.rationale

    def test_p10_05_timeout_is_non_verified_timeout(self) -> None:
        """P-10.05: TIMEOUT on either world reconciles to NON_VERIFIED_TIMEOUT."""
        # Timeout on base
        fact_base = reconcile_causal_transition(
            base_outcome=WitnessOutcome.TIMEOUT,
            candidate_outcome=WitnessOutcome.PASS,
        )
        assert fact_base.transition == CausalTransition.NON_VERIFIED_TIMEOUT
        assert fact_base.verdict == PreliminaryVerdict.INCONCLUSIVE
        assert fact_base.is_causally_verified is False

        # Timeout on candidate
        fact_cand = reconcile_causal_transition(
            base_outcome=WitnessOutcome.FAIL,
            candidate_outcome=WitnessOutcome.TIMEOUT,
        )
        assert fact_cand.transition == CausalTransition.NON_VERIFIED_TIMEOUT
        assert fact_cand.verdict == PreliminaryVerdict.INCONCLUSIVE
        assert fact_cand.is_causally_verified is False

    def test_p10_05_error_is_non_verified_execution_error(self) -> None:
        """P-10.05: ERROR on either world reconciles to NON_VERIFIED_EXECUTION_ERROR."""
        fact = reconcile_causal_transition(
            base_outcome=WitnessOutcome.ERROR,
            candidate_outcome=WitnessOutcome.PASS,
        )
        assert fact.transition == CausalTransition.NON_VERIFIED_EXECUTION_ERROR
        assert fact.verdict == PreliminaryVerdict.INCONCLUSIVE
        assert fact.is_causally_verified is False

    def test_p10_05_invalid_precondition_is_blocked(self) -> None:
        """P-10.05: INVALID_PRECONDITION reconciles to PreliminaryVerdict.BLOCKED."""
        fact = reconcile_causal_transition(
            base_outcome=WitnessOutcome.INVALID_PRECONDITION,
            candidate_outcome=WitnessOutcome.PASS,
        )
        assert fact.transition == CausalTransition.NON_VERIFIED_INVALID_PRECONDITION
        assert fact.verdict == PreliminaryVerdict.BLOCKED
        assert fact.is_causally_verified is False

    def test_vacuous_witness_defense(self) -> None:
        """Vacuous witness forces NON_VERIFIED_VACUOUS even if FAIL->PASS."""
        vacuous = VacuityCheckResult(
            status=VacuityStatus.VACUOUS_TRIVIAL_PASS,
            is_vacuous=True,
            details="All assertions are trivial constants",
            assertion_count=1,
            target_symbols_referenced=(),
        )
        fact = reconcile_causal_transition(
            base_outcome=WitnessOutcome.FAIL,
            candidate_outcome=WitnessOutcome.PASS,
            candidate_vacuity=vacuous,
        )
        assert fact.transition == CausalTransition.NON_VERIFIED_VACUOUS
        assert fact.verdict == PreliminaryVerdict.INCONCLUSIVE
        assert fact.is_causally_verified is False

    def test_integrity_failure_supersedes_all_outcomes(self) -> None:
        """Tampering or integrity failure takes absolute precedence."""
        fact = reconcile_causal_transition(
            base_outcome=WitnessOutcome.FAIL,
            candidate_outcome=WitnessOutcome.PASS,
            integrity_failure_reason="Witness digest mismatch",
        )
        assert fact.transition == CausalTransition.NON_VERIFIED_TAMPERING_OR_INTEGRITY_FAILURE
        assert fact.verdict == PreliminaryVerdict.CONTRADICTED
        assert fact.is_causally_verified is False
        assert "Witness digest mismatch" in fact.rationale

    def test_invalid_types_raise(self) -> None:
        """Passing non-enum types raises TypeError."""
        with pytest.raises(TypeError, match="WitnessOutcome"):
            reconcile_causal_transition(
                base_outcome="FAIL",  # type: ignore[arg-type]
                candidate_outcome=WitnessOutcome.PASS,
            )
