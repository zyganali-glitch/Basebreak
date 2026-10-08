"""Deterministic causal outcome reconciliation and transition taxonomy.

P-10.04: Reconcile BUG_FIX FAIL->PASS deterministically.
P-10.05: Handle PASS->PASS, FAIL->FAIL, ERROR/TIMEOUT as non-verified states.

Core Invariants:
1. Invariant truth: Under BUG_FIX, the ONLY positive causal transition is:
   BASE = FAIL, CANDIDATE = PASS -> CAUSAL_BUG_FIX_VERIFIED (PreliminaryVerdict.VERIFIED).
2. Anti-collapse: PASS->PASS (UNVERIFIED_TRIVIAL_PASS), FAIL->FAIL (UNVERIFIED_DEFECT_PERSISTS),
   and PASS->FAIL (UNVERIFIED_REGRESSION) must NEVER collapse into VERIFIED.
3. Execution safety: TIMEOUT, ERROR, and INVALID_PRECONDITION are explicit non-verified states.
4. Vacuity defense: A vacuous witness (zero assertions, trivial constants, empty test suite)
   can never grant verification and resolves to NON_VERIFIED_VACUOUS.
5. Cryptographic integrity: Any tampering, digest mismatch, or sandbox collision resolves to
   NON_VERIFIED_TAMPERING_OR_INTEGRITY_FAILURE.
6. Zero model authority: Reconciliation is a pure deterministic function; model prose or
   confidence scores possess zero authority over causal transitions.
"""

from __future__ import annotations

from dataclasses import dataclass
from enum import Enum

from basebreak.domain.verdict import PreliminaryVerdict
from basebreak.verifier.vacuity import VacuityCheckResult
from basebreak.verifier.witness_result import WitnessOutcome


class ChangeClassMismatchError(Exception):
    """Raised when verifier is invoked with a contract of mismatched change class."""


class CausalTransition(str, Enum):
    """Normalized taxonomy of two-world causal behavioral transitions.

    Explicitly maps every permutation of BASE and CANDIDATE execution outcomes
    and integrity conditions across all canonical change classes.
    """

    # Sole positive causal transition for BUG_FIX
    CAUSAL_BUG_FIX_VERIFIED = "CAUSAL_BUG_FIX_VERIFIED"

    # Positive transitions for expanded canonical change classes
    FEATURE_VERIFIED = "FEATURE_VERIFIED"
    SECURITY_FIX_VERIFIED = "SECURITY_FIX_VERIFIED"
    REFACTOR_VERIFIED = "REFACTOR_VERIFIED"
    PERFORMANCE_VERIFIED = "PERFORMANCE_VERIFIED"
    DEP_API_CHANGE_VERIFIED = "DEP_API_CHANGE_VERIFIED"

    # Three-world causal triplet transition
    CAUSAL_TRIPLET_VERIFIED = "CAUSAL_TRIPLET_VERIFIED"

    # Non-verified behavioral outcomes - BUG_FIX
    UNVERIFIED_TRIVIAL_PASS = "UNVERIFIED_TRIVIAL_PASS"
    UNVERIFIED_DEFECT_PERSISTS = "UNVERIFIED_DEFECT_PERSISTS"
    UNVERIFIED_REGRESSION = "UNVERIFIED_REGRESSION"

    # Non-verified behavioral outcomes - FEATURE (P-13.01)
    UNVERIFIED_FEATURE_ALREADY_PRESENT = "UNVERIFIED_FEATURE_ALREADY_PRESENT"
    UNVERIFIED_FEATURE_NOT_IMPLEMENTED = "UNVERIFIED_FEATURE_NOT_IMPLEMENTED"
    UNVERIFIED_FEATURE_REGRESSION = "UNVERIFIED_FEATURE_REGRESSION"

    # Non-verified behavioral outcomes - SECURITY_FIX (P-13.02)
    UNVERIFIED_VULNERABILITY_NOT_REPRODUCED = "UNVERIFIED_VULNERABILITY_NOT_REPRODUCED"
    UNVERIFIED_EXPLOIT_PERSISTS = "UNVERIFIED_EXPLOIT_PERSISTS"
    UNVERIFIED_SECURITY_FIX_REGRESSION = "UNVERIFIED_SECURITY_FIX_REGRESSION"

    # Non-verified behavioral outcomes - REFACTOR (P-13.03)
    UNVERIFIED_BEHAVIOR_CHANGED = "UNVERIFIED_BEHAVIOR_CHANGED"
    UNVERIFIED_EXIT_SEMANTICS_CHANGED = "UNVERIFIED_EXIT_SEMANTICS_CHANGED"
    UNVERIFIED_BASE_FAILED = "UNVERIFIED_BASE_FAILED"

    # Non-verified behavioral outcomes - PERFORMANCE (P-13.04)
    UNVERIFIED_PERFORMANCE_PARITY_FAILED = "UNVERIFIED_PERFORMANCE_PARITY_FAILED"
    UNVERIFIED_PERFORMANCE_DELTA_NOT_MET = "UNVERIFIED_PERFORMANCE_DELTA_NOT_MET"
    UNVERIFIED_PERFORMANCE_NOISY_OR_INCONCLUSIVE = "UNVERIFIED_PERFORMANCE_NOISY_OR_INCONCLUSIVE"

    # Non-verified behavioral outcomes - DEP_API_CHANGE (P-13.05)
    UNVERIFIED_NEW_CONTRACT_FAILED = "UNVERIFIED_NEW_CONTRACT_FAILED"
    UNVERIFIED_REGRESSION_DETECTED = "UNVERIFIED_REGRESSION_DETECTED"

    # Non-verified execution/infrastructure outcomes
    NON_VERIFIED_TIMEOUT = "NON_VERIFIED_TIMEOUT"
    NON_VERIFIED_EXECUTION_ERROR = "NON_VERIFIED_EXECUTION_ERROR"
    NON_VERIFIED_VACUOUS = "NON_VERIFIED_VACUOUS"
    NON_VERIFIED_INVALID_PRECONDITION = "NON_VERIFIED_INVALID_PRECONDITION"
    NON_VERIFIED_TAMPERING_OR_INTEGRITY_FAILURE = "NON_VERIFIED_TAMPERING_OR_INTEGRITY_FAILURE"
    NON_VERIFIED_CRASH_OR_UNHANDLED_EXCEPTION = "NON_VERIFIED_CRASH_OR_UNHANDLED_EXCEPTION"

    # Three-world causal triplet non-verified transitions
    UNVERIFIED_COUNTERFACTUAL_INEFFECTIVE = "UNVERIFIED_COUNTERFACTUAL_INEFFECTIVE"
    NON_VERIFIED_INVALID_COUNTERFACTUAL = "NON_VERIFIED_INVALID_COUNTERFACTUAL"


@dataclass(frozen=True, slots=True)
class ReconciliationFact:
    """Deterministic result of outcome reconciliation."""

    transition: CausalTransition
    verdict: PreliminaryVerdict
    is_causally_verified: bool
    rationale: str

    def __post_init__(self) -> None:
        if not isinstance(self.transition, CausalTransition):
            raise TypeError(
                f"transition must be CausalTransition, got {type(self.transition).__name__}"
            )
        if not isinstance(self.verdict, PreliminaryVerdict):
            raise TypeError(
                f"verdict must be PreliminaryVerdict, got {type(self.verdict).__name__}"
            )
        if not isinstance(self.is_causally_verified, bool):
            raise TypeError("is_causally_verified must be a boolean")
        if not isinstance(self.rationale, str) or not self.rationale.strip():
            raise ValueError("rationale must be a non-empty string")

        # Invariant: is_causally_verified iff transition is one of the canonical
        # verified transitions and verdict is VERIFIED
        positive_verified_transitions = (
            CausalTransition.CAUSAL_BUG_FIX_VERIFIED,
            CausalTransition.CAUSAL_TRIPLET_VERIFIED,
            CausalTransition.FEATURE_VERIFIED,
            CausalTransition.SECURITY_FIX_VERIFIED,
            CausalTransition.REFACTOR_VERIFIED,
            CausalTransition.PERFORMANCE_VERIFIED,
            CausalTransition.DEP_API_CHANGE_VERIFIED,
        )
        expected_verified = (
            self.transition in positive_verified_transitions
            and self.verdict == PreliminaryVerdict.VERIFIED
        )
        if self.is_causally_verified != expected_verified:
            raise ValueError(
                f"is_causally_verified mismatch: declared {self.is_causally_verified}, "
                f"expected {expected_verified} for transition {self.transition.value}"
            )


def reconcile_causal_transition(
    *,
    base_outcome: WitnessOutcome,
    candidate_outcome: WitnessOutcome,
    base_vacuity: VacuityCheckResult | None = None,
    candidate_vacuity: VacuityCheckResult | None = None,
    integrity_failure_reason: str | None = None,
) -> ReconciliationFact:
    """Deterministically reconcile BASE and CANDIDATE execution outcomes into a causal verdict.

    Args:
        base_outcome: Outcome of identical witness on trusted BASE world.
        candidate_outcome: Outcome of identical witness on exact CANDIDATE world.
        base_vacuity: Optional vacuity analysis result for BASE world.
        candidate_vacuity: Optional vacuity analysis result for CANDIDATE world.
        integrity_failure_reason: Non-None if digest/identity/tampering checks failed.

    Returns:
        ReconciliationFact containing the exact transition, preliminary verdict, and rationale.
    """
    if not isinstance(base_outcome, WitnessOutcome):
        raise TypeError(f"base_outcome must be WitnessOutcome, got {type(base_outcome).__name__}")
    if not isinstance(candidate_outcome, WitnessOutcome):
        raise TypeError(
            f"candidate_outcome must be WitnessOutcome, got {type(candidate_outcome).__name__}"
        )

    # 1. Integrity / Tampering failure takes absolute precedence
    if integrity_failure_reason is not None and str(integrity_failure_reason).strip():
        reason = str(integrity_failure_reason).strip()
        return ReconciliationFact(
            transition=CausalTransition.NON_VERIFIED_TAMPERING_OR_INTEGRITY_FAILURE,
            verdict=PreliminaryVerdict.CONTRADICTED,
            is_causally_verified=False,
            rationale=f"Cryptographic binding or integrity check failed: {reason}",
        )

    # 2. Vacuity defense: vacuous witness can never grant verification
    if base_vacuity is not None and base_vacuity.is_vacuous:
        return ReconciliationFact(
            transition=CausalTransition.NON_VERIFIED_VACUOUS,
            verdict=PreliminaryVerdict.INCONCLUSIVE,
            is_causally_verified=False,
            rationale=f"Witness on BASE world is vacuous: {base_vacuity.details}",
        )
    if candidate_vacuity is not None and candidate_vacuity.is_vacuous:
        return ReconciliationFact(
            transition=CausalTransition.NON_VERIFIED_VACUOUS,
            verdict=PreliminaryVerdict.INCONCLUSIVE,
            is_causally_verified=False,
            rationale=f"Witness on CANDIDATE world is vacuous: {candidate_vacuity.details}",
        )

    # 3. Precondition failures
    if (
        base_outcome == WitnessOutcome.INVALID_PRECONDITION
        or candidate_outcome == WitnessOutcome.INVALID_PRECONDITION
    ):
        return ReconciliationFact(
            transition=CausalTransition.NON_VERIFIED_INVALID_PRECONDITION,
            verdict=PreliminaryVerdict.BLOCKED,
            is_causally_verified=False,
            rationale="Execution precondition was invalid (e.g. missing import or setup failure)",
        )

    # 4. Timeout outcomes
    if base_outcome == WitnessOutcome.TIMEOUT or candidate_outcome == WitnessOutcome.TIMEOUT:
        return ReconciliationFact(
            transition=CausalTransition.NON_VERIFIED_TIMEOUT,
            verdict=PreliminaryVerdict.INCONCLUSIVE,
            is_causally_verified=False,
            rationale=(
                f"Execution timed out (BASE: {base_outcome.value}, "
                f"CANDIDATE: {candidate_outcome.value})"
            ),
        )

    # 5. Infrastructure / Execution errors
    if base_outcome == WitnessOutcome.ERROR or candidate_outcome == WitnessOutcome.ERROR:
        return ReconciliationFact(
            transition=CausalTransition.NON_VERIFIED_EXECUTION_ERROR,
            verdict=PreliminaryVerdict.INCONCLUSIVE,
            is_causally_verified=False,
            rationale=(
                f"Execution error encountered (BASE: {base_outcome.value}, "
                f"CANDIDATE: {candidate_outcome.value})"
            ),
        )

    # 6. Behavioral Transitions
    # 6a. BASE = FAIL, CANDIDATE = PASS -> CAUSAL BUG FIX VERIFIED
    if base_outcome == WitnessOutcome.FAIL and candidate_outcome == WitnessOutcome.PASS:
        return ReconciliationFact(
            transition=CausalTransition.CAUSAL_BUG_FIX_VERIFIED,
            verdict=PreliminaryVerdict.VERIFIED,
            is_causally_verified=True,
            rationale=(
                "BASE broke (FAIL) and CANDIDATE passed (PASS) under identical witness: "
                "causal BUG_FIX verified."
            ),
        )

    # 6b. BASE = PASS, CANDIDATE = PASS -> UNVERIFIED TRIVIAL PASS
    if base_outcome == WitnessOutcome.PASS and candidate_outcome == WitnessOutcome.PASS:
        return ReconciliationFact(
            transition=CausalTransition.UNVERIFIED_TRIVIAL_PASS,
            verdict=PreliminaryVerdict.INCONCLUSIVE,
            is_causally_verified=False,
            rationale=(
                "BASE already passed without candidate patch; "
                "patch was not causally necessary under this witness."
            ),
        )

    # 6c. BASE = FAIL, CANDIDATE = FAIL -> UNVERIFIED DEFECT PERSISTS
    if base_outcome == WitnessOutcome.FAIL and candidate_outcome == WitnessOutcome.FAIL:
        return ReconciliationFact(
            transition=CausalTransition.UNVERIFIED_DEFECT_PERSISTS,
            verdict=PreliminaryVerdict.CONTRADICTED,
            is_causally_verified=False,
            rationale="CANDIDATE still fails under witness; defect persists.",
        )

    # 6d. BASE = PASS, CANDIDATE = FAIL -> UNVERIFIED REGRESSION
    if base_outcome == WitnessOutcome.PASS and candidate_outcome == WitnessOutcome.FAIL:
        return ReconciliationFact(
            transition=CausalTransition.UNVERIFIED_REGRESSION,
            verdict=PreliminaryVerdict.CONTRADICTED,
            is_causally_verified=False,
            rationale="BASE passed but CANDIDATE failed; regression observed under witness.",
        )

    # Fail closed for any unhandled state
    return ReconciliationFact(
        transition=CausalTransition.NON_VERIFIED_EXECUTION_ERROR,
        verdict=PreliminaryVerdict.INCONCLUSIVE,
        is_causally_verified=False,
        rationale=(
            f"Unhandled outcome combination: BASE={base_outcome.value}, "
            f"CANDIDATE={candidate_outcome.value}"
        ),
    )


def reconcile_causal_triplet(
    *,
    base_outcome: WitnessOutcome,
    candidate_outcome: WitnessOutcome,
    counterfactual_outcome: WitnessOutcome,
    base_vacuity: VacuityCheckResult | None = None,
    candidate_vacuity: VacuityCheckResult | None = None,
    counterfactual_vacuity: VacuityCheckResult | None = None,
    integrity_failure_reason: str | None = None,
    invalid_counterfactual_reason: str | None = None,
) -> ReconciliationFact:
    """Deterministically reconcile BASE, CANDIDATE, and COUNTERFACTUAL execution outcomes.

    The ONLY positive causal triplet is:
    BASE = FAIL
    CANDIDATE = PASS
    COUNTERFACTUAL = FAIL
    -> CAUSAL_TRIPLET_VERIFIED (PreliminaryVerdict.VERIFIED, is_causally_verified=True).

    Any other behavioral combination, vacuous witness, timeout, error, invalid precondition,
    or integrity/construction defect resolves to a non-verified state.
    """
    if not isinstance(base_outcome, WitnessOutcome):
        raise TypeError(f"base_outcome must be WitnessOutcome, got {type(base_outcome).__name__}")
    if not isinstance(candidate_outcome, WitnessOutcome):
        raise TypeError(
            f"candidate_outcome must be WitnessOutcome, got {type(candidate_outcome).__name__}"
        )
    if not isinstance(counterfactual_outcome, WitnessOutcome):
        cf_type = type(counterfactual_outcome).__name__
        raise TypeError(f"counterfactual_outcome must be WitnessOutcome, got {cf_type}")

    # 1. Cryptographic binding or integrity failure
    if integrity_failure_reason is not None and str(integrity_failure_reason).strip():
        reason = str(integrity_failure_reason).strip()
        return ReconciliationFact(
            transition=CausalTransition.NON_VERIFIED_TAMPERING_OR_INTEGRITY_FAILURE,
            verdict=PreliminaryVerdict.CONTRADICTED,
            is_causally_verified=False,
            rationale=f"Cryptographic binding or integrity check failed: {reason}",
        )

    # 2. Invalid counterfactual construction (P-11.06: fail closed, never false PASS)
    if invalid_counterfactual_reason is not None and str(invalid_counterfactual_reason).strip():
        reason = str(invalid_counterfactual_reason).strip()
        return ReconciliationFact(
            transition=CausalTransition.NON_VERIFIED_INVALID_COUNTERFACTUAL,
            verdict=PreliminaryVerdict.INCONCLUSIVE,
            is_causally_verified=False,
            rationale=f"Invalid counterfactual construction: {reason}",
        )

    # 3. Vacuity defense across all three worlds
    if base_vacuity is not None and base_vacuity.is_vacuous:
        return ReconciliationFact(
            transition=CausalTransition.NON_VERIFIED_VACUOUS,
            verdict=PreliminaryVerdict.INCONCLUSIVE,
            is_causally_verified=False,
            rationale=f"Witness on BASE world is vacuous: {base_vacuity.details}",
        )
    if candidate_vacuity is not None and candidate_vacuity.is_vacuous:
        return ReconciliationFact(
            transition=CausalTransition.NON_VERIFIED_VACUOUS,
            verdict=PreliminaryVerdict.INCONCLUSIVE,
            is_causally_verified=False,
            rationale=f"Witness on CANDIDATE world is vacuous: {candidate_vacuity.details}",
        )
    if counterfactual_vacuity is not None and counterfactual_vacuity.is_vacuous:
        return ReconciliationFact(
            transition=CausalTransition.NON_VERIFIED_VACUOUS,
            verdict=PreliminaryVerdict.INCONCLUSIVE,
            is_causally_verified=False,
            rationale=(
                f"Witness on COUNTERFACTUAL world is vacuous: {counterfactual_vacuity.details}"
            ),
        )

    # 4. Precondition failures
    if (
        base_outcome == WitnessOutcome.INVALID_PRECONDITION
        or candidate_outcome == WitnessOutcome.INVALID_PRECONDITION
        or counterfactual_outcome == WitnessOutcome.INVALID_PRECONDITION
    ):
        return ReconciliationFact(
            transition=CausalTransition.NON_VERIFIED_INVALID_PRECONDITION,
            verdict=PreliminaryVerdict.BLOCKED,
            is_causally_verified=False,
            rationale=(
                f"Execution precondition was invalid (BASE: {base_outcome.value}, "
                f"CANDIDATE: {candidate_outcome.value}, "
                f"COUNTERFACTUAL: {counterfactual_outcome.value})"
            ),
        )

    # 5. Timeout outcomes
    if (
        base_outcome == WitnessOutcome.TIMEOUT
        or candidate_outcome == WitnessOutcome.TIMEOUT
        or counterfactual_outcome == WitnessOutcome.TIMEOUT
    ):
        return ReconciliationFact(
            transition=CausalTransition.NON_VERIFIED_TIMEOUT,
            verdict=PreliminaryVerdict.INCONCLUSIVE,
            is_causally_verified=False,
            rationale=(
                f"Execution timed out (BASE: {base_outcome.value}, "
                f"CANDIDATE: {candidate_outcome.value}, "
                f"COUNTERFACTUAL: {counterfactual_outcome.value})"
            ),
        )

    # 6. Execution / infrastructure errors
    if (
        base_outcome == WitnessOutcome.ERROR
        or candidate_outcome == WitnessOutcome.ERROR
        or counterfactual_outcome == WitnessOutcome.ERROR
    ):
        return ReconciliationFact(
            transition=CausalTransition.NON_VERIFIED_EXECUTION_ERROR,
            verdict=PreliminaryVerdict.INCONCLUSIVE,
            is_causally_verified=False,
            rationale=(
                f"Execution error encountered (BASE: {base_outcome.value}, "
                f"CANDIDATE: {candidate_outcome.value}, "
                f"COUNTERFACTUAL: {counterfactual_outcome.value})"
            ),
        )

    # 7. Candidate failure: defect persists
    if candidate_outcome == WitnessOutcome.FAIL:
        return ReconciliationFact(
            transition=CausalTransition.UNVERIFIED_DEFECT_PERSISTS,
            verdict=PreliminaryVerdict.CONTRADICTED,
            is_causally_verified=False,
            rationale="CANDIDATE failed under witness; defect persists.",
        )

    # 8. Base passed: trivial pass without patch
    if base_outcome == WitnessOutcome.PASS:
        return ReconciliationFact(
            transition=CausalTransition.UNVERIFIED_TRIVIAL_PASS,
            verdict=PreliminaryVerdict.INCONCLUSIVE,
            is_causally_verified=False,
            rationale=(
                "BASE passed without candidate patch; "
                "patch was not causally necessary under this witness."
            ),
        )

    # 9. At this point: BASE = FAIL and CANDIDATE = PASS
    # Check COUNTERFACTUAL outcome:
    if counterfactual_outcome == WitnessOutcome.FAIL:
        # Sole positive causal triplet
        return ReconciliationFact(
            transition=CausalTransition.CAUSAL_TRIPLET_VERIFIED,
            verdict=PreliminaryVerdict.VERIFIED,
            is_causally_verified=True,
            rationale=(
                "Causal triplet verified: BASE=FAIL, CANDIDATE=PASS, COUNTERFACTUAL=FAIL "
                "under identical witness. Patch delta proved causally necessary."
            ),
        )

    if counterfactual_outcome == WitnessOutcome.PASS:
        # Counterfactual also passed -> delta subtraction did not break it -> ineffective
        return ReconciliationFact(
            transition=CausalTransition.UNVERIFIED_COUNTERFACTUAL_INEFFECTIVE,
            verdict=PreliminaryVerdict.INCONCLUSIVE,
            is_causally_verified=False,
            rationale=(
                "COUNTERFACTUAL passed under witness after delta subtraction; "
                "subtracted region was not causally necessary for the fix."
            ),
        )

    # Fail closed for any unhandled combination
    return ReconciliationFact(
        transition=CausalTransition.NON_VERIFIED_EXECUTION_ERROR,
        verdict=PreliminaryVerdict.INCONCLUSIVE,
        is_causally_verified=False,
        rationale=(
            f"Unhandled outcome triplet: BASE={base_outcome.value}, "
            f"CANDIDATE={candidate_outcome.value}, "
            f"COUNTERFACTUAL={counterfactual_outcome.value}"
        ),
    )
