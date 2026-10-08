"""Deterministic FEATURE verification semantics: ABSENT -> PRESENT.

P-13.01: FEATURE ABSENT->PRESENT verifier.

Core Invariants:
1. Invariant truth: Under FEATURE, the ONLY positive transition is:
   BASE = ABSENT, CANDIDATE = PRESENT -> FEATURE_VERIFIED (PreliminaryVerdict.VERIFIED).
2. Anti-collapse:
   - Arbitrary test failure (crashes, syntax errors, unrelated exceptions) must NEVER
     collapse into ABSENT.
   - ABSENT != FAIL unless the FEATURE contract explicitly defines absence mechanically.
   - BASE=PRESENT, CANDIDATE=PRESENT -> UNVERIFIED_FEATURE_ALREADY_PRESENT (INCONCLUSIVE).
   - BASE=ABSENT, CANDIDATE=ABSENT -> UNVERIFIED_FEATURE_NOT_IMPLEMENTED (CONTRADICTED).
   - BASE=PRESENT, CANDIDATE=ABSENT -> UNVERIFIED_FEATURE_REGRESSION (CONTRADICTED).
3. Bounded absence evidence: Absence must be mechanically demonstrated via:
   SYMBOL_NOT_FOUND, INPUT_REJECTED_AS_UNSUPPORTED, PROPERTY_UNAVAILABLE,
   MECHANICAL_EXIT_CODE, or STRUCTURED_ABSENCE_ASSERTION.
4. Frozen contract authority: The contract must be frozen as ChangeClass.FEATURE;
   mismatched change-class invocation fails closed with ChangeClassMismatchError.
5. Zero model authority: Model explanations never override deterministic execution facts.
"""

from __future__ import annotations

import re
from dataclasses import dataclass
from enum import Enum
from typing import Any

from basebreak.causal.receipt import WorldExecutionFact
from basebreak.causal.reconciliation import (
    CausalTransition,
    ChangeClassMismatchError,
    ReconciliationFact,
)
from basebreak.causal.semantic_receipt import (
    SemanticVerificationReceipt,
    create_semantic_receipt,
)
from basebreak.compiler.freeze import FrozenContract
from basebreak.domain.causal import ExecutionWorld
from basebreak.domain.execution import TerminationStatus
from basebreak.domain.semantics import ChangeClass
from basebreak.domain.verdict import EvidenceProvenance, PreliminaryVerdict
from basebreak.verifier.context import VerifierContextEnvelope
from basebreak.verifier.vacuity import VacuityCheckResult
from basebreak.verifier.witness_lock import (
    ImmutableWitnessLock,
    verify_witness_lock_chain,
)
from basebreak.verifier.witness_result import NormalizedWitnessResult, WitnessOutcome
from basebreak.verifier.witness_store import SealedWitnessRecord


class FeatureState(str, Enum):
    """Deterministic observed state of a feature capability."""

    ABSENT = "ABSENT"
    PRESENT = "PRESENT"
    ERROR = "ERROR"
    TIMEOUT = "TIMEOUT"
    INVALID_PRECONDITION = "INVALID_PRECONDITION"


class FeatureAbsenceMechanism(str, Enum):
    """Mechanisms through which capability absence is mechanically demonstrated."""

    SYMBOL_NOT_FOUND = "SYMBOL_NOT_FOUND"
    INPUT_REJECTED_AS_UNSUPPORTED = "INPUT_REJECTED_AS_UNSUPPORTED"
    PROPERTY_UNAVAILABLE = "PROPERTY_UNAVAILABLE"
    MECHANICAL_EXIT_CODE = "MECHANICAL_EXIT_CODE"
    STRUCTURED_ABSENCE_ASSERTION = "STRUCTURED_ABSENCE_ASSERTION"


# Common patterns that mechanically indicate absence for each mechanism
_ABSENCE_PATTERNS: dict[FeatureAbsenceMechanism, list[re.Pattern[str]]] = {
    FeatureAbsenceMechanism.SYMBOL_NOT_FOUND: [
        re.compile(r"AttributeError:.*has no attribute", re.IGNORECASE),
        re.compile(r"NameError: name '.*' is not defined", re.IGNORECASE),
        re.compile(r"ImportError: cannot import name", re.IGNORECASE),
        re.compile(r"ModuleNotFoundError", re.IGNORECASE),
        re.compile(r"404 Not Found", re.IGNORECASE),
        re.compile(r"Cannot find symbol", re.IGNORECASE),
    ],
    FeatureAbsenceMechanism.INPUT_REJECTED_AS_UNSUPPORTED: [
        re.compile(r"NotImplementedError", re.IGNORECASE),
        re.compile(r"501 Not Implemented", re.IGNORECASE),
        re.compile(r"unsupported operand type", re.IGNORECASE),
        re.compile(r"unsupported parameter", re.IGNORECASE),
        re.compile(r"feature not supported", re.IGNORECASE),
        re.compile(r"not implemented", re.IGNORECASE),
    ],
    FeatureAbsenceMechanism.PROPERTY_UNAVAILABLE: [
        re.compile(r"KeyError:", re.IGNORECASE),
        re.compile(r"property '.*' is unavailable", re.IGNORECASE),
        re.compile(r"feature flag is disabled or absent", re.IGNORECASE),
        re.compile(r"unknown field", re.IGNORECASE),
    ],
    FeatureAbsenceMechanism.MECHANICAL_EXIT_CODE: [
        re.compile(r"command not found", re.IGNORECASE),
        re.compile(r"unrecognized option", re.IGNORECASE),
        re.compile(r"invalid command", re.IGNORECASE),
    ],
    FeatureAbsenceMechanism.STRUCTURED_ABSENCE_ASSERTION: [
        re.compile(r"FEATURE_ABSENT", re.IGNORECASE),
        re.compile(r"ASSERTION_ABSENCE_VERIFIED", re.IGNORECASE),
    ],
}


@dataclass(frozen=True, slots=True)
class FeatureObservation:
    """Immutable, bounded observation of a feature's presence or absence in a world."""

    world: ExecutionWorld
    state: FeatureState
    absence_mechanism: FeatureAbsenceMechanism | None
    evidence_detail: str
    exit_code: int | None
    stdout_digest: str
    stderr_digest: str

    def __post_init__(self) -> None:
        if not isinstance(self.world, ExecutionWorld):
            raise TypeError(f"world must be ExecutionWorld, got {type(self.world).__name__}")
        if not isinstance(self.state, FeatureState):
            raise TypeError(f"state must be FeatureState, got {type(self.state).__name__}")
        if self.state == FeatureState.ABSENT and self.absence_mechanism is None:
            raise ValueError("absence_mechanism must be specified when state is ABSENT")
        if not isinstance(self.evidence_detail, str) or not self.evidence_detail.strip():
            raise ValueError("evidence_detail must be a non-empty string")


def detect_feature_state(
    *,
    world: ExecutionWorld,
    result: NormalizedWitnessResult,
    expected_absence_mechanism: FeatureAbsenceMechanism | None = None,
    absence_indicator_pattern: str | None = None,
) -> FeatureObservation:
    """Deterministically detect feature state from normalized witness execution facts.

    CRITICAL RULE:
    Do not collapse arbitrary test failure into ABSENT.
    If BASE fails with an arbitrary crash, syntax error, or unhandled exception
    that does NOT match the mechanically defined absence mechanism, it is ERROR,
    NOT ABSENT.
    """
    if not isinstance(world, ExecutionWorld):
        raise TypeError(f"world must be ExecutionWorld, got {type(world).__name__}")
    if not isinstance(result, NormalizedWitnessResult):
        raise TypeError(f"result must be NormalizedWitnessResult, got {type(result).__name__}")

    # 1. Termination / infrastructure states take precedence
    if (
        result.termination_status == TerminationStatus.TIMED_OUT
        or result.outcome == WitnessOutcome.TIMEOUT
    ):
        return FeatureObservation(
            world=world,
            state=FeatureState.TIMEOUT,
            absence_mechanism=None,
            evidence_detail="Witness execution timed out",
            exit_code=result.exit_code,
            stdout_digest=result.stdout_digest,
            stderr_digest=result.stderr_digest,
        )

    if result.outcome == WitnessOutcome.INVALID_PRECONDITION:
        return FeatureObservation(
            world=world,
            state=FeatureState.INVALID_PRECONDITION,
            absence_mechanism=None,
            evidence_detail="Execution precondition invalid (setup or import failure)",
            exit_code=result.exit_code,
            stdout_digest=result.stdout_digest,
            stderr_digest=result.stderr_digest,
        )

    if result.termination_status in (
        TerminationStatus.CANCELLED,
        TerminationStatus.FAILED_TO_START,
    ):
        return FeatureObservation(
            world=world,
            state=FeatureState.ERROR,
            absence_mechanism=None,
            evidence_detail=f"Execution terminated with {result.termination_status.value}",
            exit_code=result.exit_code,
            stdout_digest=result.stdout_digest,
            stderr_digest=result.stderr_digest,
        )

    combined_output = f"{result.stdout_clean}\n{result.stderr_clean}"

    # 2. Check for clean PASS (capability present)
    if result.outcome == WitnessOutcome.PASS and result.exit_code == 0:
        return FeatureObservation(
            world=world,
            state=FeatureState.PRESENT,
            absence_mechanism=None,
            evidence_detail="Feature execution passed cleanly (exit code 0)",
            exit_code=result.exit_code,
            stdout_digest=result.stdout_digest,
            stderr_digest=result.stderr_digest,
        )

    # 3. Check for mechanically established ABSENT
    # Only applicable when witness explicitly looks for absence or defines an absence mechanism
    if expected_absence_mechanism is not None:
        matched = False
        matched_detail = ""

        # Check explicit custom pattern if provided
        if absence_indicator_pattern is not None:
            pat = re.compile(absence_indicator_pattern, re.IGNORECASE)
            if pat.search(combined_output):
                matched = True
                matched_detail = f"Matched custom absence pattern: {absence_indicator_pattern}"

        # Check standard absence patterns for mechanism
        if not matched and expected_absence_mechanism in _ABSENCE_PATTERNS:
            for pat in _ABSENCE_PATTERNS[expected_absence_mechanism]:
                m = pat.search(combined_output)
                if m:
                    matched = True
                    matched_line = next(
                        (line.strip() for line in combined_output.splitlines() if pat.search(line)),
                        m.group(0).strip(),
                    )
                    matched_detail = f"Matched '{pat.pattern}': {matched_line}"
                    break

        # Check mechanical exit code mechanism (e.g. exit 127 or 2)
        if (
            not matched
            and expected_absence_mechanism == FeatureAbsenceMechanism.MECHANICAL_EXIT_CODE
        ):
            if result.exit_code in (2, 127):
                matched = True
                matched_detail = f"Mechanical absence exit code: {result.exit_code}"

        if matched:
            detail_msg = (
                f"Capability mechanically demonstrated ABSENT via "
                f"{expected_absence_mechanism.value}: {matched_detail}"
            )
            return FeatureObservation(
                world=world,
                state=FeatureState.ABSENT,
                absence_mechanism=expected_absence_mechanism,
                evidence_detail=detail_msg,
                exit_code=result.exit_code,
                stdout_digest=result.stdout_digest,
                stderr_digest=result.stderr_digest,
            )

    # 4. If execution failed (outcome FAIL or ERROR) but did NOT match mechanical absence:
    # Under anti-collapse invariant: DO NOT collapse arbitrary failure into ABSENT!
    if result.outcome in (WitnessOutcome.FAIL, WitnessOutcome.ERROR):
        return FeatureObservation(
            world=world,
            state=FeatureState.ERROR,
            absence_mechanism=None,
            evidence_detail=(
                f"Execution failed with exit code {result.exit_code} but did not demonstrate "
                f"mechanical absence; treated as ERROR to prevent collapse."
            ),
            exit_code=result.exit_code,
            stdout_digest=result.stdout_digest,
            stderr_digest=result.stderr_digest,
        )

    # Fallback fail closed
    return FeatureObservation(
        world=world,
        state=FeatureState.ERROR,
        absence_mechanism=None,
        evidence_detail="Unrecognized feature execution outcome",
        exit_code=result.exit_code,
        stdout_digest=result.stdout_digest,
        stderr_digest=result.stderr_digest,
    )


def reconcile_feature_transition(
    *,
    base_observation: FeatureObservation,
    candidate_observation: FeatureObservation,
    frozen_contract: FrozenContract | None = None,
    base_vacuity: VacuityCheckResult | None = None,
    candidate_vacuity: VacuityCheckResult | None = None,
    integrity_failure_reason: str | None = None,
) -> ReconciliationFact:
    """Deterministically reconcile BASE and CANDIDATE feature observations.

    Enforces:
    - Contract change_class must be ChangeClass.FEATURE if frozen_contract provided.
    - BASE=ABSENT and CANDIDATE=PRESENT is the ONLY positive transition -> FEATURE_VERIFIED.
    - All other combinations resolve to non-verified states.
    """
    if not isinstance(base_observation, FeatureObservation):
        raise TypeError(
            f"base_observation must be FeatureObservation, got {type(base_observation).__name__}"
        )
    if not isinstance(candidate_observation, FeatureObservation):
        cand_type = type(candidate_observation).__name__
        raise TypeError(f"candidate_observation must be FeatureObservation, got {cand_type}")

    # 0. Frozen contract change class check: fails closed on mismatch
    if frozen_contract is not None:
        if not isinstance(frozen_contract, FrozenContract):
            raise TypeError(
                f"frozen_contract must be FrozenContract, got {type(frozen_contract).__name__}"
            )
        if frozen_contract.change_class != ChangeClass.FEATURE:
            raise ChangeClassMismatchError(
                f"Contract change_class is {frozen_contract.change_class.value}, "
                f"expected ChangeClass.FEATURE for feature verification"
            )

    # 1. Cryptographic binding / integrity failure
    if integrity_failure_reason is not None and str(integrity_failure_reason).strip():
        reason = str(integrity_failure_reason).strip()
        return ReconciliationFact(
            transition=CausalTransition.NON_VERIFIED_TAMPERING_OR_INTEGRITY_FAILURE,
            verdict=PreliminaryVerdict.CONTRADICTED,
            is_causally_verified=False,
            rationale=f"Cryptographic binding or integrity check failed: {reason}",
        )

    # 2. Vacuity checks
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
        base_observation.state == FeatureState.INVALID_PRECONDITION
        or candidate_observation.state == FeatureState.INVALID_PRECONDITION
    ):
        return ReconciliationFact(
            transition=CausalTransition.NON_VERIFIED_INVALID_PRECONDITION,
            verdict=PreliminaryVerdict.BLOCKED,
            is_causally_verified=False,
            rationale="Feature execution precondition invalid",
        )

    # 4. Timeout outcomes
    if (
        base_observation.state == FeatureState.TIMEOUT
        or candidate_observation.state == FeatureState.TIMEOUT
    ):
        return ReconciliationFact(
            transition=CausalTransition.NON_VERIFIED_TIMEOUT,
            verdict=PreliminaryVerdict.INCONCLUSIVE,
            is_causally_verified=False,
            rationale=(
                f"Feature execution timed out (BASE: {base_observation.state.value}, "
                f"CANDIDATE: {candidate_observation.state.value})"
            ),
        )

    # 5. Execution errors
    if (
        base_observation.state == FeatureState.ERROR
        or candidate_observation.state == FeatureState.ERROR
    ):
        return ReconciliationFact(
            transition=CausalTransition.NON_VERIFIED_EXECUTION_ERROR,
            verdict=PreliminaryVerdict.INCONCLUSIVE,
            is_causally_verified=False,
            rationale=(
                f"Feature execution encountered error (BASE: {base_observation.state.value}, "
                f"CANDIDATE: {candidate_observation.state.value}). "
                f"BASE detail: {base_observation.evidence_detail}; "
                f"CANDIDATE detail: {candidate_observation.evidence_detail}"
            ),
        )

    # 6. Behavioral transitions
    # 6a. BASE=ABSENT, CANDIDATE=PRESENT -> Sole positive transition
    if (
        base_observation.state == FeatureState.ABSENT
        and candidate_observation.state == FeatureState.PRESENT
    ):
        mech = (
            base_observation.absence_mechanism.value
            if base_observation.absence_mechanism
            else "UNKNOWN"
        )
        return ReconciliationFact(
            transition=CausalTransition.FEATURE_VERIFIED,
            verdict=PreliminaryVerdict.VERIFIED,
            is_causally_verified=True,
            rationale=(
                f"Feature capability verified: BASE demonstrated capability ABSENT via {mech}; "
                f"CANDIDATE demonstrated capability PRESENT."
            ),
        )

    # 6b. BASE=PRESENT, CANDIDATE=PRESENT -> Trivial/already present
    if (
        base_observation.state == FeatureState.PRESENT
        and candidate_observation.state == FeatureState.PRESENT
    ):
        return ReconciliationFact(
            transition=CausalTransition.UNVERIFIED_FEATURE_ALREADY_PRESENT,
            verdict=PreliminaryVerdict.INCONCLUSIVE,
            is_causally_verified=False,
            rationale=(
                "Capability was already PRESENT on BASE before patch; "
                "patch was not causally necessary."
            ),
        )

    # 6c. BASE=ABSENT, CANDIDATE=ABSENT -> Defect persists / feature not implemented
    if (
        base_observation.state == FeatureState.ABSENT
        and candidate_observation.state == FeatureState.ABSENT
    ):
        return ReconciliationFact(
            transition=CausalTransition.UNVERIFIED_FEATURE_NOT_IMPLEMENTED,
            verdict=PreliminaryVerdict.CONTRADICTED,
            is_causally_verified=False,
            rationale="Capability remains ABSENT on CANDIDATE; feature not implemented.",
        )

    # 6d. BASE=PRESENT, CANDIDATE=ABSENT -> Regression
    if (
        base_observation.state == FeatureState.PRESENT
        and candidate_observation.state == FeatureState.ABSENT
    ):
        return ReconciliationFact(
            transition=CausalTransition.UNVERIFIED_FEATURE_REGRESSION,
            verdict=PreliminaryVerdict.CONTRADICTED,
            is_causally_verified=False,
            rationale=(
                "Capability was PRESENT on BASE but became ABSENT on CANDIDATE; feature regression."
            ),
        )

    # Fail closed for any other permutation
    return ReconciliationFact(
        transition=CausalTransition.NON_VERIFIED_EXECUTION_ERROR,
        verdict=PreliminaryVerdict.INCONCLUSIVE,
        is_causally_verified=False,
        rationale=(
            f"Unhandled feature state combination: BASE={base_observation.state.value}, "
            f"CANDIDATE={candidate_observation.state.value}"
        ),
    )


def verify_feature(
    *,
    context_envelope: VerifierContextEnvelope,
    sealed_record: SealedWitnessRecord,
    witness_lock: ImmutableWitnessLock,
    base_result: NormalizedWitnessResult,
    candidate_result: NormalizedWitnessResult,
    base_tree_digest: str,
    candidate_tree_digest: str,
    expected_absence_mechanism: FeatureAbsenceMechanism,
    absence_indicator_pattern: str | None = None,
    base_vacuity: VacuityCheckResult | None = None,
    candidate_vacuity: VacuityCheckResult | None = None,
    provenance: EvidenceProvenance = EvidenceProvenance.LOCAL_EXECUTION,
) -> SemanticVerificationReceipt:
    """Coordinate deterministic FEATURE verification and generate tamper-proof receipt.

    Binds:
    - contract change_class == ChangeClass.FEATURE
    - witness lock unbroken chain
    - BASE observation (ABSENT)
    - CANDIDATE observation (PRESENT)
    - deterministic reconciliation
    - SemanticVerificationReceipt
    """
    # Step 1: Validate contract change_class
    if context_envelope.frozen_contract.change_class != ChangeClass.FEATURE:
        raise ChangeClassMismatchError(
            f"Contract change_class is {context_envelope.frozen_contract.change_class.value}, "
            f"expected ChangeClass.FEATURE"
        )

    # Step 2: Validate witness lock chain of custody
    verify_witness_lock_chain(
        lock=witness_lock,
        frozen_contract=context_envelope.frozen_contract,
        base_record=sealed_record,
        candidate_record=sealed_record,
    )

    # Step 3: Integrity checks
    integrity_failure_reason: str | None = None

    if base_result.sandbox_id == candidate_result.sandbox_id:
        integrity_failure_reason = "BASE and CANDIDATE reused the same sandbox identity"

    if base_tree_digest.lower() == candidate_tree_digest.lower():
        integrity_failure_reason = (
            "Candidate tree digest is identical to base tree digest (empty patch)"
        )

    # Step 4: Detect feature states on both worlds
    base_obs = detect_feature_state(
        world=ExecutionWorld.BASE,
        result=base_result,
        expected_absence_mechanism=expected_absence_mechanism,
        absence_indicator_pattern=absence_indicator_pattern,
    )
    cand_obs = detect_feature_state(
        world=ExecutionWorld.CANDIDATE,
        result=candidate_result,
        expected_absence_mechanism=expected_absence_mechanism,
        absence_indicator_pattern=absence_indicator_pattern,
    )

    # Step 5: Reconcile transition
    reconciliation = reconcile_feature_transition(
        base_observation=base_obs,
        candidate_observation=cand_obs,
        frozen_contract=context_envelope.frozen_contract,
        base_vacuity=base_vacuity,
        candidate_vacuity=candidate_vacuity,
        integrity_failure_reason=integrity_failure_reason,
    )

    # Step 6: Create execution facts
    base_exec = WorldExecutionFact.from_normalized_result(
        base_result,
        tree_digest=base_tree_digest,
    )
    candidate_exec = WorldExecutionFact.from_normalized_result(
        candidate_result,
        tree_digest=candidate_tree_digest,
    )

    class_payload: dict[str, Any] = {
        "absence_mechanism": expected_absence_mechanism.value,
        "base_state": base_obs.state.value,
        "base_evidence_detail": base_obs.evidence_detail,
        "candidate_state": cand_obs.state.value,
        "candidate_evidence_detail": cand_obs.evidence_detail,
    }

    # Step 7: Build and return authentic SemanticVerificationReceipt
    return create_semantic_receipt(
        change_class=ChangeClass.FEATURE,
        requirement_id=sealed_record.requirement_id,
        frozen_contract_digest=context_envelope.frozen_contract.contract_digest,
        witness_id=sealed_record.witness_id,
        witness_digest=sealed_record.seal_digest,
        lock_digest=witness_lock.lock_digest,
        source_commit_id=context_envelope.source_identity.resolved_commit_id,
        candidate_tree_digest=candidate_tree_digest,
        base_execution=base_exec,
        candidate_execution=candidate_exec,
        class_specific_payload=class_payload,
        transition=reconciliation.transition,
        verdict=reconciliation.verdict,
        is_causally_verified=reconciliation.is_causally_verified,
        provenance=provenance,
        narrative=reconciliation.rationale,
    )
