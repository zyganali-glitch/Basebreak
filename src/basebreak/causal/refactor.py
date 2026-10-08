"""Deterministic REFACTOR verification semantics: BEFORE ≡ AFTER.

P-13.03: REFACTOR behavioral-equivalence verifier.

Core Invariants:
1. Invariant truth: Under REFACTOR, the ONLY positive transition is:
   BASE ≡ CANDIDATE under sealed witness -> REFACTOR_VERIFIED (PreliminaryVerdict.VERIFIED).
2. Bounded behavioral equivalence:
   - Verification certifies strictly: "behaviorally equivalent under tested witness".
   - Universal semantic equivalence claims ("formally equivalent program") are STRICTLY FORBIDDEN.
3. Rejection of deviations:
   - Changed externally observable required output -> UNVERIFIED_BEHAVIOR_CHANGED.
   - Changed exit semantics -> UNVERIFIED_EXIT_SEMANTICS_CHANGED.
   - Changed specified side effects -> UNVERIFIED_BEHAVIOR_CHANGED.
   - Base failure under witness -> UNVERIFIED_BASE_FAILED.
   - Incomplete execution, crash, or timeout -> NON_VERIFIED_EXECUTION_ERROR / NON_VERIFIED_TIMEOUT.
4. Frozen contract authority: The contract must be frozen as ChangeClass.REFACTOR;
   mismatched change-class invocation fails closed with ChangeClassMismatchError.
5. Zero model authority: Deterministic output hashes and exit codes govern equivalence;
   model prose cannot override observed behavioral discrepancies.
"""

from __future__ import annotations

import hashlib
from dataclasses import dataclass
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

# Canonical bounded claim phrasing mandated by architecture rules
BOUNDED_EQUIVALENCE_CLAIM = "behaviorally equivalent under tested witness"
FORBIDDEN_UNIVERSAL_CLAIM = "formally equivalent program"


@dataclass(frozen=True, slots=True)
class RefactorObservation:
    """Deterministic behavioral observation of an execution world under tested witness."""

    world: ExecutionWorld
    witness_outcome: WitnessOutcome
    termination_status: TerminationStatus
    exit_code: int | None
    output_digest: str
    side_effect_digest: str | None
    is_successful: bool
    execution_error: str | None = None

    def __post_init__(self) -> None:
        if not isinstance(self.world, ExecutionWorld):
            raise TypeError(f"world must be ExecutionWorld, got {type(self.world).__name__}")
        if not isinstance(self.witness_outcome, WitnessOutcome):
            raise TypeError(
                f"witness_outcome must be WitnessOutcome, got {type(self.witness_outcome).__name__}"
            )
        if not isinstance(self.output_digest, str) or len(self.output_digest) != 64:
            raise ValueError(
                f"output_digest must be a 64-char sha256 hex string, got {self.output_digest!r}"
            )


def compute_output_digest(stdout: str, stderr: str) -> str:
    """Compute deterministic SHA-256 digest of normalized combined execution streams."""
    normalized_stdout = stdout.replace("\r\n", "\n").rstrip()
    normalized_stderr = stderr.replace("\r\n", "\n").rstrip()
    combined = f"{normalized_stdout}\n---STDERR---\n{normalized_stderr}".encode("utf-8")
    return hashlib.sha256(combined).hexdigest()


def detect_refactor_observation(
    *,
    world: ExecutionWorld,
    result: NormalizedWitnessResult,
    side_effect_digest: str | None = None,
) -> RefactorObservation:
    """Extract deterministic behavioral observation for a refactor execution world."""
    output_digest = compute_output_digest(result.stdout_clean, result.stderr_clean)

    # Determine if execution succeeded cleanly
    is_clean_success = (
        result.outcome == WitnessOutcome.PASS
        and result.exit_code == 0
        and result.termination_status == TerminationStatus.COMPLETED
    )

    err_msg: str | None = None
    if result.termination_status == TerminationStatus.TIMED_OUT:
        err_msg = "Process timed out"
    elif result.termination_status in (
        TerminationStatus.CANCELLED,
        TerminationStatus.FAILED_TO_START,
    ):
        err_msg = f"Abnormal process termination: {result.termination_status.value}"
    elif result.exit_code != 0:
        err_msg = f"Non-zero exit code: {result.exit_code}"

    return RefactorObservation(
        world=world,
        witness_outcome=result.outcome,
        termination_status=result.termination_status,
        exit_code=result.exit_code,
        output_digest=output_digest,
        side_effect_digest=side_effect_digest,
        is_successful=is_clean_success,
        execution_error=err_msg,
    )


def reconcile_refactor_transition(
    *,
    base_obs: RefactorObservation,
    candidate_obs: RefactorObservation,
    frozen_contract: FrozenContract,
    base_vacuity: VacuityCheckResult | None = None,
    candidate_vacuity: VacuityCheckResult | None = None,
    integrity_failure_reason: str | None = None,
) -> ReconciliationFact:
    """Deterministically reconcile REFACTOR behavioral observations between BASE and CANDIDATE.

    Invariants:
    1. Integrity failures fail closed.
    2. Vacuous witnesses fail closed.
    3. Timeouts on either world fail closed as NON_VERIFIED_TIMEOUT.
    4. Execution crashes/infrastructure errors fail closed as NON_VERIFIED_EXECUTION_ERROR.
    5. BASE failure -> UNVERIFIED_BASE_FAILED (refactor requires a working baseline).
    6. Exit code / termination status divergence -> UNVERIFIED_EXIT_SEMANTICS_CHANGED.
    7. Output digest or side-effect divergence -> UNVERIFIED_BEHAVIOR_CHANGED.
    8. Candidate failure -> UNVERIFIED_BEHAVIOR_CHANGED.
    9. Exact equivalence across all observable dimensions -> REFACTOR_VERIFIED.
    """
    # 1. Integrity check
    if integrity_failure_reason:
        return ReconciliationFact(
            transition=CausalTransition.NON_VERIFIED_TAMPERING_OR_INTEGRITY_FAILURE,
            verdict=PreliminaryVerdict.CONTRADICTED,
            is_causally_verified=False,
            rationale=f"Integrity check failed: {integrity_failure_reason}",
        )

    # 2. Vacuity check
    if base_vacuity and base_vacuity.is_vacuous:
        return ReconciliationFact(
            transition=CausalTransition.NON_VERIFIED_VACUOUS,
            verdict=PreliminaryVerdict.INCONCLUSIVE,
            is_causally_verified=False,
            rationale=f"BASE witness execution was vacuous: {base_vacuity.details}",
        )
    if candidate_vacuity and candidate_vacuity.is_vacuous:
        return ReconciliationFact(
            transition=CausalTransition.NON_VERIFIED_VACUOUS,
            verdict=PreliminaryVerdict.INCONCLUSIVE,
            is_causally_verified=False,
            rationale=f"CANDIDATE witness execution was vacuous: {candidate_vacuity.details}",
        )

    # 3. Timeout check
    if (
        base_obs.termination_status == TerminationStatus.TIMED_OUT
        or candidate_obs.termination_status == TerminationStatus.TIMED_OUT
    ):
        return ReconciliationFact(
            transition=CausalTransition.NON_VERIFIED_TIMEOUT,
            verdict=PreliminaryVerdict.INCONCLUSIVE,
            is_causally_verified=False,
            rationale="Witness execution timed out on one or more execution worlds.",
        )

    # 4. Infrastructure / abnormal termination check
    abnormal_statuses = (
        TerminationStatus.CANCELLED,
        TerminationStatus.FAILED_TO_START,
    )
    if (
        base_obs.termination_status in abnormal_statuses
        or candidate_obs.termination_status in abnormal_statuses
    ):
        return ReconciliationFact(
            transition=CausalTransition.NON_VERIFIED_EXECUTION_ERROR,
            verdict=PreliminaryVerdict.INCONCLUSIVE,
            is_causally_verified=False,
            rationale=(
                f"Abnormal execution status detected (BASE={base_obs.termination_status.value}, "
                f"CANDIDATE={candidate_obs.termination_status.value})."
            ),
        )

    # 5. Base must pass cleanly to serve as a valid refactoring baseline
    if not base_obs.is_successful:
        return ReconciliationFact(
            transition=CausalTransition.UNVERIFIED_BASE_FAILED,
            verdict=PreliminaryVerdict.INCONCLUSIVE,
            is_causally_verified=False,
            rationale=(
                f"BASE world failed under witness (outcome={base_obs.witness_outcome.value}, "
                f"exit_code={base_obs.exit_code}). "
                f"Refactor verification requires a passing baseline."
            ),
        )

    # 6. Exit semantics check: candidate exit status must match base exactly
    if (
        candidate_obs.exit_code != base_obs.exit_code
        or candidate_obs.termination_status != base_obs.termination_status
    ):
        return ReconciliationFact(
            transition=CausalTransition.UNVERIFIED_EXIT_SEMANTICS_CHANGED,
            verdict=PreliminaryVerdict.CONTRADICTED,
            is_causally_verified=False,
            rationale=(
                f"Candidate exit semantics diverged from baseline: "
                f"BASE exit={base_obs.exit_code} ({base_obs.termination_status.value}), "
                f"CANDIDATE exit={candidate_obs.exit_code} "
                f"({candidate_obs.termination_status.value})."
            ),
        )

    # 7. Output behavioral equivalence check
    if candidate_obs.output_digest != base_obs.output_digest:
        return ReconciliationFact(
            transition=CausalTransition.UNVERIFIED_BEHAVIOR_CHANGED,
            verdict=PreliminaryVerdict.CONTRADICTED,
            is_causally_verified=False,
            rationale=(
                f"Candidate observable output diverged from baseline: "
                f"BASE output_digest={base_obs.output_digest[:16]}..., "
                f"CANDIDATE output_digest={candidate_obs.output_digest[:16]}..."
            ),
        )

    # 8. Side effect equivalence check (if specified)
    if (
        base_obs.side_effect_digest is not None or candidate_obs.side_effect_digest is not None
    ) and base_obs.side_effect_digest != candidate_obs.side_effect_digest:
        return ReconciliationFact(
            transition=CausalTransition.UNVERIFIED_BEHAVIOR_CHANGED,
            verdict=PreliminaryVerdict.CONTRADICTED,
            is_causally_verified=False,
            rationale=(
                f"Candidate observable side effects diverged from baseline: "
                f"BASE side_effect={base_obs.side_effect_digest!r}, "
                f"CANDIDATE side_effect={candidate_obs.side_effect_digest!r}."
            ),
        )

    # 9. Candidate must have passed cleanly as well
    if not candidate_obs.is_successful:
        return ReconciliationFact(
            transition=CausalTransition.UNVERIFIED_BEHAVIOR_CHANGED,
            verdict=PreliminaryVerdict.CONTRADICTED,
            is_causally_verified=False,
            rationale=(
                f"Candidate witness outcome={candidate_obs.witness_outcome.value} "
                f"does not match baseline success."
            ),
        )

    # 10. Clean positive transition: BEFORE ≡ AFTER under tested witness
    return ReconciliationFact(
        transition=CausalTransition.REFACTOR_VERIFIED,
        verdict=PreliminaryVerdict.VERIFIED,
        is_causally_verified=True,
        rationale=(
            f"Candidate is {BOUNDED_EQUIVALENCE_CLAIM} (BEFORE ≡ AFTER). "
            f"Output digests and exit semantics match exactly across worlds."
        ),
    )


def verify_refactor(
    *,
    context_envelope: VerifierContextEnvelope,
    sealed_record: SealedWitnessRecord,
    witness_lock: ImmutableWitnessLock,
    base_result: NormalizedWitnessResult,
    candidate_result: NormalizedWitnessResult,
    base_tree_digest: str,
    candidate_tree_digest: str,
    base_side_effect_digest: str | None = None,
    candidate_side_effect_digest: str | None = None,
    base_vacuity: VacuityCheckResult | None = None,
    candidate_vacuity: VacuityCheckResult | None = None,
    provenance: EvidenceProvenance = EvidenceProvenance.LOCAL_EXECUTION,
) -> SemanticVerificationReceipt:
    """Coordinate deterministic REFACTOR verification and generate tamper-proof receipt.

    Binds:
    - contract change_class == ChangeClass.REFACTOR
    - witness lock unbroken chain of custody
    - BASE behavioral observation
    - CANDIDATE behavioral observation
    - deterministic reconciliation
    - bounded behavioral equivalence claim
    - SemanticVerificationReceipt
    """
    # Step 1: Validate contract change_class
    if context_envelope.frozen_contract.change_class != ChangeClass.REFACTOR:
        raise ChangeClassMismatchError(
            f"Contract change_class is {context_envelope.frozen_contract.change_class.value}, "
            f"expected ChangeClass.REFACTOR"
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

    # Step 4: Detect behavioral observations
    base_obs = detect_refactor_observation(
        world=ExecutionWorld.BASE,
        result=base_result,
        side_effect_digest=base_side_effect_digest,
    )
    cand_obs = detect_refactor_observation(
        world=ExecutionWorld.CANDIDATE,
        result=candidate_result,
        side_effect_digest=candidate_side_effect_digest,
    )

    # Step 5: Reconcile refactor transition
    reconciliation = reconcile_refactor_transition(
        base_obs=base_obs,
        candidate_obs=cand_obs,
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
        "equivalence_claim": BOUNDED_EQUIVALENCE_CLAIM,
        "disclaimed_universal_claim": FORBIDDEN_UNIVERSAL_CLAIM,
        "base_output_digest": base_obs.output_digest,
        "candidate_output_digest": cand_obs.output_digest,
        "output_match": base_obs.output_digest == cand_obs.output_digest,
        "exit_semantics_match": (
            base_obs.exit_code == cand_obs.exit_code
            and base_obs.termination_status == cand_obs.termination_status
        ),
        "side_effects_match": (base_obs.side_effect_digest == cand_obs.side_effect_digest),
    }

    # Step 7: Build and return authentic SemanticVerificationReceipt
    return create_semantic_receipt(
        change_class=ChangeClass.REFACTOR,
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
