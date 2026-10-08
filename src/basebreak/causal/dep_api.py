"""Deterministic DEP/API CHANGE verification semantics: New Contract + Regression Safety.

P-13.05: DEP/API contract migration and regression verifier.

Core Invariants:
1. Dual verification requirement:
   - New contract / API behavior must be mechanically demonstrated and satisfied on CANDIDATE.
   - Bounded regression safety for preserved legacy / baseline behavior must be proven.
2. Anti-collapse invariants:
   - New contract fails -> UNVERIFIED_NEW_CONTRACT_FAILED (CONTRADICTED).
   - Preserved behavior regresses -> UNVERIFIED_REGRESSION_DETECTED (CONTRADICTED).
   - Timeout -> NON_VERIFIED_TIMEOUT (INCONCLUSIVE).
   - Abnormal crash -> NON_VERIFIED_EXECUTION_ERROR (INCONCLUSIVE).
3. Contract authority over removal:
   - Disappearance of old behavior is NEVER treated as acceptable unless the frozen contract
     explicitly permits breaking removal (allow_breaking_removal=True).
4. Frozen contract authority: The contract must be frozen as ChangeClass.DEP_API_CHANGE;
   mismatched change-class invocation fails closed with ChangeClassMismatchError.
5. Zero model authority: Model explanations cannot override contract execution facts.
"""

from __future__ import annotations

from dataclasses import dataclass, field
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


class DepApiChangeType(str, Enum):
    """Category of dependency or API transition."""

    DEPENDENCY_UPGRADE = "DEPENDENCY_UPGRADE"
    API_RENAME_OR_MIGRATION = "API_RENAME_OR_MIGRATION"
    PAYLOAD_OR_SCHEMA_TRANSITION = "PAYLOAD_OR_SCHEMA_TRANSITION"
    INTERFACE_MODERNIZATION = "INTERFACE_MODERNIZATION"


@dataclass(frozen=True, slots=True)
class MigrationSpecification:
    """Specification of dependency/API change contract."""

    change_type: DepApiChangeType
    target_dependency_or_api: str
    new_version_or_signature: str
    old_version_or_signature: str | None = None
    allow_breaking_removal: bool = False
    metadata: dict[str, str] = field(default_factory=dict)

    def __post_init__(self) -> None:
        if not self.target_dependency_or_api.strip():
            raise ValueError("target_dependency_or_api must be non-empty")
        if not self.new_version_or_signature.strip():
            raise ValueError("new_version_or_signature must be non-empty")


@dataclass(frozen=True, slots=True)
class DepApiObservation:
    """Deterministic observation of new contract and regression safety on an execution world."""

    world: ExecutionWorld
    new_contract_outcome: WitnessOutcome
    new_contract_exit_code: int | None
    regression_outcome: WitnessOutcome
    regression_exit_code: int | None
    termination_status: TerminationStatus
    is_new_contract_satisfied: bool
    is_regression_safe: bool


def detect_dep_api_observation(
    *,
    world: ExecutionWorld,
    new_contract_result: NormalizedWitnessResult,
    regression_result: NormalizedWitnessResult,
) -> DepApiObservation:
    """Extract deterministic migration and regression observations."""
    new_satisfied = (
        new_contract_result.outcome == WitnessOutcome.PASS
        and new_contract_result.exit_code == 0
        and new_contract_result.termination_status == TerminationStatus.COMPLETED
    )

    reg_safe = (
        regression_result.outcome == WitnessOutcome.PASS
        and regression_result.exit_code == 0
        and regression_result.termination_status == TerminationStatus.COMPLETED
    )

    # Effective termination status: TIMED_OUT or abnormal takes precedence
    worst_status = TerminationStatus.COMPLETED
    for res in (new_contract_result, regression_result):
        if res.termination_status == TerminationStatus.TIMED_OUT:
            worst_status = TerminationStatus.TIMED_OUT
            break
        if res.termination_status in (
            TerminationStatus.CANCELLED,
            TerminationStatus.FAILED_TO_START,
        ):
            worst_status = res.termination_status

    return DepApiObservation(
        world=world,
        new_contract_outcome=new_contract_result.outcome,
        new_contract_exit_code=new_contract_result.exit_code,
        regression_outcome=regression_result.outcome,
        regression_exit_code=regression_result.exit_code,
        termination_status=worst_status,
        is_new_contract_satisfied=new_satisfied,
        is_regression_safe=reg_safe,
    )


def reconcile_dep_api_transition(
    *,
    base_obs: DepApiObservation,
    candidate_obs: DepApiObservation,
    migration_spec: MigrationSpecification,
    frozen_contract: FrozenContract,
    base_vacuity: VacuityCheckResult | None = None,
    candidate_vacuity: VacuityCheckResult | None = None,
    integrity_failure_reason: str | None = None,
) -> ReconciliationFact:
    """Reconcile DEP/API CHANGE new contract compliance and regression safety."""
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
            rationale=f"BASE regression witness was vacuous: {base_vacuity.details}",
        )
    if candidate_vacuity and candidate_vacuity.is_vacuous:
        return ReconciliationFact(
            transition=CausalTransition.NON_VERIFIED_VACUOUS,
            verdict=PreliminaryVerdict.INCONCLUSIVE,
            is_causally_verified=False,
            rationale=f"CANDIDATE migration witness was vacuous: {candidate_vacuity.details}",
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
            rationale="Witness execution timed out during DEP/API migration verification.",
        )

    # 4. Abnormal execution check
    abnormal = (TerminationStatus.CANCELLED, TerminationStatus.FAILED_TO_START)
    if base_obs.termination_status in abnormal or candidate_obs.termination_status in abnormal:
        return ReconciliationFact(
            transition=CausalTransition.NON_VERIFIED_EXECUTION_ERROR,
            verdict=PreliminaryVerdict.INCONCLUSIVE,
            is_causally_verified=False,
            rationale="Witness process terminated abnormally during migration verification.",
        )

    # 5. Candidate New Contract Check
    # Candidate MUST satisfy the new API / dependency contract
    if not candidate_obs.is_new_contract_satisfied:
        return ReconciliationFact(
            transition=CausalTransition.UNVERIFIED_NEW_CONTRACT_FAILED,
            verdict=PreliminaryVerdict.CONTRADICTED,
            is_causally_verified=False,
            rationale=(
                f"Candidate failed to satisfy new contract for "
                f"'{migration_spec.target_dependency_or_api}' "
                f"({migration_spec.new_version_or_signature}): "
                f"outcome={candidate_obs.new_contract_outcome.value}, "
                f"exit_code={candidate_obs.new_contract_exit_code}."
            ),
        )

    # 6. Candidate Regression Safety Check
    # Candidate MUST preserve required legacy / baseline behavior
    if not candidate_obs.is_regression_safe:
        return ReconciliationFact(
            transition=CausalTransition.UNVERIFIED_REGRESSION_DETECTED,
            verdict=PreliminaryVerdict.CONTRADICTED,
            is_causally_verified=False,
            rationale=(
                f"New contract succeeded, but regression was detected in preserved behavior: "
                f"outcome={candidate_obs.regression_outcome.value}, "
                f"exit_code={candidate_obs.regression_exit_code}."
            ),
        )

    # 7. Base Baseline Check
    if not base_obs.is_regression_safe:
        return ReconciliationFact(
            transition=CausalTransition.UNVERIFIED_REGRESSION_DETECTED,
            verdict=PreliminaryVerdict.INCONCLUSIVE,
            is_causally_verified=False,
            rationale=(
                f"BASE world failed regression suite (outcome="
                f"{base_obs.regression_outcome.value}); valid baseline required."
            ),
        )

    # 8. Clean positive transition: DEP_API_CHANGE_VERIFIED
    return ReconciliationFact(
        transition=CausalTransition.DEP_API_CHANGE_VERIFIED,
        verdict=PreliminaryVerdict.VERIFIED,
        is_causally_verified=True,
        rationale=(
            f"DEP/API change verified: New contract satisfied for "
            f"'{migration_spec.target_dependency_or_api}' "
            f"({migration_spec.new_version_or_signature}) "
            f"and regression suite passed with zero defects."
        ),
    )


def verify_dep_api_change(
    *,
    context_envelope: VerifierContextEnvelope,
    sealed_record: SealedWitnessRecord,
    witness_lock: ImmutableWitnessLock,
    base_new_contract_result: NormalizedWitnessResult,
    base_regression_result: NormalizedWitnessResult,
    candidate_new_contract_result: NormalizedWitnessResult,
    candidate_regression_result: NormalizedWitnessResult,
    migration_spec: MigrationSpecification,
    base_tree_digest: str,
    candidate_tree_digest: str,
    base_vacuity: VacuityCheckResult | None = None,
    candidate_vacuity: VacuityCheckResult | None = None,
    provenance: EvidenceProvenance = EvidenceProvenance.LOCAL_EXECUTION,
) -> SemanticVerificationReceipt:
    """Coordinate deterministic DEP/API CHANGE verification and generate tamper-proof receipt.

    Binds:
    - contract change_class == ChangeClass.DEP_API_CHANGE
    - witness lock unbroken chain of custody
    - new contract witness outcomes on BASE and CANDIDATE
    - regression suite witness outcomes on BASE and CANDIDATE
    - migration specification details
    - SemanticVerificationReceipt
    """
    # Step 1: Validate contract change_class
    if context_envelope.frozen_contract.change_class != ChangeClass.DEP_API_CHANGE:
        raise ChangeClassMismatchError(
            f"Contract change_class is {context_envelope.frozen_contract.change_class.value}, "
            f"expected ChangeClass.DEP_API_CHANGE"
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
    if candidate_new_contract_result.sandbox_id == base_new_contract_result.sandbox_id:
        integrity_failure_reason = "BASE and CANDIDATE reused the same sandbox identity"
    if base_tree_digest.lower() == candidate_tree_digest.lower():
        integrity_failure_reason = (
            "Candidate tree digest is identical to base tree digest (empty patch)"
        )

    # Step 4: Detect observations
    base_obs = detect_dep_api_observation(
        world=ExecutionWorld.BASE,
        new_contract_result=base_new_contract_result,
        regression_result=base_regression_result,
    )
    cand_obs = detect_dep_api_observation(
        world=ExecutionWorld.CANDIDATE,
        new_contract_result=candidate_new_contract_result,
        regression_result=candidate_regression_result,
    )

    # Step 5: Reconcile transition
    reconciliation = reconcile_dep_api_transition(
        base_obs=base_obs,
        candidate_obs=cand_obs,
        migration_spec=migration_spec,
        frozen_contract=context_envelope.frozen_contract,
        base_vacuity=base_vacuity,
        candidate_vacuity=candidate_vacuity,
        integrity_failure_reason=integrity_failure_reason,
    )

    # Step 6: Create execution facts
    base_exec = WorldExecutionFact.from_normalized_result(
        base_new_contract_result,
        tree_digest=base_tree_digest,
    )
    candidate_exec = WorldExecutionFact.from_normalized_result(
        candidate_new_contract_result,
        tree_digest=candidate_tree_digest,
    )

    class_payload: dict[str, Any] = {
        "change_type": migration_spec.change_type.value,
        "target_dependency_or_api": migration_spec.target_dependency_or_api,
        "old_version_or_signature": migration_spec.old_version_or_signature,
        "new_version_or_signature": migration_spec.new_version_or_signature,
        "allow_breaking_removal": migration_spec.allow_breaking_removal,
        "new_contract_satisfied": cand_obs.is_new_contract_satisfied,
        "regression_safe": cand_obs.is_regression_safe,
    }

    # Step 7: Build and return authentic SemanticVerificationReceipt
    return create_semantic_receipt(
        change_class=ChangeClass.DEP_API_CHANGE,
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
