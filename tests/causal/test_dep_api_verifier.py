"""Unit and adversarial tests for P-13.05 DEP/API contract migration and regression verifier."""

from __future__ import annotations

from dataclasses import replace

import pytest

from basebreak.causal.dep_api import (
    DepApiChangeType,
    MigrationSpecification,
    verify_dep_api_change,
)
from basebreak.causal.reconciliation import (
    CausalTransition,
    ChangeClassMismatchError,
)
from basebreak.causal.semantic_receipt import (
    SemanticReceiptTamperingError,
    verify_semantic_receipt_integrity,
)
from basebreak.compiler.freeze import FrozenContract, FrozenRequirement
from basebreak.compiler.semantics import CertaintyLevel
from basebreak.domain.causal import CandidateIdentity, ExecutionWorld
from basebreak.domain.execution import SandboxIdentity, TerminationStatus
from basebreak.domain.semantics import ChangeClass
from basebreak.domain.source import CommitRevision, SourceIdentity
from basebreak.domain.verdict import EvidenceProvenance, PreliminaryVerdict
from basebreak.verifier.context import VerifierContextEnvelope, VerifierExecutionPolicy
from basebreak.verifier.vacuity import VacuityCheckResult, VacuityStatus
from basebreak.verifier.witness_lock import ImmutableWitnessLock, create_witness_lock
from basebreak.verifier.witness_result import (
    NormalizedWitnessResult,
    WitnessOutcome,
    normalize_witness_execution,
)
from basebreak.verifier.witness_store import (
    SealedWitnessRecord,
    TrustedWitnessVault,
    WitnessArtifact,
)


def _make_dep_api_contract(
    change_class: ChangeClass = ChangeClass.DEP_API_CHANGE,
) -> FrozenContract:
    req = FrozenRequirement(
        requirement_id="REQ-DEP-001",
        statement=(
            "Migrate client SDK to v2 contract while maintaining legacy backward compatibility"
        ),
        citation="migrate client SDK to v2",
        citation_start=0,
        citation_end=25,
    )
    contract = object.__new__(FrozenContract)
    object.__setattr__(contract, "schema_version", "1.0.0")
    object.__setattr__(contract, "task_digest", "a" * 64)
    object.__setattr__(contract, "change_class", change_class)
    object.__setattr__(contract, "certainty", CertaintyLevel.CONFIDENT)
    object.__setattr__(contract, "requirements", (req,))
    object.__setattr__(contract, "contract_digest", "b" * 64)
    return contract


def _make_context_envelope(
    contract: FrozenContract,
    source_commit: str = "a" * 40,
    candidate_tree: str = "b" * 40,
) -> VerifierContextEnvelope:
    source_id = SourceIdentity(
        locator="https://github.com/test/repo.git",
        revision=CommitRevision(commit_id=source_commit),
    )
    cand_id = CandidateIdentity(
        candidate_id="cand-dep-1",
        source=source_id,
        patch_digest="c" * 64,
    )
    return VerifierContextEnvelope.create(
        frozen_contract=contract,
        source_identity=source_id,
        candidate_identity=cand_id,
        candidate_tree_digest=candidate_tree,
        execution_policy=VerifierExecutionPolicy(timeout_seconds=30),
    )


def _make_sealed_witness_and_lock(
    contract: FrozenContract,
    source_commit: str = "a" * 40,
    content: str = "def test_api(): pass",
) -> tuple[SealedWitnessRecord, ImmutableWitnessLock]:
    vault = TrustedWitnessVault()
    art = WitnessArtifact.from_text(
        path="tests/test_migration.py",
        content=content,
    )
    sealed = vault.seal_witness(
        witness_id="wit-dep-1",
        requirement_id=contract.requirements[0].requirement_id,
        frozen_contract_digest=contract.contract_digest,
        source_commit_id=source_commit,
        artifacts=(art,),
    )
    lock = create_witness_lock(record=sealed, vault=vault)
    return sealed, lock


def _make_result(
    outcome: WitnessOutcome = WitnessOutcome.PASS,
    stdout: str = "PASS",
    stderr: str = "",
    exit_code: int | None = 0,
    sandbox_id: str = "sbx-base",
    status: TerminationStatus = TerminationStatus.COMPLETED,
    world: ExecutionWorld = ExecutionWorld.BASE,
    witness_id: str = "wit-dep-1",
) -> NormalizedWitnessResult:
    sbx = SandboxIdentity(
        sandbox_id=sandbox_id,
        description="test sandbox",
    )
    return normalize_witness_execution(
        witness_id=witness_id,
        witness_digest="c" * 64,
        frozen_contract_digest="b" * 64,
        requirement_id="REQ-DEP-001",
        sandbox_identity=sbx,
        source_commit_id="a" * 40,
        world=world,
        status=status,
        exit_code=exit_code,
        stdout_raw=stdout,
        stderr_raw=stderr,
        duration_seconds=1.23,
        provenance=EvidenceProvenance.LOCAL_EXECUTION,
    )


def _make_spec() -> MigrationSpecification:
    return MigrationSpecification(
        change_type=DepApiChangeType.API_RENAME_OR_MIGRATION,
        target_dependency_or_api="api.v2.client",
        old_version_or_signature="api.v1.client",
        new_version_or_signature="api.v2.client",
        allow_breaking_removal=False,
    )


class TestDepApiVerifier:
    def test_dep_api_clean_verification_success(self) -> None:
        """New contract satisfied AND preserved regression suite passes cleanly."""
        contract = _make_dep_api_contract()
        envelope = _make_context_envelope(contract)
        sealed, lock = _make_sealed_witness_and_lock(contract)
        spec = _make_spec()

        base_new = _make_result(
            outcome=WitnessOutcome.FAIL,
            exit_code=1,
            sandbox_id="sbx-base-new",
            world=ExecutionWorld.BASE,
        )
        base_reg = _make_result(
            outcome=WitnessOutcome.PASS,
            exit_code=0,
            sandbox_id="sbx-base-reg",
            world=ExecutionWorld.BASE,
        )

        cand_new = _make_result(
            outcome=WitnessOutcome.PASS,
            exit_code=0,
            sandbox_id="sbx-cand-new",
            world=ExecutionWorld.CANDIDATE,
        )
        cand_reg = _make_result(
            outcome=WitnessOutcome.PASS,
            exit_code=0,
            sandbox_id="sbx-cand-reg",
            world=ExecutionWorld.CANDIDATE,
        )

        receipt = verify_dep_api_change(
            context_envelope=envelope,
            sealed_record=sealed,
            witness_lock=lock,
            base_new_contract_result=base_new,
            base_regression_result=base_reg,
            candidate_new_contract_result=cand_new,
            candidate_regression_result=cand_reg,
            migration_spec=spec,
            base_tree_digest="a" * 64,
            candidate_tree_digest="b" * 64,
        )

        assert receipt.transition == CausalTransition.DEP_API_CHANGE_VERIFIED
        assert receipt.verdict == PreliminaryVerdict.VERIFIED
        assert receipt.is_causally_verified is True
        assert receipt.change_class == ChangeClass.DEP_API_CHANGE
        assert receipt.class_specific_payload["new_contract_satisfied"] is True
        assert receipt.class_specific_payload["regression_safe"] is True

        assert verify_semantic_receipt_integrity(receipt) is True

    def test_new_contract_failed_rejected(self) -> None:
        """Candidate fails the new contract -> UNVERIFIED_NEW_CONTRACT_FAILED."""
        contract = _make_dep_api_contract()
        envelope = _make_context_envelope(contract)
        sealed, lock = _make_sealed_witness_and_lock(contract)
        spec = _make_spec()

        base_new = _make_result(sandbox_id="sbx-base-new", world=ExecutionWorld.BASE)
        base_reg = _make_result(sandbox_id="sbx-base-reg", world=ExecutionWorld.BASE)

        # Candidate fails new contract!
        cand_new = _make_result(
            outcome=WitnessOutcome.FAIL,
            exit_code=1,
            sandbox_id="sbx-cand-new",
            world=ExecutionWorld.CANDIDATE,
        )
        cand_reg = _make_result(
            outcome=WitnessOutcome.PASS,
            exit_code=0,
            sandbox_id="sbx-cand-reg",
            world=ExecutionWorld.CANDIDATE,
        )

        receipt = verify_dep_api_change(
            context_envelope=envelope,
            sealed_record=sealed,
            witness_lock=lock,
            base_new_contract_result=base_new,
            base_regression_result=base_reg,
            candidate_new_contract_result=cand_new,
            candidate_regression_result=cand_reg,
            migration_spec=spec,
            base_tree_digest="a" * 64,
            candidate_tree_digest="b" * 64,
        )

        assert receipt.transition == CausalTransition.UNVERIFIED_NEW_CONTRACT_FAILED
        assert receipt.verdict == PreliminaryVerdict.CONTRADICTED
        assert receipt.is_causally_verified is False
        assert receipt.class_specific_payload["new_contract_satisfied"] is False

    def test_regression_detected_rejected(self) -> None:
        """New contract passes, but regression breaks -> UNVERIFIED_REGRESSION_DETECTED."""
        contract = _make_dep_api_contract()
        envelope = _make_context_envelope(contract)
        sealed, lock = _make_sealed_witness_and_lock(contract)
        spec = _make_spec()

        base_new = _make_result(sandbox_id="sbx-base-new", world=ExecutionWorld.BASE)
        base_reg = _make_result(sandbox_id="sbx-base-reg", world=ExecutionWorld.BASE)

        # Candidate satisfies new contract, BUT regressed on legacy suite!
        cand_new = _make_result(
            outcome=WitnessOutcome.PASS,
            exit_code=0,
            sandbox_id="sbx-cand-new",
            world=ExecutionWorld.CANDIDATE,
        )
        cand_reg = _make_result(
            outcome=WitnessOutcome.FAIL,
            exit_code=1,
            sandbox_id="sbx-cand-reg",
            world=ExecutionWorld.CANDIDATE,
        )

        receipt = verify_dep_api_change(
            context_envelope=envelope,
            sealed_record=sealed,
            witness_lock=lock,
            base_new_contract_result=base_new,
            base_regression_result=base_reg,
            candidate_new_contract_result=cand_new,
            candidate_regression_result=cand_reg,
            migration_spec=spec,
            base_tree_digest="a" * 64,
            candidate_tree_digest="b" * 64,
        )

        assert receipt.transition == CausalTransition.UNVERIFIED_REGRESSION_DETECTED
        assert receipt.verdict == PreliminaryVerdict.CONTRADICTED
        assert receipt.is_causally_verified is False
        assert receipt.class_specific_payload["new_contract_satisfied"] is True
        assert receipt.class_specific_payload["regression_safe"] is False

    def test_base_regression_failed_inconclusive(self) -> None:
        """Base world failed regression suite -> Inconclusive baseline."""
        contract = _make_dep_api_contract()
        envelope = _make_context_envelope(contract)
        sealed, lock = _make_sealed_witness_and_lock(contract)
        spec = _make_spec()

        base_new = _make_result(sandbox_id="sbx-base-new", world=ExecutionWorld.BASE)
        base_reg = _make_result(
            outcome=WitnessOutcome.FAIL,
            exit_code=1,
            sandbox_id="sbx-base-reg",
            world=ExecutionWorld.BASE,
        )

        cand_new = _make_result(
            outcome=WitnessOutcome.PASS,
            exit_code=0,
            sandbox_id="sbx-cand-new",
            world=ExecutionWorld.CANDIDATE,
        )
        cand_reg = _make_result(
            outcome=WitnessOutcome.PASS,
            exit_code=0,
            sandbox_id="sbx-cand-reg",
            world=ExecutionWorld.CANDIDATE,
        )

        receipt = verify_dep_api_change(
            context_envelope=envelope,
            sealed_record=sealed,
            witness_lock=lock,
            base_new_contract_result=base_new,
            base_regression_result=base_reg,
            candidate_new_contract_result=cand_new,
            candidate_regression_result=cand_reg,
            migration_spec=spec,
            base_tree_digest="a" * 64,
            candidate_tree_digest="b" * 64,
        )

        assert receipt.transition == CausalTransition.UNVERIFIED_REGRESSION_DETECTED
        assert receipt.verdict == PreliminaryVerdict.INCONCLUSIVE
        assert receipt.is_causally_verified is False

    def test_dep_api_timeout_fails_closed(self) -> None:
        contract = _make_dep_api_contract()
        envelope = _make_context_envelope(contract)
        sealed, lock = _make_sealed_witness_and_lock(contract)
        spec = _make_spec()

        base_new = _make_result(sandbox_id="sbx-base-new", world=ExecutionWorld.BASE)
        base_reg = _make_result(sandbox_id="sbx-base-reg", world=ExecutionWorld.BASE)

        cand_new = _make_result(
            outcome=WitnessOutcome.TIMEOUT,
            status=TerminationStatus.TIMED_OUT,
            exit_code=None,
            sandbox_id="sbx-cand-new",
            world=ExecutionWorld.CANDIDATE,
        )
        cand_reg = _make_result(
            outcome=WitnessOutcome.PASS,
            exit_code=0,
            sandbox_id="sbx-cand-reg",
            world=ExecutionWorld.CANDIDATE,
        )

        receipt = verify_dep_api_change(
            context_envelope=envelope,
            sealed_record=sealed,
            witness_lock=lock,
            base_new_contract_result=base_new,
            base_regression_result=base_reg,
            candidate_new_contract_result=cand_new,
            candidate_regression_result=cand_reg,
            migration_spec=spec,
            base_tree_digest="a" * 64,
            candidate_tree_digest="b" * 64,
        )

        assert receipt.transition == CausalTransition.NON_VERIFIED_TIMEOUT
        assert receipt.verdict == PreliminaryVerdict.INCONCLUSIVE
        assert receipt.is_causally_verified is False

    def test_dep_api_infrastructure_failure_fails_closed(self) -> None:
        contract = _make_dep_api_contract()
        envelope = _make_context_envelope(contract)
        sealed, lock = _make_sealed_witness_and_lock(contract)
        spec = _make_spec()

        base_new = _make_result(sandbox_id="sbx-base-new", world=ExecutionWorld.BASE)
        base_reg = _make_result(sandbox_id="sbx-base-reg", world=ExecutionWorld.BASE)

        cand_new = _make_result(
            outcome=WitnessOutcome.ERROR,
            status=TerminationStatus.CANCELLED,
            exit_code=None,
            sandbox_id="sbx-cand-new",
            world=ExecutionWorld.CANDIDATE,
        )
        cand_reg = _make_result(
            outcome=WitnessOutcome.PASS,
            exit_code=0,
            sandbox_id="sbx-cand-reg",
            world=ExecutionWorld.CANDIDATE,
        )

        receipt = verify_dep_api_change(
            context_envelope=envelope,
            sealed_record=sealed,
            witness_lock=lock,
            base_new_contract_result=base_new,
            base_regression_result=base_reg,
            candidate_new_contract_result=cand_new,
            candidate_regression_result=cand_reg,
            migration_spec=spec,
            base_tree_digest="a" * 64,
            candidate_tree_digest="b" * 64,
        )

        assert receipt.transition == CausalTransition.NON_VERIFIED_EXECUTION_ERROR
        assert receipt.verdict == PreliminaryVerdict.INCONCLUSIVE
        assert receipt.is_causally_verified is False

    def test_dep_api_change_class_mismatch_raises(self) -> None:
        contract = _make_dep_api_contract(change_class=ChangeClass.FEATURE)
        envelope = _make_context_envelope(contract)
        sealed, lock = _make_sealed_witness_and_lock(contract)
        spec = _make_spec()

        base_new = _make_result(sandbox_id="sbx-base-new", world=ExecutionWorld.BASE)
        base_reg = _make_result(sandbox_id="sbx-base-reg", world=ExecutionWorld.BASE)
        cand_new = _make_result(sandbox_id="sbx-cand-new", world=ExecutionWorld.CANDIDATE)
        cand_reg = _make_result(sandbox_id="sbx-cand-reg", world=ExecutionWorld.CANDIDATE)

        with pytest.raises(ChangeClassMismatchError, match="expected ChangeClass.DEP_API_CHANGE"):
            verify_dep_api_change(
                context_envelope=envelope,
                sealed_record=sealed,
                witness_lock=lock,
                base_new_contract_result=base_new,
                base_regression_result=base_reg,
                candidate_new_contract_result=cand_new,
                candidate_regression_result=cand_reg,
                migration_spec=spec,
                base_tree_digest="a" * 64,
                candidate_tree_digest="b" * 64,
            )

    def test_dep_api_empty_patch_fails_closed(self) -> None:
        contract = _make_dep_api_contract()
        envelope = _make_context_envelope(contract)
        sealed, lock = _make_sealed_witness_and_lock(contract)
        spec = _make_spec()

        base_new = _make_result(sandbox_id="sbx-base-new", world=ExecutionWorld.BASE)
        base_reg = _make_result(sandbox_id="sbx-base-reg", world=ExecutionWorld.BASE)
        cand_new = _make_result(sandbox_id="sbx-cand-new", world=ExecutionWorld.CANDIDATE)
        cand_reg = _make_result(sandbox_id="sbx-cand-reg", world=ExecutionWorld.CANDIDATE)

        same_digest = "a" * 64
        receipt = verify_dep_api_change(
            context_envelope=envelope,
            sealed_record=sealed,
            witness_lock=lock,
            base_new_contract_result=base_new,
            base_regression_result=base_reg,
            candidate_new_contract_result=cand_new,
            candidate_regression_result=cand_reg,
            migration_spec=spec,
            base_tree_digest=same_digest,
            candidate_tree_digest=same_digest,
        )

        assert receipt.transition == CausalTransition.NON_VERIFIED_TAMPERING_OR_INTEGRITY_FAILURE
        assert receipt.verdict == PreliminaryVerdict.CONTRADICTED

    def test_dep_api_sandbox_reuse_fails_closed(self) -> None:
        contract = _make_dep_api_contract()
        envelope = _make_context_envelope(contract)
        sealed, lock = _make_sealed_witness_and_lock(contract)
        spec = _make_spec()

        reused_sbx = "sbx-reused"
        base_new = _make_result(sandbox_id=reused_sbx, world=ExecutionWorld.BASE)
        base_reg = _make_result(sandbox_id="sbx-base-reg", world=ExecutionWorld.BASE)
        cand_new = _make_result(sandbox_id=reused_sbx, world=ExecutionWorld.CANDIDATE)
        cand_reg = _make_result(sandbox_id="sbx-cand-reg", world=ExecutionWorld.CANDIDATE)

        receipt = verify_dep_api_change(
            context_envelope=envelope,
            sealed_record=sealed,
            witness_lock=lock,
            base_new_contract_result=base_new,
            base_regression_result=base_reg,
            candidate_new_contract_result=cand_new,
            candidate_regression_result=cand_reg,
            migration_spec=spec,
            base_tree_digest="a" * 64,
            candidate_tree_digest="b" * 64,
        )

        assert receipt.transition == CausalTransition.NON_VERIFIED_TAMPERING_OR_INTEGRITY_FAILURE
        assert receipt.verdict == PreliminaryVerdict.CONTRADICTED

    def test_dep_api_vacuous_witness_fails_closed(self) -> None:
        contract = _make_dep_api_contract()
        envelope = _make_context_envelope(contract)
        sealed, lock = _make_sealed_witness_and_lock(contract)
        spec = _make_spec()

        base_new = _make_result(sandbox_id="sbx-base-new", world=ExecutionWorld.BASE)
        base_reg = _make_result(sandbox_id="sbx-base-reg", world=ExecutionWorld.BASE)
        cand_new = _make_result(sandbox_id="sbx-cand-new", world=ExecutionWorld.CANDIDATE)
        cand_reg = _make_result(sandbox_id="sbx-cand-reg", world=ExecutionWorld.CANDIDATE)

        vacuity = VacuityCheckResult(
            status=VacuityStatus.VACUOUS_NO_ASSERTIONS,
            is_vacuous=True,
            details="Migration test suite had zero assertions",
            assertion_count=0,
            target_symbols_referenced=(),
        )

        receipt = verify_dep_api_change(
            context_envelope=envelope,
            sealed_record=sealed,
            witness_lock=lock,
            base_new_contract_result=base_new,
            base_regression_result=base_reg,
            candidate_new_contract_result=cand_new,
            candidate_regression_result=cand_reg,
            migration_spec=spec,
            base_tree_digest="a" * 64,
            candidate_tree_digest="b" * 64,
            candidate_vacuity=vacuity,
        )

        assert receipt.transition == CausalTransition.NON_VERIFIED_VACUOUS
        assert receipt.verdict == PreliminaryVerdict.INCONCLUSIVE
        assert receipt.is_causally_verified is False

    def test_dep_api_receipt_tampering_rejected(self) -> None:
        contract = _make_dep_api_contract()
        envelope = _make_context_envelope(contract)
        sealed, lock = _make_sealed_witness_and_lock(contract)
        spec = _make_spec()

        base_new = _make_result(sandbox_id="sbx-base-new", world=ExecutionWorld.BASE)
        base_reg = _make_result(sandbox_id="sbx-base-reg", world=ExecutionWorld.BASE)
        cand_new = _make_result(sandbox_id="sbx-cand-new", world=ExecutionWorld.CANDIDATE)
        cand_reg = _make_result(sandbox_id="sbx-cand-reg", world=ExecutionWorld.CANDIDATE)

        receipt = verify_dep_api_change(
            context_envelope=envelope,
            sealed_record=sealed,
            witness_lock=lock,
            base_new_contract_result=base_new,
            base_regression_result=base_reg,
            candidate_new_contract_result=cand_new,
            candidate_regression_result=cand_reg,
            migration_spec=spec,
            base_tree_digest="a" * 64,
            candidate_tree_digest="b" * 64,
        )

        tampered = replace(receipt, transition=CausalTransition.FEATURE_VERIFIED)
        with pytest.raises(SemanticReceiptTamperingError):
            verify_semantic_receipt_integrity(tampered)
