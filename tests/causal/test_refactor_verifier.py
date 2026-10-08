"""Unit and adversarial tests for P-13.03 REFACTOR BEFORE ≡ AFTER verifier."""

from __future__ import annotations

import pytest

from basebreak.causal.reconciliation import (
    CausalTransition,
    ChangeClassMismatchError,
)
from basebreak.causal.refactor import (
    BOUNDED_EQUIVALENCE_CLAIM,
    FORBIDDEN_UNIVERSAL_CLAIM,
    compute_output_digest,
    verify_refactor,
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


def _make_refactor_contract(
    change_class: ChangeClass = ChangeClass.REFACTOR,
) -> FrozenContract:
    """Helper to create a valid FrozenContract for refactor tests."""
    req = FrozenRequirement(
        requirement_id="REQ-REFACTOR-001",
        statement="Refactor parser without changing AST output or exit semantics",
        citation="refactor parser",
        citation_start=0,
        citation_end=15,
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
    """Helper to create a VerifierContextEnvelope."""
    source_id = SourceIdentity(
        locator="https://github.com/test/repo.git",
        revision=CommitRevision(commit_id=source_commit),
    )
    cand_id = CandidateIdentity(
        candidate_id="cand-refactor-1",
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
    content: str = "def test_parser(): assert parse('abc') == AST('abc')",
) -> tuple[SealedWitnessRecord, ImmutableWitnessLock]:
    """Helper to seal witness in vault and generate an immutable lock."""
    vault = TrustedWitnessVault()
    art = WitnessArtifact.from_text(
        path="tests/test_parser_refactor.py",
        content=content,
    )
    sealed = vault.seal_witness(
        witness_id="wit-refactor-1",
        requirement_id=contract.requirements[0].requirement_id,
        frozen_contract_digest=contract.contract_digest,
        source_commit_id=source_commit,
        artifacts=(art,),
    )
    lock = create_witness_lock(record=sealed, vault=vault)
    return sealed, lock


def _make_result(
    outcome: WitnessOutcome = WitnessOutcome.PASS,
    stdout: str = "PASS: parser output matches\nTests: 1 passed",
    stderr: str = "",
    exit_code: int | None = 0,
    sandbox_id: str = "sbx-base",
    status: TerminationStatus = TerminationStatus.COMPLETED,
    world: ExecutionWorld = ExecutionWorld.BASE,
) -> NormalizedWitnessResult:
    sbx = SandboxIdentity(
        sandbox_id=sandbox_id,
        description="test sandbox",
    )
    return normalize_witness_execution(
        witness_id="wit-refactor-1",
        witness_digest="c" * 64,
        frozen_contract_digest="b" * 64,
        requirement_id="REQ-REFACTOR-001",
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


class TestRefactorVerifier:
    def test_output_digest_normalization(self) -> None:
        d1 = compute_output_digest("Hello\r\nWorld\r\n", "Err\r\n")
        d2 = compute_output_digest("Hello\nWorld\n", "Err\n")
        assert d1 == d2
        assert len(d1) == 64

    def test_refactor_clean_equivalence_success(self) -> None:
        contract = _make_refactor_contract()
        envelope = _make_context_envelope(contract)
        sealed, lock = _make_sealed_witness_and_lock(contract)

        base_res = _make_result(
            outcome=WitnessOutcome.PASS,
            stdout="Output AST: [1, 2, 3]\nExecution finished successfully.",
            sandbox_id="sbx-base",
        )
        cand_res = _make_result(
            outcome=WitnessOutcome.PASS,
            stdout="Output AST: [1, 2, 3]\nExecution finished successfully.",
            sandbox_id="sbx-cand",
        )

        receipt = verify_refactor(
            context_envelope=envelope,
            sealed_record=sealed,
            witness_lock=lock,
            base_result=base_res,
            candidate_result=cand_res,
            base_tree_digest="a" * 64,
            candidate_tree_digest="b" * 64,
        )

        assert receipt.transition == CausalTransition.REFACTOR_VERIFIED
        assert receipt.verdict == PreliminaryVerdict.VERIFIED
        assert receipt.is_causally_verified is True
        assert receipt.change_class == ChangeClass.REFACTOR
        assert receipt.class_specific_payload["equivalence_claim"] == BOUNDED_EQUIVALENCE_CLAIM
        assert (
            receipt.class_specific_payload["disclaimed_universal_claim"]
            == FORBIDDEN_UNIVERSAL_CLAIM
        )
        assert receipt.class_specific_payload["output_match"] is True
        assert receipt.class_specific_payload["exit_semantics_match"] is True

        # Tamper-proof integrity check
        assert verify_semantic_receipt_integrity(receipt) is True

    def test_refactor_side_effect_matching_success(self) -> None:
        contract = _make_refactor_contract()
        envelope = _make_context_envelope(contract)
        sealed, lock = _make_sealed_witness_and_lock(contract)

        side_effect_hash = "f" * 64
        base_res = _make_result(sandbox_id="sbx-base")
        cand_res = _make_result(sandbox_id="sbx-cand")

        receipt = verify_refactor(
            context_envelope=envelope,
            sealed_record=sealed,
            witness_lock=lock,
            base_result=base_res,
            candidate_result=cand_res,
            base_tree_digest="a" * 64,
            candidate_tree_digest="b" * 64,
            base_side_effect_digest=side_effect_hash,
            candidate_side_effect_digest=side_effect_hash,
        )

        assert receipt.transition == CausalTransition.REFACTOR_VERIFIED
        assert receipt.is_causally_verified is True
        assert receipt.class_specific_payload["side_effects_match"] is True

    def test_refactor_output_changed_rejected(self) -> None:
        contract = _make_refactor_contract()
        envelope = _make_context_envelope(contract)
        sealed, lock = _make_sealed_witness_and_lock(contract)

        base_res = _make_result(
            outcome=WitnessOutcome.PASS,
            stdout="Output AST: [1, 2, 3]",
            sandbox_id="sbx-base",
        )
        cand_res = _make_result(
            outcome=WitnessOutcome.PASS,
            stdout="Output AST: [1, 2, 3, 4]",  # Changed observable output!
            sandbox_id="sbx-cand",
        )

        receipt = verify_refactor(
            context_envelope=envelope,
            sealed_record=sealed,
            witness_lock=lock,
            base_result=base_res,
            candidate_result=cand_res,
            base_tree_digest="a" * 64,
            candidate_tree_digest="b" * 64,
        )

        assert receipt.transition == CausalTransition.UNVERIFIED_BEHAVIOR_CHANGED
        assert receipt.verdict == PreliminaryVerdict.CONTRADICTED
        assert receipt.is_causally_verified is False
        assert receipt.class_specific_payload["output_match"] is False

    def test_refactor_exit_code_changed_rejected(self) -> None:
        contract = _make_refactor_contract()
        envelope = _make_context_envelope(contract)
        sealed, lock = _make_sealed_witness_and_lock(contract)

        base_res = _make_result(exit_code=0, sandbox_id="sbx-base")
        cand_res = _make_result(
            exit_code=1,
            outcome=WitnessOutcome.FAIL,
            sandbox_id="sbx-cand",
        )

        receipt = verify_refactor(
            context_envelope=envelope,
            sealed_record=sealed,
            witness_lock=lock,
            base_result=base_res,
            candidate_result=cand_res,
            base_tree_digest="a" * 64,
            candidate_tree_digest="b" * 64,
        )

        assert receipt.transition == CausalTransition.UNVERIFIED_EXIT_SEMANTICS_CHANGED
        assert receipt.verdict == PreliminaryVerdict.CONTRADICTED
        assert receipt.is_causally_verified is False

    def test_refactor_base_failed_rejected(self) -> None:
        contract = _make_refactor_contract()
        envelope = _make_context_envelope(contract)
        sealed, lock = _make_sealed_witness_and_lock(contract)

        # Baseline was broken to begin with
        base_res = _make_result(
            outcome=WitnessOutcome.FAIL,
            exit_code=1,
            sandbox_id="sbx-base",
        )
        cand_res = _make_result(
            outcome=WitnessOutcome.PASS,
            exit_code=0,
            sandbox_id="sbx-cand",
        )

        receipt = verify_refactor(
            context_envelope=envelope,
            sealed_record=sealed,
            witness_lock=lock,
            base_result=base_res,
            candidate_result=cand_res,
            base_tree_digest="a" * 64,
            candidate_tree_digest="b" * 64,
        )

        assert receipt.transition == CausalTransition.UNVERIFIED_BASE_FAILED
        assert receipt.verdict == PreliminaryVerdict.INCONCLUSIVE
        assert receipt.is_causally_verified is False

    def test_refactor_side_effect_diverged_rejected(self) -> None:
        contract = _make_refactor_contract()
        envelope = _make_context_envelope(contract)
        sealed, lock = _make_sealed_witness_and_lock(contract)

        base_res = _make_result(sandbox_id="sbx-base")
        cand_res = _make_result(sandbox_id="sbx-cand")

        receipt = verify_refactor(
            context_envelope=envelope,
            sealed_record=sealed,
            witness_lock=lock,
            base_result=base_res,
            candidate_result=cand_res,
            base_tree_digest="a" * 64,
            candidate_tree_digest="b" * 64,
            base_side_effect_digest="1" * 64,
            candidate_side_effect_digest="2" * 64,  # Diverged
        )

        assert receipt.transition == CausalTransition.UNVERIFIED_BEHAVIOR_CHANGED
        assert receipt.verdict == PreliminaryVerdict.CONTRADICTED
        assert receipt.is_causally_verified is False

    def test_refactor_timeout_fails_closed(self) -> None:
        contract = _make_refactor_contract()
        envelope = _make_context_envelope(contract)
        sealed, lock = _make_sealed_witness_and_lock(contract)

        base_res = _make_result(sandbox_id="sbx-base")
        cand_res = _make_result(
            outcome=WitnessOutcome.TIMEOUT,
            status=TerminationStatus.TIMED_OUT,
            exit_code=None,
            sandbox_id="sbx-cand",
        )

        receipt = verify_refactor(
            context_envelope=envelope,
            sealed_record=sealed,
            witness_lock=lock,
            base_result=base_res,
            candidate_result=cand_res,
            base_tree_digest="a" * 64,
            candidate_tree_digest="b" * 64,
        )

        assert receipt.transition == CausalTransition.NON_VERIFIED_TIMEOUT
        assert receipt.verdict == PreliminaryVerdict.INCONCLUSIVE
        assert receipt.is_causally_verified is False

    def test_refactor_infrastructure_failure_fails_closed(self) -> None:
        contract = _make_refactor_contract()
        envelope = _make_context_envelope(contract)
        sealed, lock = _make_sealed_witness_and_lock(contract)

        base_res = _make_result(sandbox_id="sbx-base")
        cand_res = _make_result(
            outcome=WitnessOutcome.ERROR,
            status=TerminationStatus.CANCELLED,
            exit_code=None,
            sandbox_id="sbx-cand",
        )

        receipt = verify_refactor(
            context_envelope=envelope,
            sealed_record=sealed,
            witness_lock=lock,
            base_result=base_res,
            candidate_result=cand_res,
            base_tree_digest="a" * 64,
            candidate_tree_digest="b" * 64,
        )

        assert receipt.transition == CausalTransition.NON_VERIFIED_EXECUTION_ERROR
        assert receipt.verdict == PreliminaryVerdict.INCONCLUSIVE
        assert receipt.is_causally_verified is False

    def test_refactor_change_class_mismatch_fails_closed(self) -> None:
        contract = _make_refactor_contract(change_class=ChangeClass.BUG_FIX)
        envelope = _make_context_envelope(contract)
        sealed, lock = _make_sealed_witness_and_lock(contract)

        base_res = _make_result(sandbox_id="sbx-base")
        cand_res = _make_result(sandbox_id="sbx-cand")

        with pytest.raises(ChangeClassMismatchError, match="expected ChangeClass.REFACTOR"):
            verify_refactor(
                context_envelope=envelope,
                sealed_record=sealed,
                witness_lock=lock,
                base_result=base_res,
                candidate_result=cand_res,
                base_tree_digest="a" * 64,
                candidate_tree_digest="b" * 64,
            )

    def test_refactor_empty_patch_fails_closed(self) -> None:
        contract = _make_refactor_contract()
        envelope = _make_context_envelope(contract)
        sealed, lock = _make_sealed_witness_and_lock(contract)

        base_res = _make_result(sandbox_id="sbx-base")
        cand_res = _make_result(sandbox_id="sbx-cand")

        same_digest = "e" * 64
        receipt = verify_refactor(
            context_envelope=envelope,
            sealed_record=sealed,
            witness_lock=lock,
            base_result=base_res,
            candidate_result=cand_res,
            base_tree_digest=same_digest,
            candidate_tree_digest=same_digest,
        )

        assert receipt.transition == CausalTransition.NON_VERIFIED_TAMPERING_OR_INTEGRITY_FAILURE
        assert receipt.verdict == PreliminaryVerdict.CONTRADICTED

    def test_refactor_receipt_tampering_rejected(self) -> None:
        contract = _make_refactor_contract()
        envelope = _make_context_envelope(contract)
        sealed, lock = _make_sealed_witness_and_lock(contract)

        base_res = _make_result(sandbox_id="sbx-base")
        cand_res = _make_result(sandbox_id="sbx-cand")

        receipt = verify_refactor(
            context_envelope=envelope,
            sealed_record=sealed,
            witness_lock=lock,
            base_result=base_res,
            candidate_result=cand_res,
            base_tree_digest="a" * 64,
            candidate_tree_digest="b" * 64,
        )

        # Tampering with transition
        from dataclasses import replace

        tampered = replace(receipt, transition=CausalTransition.CAUSAL_BUG_FIX_VERIFIED)
        with pytest.raises(SemanticReceiptTamperingError):
            verify_semantic_receipt_integrity(tampered)

    def test_refactor_sandbox_reuse_fails_closed(self) -> None:
        contract = _make_refactor_contract()
        envelope = _make_context_envelope(contract)
        sealed, lock = _make_sealed_witness_and_lock(contract)

        base_res = _make_result(sandbox_id="sbx-reused")
        cand_res = _make_result(sandbox_id="sbx-reused")

        receipt = verify_refactor(
            context_envelope=envelope,
            sealed_record=sealed,
            witness_lock=lock,
            base_result=base_res,
            candidate_result=cand_res,
            base_tree_digest="a" * 64,
            candidate_tree_digest="b" * 64,
        )

        assert receipt.transition == CausalTransition.NON_VERIFIED_TAMPERING_OR_INTEGRITY_FAILURE
        assert receipt.verdict == PreliminaryVerdict.CONTRADICTED

    def test_refactor_vacuous_witness_fails_closed(self) -> None:
        contract = _make_refactor_contract()
        envelope = _make_context_envelope(contract)
        sealed, lock = _make_sealed_witness_and_lock(contract)

        base_res = _make_result(sandbox_id="sbx-base")
        cand_res = _make_result(sandbox_id="sbx-cand")

        vacuity = VacuityCheckResult(
            status=VacuityStatus.VACUOUS_NO_ASSERTIONS,
            is_vacuous=True,
            details="Witness had no assertions",
            assertion_count=0,
            target_symbols_referenced=(),
        )

        receipt = verify_refactor(
            context_envelope=envelope,
            sealed_record=sealed,
            witness_lock=lock,
            base_result=base_res,
            candidate_result=cand_res,
            base_tree_digest="a" * 64,
            candidate_tree_digest="b" * 64,
            base_vacuity=vacuity,
        )

        assert receipt.transition == CausalTransition.NON_VERIFIED_VACUOUS
        assert receipt.verdict == PreliminaryVerdict.INCONCLUSIVE
        assert receipt.is_causally_verified is False
