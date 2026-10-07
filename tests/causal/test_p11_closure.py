"""Comprehensive closure test suite for P-11 Bounded Counterfactual Verification Batch.

Validates all 5 authorized micro-tasks of P-11:
- P-11.02: Select bounded relevant patch region without model authority over verdict.
- P-11.03: Materialize counterfactual candidate in fresh sandbox.
- P-11.04: Execute same witness against counterfactual.
- P-11.05: Reconcile FAIL->PASS->FAIL causal triplet.
- P-11.06: Detect invalid counterfactual construction and return INCONCLUSIVE, never false PASS.
"""

from __future__ import annotations

import hashlib
from typing import Any
from unittest.mock import MagicMock

import pytest

from basebreak.builder.capture import CandidateSnapshot
from basebreak.causal.engine import (
    CausalBindingError,
    CausalExecutionEngine,
)
from basebreak.causal.harness import (
    BASEBREAK_JUDGE_CLAIM,
    BASEBREAK_THESIS,
    format_judge_proof_summary,
    render_judge_proof_markdown,
    run_causal_triplet_slice,
)
from basebreak.causal.materializer import (
    CausalRepositoryMaterializer,
    CounterfactualMaterializationError,
)
from basebreak.causal.receipt import (
    CausalReceiptTamperingError,
    LocalCausalReceipt,
    WorldExecutionFact,
    create_causal_triplet_receipt,
    verify_causal_receipt_integrity,
)
from basebreak.causal.reconciliation import (
    CausalTransition,
    reconcile_causal_triplet,
)
from basebreak.causal.selector import (
    BoundedRegionSelector,
    ModelRegionProposal,
)
from basebreak.causal.subtraction import (
    CallerAuthorityError,
    CounterfactualDeltaPlan,
    ProtectedSurfaceSubtractionError,
    SubtractionRequest,
    SubtractionStrategyType,
    UnsupportedStrategyError,
    plan_subtraction_from_snapshot,
)
from basebreak.compiler.freeze import freeze_review_result
from basebreak.compiler.ingestion import ingest_task
from basebreak.compiler.requirements import ProposedRequirement
from basebreak.compiler.review import ReviewBundle, ReviewSession
from basebreak.compiler.semantics import (
    CertaintyLevel,
    ChangeClass,
    ChangeSemanticsClassification,
    DeterministicClassificationFact,
)
from basebreak.domain.causal import CandidateIdentity, ExecutionWorld
from basebreak.domain.execution import SandboxIdentity, TerminationStatus
from basebreak.domain.source import CommitRevision, SourceIdentity
from basebreak.domain.verdict import EvidenceProvenance, PreliminaryVerdict
from basebreak.verifier.context import VerifierContextEnvelope
from basebreak.verifier.sandbox import (
    BuilderSandboxReuseError,
    VerifierSandboxManager,
    VerifierTreeDigestMismatchError,
)
from basebreak.verifier.witness_lock import create_witness_lock
from basebreak.verifier.witness_plan import ValidatedWitnessArtifact, ValidatedWitnessPlan
from basebreak.verifier.witness_result import WitnessOutcome
from basebreak.verifier.witness_store import (
    SealedWitnessRecord,
    TrustedWitnessVault,
    WitnessArtifact,
)

SAMPLE_SOURCE_COMMIT = "c" * 40
SAMPLE_SOURCE_LOCATOR = "https://github.com/zyganali-glitch/Basebreak.git"
SAMPLE_BASE_TREE = "1" * 40
SAMPLE_CANDIDATE_TREE = "2" * 40
SAMPLE_COUNTERFACTUAL_TREE = "3" * 40

SAMPLE_PATCH = (
    "diff --git a/src/demo.py b/src/demo.py\n"
    "index 878b16f..f2e0928 100644\n"
    "--- a/src/demo.py\n"
    "+++ b/src/demo.py\n"
    "@@ -1,3 +1,3 @@\n"
    " def run():\n"
    "-    return 1\n"
    "+    return 0\n"
    "     pass\n"
)


def _build_test_envelope_and_vault() -> tuple[
    VerifierContextEnvelope,
    SealedWitnessRecord,
    TrustedWitnessVault,
    CandidateSnapshot,
    CounterfactualDeltaPlan,
]:
    raw_text = "When user runs the program, it must return 0 instead of 1."
    task = ingest_task(raw_text)
    fact = DeterministicClassificationFact(
        inferred_class=ChangeClass.BUG_FIX,
        certainty=CertaintyLevel.CONFIDENT,
        confidence=1.0,
        alternative_classes=(),
        rationale="Fixes return code from 1 to 0",
        evidence_citations=("return 0",),
        matched_signals=("fix", "bug"),
    )
    semantics = ChangeSemanticsClassification(
        task_digest=task.task_digest,
        change_class=ChangeClass.BUG_FIX,
        certainty=CertaintyLevel.CONFIDENT,
        confidence=1.0,
        alternative_classes=(),
        rationale="Fixes return code from 1 to 0",
        evidence_citations=("return 0",),
        deterministic_facts=fact,
    )
    cit = "When user runs the program, it must return 0 instead of 1."
    start = task.normalized_text.index(cit)
    end = start + len(cit)
    req = ProposedRequirement(
        statement="Return value must be 0",
        citation=cit,
        citation_start=start,
        citation_end=end,
        rationale="Mandated exit code fix",
    )
    bundle = ReviewBundle(
        task=task,
        semantics=semantics,
        requirements=(req,),
    )
    session = ReviewSession(bundle)
    approval = session.approve()
    contract = freeze_review_result(approval)
    req_id = contract.requirements[0].requirement_id

    source_id = SourceIdentity(
        locator=SAMPLE_SOURCE_LOCATOR,
        revision=CommitRevision(SAMPLE_SOURCE_COMMIT),
    )
    patch_digest = hashlib.sha256(SAMPLE_PATCH.encode("utf-8")).hexdigest()
    cand_id = CandidateIdentity(
        candidate_id="cand-p11-001",
        source=source_id,
        patch_digest=patch_digest,
    )
    envelope = VerifierContextEnvelope.create(
        frozen_contract=contract,
        source_identity=source_id,
        candidate_identity=cand_id,
        candidate_patch_text=SAMPLE_PATCH,
        candidate_tree_digest=SAMPLE_CANDIDATE_TREE,
    )

    vault = TrustedWitnessVault(vault_secret=b"test-secret-key-for-p11-vault-auth")
    wa = WitnessArtifact.from_text(
        path="tests/test_run.py",
        content="from src.demo import run\ndef test_run():\n    assert run() == 0\n",
    )
    sealed_record = vault.seal_witness(
        witness_id="wit-p11-001",
        requirement_id=req_id,
        frozen_contract_digest=contract.contract_digest,
        source_commit_id=SAMPLE_SOURCE_COMMIT,
        artifacts=[wa],
    )

    snapshot = CandidateSnapshot(
        candidate_id="cand-p11-001",
        source_identity=source_id,
        candidate_tree_digest=SAMPLE_CANDIDATE_TREE,
        patch_digest=patch_digest,
        patch_text=SAMPLE_PATCH,
        files_added=(),
        files_modified=("src/demo.py",),
        files_deleted=(),
        builder_authored_tests=(),
        frozen_contract_digest=contract.contract_digest,
        context_digest="c" * 64,
    )

    cf_plan = plan_subtraction_from_snapshot(
        candidate_snapshot=snapshot,
        sealed_witness_digest=sealed_record.seal_digest,
        request=SubtractionRequest(strategy_type=SubtractionStrategyType.FULL_PATCH_REVERT),
    )

    return envelope, sealed_record, vault, snapshot, cf_plan


class MockSandboxResult:
    def __init__(
        self, exit_code: int, stdout: str = "", stderr: str = "", duration: float = 0.5
    ) -> None:
        self.exit_code = exit_code
        self.stdout = stdout
        self.stderr = stderr
        self.duration_seconds = duration
        self.is_timed_out = False
        self.is_cancelled = False
        self.is_failed_to_start = False


class MockMaterializer:
    def __init__(
        self,
        candidate_tree: str = SAMPLE_CANDIDATE_TREE,
        counterfactual_tree: str = SAMPLE_COUNTERFACTUAL_TREE,
    ) -> None:
        self.candidate_tree = candidate_tree
        self.counterfactual_tree = counterfactual_tree

    def materialize_repository(self, *args: Any, **kwargs: Any) -> dict[str, object]:
        world = kwargs.get("world", ExecutionWorld.BASE)
        if world == ExecutionWorld.BASE:
            tree = SAMPLE_BASE_TREE
        elif world == ExecutionWorld.CANDIDATE:
            tree = self.candidate_tree
        elif world == ExecutionWorld.COUNTERFACTUAL:
            tree = self.counterfactual_tree
        else:
            raise ValueError(f"Unknown world: {world}")

        return {
            "resolved_commit_sha": SAMPLE_SOURCE_COMMIT,
            "resolved_tree_sha": tree,
            "workspace_path": "/verifier_workspace",
            "is_verified": True,
        }


# ==============================================================================
# P-11.02: Bounded Region Selection Tests
# ==============================================================================


class TestP1102BoundedRegionSelection:
    """Validates deterministic region selection without model verdict authority."""

    def test_untrusted_model_proposal_cannot_assert_verdict_authority(self) -> None:
        """Model proposal asserting is_authoritative=True or grants_pass=True fails closed."""
        with pytest.raises(CallerAuthorityError, match="must be False"):
            ModelRegionProposal(
                strategy_type=SubtractionStrategyType.FULL_PATCH_REVERT,
                is_authoritative=True,
            )

        with pytest.raises(CallerAuthorityError, match="must be False"):
            ModelRegionProposal(
                strategy_type=SubtractionStrategyType.FULL_PATCH_REVERT,
                grants_pass=True,
            )

        with pytest.raises(CallerAuthorityError, match="must be False"):
            ModelRegionProposal(
                strategy_type=SubtractionStrategyType.FULL_PATCH_REVERT,
                is_causally_verified=True,
            )

    def test_model_proposal_confidence_out_of_bounds_rejected(self) -> None:
        """Confidence score must strictly be in [0.0, 1.0]."""
        with pytest.raises(ValueError, match="model_confidence"):
            ModelRegionProposal(
                strategy_type=SubtractionStrategyType.FULL_PATCH_REVERT,
                model_confidence=1.5,
            )

        with pytest.raises(ValueError, match="model_confidence"):
            ModelRegionProposal(
                strategy_type=SubtractionStrategyType.FULL_PATCH_REVERT,
                model_confidence=-0.1,
            )

    def test_model_proposal_with_nonexistent_target_fails_closed(self) -> None:
        """Proposal targeting file not in candidate patch is deterministically rejected."""
        envelope, sealed_record, _, snapshot, _ = _build_test_envelope_and_vault()
        selector = BoundedRegionSelector()
        proposal = ModelRegionProposal(
            strategy_type=SubtractionStrategyType.FILE_LEVEL_REVERT,
            proposed_files=("src/nonexistent.py",),
        )

        with pytest.raises(UnsupportedStrategyError, match="not found in candidate patch"):
            selector.validate_and_plan_from_proposal(
                proposal=proposal,
                snapshot=snapshot,
                frozen_contract_digest=envelope.frozen_contract.contract_digest,
                sealed_witness_digest=sealed_record.seal_digest,
            )

    def test_proposal_touching_protected_surface_or_secret_rejected(self) -> None:
        """Proposal attempting to touch verifier/governance protected surface is blocked."""
        source_id = SourceIdentity(
            locator=SAMPLE_SOURCE_LOCATOR,
            revision=CommitRevision(SAMPLE_SOURCE_COMMIT),
        )
        gov_patch = (
            "diff --git a/plans/BASEBREAK_MASTER_EXECUTION_PLAN.md "
            "b/plans/BASEBREAK_MASTER_EXECUTION_PLAN.md\n"
            "index 1111111..2222222 100644\n"
            "--- a/plans/BASEBREAK_MASTER_EXECUTION_PLAN.md\n"
            "+++ b/plans/BASEBREAK_MASTER_EXECUTION_PLAN.md\n"
            "@@ -1,1 +1,1 @@\n"
            "-status: IN_PROGRESS\n"
            "+status: COMPLETE\n"
        )
        gov_snapshot = CandidateSnapshot(
            candidate_id="cand-tamper-001",
            source_identity=source_id,
            candidate_tree_digest=SAMPLE_CANDIDATE_TREE,
            patch_digest=hashlib.sha256(gov_patch.encode("utf-8")).hexdigest(),
            patch_text=gov_patch,
            files_added=(),
            files_modified=("plans/BASEBREAK_MASTER_EXECUTION_PLAN.md",),
            files_deleted=(),
            builder_authored_tests=(),
            frozen_contract_digest="c" * 64,
            context_digest="d" * 64,
        )
        selector = BoundedRegionSelector()
        proposal = ModelRegionProposal(
            strategy_type=SubtractionStrategyType.FULL_PATCH_REVERT,
        )

        with pytest.raises(ProtectedSurfaceSubtractionError):
            selector.validate_and_plan_from_proposal(
                proposal=proposal,
                snapshot=gov_snapshot,
                frozen_contract_digest="c" * 64,
                sealed_witness_digest="b" * 64,
            )

    def test_deterministic_bounded_selection_binds_to_exact_candidate_snapshot(self) -> None:
        """BoundedRegionSelector creates a validated selection bound to snapshot identity."""
        envelope, sealed_record, _, snapshot, _ = _build_test_envelope_and_vault()
        selector = BoundedRegionSelector()

        selection = selector.select_full_patch(
            snapshot=snapshot,
            frozen_contract_digest=envelope.frozen_contract.contract_digest,
            sealed_witness_digest=sealed_record.seal_digest,
        )

        assert selection.strategy_type == SubtractionStrategyType.FULL_PATCH_REVERT
        assert selection.selected_files == ("src/demo.py",)
        assert selection.is_authoritative is False
        assert selection.grants_pass is False
        assert selection.is_causally_verified is False
        assert selection.plan.target_candidate_id == snapshot.candidate_id


# ==============================================================================
# P-11.03: Counterfactual Materialization Tests
# ==============================================================================


class TestP1103CounterfactualMaterialization:
    """Validates materialization of counterfactual candidate in fresh sandbox."""

    def test_materializer_rejects_missing_counterfactual_plan(self) -> None:
        """Attempting to materialize ExecutionWorld.COUNTERFACTUAL without plan fails."""
        mock_adapter = MagicMock()
        materializer = CausalRepositoryMaterializer(adapter=mock_adapter)
        mock_sandbox = SandboxIdentity(sandbox_id="sbx-test-cf-001")
        with pytest.raises(
            CounterfactualMaterializationError, match="without valid CounterfactualDeltaPlan"
        ):
            materializer.materialize_repository(
                source_identity=SourceIdentity(
                    locator=SAMPLE_SOURCE_LOCATOR,
                    revision=CommitRevision(SAMPLE_SOURCE_COMMIT),
                ),
                sandbox=mock_sandbox,
                world=ExecutionWorld.COUNTERFACTUAL,
                counterfactual_plan=None,
            )

    def test_materializer_rejects_source_commit_mismatch(self) -> None:
        """Plan source_commit_id not matching source_identity fails closed."""
        _, _, _, _, cf_plan = _build_test_envelope_and_vault()
        mock_adapter = MagicMock()
        materializer = CausalRepositoryMaterializer(adapter=mock_adapter)
        mock_sandbox = SandboxIdentity(sandbox_id="sbx-test-cf-001")
        different_source = SourceIdentity(
            locator=SAMPLE_SOURCE_LOCATOR,
            revision=CommitRevision("d" * 40),
        )

        with pytest.raises(CounterfactualMaterializationError, match="source_commit_id"):
            materializer.materialize_repository(
                source_identity=different_source,
                sandbox=mock_sandbox,
                world=ExecutionWorld.COUNTERFACTUAL,
                counterfactual_plan=cf_plan,
            )

    def test_materializer_rejects_source_locator_mismatch(self) -> None:
        """Plan source_locator not matching source_identity fails closed."""
        _, _, _, _, cf_plan = _build_test_envelope_and_vault()
        mock_adapter = MagicMock()
        materializer = CausalRepositoryMaterializer(adapter=mock_adapter)
        mock_sandbox = SandboxIdentity(sandbox_id="sbx-test-cf-001")
        different_locator = SourceIdentity(
            locator="https://github.com/other/repo.git",
            revision=CommitRevision(SAMPLE_SOURCE_COMMIT),
        )

        with pytest.raises(CounterfactualMaterializationError, match="source_locator"):
            materializer.materialize_repository(
                source_identity=different_locator,
                sandbox=mock_sandbox,
                world=ExecutionWorld.COUNTERFACTUAL,
                counterfactual_plan=cf_plan,
            )

    def test_materializer_rejects_candidate_patch_digest_mismatch(self) -> None:
        """Candidate patch text mismatch against plan target digest fails closed."""
        _, _, _, _, cf_plan = _build_test_envelope_and_vault()
        mock_adapter = MagicMock()
        materializer = CausalRepositoryMaterializer(adapter=mock_adapter)
        mock_sandbox = SandboxIdentity(sandbox_id="sbx-test-cf-001")
        source = SourceIdentity(
            locator=SAMPLE_SOURCE_LOCATOR,
            revision=CommitRevision(SAMPLE_SOURCE_COMMIT),
        )

        with pytest.raises(CounterfactualMaterializationError, match="Candidate patch digest"):
            materializer.materialize_repository(
                source_identity=source,
                sandbox=mock_sandbox,
                world=ExecutionWorld.COUNTERFACTUAL,
                counterfactual_plan=cf_plan,
                candidate_patch_text="tampered patch text\n",
            )


# ==============================================================================
# P-11.04 & P-11.05: Same Witness Triplet Execution & Reconciliation Tests
# ==============================================================================


class TestP1104AndP1105CausalTripletExecution:
    """Validates 3-world witness execution and deterministic FAIL->PASS->FAIL reconciliation."""

    def test_successful_causal_triplet_verification(self) -> None:
        """BASE=FAIL (exit 1), CANDIDATE=PASS (exit 0), COUNTERFACTUAL=FAIL (exit 1) -> VERIFIED."""
        envelope, sealed_record, vault, _, cf_plan = _build_test_envelope_and_vault()
        lock = create_witness_lock(record=sealed_record, vault=vault)

        mock_adapter = MagicMock()
        sbx_count = 0

        def create_sandbox_side_effect(*args: Any, **kwargs: Any) -> SandboxIdentity:
            nonlocal sbx_count
            sbx_count += 1
            return SandboxIdentity(sandbox_id=f"sbx-fresh-p11-{sbx_count:03d}")

        mock_adapter.create_sandbox.side_effect = create_sandbox_side_effect

        def exec_side_effect(sbx: Any, cmd: Any, **kwargs: Any) -> MockSandboxResult:
            if "printf" in cmd:
                return MockSandboxResult(exit_code=0)
            # Witness execution:
            # sbx-fresh-p11-001 (BASE) -> FAIL (exit 1)
            # sbx-fresh-p11-002 (CANDIDATE) -> PASS (exit 0)
            # sbx-fresh-p11-003 (COUNTERFACTUAL) -> FAIL (exit 1)
            if "001" in sbx.sandbox_id:
                return MockSandboxResult(exit_code=1, stderr="assert run() == 0 failed")
            elif "002" in sbx.sandbox_id:
                return MockSandboxResult(exit_code=0, stdout="OK")
            elif "003" in sbx.sandbox_id:
                return MockSandboxResult(exit_code=1, stderr="assert run() == 0 failed")
            return MockSandboxResult(exit_code=99)

        mock_adapter.execute_command.side_effect = exec_side_effect

        manager = VerifierSandboxManager()
        materializer = MockMaterializer()

        engine = CausalExecutionEngine(
            sandbox_manager=manager,
            sandbox_adapter=mock_adapter,
            materializer=materializer,
            vault=vault,
            provenance=EvidenceProvenance.LOCAL_EXECUTION,
        )

        receipt = engine.execute_causal_triplet(
            context_envelope=envelope,
            sealed_record=sealed_record,
            witness_lock=lock,
            counterfactual_plan=cf_plan,
            execution_command="pytest tests/test_run.py",
        )

        # Assert preliminary verdict and causal transition
        assert receipt.verdict == PreliminaryVerdict.VERIFIED
        assert receipt.is_causally_verified is True
        assert receipt.transition == CausalTransition.CAUSAL_TRIPLET_VERIFIED
        assert receipt.provenance == EvidenceProvenance.LOCAL_EXECUTION

        # Assert 3-world execution facts
        assert receipt.base_execution.outcome == WitnessOutcome.FAIL
        assert receipt.candidate_execution.outcome == WitnessOutcome.PASS
        assert receipt.counterfactual_execution is not None
        assert receipt.counterfactual_execution.outcome == WitnessOutcome.FAIL

        # Assert sandbox isolation across all 3 worlds
        sandboxes = {
            receipt.base_execution.sandbox_id,
            receipt.candidate_execution.sandbox_id,
            receipt.counterfactual_execution.sandbox_id,
        }
        assert len(sandboxes) == 3

        # Assert cryptographic receipt integrity
        assert verify_causal_receipt_integrity(receipt) is True
        assert receipt.delta_digest == cf_plan.subtracted_delta_digest
        assert receipt.counterfactual_id == cf_plan.counterfactual_id

    def test_causal_triplet_receipt_tamper_detection(self) -> None:
        """Tampering with any digest in 3-world receipt fails verification."""
        envelope, sealed_record, vault, _, cf_plan = _build_test_envelope_and_vault()
        base_fact = WorldExecutionFact(
            world=ExecutionWorld.BASE,
            sandbox_id="sbx-base-001",
            source_commit_id=SAMPLE_SOURCE_COMMIT,
            tree_digest=SAMPLE_BASE_TREE,
            outcome=WitnessOutcome.FAIL,
            exit_code=1,
            termination_status=TerminationStatus.COMPLETED,
            stdout_digest="0" * 64,
            stderr_digest="1" * 64,
            result_digest="2" * 64,
            duration_seconds=0.5,
        )
        cand_fact = WorldExecutionFact(
            world=ExecutionWorld.CANDIDATE,
            sandbox_id="sbx-cand-002",
            source_commit_id=SAMPLE_SOURCE_COMMIT,
            tree_digest=SAMPLE_CANDIDATE_TREE,
            outcome=WitnessOutcome.PASS,
            exit_code=0,
            termination_status=TerminationStatus.COMPLETED,
            stdout_digest="3" * 64,
            stderr_digest="4" * 64,
            result_digest="5" * 64,
            duration_seconds=0.5,
        )
        cf_fact = WorldExecutionFact(
            world=ExecutionWorld.COUNTERFACTUAL,
            sandbox_id="sbx-cf-003",
            source_commit_id=SAMPLE_SOURCE_COMMIT,
            tree_digest=SAMPLE_COUNTERFACTUAL_TREE,
            outcome=WitnessOutcome.FAIL,
            exit_code=1,
            termination_status=TerminationStatus.COMPLETED,
            stdout_digest="6" * 64,
            stderr_digest="7" * 64,
            result_digest="8" * 64,
            duration_seconds=0.5,
        )
        receipt = create_causal_triplet_receipt(
            requirement_id=envelope.frozen_contract.requirements[0].requirement_id,
            frozen_contract_digest=envelope.frozen_contract.contract_digest,
            witness_id=sealed_record.witness_id,
            witness_digest=sealed_record.seal_digest,
            lock_digest="0" * 64,
            base_execution=base_fact,
            candidate_execution=cand_fact,
            counterfactual_execution=cf_fact,
            counterfactual_id=cf_plan.counterfactual_id,
            delta_digest=cf_plan.subtracted_delta_digest,
            transition=CausalTransition.CAUSAL_TRIPLET_VERIFIED,
            verdict=PreliminaryVerdict.VERIFIED,
            provenance=EvidenceProvenance.LOCAL_EXECUTION,
            narrative="Causal triplet verified: BASE=FAIL, CANDIDATE=PASS, COUNTERFACTUAL=FAIL.",
        )

        assert verify_causal_receipt_integrity(receipt) is True

        # Tamper with delta digest
        with pytest.raises(CausalReceiptTamperingError):
            LocalCausalReceipt(
                schema_version=receipt.schema_version,
                receipt_digest=receipt.receipt_digest,
                requirement_id=receipt.requirement_id,
                frozen_contract_digest=receipt.frozen_contract_digest,
                witness_id=receipt.witness_id,
                witness_digest=receipt.witness_digest,
                lock_digest=receipt.lock_digest,
                base_execution=receipt.base_execution,
                candidate_execution=receipt.candidate_execution,
                counterfactual_execution=receipt.counterfactual_execution,
                counterfactual_id=receipt.counterfactual_id,
                delta_digest="f" * 64,
                transition=receipt.transition,
                verdict=receipt.verdict,
                provenance=receipt.provenance,
                narrative=receipt.narrative,
                created_at_utc=receipt.created_at_utc,
            )

    def test_harness_renders_judge_proof_summary_and_markdown(self) -> None:
        """Harness formats 3-world comparison table and verified markdown correctly."""
        envelope, sealed_record, vault, _, cf_plan = _build_test_envelope_and_vault()

        mock_adapter = MagicMock()
        sbx_count = 0

        def create_sandbox_side_effect(*args: Any, **kwargs: Any) -> SandboxIdentity:
            nonlocal sbx_count
            sbx_count += 1
            return SandboxIdentity(sandbox_id=f"sbx-fresh-slice-{sbx_count:03d}")

        mock_adapter.create_sandbox.side_effect = create_sandbox_side_effect

        def exec_side_effect(sbx: Any, cmd: Any, **kwargs: Any) -> MockSandboxResult:
            if "printf" in cmd:
                return MockSandboxResult(exit_code=0)
            if "001" in sbx.sandbox_id:
                return MockSandboxResult(exit_code=1)
            elif "002" in sbx.sandbox_id:
                return MockSandboxResult(exit_code=0)
            elif "003" in sbx.sandbox_id:
                return MockSandboxResult(exit_code=1)
            return MockSandboxResult(exit_code=99)

        mock_adapter.execute_command.side_effect = exec_side_effect

        manager = VerifierSandboxManager()
        materializer = MockMaterializer()

        art_code = "from src.demo import run\ndef test_run():\n    assert run() == 0\n"
        art_digest = hashlib.sha256(art_code.encode("utf-8")).hexdigest()
        wa = ValidatedWitnessArtifact(
            path="tests/test_run.py",
            content=art_code,
            content_digest=art_digest,
            byte_size=len(art_code.encode("utf-8")),
            rationale="Tests run return code",
        )
        validated_plan = ValidatedWitnessPlan(
            witness_id="wit-p11-001",
            requirement_id=envelope.frozen_contract.requirements[0].requirement_id,
            frozen_contract_digest=envelope.frozen_contract.contract_digest,
            source_commit_id=SAMPLE_SOURCE_COMMIT,
            change_class=ChangeClass.BUG_FIX,
            plan_summary="Tests run behavior",
            target_files=("src/demo.py",),
            artifacts=(wa,),
            execution_command=("pytest", "tests/test_run.py"),
            expected_failure_at_base="Fails on base",
            expected_success_at_candidate="Passes on candidate",
            plan_digest="d" * 64,
        )

        receipt, summary_dict, summary_markdown = run_causal_triplet_slice(
            context_envelope=envelope,
            validated_plan=validated_plan,
            sandbox_manager=manager,
            sandbox_adapter=mock_adapter,
            materializer=materializer,
            vault=vault,
            counterfactual_plan=cf_plan,
            provenance=EvidenceProvenance.LOCAL_EXECUTION,
        )

        assert receipt.is_causally_verified is True
        assert summary_dict["causal_thesis"] == BASEBREAK_THESIS
        assert summary_dict["judge_claim"] == BASEBREAK_JUDGE_CLAIM
        assert summary_dict["world_execution_facts"]["counterfactual"]["outcome"] == "FAIL"

        # Check markdown contents
        assert "COUNTERFACTUAL WORLD [Outcome: FAIL]" in summary_markdown
        assert "COUNTERFACTUAL World (Delta Subtraction)" in summary_markdown
        assert "CAUSAL_TRIPLET_VERIFIED" in summary_markdown
        assert "[PASS] VERIFIED" in summary_markdown
        assert "## Verification Identity" not in summary_markdown

        # Verify prominent inclusion when basebreak_implementation_sha is supplied
        sample_sha = "e" * 40
        summary_with_sha = dict(summary_dict)
        summary_with_sha["basebreak_implementation_sha"] = sample_sha
        rendered_with_sha = render_judge_proof_markdown(summary_with_sha)
        assert "## Verification Identity" in rendered_with_sha
        assert f"- **Basebreak Implementation SHA:** `{sample_sha}`" in rendered_with_sha
        assert sample_sha in rendered_with_sha

    @pytest.mark.live
    def test_p11_live_causal_triplet_verification(self) -> None:
        """P-11 Live Triplet Causal Verification Slice across real Nebius sandboxes.

        Executes:
        - Target repo cloning on BASE, CANDIDATE, and COUNTERFACTUAL
        - Live candidate application & live delta subtraction
        - Real witness execution across all 3 worlds
        - Mechanical assertions on tree hashes, outcomes, lock equality, and receipt integrity.
        """
        import os
        import subprocess

        from basebreak.adapters.nebius.client import (
            ModelClientConfig,
            NebiusModelClient,
        )
        from basebreak.adapters.nebius.models import DEFAULT_PRIMARY_MODEL
        from basebreak.adapters.nebius.sandbox import (
            NebiusSandboxAdapter,
            SandboxClientConfig,
        )
        from basebreak.causal.materializer import (
            GitRepositoryMaterializer,
        )
        from basebreak.verifier.witness_generator import WitnessGenerator
        from basebreak.verifier.witness_plan import (
            WitnessPlanValidator,
            generate_witness_plan,
        )

        api_key = os.environ.get("NEBIUS_API_KEY")
        if not api_key:
            pytest.skip("NEBIUS_API_KEY not configured for live test")

        project_id = os.environ.get("NEBIUS_PROJECT_ID", "aiproject-e00mae0nmzkxjswr1k")
        if not project_id:
            pytest.skip("NEBIUS_PROJECT_ID not configured for remote VM sandbox creation")

        target_locator = "https://github.com/zyganali-glitch/basebreak-demo-target.git"
        target_base_commit = "40ff923a134a21d8e357deb7a7988571cd396b56"
        expected_candidate_tree = "31f7ab50a5e0da6da9160ce47bdc5daf71072216"

        candidate_patch_text = (
            "diff --git a/src/demo_target/cli.py b/src/demo_target/cli.py\n"
            "index 878b16f..f2e0928 100644\n"
            "--- a/src/demo_target/cli.py\n"
            "+++ b/src/demo_target/cli.py\n"
            "@@ -13,5 +13,5 @@ def format_quiet_output(output: str, quiet: bool = False) -> str:\n"
            '     When quiet is True, stdout must be empty ("").\n'
            '     """\n'
            "     if quiet:\n"
            '-        return "verbose: " + output\n'
            '+        return ""\n'
            "     return output\n"
        )
        patch_digest = hashlib.sha256(candidate_patch_text.encode("utf-8")).hexdigest()

        task_text = "When user specifies --quiet flag, stdout must be empty."
        task = ingest_task(task_text)
        fact = DeterministicClassificationFact(
            inferred_class=ChangeClass.BUG_FIX,
            certainty=CertaintyLevel.CONFIDENT,
            confidence=1.0,
            alternative_classes=(),
            rationale="Fixes verbose leak when quiet flag is passed",
            evidence_citations=("quiet flag",),
            matched_signals=("quiet", "bug"),
        )
        semantics = ChangeSemanticsClassification(
            task_digest=task.task_digest,
            change_class=ChangeClass.BUG_FIX,
            certainty=CertaintyLevel.CONFIDENT,
            confidence=1.0,
            alternative_classes=(),
            rationale="Fixes verbose leak when quiet flag is passed",
            evidence_citations=("quiet flag",),
            deterministic_facts=fact,
        )
        cit = task_text
        req = ProposedRequirement(
            statement=(
                "format_quiet_output must return empty string when quiet=True. "
                "Import via sys.path.insert(0, 'src') and "
                "from demo_target.cli import format_quiet_output."
            ),
            citation=cit,
            citation_start=0,
            citation_end=len(cit),
            rationale="Mandated quiet flag behavior",
        )
        bundle = ReviewBundle(task=task, semantics=semantics, requirements=(req,))
        session = ReviewSession(bundle)
        approval = session.approve()
        contract = freeze_review_result(approval)
        req_id = contract.requirements[0].requirement_id

        source_id = SourceIdentity(
            locator=target_locator,
            revision=CommitRevision(target_base_commit),
        )
        cand_id = CandidateIdentity(
            candidate_id="cand-p11-live-01",
            source=source_id,
            patch_digest=patch_digest,
        )
        envelope = VerifierContextEnvelope.create(
            frozen_contract=contract,
            source_identity=source_id,
            candidate_identity=cand_id,
            candidate_patch_text=candidate_patch_text,
            candidate_tree_digest=expected_candidate_tree,
        )

        model_client = NebiusModelClient(
            config=ModelClientConfig(
                api_key=api_key,
                model=DEFAULT_PRIMARY_MODEL,
                max_tokens=4096,
                temperature=0.0,
            )
        )
        source_cli_path = os.path.abspath("tests/fixtures/demo_target/src/demo_target/cli.py")
        with open(source_cli_path, "r", encoding="utf-8") as f:
            source_cli = f.read()

        proposal = generate_witness_plan(
            context_envelope=envelope,
            requirement_id=req_id,
            source_files={"src/demo_target/cli.py": source_cli},
            model_client=model_client,
        )
        validator = WitnessPlanValidator()
        plan = validator.validate(proposal, context_envelope=envelope)

        vault = TrustedWitnessVault(b"basebreak-live-proof-vault-key-32b")
        generator = WitnessGenerator(vault=vault)
        sealed_record = generator.generate_and_seal_witness(plan)
        assert vault.verify_witness_integrity(sealed_record) is True

        witness_lock = create_witness_lock(record=sealed_record, vault=vault)

        snapshot = CandidateSnapshot(
            candidate_id="cand-p11-live-01",
            source_identity=source_id,
            candidate_tree_digest=expected_candidate_tree,
            patch_digest=patch_digest,
            patch_text=candidate_patch_text,
            files_added=(),
            files_modified=("src/demo_target/cli.py",),
            files_deleted=(),
            builder_authored_tests=(),
            frozen_contract_digest=contract.contract_digest,
            context_digest=envelope.context_digest,
        )

        selection = BoundedRegionSelector.select_full_patch(
            snapshot=snapshot,
            frozen_contract_digest=contract.contract_digest,
            sealed_witness_digest=sealed_record.seal_digest,
        )
        cf_plan = selection.plan

        adapter = NebiusSandboxAdapter(
            config=SandboxClientConfig(
                api_key=api_key,
                project_id=project_id,
                poll_interval_seconds=1.0,
                default_timeout_seconds=180,
            )
        )
        manager = VerifierSandboxManager()
        materializer = GitRepositoryMaterializer(adapter=adapter)
        engine = CausalExecutionEngine(
            sandbox_manager=manager,
            sandbox_adapter=adapter,
            materializer=materializer,
            vault=vault,
            provenance=EvidenceProvenance.LIVE_NEBIUS,
        )

        receipt = engine.execute_causal_triplet(
            context_envelope=envelope,
            sealed_record=sealed_record,
            witness_lock=witness_lock,
            counterfactual_plan=cf_plan,
            execution_command=plan.execution_command,
        )

        assert receipt.provenance == EvidenceProvenance.LIVE_NEBIUS
        assert receipt.transition == CausalTransition.CAUSAL_TRIPLET_VERIFIED
        assert receipt.verdict == PreliminaryVerdict.VERIFIED
        assert receipt.is_causally_verified is True
        assert verify_causal_receipt_integrity(receipt) is True

        tested_impl_sha = subprocess.run(
            ["git", "rev-parse", "HEAD"], capture_output=True, text=True, check=True
        ).stdout.strip()
        summary_dict = format_judge_proof_summary(receipt)
        summary_dict["basebreak_implementation_sha"] = tested_impl_sha

        proof_path = os.path.abspath("docs/P11_LIVE_CLOSURE_PROOF.md")
        rendered_proof = render_judge_proof_markdown(summary_dict)
        assert tested_impl_sha in rendered_proof
        assert f"- **Basebreak Implementation SHA:** `{tested_impl_sha}`" in rendered_proof
        with open(proof_path, "w", encoding="utf-8") as f:
            f.write(rendered_proof)


# ==============================================================================
# P-11.06: Invalid Counterfactual Detection & INCONCLUSIVE Reconciliations
# ==============================================================================


class TestP1106InvalidCounterfactualDetection:
    """Validates non-verifying states, ineffective counterfactuals, and fail-closed defenses."""

    def test_ineffective_counterfactual_yields_inconclusive(self) -> None:
        """BASE=FAIL, CANDIDATE=PASS, COUNTERFACTUAL=PASS -> INCONCLUSIVE (Ineffective)."""
        reconciliation = reconcile_causal_triplet(
            base_outcome=WitnessOutcome.FAIL,
            candidate_outcome=WitnessOutcome.PASS,
            counterfactual_outcome=WitnessOutcome.PASS,
        )
        assert reconciliation.verdict == PreliminaryVerdict.INCONCLUSIVE
        assert reconciliation.transition == CausalTransition.UNVERIFIED_COUNTERFACTUAL_INEFFECTIVE
        assert reconciliation.is_causally_verified is False

    def test_trivial_pass_yields_inconclusive(self) -> None:
        """BASE=PASS, CANDIDATE=PASS, COUNTERFACTUAL=FAIL -> INCONCLUSIVE (Trivial pass)."""
        reconciliation = reconcile_causal_triplet(
            base_outcome=WitnessOutcome.PASS,
            candidate_outcome=WitnessOutcome.PASS,
            counterfactual_outcome=WitnessOutcome.FAIL,
        )
        assert reconciliation.verdict == PreliminaryVerdict.INCONCLUSIVE
        assert reconciliation.transition == CausalTransition.UNVERIFIED_TRIVIAL_PASS
        assert reconciliation.is_causally_verified is False

    def test_defect_persists_yields_contradicted(self) -> None:
        """BASE=FAIL, CANDIDATE=FAIL, COUNTERFACTUAL=FAIL -> CONTRADICTED (Defect persists)."""
        reconciliation = reconcile_causal_triplet(
            base_outcome=WitnessOutcome.FAIL,
            candidate_outcome=WitnessOutcome.FAIL,
            counterfactual_outcome=WitnessOutcome.FAIL,
        )
        assert reconciliation.verdict == PreliminaryVerdict.CONTRADICTED
        assert reconciliation.transition == CausalTransition.UNVERIFIED_DEFECT_PERSISTS
        assert reconciliation.is_causally_verified is False

    def test_counterfactual_timeout_yields_inconclusive_never_fail(self) -> None:
        """BASE=FAIL, CANDIDATE=PASS, COUNTERFACTUAL=TIMEOUT -> INCONCLUSIVE (TIMEOUT != FAIL)."""
        reconciliation = reconcile_causal_triplet(
            base_outcome=WitnessOutcome.FAIL,
            candidate_outcome=WitnessOutcome.PASS,
            counterfactual_outcome=WitnessOutcome.TIMEOUT,
        )
        assert reconciliation.verdict == PreliminaryVerdict.INCONCLUSIVE
        assert reconciliation.transition == CausalTransition.NON_VERIFIED_TIMEOUT
        assert reconciliation.is_causally_verified is False

    def test_counterfactual_error_yields_inconclusive_never_fail(self) -> None:
        """BASE=FAIL, CANDIDATE=PASS, COUNTERFACTUAL=ERROR -> INCONCLUSIVE (ERROR != FAIL)."""
        reconciliation = reconcile_causal_triplet(
            base_outcome=WitnessOutcome.FAIL,
            candidate_outcome=WitnessOutcome.PASS,
            counterfactual_outcome=WitnessOutcome.ERROR,
        )
        assert reconciliation.verdict == PreliminaryVerdict.INCONCLUSIVE
        assert reconciliation.transition == CausalTransition.NON_VERIFIED_EXECUTION_ERROR
        assert reconciliation.is_causally_verified is False

    def test_sandbox_collision_between_worlds_raises_error(self) -> None:
        """Reusing sandbox ID across BASE and COUNTERFACTUAL triggers integrity failure."""
        envelope, sealed_record, vault, _, cf_plan = _build_test_envelope_and_vault()
        lock = create_witness_lock(record=sealed_record, vault=vault)

        mock_adapter = MagicMock()
        sbx_count = 0

        def create_sandbox_side_effect(*args: Any, **kwargs: Any) -> SandboxIdentity:
            nonlocal sbx_count
            sbx_count += 1
            if sbx_count == 3:
                return SandboxIdentity(sandbox_id="sbx-base-colliding-001")
            return SandboxIdentity(sandbox_id=f"sbx-base-colliding-{sbx_count:03d}")

        mock_adapter.create_sandbox.side_effect = create_sandbox_side_effect
        mock_adapter.execute_command.return_value = MockSandboxResult(exit_code=0)

        manager = VerifierSandboxManager()
        materializer = MockMaterializer()

        engine = CausalExecutionEngine(
            sandbox_manager=manager,
            sandbox_adapter=mock_adapter,
            materializer=materializer,
            vault=vault,
        )

        receipt = engine.execute_causal_triplet(
            context_envelope=envelope,
            sealed_record=sealed_record,
            witness_lock=lock,
            counterfactual_plan=cf_plan,
            execution_command="pytest",
        )
        assert receipt.is_causally_verified is False
        assert receipt.verdict == PreliminaryVerdict.CONTRADICTED
        assert receipt.transition == CausalTransition.NON_VERIFIED_TAMPERING_OR_INTEGRITY_FAILURE
        assert "reused the same sandbox identity" in receipt.narrative

    def test_builder_sandbox_reuse_raises_error(self) -> None:
        """Builder sandbox ID reuse for counterfactual world triggers BuilderSandboxReuseError."""
        from basebreak.verifier.sandbox import BuilderSandboxReuseError

        envelope, sealed_record, vault, _, cf_plan = _build_test_envelope_and_vault()
        lock = create_witness_lock(record=sealed_record, vault=vault)

        mock_adapter = MagicMock()
        sbx_count = 0

        def create_sandbox_side_effect(*args: Any, **kwargs: Any) -> SandboxIdentity:
            nonlocal sbx_count
            sbx_count += 1
            if sbx_count == 3:
                return SandboxIdentity(sandbox_id="sbx-builder-original-001")
            return SandboxIdentity(sandbox_id=f"sbx-fresh-{sbx_count:03d}")

        mock_adapter.create_sandbox.side_effect = create_sandbox_side_effect
        mock_adapter.execute_command.return_value = MockSandboxResult(exit_code=0)

        manager = VerifierSandboxManager(known_builder_sandbox_ids=("sbx-builder-original-001",))
        materializer = MockMaterializer()

        engine = CausalExecutionEngine(
            sandbox_manager=manager,
            sandbox_adapter=mock_adapter,
            materializer=materializer,
            vault=vault,
        )

        with pytest.raises(BuilderSandboxReuseError, match="reuse Builder sandbox"):
            engine.execute_causal_triplet(
                context_envelope=envelope,
                sealed_record=sealed_record,
                witness_lock=lock,
                counterfactual_plan=cf_plan,
                execution_command="pytest",
            )

    def test_no_op_subtraction_tree_collision_rejected(self) -> None:
        """Counterfactual tree matching candidate tree (no delta) is recognized as invalid."""
        envelope, sealed_record, vault, _, cf_plan = _build_test_envelope_and_vault()
        lock = create_witness_lock(record=sealed_record, vault=vault)

        mock_adapter = MagicMock()
        sbx_count = 0

        def create_sandbox_side_effect(*args: Any, **kwargs: Any) -> SandboxIdentity:
            nonlocal sbx_count
            sbx_count += 1
            return SandboxIdentity(sandbox_id=f"sbx-fresh-{sbx_count:03d}")

        mock_adapter.create_sandbox.side_effect = create_sandbox_side_effect
        mock_adapter.execute_command.return_value = MockSandboxResult(exit_code=0)

        manager = VerifierSandboxManager()
        bad_materializer = MockMaterializer(counterfactual_tree=SAMPLE_CANDIDATE_TREE)

        engine = CausalExecutionEngine(
            sandbox_manager=manager,
            sandbox_adapter=mock_adapter,
            materializer=bad_materializer,
            vault=vault,
        )

        receipt = engine.execute_causal_triplet(
            context_envelope=envelope,
            sealed_record=sealed_record,
            witness_lock=lock,
            counterfactual_plan=cf_plan,
            execution_command="pytest",
        )
        assert receipt.is_causally_verified is False
        assert receipt.verdict == PreliminaryVerdict.INCONCLUSIVE
        assert receipt.transition == CausalTransition.NON_VERIFIED_INVALID_COUNTERFACTUAL
        assert "subtraction had zero effect" in receipt.narrative

    def test_plan_binding_mismatch_fails_closed(self) -> None:
        """Counterfactual plan bound to wrong contract/source commit/locator fails closed."""
        envelope, sealed_record, vault, snapshot, cf_plan = _build_test_envelope_and_vault()
        lock = create_witness_lock(record=sealed_record, vault=vault)

        manager = VerifierSandboxManager()
        engine = CausalExecutionEngine(
            sandbox_manager=manager,
            sandbox_adapter=MagicMock(),
            materializer=MockMaterializer(),
            vault=vault,
        )

        # Plan with wrong contract digest
        tampered_contract_plan = plan_subtraction_from_snapshot(
            candidate_snapshot=snapshot,
            sealed_witness_digest=sealed_record.seal_digest,
            request=SubtractionRequest(strategy_type=SubtractionStrategyType.FULL_PATCH_REVERT),
        )
        # Create a tampered plan copy with wrong contract digest
        object.__setattr__(tampered_contract_plan, "frozen_contract_digest", "0" * 64)

        with pytest.raises(CausalBindingError, match="frozen_contract_digest"):
            engine.execute_causal_triplet(
                context_envelope=envelope,
                sealed_record=sealed_record,
                witness_lock=lock,
                counterfactual_plan=tampered_contract_plan,
                execution_command="pytest",
            )


# ==============================================================================
# P-11.06: Surgical Repair: Invalid Construction Semantics
# ==============================================================================


class TestP1106InvalidConstructionSemanticsRepair:
    """Validates surgical repair of P-11.06 invalid counterfactual construction semantics.

    Proves:
    A. Counterfactual patch application failure -> INCONCLUSIVE, never exception/VERIFIED.
    B. Staged candidate tree mismatch -> INCONCLUSIVE.
    C. Invalid resulting counterfactual materialization -> INCONCLUSIVE.
    D. Counterfactual materialization infrastructure failure cannot masquerade as behavioral FAIL.
    E. Existing integrity/tampering behavior remains non-verifying.
    F. Sandbox teardown occurs on failed counterfactual materialization.
    G. Valid FAIL->PASS->FAIL still produces CAUSAL_TRIPLET_VERIFIED.
    """

    @staticmethod
    def _make_exec_side_effect(cf_exit_code: int = 1) -> Any:
        def exec_side_effect(sbx: Any, cmd: Any, **kwargs: Any) -> MockSandboxResult:
            if "printf" in cmd:
                return MockSandboxResult(exit_code=0)
            if "001" in getattr(sbx, "sandbox_id", str(sbx)):
                return MockSandboxResult(exit_code=1, stderr="assert run() == 0 failed")
            elif "003" in getattr(sbx, "sandbox_id", str(sbx)) or "cf" in getattr(
                sbx, "sandbox_id", str(sbx)
            ):
                return MockSandboxResult(exit_code=cf_exit_code, stderr="assert run() == 0 failed")
            return MockSandboxResult(exit_code=0)

        return exec_side_effect

    def test_a_counterfactual_patch_application_failure_yields_inconclusive(self) -> None:
        """Requirement A: Counterfactual patch failure -> INCONCLUSIVE, never exception/VERIFIED."""
        envelope, sealed_record, vault, _, cf_plan = _build_test_envelope_and_vault()
        lock = create_witness_lock(record=sealed_record, vault=vault)

        mock_adapter = MagicMock()
        mock_adapter.create_sandbox.side_effect = [
            SandboxIdentity(sandbox_id="sbx-base-001"),
            SandboxIdentity(sandbox_id="sbx-cand-002"),
            SandboxIdentity(sandbox_id="sbx-cf-003"),
        ]
        mock_adapter.execute_command.side_effect = self._make_exec_side_effect()

        class PatchFailureMaterializer:
            def materialize_repository(self, *args: Any, **kwargs: Any) -> dict[str, object]:
                world = kwargs.get("world", ExecutionWorld.BASE)
                if world == ExecutionWorld.BASE:
                    return {
                        "resolved_commit_sha": SAMPLE_SOURCE_COMMIT,
                        "resolved_tree_sha": SAMPLE_BASE_TREE,
                        "workspace_path": "/verifier_workspace",
                        "is_verified": True,
                    }
                elif world == ExecutionWorld.CANDIDATE:
                    return {
                        "resolved_commit_sha": SAMPLE_SOURCE_COMMIT,
                        "resolved_tree_sha": SAMPLE_CANDIDATE_TREE,
                        "workspace_path": "/verifier_workspace",
                        "is_verified": True,
                    }
                elif world == ExecutionWorld.COUNTERFACTUAL:
                    raise CounterfactualMaterializationError(
                        "Failed to apply counterfactual delta in sandbox workspace (exit 1): "
                        "error: patch failed: demo.py:10"
                    )
                raise ValueError(f"Unknown world: {world}")

        manager = VerifierSandboxManager()
        engine = CausalExecutionEngine(
            sandbox_manager=manager,
            sandbox_adapter=mock_adapter,
            materializer=PatchFailureMaterializer(),
            vault=vault,
        )

        receipt = engine.execute_causal_triplet(
            context_envelope=envelope,
            sealed_record=sealed_record,
            witness_lock=lock,
            counterfactual_plan=cf_plan,
            execution_command="pytest",
        )

        # Must never be VERIFIED
        assert receipt.is_causally_verified is False
        assert receipt.verdict == PreliminaryVerdict.INCONCLUSIVE
        assert receipt.transition == CausalTransition.NON_VERIFIED_INVALID_COUNTERFACTUAL
        assert receipt.counterfactual_execution is None
        assert "Counterfactual materialization failed" in receipt.narrative
        assert verify_causal_receipt_integrity(receipt) is True

    def test_b_staged_candidate_tree_mismatch_yields_inconclusive(self) -> None:
        """Requirement B: Staged candidate tree mismatch -> INCONCLUSIVE."""
        envelope, sealed_record, vault, _, cf_plan = _build_test_envelope_and_vault()
        lock = create_witness_lock(record=sealed_record, vault=vault)

        mock_adapter = MagicMock()
        mock_adapter.create_sandbox.side_effect = [
            SandboxIdentity(sandbox_id="sbx-base-001"),
            SandboxIdentity(sandbox_id="sbx-cand-002"),
            SandboxIdentity(sandbox_id="sbx-cf-003"),
        ]
        mock_adapter.execute_command.side_effect = self._make_exec_side_effect()

        class StagedMismatchMaterializer:
            def materialize_repository(self, *args: Any, **kwargs: Any) -> dict[str, object]:
                world = kwargs.get("world", ExecutionWorld.BASE)
                if world == ExecutionWorld.BASE:
                    return {
                        "resolved_commit_sha": SAMPLE_SOURCE_COMMIT,
                        "resolved_tree_sha": SAMPLE_BASE_TREE,
                        "workspace_path": "/verifier_workspace",
                        "is_verified": True,
                    }
                elif world == ExecutionWorld.CANDIDATE:
                    return {
                        "resolved_commit_sha": SAMPLE_SOURCE_COMMIT,
                        "resolved_tree_sha": SAMPLE_CANDIDATE_TREE,
                        "workspace_path": "/verifier_workspace",
                        "is_verified": True,
                    }
                elif world == ExecutionWorld.COUNTERFACTUAL:
                    raise VerifierTreeDigestMismatchError(
                        "Staged candidate tree digest 'badtree' does not match "
                        "expected candidate tree digest"
                    )
                raise ValueError(f"Unknown world: {world}")

        manager = VerifierSandboxManager()
        engine = CausalExecutionEngine(
            sandbox_manager=manager,
            sandbox_adapter=mock_adapter,
            materializer=StagedMismatchMaterializer(),
            vault=vault,
        )

        receipt = engine.execute_causal_triplet(
            context_envelope=envelope,
            sealed_record=sealed_record,
            witness_lock=lock,
            counterfactual_plan=cf_plan,
            execution_command="pytest",
        )

        assert receipt.is_causally_verified is False
        assert receipt.verdict == PreliminaryVerdict.INCONCLUSIVE
        assert receipt.transition == CausalTransition.NON_VERIFIED_INVALID_COUNTERFACTUAL
        assert receipt.counterfactual_execution is None
        assert verify_causal_receipt_integrity(receipt) is True

    def test_c_invalid_resulting_counterfactual_materialization_yields_inconclusive(self) -> None:
        """Requirement C: Invalid resulting counterfactual materialization -> INCONCLUSIVE."""
        envelope, sealed_record, vault, _, cf_plan = _build_test_envelope_and_vault()
        lock = create_witness_lock(record=sealed_record, vault=vault)

        mock_adapter = MagicMock()
        mock_adapter.create_sandbox.side_effect = [
            SandboxIdentity(sandbox_id="sbx-base-001"),
            SandboxIdentity(sandbox_id="sbx-cand-002"),
            SandboxIdentity(sandbox_id="sbx-cf-003"),
        ]
        mock_adapter.execute_command.side_effect = self._make_exec_side_effect()

        class IncompleteMaterializer:
            def materialize_repository(self, *args: Any, **kwargs: Any) -> dict[str, object]:
                world = kwargs.get("world", ExecutionWorld.BASE)
                if world == ExecutionWorld.BASE:
                    return {
                        "resolved_commit_sha": SAMPLE_SOURCE_COMMIT,
                        "resolved_tree_sha": SAMPLE_BASE_TREE,
                        "workspace_path": "/verifier_workspace",
                        "is_verified": True,
                    }
                elif world == ExecutionWorld.CANDIDATE:
                    return {
                        "resolved_commit_sha": SAMPLE_SOURCE_COMMIT,
                        "resolved_tree_sha": SAMPLE_CANDIDATE_TREE,
                        "workspace_path": "/verifier_workspace",
                        "is_verified": True,
                    }
                elif world == ExecutionWorld.COUNTERFACTUAL:
                    # Missing tree hash in return dictionary triggers VerifierMaterializationError
                    return {
                        "resolved_commit_sha": SAMPLE_SOURCE_COMMIT,
                        "workspace_path": "/verifier_workspace",
                        "is_verified": True,
                    }
                raise ValueError(f"Unknown world: {world}")

        manager = VerifierSandboxManager()
        engine = CausalExecutionEngine(
            sandbox_manager=manager,
            sandbox_adapter=mock_adapter,
            materializer=IncompleteMaterializer(),
            vault=vault,
        )

        receipt = engine.execute_causal_triplet(
            context_envelope=envelope,
            sealed_record=sealed_record,
            witness_lock=lock,
            counterfactual_plan=cf_plan,
            execution_command="pytest",
        )

        assert receipt.is_causally_verified is False
        assert receipt.verdict == PreliminaryVerdict.INCONCLUSIVE
        assert receipt.transition == CausalTransition.NON_VERIFIED_INVALID_COUNTERFACTUAL
        assert receipt.counterfactual_execution is None
        assert verify_causal_receipt_integrity(receipt) is True

    def test_d_cf_infra_failure_cannot_masquerade_as_behavioral_fail(self) -> None:
        """Requirement D: CF infra failure cannot masquerade as behavioral FAIL."""
        envelope, sealed_record, vault, _, cf_plan = _build_test_envelope_and_vault()
        lock = create_witness_lock(record=sealed_record, vault=vault)

        mock_adapter = MagicMock()
        mock_adapter.create_sandbox.side_effect = [
            SandboxIdentity(sandbox_id="sbx-base-001"),
            SandboxIdentity(sandbox_id="sbx-cand-002"),
            SandboxIdentity(sandbox_id="sbx-cf-003"),
        ]
        # BASE fails, CANDIDATE passes (prefix that would yield VERIFIED if CF was FAIL)
        mock_adapter.execute_command.side_effect = self._make_exec_side_effect()

        class InfrastructureFailureMaterializer:
            def materialize_repository(self, *args: Any, **kwargs: Any) -> dict[str, object]:
                world = kwargs.get("world", ExecutionWorld.BASE)
                if world in (ExecutionWorld.BASE, ExecutionWorld.CANDIDATE):
                    return {
                        "resolved_commit_sha": SAMPLE_SOURCE_COMMIT,
                        "resolved_tree_sha": (
                            SAMPLE_BASE_TREE
                            if world == ExecutionWorld.BASE
                            else SAMPLE_CANDIDATE_TREE
                        ),
                        "workspace_path": "/verifier_workspace",
                        "is_verified": True,
                    }
                # Failure during clone/materialization in counterfactual sandbox
                raise CounterfactualMaterializationError(
                    "Network timeout during base repository clone inside counterfactual sandbox"
                )

        manager = VerifierSandboxManager()
        engine = CausalExecutionEngine(
            sandbox_manager=manager,
            sandbox_adapter=mock_adapter,
            materializer=InfrastructureFailureMaterializer(),
            vault=vault,
        )

        receipt = engine.execute_causal_triplet(
            context_envelope=envelope,
            sealed_record=sealed_record,
            witness_lock=lock,
            counterfactual_plan=cf_plan,
            execution_command="pytest",
        )

        # Must NEVER be treated as behavioral FAIL (which would have yielded VERIFIED)
        assert receipt.transition != CausalTransition.CAUSAL_TRIPLET_VERIFIED
        assert receipt.verdict != PreliminaryVerdict.VERIFIED
        assert receipt.is_causally_verified is False
        # Must deterministically be INCONCLUSIVE
        assert receipt.verdict == PreliminaryVerdict.INCONCLUSIVE
        assert receipt.transition == CausalTransition.NON_VERIFIED_INVALID_COUNTERFACTUAL
        assert receipt.counterfactual_execution is None

    def test_e_existing_integrity_and_tampering_behavior_remains_non_verifying(self) -> None:
        """Requirement E: Existing integrity/tampering behavior remains non-verifying."""
        envelope, sealed_record, vault, snapshot, cf_plan = _build_test_envelope_and_vault()
        lock = create_witness_lock(record=sealed_record, vault=vault)

        # 1. Sandbox ID collision triggers integrity failure -> CONTRADICTED
        mock_adapter = MagicMock()
        mock_adapter.create_sandbox.side_effect = [
            SandboxIdentity(sandbox_id="sbx-colliding-001"),
            SandboxIdentity(sandbox_id="sbx-colliding-001"),
            SandboxIdentity(sandbox_id="sbx-cf-003"),
        ]
        mock_adapter.execute_command.side_effect = self._make_exec_side_effect()

        manager = VerifierSandboxManager()
        engine = CausalExecutionEngine(
            sandbox_manager=manager,
            sandbox_adapter=mock_adapter,
            materializer=MockMaterializer(),
            vault=vault,
        )
        receipt = engine.execute_causal_triplet(
            context_envelope=envelope,
            sealed_record=sealed_record,
            witness_lock=lock,
            counterfactual_plan=cf_plan,
            execution_command="pytest",
        )
        assert receipt.is_causally_verified is False
        assert receipt.verdict == PreliminaryVerdict.CONTRADICTED
        assert receipt.transition == CausalTransition.NON_VERIFIED_TAMPERING_OR_INTEGRITY_FAILURE

        # 2. Builder sandbox reuse triggers BuilderSandboxReuseError
        builder_manager = VerifierSandboxManager(known_builder_sandbox_ids=("sbx-builder-001",))
        bad_adapter = MagicMock()
        bad_adapter.create_sandbox.return_value = SandboxIdentity(sandbox_id="sbx-builder-001")
        engine_builder = CausalExecutionEngine(
            sandbox_manager=builder_manager,
            sandbox_adapter=bad_adapter,
            materializer=MockMaterializer(),
            vault=vault,
        )
        with pytest.raises(BuilderSandboxReuseError):
            engine_builder.execute_causal_triplet(
                context_envelope=envelope,
                sealed_record=sealed_record,
                witness_lock=lock,
                counterfactual_plan=cf_plan,
                execution_command="pytest",
            )

        # 3. Plan binding mismatch fails closed with CausalBindingError
        tampered_plan = plan_subtraction_from_snapshot(
            candidate_snapshot=snapshot,
            sealed_witness_digest=sealed_record.seal_digest,
            request=SubtractionRequest(strategy_type=SubtractionStrategyType.FULL_PATCH_REVERT),
        )
        object.__setattr__(tampered_plan, "frozen_contract_digest", "f" * 64)
        with pytest.raises(CausalBindingError):
            engine.execute_causal_triplet(
                context_envelope=envelope,
                sealed_record=sealed_record,
                witness_lock=lock,
                counterfactual_plan=tampered_plan,
                execution_command="pytest",
            )

        # 4. Invalid plan type raises TypeError
        with pytest.raises(TypeError, match="CounterfactualDeltaPlan"):
            engine.execute_causal_triplet(
                context_envelope=envelope,
                sealed_record=sealed_record,
                witness_lock=lock,
                counterfactual_plan="not-a-plan",  # type: ignore[arg-type]
                execution_command="pytest",
            )

    def test_f_sandbox_teardown_occurs_on_failed_counterfactual_materialization(self) -> None:
        """Requirement F: Sandbox teardown occurs on failed counterfactual materialization."""
        envelope, sealed_record, vault, _, cf_plan = _build_test_envelope_and_vault()
        lock = create_witness_lock(record=sealed_record, vault=vault)

        mock_adapter = MagicMock()
        cf_sandbox_id = SandboxIdentity(sandbox_id="sbx-cf-to-teardown-999")
        mock_adapter.create_sandbox.side_effect = [
            SandboxIdentity(sandbox_id="sbx-base-001"),
            SandboxIdentity(sandbox_id="sbx-cand-002"),
            cf_sandbox_id,
        ]
        mock_adapter.execute_command.side_effect = self._make_exec_side_effect()

        class FailingMaterializer:
            def materialize_repository(self, *args: Any, **kwargs: Any) -> dict[str, object]:
                world = kwargs.get("world", ExecutionWorld.BASE)
                if world in (ExecutionWorld.BASE, ExecutionWorld.CANDIDATE):
                    return {
                        "resolved_commit_sha": SAMPLE_SOURCE_COMMIT,
                        "resolved_tree_sha": (
                            SAMPLE_BASE_TREE
                            if world == ExecutionWorld.BASE
                            else SAMPLE_CANDIDATE_TREE
                        ),
                        "workspace_path": "/verifier_workspace",
                        "is_verified": True,
                    }
                raise CounterfactualMaterializationError(
                    "Materialization failed inside fresh CF sandbox"
                )

        manager = VerifierSandboxManager()
        engine = CausalExecutionEngine(
            sandbox_manager=manager,
            sandbox_adapter=mock_adapter,
            materializer=FailingMaterializer(),
            vault=vault,
        )

        receipt = engine.execute_causal_triplet(
            context_envelope=envelope,
            sealed_record=sealed_record,
            witness_lock=lock,
            counterfactual_plan=cf_plan,
            execution_command="pytest",
        )

        assert receipt.verdict == PreliminaryVerdict.INCONCLUSIVE
        assert receipt.transition == CausalTransition.NON_VERIFIED_INVALID_COUNTERFACTUAL

        # Verify that teardown_sandbox was called on the counterfactual sandbox!
        mock_adapter.teardown_sandbox.assert_any_call(cf_sandbox_id)

    def test_g_valid_fail_pass_fail_produces_causal_triplet_verified(self) -> None:
        """Requirement G: Valid FAIL->PASS->FAIL still produces CAUSAL_TRIPLET_VERIFIED."""
        envelope, sealed_record, vault, _, cf_plan = _build_test_envelope_and_vault()
        lock = create_witness_lock(record=sealed_record, vault=vault)

        mock_adapter = MagicMock()
        mock_adapter.create_sandbox.side_effect = [
            SandboxIdentity(sandbox_id="sbx-base-001"),
            SandboxIdentity(sandbox_id="sbx-cand-002"),
            SandboxIdentity(sandbox_id="sbx-cf-003"),
        ]
        # BASE = exit 1 (FAIL), CANDIDATE = exit 0 (PASS), COUNTERFACTUAL = exit 1 (FAIL)
        mock_adapter.execute_command.side_effect = self._make_exec_side_effect(cf_exit_code=1)

        manager = VerifierSandboxManager()
        engine = CausalExecutionEngine(
            sandbox_manager=manager,
            sandbox_adapter=mock_adapter,
            materializer=MockMaterializer(),
            vault=vault,
        )

        receipt = engine.execute_causal_triplet(
            context_envelope=envelope,
            sealed_record=sealed_record,
            witness_lock=lock,
            counterfactual_plan=cf_plan,
            execution_command="pytest",
        )

        assert receipt.is_causally_verified is True
        assert receipt.verdict == PreliminaryVerdict.VERIFIED
        assert receipt.transition == CausalTransition.CAUSAL_TRIPLET_VERIFIED
        assert receipt.counterfactual_execution is not None
        assert receipt.counterfactual_execution.outcome == WitnessOutcome.FAIL
        assert receipt.base_execution.outcome == WitnessOutcome.FAIL
        assert receipt.candidate_execution.outcome == WitnessOutcome.PASS
        assert verify_causal_receipt_integrity(receipt) is True
