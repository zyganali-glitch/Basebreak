"""Comprehensive closure test suite for Phase 2: P-10 Causal Two-World Engine.

Validates all 7 micro-tasks of P-10:
- P-10.01: Execute identical witness on trusted base.
- P-10.02: Execute identical witness on exact candidate.
- P-10.03: Bind both executions to source/sandbox/witness hashes.
- P-10.04: Reconcile BUG_FIX FAIL->PASS deterministically.
- P-10.05: Handle PASS->PASS, FAIL->FAIL, ERROR/TIMEOUT as non-verified states.
- P-10.06: Produce first local causal receipt with unbroken cryptographic chain.
- P-10.07: Execute end-to-end causal vertical slice and produce judge-readable proof summary.
"""

from __future__ import annotations

import hashlib
import os
from typing import Any
from unittest.mock import MagicMock

import pytest

from basebreak.causal.engine import (
    CausalExecutionEngine,
)
from basebreak.causal.harness import (
    BASEBREAK_JUDGE_CLAIM,
    BASEBREAK_THESIS,
    run_causal_verification_slice,
)
from basebreak.causal.receipt import (
    CausalReceiptTamperingError,
    LocalCausalReceipt,
    WorldExecutionFact,
    create_causal_receipt,
    verify_causal_receipt_integrity,
)
from basebreak.causal.reconciliation import (
    CausalTransition,
    reconcile_causal_transition,
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
from basebreak.verifier.sandbox import VerifierSandboxManager
from basebreak.verifier.vacuity import (
    VacuityCheckResult,
    VacuityStatus,
)
from basebreak.verifier.witness_lock import (
    create_witness_lock,
)
from basebreak.verifier.witness_plan import (
    ValidatedWitnessArtifact,
    ValidatedWitnessPlan,
)
from basebreak.verifier.witness_result import (
    WitnessOutcome,
)
from basebreak.verifier.witness_store import (
    SealedWitnessRecord,
    TrustedWitnessVault,
    WitnessArtifact,
)


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
    def __init__(self, candidate_tree: str = "2" * 40) -> None:
        self.candidate_tree = candidate_tree

    def materialize_repository(self, *args: Any, **kwargs: Any) -> dict[str, object]:
        world = kwargs.get("world", ExecutionWorld.BASE)
        tree = "1" * 40 if world == ExecutionWorld.BASE else self.candidate_tree
        return {
            "resolved_commit_sha": "a" * 40,
            "resolved_tree_sha": tree,
            "workspace_path": "/verifier_workspace",
            "is_verified": True,
        }


def _build_mock_adapter() -> MagicMock:
    adapter = MagicMock()
    sbx_count = 0

    def create_sandbox_side_effect(*args: Any, **kwargs: Any) -> SandboxIdentity:
        nonlocal sbx_count
        sbx_count += 1
        return SandboxIdentity(sandbox_id=f"sbx-fresh-{sbx_count:03d}")

    adapter.create_sandbox.side_effect = create_sandbox_side_effect

    def exec_side_effect(sbx: Any, cmd: Any, **kwargs: Any) -> MockSandboxResult:
        if "printf" in str(cmd) or "base64" in str(cmd):
            return MockSandboxResult(exit_code=0)
        if "sbx-fresh-001" in str(sbx):
            return MockSandboxResult(exit_code=1, stderr="AssertionError: stdout not empty")
        return MockSandboxResult(exit_code=0, stdout="1 passed")

    adapter.execute_command.side_effect = exec_side_effect
    return adapter


def _create_test_pipeline_bundle() -> tuple[
    VerifierContextEnvelope,
    ValidatedWitnessPlan,
    SealedWitnessRecord,
    TrustedWitnessVault,
]:
    raw_task = "When user specifies --quiet flag, stdout must be empty."
    task = ingest_task(raw_task)
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
    cit = "When user specifies --quiet flag, stdout must be empty."
    start = task.normalized_text.index(cit)
    end = start + len(cit)
    req = ProposedRequirement(
        statement="Stdout must be empty when --quiet flag is active",
        citation=cit,
        citation_start=start,
        citation_end=end,
        rationale="Mandated quiet flag behavior",
    )
    bundle = ReviewBundle(task=task, semantics=semantics, requirements=(req,))
    session = ReviewSession(bundle)
    approval = session.approve()
    contract = freeze_review_result(approval)
    req_id = contract.requirements[0].requirement_id

    source_id = SourceIdentity(
        locator="https://github.com/zyganali-glitch/Basebreak.git",
        revision=CommitRevision("a" * 40),
    )
    patch_text = "--- a/src/cli.py\n+++ b/src/cli.py\n@@ -1 +1 @@\n-print('verbose')\n+pass\n"
    patch_digest = hashlib.sha256(patch_text.encode("utf-8")).hexdigest()
    cand_id = CandidateIdentity(
        candidate_id="cand-closure-01",
        source=source_id,
        patch_digest=patch_digest,
    )
    envelope = VerifierContextEnvelope.create(
        frozen_contract=contract,
        source_identity=source_id,
        candidate_identity=cand_id,
        candidate_patch_text=patch_text,
        candidate_tree_digest="2" * 40,
    )

    art_code = "def test_quiet():\n    output = 'actual'\n    assert output == ''\n"
    art_digest = hashlib.sha256(art_code.encode("utf-8")).hexdigest()
    art = ValidatedWitnessArtifact(
        path="tests/test_quiet.py",
        content=art_code,
        content_digest=art_digest,
        byte_size=len(art_code.encode("utf-8")),
        rationale="Tests quiet flag behavior",
    )
    plan = ValidatedWitnessPlan(
        witness_id="wit-closure-01",
        requirement_id=req_id,
        frozen_contract_digest=contract.contract_digest,
        source_commit_id="a" * 40,
        change_class=ChangeClass.BUG_FIX,
        plan_summary="Tests quiet flag behavior",
        target_files=("src/cli.py",),
        artifacts=(art,),
        execution_command=("pytest", "tests/test_quiet.py"),
        expected_failure_at_base="Fails on base",
        expected_success_at_candidate="Passes on candidate",
        plan_digest="d" * 64,
    )

    vault = TrustedWitnessVault(b"test-secret-key-32-bytes-secure!")
    art_stored = WitnessArtifact.from_text(path=art.path, content=art.content)
    sealed = vault.seal_witness(
        witness_id=plan.witness_id,
        frozen_contract_digest=plan.frozen_contract_digest,
        requirement_id=plan.requirement_id,
        source_commit_id=plan.source_commit_id,
        artifacts=(art_stored,),
    )
    return envelope, plan, sealed, vault


class TestP10CausalClosure:
    """Verifies all P-10 requirements and invariants."""

    def test_p10_01_through_p10_03_engine_execution_and_isolation(self) -> None:
        """P-10.01-03: Clean base & candidate execution with cryptographic binding."""
        envelope, plan, sealed, vault = _create_test_pipeline_bundle()
        adapter = _build_mock_adapter()
        manager = VerifierSandboxManager()
        materializer = MockMaterializer()

        engine = CausalExecutionEngine(
            sandbox_manager=manager,
            sandbox_adapter=adapter,
            materializer=materializer,
            vault=vault,
            provenance=EvidenceProvenance.LOCAL_EXECUTION,
        )

        lock = create_witness_lock(record=sealed, vault=vault)
        receipt = engine.execute_causal_pair(
            context_envelope=envelope,
            sealed_record=sealed,
            witness_lock=lock,
            execution_command=("pytest", "tests/test_quiet.py"),
        )

        # Invariants P-10.01 & P-10.02
        assert receipt.base_execution.world == ExecutionWorld.BASE
        assert receipt.base_execution.outcome == WitnessOutcome.FAIL
        assert receipt.candidate_execution.world == ExecutionWorld.CANDIDATE
        assert receipt.candidate_execution.outcome == WitnessOutcome.PASS

        # Invariant P-10.03: Distinct sandboxes
        assert receipt.base_execution.sandbox_id != receipt.candidate_execution.sandbox_id
        assert receipt.base_execution.sandbox_id == "sbx-fresh-001"
        assert receipt.candidate_execution.sandbox_id == "sbx-fresh-002"

        # Both sandboxes were torn down
        assert adapter.teardown_sandbox.call_count == 2

        # Invariant P-10.04: Causal BUG_FIX verified
        assert receipt.transition == CausalTransition.CAUSAL_BUG_FIX_VERIFIED
        assert receipt.verdict == PreliminaryVerdict.VERIFIED
        assert receipt.is_causally_verified is True

    def test_p10_04_reconciliation_truth(self) -> None:
        """P-10.04: BASE=FAIL + CANDIDATE=PASS is the ONLY causal bug fix verified transition."""
        fact = reconcile_causal_transition(
            base_outcome=WitnessOutcome.FAIL,
            candidate_outcome=WitnessOutcome.PASS,
        )
        assert fact.transition == CausalTransition.CAUSAL_BUG_FIX_VERIFIED
        assert fact.verdict == PreliminaryVerdict.VERIFIED
        assert fact.is_causally_verified is True

    def test_p10_05_anti_collapse_and_non_verified_states(self) -> None:
        """P-10.05: Blocks non-causal outcomes, vacuous witnesses, and invalid preconditions."""
        # 1. PASS -> PASS is UNVERIFIED_TRIVIAL_PASS
        f1 = reconcile_causal_transition(
            base_outcome=WitnessOutcome.PASS,
            candidate_outcome=WitnessOutcome.PASS,
        )
        assert f1.transition == CausalTransition.UNVERIFIED_TRIVIAL_PASS
        assert f1.verdict == PreliminaryVerdict.INCONCLUSIVE
        assert f1.is_causally_verified is False

        # 2. FAIL -> FAIL is UNVERIFIED_DEFECT_PERSISTS
        f2 = reconcile_causal_transition(
            base_outcome=WitnessOutcome.FAIL,
            candidate_outcome=WitnessOutcome.FAIL,
        )
        assert f2.transition == CausalTransition.UNVERIFIED_DEFECT_PERSISTS
        assert f2.verdict == PreliminaryVerdict.CONTRADICTED
        assert f2.is_causally_verified is False

        # 3. TIMEOUT is NON_VERIFIED_TIMEOUT
        f3 = reconcile_causal_transition(
            base_outcome=WitnessOutcome.TIMEOUT,
            candidate_outcome=WitnessOutcome.PASS,
        )
        assert f3.transition == CausalTransition.NON_VERIFIED_TIMEOUT
        assert f3.verdict == PreliminaryVerdict.INCONCLUSIVE
        assert f3.is_causally_verified is False

        # 4. ERROR is NON_VERIFIED_EXECUTION_ERROR
        f4 = reconcile_causal_transition(
            base_outcome=WitnessOutcome.FAIL,
            candidate_outcome=WitnessOutcome.ERROR,
        )
        assert f4.transition == CausalTransition.NON_VERIFIED_EXECUTION_ERROR
        assert f4.verdict == PreliminaryVerdict.INCONCLUSIVE
        assert f4.is_causally_verified is False

        # 5. Vacuous witness is NON_VERIFIED_VACUOUS
        vacuous_result = VacuityCheckResult(
            status=VacuityStatus.VACUOUS_NO_ASSERTIONS,
            is_vacuous=True,
            details="Zero assertions found in witness",
            assertion_count=0,
            target_symbols_referenced=(),
        )
        f5 = reconcile_causal_transition(
            base_outcome=WitnessOutcome.FAIL,
            candidate_outcome=WitnessOutcome.PASS,
            candidate_vacuity=vacuous_result,
        )
        assert f5.transition == CausalTransition.NON_VERIFIED_VACUOUS
        assert f5.verdict == PreliminaryVerdict.INCONCLUSIVE
        assert f5.is_causally_verified is False

        # 6. Integrity failure
        f6 = reconcile_causal_transition(
            base_outcome=WitnessOutcome.FAIL,
            candidate_outcome=WitnessOutcome.PASS,
            integrity_failure_reason="Sandbox ID collision detected",
        )
        assert f6.transition == CausalTransition.NON_VERIFIED_TAMPERING_OR_INTEGRITY_FAILURE
        assert f6.verdict == PreliminaryVerdict.CONTRADICTED
        assert f6.is_causally_verified is False

    def test_p10_06_causal_receipt_tamper_detection(self) -> None:
        """P-10.06: Unbroken cryptographic receipt; tampering detected immediately."""
        base_fact = WorldExecutionFact(
            world=ExecutionWorld.BASE,
            sandbox_id="sbx-base-001",
            source_commit_id="a" * 40,
            tree_digest="1" * 40,
            outcome=WitnessOutcome.FAIL,
            exit_code=1,
            termination_status=TerminationStatus.COMPLETED,
            stdout_digest="b" * 64,
            stderr_digest="c" * 64,
            result_digest="d" * 64,
            duration_seconds=2.0,
        )
        cand_fact = WorldExecutionFact(
            world=ExecutionWorld.CANDIDATE,
            sandbox_id="sbx-cand-002",
            source_commit_id="a" * 40,
            tree_digest="2" * 40,
            outcome=WitnessOutcome.PASS,
            exit_code=0,
            termination_status=TerminationStatus.COMPLETED,
            stdout_digest="e" * 64,
            stderr_digest="f" * 64,
            result_digest="0" * 64,
            duration_seconds=1.5,
        )

        receipt = create_causal_receipt(
            requirement_id="REQ-001",
            frozen_contract_digest="c" * 64,
            witness_id="wit-001",
            witness_digest="0" * 64,
            lock_digest="1" * 64,
            base_execution=base_fact,
            candidate_execution=cand_fact,
            transition=CausalTransition.CAUSAL_BUG_FIX_VERIFIED,
            verdict=PreliminaryVerdict.VERIFIED,
            provenance=EvidenceProvenance.LOCAL_EXECUTION,
            narrative="Base failed, candidate passed.",
        )

        # Integrity verified on authentic receipt
        assert verify_causal_receipt_integrity(receipt) is True

        # Tampering with verdict triggers CausalReceiptTamperingError
        with pytest.raises(CausalReceiptTamperingError, match="receipt_digest mismatch"):
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
                transition=receipt.transition,
                verdict=PreliminaryVerdict.INCONCLUSIVE,  # Mutated!
                provenance=receipt.provenance,
                narrative=receipt.narrative,
                created_at_utc=receipt.created_at_utc,
            )

    def test_p10_07_developer_harness_and_judge_proof_summary(self) -> None:
        """P-10.07: Developer slice execution and judge-readable proof summary formatting."""
        envelope, plan, sealed, vault = _create_test_pipeline_bundle()
        adapter = _build_mock_adapter()
        manager = VerifierSandboxManager()
        materializer = MockMaterializer()

        receipt, summary, markdown = run_causal_verification_slice(
            context_envelope=envelope,
            validated_plan=plan,
            sandbox_manager=manager,
            sandbox_adapter=adapter,
            materializer=materializer,
            vault=TrustedWitnessVault(b"test-secret-key-fresh-vault-32b"),
            provenance=EvidenceProvenance.LOCAL_EXECUTION,
        )

        # Verify summary content
        assert summary["causal_thesis"] == BASEBREAK_THESIS
        assert summary["judge_claim"] == BASEBREAK_JUDGE_CLAIM
        assert summary["preliminary_verdict"] == "VERIFIED"
        assert summary["is_causally_verified"] is True
        assert summary["causal_transition"] == "CAUSAL_BUG_FIX_VERIFIED"
        assert summary["evidence_provenance"] == "LOCAL_EXECUTION"
        assert summary["cryptographic_digest_chain"]["chain_valid"] is True

        # Verify markdown layout
        assert "# Basebreak Causal Verification Proof Summary" in markdown
        assert "If the patch matters, the base must break." in markdown
        assert "CAUSAL_BUG_FIX_VERIFIED" in markdown
        assert "[PASS] VERIFIED" in markdown
        assert "Cryptographic Digest Chain" in markdown

        # Verify receipt
        assert receipt.is_causally_verified is True
        assert verify_causal_receipt_integrity(receipt) is True

    @pytest.mark.live
    def test_p10_live_causal_vertical_slice(self) -> None:
        """P-10 Live: Vertical slice against Token Factory live environment if configured."""
        api_key = os.environ.get("NEBIUS_API_KEY")
        project_id = os.environ.get("NEBIUS_PROJECT_ID")
        if not api_key:
            pytest.skip("NEBIUS_API_KEY not configured for live test")
        if not project_id:
            pytest.skip("NEBIUS_PROJECT_ID not configured for remote VM sandbox creation")

        # When project_id is available, test against real remote Token Factory Sandboxes
        from basebreak.adapter.materializer import (  # type: ignore[import-untyped]
            GitRepositoryMaterializer,
        )
        from basebreak.adapter.nebius import (  # type: ignore[import-untyped]
            NebiusSandboxAdapter,
        )

        envelope, plan, sealed, vault = _create_test_pipeline_bundle()
        adapter = NebiusSandboxAdapter(api_key=api_key, project_id=project_id)
        manager = VerifierSandboxManager()
        materializer = GitRepositoryMaterializer()

        receipt, summary, markdown = run_causal_verification_slice(
            context_envelope=envelope,
            validated_plan=plan,
            sandbox_manager=manager,
            sandbox_adapter=adapter,
            materializer=materializer,
            vault=TrustedWitnessVault(b"test-secret-key-fresh-vault-32b"),
            provenance=EvidenceProvenance.LIVE_NEBIUS,
        )

        assert receipt.is_causally_verified is True
        assert verify_causal_receipt_integrity(receipt) is True
