"""Comprehensive tests for P-14.06: Sealed repair loop orchestration and budget ceilings."""

from __future__ import annotations

import subprocess
import tempfile
from dataclasses import dataclass
from pathlib import Path
from types import SimpleNamespace
from typing import Any

import pytest

from basebreak.builder.capture import CandidateSnapshot
from basebreak.compiler.freeze import FrozenContract, freeze_review_result
from basebreak.compiler.ingestion import ingest_task
from basebreak.compiler.requirements import ProposedRequirement
from basebreak.compiler.review import ReviewBundle, ReviewSession
from basebreak.compiler.semantics import (
    CertaintyLevel,
    ChangeClass,
    ChangeSemanticsClassification,
    DeterministicClassificationFact,
)
from basebreak.domain.execution import SandboxIdentity, TerminationStatus
from basebreak.domain.source import CommitRevision, SourceIdentity
from basebreak.domain.verdict import EvidenceProvenance, PreliminaryVerdict
from basebreak.evidence.artifact import compute_bytes_digest
from basebreak.repair.context import BuilderRepairContextEnvelope
from basebreak.repair.engine import (
    CleanImplementationError,
    RepairLoopBudget,
    RepairLoopCounters,
    RepairLoopReceipt,
    RepairLoopReceiptTamperingError,
    RepairLoopStatus,
    create_repair_loop_receipt,
    run_sealed_repair_loop,
    verify_clean_implementation_preflight,
    verify_repair_loop_receipt_integrity,
)
from basebreak.repair.feedback import (
    FailedExecutionFacts,
    FailureConditionCategory,
    RepairFeedbackIntegrityError,
    derive_safe_repair_feedback,
)
from basebreak.repair.sanitizer import DisclosureSanitizer
from basebreak.verifier.sandbox import VerifierSandboxManager
from basebreak.verifier.witness_lock import ImmutableWitnessLock, create_witness_lock
from basebreak.verifier.witness_result import WitnessOutcome
from basebreak.verifier.witness_store import (
    SealedWitnessRecord,
    TrustedWitnessVault,
    WitnessArtifact,
)

SAMPLE_SOURCE = SourceIdentity(
    locator="https://github.com/zyganali-glitch/basebreak-demo-target.git",
    revision=CommitRevision("40ff923a134a21d8e357deb7a7988571cd396b56"),
)
INITIAL_TREE = "f81f6faa0c7572f9941570bbce376fadc10f39a3"
INITIAL_PATCH = "diff --git a/a.py b/a.py\n--- a/a.py\n+++ b/a.py\n@@ -1 +1 @@\n-1\n+2\n"
INITIAL_PATCH_DIGEST = compute_bytes_digest(INITIAL_PATCH.encode("utf-8")).value

R1_TREE = "1111111111111111111111111111111111111111"
R1_PATCH = "diff --git a/a.py b/a.py\n--- a/a.py\n+++ b/a.py\n@@ -1 +1 @@\n-1\n+3\n"
R1_PATCH_DIGEST = compute_bytes_digest(R1_PATCH.encode("utf-8")).value

R2_TREE = "2222222222222222222222222222222222222222"
R2_PATCH = "diff --git a/a.py b/a.py\n--- a/a.py\n+++ b/a.py\n@@ -1 +1 @@\n-1\n+4\n"
R2_PATCH_DIGEST = compute_bytes_digest(R2_PATCH.encode("utf-8")).value

ORIGINATING_C0_DIGEST = compute_bytes_digest(b"candidate-00-execution-record").value
INITIAL_FAILED_FACTS = FailedExecutionFacts(
    exit_code=1,
    failure_message="AssertionError: stdout was not empty when --quiet was passed",
    sandbox_id="sbx-c0-initial",
    execution_digest=ORIGINATING_C0_DIGEST,
    condition_category=FailureConditionCategory.BEHAVIORAL_ASSERTION_FAILED,
)


@dataclass
class MockCommandResult:
    exit_code: int = 0
    stdout: str = ""
    stderr: str = ""
    duration_seconds: float = 0.1
    is_timed_out: bool = False


class ScriptableSandboxAdapter:
    """Mock sandbox adapter allowing programmatic responses per command/sandbox."""

    def __init__(self, exit_codes: list[int] | None = None) -> None:
        self.exit_codes = exit_codes or [0]
        self.created_sandboxes: list[str] = []
        self.torn_down_sandboxes: list[str] = []
        self.executed_commands: list[str] = []
        self.sbx_counter = 0

    def create_sandbox(self, **kwargs: Any) -> SandboxIdentity:
        self.sbx_counter += 1
        sid = f"sbx-fresh-{self.sbx_counter:03d}"
        self.created_sandboxes.append(sid)
        return SandboxIdentity(sandbox_id=sid)

    def teardown_sandbox(self, sandbox_identity: SandboxIdentity) -> None:
        self.torn_down_sandboxes.append(sandbox_identity.sandbox_id)

    def execute_command(
        self, sandbox_identity: SandboxIdentity, command: str, **kwargs: Any
    ) -> MockCommandResult:
        self.executed_commands.append(command)
        if "printf" in command or "set -e" in command:
            return MockCommandResult(exit_code=0)
        code = self.exit_codes.pop(0) if self.exit_codes else 0
        return MockCommandResult(
            exit_code=code,
            stdout="pytest output",
            stderr="AssertionError" if code != 0 else "",
            duration_seconds=0.1,
        )


class DynamicMaterializer:
    """Materializer that mirrors the requested candidate tree digest."""

    def __init__(self, workspace_path: str = "/verifier_workspace") -> None:
        self.workspace_path = workspace_path

    def materialize_clean_base(self, **kwargs: Any) -> dict[str, Any]:
        tree = kwargs.get("candidate_tree_digest") or INITIAL_TREE
        return {
            "resolved_commit_sha": SAMPLE_SOURCE.resolved_commit_id,
            "materialized_tree_digest": tree,
            "workspace_path": self.workspace_path,
        }


def _make_fixture_chain() -> tuple[
    FrozenContract,
    SealedWitnessRecord,
    ImmutableWitnessLock,
    CandidateSnapshot,
]:
    raw_text = "When user specifies --quiet flag, stdout must be empty."
    task = ingest_task(raw_text)
    fact = DeterministicClassificationFact(
        inferred_class=ChangeClass.BUG_FIX,
        certainty=CertaintyLevel.CONFIDENT,
        confidence=1.0,
        alternative_classes=(),
        rationale="Fixes verbose leak when quiet flag is set",
        evidence_citations=("quiet flag",),
        matched_signals=("quiet", "bug"),
    )
    semantics = ChangeSemanticsClassification(
        task_digest=task.task_digest,
        change_class=ChangeClass.BUG_FIX,
        certainty=CertaintyLevel.CONFIDENT,
        confidence=1.0,
        alternative_classes=(),
        rationale="Fixes verbose leak when quiet flag is set",
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
    bundle = ReviewBundle(
        task=task,
        semantics=semantics,
        requirements=(req,),
    )
    session = ReviewSession(bundle)
    approval = session.approve()
    frozen_contract = freeze_review_result(approval)
    req_id = frozen_contract.requirements[0].requirement_id
    contract_digest = frozen_contract.contract_digest

    vault = TrustedWitnessVault(vault_secret=b"test-secret-key-for-vault-auth")
    wa = WitnessArtifact.from_text(
        path="tests/test_witness.py",
        content="def test_fix(): pass\n",
    )
    sealed_record = vault.seal_witness(
        witness_id="wit-01",
        requirement_id=req_id,
        frozen_contract_digest=contract_digest,
        source_commit_id=SAMPLE_SOURCE.resolved_commit_id,
        artifacts=[wa],
    )
    witness_lock = create_witness_lock(record=sealed_record, vault=vault)

    initial_candidate = CandidateSnapshot(
        candidate_id="cand-buggy-00",
        source_identity=SAMPLE_SOURCE,
        candidate_tree_digest=INITIAL_TREE,
        patch_digest=INITIAL_PATCH_DIGEST,
        patch_text=INITIAL_PATCH,
        files_added=(),
        files_modified=("a.py",),
        files_deleted=(),
        builder_authored_tests=(),
        frozen_contract_digest=contract_digest,
        context_digest="0" * 64,
        sandbox_identity=SandboxIdentity(sandbox_id="sbx-c0-initial"),
        provenance=EvidenceProvenance.LOCAL_EXECUTION,
    )

    return frozen_contract, sealed_record, witness_lock, initial_candidate


def test_repair_loop_success_on_round_1() -> None:
    frozen_contract, sealed_record, witness_lock, initial_cand = _make_fixture_chain()
    adapter = ScriptableSandboxAdapter([0])  # exit code 0 -> PASS
    materializer = DynamicMaterializer()
    manager = VerifierSandboxManager()

    def builder_fn(ctx: BuilderRepairContextEnvelope) -> CandidateSnapshot:
        return CandidateSnapshot(
            candidate_id="cand-repaired-r1",
            source_identity=SAMPLE_SOURCE,
            candidate_tree_digest=R1_TREE,
            patch_digest=R1_PATCH_DIGEST,
            patch_text=R1_PATCH,
            files_added=(),
            files_modified=("a.py",),
            files_deleted=(),
            builder_authored_tests=(),
            frozen_contract_digest=frozen_contract.contract_digest,
            context_digest=ctx.repair_context_digest,
            provenance=EvidenceProvenance.LOCAL_EXECUTION,
        )

    receipt = run_sealed_repair_loop(
        initial_candidate=initial_cand,
        frozen_contract=frozen_contract,
        source_identity=SAMPLE_SOURCE,
        sealed_record=sealed_record,
        witness_lock=witness_lock,
        builder_repair_fn=builder_fn,
        sandbox_manager=manager,
        sandbox_adapter=adapter,
        materializer=materializer,
        execution_command="pytest tests/test_witness.py",
        budget=RepairLoopBudget(max_repair_rounds=2),
        originating_receipt_digest=ORIGINATING_C0_DIGEST,
        initial_failure_facts=INITIAL_FAILED_FACTS,
        prior_sandbox_ids=["sbx-c0-initial"],
    )

    assert receipt.status == RepairLoopStatus.VERIFIED_AFTER_REPAIR
    assert receipt.preliminary_verdict == PreliminaryVerdict.VERIFIED
    assert receipt.is_causally_verified is True
    assert receipt.grants_pass is True
    assert receipt.total_rounds == 1
    assert receipt.final_candidate_id == "cand-repaired-r1"
    assert verify_repair_loop_receipt_integrity(receipt) is True


def test_repair_loop_success_on_round_2() -> None:
    frozen_contract, sealed_record, witness_lock, initial_cand = _make_fixture_chain()
    # Round 1 fails (exit 1), Round 2 passes (exit 0)
    adapter = ScriptableSandboxAdapter([1, 0])
    materializer = DynamicMaterializer()
    manager = VerifierSandboxManager()

    def builder_fn(ctx: BuilderRepairContextEnvelope) -> CandidateSnapshot:
        if ctx.repair_round == 1:
            return CandidateSnapshot(
                candidate_id="cand-attempt-r1",
                source_identity=SAMPLE_SOURCE,
                candidate_tree_digest=R1_TREE,
                patch_digest=R1_PATCH_DIGEST,
                patch_text=R1_PATCH,
                files_added=(),
                files_modified=("a.py",),
                files_deleted=(),
                builder_authored_tests=(),
                frozen_contract_digest=frozen_contract.contract_digest,
                context_digest=ctx.repair_context_digest,
                provenance=EvidenceProvenance.LOCAL_EXECUTION,
            )
        return CandidateSnapshot(
            candidate_id="cand-attempt-r2",
            source_identity=SAMPLE_SOURCE,
            candidate_tree_digest=R2_TREE,
            patch_digest=R2_PATCH_DIGEST,
            patch_text=R2_PATCH,
            files_added=(),
            files_modified=("a.py",),
            files_deleted=(),
            builder_authored_tests=(),
            frozen_contract_digest=frozen_contract.contract_digest,
            context_digest=ctx.repair_context_digest,
            provenance=EvidenceProvenance.LOCAL_EXECUTION,
        )

    receipt = run_sealed_repair_loop(
        initial_candidate=initial_cand,
        frozen_contract=frozen_contract,
        source_identity=SAMPLE_SOURCE,
        sealed_record=sealed_record,
        witness_lock=witness_lock,
        builder_repair_fn=builder_fn,
        sandbox_manager=manager,
        sandbox_adapter=adapter,
        materializer=materializer,
        execution_command="pytest tests/test_witness.py",
        budget=RepairLoopBudget(max_repair_rounds=2),
        originating_receipt_digest=ORIGINATING_C0_DIGEST,
        initial_failure_facts=INITIAL_FAILED_FACTS,
        prior_sandbox_ids=["sbx-c0-initial"],
    )

    assert receipt.status == RepairLoopStatus.VERIFIED_AFTER_REPAIR
    assert receipt.preliminary_verdict == PreliminaryVerdict.VERIFIED
    assert receipt.is_causally_verified is True
    assert receipt.grants_pass is True
    assert receipt.total_rounds == 2
    assert receipt.final_candidate_id == "cand-attempt-r2"
    assert verify_repair_loop_receipt_integrity(receipt) is True


def test_repair_budget_exhausted_rounds() -> None:
    frozen_contract, sealed_record, witness_lock, initial_cand = _make_fixture_chain()
    # Both round 1 and round 2 fail (exit 1)
    adapter = ScriptableSandboxAdapter([1, 1])
    materializer = DynamicMaterializer()
    manager = VerifierSandboxManager()

    def builder_fn(ctx: BuilderRepairContextEnvelope) -> CandidateSnapshot:
        tree = R1_TREE if ctx.repair_round == 1 else R2_TREE
        patch = R1_PATCH if ctx.repair_round == 1 else R2_PATCH
        p_digest = R1_PATCH_DIGEST if ctx.repair_round == 1 else R2_PATCH_DIGEST
        return CandidateSnapshot(
            candidate_id=f"cand-attempt-r{ctx.repair_round}",
            source_identity=SAMPLE_SOURCE,
            candidate_tree_digest=tree,
            patch_digest=p_digest,
            patch_text=patch,
            files_added=(),
            files_modified=("a.py",),
            files_deleted=(),
            builder_authored_tests=(),
            frozen_contract_digest=frozen_contract.contract_digest,
            context_digest=ctx.repair_context_digest,
            provenance=EvidenceProvenance.LOCAL_EXECUTION,
        )

    receipt = run_sealed_repair_loop(
        initial_candidate=initial_cand,
        frozen_contract=frozen_contract,
        source_identity=SAMPLE_SOURCE,
        sealed_record=sealed_record,
        witness_lock=witness_lock,
        builder_repair_fn=builder_fn,
        sandbox_manager=manager,
        sandbox_adapter=adapter,
        materializer=materializer,
        execution_command="pytest tests/test_witness.py",
        budget=RepairLoopBudget(max_repair_rounds=2),
        originating_receipt_digest=ORIGINATING_C0_DIGEST,
        initial_failure_facts=INITIAL_FAILED_FACTS,
        prior_sandbox_ids=["sbx-c0-initial"],
    )

    assert receipt.status == RepairLoopStatus.REPAIR_BUDGET_EXHAUSTED
    assert receipt.preliminary_verdict == PreliminaryVerdict.CONTRADICTED
    assert receipt.is_causally_verified is False
    assert receipt.grants_pass is False
    assert receipt.total_rounds == 2
    assert verify_repair_loop_receipt_integrity(receipt) is True


def test_repair_stagnation_no_progress() -> None:
    frozen_contract, sealed_record, witness_lock, initial_cand = _make_fixture_chain()
    adapter = ScriptableSandboxAdapter([0])
    materializer = DynamicMaterializer()
    manager = VerifierSandboxManager()

    # Builder returns unchanged patch
    def builder_stagnant_fn(ctx: BuilderRepairContextEnvelope) -> CandidateSnapshot:
        return CandidateSnapshot(
            candidate_id="cand-stagnant-01",
            source_identity=SAMPLE_SOURCE,
            candidate_tree_digest=INITIAL_TREE,  # unchanged tree!
            patch_digest=INITIAL_PATCH_DIGEST,  # unchanged patch!
            patch_text=INITIAL_PATCH,
            files_added=(),
            files_modified=("a.py",),
            files_deleted=(),
            builder_authored_tests=(),
            frozen_contract_digest=frozen_contract.contract_digest,
            context_digest=ctx.repair_context_digest,
            provenance=EvidenceProvenance.LOCAL_EXECUTION,
        )

    receipt = run_sealed_repair_loop(
        initial_candidate=initial_cand,
        frozen_contract=frozen_contract,
        source_identity=SAMPLE_SOURCE,
        sealed_record=sealed_record,
        witness_lock=witness_lock,
        builder_repair_fn=builder_stagnant_fn,
        sandbox_manager=manager,
        sandbox_adapter=adapter,
        materializer=materializer,
        execution_command="pytest tests/test_witness.py",
        budget=RepairLoopBudget(max_repair_rounds=2),
        originating_receipt_digest=ORIGINATING_C0_DIGEST,
        initial_failure_facts=INITIAL_FAILED_FACTS,
        prior_sandbox_ids=["sbx-c0-initial"],
    )

    assert receipt.status == RepairLoopStatus.REPAIR_NO_PROGRESS
    assert receipt.is_causally_verified is False
    assert receipt.grants_pass is False
    assert verify_repair_loop_receipt_integrity(receipt) is True


def test_repair_invalid_candidate_protected_surface() -> None:
    frozen_contract, sealed_record, witness_lock, initial_cand = _make_fixture_chain()
    adapter = ScriptableSandboxAdapter([0])
    materializer = DynamicMaterializer()
    manager = VerifierSandboxManager()

    # Builder tries to edit AGENTS.md (protected surface)
    def builder_malicious_fn(ctx: BuilderRepairContextEnvelope) -> CandidateSnapshot:
        return CandidateSnapshot(
            candidate_id="cand-malicious-01",
            source_identity=SAMPLE_SOURCE,
            candidate_tree_digest=R1_TREE,
            patch_digest=R1_PATCH_DIGEST,
            patch_text=R1_PATCH,
            files_added=(),
            files_modified=("AGENTS.md",),  # Protected surface!
            files_deleted=(),
            builder_authored_tests=(),
            frozen_contract_digest=frozen_contract.contract_digest,
            context_digest=ctx.repair_context_digest,
            provenance=EvidenceProvenance.LOCAL_EXECUTION,
        )

    receipt = run_sealed_repair_loop(
        initial_candidate=initial_cand,
        frozen_contract=frozen_contract,
        source_identity=SAMPLE_SOURCE,
        sealed_record=sealed_record,
        witness_lock=witness_lock,
        builder_repair_fn=builder_malicious_fn,
        sandbox_manager=manager,
        sandbox_adapter=adapter,
        materializer=materializer,
        execution_command="pytest tests/test_witness.py",
        budget=RepairLoopBudget(max_repair_rounds=2),
        originating_receipt_digest=ORIGINATING_C0_DIGEST,
        initial_failure_facts=INITIAL_FAILED_FACTS,
        prior_sandbox_ids=["sbx-c0-initial"],
    )

    assert receipt.status == RepairLoopStatus.REPAIR_INVALID_CANDIDATE
    assert receipt.grants_pass is False
    assert "protected surface" in str(receipt.failure_reason).lower()
    assert verify_repair_loop_receipt_integrity(receipt) is True


def test_repair_invalid_candidate_self_certification() -> None:
    frozen_contract, sealed_record, witness_lock, initial_cand = _make_fixture_chain()
    adapter = ScriptableSandboxAdapter([0])
    materializer = DynamicMaterializer()
    manager = VerifierSandboxManager()

    # Builder tries to set is_authoritative=True
    def builder_self_certify(ctx: BuilderRepairContextEnvelope) -> CandidateSnapshot:
        snap = CandidateSnapshot(
            candidate_id="cand-self-certify",
            source_identity=SAMPLE_SOURCE,
            candidate_tree_digest=R1_TREE,
            patch_digest=R1_PATCH_DIGEST,
            patch_text=R1_PATCH,
            files_added=(),
            files_modified=("a.py",),
            files_deleted=(),
            builder_authored_tests=(),
            frozen_contract_digest=frozen_contract.contract_digest,
            context_digest=ctx.repair_context_digest,
            provenance=EvidenceProvenance.LOCAL_EXECUTION,
            is_authoritative=False,
        )
        object.__setattr__(snap, "is_authoritative", True)
        return snap

    receipt = run_sealed_repair_loop(
        initial_candidate=initial_cand,
        frozen_contract=frozen_contract,
        source_identity=SAMPLE_SOURCE,
        sealed_record=sealed_record,
        witness_lock=witness_lock,
        builder_repair_fn=builder_self_certify,
        sandbox_manager=manager,
        sandbox_adapter=adapter,
        materializer=materializer,
        execution_command="pytest tests/test_witness.py",
        budget=RepairLoopBudget(max_repair_rounds=2),
        originating_receipt_digest=ORIGINATING_C0_DIGEST,
        initial_failure_facts=INITIAL_FAILED_FACTS,
        prior_sandbox_ids=["sbx-c0-initial"],
    )

    assert receipt.status == RepairLoopStatus.REPAIR_INVALID_CANDIDATE
    assert receipt.grants_pass is False
    assert "self-certification" in str(receipt.failure_reason).lower()
    assert verify_repair_loop_receipt_integrity(receipt) is True


def test_repair_infra_failure_builder_crash() -> None:
    frozen_contract, sealed_record, witness_lock, initial_cand = _make_fixture_chain()
    adapter = ScriptableSandboxAdapter([0])
    materializer = DynamicMaterializer()
    manager = VerifierSandboxManager()

    def builder_crashes(ctx: BuilderRepairContextEnvelope) -> CandidateSnapshot:
        raise RuntimeError("Builder process crashed with OutOfMemory")

    receipt = run_sealed_repair_loop(
        initial_candidate=initial_cand,
        frozen_contract=frozen_contract,
        source_identity=SAMPLE_SOURCE,
        sealed_record=sealed_record,
        witness_lock=witness_lock,
        builder_repair_fn=builder_crashes,
        sandbox_manager=manager,
        sandbox_adapter=adapter,
        materializer=materializer,
        execution_command="pytest tests/test_witness.py",
        budget=RepairLoopBudget(max_repair_rounds=2),
        originating_receipt_digest=ORIGINATING_C0_DIGEST,
        initial_failure_facts=INITIAL_FAILED_FACTS,
        prior_sandbox_ids=["sbx-c0-initial"],
    )

    assert receipt.status == RepairLoopStatus.REPAIR_INFRA_FAILURE
    assert receipt.grants_pass is False
    assert "crashed" in str(receipt.failure_reason).lower()
    assert verify_repair_loop_receipt_integrity(receipt) is True


def test_receipt_tamper_detection() -> None:
    receipt = create_repair_loop_receipt(
        repair_receipt_id="RLR-01",
        initial_candidate_id="cand-00",
        initial_patch_digest=INITIAL_PATCH_DIGEST,
        initial_tree_digest=INITIAL_TREE,
        final_candidate_id="cand-01",
        final_patch_digest=R1_PATCH_DIGEST,
        final_tree_digest=R1_TREE,
        status=RepairLoopStatus.REPAIR_BUDGET_EXHAUSTED,
        preliminary_verdict=PreliminaryVerdict.CONTRADICTED,
        is_causally_verified=False,
        grants_pass=False,
        total_rounds=2,
        lineage_digests=["a" * 64],
        feedback_digests=["b" * 64],
        reproduction_receipt_digests=["c" * 64],
        counters={"repair_rounds_completed": 2},
        failure_reason="Rounds exhausted",
        provenance=EvidenceProvenance.LOCAL_EXECUTION,
    )
    assert verify_repair_loop_receipt_integrity(receipt) is True

    # Tampering with grants_pass
    tampered = RepairLoopReceipt(
        schema_version=receipt.schema_version,
        repair_receipt_id=receipt.repair_receipt_id,
        initial_candidate_id=receipt.initial_candidate_id,
        initial_patch_digest=receipt.initial_patch_digest,
        initial_tree_digest=receipt.initial_tree_digest,
        final_candidate_id=receipt.final_candidate_id,
        final_patch_digest=receipt.final_patch_digest,
        final_tree_digest=receipt.final_tree_digest,
        status=receipt.status,
        preliminary_verdict=receipt.preliminary_verdict,
        is_causally_verified=False,
        grants_pass=False,
        is_authoritative=False,
        total_rounds=receipt.total_rounds,
        lineage_digests=receipt.lineage_digests,
        feedback_digests=receipt.feedback_digests,
        reproduction_receipt_digests=receipt.reproduction_receipt_digests,
        counters=receipt.counters,
        failure_reason="Modified reason",  # Tampered field!
        provenance=receipt.provenance,
        created_at=receipt.created_at,
        receipt_digest=receipt.receipt_digest,
    )
    with pytest.raises(RepairLoopReceiptTamperingError):
        verify_repair_loop_receipt_integrity(tampered)


# =============================================================================
# DEFECT A REGRESSION TESTS: Real failure feedback is execution-derived
# =============================================================================


def test_derive_safe_repair_feedback_from_execution_facts() -> None:
    san = DisclosureSanitizer(known_witness_ids=("wit-01",))
    facts = FailedExecutionFacts(
        exit_code=1,
        termination_status=TerminationStatus.COMPLETED,
        failure_message="AssertionError detected",
        sandbox_id="sbx-c0-test",
        execution_digest="a" * 64,
        condition_category=FailureConditionCategory.BEHAVIORAL_ASSERTION_FAILED,
        duration_seconds=1.23,
    )
    feedback = derive_safe_repair_feedback(
        candidate_id="cand-test-01",
        requirement_id="REQ-01",
        change_class=ChangeClass.BUG_FIX,
        failed_facts=facts,
        sanitizer=san,
        originating_receipt_digest="a" * 64,
        feedback_round=1,
        permitted_patch_region=["a.py"],
        provenance=EvidenceProvenance.LOCAL_EXECUTION,
        requirement_statement="When quiet flag is set, output must be empty",
    )
    assert feedback.candidate_id == "cand-test-01"
    assert feedback.requirement_id == "REQ-01"
    assert feedback.failed_condition == FailureConditionCategory.BEHAVIORAL_ASSERTION_FAILED
    assert "exit code 1" in feedback.observed_behavior
    assert "AssertionError detected" in feedback.observed_behavior
    assert "quiet flag is set" in feedback.expected_behavior
    assert feedback.originating_receipt_digest == "a" * 64
    assert feedback.counterexample is None  # Never fabricated!
    assert feedback.is_authoritative is False
    assert feedback.grants_pass is False


def test_derive_safe_repair_feedback_no_counterexample_fabrication() -> None:
    san = DisclosureSanitizer(known_witness_ids=("wit-01",))
    # Incomplete counterexample data (missing actual output)
    facts = FailedExecutionFacts(
        exit_code=2,
        failure_message="Error in output",
        counterexample_input="payload_input",
        counterexample_actual="",  # Empty!
        counterexample_expected="expected_output",
    )
    feedback = derive_safe_repair_feedback(
        candidate_id="cand-test-02",
        requirement_id="REQ-01",
        change_class=ChangeClass.BUG_FIX,
        failed_facts=facts,
        sanitizer=san,
        originating_receipt_digest="b" * 64,
        feedback_round=1,
        permitted_patch_region=["a.py"],
        provenance=EvidenceProvenance.LOCAL_EXECUTION,
    )
    assert feedback.counterexample is None  # Fail closed against partial/fabricated counterexample


def test_derive_safe_repair_feedback_with_verified_counterexample() -> None:
    san = DisclosureSanitizer(known_witness_ids=("wit-01",))
    facts = FailedExecutionFacts(
        exit_code=1,
        failure_message="AssertionError",
        counterexample_input="quiet=True",
        counterexample_actual="QUIET: test",
        counterexample_expected="empty string",
    )
    feedback = derive_safe_repair_feedback(
        candidate_id="cand-test-03",
        requirement_id="REQ-01",
        change_class=ChangeClass.BUG_FIX,
        failed_facts=facts,
        sanitizer=san,
        originating_receipt_digest="c" * 64,
        feedback_round=1,
        permitted_patch_region=["a.py"],
        provenance=EvidenceProvenance.LOCAL_EXECUTION,
    )
    assert feedback.counterexample is not None
    assert feedback.counterexample.input_summary == "quiet=True"
    assert feedback.counterexample.actual_output_summary == "QUIET: test"
    assert feedback.counterexample.expected_output_summary == "empty string"
    assert feedback.counterexample.is_sanitized is True


def test_derive_safe_repair_feedback_sanitization_defense() -> None:
    san = DisclosureSanitizer(known_witness_ids=("wit-01",))
    # Failure facts inadvertently containing witness ID token
    facts = FailedExecutionFacts(
        exit_code=1,
        failure_message="Failed in wit-01 execution",
    )
    feedback = derive_safe_repair_feedback(
        candidate_id="cand-test-04",
        requirement_id="REQ-01",
        change_class=ChangeClass.BUG_FIX,
        failed_facts=facts,
        sanitizer=san,
        originating_receipt_digest="d" * 64,
        feedback_round=1,
        permitted_patch_region=["a.py"],
        provenance=EvidenceProvenance.LOCAL_EXECUTION,
    )
    assert "wit-01" not in feedback.observed_behavior
    assert "[REDACTED_WITNESS]" in feedback.observed_behavior


def test_repair_loop_multi_round_execution_derived_feedback() -> None:
    frozen_contract, sealed_record, witness_lock, initial_cand = _make_fixture_chain()
    # Round 1 fails (exit 1), Round 2 passes (exit 0)
    adapter = ScriptableSandboxAdapter([1, 0])
    materializer = DynamicMaterializer()
    manager = VerifierSandboxManager()

    captured_feedback_observed: list[str] = []
    captured_orig_digests: list[str] = []

    def builder_fn(ctx: BuilderRepairContextEnvelope) -> CandidateSnapshot:
        captured_feedback_observed.append(ctx.repair_feedback.observed_behavior)
        captured_orig_digests.append(ctx.repair_feedback.originating_receipt_digest)
        if ctx.repair_round == 1:
            return CandidateSnapshot(
                candidate_id="cand-attempt-r1",
                source_identity=SAMPLE_SOURCE,
                candidate_tree_digest=R1_TREE,
                patch_digest=R1_PATCH_DIGEST,
                patch_text=R1_PATCH,
                files_added=(),
                files_modified=("a.py",),
                files_deleted=(),
                builder_authored_tests=(),
                frozen_contract_digest=frozen_contract.contract_digest,
                context_digest=ctx.repair_context_digest,
                provenance=EvidenceProvenance.LOCAL_EXECUTION,
            )
        return CandidateSnapshot(
            candidate_id="cand-attempt-r2",
            source_identity=SAMPLE_SOURCE,
            candidate_tree_digest=R2_TREE,
            patch_digest=R2_PATCH_DIGEST,
            patch_text=R2_PATCH,
            files_added=(),
            files_modified=("a.py",),
            files_deleted=(),
            builder_authored_tests=(),
            frozen_contract_digest=frozen_contract.contract_digest,
            context_digest=ctx.repair_context_digest,
            provenance=EvidenceProvenance.LOCAL_EXECUTION,
        )

    initial_facts = FailedExecutionFacts(
        exit_code=42,
        failure_message="Initial defect reproduced",
        sandbox_id="sbx-c0-initial",
        execution_digest="e" * 64,
    )

    receipt = run_sealed_repair_loop(
        initial_candidate=initial_cand,
        frozen_contract=frozen_contract,
        source_identity=SAMPLE_SOURCE,
        sealed_record=sealed_record,
        witness_lock=witness_lock,
        builder_repair_fn=builder_fn,
        sandbox_manager=manager,
        sandbox_adapter=adapter,
        materializer=materializer,
        execution_command="pytest tests/test_witness.py",
        budget=RepairLoopBudget(max_repair_rounds=2),
        originating_receipt_digest="e" * 64,
        initial_failure_facts=initial_facts,
        prior_sandbox_ids=["sbx-c0-initial"],
    )

    assert receipt.status == RepairLoopStatus.VERIFIED_AFTER_REPAIR
    assert len(captured_feedback_observed) == 2
    # Round 1 feedback is derived from initial_facts
    assert "exit code 42" in captured_feedback_observed[0]
    assert "Initial defect reproduced" in captured_feedback_observed[0]
    assert captured_orig_digests[0] == "e" * 64
    # Round 2 feedback is derived from Round 1 reproduction receipt
    assert "exit code 1" in captured_feedback_observed[1]
    assert "Reproduction outcome: FAIL" in captured_feedback_observed[1]
    assert captured_orig_digests[1] == receipt.reproduction_receipt_digests[0]


# =============================================================================
# DEFECT B REGRESSION TESTS: Sandbox execution budget is fail-closed
# =============================================================================


def test_repair_sandbox_budget_exhausted_pre_execution_gate() -> None:
    frozen_contract, sealed_record, witness_lock, initial_cand = _make_fixture_chain()
    adapter = ScriptableSandboxAdapter([0])
    materializer = DynamicMaterializer()
    manager = VerifierSandboxManager()

    def builder_fn(ctx: BuilderRepairContextEnvelope) -> CandidateSnapshot:
        return CandidateSnapshot(
            candidate_id="cand-repaired-r1",
            source_identity=SAMPLE_SOURCE,
            candidate_tree_digest=R1_TREE,
            patch_digest=R1_PATCH_DIGEST,
            patch_text=R1_PATCH,
            files_added=(),
            files_modified=("a.py",),
            files_deleted=(),
            builder_authored_tests=(),
            frozen_contract_digest=frozen_contract.contract_digest,
            context_digest=ctx.repair_context_digest,
            provenance=EvidenceProvenance.LOCAL_EXECUTION,
        )

    # Pre-exhaust the sandbox executions budget
    counters = RepairLoopCounters(sandbox_executions_used=2)
    budget = RepairLoopBudget(max_sandbox_executions=2, max_repair_rounds=2)

    receipt = run_sealed_repair_loop(
        initial_candidate=initial_cand,
        frozen_contract=frozen_contract,
        source_identity=SAMPLE_SOURCE,
        sealed_record=sealed_record,
        witness_lock=witness_lock,
        builder_repair_fn=builder_fn,
        sandbox_manager=manager,
        sandbox_adapter=adapter,
        materializer=materializer,
        execution_command="pytest tests/test_witness.py",
        budget=budget,
        counters=counters,
        originating_receipt_digest=ORIGINATING_C0_DIGEST,
        initial_failure_facts=INITIAL_FAILED_FACTS,
        prior_sandbox_ids=["sbx-c0-initial"],
    )

    assert receipt.status == RepairLoopStatus.REPAIR_BUDGET_EXHAUSTED
    assert receipt.failure_reason == "Sandbox executions budget exhausted"
    assert receipt.grants_pass is False
    assert receipt.is_causally_verified is False
    # Zero sandboxes created because pre-execution gate failed closed
    assert len(adapter.created_sandboxes) == 0
    assert receipt.counters["sandbox_executions_used"] == 2


def test_repair_sandbox_budget_exhausted_multi_round() -> None:
    frozen_contract, sealed_record, witness_lock, initial_cand = _make_fixture_chain()
    # Round 1 reproduction fails (exit 1)
    adapter = ScriptableSandboxAdapter([1])
    materializer = DynamicMaterializer()
    manager = VerifierSandboxManager()

    def builder_fn(ctx: BuilderRepairContextEnvelope) -> CandidateSnapshot:
        tree = R1_TREE if ctx.repair_round == 1 else R2_TREE
        patch = R1_PATCH if ctx.repair_round == 1 else R2_PATCH
        p_digest = R1_PATCH_DIGEST if ctx.repair_round == 1 else R2_PATCH_DIGEST
        return CandidateSnapshot(
            candidate_id=f"cand-attempt-r{ctx.repair_round}",
            source_identity=SAMPLE_SOURCE,
            candidate_tree_digest=tree,
            patch_digest=p_digest,
            patch_text=patch,
            files_added=(),
            files_modified=("a.py",),
            files_deleted=(),
            builder_authored_tests=(),
            frozen_contract_digest=frozen_contract.contract_digest,
            context_digest=ctx.repair_context_digest,
            provenance=EvidenceProvenance.LOCAL_EXECUTION,
        )

    # Allow exactly 1 sandbox execution across up to 2 rounds
    budget = RepairLoopBudget(max_sandbox_executions=1, max_repair_rounds=2)

    receipt = run_sealed_repair_loop(
        initial_candidate=initial_cand,
        frozen_contract=frozen_contract,
        source_identity=SAMPLE_SOURCE,
        sealed_record=sealed_record,
        witness_lock=witness_lock,
        builder_repair_fn=builder_fn,
        sandbox_manager=manager,
        sandbox_adapter=adapter,
        materializer=materializer,
        execution_command="pytest tests/test_witness.py",
        budget=budget,
        originating_receipt_digest=ORIGINATING_C0_DIGEST,
        initial_failure_facts=INITIAL_FAILED_FACTS,
        prior_sandbox_ids=["sbx-c0-initial"],
    )

    assert receipt.status == RepairLoopStatus.REPAIR_BUDGET_EXHAUSTED
    assert receipt.failure_reason == "Sandbox executions budget exhausted"
    assert receipt.grants_pass is False
    assert receipt.is_causally_verified is False
    # Exactly 1 sandbox was used in round 1; round 2 was blocked before launch
    assert len(adapter.created_sandboxes) == 1
    assert receipt.counters["sandbox_executions_used"] == 1


def test_repair_sandbox_budget_in_budget_success() -> None:
    frozen_contract, sealed_record, witness_lock, initial_cand = _make_fixture_chain()
    adapter = ScriptableSandboxAdapter([0])
    materializer = DynamicMaterializer()
    manager = VerifierSandboxManager()

    def builder_fn(ctx: BuilderRepairContextEnvelope) -> CandidateSnapshot:
        return CandidateSnapshot(
            candidate_id="cand-repaired-r1",
            source_identity=SAMPLE_SOURCE,
            candidate_tree_digest=R1_TREE,
            patch_digest=R1_PATCH_DIGEST,
            patch_text=R1_PATCH,
            files_added=(),
            files_modified=("a.py",),
            files_deleted=(),
            builder_authored_tests=(),
            frozen_contract_digest=frozen_contract.contract_digest,
            context_digest=ctx.repair_context_digest,
            provenance=EvidenceProvenance.LOCAL_EXECUTION,
        )

    budget = RepairLoopBudget(max_sandbox_executions=2, max_repair_rounds=2)

    receipt = run_sealed_repair_loop(
        initial_candidate=initial_cand,
        frozen_contract=frozen_contract,
        source_identity=SAMPLE_SOURCE,
        sealed_record=sealed_record,
        witness_lock=witness_lock,
        builder_repair_fn=builder_fn,
        sandbox_manager=manager,
        sandbox_adapter=adapter,
        materializer=materializer,
        execution_command="pytest tests/test_witness.py",
        budget=budget,
        originating_receipt_digest=ORIGINATING_C0_DIGEST,
        initial_failure_facts=INITIAL_FAILED_FACTS,
        prior_sandbox_ids=["sbx-c0-initial"],
    )

    assert receipt.status == RepairLoopStatus.VERIFIED_AFTER_REPAIR
    assert receipt.grants_pass is True
    assert receipt.counters["sandbox_executions_used"] == 1
    assert len(adapter.created_sandboxes) == 1


# =============================================================================
# DEFECT C REGRESSION TESTS: Clean implementation identity preflight
# =============================================================================


def test_clean_implementation_preflight_clean() -> None:
    with tempfile.TemporaryDirectory() as td:
        repo = Path(td)
        subprocess.run(["git", "init"], cwd=repo, check=True, capture_output=True)
        subprocess.run(
            ["git", "config", "user.name", "Test User"], cwd=repo, check=True, capture_output=True
        )
        subprocess.run(
            ["git", "config", "user.email", "test@example.com"],
            cwd=repo,
            check=True,
            capture_output=True,
        )
        (repo / "file.txt").write_text("initial\n", encoding="utf-8")
        subprocess.run(["git", "add", "file.txt"], cwd=repo, check=True, capture_output=True)
        subprocess.run(["git", "commit", "-m", "init"], cwd=repo, check=True, capture_output=True)

        sha = verify_clean_implementation_preflight(repo)
        assert len(sha) in (40, 64)


def test_clean_implementation_preflight_dirty_tracked_fails() -> None:
    with tempfile.TemporaryDirectory() as td:
        repo = Path(td)
        subprocess.run(["git", "init"], cwd=repo, check=True, capture_output=True)
        subprocess.run(
            ["git", "config", "user.name", "Test User"], cwd=repo, check=True, capture_output=True
        )
        subprocess.run(
            ["git", "config", "user.email", "test@example.com"],
            cwd=repo,
            check=True,
            capture_output=True,
        )
        (repo / "file.txt").write_text("initial\n", encoding="utf-8")
        subprocess.run(["git", "add", "file.txt"], cwd=repo, check=True, capture_output=True)
        subprocess.run(["git", "commit", "-m", "init"], cwd=repo, check=True, capture_output=True)

        # Modify tracked file without committing
        (repo / "file.txt").write_text("modified\n", encoding="utf-8")

        with pytest.raises(CleanImplementationError, match="Dirty working tree state detected"):
            verify_clean_implementation_preflight(repo)


def test_clean_implementation_preflight_staged_fails() -> None:
    with tempfile.TemporaryDirectory() as td:
        repo = Path(td)
        subprocess.run(["git", "init"], cwd=repo, check=True, capture_output=True)
        subprocess.run(
            ["git", "config", "user.name", "Test User"], cwd=repo, check=True, capture_output=True
        )
        subprocess.run(
            ["git", "config", "user.email", "test@example.com"],
            cwd=repo,
            check=True,
            capture_output=True,
        )
        (repo / "file.txt").write_text("initial\n", encoding="utf-8")
        subprocess.run(["git", "add", "file.txt"], cwd=repo, check=True, capture_output=True)
        subprocess.run(["git", "commit", "-m", "init"], cwd=repo, check=True, capture_output=True)

        # Stage a new file without committing
        (repo / "staged.txt").write_text("staged\n", encoding="utf-8")
        subprocess.run(["git", "add", "staged.txt"], cwd=repo, check=True, capture_output=True)

        with pytest.raises(CleanImplementationError, match="Dirty working tree state detected"):
            verify_clean_implementation_preflight(repo)


def test_clean_implementation_preflight_untracked_fails() -> None:
    with tempfile.TemporaryDirectory() as td:
        repo = Path(td)
        subprocess.run(["git", "init"], cwd=repo, check=True, capture_output=True)
        subprocess.run(
            ["git", "config", "user.name", "Test User"], cwd=repo, check=True, capture_output=True
        )
        subprocess.run(
            ["git", "config", "user.email", "test@example.com"],
            cwd=repo,
            check=True,
            capture_output=True,
        )
        (repo / "file.txt").write_text("initial\n", encoding="utf-8")
        subprocess.run(["git", "add", "file.txt"], cwd=repo, check=True, capture_output=True)
        subprocess.run(["git", "commit", "-m", "init"], cwd=repo, check=True, capture_output=True)

        # Add untracked file
        (repo / "untracked.py").write_text("print(1)\n", encoding="utf-8")

        with pytest.raises(CleanImplementationError, match="Dirty working tree state detected"):
            verify_clean_implementation_preflight(repo)


def test_clean_implementation_preflight_dirty_tracked_env_fails() -> None:
    with tempfile.TemporaryDirectory() as td:
        repo = Path(td)
        subprocess.run(["git", "init"], cwd=repo, check=True, capture_output=True)
        subprocess.run(
            ["git", "config", "user.name", "Test User"], cwd=repo, check=True, capture_output=True
        )
        subprocess.run(
            ["git", "config", "user.email", "test@example.com"],
            cwd=repo,
            check=True,
            capture_output=True,
        )
        env_file = repo / ".env"
        env_file.write_text("API_KEY=initial_value\n", encoding="utf-8")
        subprocess.run(["git", "add", ".env"], cwd=repo, check=True, capture_output=True)
        subprocess.run(
            ["git", "commit", "-m", "track .env"], cwd=repo, check=True, capture_output=True
        )

        # Modify tracked .env
        env_file.write_text("API_KEY=modified_value\n", encoding="utf-8")

        with pytest.raises(CleanImplementationError, match="Dirty working tree state detected"):
            verify_clean_implementation_preflight(repo)


def test_clean_implementation_preflight_staged_env_fails() -> None:
    with tempfile.TemporaryDirectory() as td:
        repo = Path(td)
        subprocess.run(["git", "init"], cwd=repo, check=True, capture_output=True)
        subprocess.run(
            ["git", "config", "user.name", "Test User"], cwd=repo, check=True, capture_output=True
        )
        subprocess.run(
            ["git", "config", "user.email", "test@example.com"],
            cwd=repo,
            check=True,
            capture_output=True,
        )
        (repo / "file.txt").write_text("initial\n", encoding="utf-8")
        subprocess.run(["git", "add", "file.txt"], cwd=repo, check=True, capture_output=True)
        subprocess.run(["git", "commit", "-m", "init"], cwd=repo, check=True, capture_output=True)

        # Stage a new .env file
        (repo / ".env").write_text("SECRET=123\n", encoding="utf-8")
        subprocess.run(["git", "add", ".env"], cwd=repo, check=True, capture_output=True)

        with pytest.raises(CleanImplementationError, match="Dirty working tree state detected"):
            verify_clean_implementation_preflight(repo)


def test_clean_implementation_preflight_untracked_non_ignored_env_fails() -> None:
    with tempfile.TemporaryDirectory() as td:
        repo = Path(td)
        subprocess.run(["git", "init"], cwd=repo, check=True, capture_output=True)
        subprocess.run(
            ["git", "config", "user.name", "Test User"], cwd=repo, check=True, capture_output=True
        )
        subprocess.run(
            ["git", "config", "user.email", "test@example.com"],
            cwd=repo,
            check=True,
            capture_output=True,
        )
        (repo / "file.txt").write_text("initial\n", encoding="utf-8")
        subprocess.run(["git", "add", "file.txt"], cwd=repo, check=True, capture_output=True)
        subprocess.run(["git", "commit", "-m", "init"], cwd=repo, check=True, capture_output=True)

        # Create untracked .env without .gitignore
        (repo / ".env").write_text("UNTRACKED_SECRET=abc\n", encoding="utf-8")

        with pytest.raises(CleanImplementationError, match="Dirty working tree state detected"):
            verify_clean_implementation_preflight(repo)


def test_clean_implementation_preflight_clean_ignored_credentials() -> None:
    with tempfile.TemporaryDirectory() as td:
        repo = Path(td)
        subprocess.run(["git", "init"], cwd=repo, check=True, capture_output=True)
        subprocess.run(
            ["git", "config", "user.name", "Test User"], cwd=repo, check=True, capture_output=True
        )
        subprocess.run(
            ["git", "config", "user.email", "test@example.com"],
            cwd=repo,
            check=True,
            capture_output=True,
        )
        # Commit .gitignore ignoring .env
        (repo / ".gitignore").write_text(".env\n", encoding="utf-8")
        (repo / "file.txt").write_text("initial\n", encoding="utf-8")
        subprocess.run(
            ["git", "add", ".gitignore", "file.txt"], cwd=repo, check=True, capture_output=True
        )
        subprocess.run(
            ["git", "commit", "-m", "init with gitignore"],
            cwd=repo,
            check=True,
            capture_output=True,
        )

        # Place local .env outside tracked tree, ignored by git
        (repo / ".env").write_text("NEBIUS_API_KEY=real_local_key\n", encoding="utf-8")

        # Must succeed without error because git status --porcelain is clean
        sha = verify_clean_implementation_preflight(repo)
        assert len(sha) in (40, 64)


# =============================================================================
# DEFECT 1 REGRESSION TESTS: Initial failure evidence fail-closed
# =============================================================================


def test_repair_loop_missing_initial_facts_fails_closed() -> None:
    frozen_contract, sealed_record, witness_lock, initial_cand = _make_fixture_chain()
    adapter = ScriptableSandboxAdapter([0])
    materializer = DynamicMaterializer()
    manager = VerifierSandboxManager()

    def builder_fn(ctx: BuilderRepairContextEnvelope) -> CandidateSnapshot:
        raise AssertionError("Builder should not be called when initial facts are missing")

    # 1. Missing initial_failure_facts
    receipt = run_sealed_repair_loop(
        initial_candidate=initial_cand,
        frozen_contract=frozen_contract,
        source_identity=SAMPLE_SOURCE,
        sealed_record=sealed_record,
        witness_lock=witness_lock,
        builder_repair_fn=builder_fn,
        sandbox_manager=manager,
        sandbox_adapter=adapter,
        materializer=materializer,
        execution_command="pytest tests/test_witness.py",
        budget=RepairLoopBudget(max_repair_rounds=2),
        originating_receipt_digest=ORIGINATING_C0_DIGEST,
        initial_failure_facts=None,
    )
    assert receipt.status == RepairLoopStatus.INCONCLUSIVE
    assert receipt.preliminary_verdict == PreliminaryVerdict.INCONCLUSIVE
    assert receipt.grants_pass is False
    assert receipt.total_rounds == 0
    assert "Missing initial failure facts" in (receipt.failure_reason or "")

    # 2. Missing originating_receipt_digest
    receipt2 = run_sealed_repair_loop(
        initial_candidate=initial_cand,
        frozen_contract=frozen_contract,
        source_identity=SAMPLE_SOURCE,
        sealed_record=sealed_record,
        witness_lock=witness_lock,
        builder_repair_fn=builder_fn,
        sandbox_manager=manager,
        sandbox_adapter=adapter,
        materializer=materializer,
        execution_command="pytest tests/test_witness.py",
        budget=RepairLoopBudget(max_repair_rounds=2),
        originating_receipt_digest=None,
        initial_failure_facts=INITIAL_FAILED_FACTS,
    )
    assert receipt2.status == RepairLoopStatus.INCONCLUSIVE
    assert receipt2.grants_pass is False
    assert receipt2.total_rounds == 0
    assert "Missing or invalid originating_receipt_digest" in (receipt2.failure_reason or "")

    # 3. Dummy originating_receipt_digest
    receipt3 = run_sealed_repair_loop(
        initial_candidate=initial_cand,
        frozen_contract=frozen_contract,
        source_identity=SAMPLE_SOURCE,
        sealed_record=sealed_record,
        witness_lock=witness_lock,
        builder_repair_fn=builder_fn,
        sandbox_manager=manager,
        sandbox_adapter=adapter,
        materializer=materializer,
        execution_command="pytest tests/test_witness.py",
        budget=RepairLoopBudget(max_repair_rounds=2),
        originating_receipt_digest="0" * 64,
        initial_failure_facts=INITIAL_FAILED_FACTS,
    )
    assert receipt3.status == RepairLoopStatus.INCONCLUSIVE
    assert receipt3.grants_pass is False
    assert receipt3.total_rounds == 0


def test_failed_execution_facts_rejects_successful_execution() -> None:
    # 1. Direct constructor with exit_code=0 without justification
    with pytest.raises(RepairFeedbackIntegrityError, match="exit_code=0 cannot be accepted"):
        FailedExecutionFacts(
            exit_code=0,
            failure_message="",
            sandbox_id="sbx-test",
            execution_digest="a" * 64,
        )

    # 2. from_execution with exit_code=0 without justification
    with pytest.raises(RepairFeedbackIntegrityError, match="successful execution"):
        FailedExecutionFacts.from_execution(
            exit_code=0,
            failure_indicator="Nothing failed",
            sandbox_id="sbx-test",
            execution_digest="a" * 64,
        )

    # 3. from_witness_result with outcome=PASS
    witness_pass = SimpleNamespace(
        witness_id="wit-test",
        sandbox_id="sbx-test",
        exit_code=0,
        outcome=WitnessOutcome.PASS,
        result_digest="b" * 64,
    )
    with pytest.raises(RepairFeedbackIntegrityError, match="successful witness result"):
        FailedExecutionFacts.from_witness_result(witness_pass)

    # 4. from_reproduction_receipt with grants_pass=True
    receipt_pass = SimpleNamespace(
        receipt_id="RVR-test-pass",
        repaired_candidate_id="cand-test",
        sandbox_id="sbx-test",
        exit_code=0,
        witness_outcome=WitnessOutcome.PASS,
        preliminary_verdict=PreliminaryVerdict.VERIFIED,
        is_causally_verified=True,
        grants_pass=True,
        duration_seconds=1.0,
        receipt_digest="c" * 64,
    )
    with pytest.raises(RepairFeedbackIntegrityError, match="passing reproduction receipt"):
        FailedExecutionFacts.from_reproduction_receipt(receipt_pass)


def test_failed_execution_facts_exit_code_zero_with_deterministic_failing_outcome() -> None:
    # Legitimate behavior-failure-with-exit-0 backed by validated deterministic failing outcome
    facts = FailedExecutionFacts(
        exit_code=0,
        failure_message="Exit 0 but behavioral invariant violated",
        sandbox_id="sbx-test",
        execution_digest="d" * 64,
        failing_outcome=WitnessOutcome.FAIL,
        deterministic_failure_justification="Silent failure: output contained forbidden token",
    )
    assert facts.exit_code == 0
    assert facts.failing_outcome == WitnessOutcome.FAIL
    assert facts.deterministic_failure_justification is not None

    san = DisclosureSanitizer()
    fb = derive_safe_repair_feedback(
        candidate_id="cand-01",
        requirement_id="REQ-01",
        change_class=ChangeClass.BUG_FIX,
        failed_facts=facts,
        sanitizer=san,
        originating_receipt_digest="d" * 64,
        feedback_round=1,
        permitted_patch_region=["a.py"],
        provenance=EvidenceProvenance.LOCAL_EXECUTION,
    )
    assert "FAIL" in fb.observed_behavior
    assert fb.originating_receipt_digest == "d" * 64


def test_failed_facts_exit_0_rejects_arbitrary_string_justification() -> None:
    # Arbitrary caller-controlled justification string cannot authorize exit_code=0
    with pytest.raises(RepairFeedbackIntegrityError, match="exit_code=0 cannot be accepted"):
        FailedExecutionFacts(
            exit_code=0,
            failure_message="Exit 0 but claimed failed",
            sandbox_id="sbx-test",
            execution_digest="d" * 64,
            deterministic_failure_justification="Silent failure: arbitrary caller justification",
            failing_outcome=None,
        )

    # from_execution also rejects arbitrary string justification without failing outcome
    with pytest.raises(
        RepairFeedbackIntegrityError,
        match="without a genuine validated deterministic failing outcome",
    ):
        FailedExecutionFacts.from_execution(
            exit_code=0,
            failure_indicator="Claimed failure",
            sandbox_id="sbx-test",
            execution_digest="d" * 64,
            deterministic_failure_justification="Caller claims failure happened",
            failing_outcome=None,
        )


def test_failed_facts_exit_0_rejects_arbitrary_or_fabricated_outcome() -> None:
    # 1. Arbitrary string passed to failing_outcome
    with pytest.raises(
        RepairFeedbackIntegrityError,
        match="must be a typed WitnessOutcome or PreliminaryVerdict",
    ):
        FailedExecutionFacts(
            exit_code=0,
            failure_message="Error",
            sandbox_id="sbx-test",
            execution_digest="d" * 64,
            failing_outcome="FAIL",  # type: ignore[arg-type]
        )

    # 2. Fabricated outcome name passed as string
    with pytest.raises(
        RepairFeedbackIntegrityError,
        match="must be a typed WitnessOutcome or PreliminaryVerdict",
    ):
        FailedExecutionFacts(
            exit_code=0,
            failure_message="Error",
            sandbox_id="sbx-test",
            execution_digest="d" * 64,
            failing_outcome="FABRICATED_OUTCOME",  # type: ignore[arg-type]
        )

    # 3. Arbitrary non-enum object
    with pytest.raises(
        RepairFeedbackIntegrityError,
        match="must be a typed WitnessOutcome or PreliminaryVerdict",
    ):
        FailedExecutionFacts(
            exit_code=0,
            failure_message="Error",
            sandbox_id="sbx-test",
            execution_digest="d" * 64,
            failing_outcome=SimpleNamespace(value="FAIL"),  # type: ignore[arg-type]
        )


def test_failed_facts_exit_0_rejects_passing_and_unsupported_outcomes() -> None:
    # 1. WitnessOutcome.PASS
    with pytest.raises(RepairFeedbackIntegrityError, match="Passing or partially passing outcome"):
        FailedExecutionFacts(
            exit_code=0,
            failure_message="No error",
            sandbox_id="sbx-test",
            execution_digest="d" * 64,
            failing_outcome=WitnessOutcome.PASS,
        )

    # 2. PreliminaryVerdict.VERIFIED
    with pytest.raises(RepairFeedbackIntegrityError, match="Passing or partially passing outcome"):
        FailedExecutionFacts(
            exit_code=0,
            failure_message="Verified",
            sandbox_id="sbx-test",
            execution_digest="d" * 64,
            failing_outcome=PreliminaryVerdict.VERIFIED,
        )

    # 3. PreliminaryVerdict.PARTIALLY_VERIFIED
    with pytest.raises(RepairFeedbackIntegrityError, match="Passing or partially passing outcome"):
        FailedExecutionFacts(
            exit_code=0,
            failure_message="Partially verified",
            sandbox_id="sbx-test",
            execution_digest="d" * 64,
            failing_outcome=PreliminaryVerdict.PARTIALLY_VERIFIED,
        )

    # 4. PreliminaryVerdict.NOT_RUN
    with pytest.raises(RepairFeedbackIntegrityError, match="Non-execution verdict NOT_RUN"):
        FailedExecutionFacts(
            exit_code=0,
            failure_message="Not run",
            sandbox_id="sbx-test",
            execution_digest="d" * 64,
            failing_outcome=PreliminaryVerdict.NOT_RUN,
        )

    # 5. Contradictory outcome: WitnessOutcome.TIMEOUT with exit_code=0
    with pytest.raises(RepairFeedbackIntegrityError, match="Contradictory execution state"):
        FailedExecutionFacts(
            exit_code=0,
            failure_message="Timed out but exited 0",
            sandbox_id="sbx-test",
            execution_digest="d" * 64,
            failing_outcome=WitnessOutcome.TIMEOUT,
        )


def test_failed_facts_exit_0_rejects_missing_or_dummy_execution_digest() -> None:
    # 1. Missing execution_digest with exit_code=0
    with pytest.raises(
        RepairFeedbackIntegrityError,
        match="requires a valid non-dummy execution_digest",
    ):
        FailedExecutionFacts(
            exit_code=0,
            failure_message="Exit 0",
            sandbox_id="sbx-test",
            execution_digest=None,
            failing_outcome=WitnessOutcome.FAIL,
        )

    # 2. Dummy all-zero execution_digest with exit_code=0
    with pytest.raises(RepairFeedbackIntegrityError, match="cannot be a dummy or invalid"):
        FailedExecutionFacts(
            exit_code=0,
            failure_message="Exit 0",
            sandbox_id="sbx-test",
            execution_digest="0" * 64,
            failing_outcome=WitnessOutcome.FAIL,
        )


def test_boundary_helpers_cannot_bypass_exit_code_zero_validation() -> None:
    # 1. from_execution rejects passing outcome
    with pytest.raises(RepairFeedbackIntegrityError, match="Passing or partially passing outcome"):
        FailedExecutionFacts.from_execution(
            exit_code=0,
            execution_digest="e" * 64,
            failing_outcome=WitnessOutcome.PASS,
        )

    # 2. from_execution rejects string outcome
    with pytest.raises(
        RepairFeedbackIntegrityError,
        match="must be a typed WitnessOutcome or PreliminaryVerdict",
    ):
        FailedExecutionFacts.from_execution(
            exit_code=0,
            execution_digest="e" * 64,
            failing_outcome="FAIL",  # type: ignore[arg-type]
        )

    # 3. from_witness_result with PASS
    pass_witness = SimpleNamespace(
        outcome=WitnessOutcome.PASS,
        result_digest="e" * 64,
        sandbox_id="sbx-test",
        exit_code=0,
    )
    with pytest.raises(RepairFeedbackIntegrityError, match="successful witness result"):
        FailedExecutionFacts.from_witness_result(pass_witness)

    # 4. from_reproduction_receipt with PASS
    pass_receipt = SimpleNamespace(
        grants_pass=False,
        witness_outcome=WitnessOutcome.PASS,
        preliminary_verdict=PreliminaryVerdict.VERIFIED,
        receipt_digest="e" * 64,
        sandbox_id="sbx-test",
        exit_code=0,
    )
    with pytest.raises(RepairFeedbackIntegrityError, match="passing reproduction receipt"):
        FailedExecutionFacts.from_reproduction_receipt(pass_receipt)

    # 5. Legitimate behavior-failure-with-exit-0 from witness result is preserved
    failing_witness = SimpleNamespace(
        outcome=WitnessOutcome.FAIL,
        result_digest="e" * 64,
        sandbox_id="sbx-test",
        exit_code=0,
        termination_status=TerminationStatus.COMPLETED,
        duration_seconds=0.5,
    )
    facts = FailedExecutionFacts.from_witness_result(failing_witness)
    assert facts.exit_code == 0
    assert facts.failing_outcome == WitnessOutcome.FAIL
    assert facts.execution_digest == "e" * 64


def test_repair_loop_incomplete_or_mismatched_execution_identity_fails_closed() -> None:
    frozen_contract, sealed_record, witness_lock, initial_cand = _make_fixture_chain()
    adapter = ScriptableSandboxAdapter([0])
    materializer = DynamicMaterializer()
    manager = VerifierSandboxManager()

    def builder_fn(ctx: BuilderRepairContextEnvelope) -> CandidateSnapshot:
        raise AssertionError("Builder should not be called on identity mismatch")

    # 1. Missing execution_digest: initial_failure_facts.execution_digest is None (Repair B)
    none_digest_facts = FailedExecutionFacts(
        exit_code=1,
        failure_message="Error",
        sandbox_id="sbx-c0-initial",
        execution_digest=None,
    )
    receipt_none = run_sealed_repair_loop(
        initial_candidate=initial_cand,
        frozen_contract=frozen_contract,
        source_identity=SAMPLE_SOURCE,
        sealed_record=sealed_record,
        witness_lock=witness_lock,
        builder_repair_fn=builder_fn,
        sandbox_manager=manager,
        sandbox_adapter=adapter,
        materializer=materializer,
        execution_command="pytest tests/test_witness.py",
        budget=RepairLoopBudget(max_repair_rounds=2),
        originating_receipt_digest=ORIGINATING_C0_DIGEST,
        initial_failure_facts=none_digest_facts,
    )
    assert receipt_none.status == RepairLoopStatus.INCONCLUSIVE
    assert "Missing or invalid execution_digest in initial_failure_facts" in (
        receipt_none.failure_reason or ""
    )

    # 2. Dummy execution_digest: all-zero digest rejected at construction (Repair B)
    with pytest.raises(RepairFeedbackIntegrityError, match="cannot be a dummy or invalid"):
        FailedExecutionFacts(
            exit_code=1,
            failure_message="Error",
            sandbox_id="sbx-c0-initial",
            execution_digest="0" * 64,
        )

    # 3. Digest mismatch: initial_failure_facts.execution_digest != originating_receipt_digest
    mismatched_facts = FailedExecutionFacts(
        exit_code=1,
        failure_message="Error",
        sandbox_id="sbx-c0-initial",
        execution_digest="1" * 64,
    )
    receipt1 = run_sealed_repair_loop(
        initial_candidate=initial_cand,
        frozen_contract=frozen_contract,
        source_identity=SAMPLE_SOURCE,
        sealed_record=sealed_record,
        witness_lock=witness_lock,
        builder_repair_fn=builder_fn,
        sandbox_manager=manager,
        sandbox_adapter=adapter,
        materializer=materializer,
        execution_command="pytest tests/test_witness.py",
        budget=RepairLoopBudget(max_repair_rounds=2),
        originating_receipt_digest="2" * 64,
        initial_failure_facts=mismatched_facts,
    )
    assert receipt1.status == RepairLoopStatus.INCONCLUSIVE
    assert "Mismatched execution identity" in (receipt1.failure_reason or "")

    # 4. Sandbox mismatch: initial_cand.sandbox_identity != initial_failure_facts.sandbox_id
    mismatched_sbx_facts = FailedExecutionFacts(
        exit_code=1,
        failure_message="Error",
        sandbox_id="sbx-different",
        execution_digest=ORIGINATING_C0_DIGEST,
    )
    receipt2 = run_sealed_repair_loop(
        initial_candidate=initial_cand,
        frozen_contract=frozen_contract,
        source_identity=SAMPLE_SOURCE,
        sealed_record=sealed_record,
        witness_lock=witness_lock,
        builder_repair_fn=builder_fn,
        sandbox_manager=manager,
        sandbox_adapter=adapter,
        materializer=materializer,
        execution_command="pytest tests/test_witness.py",
        budget=RepairLoopBudget(max_repair_rounds=2),
        originating_receipt_digest=ORIGINATING_C0_DIGEST,
        initial_failure_facts=mismatched_sbx_facts,
    )
    assert receipt2.status == RepairLoopStatus.INCONCLUSIVE
    assert "Mismatched sandbox identity" in (receipt2.failure_reason or "")

    # 5. Exit code 0 without failing outcome fails closed in run_sealed_repair_loop (Repair A)
    # Direct construction with exit_code=0 without failing outcome is blocked by
    # FailedExecutionFacts, but if a bypass attempted to reach run_sealed_repair_loop,
    # it returns INCONCLUSIVE.
    zero_exit_facts = FailedExecutionFacts(
        exit_code=0,
        failure_message="Exit 0 but failed assertion",
        sandbox_id="sbx-c0-initial",
        execution_digest=ORIGINATING_C0_DIGEST,
        failing_outcome=WitnessOutcome.FAIL,
    )
    # With valid failing outcome, it enters the repair loop (here adapter returns 0 -> VERIFIED)
    receipt_valid = run_sealed_repair_loop(
        initial_candidate=initial_cand,
        frozen_contract=frozen_contract,
        source_identity=SAMPLE_SOURCE,
        sealed_record=sealed_record,
        witness_lock=witness_lock,
        builder_repair_fn=lambda ctx: CandidateSnapshot(
            candidate_id="cand-repaired-r1",
            source_identity=SAMPLE_SOURCE,
            candidate_tree_digest=R1_TREE,
            patch_digest=R1_PATCH_DIGEST,
            patch_text=R1_PATCH,
            files_added=(),
            files_modified=("a.py",),
            files_deleted=(),
            builder_authored_tests=(),
            frozen_contract_digest=frozen_contract.contract_digest,
            context_digest=ctx.repair_context_digest,
            provenance=EvidenceProvenance.LOCAL_EXECUTION,
        ),
        sandbox_manager=manager,
        sandbox_adapter=adapter,
        materializer=materializer,
        execution_command="pytest tests/test_witness.py",
        budget=RepairLoopBudget(max_repair_rounds=1),
        originating_receipt_digest=ORIGINATING_C0_DIGEST,
        initial_failure_facts=zero_exit_facts,
        prior_sandbox_ids=["sbx-c0-initial"],
    )
    assert receipt_valid.status == RepairLoopStatus.VERIFIED_AFTER_REPAIR


def test_repair_loop_failed_reproduction_feedback_across_multiple_rounds() -> None:
    frozen_contract, sealed_record, witness_lock, initial_cand = _make_fixture_chain()
    # 2 rounds of failure (exit 1, exit 1)
    adapter = ScriptableSandboxAdapter([1, 1])
    materializer = DynamicMaterializer()
    manager = VerifierSandboxManager()

    captured_orig_digests: list[str] = []

    def builder_fn(ctx: BuilderRepairContextEnvelope) -> CandidateSnapshot:
        captured_orig_digests.append(ctx.repair_feedback.originating_receipt_digest)
        tree = R1_TREE if ctx.repair_round == 1 else R2_TREE
        patch = R1_PATCH if ctx.repair_round == 1 else R2_PATCH
        p_digest = R1_PATCH_DIGEST if ctx.repair_round == 1 else R2_PATCH_DIGEST
        return CandidateSnapshot(
            candidate_id=f"cand-attempt-r{ctx.repair_round}",
            source_identity=SAMPLE_SOURCE,
            candidate_tree_digest=tree,
            patch_digest=p_digest,
            patch_text=patch,
            files_added=(),
            files_modified=("a.py",),
            files_deleted=(),
            builder_authored_tests=(),
            frozen_contract_digest=frozen_contract.contract_digest,
            context_digest=ctx.repair_context_digest,
            provenance=EvidenceProvenance.LOCAL_EXECUTION,
        )

    receipt = run_sealed_repair_loop(
        initial_candidate=initial_cand,
        frozen_contract=frozen_contract,
        source_identity=SAMPLE_SOURCE,
        sealed_record=sealed_record,
        witness_lock=witness_lock,
        builder_repair_fn=builder_fn,
        sandbox_manager=manager,
        sandbox_adapter=adapter,
        materializer=materializer,
        execution_command="pytest tests/test_witness.py",
        budget=RepairLoopBudget(max_repair_rounds=2),
        originating_receipt_digest=ORIGINATING_C0_DIGEST,
        initial_failure_facts=INITIAL_FAILED_FACTS,
        prior_sandbox_ids=["sbx-c0-initial"],
    )

    assert receipt.status == RepairLoopStatus.REPAIR_BUDGET_EXHAUSTED
    assert len(captured_orig_digests) == 2
    # Round 1 originated from initial receipt digest
    assert captured_orig_digests[0] == ORIGINATING_C0_DIGEST
    # Round 2 originated from Round 1's reproduction receipt digest
    assert captured_orig_digests[1] == receipt.reproduction_receipt_digests[0]
    assert captured_orig_digests[1] != ORIGINATING_C0_DIGEST
