"""Unit tests for P-14.05: Fresh verifier reproduction for repaired candidate."""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any

import pytest

from basebreak.builder.capture import CandidateSnapshot
from basebreak.compiler.freeze import FrozenContract, freeze_review_result
from basebreak.compiler.ingestion import ingest_task
from basebreak.compiler.requirements import ProposedRequirement
from basebreak.compiler.review import ReviewBundle, ReviewSession
from basebreak.compiler.semantics import (
    CertaintyLevel,
    ChangeSemanticsClassification,
    DeterministicClassificationFact,
)
from basebreak.domain.execution import SandboxIdentity
from basebreak.domain.semantics import ChangeClass
from basebreak.domain.source import CommitRevision, SourceIdentity
from basebreak.domain.verdict import EvidenceProvenance, PreliminaryVerdict
from basebreak.evidence.artifact import compute_bytes_digest
from basebreak.repair.context import (
    BuilderRepairContextEnvelope,
    create_builder_repair_context,
)
from basebreak.repair.feedback import (
    FailureConditionCategory,
    create_safe_repair_feedback,
)
from basebreak.repair.lineage import (
    CandidateLineageRecord,
    RepairedCandidateSnapshot,
    create_candidate_lineage_record,
)
from basebreak.repair.reproduction import (
    RepairedCandidateVerificationMismatchError,
    RepairedReceiptReplayError,
    RepairedReceiptTamperingError,
    RepairedVerificationReceipt,
    VerifierSandboxReuseError,
    create_repaired_verification_receipt,
    execute_repaired_verifier_reproduction,
    verify_repaired_receipt_integrity,
    verify_repaired_receipt_non_inheritance,
)
from basebreak.verifier.context import VerifierContextEnvelope
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
PARENT_TREE = "f81f6faa0c7572f9941570bbce376fadc10f39a3"
PARENT_PATCH = "diff --git a/a.py b/a.py\n--- a/a.py\n+++ b/a.py\n@@ -1 +1 @@\n-1\n+2\n"
PARENT_PATCH_DIGEST = compute_bytes_digest(PARENT_PATCH.encode("utf-8")).value

REPAIRED_TREE = "1111111111111111111111111111111111111111"
REPAIRED_PATCH = "diff --git a/a.py b/a.py\n--- a/a.py\n+++ b/a.py\n@@ -1 +1 @@\n-1\n+3\n"
REPAIRED_PATCH_DIGEST = compute_bytes_digest(REPAIRED_PATCH.encode("utf-8")).value

RECEIPT_DIGEST = "d" * 64


@dataclass
class MockCommandResult:
    exit_code: int = 0
    stdout: str = ""
    stderr: str = ""
    duration_seconds: float = 0.1
    is_timed_out: bool = False


class MockSandboxAdapter:
    """Deterministic in-memory mock sandbox adapter for verifier testing."""

    def __init__(self, sandbox_id_sequence: list[str] | None = None) -> None:
        self.sandbox_id_sequence = sandbox_id_sequence or ["sbx-fresh-001", "sbx-fresh-002"]
        self.created_sandboxes: list[str] = []
        self.torn_down_sandboxes: list[str] = []
        self.executed_commands: list[str] = []
        self.command_exit_code = 0
        self.command_stdout = "test output"
        self.command_stderr = ""
        self.is_timed_out = False

    def create_sandbox(self, **kwargs: Any) -> SandboxIdentity:
        sid = self.sandbox_id_sequence.pop(0) if self.sandbox_id_sequence else "sbx-fallback-999"
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
        return MockCommandResult(
            exit_code=self.command_exit_code,
            stdout=self.command_stdout,
            stderr=self.command_stderr,
            duration_seconds=0.1,
            is_timed_out=self.is_timed_out,
        )


class MockMaterializer:
    """Mock materializer that simulates clean base materialization + patch application."""

    def __init__(
        self, tree_digest: str = REPAIRED_TREE, workspace_path: str = "/verifier_workspace"
    ) -> None:
        self.tree_digest = tree_digest
        self.workspace_path = workspace_path

    def materialize_clean_base(self, **kwargs: Any) -> dict[str, Any]:
        return {
            "resolved_commit_sha": SAMPLE_SOURCE.resolved_commit_id,
            "materialized_tree_digest": self.tree_digest,
            "workspace_path": self.workspace_path,
        }


def _make_setup() -> tuple[
    FrozenContract,
    SealedWitnessRecord,
    ImmutableWitnessLock,
    BuilderRepairContextEnvelope,
    RepairedCandidateSnapshot,
    CandidateLineageRecord,
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

    feedback = create_safe_repair_feedback(
        feedback_id="FB-01",
        candidate_id="cand-parent",
        requirement_id=req_id,
        change_class=ChangeClass.BUG_FIX,
        failed_condition=FailureConditionCategory.BEHAVIORAL_ASSERTION_FAILED,
        observed_behavior="Failed test",
        expected_behavior="Passed test",
        originating_receipt_digest=RECEIPT_DIGEST,
        feedback_round=1,
        provenance=EvidenceProvenance.LOCAL_EXECUTION,
        permitted_patch_region=["a.py"],
    )

    repair_context = create_builder_repair_context(
        repair_context_id="RPC-01",
        parent_candidate_id="cand-parent",
        parent_candidate_tree_digest=PARENT_TREE,
        parent_patch_digest=PARENT_PATCH_DIGEST,
        parent_patch_text=PARENT_PATCH,
        source_identity=SAMPLE_SOURCE,
        frozen_contract_digest=contract_digest,
        requirement_id=req_id,
        change_class=ChangeClass.BUG_FIX,
        repair_feedback=feedback,
        permitted_paths=["a.py"],
        repair_round=1,
        max_repair_rounds=3,
    )

    lineage_record = create_candidate_lineage_record(
        lineage_id="LIN-01",
        context=repair_context,
        repaired_candidate_id="cand-repaired-01",
        repaired_tree_digest=REPAIRED_TREE,
        repaired_patch_digest=REPAIRED_PATCH_DIGEST,
        builder_execution_identity="bexec-01",
    )

    candidate = CandidateSnapshot(
        candidate_id="cand-repaired-01",
        source_identity=SAMPLE_SOURCE,
        candidate_tree_digest=REPAIRED_TREE,
        patch_digest=REPAIRED_PATCH_DIGEST,
        patch_text=REPAIRED_PATCH,
        files_added=(),
        files_modified=("a.py",),
        files_deleted=(),
        builder_authored_tests=(),
        frozen_contract_digest=contract_digest,
        context_digest=repair_context.repair_context_digest,
        provenance=EvidenceProvenance.LOCAL_EXECUTION,
    )

    repaired_candidate = RepairedCandidateSnapshot(
        candidate=candidate,
        lineage=lineage_record,
        is_authoritative=False,
    )

    return (
        frozen_contract,
        sealed_record,
        witness_lock,
        repair_context,
        repaired_candidate,
        lineage_record,
    )


def test_fresh_reproduction_success_bug_fix() -> None:
    (
        frozen_contract,
        sealed_record,
        witness_lock,
        repair_context,
        repaired_candidate,
        lineage_record,
    ) = _make_setup()

    adapter = MockSandboxAdapter(["sbx-verifier-rep-01"])
    materializer = MockMaterializer(REPAIRED_TREE)
    manager = VerifierSandboxManager()

    receipt = execute_repaired_verifier_reproduction(
        repaired_candidate=repaired_candidate,
        lineage_record=lineage_record,
        sealed_record=sealed_record,
        witness_lock=witness_lock,
        sandbox_manager=manager,
        sandbox_adapter=adapter,
        materializer=materializer,
        execution_command="pytest tests/test_witness.py",
        frozen_contract=frozen_contract,
        source_identity=SAMPLE_SOURCE,
        base_outcome=WitnessOutcome.FAIL,
    )

    assert receipt.repaired_candidate_id == "cand-repaired-01"
    assert receipt.parent_candidate_id == "cand-parent"
    assert receipt.witness_outcome == WitnessOutcome.PASS
    assert receipt.preliminary_verdict == PreliminaryVerdict.VERIFIED
    assert receipt.is_causally_verified is True
    assert receipt.grants_pass is True
    assert receipt.is_authoritative is False
    assert receipt.sandbox_id == "sbx-verifier-rep-01"
    assert verify_repaired_receipt_integrity(receipt) is True
    # Guaranteed teardown
    assert "sbx-verifier-rep-01" in adapter.torn_down_sandboxes


def test_fresh_reproduction_counterfactual_checked() -> None:
    (
        frozen_contract,
        sealed_record,
        witness_lock,
        repair_context,
        repaired_candidate,
        lineage_record,
    ) = _make_setup()

    adapter = MockSandboxAdapter(["sbx-cf-fail", "sbx-cf-pass"])
    materializer = MockMaterializer(REPAIRED_TREE)
    manager = VerifierSandboxManager()

    # Case 1: counterfactual outcome is FAIL -> preliminary verdict VERIFIED
    receipt_valid = execute_repaired_verifier_reproduction(
        repaired_candidate=repaired_candidate,
        lineage_record=lineage_record,
        sealed_record=sealed_record,
        witness_lock=witness_lock,
        sandbox_manager=manager,
        sandbox_adapter=adapter,
        materializer=materializer,
        execution_command="pytest tests/test_witness.py",
        frozen_contract=frozen_contract,
        source_identity=SAMPLE_SOURCE,
        base_outcome=WitnessOutcome.FAIL,
        counterfactual_outcome=WitnessOutcome.FAIL,
    )
    assert receipt_valid.grants_pass is True
    assert receipt_valid.preliminary_verdict == PreliminaryVerdict.VERIFIED

    # Case 2: counterfactual outcome is PASS -> counterfactual invariant violated!
    receipt_invalid = execute_repaired_verifier_reproduction(
        repaired_candidate=repaired_candidate,
        lineage_record=lineage_record,
        sealed_record=sealed_record,
        witness_lock=witness_lock,
        sandbox_manager=manager,
        sandbox_adapter=adapter,
        materializer=materializer,
        execution_command="pytest tests/test_witness.py",
        frozen_contract=frozen_contract,
        source_identity=SAMPLE_SOURCE,
        base_outcome=WitnessOutcome.FAIL,
        counterfactual_outcome=WitnessOutcome.PASS,
    )
    assert receipt_invalid.grants_pass is False
    assert receipt_invalid.is_causally_verified is False
    assert receipt_invalid.preliminary_verdict == PreliminaryVerdict.CONTRADICTED


def test_verifier_crash_or_timeout_never_passes() -> None:
    (
        frozen_contract,
        sealed_record,
        witness_lock,
        repair_context,
        repaired_candidate,
        lineage_record,
    ) = _make_setup()

    # Case 1: Verifier execution non-zero exit code (failure)
    adapter_fail = MockSandboxAdapter(["sbx-crash-01"])
    adapter_fail.command_exit_code = 1
    materializer = MockMaterializer(REPAIRED_TREE)
    manager = VerifierSandboxManager()

    receipt_fail = execute_repaired_verifier_reproduction(
        repaired_candidate=repaired_candidate,
        lineage_record=lineage_record,
        sealed_record=sealed_record,
        witness_lock=witness_lock,
        sandbox_manager=manager,
        sandbox_adapter=adapter_fail,
        materializer=materializer,
        execution_command="pytest tests/test_witness.py",
        frozen_contract=frozen_contract,
        source_identity=SAMPLE_SOURCE,
    )
    assert receipt_fail.grants_pass is False
    assert receipt_fail.is_causally_verified is False
    assert receipt_fail.witness_outcome == WitnessOutcome.FAIL
    assert receipt_fail.preliminary_verdict == PreliminaryVerdict.CONTRADICTED

    # Case 2: Verifier execution times out
    adapter_timeout = MockSandboxAdapter(["sbx-timeout-01"])
    adapter_timeout.is_timed_out = True
    receipt_timeout = execute_repaired_verifier_reproduction(
        repaired_candidate=repaired_candidate,
        lineage_record=lineage_record,
        sealed_record=sealed_record,
        witness_lock=witness_lock,
        sandbox_manager=manager,
        sandbox_adapter=adapter_timeout,
        materializer=materializer,
        execution_command="pytest tests/test_witness.py",
        frozen_contract=frozen_contract,
        source_identity=SAMPLE_SOURCE,
    )
    assert receipt_timeout.grants_pass is False
    assert receipt_timeout.is_causally_verified is False
    assert receipt_timeout.witness_outcome == WitnessOutcome.TIMEOUT
    assert receipt_timeout.preliminary_verdict == PreliminaryVerdict.INCONCLUSIVE


def test_anti_sandbox_reuse_defense() -> None:
    (
        frozen_contract,
        sealed_record,
        witness_lock,
        repair_context,
        repaired_candidate,
        lineage_record,
    ) = _make_setup()

    # Adapter tries to return an already used sandbox ID
    adapter = MockSandboxAdapter(["sbx-prior-used-01"])
    materializer = MockMaterializer(REPAIRED_TREE)
    manager = VerifierSandboxManager(known_builder_sandbox_ids=["sbx-builder-01"])

    with pytest.raises(VerifierSandboxReuseError):
        execute_repaired_verifier_reproduction(
            repaired_candidate=repaired_candidate,
            lineage_record=lineage_record,
            sealed_record=sealed_record,
            witness_lock=witness_lock,
            sandbox_manager=manager,
            sandbox_adapter=adapter,
            materializer=materializer,
            execution_command="pytest tests/test_witness.py",
            frozen_contract=frozen_contract,
            source_identity=SAMPLE_SOURCE,
            prior_sandbox_ids=["sbx-prior-used-01"],
        )


def test_anti_receipt_replay_and_non_inheritance() -> None:
    (
        frozen_contract,
        sealed_record,
        witness_lock,
        repair_context,
        repaired_candidate,
        lineage_record,
    ) = _make_setup()

    adapter = MockSandboxAdapter(["sbx-clean-01"])
    materializer = MockMaterializer(REPAIRED_TREE)
    manager = VerifierSandboxManager()

    valid_receipt = execute_repaired_verifier_reproduction(
        repaired_candidate=repaired_candidate,
        lineage_record=lineage_record,
        sealed_record=sealed_record,
        witness_lock=witness_lock,
        sandbox_manager=manager,
        sandbox_adapter=adapter,
        materializer=materializer,
        execution_command="pytest tests/test_witness.py",
        frozen_contract=frozen_contract,
        source_identity=SAMPLE_SOURCE,
        base_outcome=WitnessOutcome.FAIL,
    )

    # Calling non-inheritance check with prior candidate IDs containing this ID must fail
    with pytest.raises(RepairedReceiptReplayError):
        verify_repaired_receipt_non_inheritance(
            valid_receipt,
            repaired_candidate=repaired_candidate,
            lineage_record=lineage_record,
            prior_candidate_ids=["cand-repaired-01", "cand-parent"],
        )


def test_tamper_detection_on_repaired_receipt() -> None:
    (
        frozen_contract,
        sealed_record,
        witness_lock,
        repair_context,
        repaired_candidate,
        lineage_record,
    ) = _make_setup()

    receipt = create_repaired_verification_receipt(
        receipt_id="RVR-01",
        repaired_candidate_id="cand-repaired-01",
        repaired_patch_digest=REPAIRED_PATCH_DIGEST,
        repaired_tree_digest=REPAIRED_TREE,
        parent_candidate_id="cand-parent",
        lineage_digest=lineage_record.lineage_digest,
        feedback_round=1,
        requirement_id=sealed_record.requirement_id,
        change_class=ChangeClass.BUG_FIX,
        frozen_contract_digest=frozen_contract.contract_digest,
        witness_digest=sealed_record.seal_digest,
        lock_digest=witness_lock.lock_digest,
        sandbox_id="sbx-01",
        witness_outcome=WitnessOutcome.PASS,
        exit_code=0,
        duration_seconds=1.23,
        preliminary_verdict=PreliminaryVerdict.VERIFIED,
        is_causally_verified=True,
        grants_pass=True,
        provenance=EvidenceProvenance.LOCAL_EXECUTION,
    )
    assert verify_repaired_receipt_integrity(receipt) is True

    # Tampering with grants_pass
    tampered_pass = RepairedVerificationReceipt(
        schema_version=receipt.schema_version,
        receipt_id=receipt.receipt_id,
        repaired_candidate_id=receipt.repaired_candidate_id,
        repaired_patch_digest=receipt.repaired_patch_digest,
        repaired_tree_digest=receipt.repaired_tree_digest,
        parent_candidate_id=receipt.parent_candidate_id,
        lineage_digest=receipt.lineage_digest,
        feedback_round=receipt.feedback_round,
        requirement_id=receipt.requirement_id,
        change_class=receipt.change_class,
        frozen_contract_digest=receipt.frozen_contract_digest,
        witness_digest=receipt.witness_digest,
        lock_digest=receipt.lock_digest,
        sandbox_id=receipt.sandbox_id,
        witness_outcome=receipt.witness_outcome,
        exit_code=receipt.exit_code,
        duration_seconds=receipt.duration_seconds,
        preliminary_verdict=PreliminaryVerdict.CONTRADICTED,
        is_causally_verified=False,
        grants_pass=False,
        is_authoritative=False,
        provenance=receipt.provenance,
        created_at=receipt.created_at,
        receipt_digest=receipt.receipt_digest,  # old digest
    )
    with pytest.raises(RepairedReceiptTamperingError):
        verify_repaired_receipt_integrity(tampered_pass)


def test_mismatched_context_envelope_rejected() -> None:
    (
        frozen_contract,
        sealed_record,
        witness_lock,
        repair_context,
        repaired_candidate,
        lineage_record,
    ) = _make_setup()

    # Create context envelope targeting the parent candidate
    from basebreak.domain.causal import CandidateIdentity

    parent_context_env = VerifierContextEnvelope.create(
        frozen_contract=frozen_contract,
        source_identity=SAMPLE_SOURCE,
        candidate_identity=CandidateIdentity(
            candidate_id="cand-parent",
            source=SAMPLE_SOURCE,
            patch_digest=PARENT_PATCH_DIGEST,
        ),
        candidate_patch_text=PARENT_PATCH,
        candidate_tree_digest=PARENT_TREE,
        sealed_witness_references=[sealed_record.witness_id],
    )

    adapter = MockSandboxAdapter(["sbx-env-mismatch"])
    materializer = MockMaterializer(REPAIRED_TREE)
    manager = VerifierSandboxManager()

    with pytest.raises(RepairedCandidateVerificationMismatchError):
        execute_repaired_verifier_reproduction(
            repaired_candidate=repaired_candidate,
            lineage_record=lineage_record,
            sealed_record=sealed_record,
            witness_lock=witness_lock,
            sandbox_manager=manager,
            sandbox_adapter=adapter,
            materializer=materializer,
            execution_command="pytest tests/test_witness.py",
            context_envelope=parent_context_env,
        )
