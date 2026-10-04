"""Adversarial and regression tests for P-07.06 final surgical repairs.

Covers all 12 required test conditions:
1. execution provenance cannot be caller-upgraded;
2. reproduction provenance cannot be caller-upgraded;
3. fake adapter LIVE property cannot establish LIVE_NEBIUS;
4. no successful provider operation => no LIVE_NEBIUS;
5. canonical production execution cannot enter disposable multi-operation state-loss mode;
6. canonical reproduction cannot enter that mode;
7. synthetic caller clean-base record is rejected;
8. exact checkpoint image/source/tree/workspace binding is enforced;
9. disposable Builder execution with non-null result_image_uuid fails closed;
10. disposable reproduction with non-null result_image_uuid fails closed;
11. clean-base checkpoint requires non-null image UUID;
12. provider operation IDs/result-image facts are retained for evidence.
"""

from __future__ import annotations

import base64
from types import SimpleNamespace
from typing import Any

import pytest

from basebreak.builder.capture import CandidateSnapshot
from basebreak.builder.context import (
    BuilderContextAllowlist,
    BuilderContextEnvelope,
    assemble_builder_context,
)
from basebreak.builder.execution import (
    CandidateExecutionConfig,
    CandidateExecutionResult,
    CandidateWorkspaceExecutor,
    CleanBaseCheckpointRecord,
    CleanBaseRecordAuthorityError,
    DisposableExecutionPolicyViolationError,
    InvalidExecutionModeError,
    SourceCommitMismatchError,
)
from basebreak.builder.loop import (
    BuilderPlan,
    BuilderProposal,
    FileActionType,
    ProposedCommand,
    ProposedFileAction,
)
from basebreak.builder.reproduction import (
    CandidateReproductionConfig,
    CandidateReproductionExecutor,
    CandidateReproductionResult,
)
from basebreak.compiler.freeze import FrozenContract
from basebreak.compiler.ingestion import ingest_task
from basebreak.compiler.requirements import ProposedRequirement
from basebreak.compiler.review import ReviewBundle, ReviewResult, ReviewSession
from basebreak.compiler.semantics import (
    CertaintyLevel,
    ChangeSemanticsClassification,
    DeterministicClassificationFact,
)
from basebreak.domain.execution import SandboxIdentity
from basebreak.domain.semantics import ChangeClass
from basebreak.domain.source import CommitRevision, SourceIdentity
from basebreak.domain.verdict import EvidenceProvenance
from basebreak.evidence.artifact import compute_bytes_digest
from basebreak.evidence.provenance import ProvenanceLaunderingError

VALID_COMMIT_SHA = "a" * 40
VALID_TREE_SHA = "b" * 40
VALID_WORKSPACE = "/workspace/repo"


def _create_source_identity() -> SourceIdentity:
    return SourceIdentity(
        locator="https://github.com/zyganali-glitch/Basebreak.git",
        revision=CommitRevision(VALID_COMMIT_SHA),
    )


def _create_envelope() -> BuilderContextEnvelope:
    task = ingest_task("Task: Test repair\nRequirements:\n1. Ensure safe execution")
    fact = DeterministicClassificationFact(
        inferred_class=ChangeClass.FEATURE,
        certainty=CertaintyLevel.CONFIDENT,
        confidence=0.95,
        alternative_classes=(),
        rationale="Test",
        evidence_citations=("Task: Test repair",),
        matched_signals=("test",),
    )
    semantics = ChangeSemanticsClassification(
        task_digest=task.task_digest,
        change_class=ChangeClass.FEATURE,
        certainty=CertaintyLevel.CONFIDENT,
        confidence=0.95,
        alternative_classes=(),
        rationale="Test",
        evidence_citations=("Task: Test repair",),
        deterministic_facts=fact,
    )
    req = ProposedRequirement(
        statement="Ensure safe execution",
        citation="Task: Test repair",
        citation_start=0,
        citation_end=17,
        rationale="Test",
    )
    bundle = ReviewBundle(task=task, semantics=semantics, requirements=(req,))
    session = ReviewSession(bundle)
    review_result: ReviewResult = session.approve(reviewer_note="Approved")
    from basebreak.compiler.freeze import freeze_review_result

    frozen_contract: FrozenContract = freeze_review_result(review_result)
    src_id = _create_source_identity()
    allowlist = BuilderContextAllowlist.from_paths(["tests/test_foo.py"])
    return assemble_builder_context(
        frozen_contract=frozen_contract,
        source_identity=src_id,
        allowlist=allowlist,
        repository_files={"tests/test_foo.py": "def test_foo(): pass"},
    )


def _create_proposal() -> BuilderProposal:
    plan = BuilderPlan(
        summary="Add probe test",
        reasoning="Validation",
        steps=("Create test", "Run test"),
        is_authoritative=False,
    )
    action = ProposedFileAction(
        path="tests/test_probe.py",
        action=FileActionType.CREATE,
        content="def test_probe(): pass",
    )
    cmd = ProposedCommand(
        command="pytest tests/test_probe.py",
        rationale="Run probe test",
    )
    return BuilderProposal(
        plan=plan,
        proposed_file_actions=(action,),
        proposed_commands=(cmd,),
        raw_response='{"mock": "response"}',
        is_authoritative=False,
    )


def _create_clean_base_record() -> CleanBaseCheckpointRecord:
    return CleanBaseCheckpointRecord(
        source_identity=_create_source_identity(),
        resolved_commit_sha=VALID_COMMIT_SHA,
        resolved_tree_sha=VALID_TREE_SHA,
        workspace_path=VALID_WORKSPACE,
        sandbox_identity=SandboxIdentity("sbx-clean-base-orig"),
        operation_id="op-clean-base-001",
        checkpoint_image_uuid="img-clean-base-checkpoint-uuid",
        is_verified=True,
    )


def _create_mock_adapter(*, is_disposable: bool = True, fake_live: bool = False) -> Any:
    class MockAdapter:
        is_disposable_provider = is_disposable
        if fake_live:
            execution_provenance = EvidenceProvenance.LIVE_NEBIUS

        def __init__(self) -> None:
            self.created_handles: list[Any] = []
            self.executed_commands: list[str] = []

        def create_sandbox(self, image: str, disposable: bool = True) -> Any:
            h = SimpleNamespace(
                sandbox_identity=SandboxIdentity("sbx-mock-test"),
                image=image,
                disposable=disposable,
            )
            self.created_handles.append(h)
            return h

        def execute_command(self, sandbox: Any, command: str, **kwargs: Any) -> Any:
            self.executed_commands.append(command)
            status_b64 = base64.b64encode(b"A\ttests/test_probe.py\n").decode("ascii")
            patch_bytes = (
                b"--- a/tests/test_probe.py\n"
                b"+++ b/tests/test_probe.py\n"
                b"@@ -0,0 +1,2 @@\n"
                b"+def test_probe():\n"
                b"+    pass\n"
            )
            diff_b64 = base64.b64encode(patch_bytes).decode("ascii")
            stdout = (
                f"BASEBREAK_TOPLEVEL={VALID_WORKSPACE}\n"
                f"BASEBREAK_HEAD={VALID_COMMIT_SHA}\n"
                f"BASEBREAK_CANDIDATE_TREE={VALID_TREE_SHA}\n"
                f"BASEBREAK_STATUS_B64={status_b64}\n"
                f"BASEBREAK_DIFF_B64={diff_b64}\n"
                f"BASEBREAK_REPRO_TREE={VALID_TREE_SHA}\n"
                f"BASEBREAK_REPRO_DIFF_START\nA\ttests/test_probe.py\nBASEBREAK_REPRO_DIFF_END\n"
            )
            return SimpleNamespace(
                exit_code=0,
                stdout=stdout,
                stderr="",
                result_image_uuid=None,
                operation_id="op-mock-001",
            )

        def teardown_sandbox(self, sandbox: Any) -> None:
            pass

    return MockAdapter()


def _create_snapshot(
    envelope: BuilderContextEnvelope,
    *,
    provenance: EvidenceProvenance = EvidenceProvenance.LOCAL_EXECUTION,
) -> CandidateSnapshot:
    patch_text = (
        "--- a/tests/test_probe.py\n"
        "+++ b/tests/test_probe.py\n"
        "@@ -0,0 +1,2 @@\n"
        "+def test_probe():\n"
        "+    pass\n"
    )
    patch_digest = compute_bytes_digest(patch_text.encode("utf-8")).value
    return CandidateSnapshot(
        candidate_id="cand-test-001",
        source_identity=envelope.source_identity,
        candidate_tree_digest=VALID_TREE_SHA,
        patch_digest=patch_digest,
        patch_text=patch_text,
        files_added=("tests/test_probe.py",),
        files_modified=(),
        files_deleted=(),
        builder_authored_tests=(),
        frozen_contract_digest=envelope.frozen_contract.contract_digest,
        context_digest=envelope.context_digest,
        sandbox_identity=SandboxIdentity("sbx-builder-orig"),
        provenance=provenance,
        is_authoritative=False,
    )


# --- Test 1: Caller cannot upgrade execution provenance ---
def test_caller_cannot_upgrade_execution_provenance() -> None:
    envelope = _create_envelope()
    proposal = _create_proposal()
    adapter = _create_mock_adapter()
    config = CandidateExecutionConfig(
        bundled_execution=True,
        clean_base_record=_create_clean_base_record(),
        workspace_path=VALID_WORKSPACE,
    )
    executor = CandidateWorkspaceExecutor(
        adapter, source_materializer=SimpleNamespace(), config=config
    )

    with pytest.raises(ProvenanceLaunderingError, match="Caller-supplied LIVE_NEBIUS"):
        executor.execute(proposal, envelope=envelope, provenance=EvidenceProvenance.LIVE_NEBIUS)

    with pytest.raises(ProvenanceLaunderingError, match="Caller-supplied RECORDED_LIVE"):
        executor.execute(proposal, envelope=envelope, provenance=EvidenceProvenance.RECORDED_LIVE)


# --- Test 2: Caller cannot upgrade reproduction provenance ---
def test_caller_cannot_upgrade_reproduction_provenance() -> None:
    envelope = _create_envelope()
    snapshot = _create_snapshot(envelope)
    adapter = _create_mock_adapter()
    config = CandidateReproductionConfig(
        bundled_execution=True,
        clean_base_record=_create_clean_base_record(),
        workspace_path=VALID_WORKSPACE,
    )
    reproducer = CandidateReproductionExecutor(
        sandbox_adapter=adapter,
        source_materializer=SimpleNamespace(),
        config=config,
    )

    with pytest.raises(ProvenanceLaunderingError, match="LIVE_NEBIUS"):
        reproducer.reproduce(
            snapshot=snapshot, envelope=envelope, provenance=EvidenceProvenance.LIVE_NEBIUS
        )

    with pytest.raises(ProvenanceLaunderingError, match="RECORDED_LIVE"):
        reproducer.reproduce(
            snapshot=snapshot, envelope=envelope, provenance=EvidenceProvenance.RECORDED_LIVE
        )


# --- Test 3: Fake adapter LIVE property cannot establish LIVE_NEBIUS ---
def test_fake_adapter_live_property_cannot_establish_live_nebius() -> None:
    envelope = _create_envelope()
    proposal = _create_proposal()
    fake_adapter = _create_mock_adapter(fake_live=True)
    config = CandidateExecutionConfig(
        bundled_execution=True,
        clean_base_record=_create_clean_base_record(),
        workspace_path=VALID_WORKSPACE,
    )
    executor = CandidateWorkspaceExecutor(
        fake_adapter, source_materializer=SimpleNamespace(), config=config
    )
    res = executor.execute(proposal, envelope=envelope)
    # Must NOT be LIVE_NEBIUS just because fake adapter asserted it
    assert res.provenance == EvidenceProvenance.LOCAL_EXECUTION

    snapshot = _create_snapshot(envelope, provenance=EvidenceProvenance.LIVE_NEBIUS)
    repro_cfg = CandidateReproductionConfig(
        bundled_execution=True,
        clean_base_record=_create_clean_base_record(),
        workspace_path=VALID_WORKSPACE,
    )
    reproducer = CandidateReproductionExecutor(
        fake_adapter, source_materializer=SimpleNamespace(), config=repro_cfg
    )
    repro_res = reproducer.reproduce(snapshot=snapshot, envelope=envelope)
    assert repro_res.provenance == EvidenceProvenance.LOCAL_EXECUTION


# --- Test 4: No successful provider operation => no LIVE_NEBIUS ---
def test_no_successful_provider_operation_no_live_nebius() -> None:
    from basebreak.adapters.nebius.sandbox import (
        NebiusSandboxAdapter,
        SandboxClientConfig,
    )

    # Configuration alone with credentials does NOT yield LIVE_NEBIUS
    cfg = SandboxClientConfig(api_key="test-key", project_id="test-proj")
    adapter = NebiusSandboxAdapter(config=cfg)
    assert adapter.execution_provenance == EvidenceProvenance.LOCAL_EXECUTION


# --- Test 5: Disposable provider rejects non-bundled candidate execution ---
def test_disposable_provider_rejects_non_bundled_execution() -> None:
    adapter = _create_mock_adapter(is_disposable=True)
    bad_config = CandidateExecutionConfig(bundled_execution=False)
    with pytest.raises(
        InvalidExecutionModeError, match="Canonical production execution cannot enter disposable"
    ):
        CandidateWorkspaceExecutor(
            adapter, source_materializer=SimpleNamespace(), config=bad_config
        )


# --- Test 6: Disposable provider rejects non-bundled reproduction ---
def test_disposable_provider_rejects_non_bundled_reproduction() -> None:
    adapter = _create_mock_adapter(is_disposable=True)
    bad_config = CandidateReproductionConfig(bundled_execution=False)
    with pytest.raises(
        InvalidExecutionModeError, match="Canonical reproduction cannot enter disposable"
    ):
        CandidateReproductionExecutor(
            sandbox_adapter=adapter,
            source_materializer=SimpleNamespace(),
            config=bad_config,
        )


# --- Test 7: Synthetic caller clean-base record is strictly rejected ---
def test_synthetic_clean_base_record_rejected() -> None:
    forged_cbr = SimpleNamespace(
        source_identity=_create_source_identity(),
        resolved_commit_sha=VALID_COMMIT_SHA,
        resolved_tree_sha=VALID_TREE_SHA,
        workspace_path=VALID_WORKSPACE,
        checkpoint_image_uuid="img-forged",
        is_verified=True,
    )

    with pytest.raises(CleanBaseRecordAuthorityError, match="must be CleanBaseCheckpointRecord"):
        CandidateExecutionConfig(clean_base_record=forged_cbr)  # type: ignore[arg-type]

    with pytest.raises(CleanBaseRecordAuthorityError, match="must be CleanBaseCheckpointRecord"):
        CandidateReproductionConfig(clean_base_record=forged_cbr)  # type: ignore[arg-type]


# --- Test 8: Checkpoint image/source/tree/workspace binding is enforced ---
def test_checkpoint_binding_enforced() -> None:
    # 1. Invalid commit SHA hex
    with pytest.raises(
        CleanBaseRecordAuthorityError, match="resolved_commit_sha must be a 40 or 64 hex"
    ):
        CleanBaseCheckpointRecord(
            source_identity=_create_source_identity(),
            resolved_commit_sha="invalid-commit",
            resolved_tree_sha=VALID_TREE_SHA,
            workspace_path=VALID_WORKSPACE,
            sandbox_identity=SandboxIdentity("sbx-1"),
            operation_id="op-1",
            checkpoint_image_uuid="img-1",
            is_verified=True,
        )

    # 2. Invalid tree SHA hex
    with pytest.raises(
        CleanBaseRecordAuthorityError, match="resolved_tree_sha must be a 40 or 64 hex"
    ):
        CleanBaseCheckpointRecord(
            source_identity=_create_source_identity(),
            resolved_commit_sha=VALID_COMMIT_SHA,
            resolved_tree_sha="invalid-tree",
            workspace_path=VALID_WORKSPACE,
            sandbox_identity=SandboxIdentity("sbx-1"),
            operation_id="op-1",
            checkpoint_image_uuid="img-1",
            is_verified=True,
        )

    # 3. is_verified=False rejected
    with pytest.raises(CleanBaseRecordAuthorityError, match="is_verified must be strictly True"):
        CleanBaseCheckpointRecord(
            source_identity=_create_source_identity(),
            resolved_commit_sha=VALID_COMMIT_SHA,
            resolved_tree_sha=VALID_TREE_SHA,
            workspace_path=VALID_WORKSPACE,
            sandbox_identity=SandboxIdentity("sbx-1"),
            operation_id="op-1",
            checkpoint_image_uuid="img-1",
            is_verified=False,
        )

    # 4. Commit mismatch during execution
    mismatched_cbr = CleanBaseCheckpointRecord(
        source_identity=_create_source_identity(),
        resolved_commit_sha="f" * 40,
        resolved_tree_sha=VALID_TREE_SHA,
        workspace_path=VALID_WORKSPACE,
        sandbox_identity=SandboxIdentity("sbx-1"),
        operation_id="op-1",
        checkpoint_image_uuid="img-1",
        is_verified=True,
    )
    envelope = _create_envelope()
    proposal = _create_proposal()
    adapter = _create_mock_adapter()
    cfg = CandidateExecutionConfig(
        bundled_execution=True,
        clean_base_record=mismatched_cbr,
        workspace_path=VALID_WORKSPACE,
    )
    executor = CandidateWorkspaceExecutor(
        adapter, source_materializer=SimpleNamespace(), config=cfg
    )
    with pytest.raises(SourceCommitMismatchError):
        executor.execute(proposal, envelope=envelope)


# --- Test 9: Disposable Builder execution with non-null result_image_uuid fails closed ---
def test_disposable_builder_with_persistent_image_fails_closed() -> None:
    envelope = _create_envelope()
    proposal = _create_proposal()

    class LeakingAdapter:
        is_disposable_provider = True

        def create_sandbox(self, image: str, disposable: bool = True) -> Any:
            return SimpleNamespace(
                sandbox_identity=SandboxIdentity("sbx-leak"),
                image=image,
                disposable=disposable,
            )

        def execute_command(self, sandbox: Any, command: str, **kwargs: Any) -> Any:
            return SimpleNamespace(
                exit_code=0,
                stdout="BASEBREAK_TOPLEVEL=/workspace/repo\nBASEBREAK_HEAD="
                + VALID_COMMIT_SHA
                + "\n",
                stderr="",
                result_image_uuid="img-persisted-leak",  # VIOLATION on disposable execution!
                operation_id="op-leak-001",
            )

        def teardown_sandbox(self, sandbox: Any) -> None:
            pass

    config = CandidateExecutionConfig(
        bundled_execution=True,
        clean_base_record=_create_clean_base_record(),
        workspace_path=VALID_WORKSPACE,
    )
    executor = CandidateWorkspaceExecutor(
        LeakingAdapter(), source_materializer=SimpleNamespace(), config=config
    )
    with pytest.raises(
        DisposableExecutionPolicyViolationError, match="unexpectedly returned persistent image UUID"
    ):
        executor.execute(proposal, envelope=envelope)


# --- Test 10: Disposable reproduction with non-null result_image_uuid fails closed ---
def test_disposable_reproduction_with_persistent_image_fails_closed() -> None:
    envelope = _create_envelope()
    snapshot = _create_snapshot(envelope)

    class LeakingReproAdapter:
        is_disposable_provider = True

        def create_sandbox(self, image: str, disposable: bool = True) -> Any:
            return SimpleNamespace(
                sandbox_identity=SandboxIdentity("sbx-repro-leak"),
                image=image,
                disposable=disposable,
            )

        def execute_command(self, sandbox: Any, command: str, **kwargs: Any) -> Any:
            return SimpleNamespace(
                exit_code=0,
                stdout="BASEBREAK_REPRO_TREE=" + VALID_TREE_SHA + "\n",
                stderr="",
                result_image_uuid="img-repro-persisted-leak",  # VIOLATION on disposable execution!
                operation_id="op-repro-leak-001",
            )

        def teardown_sandbox(self, sandbox: Any) -> None:
            pass

    config = CandidateReproductionConfig(
        bundled_execution=True,
        clean_base_record=_create_clean_base_record(),
        workspace_path=VALID_WORKSPACE,
    )
    reproducer = CandidateReproductionExecutor(
        sandbox_adapter=LeakingReproAdapter(),
        source_materializer=SimpleNamespace(),
        config=config,
    )
    with pytest.raises(
        DisposableExecutionPolicyViolationError, match="unexpectedly returned persistent image UUID"
    ):
        reproducer.reproduce(snapshot=snapshot, envelope=envelope)


# --- Test 11: Clean-base checkpoint materialization requires non-null image UUID ---
def test_clean_base_checkpoint_requires_non_null_image_uuid() -> None:
    record_without_img = SimpleNamespace(
        source_identity=_create_source_identity(),
        resolved_commit_sha=VALID_COMMIT_SHA,
        resolved_tree_sha=VALID_TREE_SHA,
        workspace_path=VALID_WORKSPACE,
        sandbox_identity=SandboxIdentity("sbx-clean"),
        operation_id="op-clean-001",
        result_image_uuid=None,  # Missing image UUID on clean base checkpoint!
        is_verified=True,
    )
    with pytest.raises(
        CleanBaseRecordAuthorityError, match="requires non-null, non-empty result_image_uuid"
    ):
        CleanBaseCheckpointRecord.from_materialized_record(record_without_img)

    record_without_op = SimpleNamespace(
        source_identity=_create_source_identity(),
        resolved_commit_sha=VALID_COMMIT_SHA,
        resolved_tree_sha=VALID_TREE_SHA,
        workspace_path=VALID_WORKSPACE,
        sandbox_identity=SandboxIdentity("sbx-clean"),
        operation_id="",  # Missing op ID!
        result_image_uuid="img-clean-uuid",
        is_verified=True,
    )
    with pytest.raises(
        CleanBaseRecordAuthorityError, match="requires non-null, non-empty operation_id"
    ):
        CleanBaseCheckpointRecord.from_materialized_record(record_without_op)


# --- Test 12: Provider operation IDs and image facts retained for evidence ---
def test_evidence_facts_retained() -> None:
    envelope = _create_envelope()
    proposal = _create_proposal()
    adapter = _create_mock_adapter()
    cbr = _create_clean_base_record()
    config = CandidateExecutionConfig(
        bundled_execution=True,
        clean_base_record=cbr,
        workspace_path=VALID_WORKSPACE,
    )
    executor = CandidateWorkspaceExecutor(
        adapter, source_materializer=SimpleNamespace(), config=config
    )
    res = executor.execute(proposal, envelope=envelope)

    assert res.clean_base_checkpoint_image_uuid == "img-clean-base-checkpoint-uuid"
    assert res.clean_base_operation_id == "op-clean-base-001"
    assert res.provider_operation_id == "op-mock-001"
    assert res.result_image_uuid is None

    # Serialization roundtrip
    d = res.to_dict()
    assert d["clean_base_checkpoint_image_uuid"] == "img-clean-base-checkpoint-uuid"
    assert d["clean_base_operation_id"] == "op-clean-base-001"
    assert d["provider_operation_id"] == "op-mock-001"
    assert d["result_image_uuid"] is None

    res_restored = CandidateExecutionResult.from_dict(d)
    assert res_restored.clean_base_checkpoint_image_uuid == "img-clean-base-checkpoint-uuid"
    assert res_restored.clean_base_operation_id == "op-clean-base-001"
    assert res_restored.provider_operation_id == "op-mock-001"
    assert res_restored.result_image_uuid is None

    # Reproduction facts
    snapshot = _create_snapshot(envelope)
    repro_cfg = CandidateReproductionConfig(
        bundled_execution=True,
        clean_base_record=cbr,
        workspace_path=VALID_WORKSPACE,
    )
    reproducer = CandidateReproductionExecutor(
        adapter, source_materializer=SimpleNamespace(), config=repro_cfg
    )
    repro_res = reproducer.reproduce(snapshot=snapshot, envelope=envelope)

    assert repro_res.clean_base_checkpoint_image_uuid == "img-clean-base-checkpoint-uuid"
    assert repro_res.clean_base_operation_id == "op-clean-base-001"
    assert repro_res.provider_operation_id == "op-mock-001"
    assert repro_res.result_image_uuid is None

    repro_d = repro_res.to_dict()
    assert repro_d["clean_base_checkpoint_image_uuid"] == "img-clean-base-checkpoint-uuid"
    assert repro_d["clean_base_operation_id"] == "op-clean-base-001"
    assert repro_d["provider_operation_id"] == "op-mock-001"
    assert repro_d["result_image_uuid"] is None

    repro_restored = CandidateReproductionResult.from_dict(repro_d)
    assert repro_restored.clean_base_checkpoint_image_uuid == "img-clean-base-checkpoint-uuid"
    assert repro_restored.clean_base_operation_id == "op-clean-base-001"
    assert repro_restored.provider_operation_id == "op-mock-001"
    assert repro_restored.result_image_uuid is None
