"""Adversarial and regression tests for P-07.06 final surgical repairs.

Covers all 12 required test conditions proving clean-base authority repair:
1. public execution config cannot accept CleanBaseCheckpointRecord;
2. public reproduction config cannot accept CleanBaseCheckpointRecord;
3. caller cannot inject arbitrary checkpoint image UUID;
4. caller cannot inject arbitrary clean-base operation ID;
5. caller cannot inject a forged but field-valid typed record;
6. execution internally invokes trusted materializer for clean checkpoint creation;
7. reproduction independently invokes trusted materializer for its own clean checkpoint;
8. exact source commit mismatch fails closed;
9. resolved tree mismatch fails closed;
10. checkpoint materialization requires non-null provider operation ID;
11. checkpoint materialization requires non-null image UUID;
12. Builder and reproduction clean checkpoint facts remain separately retained in evidence.

And preserves all verified P-04/P-07 security and provenance invariants:
- provenance laundering prevention (execution & reproduction);
- fake adapter LIVE property rejection;
- provider fact requirement for LIVE_NEBIUS;
- mandatory bundled execution on disposable providers;
- disposable execution persistent image leak rejection.
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
    CandidateExecutionConfigError,
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
    CandidateReproductionConfigError,
    CandidateReproductionExecutor,
    CandidateReproductionResult,
    TreeDigestMismatchError,
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


def _create_source_identity(commit: str = VALID_COMMIT_SHA) -> SourceIdentity:
    return SourceIdentity(
        locator="https://github.com/zyganali-glitch/Basebreak.git",
        revision=CommitRevision(commit),
    )


def _create_envelope(commit: str = VALID_COMMIT_SHA) -> BuilderContextEnvelope:
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
    src_id = _create_source_identity(commit)
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


def _create_clean_base_record(
    commit: str = VALID_COMMIT_SHA,
    tree: str = VALID_TREE_SHA,
    op_id: str = "op-clean-base-001",
    img_uuid: str = "img-clean-base-checkpoint-uuid",
) -> CleanBaseCheckpointRecord:
    return CleanBaseCheckpointRecord(
        source_identity=_create_source_identity(commit),
        resolved_commit_sha=commit,
        resolved_tree_sha=tree,
        workspace_path=VALID_WORKSPACE,
        sandbox_identity=SandboxIdentity("sbx-clean-base-orig"),
        operation_id=op_id,
        checkpoint_image_uuid=img_uuid,
        is_verified=True,
    )


def _create_mock_adapter(
    *,
    is_disposable: bool = True,
    fake_live: bool = False,
    op_id: str = "op-mock-disp-001",
    repro_tree: str = VALID_TREE_SHA,
    result_image_uuid: str | None = None,
    sandbox_id: str = "sbx-mock-test",
) -> Any:
    class MockAdapter:
        is_disposable_provider = is_disposable
        if fake_live:
            execution_provenance = EvidenceProvenance.LIVE_NEBIUS

        def __init__(self) -> None:
            self.created_handles: list[Any] = []
            self.executed_commands: list[str] = []

        def create_sandbox(self, image: str, disposable: bool = True) -> Any:
            h = SimpleNamespace(
                sandbox_identity=SandboxIdentity(sandbox_id),
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
                f"BASEBREAK_REPRO_TREE={repro_tree}\n"
                f"BASEBREAK_REPRO_DIFF_START\nA\ttests/test_probe.py\nBASEBREAK_REPRO_DIFF_END\n"
            )
            return SimpleNamespace(
                exit_code=0,
                stdout=stdout,
                stderr="",
                result_image_uuid=result_image_uuid,
                operation_id=op_id,
            )

        def teardown_sandbox(self, sandbox: Any) -> None:
            pass

    return MockAdapter()


def _create_mock_materializer(
    *,
    commit: str = VALID_COMMIT_SHA,
    tree: str = VALID_TREE_SHA,
    workspace: str = VALID_WORKSPACE,
    op_id: str = "op-clean-base-001",
    image_uuid: str | None = "img-clean-base-checkpoint-uuid",
    is_verified: bool = True,
    should_fail: bool = False,
) -> Any:
    class MockMaterializer:
        def __init__(self) -> None:
            self.materialized_calls: list[dict[str, Any]] = []

        def materialize_repository(
            self,
            source_identity: SourceIdentity,
            *,
            sandbox: Any = None,
            workspace_path: str = VALID_WORKSPACE,
            disposable: bool = False,
            timeout_seconds: int = 120,
            **kwargs: Any,
        ) -> Any:
            self.materialized_calls.append(
                {
                    "source_identity": source_identity,
                    "sandbox": sandbox,
                    "workspace_path": workspace_path,
                    "disposable": disposable,
                    "timeout_seconds": timeout_seconds,
                }
            )
            if should_fail:
                raise RuntimeError("Materialization failed")
            return SimpleNamespace(
                source_identity=source_identity,
                resolved_commit_sha=commit,
                resolved_tree_sha=tree,
                workspace_path=workspace,
                sandbox_identity=SandboxIdentity("sbx-clean-base-orig"),
                operation_id=op_id,
                result_image_uuid=image_uuid,
                duration_seconds=0.1,
                is_verified=is_verified,
            )

    return MockMaterializer()


def _create_snapshot(
    envelope: BuilderContextEnvelope,
    *,
    provenance: EvidenceProvenance = EvidenceProvenance.LOCAL_EXECUTION,
    clean_base_img: str | None = "img-clean-base-checkpoint-uuid",
    clean_base_op: str | None = "op-clean-base-001",
    builder_disp_op: str | None = "op-builder-disp-001",
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
        clean_base_checkpoint_image_uuid=clean_base_img,
        clean_base_operation_id=clean_base_op,
        provider_operation_id=builder_disp_op,
        result_image_uuid=None,
    )


# ==============================================================================
# 12 REQUIRED ADVERSARIAL TESTS PROVING CLEAN-BASE REPAIR
# ==============================================================================


# --- Condition 1: Public execution config cannot accept CleanBaseCheckpointRecord ---
def test_execution_config_cannot_accept_clean_base_record() -> None:
    cbr = _create_clean_base_record()
    with pytest.raises((TypeError, CandidateExecutionConfigError)):
        CandidateExecutionConfig(clean_base_record=cbr)  # type: ignore[call-arg]


# --- Condition 2: Public reproduction config cannot accept CleanBaseCheckpointRecord ---
def test_reproduction_config_cannot_accept_clean_base_record() -> None:
    cbr = _create_clean_base_record()
    with pytest.raises((TypeError, CandidateReproductionConfigError)):
        CandidateReproductionConfig(clean_base_record=cbr)  # type: ignore[call-arg]


# --- Condition 3: Caller cannot inject arbitrary checkpoint image UUID ---
def test_caller_cannot_inject_arbitrary_checkpoint_image_uuid() -> None:
    with pytest.raises((TypeError, CandidateExecutionConfigError)):
        CandidateExecutionConfig(checkpoint_image_uuid="img-attacker-image")  # type: ignore[call-arg]
    with pytest.raises((TypeError, CandidateReproductionConfigError)):
        CandidateReproductionConfig(checkpoint_image_uuid="img-attacker-image")  # type: ignore[call-arg]

    envelope = _create_envelope()
    proposal = _create_proposal()
    adapter = _create_mock_adapter()
    mat = _create_mock_materializer()
    executor = CandidateWorkspaceExecutor(adapter, source_materializer=mat)
    with pytest.raises(TypeError):
        executor.execute(proposal, envelope=envelope, checkpoint_image_uuid="img-attacker-image")

    snapshot = _create_snapshot(envelope)
    reproducer = CandidateReproductionExecutor(sandbox_adapter=adapter, source_materializer=mat)
    with pytest.raises(TypeError):
        reproducer.reproduce(
            snapshot=snapshot, envelope=envelope, checkpoint_image_uuid="img-attacker-image"
        )

    # Even if caller passes sandbox_image="img-attacker", executor uses internally
    # materialized checkpoint image
    attacker_cfg = CandidateExecutionConfig(
        bundled_execution=True,
        sandbox_image="img-attacker-override",
        workspace_path=VALID_WORKSPACE,
    )
    executor2 = CandidateWorkspaceExecutor(adapter, source_materializer=mat, config=attacker_cfg)
    res = executor2.execute(proposal, envelope=envelope)
    assert res.clean_base_checkpoint_image_uuid == "img-clean-base-checkpoint-uuid"
    assert adapter.created_handles[-1].image == "img-clean-base-checkpoint-uuid"


# --- Condition 4: Caller cannot inject arbitrary clean-base operation ID ---
def test_caller_cannot_inject_arbitrary_clean_base_operation_id() -> None:
    with pytest.raises((TypeError, CandidateExecutionConfigError)):
        CandidateExecutionConfig(clean_base_operation_id="op-attacker-op")  # type: ignore[call-arg]
    with pytest.raises((TypeError, CandidateReproductionConfigError)):
        CandidateReproductionConfig(clean_base_operation_id="op-attacker-op")  # type: ignore[call-arg]

    envelope = _create_envelope()
    proposal = _create_proposal()
    adapter = _create_mock_adapter()
    mat = _create_mock_materializer()
    executor = CandidateWorkspaceExecutor(adapter, source_materializer=mat)
    with pytest.raises(TypeError):
        executor.execute(proposal, envelope=envelope, clean_base_operation_id="op-attacker-op")

    snapshot = _create_snapshot(envelope)
    reproducer = CandidateReproductionExecutor(sandbox_adapter=adapter, source_materializer=mat)
    with pytest.raises(TypeError):
        reproducer.reproduce(
            snapshot=snapshot, envelope=envelope, clean_base_operation_id="op-attacker-op"
        )


# --- Condition 5: Caller cannot inject a forged but field-valid typed record ---
def test_caller_cannot_inject_forged_typed_clean_base_record() -> None:
    forged_cbr = CleanBaseCheckpointRecord(
        source_identity=_create_source_identity(),
        resolved_commit_sha=VALID_COMMIT_SHA,
        resolved_tree_sha=VALID_TREE_SHA,
        workspace_path=VALID_WORKSPACE,
        sandbox_identity=SandboxIdentity("sbx-forged"),
        operation_id="op-forged-001",
        checkpoint_image_uuid="img-forged-uuid",
        is_verified=True,
    )
    with pytest.raises((TypeError, CandidateExecutionConfigError)):
        CandidateExecutionConfig(clean_base_record=forged_cbr)  # type: ignore[call-arg]
    with pytest.raises((TypeError, CandidateReproductionConfigError)):
        CandidateReproductionConfig(clean_base_record=forged_cbr)  # type: ignore[call-arg]

    envelope = _create_envelope()
    proposal = _create_proposal()
    adapter = _create_mock_adapter()
    mat = _create_mock_materializer()
    executor = CandidateWorkspaceExecutor(adapter, source_materializer=mat)
    with pytest.raises((TypeError, CleanBaseRecordAuthorityError)):
        executor.execute(proposal, envelope=envelope, clean_base_record=forged_cbr)

    snapshot = _create_snapshot(envelope)
    reproducer = CandidateReproductionExecutor(sandbox_adapter=adapter, source_materializer=mat)
    with pytest.raises((TypeError, CleanBaseRecordAuthorityError)):
        reproducer.reproduce(snapshot=snapshot, envelope=envelope, clean_base_record=forged_cbr)


# --- Condition 6: Execution internally invokes trusted materializer for clean checkpoint ---
def test_execution_internally_invokes_trusted_materializer_for_clean_checkpoint() -> None:
    envelope = _create_envelope()
    proposal = _create_proposal()
    adapter = _create_mock_adapter()
    mat = _create_mock_materializer()
    config = CandidateExecutionConfig(bundled_execution=True, workspace_path=VALID_WORKSPACE)
    executor = CandidateWorkspaceExecutor(adapter, source_materializer=mat, config=config)

    res = executor.execute(proposal, envelope=envelope)

    assert len(mat.materialized_calls) >= 1
    call = mat.materialized_calls[0]
    assert call["source_identity"] == envelope.source_identity
    assert call["disposable"] is False
    assert res.clean_base_checkpoint_image_uuid == "img-clean-base-checkpoint-uuid"
    assert res.clean_base_operation_id == "op-clean-base-001"


# --- Condition 7: Reproduction independently invokes trusted materializer for clean checkpoint ---
def test_reproduction_independently_invokes_trusted_materializer_for_clean_checkpoint() -> None:
    envelope = _create_envelope()
    snapshot = _create_snapshot(envelope)
    adapter = _create_mock_adapter()
    mat = _create_mock_materializer()
    config = CandidateReproductionConfig(bundled_execution=True, workspace_path=VALID_WORKSPACE)
    reproducer = CandidateReproductionExecutor(
        sandbox_adapter=adapter, source_materializer=mat, config=config
    )

    res = reproducer.reproduce(snapshot=snapshot, envelope=envelope)

    assert len(mat.materialized_calls) >= 1
    call = mat.materialized_calls[0]
    assert call["source_identity"] == envelope.source_identity
    assert call["disposable"] is False
    assert res.clean_base_checkpoint_image_uuid == "img-clean-base-checkpoint-uuid"
    assert res.clean_base_operation_id == "op-clean-base-001"


# --- Condition 8: Exact source commit mismatch fails closed ---
def test_exact_source_commit_mismatch_fails_closed() -> None:
    envelope = _create_envelope()
    proposal = _create_proposal()
    adapter = _create_mock_adapter()
    mat_mismatch = _create_mock_materializer(commit="f" * 40)
    config = CandidateExecutionConfig(bundled_execution=True, workspace_path=VALID_WORKSPACE)
    executor = CandidateWorkspaceExecutor(adapter, source_materializer=mat_mismatch, config=config)
    with pytest.raises(SourceCommitMismatchError):
        executor.execute(proposal, envelope=envelope)

    snapshot = _create_snapshot(envelope)
    repro_cfg = CandidateReproductionConfig(bundled_execution=True, workspace_path=VALID_WORKSPACE)
    reproducer = CandidateReproductionExecutor(
        sandbox_adapter=adapter, source_materializer=mat_mismatch, config=repro_cfg
    )
    with pytest.raises(SourceCommitMismatchError):
        reproducer.reproduce(snapshot=snapshot, envelope=envelope)


# --- Condition 9: Resolved tree mismatch fails closed ---
def test_resolved_tree_mismatch_fails_closed() -> None:
    envelope = _create_envelope()
    proposal = _create_proposal()
    adapter = _create_mock_adapter()

    # 1. Invalid tree SHA on clean base materialization fails closed
    mat_invalid_tree = _create_mock_materializer(tree="invalid-tree-sha")
    config = CandidateExecutionConfig(bundled_execution=True, workspace_path=VALID_WORKSPACE)
    executor = CandidateWorkspaceExecutor(
        adapter, source_materializer=mat_invalid_tree, config=config
    )
    with pytest.raises(
        CleanBaseRecordAuthorityError, match="resolved_tree_sha must be a 40 or 64 hex"
    ):
        executor.execute(proposal, envelope=envelope)

    # 2. Reproduced tree mismatch against snapshot candidate tree fails closed
    snapshot = _create_snapshot(envelope)
    mat_valid = _create_mock_materializer()
    repro_cfg = CandidateReproductionConfig(bundled_execution=True, workspace_path=VALID_WORKSPACE)
    adapter_wrong_tree = _create_mock_adapter(repro_tree="c" * 40)
    reproducer = CandidateReproductionExecutor(
        sandbox_adapter=adapter_wrong_tree, source_materializer=mat_valid, config=repro_cfg
    )
    with pytest.raises(
        TreeDigestMismatchError, match="reproduced tree digest .* does not match captured candidate"
    ):
        reproducer.reproduce(snapshot=snapshot, envelope=envelope)


# --- Condition 10: Checkpoint materialization requires non-null provider operation ID ---
def test_checkpoint_materialization_requires_non_null_provider_operation_id() -> None:
    envelope = _create_envelope()
    proposal = _create_proposal()
    adapter = _create_mock_adapter()
    mat_no_op = _create_mock_materializer(op_id="")
    config = CandidateExecutionConfig(bundled_execution=True, workspace_path=VALID_WORKSPACE)
    executor = CandidateWorkspaceExecutor(adapter, source_materializer=mat_no_op, config=config)
    with pytest.raises(
        CleanBaseRecordAuthorityError, match="requires non-null, non-empty operation_id"
    ):
        executor.execute(proposal, envelope=envelope)


# --- Condition 11: Checkpoint materialization requires non-null image UUID ---
def test_checkpoint_materialization_requires_non_null_image_uuid() -> None:
    envelope = _create_envelope()
    proposal = _create_proposal()
    adapter = _create_mock_adapter()
    mat_no_img = _create_mock_materializer(image_uuid=None)
    config = CandidateExecutionConfig(bundled_execution=True, workspace_path=VALID_WORKSPACE)
    executor = CandidateWorkspaceExecutor(adapter, source_materializer=mat_no_img, config=config)
    with pytest.raises(
        CleanBaseRecordAuthorityError, match="requires non-null, non-empty result_image_uuid"
    ):
        executor.execute(proposal, envelope=envelope)


# --- Condition 12: Builder and reproduction clean checkpoint facts remain ---
# separately retained in evidence
def test_builder_and_reproduction_clean_checkpoint_facts_retained_in_evidence() -> None:
    envelope = _create_envelope()
    proposal = _create_proposal()
    adapter_builder = _create_mock_adapter(
        op_id="op-builder-disp-001", sandbox_id="sbx-builder-disp-001"
    )
    mat_builder = _create_mock_materializer(
        op_id="op-builder-clean-001", image_uuid="img-builder-clean-uuid"
    )
    cfg_builder = CandidateExecutionConfig(bundled_execution=True, workspace_path=VALID_WORKSPACE)
    executor = CandidateWorkspaceExecutor(
        adapter_builder, source_materializer=mat_builder, config=cfg_builder
    )
    res = executor.execute(proposal, envelope=envelope)

    assert res.clean_base_checkpoint_image_uuid == "img-builder-clean-uuid"
    assert res.clean_base_operation_id == "op-builder-clean-001"
    assert res.provider_operation_id == "op-builder-disp-001"
    assert res.result_image_uuid is None

    snapshot = res.bundled_snapshot
    assert snapshot is not None
    assert snapshot.clean_base_checkpoint_image_uuid == "img-builder-clean-uuid"
    assert snapshot.clean_base_operation_id == "op-builder-clean-001"
    assert snapshot.provider_operation_id == "op-builder-disp-001"
    assert snapshot.result_image_uuid is None

    adapter_repro = _create_mock_adapter(op_id="op-repro-disp-002", sandbox_id="sbx-repro-disp-002")
    mat_repro = _create_mock_materializer(
        op_id="op-repro-clean-002", image_uuid="img-repro-clean-uuid"
    )
    cfg_repro = CandidateReproductionConfig(bundled_execution=True, workspace_path=VALID_WORKSPACE)
    reproducer = CandidateReproductionExecutor(
        sandbox_adapter=adapter_repro, source_materializer=mat_repro, config=cfg_repro
    )
    repro_res = reproducer.reproduce(snapshot=snapshot, envelope=envelope)

    assert repro_res.clean_base_checkpoint_image_uuid == "img-repro-clean-uuid"
    assert repro_res.clean_base_operation_id == "op-repro-clean-002"
    assert repro_res.provider_operation_id == "op-repro-disp-002"
    assert repro_res.result_image_uuid is None

    # Prove all 4 operations are distinct
    assert res.clean_base_operation_id != repro_res.clean_base_operation_id
    assert res.provider_operation_id != repro_res.provider_operation_id
    assert res.clean_base_operation_id != res.provider_operation_id
    assert repro_res.clean_base_operation_id != repro_res.provider_operation_id

    # Roundtrip serialization verification
    d_builder = res.to_dict()
    restored_builder = CandidateExecutionResult.from_dict(d_builder)
    assert restored_builder.clean_base_checkpoint_image_uuid == "img-builder-clean-uuid"
    assert restored_builder.clean_base_operation_id == "op-builder-clean-001"
    assert restored_builder.provider_operation_id == "op-builder-disp-001"
    assert restored_builder.result_image_uuid is None

    d_repro = repro_res.to_dict()
    restored_repro = CandidateReproductionResult.from_dict(d_repro)
    assert restored_repro.clean_base_checkpoint_image_uuid == "img-repro-clean-uuid"
    assert restored_repro.clean_base_operation_id == "op-repro-clean-002"
    assert restored_repro.provider_operation_id == "op-repro-disp-002"
    assert restored_repro.result_image_uuid is None


# ==============================================================================
# PRESERVED SECURITY & PROVENANCE INVARIANTS
# ==============================================================================


def test_caller_cannot_upgrade_execution_provenance() -> None:
    envelope = _create_envelope()
    proposal = _create_proposal()
    adapter = _create_mock_adapter()
    mat = _create_mock_materializer()
    config = CandidateExecutionConfig(bundled_execution=True, workspace_path=VALID_WORKSPACE)
    executor = CandidateWorkspaceExecutor(adapter, source_materializer=mat, config=config)

    with pytest.raises(ProvenanceLaunderingError, match="Caller-supplied LIVE_NEBIUS"):
        executor.execute(proposal, envelope=envelope, provenance=EvidenceProvenance.LIVE_NEBIUS)

    with pytest.raises(ProvenanceLaunderingError, match="Caller-supplied RECORDED_LIVE"):
        executor.execute(proposal, envelope=envelope, provenance=EvidenceProvenance.RECORDED_LIVE)


def test_caller_cannot_upgrade_reproduction_provenance() -> None:
    envelope = _create_envelope()
    snapshot = _create_snapshot(envelope)
    adapter = _create_mock_adapter()
    mat = _create_mock_materializer()
    config = CandidateReproductionConfig(bundled_execution=True, workspace_path=VALID_WORKSPACE)
    reproducer = CandidateReproductionExecutor(
        sandbox_adapter=adapter, source_materializer=mat, config=config
    )

    with pytest.raises(ProvenanceLaunderingError, match="LIVE_NEBIUS"):
        reproducer.reproduce(
            snapshot=snapshot, envelope=envelope, provenance=EvidenceProvenance.LIVE_NEBIUS
        )

    with pytest.raises(ProvenanceLaunderingError, match="RECORDED_LIVE"):
        reproducer.reproduce(
            snapshot=snapshot, envelope=envelope, provenance=EvidenceProvenance.RECORDED_LIVE
        )


def test_fake_adapter_live_property_cannot_establish_live_nebius() -> None:
    envelope = _create_envelope()
    proposal = _create_proposal()
    fake_adapter = _create_mock_adapter(fake_live=True)
    mat = _create_mock_materializer()
    config = CandidateExecutionConfig(bundled_execution=True, workspace_path=VALID_WORKSPACE)
    executor = CandidateWorkspaceExecutor(fake_adapter, source_materializer=mat, config=config)
    res = executor.execute(proposal, envelope=envelope)
    assert res.provenance == EvidenceProvenance.LOCAL_EXECUTION

    snapshot = _create_snapshot(envelope, provenance=EvidenceProvenance.LIVE_NEBIUS)
    repro_cfg = CandidateReproductionConfig(bundled_execution=True, workspace_path=VALID_WORKSPACE)
    reproducer = CandidateReproductionExecutor(
        fake_adapter, source_materializer=mat, config=repro_cfg
    )
    repro_res = reproducer.reproduce(snapshot=snapshot, envelope=envelope)
    assert repro_res.provenance == EvidenceProvenance.LOCAL_EXECUTION


def test_no_successful_provider_operation_no_live_nebius() -> None:
    from basebreak.adapters.nebius.sandbox import (
        NebiusSandboxAdapter,
        SandboxClientConfig,
    )

    cfg = SandboxClientConfig(api_key="test-key", project_id="test-proj")
    adapter = NebiusSandboxAdapter(config=cfg)
    assert adapter.execution_provenance == EvidenceProvenance.LOCAL_EXECUTION


def test_disposable_provider_rejects_non_bundled_execution() -> None:
    adapter = _create_mock_adapter(is_disposable=True)
    mat = _create_mock_materializer()
    bad_config = CandidateExecutionConfig(bundled_execution=False)
    with pytest.raises(
        InvalidExecutionModeError, match="Canonical production execution cannot enter disposable"
    ):
        CandidateWorkspaceExecutor(adapter, source_materializer=mat, config=bad_config)


def test_disposable_provider_rejects_non_bundled_reproduction() -> None:
    adapter = _create_mock_adapter(is_disposable=True)
    mat = _create_mock_materializer()
    bad_config = CandidateReproductionConfig(bundled_execution=False)
    with pytest.raises(
        InvalidExecutionModeError, match="Canonical reproduction cannot enter disposable"
    ):
        CandidateReproductionExecutor(
            sandbox_adapter=adapter,
            source_materializer=mat,
            config=bad_config,
        )


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
                stdout=f"BASEBREAK_TOPLEVEL=/workspace/repo\nBASEBREAK_HEAD={VALID_COMMIT_SHA}\n",
                stderr="",
                result_image_uuid="img-persisted-leak",  # VIOLATION
                operation_id="op-leak-001",
            )

        def teardown_sandbox(self, sandbox: Any) -> None:
            pass

    mat = _create_mock_materializer()
    config = CandidateExecutionConfig(bundled_execution=True, workspace_path=VALID_WORKSPACE)
    executor = CandidateWorkspaceExecutor(LeakingAdapter(), source_materializer=mat, config=config)
    with pytest.raises(
        DisposableExecutionPolicyViolationError, match="unexpectedly returned persistent image UUID"
    ):
        executor.execute(proposal, envelope=envelope)


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
                stdout=f"BASEBREAK_REPRO_TREE={VALID_TREE_SHA}\n",
                stderr="",
                result_image_uuid="img-repro-persisted-leak",  # VIOLATION
                operation_id="op-repro-leak-001",
            )

        def teardown_sandbox(self, sandbox: Any) -> None:
            pass

    mat = _create_mock_materializer()
    config = CandidateReproductionConfig(bundled_execution=True, workspace_path=VALID_WORKSPACE)
    reproducer = CandidateReproductionExecutor(
        sandbox_adapter=LeakingReproAdapter(),
        source_materializer=mat,
        config=config,
    )
    with pytest.raises(
        DisposableExecutionPolicyViolationError, match="unexpectedly returned persistent image UUID"
    ):
        reproducer.reproduce(snapshot=snapshot, envelope=envelope)
