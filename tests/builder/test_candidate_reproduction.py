"""Focused deterministic unit tests for P-07.06: Candidate reproduction in a fresh sandbox.

Tests cover:
1. Fresh sandbox is distinct from Builder sandbox;
2. Builder sandbox and workspace state cannot be reused (fails closed with SandboxFreshnessError);
3. Source identity mismatch fails closed (locator, commit ID, subpath);
4. Frozen-contract and Builder context binding mismatch fails closed;
5. Patch digest tampering fails closed;
6. Caller cannot substitute BuilderProposal for captured patch;
7. Protected-surface patch fails before acceptance (diff validation);
8. Patch-apply failure fails closed (git apply non-zero exit);
9. Reproduced tree mismatch fails closed (git write-tree SHA mismatch);
10. Exact trusted base + exact patch reproduces exact candidate tree successfully;
11. Failure tears down reproduction sandbox (materialization, patch apply, tree mismatch);
12. Reproduction result cannot claim authority/causal verification/PASS;
13. Config invariants and non-downgradable canonical P-04 policy;
14. Host execution fallback rejected (missing sandbox_adapter);
15. Unmaterialized workspace rejected (missing source_materializer);
16. Caller-supplied materialized_source rejected;
17. No-change candidate reproduction;
18. Large patch chunking transport;
19. Serialization roundtrip for CandidateReproductionResult;
20. Existing regressions remain green.
"""

from __future__ import annotations

from collections.abc import Sequence
from dataclasses import dataclass
from types import SimpleNamespace
from typing import Any

import pytest

from basebreak.builder.capture import (
    CandidateSnapshot,
)
from basebreak.builder.context import BuilderContextAllowlist, assemble_builder_context
from basebreak.builder.execution import (
    HostExecutionFallbackError,
    MaterializedSourceVerificationError,
    UnmaterializedWorkspaceError,
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
    MalformedReproductionInputError,
    PatchApplicationError,
    SandboxFreshnessError,
    TreeDigestMismatchError,
    TrustedInputBindingError,
    build_patch_transport_scripts,
)
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
from basebreak.domain.verdict import EvidenceProvenance
from basebreak.evidence.artifact import compute_bytes_digest
from basebreak.security.protected_surfaces import (
    ProtectedSurfaceManifest,
    ProtectedSurfaceViolation,
)

BASE_COMMIT_ID: str = "0123456789abcdef0123456789abcdef01234567"
DEFAULT_WORKSPACE: str = "/workspace/reproduction"
VALID_TREE_SHA: str = "11223344556677889900aabbccddeeff11223344"
SAMPLE_PATCH_TEXT: str = (
    "--- a/src/pool.py\n"
    "+++ b/src/pool.py\n"
    "@@ -1 +1,2 @@\n"
    " class ConnectionPool:\n"
    "+    def close(self): pass\n"
)


# --- Test Fixtures & Helpers ---


def _create_source_identity(
    locator: str = "https://github.com/example/repo.git",
    commit_id: str = BASE_COMMIT_ID,
    subpath: str | None = None,
) -> SourceIdentity:
    return SourceIdentity(
        locator=locator,
        revision=CommitRevision(commit_id),
        subpath=subpath,
    )


def _create_frozen_contract() -> FrozenContract:
    norm_task = ingest_task(
        "Task: Fix connection pool leak by closing idle handles.\n"
        "Requirements:\n"
        "1. Close idle handles when pool is drained."
    )
    fact = DeterministicClassificationFact(
        inferred_class=ChangeClass.BUG_FIX,
        certainty=CertaintyLevel.CONFIDENT,
        confidence=0.95,
        alternative_classes=(),
        rationale="Fix connection leak defect",
        evidence_citations=("Fix connection pool leak",),
        matched_signals=("fix", "leak"),
    )
    semantics = ChangeSemanticsClassification(
        task_digest=norm_task.task_digest,
        change_class=ChangeClass.BUG_FIX,
        certainty=CertaintyLevel.CONFIDENT,
        confidence=0.95,
        alternative_classes=(),
        rationale="Fix connection leak defect",
        evidence_citations=("Fix connection pool leak",),
        deterministic_facts=fact,
    )
    cit = "Close idle handles when pool is drained."
    start = norm_task.normalized_text.index(cit)
    end = start + len(cit)

    req = ProposedRequirement(
        statement="Close idle handles when pool is drained",
        citation=cit,
        citation_start=start,
        citation_end=end,
        rationale="Prevents leaking socket descriptors.",
    )
    bundle = ReviewBundle(task=norm_task, semantics=semantics, requirements=(req,))
    session = ReviewSession(bundle)
    review_result = session.approve(reviewer_note="Approved for freeze")
    return freeze_review_result(review_result)


def _create_envelope(
    contract: FrozenContract | None = None,
    source_id: SourceIdentity | None = None,
    allowed_files: Sequence[str] = ("src/pool.py",),
) -> Any:
    ct = contract or _create_frozen_contract()
    src = source_id or _create_source_identity()
    repo_files = {
        "src/pool.py": "class ConnectionPool:\n    pass\n",
    }
    allowlist = BuilderContextAllowlist.from_paths(list(allowed_files))
    return assemble_builder_context(
        frozen_contract=ct,
        source_identity=src,
        allowlist=allowlist,
        repository_files=repo_files,
    )


def _create_snapshot(
    envelope: Any | None = None,
    patch_text: str = SAMPLE_PATCH_TEXT,
    candidate_tree_digest: str = VALID_TREE_SHA,
    builder_sandbox_id: str = "sbx-builder-0001",
    files_added: tuple[str, ...] = (),
    files_modified: tuple[str, ...] = ("src/pool.py",),
    files_deleted: tuple[str, ...] = (),
    source_identity: SourceIdentity | None = None,
    frozen_contract_digest: str | None = None,
    context_digest: str | None = None,
    is_authoritative: bool = False,
) -> CandidateSnapshot:
    env = envelope or _create_envelope()
    patch_digest = compute_bytes_digest(patch_text.encode("utf-8")).value

    src_id = source_identity or env.source_identity
    fc_digest = frozen_contract_digest or env.frozen_contract.contract_digest
    ctx_digest = context_digest or env.context_digest

    return CandidateSnapshot(
        candidate_id="cand-test-0001",
        source_identity=src_id,
        candidate_tree_digest=candidate_tree_digest,
        patch_digest=patch_digest,
        patch_text=patch_text,
        files_added=files_added,
        files_modified=files_modified,
        files_deleted=files_deleted,
        builder_authored_tests=(),
        frozen_contract_digest=fc_digest,
        context_digest=ctx_digest,
        sandbox_identity=SandboxIdentity(builder_sandbox_id),
        is_authoritative=is_authoritative,
    )


# --- Mocks ---


@dataclass
class MockSandboxHandle:
    sandbox_identity: SandboxIdentity
    image: str = "tag:astral/uv:python3.11-alpine"
    disposable: bool = True
    is_torn_down: bool = False


@dataclass(frozen=True, slots=True)
class MockMaterializedSourceRecord:
    source_identity: SourceIdentity
    resolved_commit_sha: str
    workspace_path: str
    sandbox_identity: SandboxIdentity
    is_verified: bool = True


class MockSourceMaterializer:
    def __init__(
        self,
        *,
        should_fail: bool = False,
        mismatched_commit: str | None = None,
    ) -> None:
        self.should_fail = should_fail
        self.mismatched_commit = mismatched_commit
        self.materialize_calls: list[tuple[SourceIdentity, Any, str]] = []

    def materialize_repository(
        self,
        source_identity: SourceIdentity,
        sandbox: Any,
        workspace_path: str,
        timeout_seconds: int = 120,
        disposable: bool = True,
        **kwargs: Any,
    ) -> MockMaterializedSourceRecord:
        if self.should_fail:
            raise RuntimeError("Simulated repository materialization failure")
        sbx_id = getattr(sandbox, "sandbox_identity", SandboxIdentity("sbx-default"))
        commit_sha = self.mismatched_commit or source_identity.resolved_commit_id
        self.materialize_calls.append((source_identity, sandbox, workspace_path))
        return MockMaterializedSourceRecord(
            source_identity=source_identity,
            resolved_commit_sha=commit_sha,
            workspace_path=workspace_path,
            sandbox_identity=sbx_id,
            is_verified=True,
        )


class MockReproductionSandboxAdapter:
    """Mock sandbox adapter for candidate reproduction testing."""

    def __init__(
        self,
        *,
        git_tree_output: str = VALID_TREE_SHA,
        git_name_status_output: str = "M\tsrc/pool.py\n",
        fail_apply: bool = False,
        fail_add: bool = False,
        fail_write_tree: bool = False,
        forced_sandbox_id: str | None = None,
    ) -> None:
        self.git_tree_output = git_tree_output
        self.git_name_status_output = git_name_status_output
        self.fail_apply = fail_apply
        self.fail_add = fail_add
        self.fail_write_tree = fail_write_tree
        self.forced_sandbox_id = forced_sandbox_id
        self.created_handles: list[MockSandboxHandle] = []
        self.executed_commands: list[tuple[MockSandboxHandle, str, str | None]] = []
        self.torn_down_handles: list[MockSandboxHandle] = []

    def create_sandbox(self, image: str, disposable: bool = True) -> MockSandboxHandle:
        sbx_id = self.forced_sandbox_id or f"sbx-repro-{len(self.created_handles) + 1:04d}"
        handle = MockSandboxHandle(
            sandbox_identity=SandboxIdentity(sbx_id),
            image=image,
            disposable=disposable,
        )
        self.created_handles.append(handle)
        return handle

    def execute_command(
        self,
        sandbox: MockSandboxHandle,
        command: str,
        *,
        working_dir: str | None = None,
        timeout_seconds: int | None = None,
    ) -> Any:
        self.executed_commands.append((sandbox, command, working_dir))

        if "git apply" in command:
            if self.fail_apply:
                return SimpleNamespace(exit_code=1, stdout="", stderr="error: patch does not apply")
            return SimpleNamespace(exit_code=0, stdout="", stderr="")

        if "git add -A" in command:
            if self.fail_add:
                return SimpleNamespace(exit_code=1, stdout="", stderr="fatal: git add failed")
            return SimpleNamespace(exit_code=0, stdout="", stderr="")

        if "git write-tree" in command:
            if self.fail_write_tree:
                return SimpleNamespace(
                    exit_code=1, stdout="", stderr="fatal: git write-tree failed"
                )
            return SimpleNamespace(exit_code=0, stdout=f"{self.git_tree_output}\n", stderr="")

        if "git diff --name-status" in command:
            return SimpleNamespace(exit_code=0, stdout=self.git_name_status_output, stderr="")

        # Default success for file transport scripts and cleanup
        return SimpleNamespace(exit_code=0, stdout="", stderr="")

    def teardown_sandbox(self, sandbox: MockSandboxHandle) -> None:
        sandbox.is_torn_down = True
        self.torn_down_handles.append(sandbox)


# --- Unit Tests ---


def test_fresh_sandbox_distinct_from_builder_sandbox() -> None:
    """1. Fresh sandbox is created and mechanically distinct from Builder sandbox."""
    envelope = _create_envelope()
    snapshot = _create_snapshot(envelope, builder_sandbox_id="sbx-builder-orig")

    adapter = MockReproductionSandboxAdapter()
    materializer = MockSourceMaterializer()
    executor = CandidateReproductionExecutor(adapter, materializer)

    result = executor.reproduce(snapshot=snapshot, envelope=envelope)

    assert result.is_reproduced is True
    assert result.sandbox_identity != snapshot.sandbox_identity
    assert result.sandbox_identity.sandbox_id != "sbx-builder-orig"
    assert len(adapter.created_handles) == 1
    assert adapter.created_handles[0].sandbox_identity == result.sandbox_identity


def test_builder_sandbox_reuse_rejected() -> None:
    """2. Builder sandbox reuse is rejected and fails closed."""
    envelope = _create_envelope()
    snapshot = _create_snapshot(envelope, builder_sandbox_id="sbx-shared-id")

    # Adapter forces identical sandbox ID to Builder's sandbox
    adapter = MockReproductionSandboxAdapter(forced_sandbox_id="sbx-shared-id")
    materializer = MockSourceMaterializer()
    executor = CandidateReproductionExecutor(adapter, materializer)

    with pytest.raises(SandboxFreshnessError) as exc_info:
        executor.reproduce(snapshot=snapshot, envelope=envelope)

    assert "identical to Builder sandbox identity" in str(exc_info.value)
    # Ensure handle was created and then torn down
    assert len(adapter.torn_down_handles) == 1


def test_caller_supplied_sandbox_rejected() -> None:
    """2b. Caller attempting to supply pre-existing sandbox_handle fails closed."""
    envelope = _create_envelope()
    snapshot = _create_snapshot(envelope)

    adapter = MockReproductionSandboxAdapter()
    materializer = MockSourceMaterializer()
    executor = CandidateReproductionExecutor(adapter, materializer)

    with pytest.raises(SandboxFreshnessError) as exc_info:
        executor.reproduce(
            snapshot=snapshot,
            envelope=envelope,
            sandbox_handle=MockSandboxHandle(SandboxIdentity("sbx-caller")),
        )

    assert "Caller-supplied sandbox is strictly prohibited" in str(exc_info.value)


def test_source_identity_locator_mismatch_fails_closed() -> None:
    """3a. Snapshot with mismatched repository locator fails closed."""
    envelope = _create_envelope()
    bad_source = _create_source_identity(locator="https://github.com/attacker/repo.git")
    snapshot = _create_snapshot(envelope, source_identity=bad_source)

    adapter = MockReproductionSandboxAdapter()
    materializer = MockSourceMaterializer()
    executor = CandidateReproductionExecutor(adapter, materializer)

    with pytest.raises(TrustedInputBindingError) as exc_info:
        executor.reproduce(snapshot=snapshot, envelope=envelope)

    assert "does not match authoritative envelope source identity" in str(exc_info.value)
    assert len(adapter.created_handles) == 0  # Pre-sandbox check


def test_source_identity_commit_mismatch_fails_closed() -> None:
    """3b. Snapshot with mismatched commit ID fails closed."""
    envelope = _create_envelope()
    bad_source = _create_source_identity(commit_id="9999999999abcdef0123456789abcdef01234567")
    snapshot = _create_snapshot(envelope, source_identity=bad_source)

    adapter = MockReproductionSandboxAdapter()
    materializer = MockSourceMaterializer()
    executor = CandidateReproductionExecutor(adapter, materializer)

    with pytest.raises(TrustedInputBindingError) as exc_info:
        executor.reproduce(snapshot=snapshot, envelope=envelope)

    assert "does not match authoritative envelope source identity" in str(exc_info.value)


def test_materialized_source_commit_mismatch_fails_closed() -> None:
    """3c. Materializer resolving different commit SHA inside sandbox fails closed."""
    envelope = _create_envelope()
    snapshot = _create_snapshot(envelope)

    adapter = MockReproductionSandboxAdapter()
    materializer = MockSourceMaterializer(
        mismatched_commit="ffffffffffffffffffffffffffffffffffffffff"
    )
    executor = CandidateReproductionExecutor(adapter, materializer)

    with pytest.raises(MaterializedSourceVerificationError):
        executor.reproduce(snapshot=snapshot, envelope=envelope)

    assert len(adapter.torn_down_handles) == 1


def test_frozen_contract_digest_mismatch_fails_closed() -> None:
    """4a. Snapshot with tampered frozen_contract_digest fails closed."""
    envelope = _create_envelope()
    bad_contract_digest = "0" * 64
    snapshot = _create_snapshot(envelope, frozen_contract_digest=bad_contract_digest)

    adapter = MockReproductionSandboxAdapter()
    materializer = MockSourceMaterializer()
    executor = CandidateReproductionExecutor(adapter, materializer)

    with pytest.raises(TrustedInputBindingError) as exc_info:
        executor.reproduce(snapshot=snapshot, envelope=envelope)

    assert "frozen contract digest" in str(exc_info.value)
    assert len(adapter.created_handles) == 0


def test_context_digest_mismatch_fails_closed() -> None:
    """4b. Snapshot with tampered context_digest fails closed."""
    envelope = _create_envelope()
    bad_ctx_digest = "f" * 64
    snapshot = _create_snapshot(envelope, context_digest=bad_ctx_digest)

    adapter = MockReproductionSandboxAdapter()
    materializer = MockSourceMaterializer()
    executor = CandidateReproductionExecutor(adapter, materializer)

    with pytest.raises(TrustedInputBindingError) as exc_info:
        executor.reproduce(snapshot=snapshot, envelope=envelope)

    assert "context digest" in str(exc_info.value)
    assert len(adapter.created_handles) == 0


def test_patch_digest_tampering_fails_closed() -> None:
    """5. Tampered patch text without matching patch_digest fails closed."""
    envelope = _create_envelope()

    # Create snapshot directly with tampered patch_text but old patch_digest
    # CandidateSnapshot.__post_init__ already validates this, but let's test reproduction
    with pytest.raises(Exception):
        CandidateSnapshot(
            candidate_id="cand-tampered",
            source_identity=envelope.source_identity,
            candidate_tree_digest=VALID_TREE_SHA,
            patch_digest="a" * 64,  # Mismatched digest
            patch_text="--- a/file.py\n+++ b/file.py\n@@ -0,0 +1 @@\n+# tampered\n",
            files_added=(),
            files_modified=(),
            files_deleted=(),
            builder_authored_tests=(),
            frozen_contract_digest=envelope.frozen_contract.contract_digest,
            context_digest=envelope.context_digest,
        )


def test_caller_cannot_substitute_builder_proposal() -> None:
    """6. Caller cannot substitute BuilderProposal for CandidateSnapshot."""
    envelope = _create_envelope()
    proposal = BuilderProposal(
        plan=BuilderPlan(summary="Plan", steps=("Step 1",)),
        proposed_file_actions=(
            ProposedFileAction(
                path="src/pool.py",
                action=FileActionType.MODIFY,
                content="class ConnectionPool: pass\n",
                rationale="Fix",
            ),
        ),
        proposed_commands=(ProposedCommand(command="pytest", rationale="Test"),),
        raw_response='{"mock": "response"}',
    )

    adapter = MockReproductionSandboxAdapter()
    materializer = MockSourceMaterializer()
    executor = CandidateReproductionExecutor(adapter, materializer)

    # 1. As snapshot argument
    with pytest.raises(MalformedReproductionInputError) as exc_info:
        executor.reproduce(snapshot=proposal, envelope=envelope)  # type: ignore[arg-type]
    assert "Caller cannot substitute BuilderProposal" in str(exc_info.value)

    # 2. As proposal keyword argument
    snapshot = _create_snapshot(envelope)
    with pytest.raises(MalformedReproductionInputError) as exc_info2:
        executor.reproduce(snapshot=snapshot, envelope=envelope, proposal=proposal)
    assert "Caller cannot substitute BuilderProposal" in str(exc_info2.value)


def test_protected_surface_patch_fails_before_acceptance() -> None:
    """7. Patch mutating protected surfaces fails closed via diff validation."""
    envelope = _create_envelope()

    # Patch modifying AGENTS.md
    protected_patch = (
        "--- a/AGENTS.md\n"
        "+++ b/AGENTS.md\n"
        "@@ -1,2 +1,3 @@\n"
        " # Constitution\n"
        "+# Malicious modification\n"
    )
    patch_digest = compute_bytes_digest(protected_patch.encode("utf-8")).value

    snapshot = CandidateSnapshot(
        candidate_id="cand-malicious",
        source_identity=envelope.source_identity,
        candidate_tree_digest=VALID_TREE_SHA,
        patch_digest=patch_digest,
        patch_text=protected_patch,
        files_added=(),
        files_modified=("AGENTS.md",),
        files_deleted=(),
        builder_authored_tests=(),
        frozen_contract_digest=envelope.frozen_contract.contract_digest,
        context_digest=envelope.context_digest,
    )

    adapter = MockReproductionSandboxAdapter()
    materializer = MockSourceMaterializer()
    executor = CandidateReproductionExecutor(adapter, materializer)

    with pytest.raises(ProtectedSurfaceViolation) as exc_info:
        executor.reproduce(snapshot=snapshot, envelope=envelope)

    assert "AGENTS.md" in str(exc_info.value)
    # Ensure sandbox was NOT created since pre-validation caught it
    assert len(adapter.created_handles) == 0


def test_patch_apply_failure_fails_closed() -> None:
    """8. Failure during git apply fails closed and tears down sandbox."""
    envelope = _create_envelope()
    snapshot = _create_snapshot(envelope)

    adapter = MockReproductionSandboxAdapter(fail_apply=True)
    materializer = MockSourceMaterializer()
    executor = CandidateReproductionExecutor(adapter, materializer)

    with pytest.raises(PatchApplicationError) as exc_info:
        executor.reproduce(snapshot=snapshot, envelope=envelope)

    assert "git apply failed" in str(exc_info.value)
    assert len(adapter.torn_down_handles) == 1


def test_git_add_failure_fails_closed() -> None:
    """8b. Failure during git add -A fails closed and tears down sandbox."""
    envelope = _create_envelope()
    snapshot = _create_snapshot(envelope)

    adapter = MockReproductionSandboxAdapter(fail_add=True)
    materializer = MockSourceMaterializer()
    executor = CandidateReproductionExecutor(adapter, materializer)

    with pytest.raises(PatchApplicationError) as exc_info:
        executor.reproduce(snapshot=snapshot, envelope=envelope)

    assert "git add -A failed" in str(exc_info.value)
    assert len(adapter.torn_down_handles) == 1


def test_reproduced_tree_mismatch_fails_closed() -> None:
    """9. Tree hash mismatch between reproduced state and snapshot fails closed."""
    envelope = _create_envelope()
    snapshot = _create_snapshot(envelope, candidate_tree_digest=VALID_TREE_SHA)

    different_tree_sha = "99887766554433221100aabbccddeeff99887766"
    adapter = MockReproductionSandboxAdapter(git_tree_output=different_tree_sha)
    materializer = MockSourceMaterializer()
    executor = CandidateReproductionExecutor(adapter, materializer)

    with pytest.raises(TreeDigestMismatchError) as exc_info:
        executor.reproduce(snapshot=snapshot, envelope=envelope)

    assert "does not match captured candidate tree digest" in str(exc_info.value)
    assert len(adapter.torn_down_handles) == 1


def test_exact_trusted_base_plus_patch_reproduces_successfully() -> None:
    """10. Exact trusted base + exact patch reproduces exact candidate tree successfully."""
    envelope = _create_envelope()
    snapshot = _create_snapshot(envelope, candidate_tree_digest=VALID_TREE_SHA)

    adapter = MockReproductionSandboxAdapter(
        git_tree_output=VALID_TREE_SHA,
        git_name_status_output="M\tsrc/pool.py\n",
    )
    materializer = MockSourceMaterializer()
    executor = CandidateReproductionExecutor(adapter, materializer)

    result = executor.reproduce(
        snapshot=snapshot,
        envelope=envelope,
        provenance=EvidenceProvenance.LOCAL_EXECUTION,
    )

    assert isinstance(result, CandidateReproductionResult)
    assert result.is_reproduced is True
    assert result.reproduced_tree_digest == VALID_TREE_SHA
    assert result.reproduced_patch_digest == snapshot.patch_digest
    assert result.files_modified == ("src/pool.py",)
    assert result.is_authoritative is False
    assert result.is_causally_verified is False
    assert result.grants_pass is False
    # Sandbox was torn down on completion
    assert len(adapter.torn_down_handles) == 1


def test_failure_teardown_reproduction_sandbox_on_materialization() -> None:
    """11a. Failure during materialization tears down reproduction sandbox."""
    envelope = _create_envelope()
    snapshot = _create_snapshot(envelope)

    adapter = MockReproductionSandboxAdapter()
    materializer = MockSourceMaterializer(should_fail=True)
    executor = CandidateReproductionExecutor(adapter, materializer)

    with pytest.raises(MaterializedSourceVerificationError):
        executor.reproduce(snapshot=snapshot, envelope=envelope)

    assert len(adapter.created_handles) == 1
    assert len(adapter.torn_down_handles) == 1
    assert adapter.created_handles[0].is_torn_down is True


def test_failure_teardown_reproduction_sandbox_on_write_tree_failure() -> None:
    """11b. Failure during git write-tree command tears down reproduction sandbox."""
    envelope = _create_envelope()
    snapshot = _create_snapshot(envelope)

    adapter = MockReproductionSandboxAdapter(fail_write_tree=True)
    materializer = MockSourceMaterializer()
    executor = CandidateReproductionExecutor(adapter, materializer)

    with pytest.raises(PatchApplicationError):
        executor.reproduce(snapshot=snapshot, envelope=envelope)

    assert len(adapter.created_handles) == 1
    assert len(adapter.torn_down_handles) == 1


def test_reproduction_result_authority_invariants() -> None:
    """12. CandidateReproductionResult strictly enforces non-authoritative invariants."""
    envelope = _create_envelope()
    snapshot = _create_snapshot(envelope)

    # 1. Setting is_authoritative=True fails
    with pytest.raises(ValueError, match="is_authoritative must be strictly False"):
        CandidateReproductionResult(
            candidate_snapshot=snapshot,
            reproduced_tree_digest=VALID_TREE_SHA,
            reproduced_patch_digest=snapshot.patch_digest,
            sandbox_identity=SandboxIdentity("sbx-other"),
            source_identity=envelope.source_identity,
            is_authoritative=True,  # Forbidden!
        )

    # 2. Setting is_causally_verified=True fails
    with pytest.raises(ValueError, match="is_causally_verified must be strictly False"):
        CandidateReproductionResult(
            candidate_snapshot=snapshot,
            reproduced_tree_digest=VALID_TREE_SHA,
            reproduced_patch_digest=snapshot.patch_digest,
            sandbox_identity=SandboxIdentity("sbx-other"),
            source_identity=envelope.source_identity,
            is_causally_verified=True,  # Forbidden!
        )

    # 3. Setting grants_pass=True fails
    with pytest.raises(ValueError, match="grants_pass must be strictly False"):
        CandidateReproductionResult(
            candidate_snapshot=snapshot,
            reproduced_tree_digest=VALID_TREE_SHA,
            reproduced_patch_digest=snapshot.patch_digest,
            sandbox_identity=SandboxIdentity("sbx-other"),
            source_identity=envelope.source_identity,
            grants_pass=True,  # Forbidden!
        )

    # 4. Setting is_reproduced=False fails
    with pytest.raises(ValueError, match="is_reproduced must be strictly True"):
        CandidateReproductionResult(
            candidate_snapshot=snapshot,
            reproduced_tree_digest=VALID_TREE_SHA,
            reproduced_patch_digest=snapshot.patch_digest,
            sandbox_identity=SandboxIdentity("sbx-other"),
            source_identity=envelope.source_identity,
            is_reproduced=False,  # Forbidden!
        )


def test_config_non_downgradable_policy() -> None:
    """13. Canonical P-04 policy is non-downgradable across config."""
    with pytest.raises(
        CandidateReproductionConfigError,
        match="enforce_protected_surfaces cannot be disabled",
    ):
        CandidateReproductionConfig(enforce_protected_surfaces=False)

    with pytest.raises(
        CandidateReproductionConfigError,
        match="Caller cannot override protected_manifest",
    ):
        CandidateReproductionConfig(
            protected_manifest=ProtectedSurfaceManifest(
                exact_files=frozenset({"dummy"}),
                directory_prefixes=frozenset(),
            )
        )


def test_host_execution_fallback_rejected() -> None:
    """14. Missing sandbox_adapter raises HostExecutionFallbackError."""
    materializer = MockSourceMaterializer()
    with pytest.raises(
        HostExecutionFallbackError,
        match="host execution fallback is strictly prohibited",
    ):
        CandidateReproductionExecutor(sandbox_adapter=None, source_materializer=materializer)


def test_missing_source_materializer_rejected() -> None:
    """15. Missing source_materializer raises UnmaterializedWorkspaceError."""
    adapter = MockReproductionSandboxAdapter()
    with pytest.raises(UnmaterializedWorkspaceError, match="source_materializer is required"):
        CandidateReproductionExecutor(sandbox_adapter=adapter, source_materializer=None)


def test_caller_supplied_materialized_source_rejected() -> None:
    """16. Passing materialized_source keyword argument fails closed."""
    envelope = _create_envelope()
    snapshot = _create_snapshot(envelope)

    adapter = MockReproductionSandboxAdapter()
    materializer = MockSourceMaterializer()
    executor = CandidateReproductionExecutor(adapter, materializer)

    with pytest.raises(
        MaterializedSourceVerificationError,
        match="Caller-supplied materialized_source is strictly forbidden",
    ):
        executor.reproduce(
            snapshot=snapshot,
            envelope=envelope,
            materialized_source=MockMaterializedSourceRecord(
                source_identity=envelope.source_identity,
                resolved_commit_sha=BASE_COMMIT_ID,
                workspace_path=DEFAULT_WORKSPACE,
                sandbox_identity=SandboxIdentity("sbx-caller"),
            ),
        )


def test_no_change_candidate_reproduction() -> None:
    """17. No-change candidate reproduces cleanly without patch application."""
    envelope = _create_envelope()
    empty_patch = ""
    patch_digest = compute_bytes_digest(b"").value

    snapshot = CandidateSnapshot(
        candidate_id="cand-noop",
        source_identity=envelope.source_identity,
        candidate_tree_digest=VALID_TREE_SHA,
        patch_digest=patch_digest,
        patch_text=empty_patch,
        files_added=(),
        files_modified=(),
        files_deleted=(),
        builder_authored_tests=(),
        frozen_contract_digest=envelope.frozen_contract.contract_digest,
        context_digest=envelope.context_digest,
        sandbox_identity=SandboxIdentity("sbx-builder-orig"),
    )

    adapter = MockReproductionSandboxAdapter(
        git_tree_output=VALID_TREE_SHA,
        git_name_status_output="",
    )
    materializer = MockSourceMaterializer()
    executor = CandidateReproductionExecutor(adapter, materializer)

    result = executor.reproduce(snapshot=snapshot, envelope=envelope)

    assert result.is_reproduced is True
    assert result.files_added == ()
    assert result.files_modified == ()
    assert result.files_deleted == ()

    # Verify no git apply command was run
    applied_commands = [cmd for _, cmd, _ in adapter.executed_commands if "git apply" in cmd]
    assert len(applied_commands) == 0


def test_large_patch_chunking_transport() -> None:
    """18. Large patches exceeding 8000 base64 chars are safely chunked."""
    # Create large patch (> 10,000 chars)
    large_patch = SAMPLE_PATCH_TEXT + ("# padding line for size\n" * 500)
    scripts = build_patch_transport_scripts(large_patch, "/tmp/test.patch")

    assert len(scripts) > 1
    assert "mkdir -p" in scripts[0]
    assert ": > /tmp/test.patch" in scripts[0]
    for middle_script in scripts[1:-1]:
        assert "base64 -d >> /tmp/test.patch" in middle_script
    assert "BASEBREAK_PATCH_TRANSPORT_ERROR" in scripts[-1]


def test_serialization_roundtrip() -> None:
    """19. CandidateReproductionResult roundtrips to_dict / from_dict perfectly."""
    envelope = _create_envelope()
    snapshot = _create_snapshot(envelope)

    result = CandidateReproductionResult(
        candidate_snapshot=snapshot,
        reproduced_tree_digest=VALID_TREE_SHA,
        reproduced_patch_digest=snapshot.patch_digest,
        sandbox_identity=SandboxIdentity("sbx-repro-0001"),
        source_identity=envelope.source_identity,
        duration_seconds=1.234,
        files_modified=("src/pool.py",),
        provenance=EvidenceProvenance.LOCAL_EXECUTION,
    )

    data = result.to_dict()
    assert data["is_authoritative"] is False
    assert data["is_causally_verified"] is False
    assert data["grants_pass"] is False
    assert data["is_reproduced"] is True
    assert data["sandbox_id"] == "sbx-repro-0001"

    restored = CandidateReproductionResult.from_dict(data)
    assert restored.reproduced_tree_digest == result.reproduced_tree_digest
    assert restored.reproduced_patch_digest == result.reproduced_patch_digest
    assert restored.sandbox_identity == result.sandbox_identity
    assert restored.source_identity == result.source_identity
    assert restored.is_authoritative is False
    assert restored.is_causally_verified is False
    assert restored.grants_pass is False


# --- Blocker 2 & 3 QA Regression Tests ---


def test_caller_cannot_forge_live_nebius_provenance() -> None:
    """Blocker 3: Caller cannot assert or forge LIVE_NEBIUS in reproduction."""
    from basebreak.evidence.provenance import ProvenanceLaunderingError

    envelope = _create_envelope()
    snapshot = _create_snapshot(envelope)
    adapter = MockReproductionSandboxAdapter()
    materializer = MockSourceMaterializer()
    executor = CandidateReproductionExecutor(
        sandbox_adapter=adapter,
        source_materializer=materializer,
    )

    with pytest.raises(
        ProvenanceLaunderingError, match="Caller cannot assert or request 'LIVE_NEBIUS'"
    ):
        executor.reproduce(
            snapshot=snapshot,
            envelope=envelope,
            provenance=EvidenceProvenance.LIVE_NEBIUS,
        )


def test_caller_cannot_pass_recorded_live_provenance() -> None:
    """Blocker 3: RECORDED_LIVE cannot masquerade as fresh live reproduction."""
    from basebreak.evidence.provenance import ProvenanceLaunderingError

    envelope = _create_envelope()
    snapshot = _create_snapshot(envelope)
    adapter = MockReproductionSandboxAdapter()
    materializer = MockSourceMaterializer()
    executor = CandidateReproductionExecutor(
        sandbox_adapter=adapter,
        source_materializer=materializer,
    )

    with pytest.raises(
        ProvenanceLaunderingError, match="Caller cannot assert or request 'RECORDED_LIVE'"
    ):
        executor.reproduce(
            snapshot=snapshot,
            envelope=envelope,
            provenance=EvidenceProvenance.RECORDED_LIVE,
        )


def test_local_mock_reproduction_derives_local_execution() -> None:
    """Blocker 3: Local/mock reproduction mechanically derives LOCAL_EXECUTION."""
    envelope = _create_envelope()
    snapshot = _create_snapshot(envelope)
    adapter = MockReproductionSandboxAdapter()
    materializer = MockSourceMaterializer()
    executor = CandidateReproductionExecutor(
        sandbox_adapter=adapter,
        source_materializer=materializer,
    )

    result = executor.reproduce(snapshot=snapshot, envelope=envelope)
    assert result.provenance == EvidenceProvenance.LOCAL_EXECUTION


def test_cannot_derive_live_nebius_from_non_live_snapshot() -> None:
    """Blocker 3: LIVE_NEBIUS reproduction cannot be derived from a non-live snapshot."""
    from basebreak.evidence.provenance import ProvenanceLaunderingError

    envelope = _create_envelope()
    # snapshot has LOCAL_EXECUTION provenance
    snapshot = _create_snapshot(envelope)
    assert snapshot.provenance == EvidenceProvenance.LOCAL_EXECUTION

    # Adapter claims LIVE_NEBIUS execution
    adapter = MockReproductionSandboxAdapter()
    adapter.execution_provenance = EvidenceProvenance.LIVE_NEBIUS  # type: ignore[attr-defined]

    materializer = MockSourceMaterializer()
    executor = CandidateReproductionExecutor(
        sandbox_adapter=adapter,
        source_materializer=materializer,
    )

    with pytest.raises(
        ProvenanceLaunderingError,
        match="Cannot derive LIVE_NEBIUS reproduction from non-live snapshot",
    ):
        executor.reproduce(snapshot=snapshot, envelope=envelope)


def test_deserialization_cannot_upgrade_provenance_to_live_nebius() -> None:
    """Blocker 3: Deserialization cannot upgrade non-live snapshot to LIVE_NEBIUS."""
    from basebreak.evidence.provenance import ProvenanceLaunderingError

    envelope = _create_envelope()
    snapshot = _create_snapshot(envelope)

    result = CandidateReproductionResult(
        candidate_snapshot=snapshot,
        reproduced_tree_digest=VALID_TREE_SHA,
        reproduced_patch_digest=snapshot.patch_digest,
        sandbox_identity=SandboxIdentity("sbx-repro-0001"),
        source_identity=envelope.source_identity,
        duration_seconds=1.0,
        provenance=EvidenceProvenance.LOCAL_EXECUTION,
    )

    tampered_data = result.to_dict()
    tampered_data["provenance"] = "LIVE_NEBIUS"

    with pytest.raises(
        ProvenanceLaunderingError,
        match="Cannot deserialize CandidateReproductionResult claiming LIVE_NEBIUS",
    ):
        CandidateReproductionResult.from_dict(tampered_data)


def test_reproduction_creates_disposable_sandbox() -> None:
    """Blocker 2: Reproduction sandbox must be created with disposable=True."""
    envelope = _create_envelope()
    snapshot = _create_snapshot(envelope)
    adapter = MockReproductionSandboxAdapter()
    materializer = MockSourceMaterializer()
    executor = CandidateReproductionExecutor(
        sandbox_adapter=adapter,
        source_materializer=materializer,
    )

    executor.reproduce(snapshot=snapshot, envelope=envelope)
    assert len(adapter.created_handles) == 1
    assert adapter.created_handles[0].disposable is True, (
        "Reproduction sandbox must be disposable=True"
    )


def test_materializer_type_error_fails_closed_no_retry() -> None:
    """Blocker 2: Internal materializer TypeError fails closed and is NOT silently retried."""
    envelope = _create_envelope()
    snapshot = _create_snapshot(envelope)
    adapter = MockReproductionSandboxAdapter()

    call_count = 0

    class FailingMaterializer:
        def materialize_repository(self, *args: Any, **kwargs: Any) -> Any:
            nonlocal call_count
            call_count += 1
            raise TypeError("Simulated internal materializer bug")

    executor = CandidateReproductionExecutor(
        sandbox_adapter=adapter,
        source_materializer=FailingMaterializer(),
    )

    with pytest.raises(
        MaterializedSourceVerificationError, match="Simulated internal materializer bug"
    ):
        executor.reproduce(snapshot=snapshot, envelope=envelope)

    assert call_count == 1, f"Materializer must be called exactly once, called {call_count} times"


def test_bundled_execution_mode_succeeds() -> None:
    """Blocker 2: Bundled execution mode executes in single command without checkpoint layers."""
    envelope = _create_envelope()
    snapshot = _create_snapshot(envelope)

    class MockBundledAdapter:
        execution_provenance = EvidenceProvenance.LOCAL_EXECUTION

        def __init__(self) -> None:
            self.created_handles: list[MockSandboxHandle] = []
            self.executed_commands: list[str] = []

        def create_sandbox(self, image: str, disposable: bool = True) -> MockSandboxHandle:
            h = MockSandboxHandle(
                sandbox_identity=SandboxIdentity("sbx-bundled-001"),
                image=image,
                disposable=disposable,
            )
            self.created_handles.append(h)
            return h

        def execute_command(self, sandbox: Any, command: str, **kwargs: Any) -> Any:
            self.executed_commands.append(command)
            stdout = (
                f"BASEBREAK_REPRO_TREE={VALID_TREE_SHA}\n"
                "BASEBREAK_REPRO_DIFF_START\n"
                "M\tsrc/pool.py\n"
                "BASEBREAK_REPRO_DIFF_END\n"
            )
            return SimpleNamespace(exit_code=0, stdout=stdout, stderr="")

        def teardown_sandbox(self, sandbox: Any) -> None:
            pass

    adapter = MockBundledAdapter()
    materializer = MockSourceMaterializer()
    config = CandidateReproductionConfig(bundled_execution=True)
    executor = CandidateReproductionExecutor(
        sandbox_adapter=adapter,
        source_materializer=materializer,
        config=config,
    )

    result = executor.reproduce(snapshot=snapshot, envelope=envelope)
    assert result.reproduced_tree_digest == VALID_TREE_SHA
    assert result.is_reproduced is True
    assert adapter.created_handles[0].disposable is True
    # In bundled mode, exactly 1 command was executed on the handle after materialization
    assert len(adapter.executed_commands) == 1
    assert "BASEBREAK_REPRO_TREE" in adapter.executed_commands[0]


def test_clean_base_checkpoint_and_bundled_reproduction() -> None:
    """Blocker 2: Reproduction with clean_base_record uses clean checkpoint image
    and bundled disposable execution.
    """
    from types import SimpleNamespace

    from basebreak.builder.execution import CleanBaseCheckpointRecord

    envelope = _create_envelope()
    snapshot = _create_snapshot(envelope)

    clean_base_record = CleanBaseCheckpointRecord(
        source_identity=envelope.source_identity,
        resolved_commit_sha=envelope.source_identity.resolved_commit_id,
        resolved_tree_sha="abcdef1234567890abcdef1234567890abcdef12",
        workspace_path="/workspace/repo",
        sandbox_identity=SandboxIdentity("sbx-clean-base-orig"),
        operation_id="op-clean-base-001",
        checkpoint_image_uuid="img-clean-base-checkpoint-uuid",
        is_verified=True,
    )

    class MockCleanBaseBundledAdapter:
        def __init__(self) -> None:
            self.created_handles: list[MockSandboxHandle] = []
            self.executed_commands: list[str] = []

        def create_sandbox(self, image: str, disposable: bool = True) -> MockSandboxHandle:
            h = MockSandboxHandle(
                sandbox_identity=SandboxIdentity("sbx-repro-bundled-002"),
                image=image,
                disposable=disposable,
            )
            self.created_handles.append(h)
            return h

        def execute_command(self, sandbox: Any, command: str, **kwargs: Any) -> Any:
            self.executed_commands.append(command)
            stdout = (
                f"BASEBREAK_REPRO_TREE={VALID_TREE_SHA}\n"
                "BASEBREAK_REPRO_DIFF_START\n"
                "M\tsrc/pool.py\n"
                "BASEBREAK_REPRO_DIFF_END\n"
            )
            return SimpleNamespace(
                exit_code=0,
                stdout=stdout,
                stderr="",
                result_image_uuid=None,
                operation_id="op-repro-001",
            )

        def teardown_sandbox(self, sandbox: Any) -> None:
            pass

    adapter = MockCleanBaseBundledAdapter()
    materializer = MockSourceMaterializer()
    config = CandidateReproductionConfig(
        bundled_execution=True,
        clean_base_record=clean_base_record,
        sandbox_image=clean_base_record.checkpoint_image_uuid,
        workspace_path=clean_base_record.workspace_path,
    )
    executor = CandidateReproductionExecutor(
        sandbox_adapter=adapter,
        source_materializer=materializer,
        config=config,
    )

    result = executor.reproduce(snapshot=snapshot, envelope=envelope)
    assert result.reproduced_tree_digest == VALID_TREE_SHA
    assert result.is_reproduced is True
    assert adapter.created_handles[0].disposable is True
    assert adapter.created_handles[0].image == "img-clean-base-checkpoint-uuid"
    assert len(adapter.executed_commands) == 1
    assert "BASEBREAK_REPRO_TREE" in adapter.executed_commands[0]
