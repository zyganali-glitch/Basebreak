"""Tests for P-08.02: Verifier execution sandbox and workspace isolation.

Verifies:
1. Fresh verifier sandbox creation with independent recorded identity.
2. Zero Builder workspace inheritance.
3. Rejection of Builder sandbox reuse (BuilderSandboxReuseError).
4. Rejection of missing/empty/whitespace sandbox identity (MissingSandboxIdentityError).
5. Rejection of host execution fallback (HostExecutionFallbackError).
6. Rejection of simulated adapter on LIVE_NEBIUS path (SimulationFallbackError).
7. Fail-closed teardown on error.
8. Zero self-certification (is_authoritative=False, is_causally_verified=False, grants_pass=False).
9. Provider purity (zero adapter imports in verifier sandbox module).
"""

from __future__ import annotations

import ast
import inspect
from dataclasses import dataclass
from typing import Any

import pytest

from basebreak.compiler.freeze import FrozenContract, freeze_review_result
from basebreak.compiler.ingestion import NormalizedTask, ingest_task
from basebreak.compiler.requirements import ProposedRequirement
from basebreak.compiler.review import ReviewBundle, ReviewResult, ReviewSession
from basebreak.compiler.semantics import (
    CertaintyLevel,
    ChangeClass,
    ChangeSemanticsClassification,
    DeterministicClassificationFact,
)
from basebreak.domain.causal import ExecutionWorld
from basebreak.domain.execution import SandboxIdentity
from basebreak.domain.source import CommitRevision, SourceIdentity
from basebreak.domain.verdict import EvidenceProvenance
from basebreak.verifier.context import VerifierContextEnvelope
from basebreak.verifier.sandbox import (
    BuilderSandboxReuseError,
    BuilderWorkspaceInheritanceError,
    HostExecutionFallbackError,
    MissingSandboxIdentityError,
    SimulationFallbackError,
    VerifierMaterializationError,
    VerifierSandboxConfig,
    VerifierSandboxManager,
    VerifierSandboxSession,
    VerifierTreeDigestMismatchError,
)


class MockSandboxAdapter:
    """Mock sandbox adapter for deterministic isolation testing."""

    def __init__(self, sandbox_id: str = "sbx-v-001") -> None:
        self.sandbox_id = sandbox_id
        self.created_count = 0
        self.torn_down_ids: list[str] = []

    def create_sandbox(self, image: str, timeout_seconds: int) -> SandboxIdentity:
        self.created_count += 1
        return SandboxIdentity(sandbox_id=self.sandbox_id)

    def teardown_sandbox(self, sandbox_identity: SandboxIdentity) -> None:
        self.torn_down_ids.append(sandbox_identity.sandbox_id)


class SimulatedSandboxAdapter:
    """Adapter marked as simulated for testing simulation fallback rejection."""

    is_simulation = True

    def create_sandbox(self, image: str, timeout_seconds: int) -> SandboxIdentity:
        return SandboxIdentity(sandbox_id="sbx-sim-001")


@dataclass(frozen=True, slots=True)
class MockMaterializationResult:
    """Deterministic materialization result record for verifier testing."""

    resolved_commit_sha: str
    resolved_tree_sha: str
    workspace_path: str
    sandbox_identity: SandboxIdentity
    source_identity: SourceIdentity | None = None
    is_verified: bool = True


class MockMaterializer:
    """Mock repository materializer providing deterministic runtime facts."""

    def __init__(
        self,
        commit: str = "0123456789abcdef0123456789abcdef01234567",
        tree_digest: str = "0" * 40,
        workspace_path: str = "/verifier_workspace",
        sandbox_id: str = "sbx-verifier-999",
    ) -> None:
        self.commit = commit
        self.tree_digest = tree_digest
        self.workspace_path = workspace_path
        self.sandbox_id = sandbox_id

    def materialize_repository(
        self,
        source_identity: SourceIdentity,
        *,
        sandbox: Any = None,
        workspace_path: str = "/verifier_workspace",
        **kwargs: Any,
    ) -> MockMaterializationResult:
        sbx_id = (
            SandboxIdentity(self.sandbox_id)
            if self.sandbox_id
            else (
                sandbox if isinstance(sandbox, SandboxIdentity) else SandboxIdentity("sbx-unknown")
            )
        )
        return MockMaterializationResult(
            resolved_commit_sha=self.commit,
            resolved_tree_sha=self.tree_digest,
            workspace_path=self.workspace_path,
            sandbox_identity=sbx_id,
            source_identity=source_identity,
            is_verified=True,
        )


@pytest.fixture
def sample_task() -> NormalizedTask:
    raw_text = (
        "Task: Fix memory leak in connection pool.\n"
        "Requirements:\n"
        "1. Close idle connections when pool exceeds threshold."
    )
    return ingest_task(raw_text)


@pytest.fixture
def sample_contract(sample_task: NormalizedTask) -> FrozenContract:
    fact = DeterministicClassificationFact(
        inferred_class=ChangeClass.BUG_FIX,
        certainty=CertaintyLevel.CONFIDENT,
        confidence=0.95,
        alternative_classes=(),
        rationale="Fix memory leak in pool",
        evidence_citations=("Fix memory leak",),
        matched_signals=("fix", "leak"),
    )
    semantics = ChangeSemanticsClassification(
        task_digest=sample_task.task_digest,
        change_class=ChangeClass.BUG_FIX,
        certainty=CertaintyLevel.CONFIDENT,
        confidence=0.95,
        alternative_classes=(),
        rationale="Fix memory leak in pool",
        evidence_citations=("Fix memory leak",),
        deterministic_facts=fact,
    )
    cit1 = "Close idle connections when pool exceeds threshold."
    start1 = sample_task.normalized_text.index(cit1)
    end1 = start1 + len(cit1)

    reqs = [
        ProposedRequirement(
            statement="Close idle connections on threshold",
            citation=cit1,
            citation_start=start1,
            citation_end=end1,
            rationale="Prevent connection leakage",
        )
    ]
    bundle = ReviewBundle(task=sample_task, semantics=semantics, requirements=tuple(reqs))
    session = ReviewSession(bundle)
    review_result: ReviewResult = session.approve(reviewer_note="Approved for freeze")
    return freeze_review_result(review_result)


@pytest.fixture
def sample_source_identity() -> SourceIdentity:
    return SourceIdentity(
        locator="github.com/example/pool-lib",
        revision=CommitRevision("0123456789abcdef0123456789abcdef01234567"),
    )


@pytest.fixture
def sample_envelope(
    sample_contract: FrozenContract,
    sample_source_identity: SourceIdentity,
) -> VerifierContextEnvelope:
    return VerifierContextEnvelope.create(
        frozen_contract=sample_contract,
        source_identity=sample_source_identity,
    )


def test_create_isolated_verifier_sandbox_success(
    sample_envelope: VerifierContextEnvelope,
) -> None:
    """Verifier sandbox is created cleanly in isolation with deterministic materializer (Test F)."""
    adapter = MockSandboxAdapter(sandbox_id="sbx-verifier-999")
    materializer = MockMaterializer(
        commit=sample_envelope.source_identity.resolved_commit_id,
        tree_digest="a" * 40,
        workspace_path="/verifier_workspace",
        sandbox_id="sbx-verifier-999",
    )
    manager = VerifierSandboxManager(known_builder_sandbox_ids=["sbx-builder-001"])

    session = manager.create_isolated_verifier_sandbox(
        context_envelope=sample_envelope,
        world=ExecutionWorld.BASE,
        sandbox_adapter=adapter,
        materializer=materializer,
    )

    assert isinstance(session, VerifierSandboxSession)
    assert session.sandbox_identity.sandbox_id == "sbx-verifier-999"
    assert session.world == ExecutionWorld.BASE
    assert session.workspace_path == "/verifier_workspace"
    assert session.context_digest == sample_envelope.context_digest
    assert session.materialized_commit_id == sample_envelope.source_identity.resolved_commit_id
    assert session.materialized_tree_digest == "a" * 40
    assert not session.is_authoritative
    assert not session.is_causally_verified
    assert not session.grants_pass


def test_materializer_none_fails_closed(
    sample_envelope: VerifierContextEnvelope,
) -> None:
    """Test A: materializer=None fails closed with VerifierMaterializationError and tears down."""
    adapter = MockSandboxAdapter(sandbox_id="sbx-no-mat")
    manager = VerifierSandboxManager()

    with pytest.raises(VerifierMaterializationError, match="Materializer is mandatory"):
        manager.create_isolated_verifier_sandbox(
            context_envelope=sample_envelope,
            world=ExecutionWorld.BASE,
            sandbox_adapter=adapter,
            materializer=None,
        )

    assert "sbx-no-mat" in adapter.torn_down_ids


def test_materializer_missing_tree_digest_fails_closed(
    sample_envelope: VerifierContextEnvelope,
) -> None:
    """Test B: A materializer returning no tree digest fails closed."""
    adapter = MockSandboxAdapter(sandbox_id="sbx-no-tree")
    manager = VerifierSandboxManager()

    def no_tree_materializer(**kwargs: Any) -> Any:
        return {
            "resolved_commit_sha": sample_envelope.source_identity.resolved_commit_id,
            "workspace_path": "/verifier_workspace",
            # tree digest omitted!
        }

    with pytest.raises(VerifierMaterializationError, match="missing required tree digest"):
        manager.create_isolated_verifier_sandbox(
            context_envelope=sample_envelope,
            world=ExecutionWorld.BASE,
            sandbox_adapter=adapter,
            materializer=no_tree_materializer,
        )

    assert "sbx-no-tree" in adapter.torn_down_ids


def test_materializer_wrong_commit_fails_closed(
    sample_envelope: VerifierContextEnvelope,
) -> None:
    """Test C: A materializer returning expected tree string but wrong commit fails closed."""
    adapter = MockSandboxAdapter(sandbox_id="sbx-wrong-commit")
    manager = VerifierSandboxManager()

    wrong_commit = "9" * 40
    materializer = MockMaterializer(
        commit=wrong_commit,
        tree_digest="a" * 40,
        workspace_path="/verifier_workspace",
        sandbox_id="sbx-wrong-commit",
    )

    with pytest.raises(VerifierMaterializationError, match="does not match authoritative"):
        manager.create_isolated_verifier_sandbox(
            context_envelope=sample_envelope,
            world=ExecutionWorld.BASE,
            sandbox_adapter=adapter,
            materializer=materializer,
        )

    assert "sbx-wrong-commit" in adapter.torn_down_ids


def test_materializer_wrong_tree_fails_closed(
    sample_envelope: VerifierContextEnvelope,
) -> None:
    """Test D: A materializer returning correct commit but wrong tree fails closed."""
    adapter = MockSandboxAdapter(sandbox_id="sbx-wrong-tree")
    manager = VerifierSandboxManager()

    materializer = MockMaterializer(
        commit=sample_envelope.source_identity.resolved_commit_id,
        tree_digest="1" * 40,
        workspace_path="/verifier_workspace",
        sandbox_id="sbx-wrong-tree",
    )

    with pytest.raises(VerifierTreeDigestMismatchError, match="does not match expected"):
        manager.create_isolated_verifier_sandbox(
            context_envelope=sample_envelope,
            world=ExecutionWorld.BASE,
            sandbox_adapter=adapter,
            materializer=materializer,
            candidate_tree_digest="2" * 40,
        )

    assert "sbx-wrong-tree" in adapter.torn_down_ids


def test_materializer_wrong_sandbox_or_workspace_fails_closed(
    sample_envelope: VerifierContextEnvelope,
) -> None:
    """Test E: A materializer bound to wrong sandbox or workspace fails closed."""
    adapter = MockSandboxAdapter(sandbox_id="sbx-ver-123")
    manager = VerifierSandboxManager()

    # Wrong sandbox ID
    wrong_sbx_materializer = MockMaterializer(
        commit=sample_envelope.source_identity.resolved_commit_id,
        tree_digest="a" * 40,
        workspace_path="/verifier_workspace",
        sandbox_id="sbx-DIFFERENT-456",
    )
    with pytest.raises(VerifierMaterializationError, match="does not match newly created"):
        manager.create_isolated_verifier_sandbox(
            context_envelope=sample_envelope,
            world=ExecutionWorld.BASE,
            sandbox_adapter=adapter,
            materializer=wrong_sbx_materializer,
        )

    # Wrong workspace path
    wrong_ws_materializer = MockMaterializer(
        commit=sample_envelope.source_identity.resolved_commit_id,
        tree_digest="a" * 40,
        workspace_path="/wrong_workspace",
        sandbox_id="sbx-ver-123",
    )
    with pytest.raises(
        VerifierMaterializationError,
        match="does not match isolated verifier workspace",
    ):
        manager.create_isolated_verifier_sandbox(
            context_envelope=sample_envelope,
            world=ExecutionWorld.BASE,
            sandbox_adapter=adapter,
            materializer=wrong_ws_materializer,
        )

    # Colliding builder workspace path
    colliding_ws_materializer = MockMaterializer(
        commit=sample_envelope.source_identity.resolved_commit_id,
        tree_digest="a" * 40,
        workspace_path="/builder_workspace",
        sandbox_id="sbx-ver-123",
    )
    with pytest.raises(BuilderWorkspaceInheritanceError, match="collides with"):
        manager.create_isolated_verifier_sandbox(
            context_envelope=sample_envelope,
            world=ExecutionWorld.BASE,
            sandbox_adapter=adapter,
            materializer=colliding_ws_materializer,
        )


def test_reject_builder_sandbox_reuse(
    sample_envelope: VerifierContextEnvelope,
) -> None:
    """Reusing Builder sandbox ID is rejected with BuilderSandboxReuseError and torn down."""
    adapter = MockSandboxAdapter(sandbox_id="sbx-builder-reused")
    manager = VerifierSandboxManager(known_builder_sandbox_ids=["sbx-builder-reused"])

    with pytest.raises(BuilderSandboxReuseError, match="reuse Builder sandbox"):
        manager.create_isolated_verifier_sandbox(
            context_envelope=sample_envelope,
            world=ExecutionWorld.BASE,
            sandbox_adapter=adapter,
        )

    assert "sbx-builder-reused" in adapter.torn_down_ids


def test_reject_builder_workspace_path_collision() -> None:
    """Configuring verifier workspace to point to Builder workspace fails closed."""
    with pytest.raises(BuilderWorkspaceInheritanceError, match="collides with"):
        VerifierSandboxManager(config=VerifierSandboxConfig(workspace_path="/workspace/candidate"))

    with pytest.raises(BuilderWorkspaceInheritanceError, match="collides with"):
        VerifierSandboxManager(config=VerifierSandboxConfig(workspace_path="/workspace"))


def test_reject_missing_sandbox_identity(
    sample_envelope: VerifierContextEnvelope,
) -> None:
    """Null, empty, or whitespace sandbox identity fails closed."""

    class NoneAdapter:
        def create_sandbox(self, image: str, timeout_seconds: int) -> Any:
            return None

    class EmptyAdapter:
        def create_sandbox(self, image: str, timeout_seconds: int) -> str:
            return "   \t"

    manager = VerifierSandboxManager()

    with pytest.raises(MissingSandboxIdentityError):
        manager.create_isolated_verifier_sandbox(
            context_envelope=sample_envelope,
            world=ExecutionWorld.BASE,
            sandbox_adapter=NoneAdapter(),
        )

    with pytest.raises(MissingSandboxIdentityError):
        manager.create_isolated_verifier_sandbox(
            context_envelope=sample_envelope,
            world=ExecutionWorld.BASE,
            sandbox_adapter=EmptyAdapter(),
        )


def test_reject_host_execution_fallback(
    sample_envelope: VerifierContextEnvelope,
) -> None:
    """Passing None as sandbox adapter fails with HostExecutionFallbackError."""
    manager = VerifierSandboxManager()
    with pytest.raises(HostExecutionFallbackError, match="strictly prohibited"):
        manager.create_isolated_verifier_sandbox(
            context_envelope=sample_envelope,
            world=ExecutionWorld.BASE,
            sandbox_adapter=None,
        )


def test_reject_simulation_fallback_on_live_provenance(
    sample_envelope: VerifierContextEnvelope,
) -> None:
    """Attempting LIVE_NEBIUS provenance with a simulated adapter fails
    with SimulationFallbackError.
    """
    manager = VerifierSandboxManager()
    sim_adapter = SimulatedSandboxAdapter()

    with pytest.raises(SimulationFallbackError, match="is simulated"):
        manager.create_isolated_verifier_sandbox(
            context_envelope=sample_envelope,
            world=ExecutionWorld.BASE,
            sandbox_adapter=sim_adapter,
            provenance=EvidenceProvenance.LIVE_NEBIUS,
        )


def test_tree_digest_mismatch_tears_down_sandbox(
    sample_envelope: VerifierContextEnvelope,
) -> None:
    """Mismatched tree digest fails closed and tears down the sandbox."""
    adapter = MockSandboxAdapter(sandbox_id="sbx-tree-test")
    manager = VerifierSandboxManager()

    def bad_materializer(**kwargs: Any) -> Any:
        return {
            "resolved_commit_sha": sample_envelope.source_identity.resolved_commit_id,
            "resolved_tree_sha": "1" * 40,
            "workspace_path": "/verifier_workspace",
            "sandbox_id": "sbx-tree-test",
        }

    with pytest.raises(VerifierTreeDigestMismatchError):
        manager.create_isolated_verifier_sandbox(
            context_envelope=sample_envelope,
            world=ExecutionWorld.BASE,
            sandbox_adapter=adapter,
            materializer=bad_materializer,
            candidate_tree_digest="2" * 40,
        )

    assert "sbx-tree-test" in adapter.torn_down_ids


def test_provider_purity_sandbox() -> None:
    """Verifier sandbox module has zero imports from basebreak.adapters."""
    import basebreak.verifier.sandbox as verifier_sandbox

    tree = ast.parse(inspect.getsource(verifier_sandbox))
    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            for name in node.names:
                assert not name.name.startswith("basebreak.adapters"), (
                    f"Forbidden adapter import: {name.name}"
                )
        elif isinstance(node, ast.ImportFrom):
            if node.module:
                assert not node.module.startswith("basebreak.adapters"), (
                    f"Forbidden adapter import from: {node.module}"
                )
