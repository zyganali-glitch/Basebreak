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
    """Verifier sandbox is created cleanly in isolation."""
    adapter = MockSandboxAdapter(sandbox_id="sbx-verifier-999")
    manager = VerifierSandboxManager(known_builder_sandbox_ids=["sbx-builder-001"])

    session = manager.create_isolated_verifier_sandbox(
        context_envelope=sample_envelope,
        world=ExecutionWorld.BASE,
        sandbox_adapter=adapter,
    )

    assert isinstance(session, VerifierSandboxSession)
    assert session.sandbox_identity.sandbox_id == "sbx-verifier-999"
    assert session.world == ExecutionWorld.BASE
    assert session.workspace_path == "/verifier_workspace"
    assert session.context_digest == sample_envelope.context_digest
    assert not session.is_authoritative
    assert not session.is_causally_verified
    assert not session.grants_pass


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
        class Result:
            tree_digest = "1" * 40

        return Result()

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
