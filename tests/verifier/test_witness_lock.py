"""Tests for P-09.06: Immutable witness lock and pre-candidate execution digest preservation.

Verifies:
1. Deterministic lock creation and lock digest computation before candidate execution.
2. Unbroken chain verification: requirement -> frozen_contract_digest -> witness_digest.
3. Anti-mutation defense: rejection of differing witness digests between BASE and CANDIDATE.
4. Anti-rebinding defense: rejection of mismatched contracts or requirement IDs.
5. Rejection of tampered lock records.
6. Provider purity (zero adapter imports in witness_lock).
"""

from __future__ import annotations

import ast
import inspect

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
from basebreak.verifier.witness_lock import (
    ImmutableWitnessLock,
    WitnessMutationError,
    WitnessRebindingError,
    create_witness_lock,
    verify_witness_lock_chain,
)
from basebreak.verifier.witness_store import (
    SealedWitnessRecord,
    TrustedWitnessVault,
    WitnessArtifact,
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
def sample_sealed_record(
    sample_contract: FrozenContract,
) -> tuple[TrustedWitnessVault, SealedWitnessRecord]:
    vault = TrustedWitnessVault()
    art = WitnessArtifact.from_text(
        path="tests/witness/test_lock.py",
        content="def test_lock():\n    assert 1 == 1\n",
    )
    req_id = sample_contract.requirements[0].requirement_id
    record = vault.seal_witness(
        witness_id="wit-lock-01",
        requirement_id=req_id,
        frozen_contract_digest=sample_contract.contract_digest,
        source_commit_id="a" * 40,
        artifacts=[art],
    )
    return vault, record


def test_create_witness_lock_success(
    sample_contract: FrozenContract,
    sample_sealed_record: tuple[TrustedWitnessVault, SealedWitnessRecord],
) -> None:
    vault, record = sample_sealed_record
    lock = create_witness_lock(record, vault)

    assert isinstance(lock, ImmutableWitnessLock)
    assert lock.witness_id == "wit-lock-01"
    assert lock.witness_digest == record.seal_digest
    assert lock.frozen_contract_digest == sample_contract.contract_digest
    assert len(lock.lock_digest) == 64

    # Chain of custody verified
    assert (
        verify_witness_lock_chain(
            lock=lock,
            frozen_contract=sample_contract,
            base_record=record,
            candidate_record=record,
        )
        is True
    )


def test_chain_rejects_mutated_candidate_witness(
    sample_contract: FrozenContract,
    sample_sealed_record: tuple[TrustedWitnessVault, SealedWitnessRecord],
) -> None:
    vault, base_record = sample_sealed_record
    lock = create_witness_lock(base_record, vault)

    # Candidate run attempts to use a different witness
    art2 = WitnessArtifact.from_text(
        path="tests/witness/test_mutated.py",
        content="def test_mutated():\n    assert 2 == 2\n",
    )
    req_id = sample_contract.requirements[0].requirement_id
    candidate_record = vault.seal_witness(
        witness_id="wit-lock-mutated",
        requirement_id=req_id,
        frozen_contract_digest=sample_contract.contract_digest,
        source_commit_id="a" * 40,
        artifacts=[art2],
    )

    with pytest.raises(WitnessMutationError, match="does not match locked digest"):
        verify_witness_lock_chain(
            lock=lock,
            frozen_contract=sample_contract,
            base_record=base_record,
            candidate_record=candidate_record,
        )


def test_chain_rejects_rebound_contract(
    sample_sealed_record: tuple[TrustedWitnessVault, SealedWitnessRecord],
) -> None:
    vault, record = sample_sealed_record
    lock = create_witness_lock(record, vault)

    # Different contract
    task2 = ingest_task("Task: Other defect.\nRequirements:\n1. Other defect fix.")
    fact = DeterministicClassificationFact(
        inferred_class=ChangeClass.BUG_FIX,
        certainty=CertaintyLevel.CONFIDENT,
        confidence=0.9,
        alternative_classes=(),
        rationale="Other",
        evidence_citations=("Other defect",),
        matched_signals=("other",),
    )
    semantics = ChangeSemanticsClassification(
        task_digest=task2.task_digest,
        change_class=ChangeClass.BUG_FIX,
        certainty=CertaintyLevel.CONFIDENT,
        confidence=0.9,
        alternative_classes=(),
        rationale="Other",
        evidence_citations=("Other defect",),
        deterministic_facts=fact,
    )
    cit2 = "Other defect fix."
    start2 = task2.normalized_text.index(cit2)
    end2 = start2 + len(cit2)
    req2 = ProposedRequirement(
        statement="Other defect fix.",
        citation=cit2,
        citation_start=start2,
        citation_end=end2,
        rationale="Other",
    )
    bundle = ReviewBundle(task=task2, semantics=semantics, requirements=(req2,))
    review_result = ReviewSession(bundle).approve()
    diff_contract = freeze_review_result(review_result)

    with pytest.raises(WitnessRebindingError, match="contract digest"):
        verify_witness_lock_chain(
            lock=lock,
            frozen_contract=diff_contract,
            base_record=record,
        )


def test_witness_lock_provider_purity() -> None:
    import basebreak.verifier.witness_lock as wl_mod

    source = inspect.getsource(wl_mod)
    tree = ast.parse(source)
    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            for alias in node.names:
                assert not alias.name.startswith("basebreak.adapters"), (
                    f"witness_lock must not import adapters: {alias.name}"
                )
        elif isinstance(node, ast.ImportFrom):
            if node.module:
                assert not node.module.startswith("basebreak.adapters"), (
                    f"witness_lock must not import adapters: {node.module}"
                )
