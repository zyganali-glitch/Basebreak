"""Tests for P-08.01: VerifierContextEnvelope and minimum trusted inputs.

Verifies:
1. Narrow verifier input contract visible to Verifier.
2. Explicit classification of trusted control data vs untrusted candidate data.
3. Rejection of Builder summaries, Builder reasoning, Builder proposals, and pass claims.
4. Rejection of unpinned source identities.
5. Deterministic canonical serialization and cryptographic context digest.
6. Tamper-evident digest validation.
7. Provider purity (zero adapter imports in verifier context).
"""

from __future__ import annotations

import ast
import hashlib
import inspect
from dataclasses import FrozenInstanceError

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
from basebreak.domain.causal import CandidateIdentity
from basebreak.domain.source import CommitRevision, RequestedRef, SourceIdentity
from basebreak.verifier.context import (
    VERIFIER_CONTEXT_SCHEMA_VERSION,
    BuilderAuthoritySmugglingError,
    UnpinnedSourceError,
    UntrustedBuilderInputError,
    VerifierContextEnvelope,
    VerifierContextError,
    VerifierDigestMismatchError,
    VerifierInputClassification,
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
def sample_candidate(sample_source_identity: SourceIdentity) -> tuple[CandidateIdentity, str, str]:
    patch = (
        "diff --git a/pool.py b/pool.py\n"
        "--- a/pool.py\n"
        "+++ b/pool.py\n"
        "@@ -1 +1 @@\n"
        "-pass\n"
        "+close()\n"
    )
    patch_digest = hashlib.sha256(patch.encode("utf-8")).hexdigest()
    tree_digest = "abcdef0123456789abcdef0123456789abcdef01"
    candidate = CandidateIdentity(
        candidate_id="cand-001",
        source=sample_source_identity,
        patch_digest=patch_digest,
    )
    return candidate, patch, tree_digest


def test_verifier_context_creation_base_only(
    sample_contract: FrozenContract,
    sample_source_identity: SourceIdentity,
) -> None:
    """Verifier context can be created for BASE verification without candidate."""
    envelope = VerifierContextEnvelope.create(
        frozen_contract=sample_contract,
        source_identity=sample_source_identity,
        sealed_witness_references=("wit-02", "wit-01"),
    )

    assert envelope.schema_version == VERIFIER_CONTEXT_SCHEMA_VERSION
    assert envelope.frozen_contract == sample_contract
    assert envelope.source_identity == sample_source_identity
    assert envelope.candidate_identity is None
    assert envelope.candidate_patch_text is None
    assert envelope.candidate_tree_digest is None
    # Witness references are canonically sorted
    assert envelope.sealed_witness_references == ("wit-01", "wit-02")
    assert len(envelope.context_digest) == 64
    assert not envelope.is_candidate_verification


def test_verifier_context_creation_with_candidate(
    sample_contract: FrozenContract,
    sample_source_identity: SourceIdentity,
    sample_candidate: tuple[CandidateIdentity, str, str],
) -> None:
    """Verifier context correctly includes untrusted candidate data when present."""
    candidate, patch, tree_digest = sample_candidate
    envelope = VerifierContextEnvelope.create(
        frozen_contract=sample_contract,
        source_identity=sample_source_identity,
        candidate_identity=candidate,
        candidate_patch_text=patch,
        candidate_tree_digest=tree_digest,
    )

    assert envelope.is_candidate_verification
    assert envelope.candidate_identity == candidate
    assert envelope.candidate_patch_text == patch
    assert envelope.candidate_tree_digest == tree_digest


def test_verifier_input_classifications(
    sample_contract: FrozenContract,
    sample_source_identity: SourceIdentity,
    sample_candidate: tuple[CandidateIdentity, str, str],
) -> None:
    """Inputs are explicitly classified as TRUSTED_CONTROL vs UNTRUSTED_CANDIDATE."""
    candidate, patch, tree_digest = sample_candidate
    envelope = VerifierContextEnvelope.create(
        frozen_contract=sample_contract,
        source_identity=sample_source_identity,
        candidate_identity=candidate,
        candidate_patch_text=patch,
        candidate_tree_digest=tree_digest,
    )

    classifications = envelope.get_input_classifications()
    assert classifications["frozen_contract"] == VerifierInputClassification.TRUSTED_CONTROL
    assert classifications["source_identity"] == VerifierInputClassification.TRUSTED_CONTROL
    assert classifications["execution_policy"] == VerifierInputClassification.TRUSTED_CONTROL
    assert (
        classifications["sealed_witness_references"] == VerifierInputClassification.TRUSTED_CONTROL
    )
    assert classifications["candidate_identity"] == VerifierInputClassification.UNTRUSTED_CANDIDATE
    assert (
        classifications["candidate_patch_text"] == VerifierInputClassification.UNTRUSTED_CANDIDATE
    )
    assert (
        classifications["candidate_tree_digest"] == VerifierInputClassification.UNTRUSTED_CANDIDATE
    )


def test_reject_builder_summary_and_reasoning_smuggling(
    sample_contract: FrozenContract,
    sample_source_identity: SourceIdentity,
) -> None:
    """Builder summaries, reasoning, and proposals are rejected with UntrustedBuilderInputError."""
    with pytest.raises(UntrustedBuilderInputError):
        VerifierContextEnvelope.create(
            frozen_contract=sample_contract,
            source_identity=sample_source_identity,
            builder_summary="I fixed the memory leak by closing connections",
        )

    with pytest.raises(UntrustedBuilderInputError):
        VerifierContextEnvelope.create(
            frozen_contract=sample_contract,
            source_identity=sample_source_identity,
            builder_reasoning="Step 1 was to edit pool.py",
        )

    with pytest.raises(UntrustedBuilderInputError):
        VerifierContextEnvelope.create(
            frozen_contract=sample_contract,
            source_identity=sample_source_identity,
            builder_proposal={"steps": ["edit pool.py"]},
        )


def test_reject_builder_authority_smuggling(
    sample_contract: FrozenContract,
    sample_source_identity: SourceIdentity,
) -> None:
    """Self-certification flags (is_verified, claims_pass) are rejected."""
    with pytest.raises(BuilderAuthoritySmugglingError):
        VerifierContextEnvelope.create(
            frozen_contract=sample_contract,
            source_identity=sample_source_identity,
            is_verified=True,
        )

    with pytest.raises(BuilderAuthoritySmugglingError):
        VerifierContextEnvelope.create(
            frozen_contract=sample_contract,
            source_identity=sample_source_identity,
            claims_pass=True,
        )


def test_reject_unpinned_source(
    sample_contract: FrozenContract,
    sample_source_identity: SourceIdentity,
) -> None:
    """Unpinned branch references or mutable refs are rejected with UnpinnedSourceError."""
    # Test bypassed or non-CommitRevision
    fake_source = SourceIdentity(
        locator="github.com/example/pool-lib",
        revision=CommitRevision("0123456789abcdef0123456789abcdef01234567"),
    )
    object.__setattr__(fake_source, "revision", RequestedRef("main"))
    with pytest.raises(UnpinnedSourceError, match="must use CommitRevision"):
        VerifierContextEnvelope.create(
            frozen_contract=sample_contract,
            source_identity=fake_source,
        )


def test_reject_candidate_base_mismatch(
    sample_contract: FrozenContract,
    sample_source_identity: SourceIdentity,
) -> None:
    """Candidate targeting a different base commit is rejected."""
    other_source = SourceIdentity(
        locator="github.com/example/pool-lib",
        revision=CommitRevision("fedcba9876543210fedcba9876543210fedcba98"),
    )
    mismatched_candidate = CandidateIdentity(
        candidate_id="cand-mismatch",
        source=other_source,
    )
    with pytest.raises(VerifierContextError, match="does not match trusted source commit"):
        VerifierContextEnvelope.create(
            frozen_contract=sample_contract,
            source_identity=sample_source_identity,
            candidate_identity=mismatched_candidate,
        )


def test_reject_candidate_patch_digest_mismatch(
    sample_contract: FrozenContract,
    sample_source_identity: SourceIdentity,
) -> None:
    """Patch text not matching CandidateIdentity.patch_digest is rejected."""
    candidate = CandidateIdentity(
        candidate_id="cand-001",
        source=sample_source_identity,
        patch_digest="0" * 64,
    )
    with pytest.raises(VerifierContextError, match="does not match"):
        VerifierContextEnvelope.create(
            frozen_contract=sample_contract,
            source_identity=sample_source_identity,
            candidate_identity=candidate,
            candidate_patch_text="some other patch text",
        )


def test_tampered_context_digest_fails(
    sample_contract: FrozenContract,
    sample_source_identity: SourceIdentity,
) -> None:
    """Altered context digest fails closed with VerifierDigestMismatchError."""
    envelope = VerifierContextEnvelope.create(
        frozen_contract=sample_contract,
        source_identity=sample_source_identity,
    )

    with pytest.raises(VerifierDigestMismatchError):
        VerifierContextEnvelope(
            schema_version=envelope.schema_version,
            frozen_contract=envelope.frozen_contract,
            source_identity=envelope.source_identity,
            execution_policy=envelope.execution_policy,
            candidate_identity=envelope.candidate_identity,
            candidate_patch_text=envelope.candidate_patch_text,
            candidate_tree_digest=envelope.candidate_tree_digest,
            sealed_witness_references=envelope.sealed_witness_references,
            context_digest="f" * 64,  # forged digest
        )


def test_verifier_context_immutability(
    sample_contract: FrozenContract,
    sample_source_identity: SourceIdentity,
) -> None:
    """VerifierContextEnvelope is strictly immutable."""
    envelope = VerifierContextEnvelope.create(
        frozen_contract=sample_contract,
        source_identity=sample_source_identity,
    )

    with pytest.raises(FrozenInstanceError):
        envelope.context_digest = "mutated"  # type: ignore[misc]


def test_provider_purity() -> None:
    """Verifier context module has zero imports from basebreak.adapters."""
    import basebreak.verifier.context as verifier_context

    tree = ast.parse(inspect.getsource(verifier_context))
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
