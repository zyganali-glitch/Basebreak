"""Unit tests for P-14.04: Repaired candidate identity and lineage tracking."""

from __future__ import annotations

import dataclasses
import inspect

import pytest

from basebreak.builder.capture import CandidateSnapshot
from basebreak.domain.semantics import ChangeClass
from basebreak.domain.source import CommitRevision, SourceIdentity
from basebreak.domain.verdict import EvidenceProvenance
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
    CandidateIdentityReuseError,
    CandidateLineageMismatchError,
    CandidateLineageTamperingError,
    RepairedCandidateSnapshot,
    UnchangedCandidateError,
    create_candidate_lineage_record,
    verify_candidate_lineage_integrity,
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

CONTRACT_DIGEST = "c" * 64
RECEIPT_DIGEST = "d" * 64


def _make_context() -> BuilderRepairContextEnvelope:
    feedback = create_safe_repair_feedback(
        feedback_id="FB-01",
        candidate_id="cand-01",
        requirement_id="REQ-BUG-01",
        change_class=ChangeClass.BUG_FIX,
        failed_condition=FailureConditionCategory.BEHAVIORAL_ASSERTION_FAILED,
        observed_behavior="Failed test",
        expected_behavior="Passed test",
        originating_receipt_digest=RECEIPT_DIGEST,
        feedback_round=1,
        provenance=EvidenceProvenance.LOCAL_EXECUTION,
        permitted_patch_region=["a.py"],
    )
    return create_builder_repair_context(
        repair_context_id="RPC-01",
        parent_candidate_id="cand-01",
        parent_candidate_tree_digest=PARENT_TREE,
        parent_patch_digest=PARENT_PATCH_DIGEST,
        parent_patch_text=PARENT_PATCH,
        source_identity=SAMPLE_SOURCE,
        frozen_contract_digest=CONTRACT_DIGEST,
        requirement_id="REQ-BUG-01",
        change_class=ChangeClass.BUG_FIX,
        repair_feedback=feedback,
        permitted_paths=["a.py"],
        repair_round=1,
        max_repair_rounds=3,
    )


def test_create_valid_lineage_and_repaired_snapshot() -> None:
    ctx = _make_context()
    lineage = create_candidate_lineage_record(
        lineage_id="LIN-01",
        context=ctx,
        repaired_candidate_id="cand-02",
        repaired_tree_digest=REPAIRED_TREE,
        repaired_patch_digest=REPAIRED_PATCH_DIGEST,
        builder_execution_identity="bexec-01",
    )

    assert lineage.parent_candidate_id == "cand-01"
    assert lineage.repaired_candidate_id == "cand-02"
    assert lineage.repair_round == 1
    assert lineage.is_authoritative is False
    assert len(lineage.lineage_digest) == 64
    assert verify_candidate_lineage_integrity(lineage) is True

    candidate = CandidateSnapshot(
        candidate_id="cand-02",
        source_identity=SAMPLE_SOURCE,
        candidate_tree_digest=REPAIRED_TREE,
        patch_digest=REPAIRED_PATCH_DIGEST,
        patch_text=REPAIRED_PATCH,
        files_added=(),
        files_modified=("a.py",),
        files_deleted=(),
        builder_authored_tests=(),
        frozen_contract_digest=CONTRACT_DIGEST,
        context_digest=ctx.repair_context_digest,
        provenance=EvidenceProvenance.LOCAL_EXECUTION,
    )

    snapshot = RepairedCandidateSnapshot(
        candidate=candidate,
        lineage=lineage,
        is_authoritative=False,
    )
    assert snapshot.candidate.candidate_id == "cand-02"
    assert snapshot.lineage.parent_candidate_id == "cand-01"


def test_reusing_parent_candidate_id_rejected() -> None:
    ctx = _make_context()
    with pytest.raises(CandidateIdentityReuseError):
        create_candidate_lineage_record(
            lineage_id="LIN-02",
            context=ctx,
            repaired_candidate_id="cand-01",  # Same as parent!
            repaired_tree_digest=REPAIRED_TREE,
            repaired_patch_digest=REPAIRED_PATCH_DIGEST,
        )


def test_unchanged_patch_rejected() -> None:
    ctx = _make_context()
    with pytest.raises(UnchangedCandidateError):
        create_candidate_lineage_record(
            lineage_id="LIN-03",
            context=ctx,
            repaired_candidate_id="cand-02",
            repaired_tree_digest=REPAIRED_TREE,
            repaired_patch_digest=PARENT_PATCH_DIGEST,  # Same as parent patch!
        )


def test_unchanged_tree_rejected() -> None:
    ctx = _make_context()
    with pytest.raises(UnchangedCandidateError):
        create_candidate_lineage_record(
            lineage_id="LIN-04",
            context=ctx,
            repaired_candidate_id="cand-02",
            repaired_tree_digest=PARENT_TREE,  # Same as parent tree!
            repaired_patch_digest=REPAIRED_PATCH_DIGEST,
        )


def test_snapshot_mismatch_rejected() -> None:
    ctx = _make_context()
    lineage = create_candidate_lineage_record(
        lineage_id="LIN-05",
        context=ctx,
        repaired_candidate_id="cand-02",
        repaired_tree_digest=REPAIRED_TREE,
        repaired_patch_digest=REPAIRED_PATCH_DIGEST,
    )

    candidate = CandidateSnapshot(
        candidate_id="cand-DIFFERENT",  # Mismatched ID!
        source_identity=SAMPLE_SOURCE,
        candidate_tree_digest=REPAIRED_TREE,
        patch_digest=REPAIRED_PATCH_DIGEST,
        patch_text=REPAIRED_PATCH,
        files_added=(),
        files_modified=("a.py",),
        files_deleted=(),
        builder_authored_tests=(),
        frozen_contract_digest=CONTRACT_DIGEST,
        context_digest=ctx.repair_context_digest,
        provenance=EvidenceProvenance.LOCAL_EXECUTION,
    )

    with pytest.raises(CandidateLineageMismatchError):
        RepairedCandidateSnapshot(
            candidate=candidate,
            lineage=lineage,
        )


def test_lineage_tampering_rejected() -> None:
    ctx = _make_context()
    lineage = create_candidate_lineage_record(
        lineage_id="LIN-06",
        context=ctx,
        repaired_candidate_id="cand-02",
        repaired_tree_digest=REPAIRED_TREE,
        repaired_patch_digest=REPAIRED_PATCH_DIGEST,
    )

    tampered = dataclasses.replace(lineage, repair_round=99)
    with pytest.raises(CandidateLineageTamperingError):
        verify_candidate_lineage_integrity(tampered)


def test_lineage_provider_purity() -> None:
    import basebreak.repair.lineage as lin_module

    source = inspect.getsource(lin_module)
    assert "basebreak.adapters" not in source
    assert "nebius" not in source.lower()
    assert "openai" not in source.lower()
    assert "nemotron" not in source.lower()
