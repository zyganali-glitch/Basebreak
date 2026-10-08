"""Unit tests for P-14.03: Builder fresh repair context envelope and isolation."""

from __future__ import annotations

import dataclasses
import inspect

import pytest

from basebreak.domain.semantics import ChangeClass
from basebreak.domain.source import CommitRevision, SourceIdentity
from basebreak.domain.verdict import EvidenceProvenance
from basebreak.evidence.artifact import compute_bytes_digest
from basebreak.repair.context import (
    RepairContextBudgetExceededError,
    RepairContextMismatchedCandidateError,
    RepairContextMismatchedContractError,
    RepairContextProtectedSurfaceError,
    RepairContextTamperingError,
    VerifierStateLeakError,
    create_builder_repair_context,
    verify_builder_repair_context_integrity,
)
from basebreak.repair.feedback import (
    FailureConditionCategory,
    SafeRepairFeedback,
    create_safe_repair_feedback,
)

SAMPLE_SOURCE = SourceIdentity(
    locator="https://github.com/zyganali-glitch/basebreak-demo-target.git",
    revision=CommitRevision("40ff923a134a21d8e357deb7a7988571cd396b56"),
)
SAMPLE_TREE_DIGEST = "f81f6faa0c7572f9941570bbce376fadc10f39a3"
SAMPLE_CONTRACT_DIGEST = "b" * 64
SAMPLE_RECEIPT_DIGEST = "a" * 64
SAMPLE_PATCH_TEXT = (
    "diff --git a/src/demo/cli.py b/src/demo/cli.py\n"
    "--- a/src/demo/cli.py\n"
    "+++ b/src/demo/cli.py\n"
    "@@ -1,1 +1,2 @@\n"
    "+# fix\n"
)
SAMPLE_PATCH_DIGEST = compute_bytes_digest(SAMPLE_PATCH_TEXT.encode("utf-8")).value


def _make_feedback(
    candidate_id: str = "cand-01",
    requirement_id: str = "REQ-BUG-01",
    change_class: ChangeClass = ChangeClass.BUG_FIX,
    feedback_round: int = 1,
) -> SafeRepairFeedback:
    return create_safe_repair_feedback(
        feedback_id="FB-001",
        candidate_id=candidate_id,
        requirement_id=requirement_id,
        change_class=change_class,
        failed_condition=FailureConditionCategory.BEHAVIORAL_ASSERTION_FAILED,
        observed_behavior="Failed assertion on input x=5",
        expected_behavior="Expected x=5 to return 10",
        originating_receipt_digest=SAMPLE_RECEIPT_DIGEST,
        feedback_round=feedback_round,
        provenance=EvidenceProvenance.LOCAL_EXECUTION,
        permitted_patch_region=["src/demo/cli.py"],
    )


def test_create_valid_builder_repair_context() -> None:
    feedback = _make_feedback()
    ctx = create_builder_repair_context(
        repair_context_id="RPC-01",
        parent_candidate_id="cand-01",
        parent_candidate_tree_digest=SAMPLE_TREE_DIGEST,
        parent_patch_digest=SAMPLE_PATCH_DIGEST,
        parent_patch_text=SAMPLE_PATCH_TEXT,
        source_identity=SAMPLE_SOURCE,
        frozen_contract_digest=SAMPLE_CONTRACT_DIGEST,
        requirement_id="REQ-BUG-01",
        change_class=ChangeClass.BUG_FIX,
        repair_feedback=feedback,
        permitted_paths=["src/demo/cli.py"],
        repair_round=1,
        max_repair_rounds=3,
    )

    assert ctx.repair_context_id == "RPC-01"
    assert ctx.parent_candidate_id == "cand-01"
    assert ctx.repair_round == 1
    assert ctx.max_repair_rounds == 3
    assert ctx.is_authoritative is False
    assert len(ctx.repair_context_digest) == 64
    assert verify_builder_repair_context_integrity(ctx) is True


def test_mismatched_candidate_id_rejected() -> None:
    feedback = _make_feedback(candidate_id="cand-FOREIGN")
    with pytest.raises(RepairContextMismatchedCandidateError):
        create_builder_repair_context(
            repair_context_id="RPC-02",
            parent_candidate_id="cand-01",
            parent_candidate_tree_digest=SAMPLE_TREE_DIGEST,
            parent_patch_digest=SAMPLE_PATCH_DIGEST,
            parent_patch_text=SAMPLE_PATCH_TEXT,
            source_identity=SAMPLE_SOURCE,
            frozen_contract_digest=SAMPLE_CONTRACT_DIGEST,
            requirement_id="REQ-BUG-01",
            change_class=ChangeClass.BUG_FIX,
            repair_feedback=feedback,
            permitted_paths=["src/demo/cli.py"],
            repair_round=1,
            max_repair_rounds=3,
        )


def test_mismatched_contract_requirement_rejected() -> None:
    feedback = _make_feedback(requirement_id="REQ-FOREIGN")
    with pytest.raises(RepairContextMismatchedContractError):
        create_builder_repair_context(
            repair_context_id="RPC-03",
            parent_candidate_id="cand-01",
            parent_candidate_tree_digest=SAMPLE_TREE_DIGEST,
            parent_patch_digest=SAMPLE_PATCH_DIGEST,
            parent_patch_text=SAMPLE_PATCH_TEXT,
            source_identity=SAMPLE_SOURCE,
            frozen_contract_digest=SAMPLE_CONTRACT_DIGEST,
            requirement_id="REQ-BUG-01",
            change_class=ChangeClass.BUG_FIX,
            repair_feedback=feedback,
            permitted_paths=["src/demo/cli.py"],
            repair_round=1,
            max_repair_rounds=3,
        )


def test_budget_exceeded_rejected() -> None:
    feedback = _make_feedback(feedback_round=4)
    with pytest.raises(RepairContextBudgetExceededError):
        create_builder_repair_context(
            repair_context_id="RPC-04",
            parent_candidate_id="cand-01",
            parent_candidate_tree_digest=SAMPLE_TREE_DIGEST,
            parent_patch_digest=SAMPLE_PATCH_DIGEST,
            parent_patch_text=SAMPLE_PATCH_TEXT,
            source_identity=SAMPLE_SOURCE,
            frozen_contract_digest=SAMPLE_CONTRACT_DIGEST,
            requirement_id="REQ-BUG-01",
            change_class=ChangeClass.BUG_FIX,
            repair_feedback=feedback,
            permitted_paths=["src/demo/cli.py"],
            repair_round=4,
            max_repair_rounds=3,
        )


def test_protected_surface_permitted_path_rejected() -> None:
    feedback = _make_feedback()
    # Attempting to permit modification to AGENTS.md or tests/verifier/
    with pytest.raises(RepairContextProtectedSurfaceError):
        create_builder_repair_context(
            repair_context_id="RPC-05",
            parent_candidate_id="cand-01",
            parent_candidate_tree_digest=SAMPLE_TREE_DIGEST,
            parent_patch_digest=SAMPLE_PATCH_DIGEST,
            parent_patch_text=SAMPLE_PATCH_TEXT,
            source_identity=SAMPLE_SOURCE,
            frozen_contract_digest=SAMPLE_CONTRACT_DIGEST,
            requirement_id="REQ-BUG-01",
            change_class=ChangeClass.BUG_FIX,
            repair_feedback=feedback,
            permitted_paths=["AGENTS.md"],
            repair_round=1,
            max_repair_rounds=3,
        )


def test_verifier_state_leak_rejected() -> None:
    feedback = _make_feedback()
    leaked_patch = (
        "diff --git a/src/demo/cli.py b/src/demo/cli.py\n"
        "--- a/src/demo/cli.py\n"
        "+++ b/src/demo/cli.py\n"
        "@@ -1,1 +1,2 @@\n"
        "+# leak /verifier_workspace/secret_witness.py\n"
    )
    leaked_patch_digest = compute_bytes_digest(leaked_patch.encode("utf-8")).value

    with pytest.raises(VerifierStateLeakError):
        create_builder_repair_context(
            repair_context_id="RPC-06",
            parent_candidate_id="cand-01",
            parent_candidate_tree_digest=SAMPLE_TREE_DIGEST,
            parent_patch_digest=leaked_patch_digest,
            parent_patch_text=leaked_patch,
            source_identity=SAMPLE_SOURCE,
            frozen_contract_digest=SAMPLE_CONTRACT_DIGEST,
            requirement_id="REQ-BUG-01",
            change_class=ChangeClass.BUG_FIX,
            repair_feedback=feedback,
            permitted_paths=["src/demo/cli.py"],
            repair_round=1,
            max_repair_rounds=3,
        )


def test_context_tampering_rejected() -> None:
    feedback = _make_feedback()
    ctx = create_builder_repair_context(
        repair_context_id="RPC-07",
        parent_candidate_id="cand-01",
        parent_candidate_tree_digest=SAMPLE_TREE_DIGEST,
        parent_patch_digest=SAMPLE_PATCH_DIGEST,
        parent_patch_text=SAMPLE_PATCH_TEXT,
        source_identity=SAMPLE_SOURCE,
        frozen_contract_digest=SAMPLE_CONTRACT_DIGEST,
        requirement_id="REQ-BUG-01",
        change_class=ChangeClass.BUG_FIX,
        repair_feedback=feedback,
        permitted_paths=["src/demo/cli.py"],
        repair_round=1,
        max_repair_rounds=3,
    )

    tampered = dataclasses.replace(ctx, frozen_contract_digest="c" * 64)
    with pytest.raises(RepairContextTamperingError):
        verify_builder_repair_context_integrity(tampered)


def test_context_provider_purity() -> None:
    import basebreak.repair.context as ctx_module

    source = inspect.getsource(ctx_module)
    assert "basebreak.adapters" not in source
    assert "nebius" not in source.lower()
    assert "openai" not in source.lower()
    assert "nemotron" not in source.lower()
