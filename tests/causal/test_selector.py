"""Focused tests for P-11.02: Bounded deterministic region selection without model authority.

Validates:
1. Zero model authority: Model proposals, confidence, ranking, or reasoning have zero authority.
2. Deterministic validation: Nonexistent, ambiguous, overlapping, or empty selections fail closed.
3. Cryptographic binding: Exact candidate snapshot, source commit, locator, contract,
   and witness digests survive.
4. Authority boundary: Neither proposal nor selection can assert authority or grant verification.
5. Protected surface and secret safety: Rejected immediately upon violation.
"""

from __future__ import annotations

import pytest

from basebreak.builder.capture import CandidateSnapshot
from basebreak.causal.selector import (
    BoundedRegionSelector,
    ModelRegionProposal,
    ValidatedRegionSelection,
)
from basebreak.causal.subtraction import (
    AmbiguousSubtractionError,
    CallerAuthorityError,
    DigestTamperingError,
    EmptySubtractionError,
    ProtectedSurfaceSubtractionError,
    SecretPolicySubtractionError,
    SubtractionStrategyType,
    UnsupportedStrategyError,
)
from basebreak.domain.source import CommitRevision, SourceIdentity
from basebreak.evidence.artifact import compute_bytes_digest

FROZEN_CONTRACT_DIGEST = "a" * 64
SEALED_WITNESS_DIGEST = "b" * 64
BASE_COMMIT_ID = "c" * 40
REPO_LOCATOR = "https://github.com/example/repo.git"

SAMPLE_MULTI_FILE_PATCH = (
    "diff --git a/src/calc.py b/src/calc.py\n"
    "index 1111111..2222222 100644\n"
    "--- a/src/calc.py\n"
    "+++ b/src/calc.py\n"
    "@@ -1,2 +1,3 @@\n"
    " def add(a, b):\n"
    "+    # validation\n"
    "     return a + b\n"
    "@@ -10,2 +10,3 @@\n"
    " def sub(a, b):\n"
    "+    # sub check\n"
    "     return a - b\n"
    "diff --git a/src/utils.py b/src/utils.py\n"
    "index 3333333..4444444 100644\n"
    "--- a/src/utils.py\n"
    "+++ b/src/utils.py\n"
    "@@ -1,1 +1,2 @@\n"
    "+# util comment\n"
    " def noop(): pass\n"
)


def _make_snapshot(
    patch_text: str = SAMPLE_MULTI_FILE_PATCH,
    files_modified: tuple[str, ...] = ("src/calc.py", "src/utils.py"),
) -> CandidateSnapshot:
    patch_digest = compute_bytes_digest(patch_text.encode("utf-8")).value
    source = SourceIdentity(
        locator=REPO_LOCATOR,
        revision=CommitRevision(BASE_COMMIT_ID),
    )
    return CandidateSnapshot(
        candidate_id="cand-001",
        source_identity=source,
        candidate_tree_digest="d" * 40,
        patch_digest=patch_digest,
        patch_text=patch_text,
        files_added=(),
        files_modified=files_modified,
        files_deleted=(),
        builder_authored_tests=(),
        frozen_contract_digest=FROZEN_CONTRACT_DIGEST,
        context_digest="f" * 64,
    )


class TestModelRegionProposalAuthorityBoundary:
    """Proves that untrusted model proposals cannot assert authority."""

    def test_proposal_asserting_authority_rejected(self) -> None:
        with pytest.raises(CallerAuthorityError, match="cannot assert authority"):
            ModelRegionProposal(
                strategy_type=SubtractionStrategyType.FULL_PATCH_REVERT,
                is_authoritative=True,
            )

    def test_proposal_granting_pass_rejected(self) -> None:
        with pytest.raises(CallerAuthorityError, match="cannot grant pass"):
            ModelRegionProposal(
                strategy_type=SubtractionStrategyType.FULL_PATCH_REVERT,
                grants_pass=True,
            )

    def test_proposal_asserting_verification_rejected(self) -> None:
        with pytest.raises(CallerAuthorityError, match="cannot assert verification"):
            ModelRegionProposal(
                strategy_type=SubtractionStrategyType.FULL_PATCH_REVERT,
                is_causally_verified=True,
            )

    def test_validated_selection_asserting_authority_rejected(self) -> None:
        snapshot = _make_snapshot()
        sel = BoundedRegionSelector.select_full_patch(
            snapshot=snapshot,
            frozen_contract_digest=FROZEN_CONTRACT_DIGEST,
            sealed_witness_digest=SEALED_WITNESS_DIGEST,
        )
        assert sel.is_authoritative is False
        assert sel.grants_pass is False
        assert sel.is_causally_verified is False

        with pytest.raises(CallerAuthorityError):
            ValidatedRegionSelection(
                strategy_type=SubtractionStrategyType.FULL_PATCH_REVERT,
                selected_files=sel.selected_files,
                selected_hunk_ids=sel.selected_hunk_ids,
                plan=sel.plan,
                is_authoritative=True,
            )


class TestDeterministicBoundedSelection:
    """Proves deterministic bounded selection over candidate snapshot."""

    def test_select_full_patch_revert(self) -> None:
        snapshot = _make_snapshot()
        selection = BoundedRegionSelector.select_full_patch(
            snapshot=snapshot,
            frozen_contract_digest=FROZEN_CONTRACT_DIGEST,
            sealed_witness_digest=SEALED_WITNESS_DIGEST,
        )
        assert selection.strategy_type == SubtractionStrategyType.FULL_PATCH_REVERT
        assert "src/calc.py" in selection.selected_files
        assert "src/utils.py" in selection.selected_files
        assert len(selection.selected_hunk_ids) == 3
        assert selection.plan.source_locator == REPO_LOCATOR
        assert selection.plan.source_commit_id == BASE_COMMIT_ID
        assert selection.plan.frozen_contract_digest == FROZEN_CONTRACT_DIGEST
        assert selection.plan.sealed_witness_digest == SEALED_WITNESS_DIGEST

    def test_select_files_revert(self) -> None:
        snapshot = _make_snapshot()
        selection = BoundedRegionSelector.select_files(
            target_files=["src/utils.py"],
            snapshot=snapshot,
            frozen_contract_digest=FROZEN_CONTRACT_DIGEST,
            sealed_witness_digest=SEALED_WITNESS_DIGEST,
        )
        assert selection.strategy_type == SubtractionStrategyType.FILE_LEVEL_REVERT
        assert selection.selected_files == ("src/utils.py",)
        assert len(selection.selected_hunk_ids) == 1
        assert "src/calc.py" in selection.plan.counterfactual_patch_text
        assert "src/utils.py" not in selection.plan.counterfactual_patch_text

    def test_select_hunks_revert(self) -> None:
        snapshot = _make_snapshot()
        from basebreak.causal.subtraction import parse_candidate_patch

        parsed = parse_candidate_patch(snapshot.patch_text)
        target_hunk_id = parsed.files[0].hunks[0].hunk_id

        selection = BoundedRegionSelector.select_hunks(
            target_hunk_ids=[target_hunk_id],
            snapshot=snapshot,
            frozen_contract_digest=FROZEN_CONTRACT_DIGEST,
            sealed_witness_digest=SEALED_WITNESS_DIGEST,
        )
        assert selection.strategy_type == SubtractionStrategyType.HUNK_LEVEL_REVERT
        assert selection.selected_hunk_ids == (target_hunk_id,)
        assert "src/calc.py" in selection.selected_files
        assert "src/utils.py" in selection.plan.counterfactual_patch_text


class TestAdversarialModelProposals:
    """Proves that malicious or flawed model proposals fail closed."""

    def test_proposal_with_nonexistent_file_rejected(self) -> None:
        snapshot = _make_snapshot()
        proposal = ModelRegionProposal(
            strategy_type=SubtractionStrategyType.FILE_LEVEL_REVERT,
            proposed_files=("src/nonexistent.py",),
            model_confidence=0.99,
            model_reasoning="Model claims this file exists and is crucial",
        )
        with pytest.raises(UnsupportedStrategyError, match="not found in candidate patch"):
            BoundedRegionSelector.validate_and_plan_from_proposal(
                proposal=proposal,
                snapshot=snapshot,
                frozen_contract_digest=FROZEN_CONTRACT_DIGEST,
                sealed_witness_digest=SEALED_WITNESS_DIGEST,
            )

    def test_proposal_with_nonexistent_hunk_rejected(self) -> None:
        snapshot = _make_snapshot()
        proposal = ModelRegionProposal(
            strategy_type=SubtractionStrategyType.HUNK_LEVEL_REVERT,
            proposed_hunk_ids=("src/calc.py:99",),
            model_confidence=0.95,
            model_reasoning="Model hallucinates hunk index 99",
        )
        with pytest.raises(UnsupportedStrategyError, match="not found in candidate patch"):
            BoundedRegionSelector.validate_and_plan_from_proposal(
                proposal=proposal,
                snapshot=snapshot,
                frozen_contract_digest=FROZEN_CONTRACT_DIGEST,
                sealed_witness_digest=SEALED_WITNESS_DIGEST,
            )

    def test_proposal_with_empty_files_rejected(self) -> None:
        snapshot = _make_snapshot()
        proposal = ModelRegionProposal(
            strategy_type=SubtractionStrategyType.FILE_LEVEL_REVERT,
            proposed_files=(),
        )
        with pytest.raises(EmptySubtractionError):
            BoundedRegionSelector.validate_and_plan_from_proposal(
                proposal=proposal,
                snapshot=snapshot,
                frozen_contract_digest=FROZEN_CONTRACT_DIGEST,
                sealed_witness_digest=SEALED_WITNESS_DIGEST,
            )

    def test_proposal_with_empty_hunks_rejected(self) -> None:
        snapshot = _make_snapshot()
        proposal = ModelRegionProposal(
            strategy_type=SubtractionStrategyType.HUNK_LEVEL_REVERT,
            proposed_hunk_ids=(),
        )
        with pytest.raises(EmptySubtractionError):
            BoundedRegionSelector.validate_and_plan_from_proposal(
                proposal=proposal,
                snapshot=snapshot,
                frozen_contract_digest=FROZEN_CONTRACT_DIGEST,
                sealed_witness_digest=SEALED_WITNESS_DIGEST,
            )

    def test_proposal_touching_protected_surface_rejected(self) -> None:
        protected_patch = (
            "diff --git a/AGENTS.md b/AGENTS.md\n"
            "index 1111111..2222222 100644\n"
            "--- a/AGENTS.md\n"
            "+++ b/AGENTS.md\n"
            "@@ -1,1 +1,2 @@\n"
            "+tampering governance\n"
            " protected\n"
        )
        snapshot = _make_snapshot(protected_patch, files_modified=("AGENTS.md",))
        proposal = ModelRegionProposal(
            strategy_type=SubtractionStrategyType.FULL_PATCH_REVERT,
        )
        with pytest.raises(ProtectedSurfaceSubtractionError):
            BoundedRegionSelector.validate_and_plan_from_proposal(
                proposal=proposal,
                snapshot=snapshot,
                frozen_contract_digest=FROZEN_CONTRACT_DIGEST,
                sealed_witness_digest=SEALED_WITNESS_DIGEST,
            )

    def test_proposal_containing_secret_rejected(self) -> None:
        secret_patch = (
            "diff --git a/src/keys.py b/src/keys.py\n"
            "index 1111111..2222222 100644\n"
            "--- a/src/keys.py\n"
            "+++ b/src/keys.py\n"
            "@@ -1,1 +1,2 @@\n"
            '+NEBIUS_API_KEY = "nb_live_123456789012345678901234567890"\n'
            " def key(): pass\n"
        )
        snapshot = _make_snapshot(secret_patch, files_modified=("src/keys.py",))
        proposal = ModelRegionProposal(
            strategy_type=SubtractionStrategyType.FULL_PATCH_REVERT,
        )
        with pytest.raises(SecretPolicySubtractionError):
            BoundedRegionSelector.validate_and_plan_from_proposal(
                proposal=proposal,
                snapshot=snapshot,
                frozen_contract_digest=FROZEN_CONTRACT_DIGEST,
                sealed_witness_digest=SEALED_WITNESS_DIGEST,
            )

    def test_proposal_confidence_out_of_bounds_rejected(self) -> None:
        with pytest.raises(ValueError, match="between 0.0 and 1.0"):
            ModelRegionProposal(
                strategy_type=SubtractionStrategyType.FULL_PATCH_REVERT,
                model_confidence=1.5,
            )

    def test_tampered_contract_digest_rejected(self) -> None:
        snapshot = _make_snapshot()
        proposal = ModelRegionProposal(
            strategy_type=SubtractionStrategyType.FULL_PATCH_REVERT,
        )
        with pytest.raises(DigestTamperingError):
            BoundedRegionSelector.validate_and_plan_from_proposal(
                proposal=proposal,
                snapshot=snapshot,
                frozen_contract_digest="e" * 64,  # doesn't match snapshot.frozen_contract_digest
                sealed_witness_digest=SEALED_WITNESS_DIGEST,
            )

    def test_overlapping_hunks_proposal_rejected_as_ambiguous(self) -> None:
        overlapping_patch = (
            "diff --git a/src/demo_target/cli.py b/src/demo_target/cli.py\n"
            "index 878b16f..f2e0928 100644\n"
            "--- a/src/demo_target/cli.py\n"
            "+++ b/src/demo_target/cli.py\n"
            "@@ -10,10 +10,10 @@\n"
            " line 10\n"
            "-line 11 old\n"
            "+line 11 new\n"
            " line 12\n"
            " line 13\n"
            " line 14\n"
            " line 15\n"
            " line 16\n"
            " line 17\n"
            " line 18\n"
            " line 19\n"
            "@@ -15,5 +15,5 @@\n"
            " line 15\n"
            "-line 16 old\n"
            "+line 16 new\n"
            " line 17\n"
            " line 18\n"
            " line 19\n"
        )
        snapshot = _make_snapshot(overlapping_patch, files_modified=("src/demo_target/cli.py",))
        from basebreak.causal.subtraction import parse_candidate_patch

        parsed = parse_candidate_patch(snapshot.patch_text)
        hunk0 = parsed.files[0].hunks[0].hunk_id
        hunk1 = parsed.files[0].hunks[1].hunk_id

        proposal = ModelRegionProposal(
            strategy_type=SubtractionStrategyType.HUNK_LEVEL_REVERT,
            proposed_hunk_ids=(hunk0, hunk1),
        )
        with pytest.raises(AmbiguousSubtractionError):
            BoundedRegionSelector.validate_and_plan_from_proposal(
                proposal=proposal,
                snapshot=snapshot,
                frozen_contract_digest=FROZEN_CONTRACT_DIGEST,
                sealed_witness_digest=SEALED_WITNESS_DIGEST,
            )
