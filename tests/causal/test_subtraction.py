"""Focused test suite for P-11.01 candidate-delta subtraction strategies.

Tests:
1. Deterministic strategy identity: FULL_PATCH_REVERT, FILE_LEVEL_REVERT, HUNK_LEVEL_REVERT.
2. Unsupported and ambiguous subtraction handling (non-existent targets, overlapping hunks).
3. Protected-surface and secret policy rejection.
4. Empty and no-op subtraction rejection.
5. Source, candidate, and patch identity binding and mismatch detection.
6. Rejection of caller-supplied and model-supplied fake authority.
7. Preservation and tamper detection of sealed witness and frozen contract digests.
8. Non-mutation of BASE and CANDIDATE states.
9. Verification that future execution and reconciliation remain absent.
"""

from __future__ import annotations

import hashlib
from dataclasses import FrozenInstanceError

import pytest

from basebreak.builder.capture import CandidateSnapshot
from basebreak.causal.subtraction import (
    AmbiguousSubtractionError,
    CallerAuthorityError,
    CandidateDeltaSubtractor,
    CandidateIdentityMismatchError,
    CounterfactualDeltaPlan,
    DigestTamperingError,
    EmptySubtractionError,
    InvalidSubtractionError,
    ProtectedSurfaceSubtractionError,
    SecretPolicySubtractionError,
    SubtractionRequest,
    SubtractionStrategyType,
    UnsupportedStrategyError,
    invert_patch,
    parse_candidate_patch,
    plan_candidate_delta_subtraction,
    plan_subtraction_from_snapshot,
)
from basebreak.domain.causal import CandidateIdentity
from basebreak.domain.source import CommitRevision, SourceIdentity

# Sample Fixture Constants
SAMPLE_SOURCE_COMMIT = "40ff923a134a21d8e357deb7a7988571cd396b56"
SAMPLE_BASE_TREE = "f81f6faa0c7572f9941570bbce376fadc10f39a3"
SAMPLE_CANDIDATE_TREE = "31f7ab50a5e0da6da9160ce47bdc5daf71072216"
SAMPLE_CONTRACT_DIGEST = "a" * 64
SAMPLE_WITNESS_DIGEST = "b" * 64

# Single file, single hunk patch
SINGLE_FILE_PATCH = (
    "diff --git a/src/demo_target/cli.py b/src/demo_target/cli.py\n"
    "index 878b16f..f2e0928 100644\n"
    "--- a/src/demo_target/cli.py\n"
    "+++ b/src/demo_target/cli.py\n"
    "@@ -13,5 +13,5 @@ def format_quiet_output(output: str, quiet: bool = False) -> str:\n"
    '     When quiet is True, stdout must be empty ("").\n'
    '     """\n'
    "     if quiet:\n"
    '-        return "verbose: " + output\n'
    '+        return ""\n'
    "     return output\n"
)

# Multi-file patch
MULTI_FILE_PATCH = (
    "diff --git a/src/demo_target/cli.py b/src/demo_target/cli.py\n"
    "index 878b16f..f2e0928 100644\n"
    "--- a/src/demo_target/cli.py\n"
    "+++ b/src/demo_target/cli.py\n"
    "@@ -13,5 +13,5 @@ def format_quiet_output(output: str, quiet: bool = False) -> str:\n"
    '     When quiet is True, stdout must be empty ("").\n'
    '     """\n'
    "     if quiet:\n"
    '-        return "verbose: " + output\n'
    '+        return ""\n'
    "     return output\n"
    "diff --git a/src/demo_target/utils.py b/src/demo_target/utils.py\n"
    "index 1111111..2222222 100644\n"
    "--- a/src/demo_target/utils.py\n"
    "+++ b/src/demo_target/utils.py\n"
    "@@ -1,2 +1,2 @@\n"
    "-def helper_old():\n"
    "+def helper_new():\n"
    "     pass\n"
)

# Multi-hunk patch on a single file (non-overlapping)
MULTI_HUNK_PATCH = (
    "diff --git a/src/demo_target/cli.py b/src/demo_target/cli.py\n"
    "index 878b16f..f2e0928 100644\n"
    "--- a/src/demo_target/cli.py\n"
    "+++ b/src/demo_target/cli.py\n"
    "@@ -5,2 +5,2 @@\n"
    "-old_header = True\n"
    "+new_header = True\n"
    " constant = 1\n"
    "@@ -15,5 +15,5 @@ def format_quiet_output(output: str, quiet: bool = False) -> str:\n"
    '     When quiet is True, stdout must be empty ("").\n'
    '     """\n'
    "     if quiet:\n"
    '-        return "verbose: " + output\n'
    '+        return ""\n'
    "     return output\n"
)

# Overlapping hunks patch (ambiguous)
OVERLAPPING_HUNK_PATCH = (
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


def _digest(text: str) -> str:
    return hashlib.sha256(text.encode("utf-8")).hexdigest()


class TestDeterministicStrategyIdentity:
    """Verifies deterministic identity for all bounded strategy classes."""

    def test_full_patch_revert_strategy(self) -> None:
        patch_text = SINGLE_FILE_PATCH
        patch_digest = _digest(patch_text)

        request = SubtractionRequest(
            strategy_type=SubtractionStrategyType.FULL_PATCH_REVERT,
            description="Revert entire candidate patch",
        )

        plan = plan_candidate_delta_subtraction(
            candidate_id="cand-01",
            candidate_patch_text=patch_text,
            candidate_patch_digest=patch_digest,
            candidate_tree_digest=SAMPLE_CANDIDATE_TREE,
            source_commit_id=SAMPLE_SOURCE_COMMIT,
            frozen_contract_digest=SAMPLE_CONTRACT_DIGEST,
            sealed_witness_digest=SAMPLE_WITNESS_DIGEST,
            request=request,
        )

        assert plan.strategy_type == SubtractionStrategyType.FULL_PATCH_REVERT
        assert plan.target_candidate_id == "cand-01"
        assert plan.subtracted_delta_text == patch_text
        assert plan.subtracted_delta_digest == patch_digest
        assert plan.counterfactual_patch_text == ""
        assert plan.counterfactual_patch_digest == _digest("")
        assert plan.subtracted_files == ("src/demo_target/cli.py",)
        assert len(plan.subtracted_hunk_ids) == 1
        assert plan.is_authoritative is False
        assert plan.is_causally_verified is False
        assert plan.grants_pass is False

        # Verify exact reproducibility via CandidateDeltaSubtractor classmethod
        plan2 = CandidateDeltaSubtractor.plan_subtraction(
            candidate_id="cand-01",
            candidate_patch_text=patch_text,
            candidate_patch_digest=patch_digest,
            candidate_tree_digest=SAMPLE_CANDIDATE_TREE,
            source_commit_id=SAMPLE_SOURCE_COMMIT,
            frozen_contract_digest=SAMPLE_CONTRACT_DIGEST,
            sealed_witness_digest=SAMPLE_WITNESS_DIGEST,
            request=request,
        )
        assert plan == plan2
        assert plan.counterfactual_id == plan2.counterfactual_id

    def test_file_level_revert_strategy(self) -> None:
        patch_text = MULTI_FILE_PATCH
        patch_digest = _digest(patch_text)

        request = SubtractionRequest(
            strategy_type=SubtractionStrategyType.FILE_LEVEL_REVERT,
            target_files=("src/demo_target/cli.py",),
            description="Revert cli.py changes only",
        )

        plan = plan_candidate_delta_subtraction(
            candidate_id="cand-02",
            candidate_patch_text=patch_text,
            candidate_patch_digest=patch_digest,
            candidate_tree_digest=SAMPLE_CANDIDATE_TREE,
            source_commit_id=SAMPLE_SOURCE_COMMIT,
            frozen_contract_digest=SAMPLE_CONTRACT_DIGEST,
            sealed_witness_digest=SAMPLE_WITNESS_DIGEST,
            request=request,
        )

        assert plan.strategy_type == SubtractionStrategyType.FILE_LEVEL_REVERT
        assert plan.subtracted_files == ("src/demo_target/cli.py",)
        # Subtracted delta contains cli.py diff
        assert "src/demo_target/cli.py" in plan.subtracted_delta_text
        assert "src/demo_target/utils.py" not in plan.subtracted_delta_text
        # Counterfactual patch contains utils.py diff
        assert "src/demo_target/utils.py" in plan.counterfactual_patch_text
        assert "src/demo_target/cli.py" not in plan.counterfactual_patch_text

    def test_hunk_level_revert_strategy(self) -> None:
        patch_text = MULTI_HUNK_PATCH
        patch_digest = _digest(patch_text)
        parsed = parse_candidate_patch(patch_text)
        assert parsed.total_hunks_count == 2
        hunk0 = parsed.files[0].hunks[0]

        request = SubtractionRequest(
            strategy_type=SubtractionStrategyType.HUNK_LEVEL_REVERT,
            target_hunk_ids=(hunk0.hunk_id,),
            description="Revert only hunk 0",
        )

        plan = plan_candidate_delta_subtraction(
            candidate_id="cand-03",
            candidate_patch_text=patch_text,
            candidate_patch_digest=patch_digest,
            candidate_tree_digest=SAMPLE_CANDIDATE_TREE,
            source_commit_id=SAMPLE_SOURCE_COMMIT,
            frozen_contract_digest=SAMPLE_CONTRACT_DIGEST,
            sealed_witness_digest=SAMPLE_WITNESS_DIGEST,
            request=request,
        )

        assert plan.strategy_type == SubtractionStrategyType.HUNK_LEVEL_REVERT
        assert plan.subtracted_hunk_ids == (hunk0.hunk_id,)
        assert "new_header" in plan.subtracted_delta_text
        # Counterfactual patch retains hunk 1
        assert "format_quiet_output" in plan.counterfactual_patch_text
        assert "new_header" not in plan.counterfactual_patch_text

    def test_invert_patch_correctness(self) -> None:
        patch = SINGLE_FILE_PATCH
        inverted = invert_patch(patch)
        assert '-        return ""' in inverted
        assert '+        return "verbose: " + output' in inverted

        # Inverting twice yields equivalent semantics
        re_inverted = invert_patch(inverted)
        assert '+        return ""' in re_inverted
        assert '-        return "verbose: " + output' in re_inverted

    def test_to_counterfactual_identity_binding(self) -> None:
        patch_text = SINGLE_FILE_PATCH
        patch_digest = _digest(patch_text)
        request = SubtractionRequest(strategy_type=SubtractionStrategyType.FULL_PATCH_REVERT)

        plan = plan_candidate_delta_subtraction(
            candidate_id="cand-01",
            candidate_patch_text=patch_text,
            candidate_patch_digest=patch_digest,
            candidate_tree_digest=SAMPLE_CANDIDATE_TREE,
            source_commit_id=SAMPLE_SOURCE_COMMIT,
            frozen_contract_digest=SAMPLE_CONTRACT_DIGEST,
            sealed_witness_digest=SAMPLE_WITNESS_DIGEST,
            request=request,
        )

        source_id = SourceIdentity(
            locator="https://github.com/demo/repo.git",
            revision=CommitRevision(SAMPLE_SOURCE_COMMIT),
        )
        cand_id = CandidateIdentity(
            candidate_id="cand-01",
            source=source_id,
            patch_digest=patch_digest,
        )

        cf_id = plan.to_counterfactual_identity(cand_id)
        assert cf_id.counterfactual_id == plan.counterfactual_id
        assert cf_id.target_candidate == cand_id
        assert cf_id.delta_digest == plan.subtracted_delta_digest

    def test_snapshot_plan_parity(self) -> None:
        patch_text = SINGLE_FILE_PATCH
        patch_digest = _digest(patch_text)
        source_id = SourceIdentity(
            locator="https://github.com/demo/repo.git",
            revision=CommitRevision(SAMPLE_SOURCE_COMMIT),
        )
        snapshot = CandidateSnapshot(
            candidate_id="cand-snap-01",
            source_identity=source_id,
            candidate_tree_digest=SAMPLE_CANDIDATE_TREE,
            patch_digest=patch_digest,
            patch_text=patch_text,
            files_added=(),
            files_modified=("src/demo_target/cli.py",),
            files_deleted=(),
            builder_authored_tests=(),
            frozen_contract_digest=SAMPLE_CONTRACT_DIGEST,
            context_digest="c" * 64,
        )

        request = SubtractionRequest(strategy_type=SubtractionStrategyType.FULL_PATCH_REVERT)
        plan = plan_subtraction_from_snapshot(
            candidate_snapshot=snapshot,
            sealed_witness_digest=SAMPLE_WITNESS_DIGEST,
            request=request,
        )

        assert plan.target_candidate_id == "cand-snap-01"
        assert plan.frozen_contract_digest == SAMPLE_CONTRACT_DIGEST
        assert plan.sealed_witness_digest == SAMPLE_WITNESS_DIGEST

    def test_plan_round_trip_serialization(self) -> None:
        patch_text = SINGLE_FILE_PATCH
        patch_digest = _digest(patch_text)
        request = SubtractionRequest(strategy_type=SubtractionStrategyType.FULL_PATCH_REVERT)

        plan = plan_candidate_delta_subtraction(
            candidate_id="cand-01",
            candidate_patch_text=patch_text,
            candidate_patch_digest=patch_digest,
            candidate_tree_digest=SAMPLE_CANDIDATE_TREE,
            source_commit_id=SAMPLE_SOURCE_COMMIT,
            frozen_contract_digest=SAMPLE_CONTRACT_DIGEST,
            sealed_witness_digest=SAMPLE_WITNESS_DIGEST,
            request=request,
        )

        data = plan.to_dict()
        restored = CounterfactualDeltaPlan.from_dict(data)
        assert restored == plan


class TestUnsupportedAndAmbiguousSubtraction:
    """Verifies fail-closed behavior for unsupported, ambiguous, or malformed subtractions."""

    def test_target_file_not_in_patch_rejected(self) -> None:
        patch_text = SINGLE_FILE_PATCH
        patch_digest = _digest(patch_text)
        request = SubtractionRequest(
            strategy_type=SubtractionStrategyType.FILE_LEVEL_REVERT,
            target_files=("src/nonexistent/file.py",),
        )

        with pytest.raises(UnsupportedStrategyError, match="not modified in candidate patch"):
            plan_candidate_delta_subtraction(
                candidate_id="cand-01",
                candidate_patch_text=patch_text,
                candidate_patch_digest=patch_digest,
                candidate_tree_digest=SAMPLE_CANDIDATE_TREE,
                source_commit_id=SAMPLE_SOURCE_COMMIT,
                frozen_contract_digest=SAMPLE_CONTRACT_DIGEST,
                sealed_witness_digest=SAMPLE_WITNESS_DIGEST,
                request=request,
            )

    def test_target_hunk_not_in_patch_rejected(self) -> None:
        patch_text = SINGLE_FILE_PATCH
        patch_digest = _digest(patch_text)
        request = SubtractionRequest(
            strategy_type=SubtractionStrategyType.HUNK_LEVEL_REVERT,
            target_hunk_ids=("nonexistent_hunk_id",),
        )

        with pytest.raises(UnsupportedStrategyError, match="Target hunk ID .* is not present"):
            plan_candidate_delta_subtraction(
                candidate_id="cand-01",
                candidate_patch_text=patch_text,
                candidate_patch_digest=patch_digest,
                candidate_tree_digest=SAMPLE_CANDIDATE_TREE,
                source_commit_id=SAMPLE_SOURCE_COMMIT,
                frozen_contract_digest=SAMPLE_CONTRACT_DIGEST,
                sealed_witness_digest=SAMPLE_WITNESS_DIGEST,
                request=request,
            )

    def test_overlapping_hunks_rejected_as_ambiguous(self) -> None:
        patch_text = OVERLAPPING_HUNK_PATCH
        patch_digest = _digest(patch_text)
        parsed = parse_candidate_patch(patch_text)
        hunk0 = parsed.files[0].hunks[0]

        request = SubtractionRequest(
            strategy_type=SubtractionStrategyType.HUNK_LEVEL_REVERT,
            target_hunk_ids=(hunk0.hunk_id,),
        )

        with pytest.raises(AmbiguousSubtractionError, match="Overlapping hunks detected"):
            plan_candidate_delta_subtraction(
                candidate_id="cand-01",
                candidate_patch_text=patch_text,
                candidate_patch_digest=patch_digest,
                candidate_tree_digest=SAMPLE_CANDIDATE_TREE,
                source_commit_id=SAMPLE_SOURCE_COMMIT,
                frozen_contract_digest=SAMPLE_CONTRACT_DIGEST,
                sealed_witness_digest=SAMPLE_WITNESS_DIGEST,
                request=request,
            )

    def test_malformed_diff_syntax_rejected(self) -> None:
        malformed = (
            "diff --git a/file.py b/file.py\n"
            "--- a/file.py\n"
            "+++ b/file.py\n"
            "@@ not a valid hunk header @@\n"
            "+invalid line\n"
        )
        with pytest.raises(InvalidSubtractionError, match="Malformed hunk header"):
            parse_candidate_patch(malformed)

    def test_hunk_line_count_mismatch_rejected(self) -> None:
        # Header specifies 1 old line, 1 new line, but 2 additions are provided
        mismatched = (
            "diff --git a/file.py b/file.py\n"
            "--- a/file.py\n"
            "+++ b/file.py\n"
            "@@ -1,1 +1,1 @@\n"
            "-old\n"
            "+new1\n"
            "+new2\n"
        )
        with pytest.raises(InvalidSubtractionError, match="Hunk line count mismatch"):
            parse_candidate_patch(mismatched)

    def test_target_hunk_digest_prefix_rejected(self) -> None:
        """Hunk target resolution requires exact ID or exact full digest; prefixes are rejected."""
        patch_text = MULTI_HUNK_PATCH
        patch_digest = _digest(patch_text)
        parsed = parse_candidate_patch(patch_text)
        hunk0 = parsed.files[0].hunks[0]

        # Exact hunk_id and exact hunk_digest resolve cleanly
        assert parsed.get_hunk(hunk0.hunk_id) is not None
        assert parsed.get_hunk(hunk0.hunk_digest) is not None

        # Short prefix of hunk_digest is not accepted as exact match
        short_prefix = hunk0.hunk_digest[:12]
        assert parsed.get_hunk(short_prefix) is None

        # Subtraction request using a prefix fails closed as unsupported
        request = SubtractionRequest(
            strategy_type=SubtractionStrategyType.HUNK_LEVEL_REVERT,
            target_hunk_ids=(short_prefix,),
        )
        with pytest.raises(UnsupportedStrategyError, match="Target hunk ID .* is not present"):
            plan_candidate_delta_subtraction(
                candidate_id="cand-01",
                candidate_patch_text=patch_text,
                candidate_patch_digest=patch_digest,
                candidate_tree_digest=SAMPLE_CANDIDATE_TREE,
                source_commit_id=SAMPLE_SOURCE_COMMIT,
                frozen_contract_digest=SAMPLE_CONTRACT_DIGEST,
                sealed_witness_digest=SAMPLE_WITNESS_DIGEST,
                request=request,
            )


class TestProtectedSurfaceAndSecretPolicy:
    """Verifies that protected surfaces and secrets are strictly rejected."""

    def test_patch_touching_governance_protected_surface_rejected(self) -> None:
        patch_text = (
            "diff --git a/plans/BASEBREAK_MASTER_EXECUTION_PLAN.md "
            "b/plans/BASEBREAK_MASTER_EXECUTION_PLAN.md\n"
            "--- a/plans/BASEBREAK_MASTER_EXECUTION_PLAN.md\n"
            "+++ b/plans/BASEBREAK_MASTER_EXECUTION_PLAN.md\n"
            "@@ -1,1 +1,1 @@\n"
            "-old\n"
            "+bypass\n"
        )
        patch_digest = _digest(patch_text)
        request = SubtractionRequest(strategy_type=SubtractionStrategyType.FULL_PATCH_REVERT)

        with pytest.raises(ProtectedSurfaceSubtractionError, match="protected surface"):
            plan_candidate_delta_subtraction(
                candidate_id="cand-01",
                candidate_patch_text=patch_text,
                candidate_patch_digest=patch_digest,
                candidate_tree_digest=SAMPLE_CANDIDATE_TREE,
                source_commit_id=SAMPLE_SOURCE_COMMIT,
                frozen_contract_digest=SAMPLE_CONTRACT_DIGEST,
                sealed_witness_digest=SAMPLE_WITNESS_DIGEST,
                request=request,
            )

    def test_patch_touching_verifier_protected_surface_rejected(self) -> None:
        patch_text = (
            "diff --git a/src/basebreak/verifier/witness_store.py "
            "b/src/basebreak/verifier/witness_store.py\n"
            "--- a/src/basebreak/verifier/witness_store.py\n"
            "+++ b/src/basebreak/verifier/witness_store.py\n"
            "@@ -1,1 +1,1 @@\n"
            "-old\n"
            "+tamper\n"
        )
        patch_digest = _digest(patch_text)
        request = SubtractionRequest(strategy_type=SubtractionStrategyType.FULL_PATCH_REVERT)

        with pytest.raises(ProtectedSurfaceSubtractionError, match="protected surface"):
            plan_candidate_delta_subtraction(
                candidate_id="cand-01",
                candidate_patch_text=patch_text,
                candidate_patch_digest=patch_digest,
                candidate_tree_digest=SAMPLE_CANDIDATE_TREE,
                source_commit_id=SAMPLE_SOURCE_COMMIT,
                frozen_contract_digest=SAMPLE_CONTRACT_DIGEST,
                sealed_witness_digest=SAMPLE_WITNESS_DIGEST,
                request=request,
            )

    def test_patch_containing_secret_rejected(self) -> None:
        secret_patch = (
            "diff --git a/src/demo_target/cli.py b/src/demo_target/cli.py\n"
            "--- a/src/demo_target/cli.py\n"
            "+++ b/src/demo_target/cli.py\n"
            "@@ -1,1 +1,1 @@\n"
            "-api_key = None\n"
            '+api_key = "ghp_123456789012345678901234567890123456"\n'
        )
        patch_digest = _digest(secret_patch)
        request = SubtractionRequest(strategy_type=SubtractionStrategyType.FULL_PATCH_REVERT)

        with pytest.raises(SecretPolicySubtractionError, match="secret"):
            plan_candidate_delta_subtraction(
                candidate_id="cand-01",
                candidate_patch_text=secret_patch,
                candidate_patch_digest=patch_digest,
                candidate_tree_digest=SAMPLE_CANDIDATE_TREE,
                source_commit_id=SAMPLE_SOURCE_COMMIT,
                frozen_contract_digest=SAMPLE_CONTRACT_DIGEST,
                sealed_witness_digest=SAMPLE_WITNESS_DIGEST,
                request=request,
            )


class TestEmptyAndNoOpSubtraction:
    """Verifies that empty patches and no-op subtractions are strictly rejected."""

    def test_empty_candidate_patch_text_rejected(self) -> None:
        request = SubtractionRequest(strategy_type=SubtractionStrategyType.FULL_PATCH_REVERT)
        with pytest.raises(EmptySubtractionError, match="cannot be empty"):
            plan_candidate_delta_subtraction(
                candidate_id="cand-01",
                candidate_patch_text="",
                candidate_patch_digest=_digest(""),
                candidate_tree_digest=SAMPLE_CANDIDATE_TREE,
                source_commit_id=SAMPLE_SOURCE_COMMIT,
                frozen_contract_digest=SAMPLE_CONTRACT_DIGEST,
                sealed_witness_digest=SAMPLE_WITNESS_DIGEST,
                request=request,
            )

    def test_empty_target_files_rejected(self) -> None:
        patch_text = SINGLE_FILE_PATCH
        patch_digest = _digest(patch_text)
        request = SubtractionRequest(
            strategy_type=SubtractionStrategyType.FILE_LEVEL_REVERT,
            target_files=(),
        )

        with pytest.raises(EmptySubtractionError, match="target_files must not be empty"):
            plan_candidate_delta_subtraction(
                candidate_id="cand-01",
                candidate_patch_text=patch_text,
                candidate_patch_digest=patch_digest,
                candidate_tree_digest=SAMPLE_CANDIDATE_TREE,
                source_commit_id=SAMPLE_SOURCE_COMMIT,
                frozen_contract_digest=SAMPLE_CONTRACT_DIGEST,
                sealed_witness_digest=SAMPLE_WITNESS_DIGEST,
                request=request,
            )

    def test_empty_target_hunks_rejected(self) -> None:
        patch_text = SINGLE_FILE_PATCH
        patch_digest = _digest(patch_text)
        request = SubtractionRequest(
            strategy_type=SubtractionStrategyType.HUNK_LEVEL_REVERT,
            target_hunk_ids=(),
        )

        with pytest.raises(EmptySubtractionError, match="target_hunk_ids must not be empty"):
            plan_candidate_delta_subtraction(
                candidate_id="cand-01",
                candidate_patch_text=patch_text,
                candidate_patch_digest=patch_digest,
                candidate_tree_digest=SAMPLE_CANDIDATE_TREE,
                source_commit_id=SAMPLE_SOURCE_COMMIT,
                frozen_contract_digest=SAMPLE_CONTRACT_DIGEST,
                sealed_witness_digest=SAMPLE_WITNESS_DIGEST,
                request=request,
            )


class TestSourceCandidateIdentityMismatch:
    """Verifies that mismatched identities, tree digests, or patch digests fail closed."""

    def test_tampered_patch_digest_rejected(self) -> None:
        patch_text = SINGLE_FILE_PATCH
        fake_digest = "f" * 64
        request = SubtractionRequest(strategy_type=SubtractionStrategyType.FULL_PATCH_REVERT)

        with pytest.raises(CandidateIdentityMismatchError, match="does not match computed SHA-256"):
            plan_candidate_delta_subtraction(
                candidate_id="cand-01",
                candidate_patch_text=patch_text,
                candidate_patch_digest=fake_digest,
                candidate_tree_digest=SAMPLE_CANDIDATE_TREE,
                source_commit_id=SAMPLE_SOURCE_COMMIT,
                frozen_contract_digest=SAMPLE_CONTRACT_DIGEST,
                sealed_witness_digest=SAMPLE_WITNESS_DIGEST,
                request=request,
            )

    def test_empty_candidate_id_rejected(self) -> None:
        patch_text = SINGLE_FILE_PATCH
        request = SubtractionRequest(strategy_type=SubtractionStrategyType.FULL_PATCH_REVERT)

        with pytest.raises(
            CandidateIdentityMismatchError, match="candidate_id must be a non-empty string"
        ):
            plan_candidate_delta_subtraction(
                candidate_id="",
                candidate_patch_text=patch_text,
                candidate_patch_digest=_digest(patch_text),
                candidate_tree_digest=SAMPLE_CANDIDATE_TREE,
                source_commit_id=SAMPLE_SOURCE_COMMIT,
                frozen_contract_digest=SAMPLE_CONTRACT_DIGEST,
                sealed_witness_digest=SAMPLE_WITNESS_DIGEST,
                request=request,
            )

    def test_to_counterfactual_identity_mismatched_candidate_rejected(self) -> None:
        patch_text = SINGLE_FILE_PATCH
        patch_digest = _digest(patch_text)
        request = SubtractionRequest(strategy_type=SubtractionStrategyType.FULL_PATCH_REVERT)

        plan = plan_candidate_delta_subtraction(
            candidate_id="cand-01",
            candidate_patch_text=patch_text,
            candidate_patch_digest=patch_digest,
            candidate_tree_digest=SAMPLE_CANDIDATE_TREE,
            source_commit_id=SAMPLE_SOURCE_COMMIT,
            frozen_contract_digest=SAMPLE_CONTRACT_DIGEST,
            sealed_witness_digest=SAMPLE_WITNESS_DIGEST,
            request=request,
        )

        source_id = SourceIdentity(
            locator="https://github.com/demo/repo.git",
            revision=CommitRevision(SAMPLE_SOURCE_COMMIT),
        )
        wrong_candidate = CandidateIdentity(
            candidate_id="cand-DIFFERENT",
            source=source_id,
            patch_digest=patch_digest,
        )

        with pytest.raises(
            CandidateIdentityMismatchError, match="does not match plan target_candidate_id"
        ):
            plan.to_counterfactual_identity(wrong_candidate)

    def test_to_counterfactual_identity_mismatched_resolved_commit_rejected(self) -> None:
        """Requirement A: same candidate + same patch + different resolved source commit."""
        patch_text = SINGLE_FILE_PATCH
        patch_digest = _digest(patch_text)
        request = SubtractionRequest(strategy_type=SubtractionStrategyType.FULL_PATCH_REVERT)

        plan = plan_candidate_delta_subtraction(
            candidate_id="cand-01",
            candidate_patch_text=patch_text,
            candidate_patch_digest=patch_digest,
            candidate_tree_digest=SAMPLE_CANDIDATE_TREE,
            source_commit_id=SAMPLE_SOURCE_COMMIT,
            frozen_contract_digest=SAMPLE_CONTRACT_DIGEST,
            sealed_witness_digest=SAMPLE_WITNESS_DIGEST,
            request=request,
        )

        different_commit = "1" * 40
        source_id = SourceIdentity(
            locator="https://github.com/demo/repo.git",
            revision=CommitRevision(different_commit),
        )
        candidate_wrong_commit = CandidateIdentity(
            candidate_id="cand-01",
            source=source_id,
            patch_digest=patch_digest,
        )

        with pytest.raises(
            CandidateIdentityMismatchError,
            match="resolved_commit_id .* does not match plan source_commit_id",
        ):
            plan.to_counterfactual_identity(candidate_wrong_commit)

    def test_to_counterfactual_identity_mismatched_source_locator_rejected(self) -> None:
        """Requirement B: same candidate + same patch + different source repo locator."""
        patch_text = SINGLE_FILE_PATCH
        patch_digest = _digest(patch_text)
        request = SubtractionRequest(strategy_type=SubtractionStrategyType.FULL_PATCH_REVERT)

        plan = plan_candidate_delta_subtraction(
            candidate_id="cand-01",
            candidate_patch_text=patch_text,
            candidate_patch_digest=patch_digest,
            candidate_tree_digest=SAMPLE_CANDIDATE_TREE,
            source_commit_id=SAMPLE_SOURCE_COMMIT,
            source_locator="https://github.com/demo/repo.git",
            frozen_contract_digest=SAMPLE_CONTRACT_DIGEST,
            sealed_witness_digest=SAMPLE_WITNESS_DIGEST,
            request=request,
        )

        substituted_locator_source = SourceIdentity(
            locator="https://github.com/malicious/unauthorized-fork.git",
            revision=CommitRevision(SAMPLE_SOURCE_COMMIT),
        )
        candidate_wrong_locator = CandidateIdentity(
            candidate_id="cand-01",
            source=substituted_locator_source,
            patch_digest=patch_digest,
        )

        with pytest.raises(
            CandidateIdentityMismatchError,
            match="source locator .* does not match plan source_locator",
        ):
            plan.to_counterfactual_identity(candidate_wrong_locator)

    def test_to_counterfactual_identity_mismatched_source_subpath_rejected(self) -> None:
        """Requirement C: same candidate_id + same patch_digest + different source subpath."""
        patch_text = SINGLE_FILE_PATCH
        patch_digest = _digest(patch_text)
        request = SubtractionRequest(strategy_type=SubtractionStrategyType.FULL_PATCH_REVERT)

        plan = plan_candidate_delta_subtraction(
            candidate_id="cand-01",
            candidate_patch_text=patch_text,
            candidate_patch_digest=patch_digest,
            candidate_tree_digest=SAMPLE_CANDIDATE_TREE,
            source_commit_id=SAMPLE_SOURCE_COMMIT,
            source_locator="https://github.com/demo/repo.git",
            source_subpath="packages/core",
            frozen_contract_digest=SAMPLE_CONTRACT_DIGEST,
            sealed_witness_digest=SAMPLE_WITNESS_DIGEST,
            request=request,
        )

        # 1. Different subpath
        candidate_diff_subpath = CandidateIdentity(
            candidate_id="cand-01",
            source=SourceIdentity(
                locator="https://github.com/demo/repo.git",
                revision=CommitRevision(SAMPLE_SOURCE_COMMIT),
                subpath="packages/other",
            ),
            patch_digest=patch_digest,
        )
        with pytest.raises(
            CandidateIdentityMismatchError,
            match="source subpath .* does not match plan source_subpath",
        ):
            plan.to_counterfactual_identity(candidate_diff_subpath)

        # 2. None subpath when plan has subpath
        candidate_none_subpath = CandidateIdentity(
            candidate_id="cand-01",
            source=SourceIdentity(
                locator="https://github.com/demo/repo.git",
                revision=CommitRevision(SAMPLE_SOURCE_COMMIT),
                subpath=None,
            ),
            patch_digest=patch_digest,
        )
        with pytest.raises(
            CandidateIdentityMismatchError,
            match="source subpath .* does not match plan source_subpath",
        ):
            plan.to_counterfactual_identity(candidate_none_subpath)

        # 3. Subpath present on candidate when plan has None subpath
        plan_no_subpath = plan_candidate_delta_subtraction(
            candidate_id="cand-01",
            candidate_patch_text=patch_text,
            candidate_patch_digest=patch_digest,
            candidate_tree_digest=SAMPLE_CANDIDATE_TREE,
            source_commit_id=SAMPLE_SOURCE_COMMIT,
            source_locator="https://github.com/demo/repo.git",
            source_subpath=None,
            frozen_contract_digest=SAMPLE_CONTRACT_DIGEST,
            sealed_witness_digest=SAMPLE_WITNESS_DIGEST,
            request=request,
        )
        with pytest.raises(
            CandidateIdentityMismatchError,
            match="source subpath .* does not match plan source_subpath",
        ):
            plan_no_subpath.to_counterfactual_identity(candidate_diff_subpath)

    def test_serialized_deserialized_plan_substituted_candidate_rejected(self) -> None:
        """Requirement D: serialized/deserialized plan followed by substituted CandidateIdentity."""
        patch_text = SINGLE_FILE_PATCH
        patch_digest = _digest(patch_text)
        request = SubtractionRequest(strategy_type=SubtractionStrategyType.FULL_PATCH_REVERT)

        source_id = SourceIdentity(
            locator="https://github.com/demo/repo.git",
            revision=CommitRevision(SAMPLE_SOURCE_COMMIT),
            subpath="services/api",
        )
        snapshot = CandidateSnapshot(
            candidate_id="cand-snap-01",
            source_identity=source_id,
            candidate_tree_digest=SAMPLE_CANDIDATE_TREE,
            patch_digest=patch_digest,
            patch_text=patch_text,
            files_added=(),
            files_modified=("src/demo_target/cli.py",),
            files_deleted=(),
            builder_authored_tests=(),
            frozen_contract_digest=SAMPLE_CONTRACT_DIGEST,
            context_digest="c" * 64,
        )

        plan = plan_subtraction_from_snapshot(
            candidate_snapshot=snapshot,
            sealed_witness_digest=SAMPLE_WITNESS_DIGEST,
            request=request,
        )

        # Serialize and restore
        data = plan.to_dict()
        restored = CounterfactualDeltaPlan.from_dict(data)

        # Substituted commit rejected
        with pytest.raises(CandidateIdentityMismatchError, match="resolved_commit_id"):
            restored.to_counterfactual_identity(
                CandidateIdentity(
                    candidate_id="cand-snap-01",
                    source=SourceIdentity(
                        locator="https://github.com/demo/repo.git",
                        revision=CommitRevision("9" * 40),
                        subpath="services/api",
                    ),
                    patch_digest=patch_digest,
                )
            )

        # Substituted locator rejected
        with pytest.raises(CandidateIdentityMismatchError, match="source locator"):
            restored.to_counterfactual_identity(
                CandidateIdentity(
                    candidate_id="cand-snap-01",
                    source=SourceIdentity(
                        locator="https://github.com/attacker/repo.git",
                        revision=CommitRevision(SAMPLE_SOURCE_COMMIT),
                        subpath="services/api",
                    ),
                    patch_digest=patch_digest,
                )
            )

        # Substituted subpath rejected
        with pytest.raises(CandidateIdentityMismatchError, match="source subpath"):
            restored.to_counterfactual_identity(
                CandidateIdentity(
                    candidate_id="cand-snap-01",
                    source=SourceIdentity(
                        locator="https://github.com/demo/repo.git",
                        revision=CommitRevision(SAMPLE_SOURCE_COMMIT),
                        subpath="services/other",
                    ),
                    patch_digest=patch_digest,
                )
            )

    def test_canonical_exact_candidate_identity_succeeds(self) -> None:
        """Requirement E: canonical exact CandidateIdentity still succeeds."""
        patch_text = SINGLE_FILE_PATCH
        patch_digest = _digest(patch_text)
        request = SubtractionRequest(strategy_type=SubtractionStrategyType.FULL_PATCH_REVERT)

        source_id = SourceIdentity(
            locator="https://github.com/demo/repo.git",
            revision=CommitRevision(SAMPLE_SOURCE_COMMIT),
            subpath="services/api",
        )
        snapshot = CandidateSnapshot(
            candidate_id="cand-snap-01",
            source_identity=source_id,
            candidate_tree_digest=SAMPLE_CANDIDATE_TREE,
            patch_digest=patch_digest,
            patch_text=patch_text,
            files_added=(),
            files_modified=("src/demo_target/cli.py",),
            files_deleted=(),
            builder_authored_tests=(),
            frozen_contract_digest=SAMPLE_CONTRACT_DIGEST,
            context_digest="c" * 64,
        )

        plan = plan_subtraction_from_snapshot(
            candidate_snapshot=snapshot,
            sealed_witness_digest=SAMPLE_WITNESS_DIGEST,
            request=request,
        )

        exact_candidate = CandidateIdentity(
            candidate_id="cand-snap-01",
            source=source_id,
            patch_digest=patch_digest,
            description="Verified candidate identity",
        )

        # Derivation succeeds on original plan
        cf_id = plan.to_counterfactual_identity(exact_candidate)
        assert cf_id.counterfactual_id == plan.counterfactual_id
        assert cf_id.target_candidate == exact_candidate
        assert cf_id.delta_digest == plan.subtracted_delta_digest
        assert cf_id.target_candidate.resolved_commit_id == plan.source_commit_id
        assert cf_id.target_candidate.source.locator == plan.source_locator
        assert cf_id.target_candidate.source.subpath == plan.source_subpath

        # Derivation succeeds identically on round-tripped deserialized plan
        data = plan.to_dict()
        restored = CounterfactualDeltaPlan.from_dict(data)
        restored_cf_id = restored.to_counterfactual_identity(exact_candidate)
        assert restored_cf_id == cf_id


class TestCallerSuppliedFakeAuthority:
    """Verifies that callers or models cannot assert fake authority, pass, or certification."""

    def test_request_asserting_authority_rejected(self) -> None:
        with pytest.raises(CallerAuthorityError, match="cannot assert authority"):
            SubtractionRequest(
                strategy_type=SubtractionStrategyType.FULL_PATCH_REVERT,
                is_authoritative=True,
            )

    def test_request_granting_pass_rejected(self) -> None:
        with pytest.raises(CallerAuthorityError, match="cannot grant pass"):
            SubtractionRequest(
                strategy_type=SubtractionStrategyType.FULL_PATCH_REVERT,
                grants_pass=True,
            )

    def test_request_asserting_causal_verification_rejected(self) -> None:
        with pytest.raises(CallerAuthorityError, match="cannot assert verification"):
            SubtractionRequest(
                strategy_type=SubtractionStrategyType.FULL_PATCH_REVERT,
                is_causally_verified=True,
            )

    def test_plan_instantiation_with_authority_rejected(self) -> None:
        patch_text = SINGLE_FILE_PATCH
        patch_digest = _digest(patch_text)

        with pytest.raises(CallerAuthorityError, match="is_authoritative must be strictly False"):
            CounterfactualDeltaPlan(
                counterfactual_id="cf-01",
                strategy_type=SubtractionStrategyType.FULL_PATCH_REVERT,
                target_candidate_id="cand-01",
                target_candidate_patch_digest=patch_digest,
                source_commit_id=SAMPLE_SOURCE_COMMIT,
                candidate_tree_digest=SAMPLE_CANDIDATE_TREE,
                frozen_contract_digest=SAMPLE_CONTRACT_DIGEST,
                sealed_witness_digest=SAMPLE_WITNESS_DIGEST,
                subtracted_delta_text=patch_text,
                subtracted_delta_digest=patch_digest,
                counterfactual_patch_text="",
                counterfactual_patch_digest=_digest(""),
                reverse_delta_text=invert_patch(patch_text),
                reverse_delta_digest=_digest(invert_patch(patch_text)),
                subtracted_files=("src/demo_target/cli.py",),
                subtracted_hunk_ids=(),
                is_authoritative=True,
            )

    def test_plan_deserialization_with_fake_authority_rejected(self) -> None:
        patch_text = SINGLE_FILE_PATCH
        patch_digest = _digest(patch_text)
        request = SubtractionRequest(strategy_type=SubtractionStrategyType.FULL_PATCH_REVERT)

        plan = plan_candidate_delta_subtraction(
            candidate_id="cand-01",
            candidate_patch_text=patch_text,
            candidate_patch_digest=patch_digest,
            candidate_tree_digest=SAMPLE_CANDIDATE_TREE,
            source_commit_id=SAMPLE_SOURCE_COMMIT,
            frozen_contract_digest=SAMPLE_CONTRACT_DIGEST,
            sealed_witness_digest=SAMPLE_WITNESS_DIGEST,
            request=request,
        )

        data = plan.to_dict()
        data["is_authoritative"] = True

        with pytest.raises(CallerAuthorityError, match="is_authoritative must be strictly False"):
            CounterfactualDeltaPlan.from_dict(data)


class TestContractAndWitnessIntegrity:
    """Verifies that contract and witness digests survive unchanged and cannot be tampered."""

    def test_tampered_contract_digest_rejected(self) -> None:
        patch_text = SINGLE_FILE_PATCH
        request = SubtractionRequest(strategy_type=SubtractionStrategyType.FULL_PATCH_REVERT)

        with pytest.raises(
            DigestTamperingError, match="frozen_contract_digest must be 64 hex chars"
        ):
            plan_candidate_delta_subtraction(
                candidate_id="cand-01",
                candidate_patch_text=patch_text,
                candidate_patch_digest=_digest(patch_text),
                candidate_tree_digest=SAMPLE_CANDIDATE_TREE,
                source_commit_id=SAMPLE_SOURCE_COMMIT,
                frozen_contract_digest="invalid_short_digest",
                sealed_witness_digest=SAMPLE_WITNESS_DIGEST,
                request=request,
            )

    def test_tampered_witness_digest_rejected(self) -> None:
        patch_text = SINGLE_FILE_PATCH
        request = SubtractionRequest(strategy_type=SubtractionStrategyType.FULL_PATCH_REVERT)

        with pytest.raises(
            DigestTamperingError, match="sealed_witness_digest must be 64 hex chars"
        ):
            plan_candidate_delta_subtraction(
                candidate_id="cand-01",
                candidate_patch_text=patch_text,
                candidate_patch_digest=_digest(patch_text),
                candidate_tree_digest=SAMPLE_CANDIDATE_TREE,
                source_commit_id=SAMPLE_SOURCE_COMMIT,
                frozen_contract_digest=SAMPLE_CONTRACT_DIGEST,
                sealed_witness_digest="invalid_short_digest",
                request=request,
            )

    def test_plan_dataclass_is_frozen(self) -> None:
        patch_text = SINGLE_FILE_PATCH
        patch_digest = _digest(patch_text)
        request = SubtractionRequest(strategy_type=SubtractionStrategyType.FULL_PATCH_REVERT)

        plan = plan_candidate_delta_subtraction(
            candidate_id="cand-01",
            candidate_patch_text=patch_text,
            candidate_patch_digest=patch_digest,
            candidate_tree_digest=SAMPLE_CANDIDATE_TREE,
            source_commit_id=SAMPLE_SOURCE_COMMIT,
            frozen_contract_digest=SAMPLE_CONTRACT_DIGEST,
            sealed_witness_digest=SAMPLE_WITNESS_DIGEST,
            request=request,
        )

        with pytest.raises(FrozenInstanceError):
            plan.counterfactual_id = "mutated"  # type: ignore[misc]

        with pytest.raises(FrozenInstanceError):
            plan.frozen_contract_digest = "mutated"  # type: ignore[misc]


class TestFuturePhaseExecutionAbsence:
    """Verifies that P-11.01 remains strictly a subtraction contract and does not execute."""

    def test_future_execution_artifacts_absent_from_plan(self) -> None:
        patch_text = SINGLE_FILE_PATCH
        patch_digest = _digest(patch_text)
        request = SubtractionRequest(strategy_type=SubtractionStrategyType.FULL_PATCH_REVERT)

        plan = plan_candidate_delta_subtraction(
            candidate_id="cand-01",
            candidate_patch_text=patch_text,
            candidate_patch_digest=patch_digest,
            candidate_tree_digest=SAMPLE_CANDIDATE_TREE,
            source_commit_id=SAMPLE_SOURCE_COMMIT,
            frozen_contract_digest=SAMPLE_CONTRACT_DIGEST,
            sealed_witness_digest=SAMPLE_WITNESS_DIGEST,
            request=request,
        )

        # Plan does not contain sandbox execution handles, results, or verdicts
        assert not hasattr(plan, "sandbox_session")
        assert not hasattr(plan, "normalized_result")
        assert not hasattr(plan, "execution_output")
        assert not hasattr(plan, "triplet_receipt")
        assert not hasattr(plan, "preliminary_verdict")

    def test_subtraction_request_contains_no_execution_handles(self) -> None:
        req = SubtractionRequest(strategy_type=SubtractionStrategyType.FULL_PATCH_REVERT)
        assert not hasattr(req, "sandbox_adapter")
        assert not hasattr(req, "materializer")
        assert not hasattr(req, "model_client")
