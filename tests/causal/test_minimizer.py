"""Unit tests for P-12.02: Bounded hunk/subset minimization algorithm."""

from __future__ import annotations

import pytest

from basebreak.builder.capture import CandidateSnapshot
from basebreak.causal.minimizer import (
    BoundedMinimizerResult,
    BoundedSubsetMinimizer,
    PatchUnit,
    SliceSearchBudget,
    create_tested_patch_subset_from_hunks,
)
from basebreak.causal.slice import (
    CausalSliceStatus,
    ModelSliceProposal,
    SliceAuthorityError,
    SliceSearchCompleteness,
    TestedPatchSubset,
)
from basebreak.causal.subtraction import parse_candidate_patch
from basebreak.domain.source import CommitRevision, SourceIdentity
from basebreak.domain.verdict import EvidenceProvenance
from basebreak.evidence.artifact import compute_bytes_digest
from basebreak.verifier.witness_result import WitnessOutcome

FROZEN_CONTRACT = "a" * 64
SEALED_WITNESS = "b" * 64
BASE_COMMIT = "c" * 40
CAND_TREE = "d" * 40
REPO_LOCATOR = "https://github.com/example/repo.git"
REQ_ID = "REQ-MIN-001"

TWO_HUNK_PATCH = (
    "diff --git a/src/calc.py b/src/calc.py\n"
    "index 1111111..2222222 100644\n"
    "--- a/src/calc.py\n"
    "+++ b/src/calc.py\n"
    "@@ -1,2 +1,3 @@\n"
    " def add(a, b):\n"
    "+    # Necessary fix\n"
    "     return a + b\n"
    "@@ -10,2 +11,3 @@\n"
    " def sub(a, b):\n"
    "+    # Irrelevant comment\n"
    "     return a - b\n"
)

SINGLE_HUNK_PATCH = (
    "diff --git a/src/calc.py b/src/calc.py\n"
    "index 1111111..2222222 100644\n"
    "--- a/src/calc.py\n"
    "+++ b/src/calc.py\n"
    "@@ -1,2 +1,3 @@\n"
    " def add(a, b):\n"
    "+    if b < 0: return a - abs(b)\n"
    "     return a + b\n"
)


def _make_snapshot(patch_text: str = TWO_HUNK_PATCH) -> CandidateSnapshot:
    p_digest = compute_bytes_digest(patch_text.encode("utf-8")).value
    source = SourceIdentity(locator=REPO_LOCATOR, revision=CommitRevision(BASE_COMMIT))
    return CandidateSnapshot(
        candidate_id="cand-test-01",
        source_identity=source,
        candidate_tree_digest=CAND_TREE,
        patch_digest=p_digest,
        patch_text=patch_text,
        files_added=(),
        files_modified=("src/calc.py",),
        files_deleted=(),
        builder_authored_tests=(),
        frozen_contract_digest=FROZEN_CONTRACT,
        context_digest="f" * 64,
        provenance=EvidenceProvenance.LOCAL_EXECUTION,
    )


class TestBoundedHunkDerivation:
    """Tests deriving canonical PatchUnits from snapshot."""

    def test_derive_patch_units_mechanically(self) -> None:
        snap = _make_snapshot(TWO_HUNK_PATCH)
        units = BoundedSubsetMinimizer.derive_patch_units(snap)
        assert len(units) == 2
        assert all(isinstance(u, PatchUnit) for u in units)
        assert units[0].file_path == "src/calc.py"
        assert units[0].hunk_index == 0
        assert units[1].hunk_index == 1
        assert "hunk-0" in units[0].hunk_id
        assert "hunk-1" in units[1].hunk_id

    def test_single_hunk_derivation(self) -> None:
        snap = _make_snapshot(SINGLE_HUNK_PATCH)
        units = BoundedSubsetMinimizer.derive_patch_units(snap)
        assert len(units) == 1
        assert units[0].hunk_index == 0


class TestBoundedMinimizationExecution:
    """Tests minimization search under various causal outcomes."""

    def test_single_hunk_patch_is_tested_necessary_subset(self) -> None:
        snap = _make_snapshot(SINGLE_HUNK_PATCH)

        def mock_callback(sub: TestedPatchSubset, scope: Any) -> WitnessOutcome:
            return WitnessOutcome.PASS

        minimizer = BoundedSubsetMinimizer(execution_callback=mock_callback)
        result = minimizer.minimize(
            snapshot=snap,
            frozen_contract_digest=FROZEN_CONTRACT,
            sealed_witness_digest=SEALED_WITNESS,
            requirement_id=REQ_ID,
            base_outcome=WitnessOutcome.FAIL,
        )

        assert result.status == CausalSliceStatus.TESTED_NECESSARY_SUBSET
        assert result.completeness == SliceSearchCompleteness.EXHAUSTIVE_BOUNDED
        assert result.minimal_subset is not None
        assert len(result.minimal_subset.retained_hunk_ids) == 1
        assert result.slice_artifact is not None
        assert result.slice_artifact.is_authoritative is False
        assert result.slice_artifact.claims_global_minimality is False

    def test_one_necessary_hunk_and_one_irrelevant_hunk_removed(self) -> None:
        snap = _make_snapshot(TWO_HUNK_PATCH)
        units = BoundedSubsetMinimizer.derive_patch_units(snap)
        h0 = units[0].hunk_id
        h1 = units[1].hunk_id

        # Hunk 0 is the necessary fix (passes whenever hunk 0 is present)
        # Hunk 1 is irrelevant (fails if only hunk 1 is present)
        def mock_callback(sub: TestedPatchSubset, scope: Any) -> WitnessOutcome:
            if h0 in sub.retained_hunk_ids:
                return WitnessOutcome.PASS
            return WitnessOutcome.FAIL

        minimizer = BoundedSubsetMinimizer(execution_callback=mock_callback)
        result = minimizer.minimize(
            snapshot=snap,
            frozen_contract_digest=FROZEN_CONTRACT,
            sealed_witness_digest=SEALED_WITNESS,
            requirement_id=REQ_ID,
            base_outcome=WitnessOutcome.FAIL,
        )

        assert result.status == CausalSliceStatus.TESTED_NECESSARY_SUBSET
        assert result.minimal_subset is not None
        assert result.minimal_subset.retained_hunk_ids == (h0,)
        assert result.minimal_subset.subtracted_hunk_ids == (h1,)
        assert result.slice_artifact is not None

    def test_two_interacting_hunks_required_together(self) -> None:
        snap = _make_snapshot(TWO_HUNK_PATCH)
        units = BoundedSubsetMinimizer.derive_patch_units(snap)
        h0 = units[0].hunk_id
        h1 = units[1].hunk_id

        # Both hunks are required together (neither alone passes)
        def mock_callback(sub: TestedPatchSubset, scope: Any) -> WitnessOutcome:
            if h0 in sub.retained_hunk_ids and h1 in sub.retained_hunk_ids:
                return WitnessOutcome.PASS
            return WitnessOutcome.FAIL

        minimizer = BoundedSubsetMinimizer(execution_callback=mock_callback)
        result = minimizer.minimize(
            snapshot=snap,
            frozen_contract_digest=FROZEN_CONTRACT,
            sealed_witness_digest=SEALED_WITNESS,
            requirement_id=REQ_ID,
            base_outcome=WitnessOutcome.FAIL,
        )

        assert result.status == CausalSliceStatus.NO_REDUCTION_FOUND
        assert result.minimal_subset is not None
        assert set(result.minimal_subset.retained_hunk_ids) == {h0, h1}

    def test_multiple_alternative_sufficient_subsets(self) -> None:
        snap = _make_snapshot(TWO_HUNK_PATCH)

        # Either hunk alone passes!
        def mock_callback(sub: TestedPatchSubset, scope: Any) -> WitnessOutcome:
            return WitnessOutcome.PASS

        minimizer = BoundedSubsetMinimizer(execution_callback=mock_callback)
        result = minimizer.minimize(
            snapshot=snap,
            frozen_contract_digest=FROZEN_CONTRACT,
            sealed_witness_digest=SEALED_WITNESS,
            requirement_id=REQ_ID,
            base_outcome=WitnessOutcome.FAIL,
        )

        assert result.status == CausalSliceStatus.MULTIPLE_SUFFICIENT_SUBSETS
        assert len(result.alternative_subsets) == 2
        assert result.claims_global_minimality is False

    def test_budget_exhaustion_terminates_as_inconclusive_incomplete(self) -> None:
        snap = _make_snapshot(TWO_HUNK_PATCH)

        # First evaluation (full candidate) passes, subsequent evaluations not run due to budget
        call_count = 0

        def mock_callback(sub: TestedPatchSubset, scope: Any) -> WitnessOutcome:
            nonlocal call_count
            call_count += 1
            if len(sub.retained_hunk_ids) == 2:
                return WitnessOutcome.PASS
            return WitnessOutcome.FAIL

        # Budget allows max 1 subset test (only full candidate will run)
        budget = SliceSearchBudget(max_iterations=1, max_subsets_tested=1)
        minimizer = BoundedSubsetMinimizer(execution_callback=mock_callback, budget=budget)
        result = minimizer.minimize(
            snapshot=snap,
            frozen_contract_digest=FROZEN_CONTRACT,
            sealed_witness_digest=SEALED_WITNESS,
            requirement_id=REQ_ID,
            base_outcome=WitnessOutcome.FAIL,
        )

        assert result.status == CausalSliceStatus.INCONCLUSIVE_INCOMPLETE
        assert result.completeness == SliceSearchCompleteness.PARTIAL_ABORTED

    def test_base_outcome_not_fail_rejected(self) -> None:
        snap = _make_snapshot(SINGLE_HUNK_PATCH)

        def mock_callback(sub: TestedPatchSubset, scope: Any) -> WitnessOutcome:
            return WitnessOutcome.PASS

        minimizer = BoundedSubsetMinimizer(execution_callback=mock_callback)
        result = minimizer.minimize(
            snapshot=snap,
            frozen_contract_digest=FROZEN_CONTRACT,
            sealed_witness_digest=SEALED_WITNESS,
            requirement_id=REQ_ID,
            base_outcome=WitnessOutcome.PASS,  # Base PASS violates precondition
        )

        assert result.status == CausalSliceStatus.INVALID_SUBSET
        assert result.minimal_subset is None

    def test_full_candidate_error_or_timeout_not_collapsed_to_fail(self) -> None:
        snap = _make_snapshot(SINGLE_HUNK_PATCH)

        def mock_callback(sub: TestedPatchSubset, scope: Any) -> WitnessOutcome:
            return WitnessOutcome.TIMEOUT

        minimizer = BoundedSubsetMinimizer(execution_callback=mock_callback)
        result = minimizer.minimize(
            snapshot=snap,
            frozen_contract_digest=FROZEN_CONTRACT,
            sealed_witness_digest=SEALED_WITNESS,
            requirement_id=REQ_ID,
            base_outcome=WitnessOutcome.FAIL,
        )

        assert result.status == CausalSliceStatus.INVALID_SUBSET
        assert result.minimal_subset is None

    def test_model_proposal_with_authority_rejected(self) -> None:
        snap = _make_snapshot(TWO_HUNK_PATCH)
        minimizer = BoundedSubsetMinimizer(execution_callback=lambda s, sc: WitnessOutcome.PASS)

        with pytest.raises(SliceAuthorityError, match="is_authoritative must be False"):
            ModelSliceProposal(is_authoritative=True)  # type: ignore[arg-type]

        with pytest.raises(SliceAuthorityError, match="claims_minimality must be False"):
            ModelSliceProposal(claims_minimality=True)  # type: ignore[arg-type]

    def test_untrusted_model_proposal_prioritizes_search_order_without_verdict_authority(
        self,
    ) -> None:
        snap = _make_snapshot(TWO_HUNK_PATCH)
        units = BoundedSubsetMinimizer.derive_patch_units(snap)
        h0 = units[0].hunk_id
        h1 = units[1].hunk_id

        # Model suggests testing h1 first
        proposal = ModelSliceProposal(proposed_retained_hunks=(h1,))

        tested_orders: list[tuple[str, ...]] = []

        def mock_callback(sub: TestedPatchSubset, scope: Any) -> WitnessOutcome:
            tested_orders.append(sub.retained_hunk_ids)
            # Full candidate passes, h1 alone fails, h0 alone passes
            if set(sub.retained_hunk_ids) == {h0, h1}:
                return WitnessOutcome.PASS
            if sub.retained_hunk_ids == (h0,):
                return WitnessOutcome.PASS
            return WitnessOutcome.FAIL

        minimizer = BoundedSubsetMinimizer(execution_callback=mock_callback)
        result = minimizer.minimize(
            snapshot=snap,
            frozen_contract_digest=FROZEN_CONTRACT,
            sealed_witness_digest=SEALED_WITNESS,
            requirement_id=REQ_ID,
            base_outcome=WitnessOutcome.FAIL,
            model_proposal=proposal,
        )

        # The model's proposed subset (h1,) was evaluated first among proper subsets (index 1 after full)
        assert tested_orders[1] == (h1,)
        # But because h1 failed, model proposal did NOT get accepted as minimal
        assert result.minimal_subset is not None
        assert result.minimal_subset.retained_hunk_ids == (h0,)
        assert result.status == CausalSliceStatus.TESTED_NECESSARY_SUBSET
