"""Deterministic adversarial, interaction, and ambiguity tests for P-12.05.

Basebreak Thesis:
"If the patch matters, the base must break."

Covers all 27 required adversarial and edge-case scenarios:
1. One necessary hunk.
2. Irrelevant hunk removed.
3. Two interacting hunks required together.
4. Multiple alternative sufficient subsets.
5. Non-monotonic subset behavior.
6. A passes, B passes, A+B fails.
7. Search budget exhaustion.
8. Ambiguous bounded slice.
9. No reduction possible.
10. Invalid subset materialization.
11. Counterfactual ERROR.
12. Counterfactual TIMEOUT.
13. Witness mismatch.
14. Frozen-contract mismatch.
15. Candidate ID mismatch.
16. Tree digest mismatch.
17. Patch/subset digest mismatch.
18. Cache-key collision attempt.
19. Stale cache evidence.
20. Provenance mismatch.
21. Model proposal attempting authority.
22. Protected-surface interaction.
23. Secret-policy violation.
24. Serialization tampering.
25. Incomplete search attempting global-minimality claim.
26. Alternative sufficient subset discovered after earlier greedy candidate.
27. Deterministic repeatability for identical search inputs.
"""

from __future__ import annotations

from dataclasses import replace
from typing import Any

import pytest

from basebreak.builder.capture import CandidateSnapshot
from basebreak.causal.cache import (
    CacheRejectionReason,
    CacheTamperingError,
    DeterministicExecutionCache,
    ForbiddenProvenanceSubstitutionError,
    create_execution_cache_entry,
    create_execution_cache_key,
)
from basebreak.causal.minimizer import (
    BoundedSubsetMinimizer,
    SliceSearchBudget,
    create_tested_patch_subset_from_hunks,
)
from basebreak.causal.slice import (
    BoundedCausalSlice,
    CausalSliceStatus,
    IncompleteSearchAuthorityError,
    InvalidSubsetError,
    ModelSliceProposal,
    NonFormalProofDisclaimer,
    SliceAuthorityError,
    SliceIdentityMismatchError,
    SliceScopeTamperingError,
    SliceSearchCompleteness,
    SubsetExecutionFact,
    TestedPatchSubset,
    compute_runtime_config_digest,
    create_bounded_causal_slice,
    create_causal_slice_scope,
    create_subset_execution_fact,
)
from basebreak.causal.slice_receipt import (
    CausalSliceReceipt,
    SliceReceiptIntegrityError,
    SliceReceiptTamperingError,
    create_causal_slice_receipt,
    create_causal_slice_receipt_from_result,
)
from basebreak.causal.subtraction import (
    EmptySubtractionError,
    SubtractionStrategyType,
    parse_candidate_patch,
)
from basebreak.domain.source import CommitRevision, SourceIdentity
from basebreak.domain.verdict import EvidenceProvenance
from basebreak.evidence.artifact import compute_bytes_digest
from basebreak.security.protected_surfaces import ProtectedSurfaceViolation
from basebreak.security.secret_policy import SecretPersistenceError
from basebreak.verifier.witness_result import WitnessOutcome

FROZEN_CONTRACT = "a" * 64
SEALED_WITNESS = "b" * 64
BASE_COMMIT = "c" * 40
CAND_TREE = "d" * 40
REPO_LOCATOR = "https://github.com/example/repo.git"
REQ_ID = "REQ-ADV-001"

SINGLE_HUNK_PATCH = (
    "diff --git a/src/calc.py b/src/calc.py\n"
    "index 1111111..2222222 100644\n"
    "--- a/src/calc.py\n"
    "+++ b/src/calc.py\n"
    "@@ -1,2 +1,3 @@\n"
    " def add(a, b):\n"
    "+    # Hunk 1\n"
    "     return a + b\n"
)

TWO_HUNK_PATCH = (
    "diff --git a/src/calc.py b/src/calc.py\n"
    "index 1111111..2222222 100644\n"
    "--- a/src/calc.py\n"
    "+++ b/src/calc.py\n"
    "@@ -1,2 +1,3 @@\n"
    " def add(a, b):\n"
    "+    # Hunk 1\n"
    "     return a + b\n"
    "@@ -10,2 +11,3 @@\n"
    " def sub(a, b):\n"
    "+    # Hunk 2\n"
    "     return a - b\n"
)

THREE_HUNK_PATCH = (
    "diff --git a/src/calc.py b/src/calc.py\n"
    "index 1111111..2222222 100644\n"
    "--- a/src/calc.py\n"
    "+++ b/src/calc.py\n"
    "@@ -1,2 +1,3 @@\n"
    " def add(a, b):\n"
    "+    # Hunk 1\n"
    "     return a + b\n"
    "@@ -10,2 +11,3 @@\n"
    " def sub(a, b):\n"
    "+    # Hunk 2\n"
    "     return a - b\n"
    "@@ -20,2 +21,3 @@\n"
    " def mul(a, b):\n"
    "+    # Hunk 3\n"
    "     return a * b\n"
)


def _make_snapshot(
    patch_text: str = TWO_HUNK_PATCH,
    candidate_id: str = "cand-adv-01",
    tree_digest: str = CAND_TREE,
    frozen_contract: str = FROZEN_CONTRACT,
    commit_id: str = BASE_COMMIT,
) -> CandidateSnapshot:
    p_digest = compute_bytes_digest(patch_text.encode("utf-8")).value
    source = SourceIdentity(
        locator=REPO_LOCATOR,
        revision=CommitRevision(commit_id),
        subpath="src/calc.py",
    )
    return CandidateSnapshot(
        candidate_id=candidate_id,
        source_identity=source,
        candidate_tree_digest=tree_digest,
        patch_digest=p_digest,
        patch_text=patch_text,
        files_added=(),
        files_modified=("src/calc.py",),
        files_deleted=(),
        builder_authored_tests=(),
        frozen_contract_digest=frozen_contract,
        context_digest="f" * 64,
        provenance=EvidenceProvenance.LOCAL_EXECUTION,
    )


def _make_fact(
    sub: TestedPatchSubset,
    scope: Any,
    outcome: WitnessOutcome,
) -> SubsetExecutionFact:
    return create_subset_execution_fact(
        subset=sub,
        scope=scope,
        outcome=outcome,
        exit_code=0 if outcome == WitnessOutcome.PASS else 1,
    )


class TestP12AdversarialCoverage:
    """Complete 27-scenario adversarial and boundary verification suite for P-12."""

    def test_p12_05_01_one_necessary_hunk(self) -> None:
        """1. Candidate with 1 hunk: base failed, full candidate passes."""
        snap = _make_snapshot(SINGLE_HUNK_PATCH)
        minimizer = BoundedSubsetMinimizer(
            execution_callback=lambda sub, scope: _make_fact(sub, scope, WitnessOutcome.PASS)
        )
        res = minimizer.minimize(
            snapshot=snap,
            frozen_contract_digest=FROZEN_CONTRACT,
            sealed_witness_digest=SEALED_WITNESS,
            requirement_id=REQ_ID,
            base_outcome=WitnessOutcome.FAIL,
        )

        assert res.status == CausalSliceStatus.TESTED_NECESSARY_SUBSET
        assert res.completeness == SliceSearchCompleteness.EXHAUSTIVE_BOUNDED
        assert res.minimal_subset is not None
        assert res.iterations_used == 1
        assert res.claims_global_minimality is False
        assert res.is_authoritative is False

    def test_p12_05_02_irrelevant_hunk_removed(self) -> None:
        """2. Candidate with 2 hunks: Hunk 1 is necessary, Hunk 2 is irrelevant comment."""
        snap = _make_snapshot(TWO_HUNK_PATCH)
        units = BoundedSubsetMinimizer.derive_patch_units(snap)
        h0 = units[0].hunk_id
        h1 = units[1].hunk_id

        def eval_cb(sub: TestedPatchSubset, scope: object) -> SubsetExecutionFact:
            return _make_fact(
                sub,
                scope,
                WitnessOutcome.PASS if h0 in sub.retained_hunk_ids else WitnessOutcome.FAIL,
            )

        minimizer = BoundedSubsetMinimizer(execution_callback=eval_cb)
        res = minimizer.minimize(
            snapshot=snap,
            frozen_contract_digest=FROZEN_CONTRACT,
            sealed_witness_digest=SEALED_WITNESS,
            requirement_id=REQ_ID,
            base_outcome=WitnessOutcome.FAIL,
        )

        assert res.status == CausalSliceStatus.TESTED_NECESSARY_SUBSET
        assert res.minimal_subset is not None
        assert res.minimal_subset.retained_hunk_ids == (h0,)
        assert h1 in res.minimal_subset.subtracted_hunk_ids

    def test_p12_05_03_two_interacting_hunks_required_together(self) -> None:
        """3. Candidate with 2 hunks: both hunks required together; neither passes alone."""
        snap = _make_snapshot(TWO_HUNK_PATCH)

        def eval_cb(sub: TestedPatchSubset, scope: object) -> SubsetExecutionFact:
            return _make_fact(
                sub,
                scope,
                WitnessOutcome.PASS if len(sub.retained_hunk_ids) == 2 else WitnessOutcome.FAIL,
            )

        minimizer = BoundedSubsetMinimizer(execution_callback=eval_cb)
        res = minimizer.minimize(
            snapshot=snap,
            frozen_contract_digest=FROZEN_CONTRACT,
            sealed_witness_digest=SEALED_WITNESS,
            requirement_id=REQ_ID,
            base_outcome=WitnessOutcome.FAIL,
        )

        assert res.status == CausalSliceStatus.NO_REDUCTION_FOUND
        assert res.minimal_subset is not None
        assert len(res.minimal_subset.retained_hunk_ids) == 2

    def test_p12_05_04_multiple_alternative_sufficient_subsets(self) -> None:
        """4. Candidate with 2 hunks: Hunk 1 alone passes, Hunk 2 alone passes."""
        snap = _make_snapshot(TWO_HUNK_PATCH)

        def eval_cb(sub: TestedPatchSubset, scope: object) -> SubsetExecutionFact:
            return _make_fact(sub, scope, WitnessOutcome.PASS)

        minimizer = BoundedSubsetMinimizer(execution_callback=eval_cb)
        res = minimizer.minimize(
            snapshot=snap,
            frozen_contract_digest=FROZEN_CONTRACT,
            sealed_witness_digest=SEALED_WITNESS,
            requirement_id=REQ_ID,
            base_outcome=WitnessOutcome.FAIL,
        )

        assert res.status == CausalSliceStatus.MULTIPLE_SUFFICIENT_SUBSETS
        assert len(res.alternative_subsets) >= 2

    def test_p12_05_05_non_monotonic_subset_behavior(self) -> None:
        """5. Non-monotonic behavior: H1 alone passes, H2 alone passes, but H1+H2 fails."""
        snap = _make_snapshot(THREE_HUNK_PATCH)
        units = BoundedSubsetMinimizer.derive_patch_units(snap)
        h0, h1 = units[0].hunk_id, units[1].hunk_id

        def eval_cb(sub: TestedPatchSubset, scope: object) -> SubsetExecutionFact:
            retained = set(sub.retained_hunk_ids)
            if len(retained) == 3:
                return _make_fact(sub, scope, WitnessOutcome.PASS)
            if retained in ({h0}, {h1}):
                return _make_fact(sub, scope, WitnessOutcome.PASS)
            if retained == {h0, h1}:
                return _make_fact(sub, scope, WitnessOutcome.FAIL)
            return _make_fact(sub, scope, WitnessOutcome.FAIL)

        minimizer = BoundedSubsetMinimizer(execution_callback=eval_cb)
        res = minimizer.minimize(
            snapshot=snap,
            frozen_contract_digest=FROZEN_CONTRACT,
            sealed_witness_digest=SEALED_WITNESS,
            requirement_id=REQ_ID,
            base_outcome=WitnessOutcome.FAIL,
        )

        assert res.status == CausalSliceStatus.INCONCLUSIVE_INTERACTION

    def test_p12_05_06_a_passes_b_passes_ab_fails(self) -> None:
        """6. Exact invariant check: A alone passes, B alone passes, A+B fails."""
        snap = _make_snapshot(THREE_HUNK_PATCH)
        units = BoundedSubsetMinimizer.derive_patch_units(snap)
        h0, h1 = units[0].hunk_id, units[1].hunk_id

        def eval_cb(sub: TestedPatchSubset, scope: object) -> SubsetExecutionFact:
            retained = set(sub.retained_hunk_ids)
            if len(retained) == 3:
                return _make_fact(sub, scope, WitnessOutcome.PASS)
            if retained in ({h0}, {h1}):
                return _make_fact(sub, scope, WitnessOutcome.PASS)
            if retained == {h0, h1}:
                return _make_fact(sub, scope, WitnessOutcome.FAIL)
            return _make_fact(sub, scope, WitnessOutcome.FAIL)

        minimizer = BoundedSubsetMinimizer(execution_callback=eval_cb)
        res = minimizer.minimize(
            snapshot=snap,
            frozen_contract_digest=FROZEN_CONTRACT,
            sealed_witness_digest=SEALED_WITNESS,
            requirement_id=REQ_ID,
            base_outcome=WitnessOutcome.FAIL,
        )

        assert res.status == CausalSliceStatus.INCONCLUSIVE_INTERACTION
        assert "non-monotonic" in res.summary_label.lower()

    def test_p12_05_07_search_budget_exhaustion(self) -> None:
        """7. Search budget exhaustion: budget limits evaluation before resolution."""
        snap = _make_snapshot(THREE_HUNK_PATCH)
        budget = SliceSearchBudget(max_iterations=1, max_subsets_tested=1)
        minimizer = BoundedSubsetMinimizer(
            execution_callback=lambda sub, scope: _make_fact(sub, scope, WitnessOutcome.PASS),
            budget=budget,
        )
        res = minimizer.minimize(
            snapshot=snap,
            frozen_contract_digest=FROZEN_CONTRACT,
            sealed_witness_digest=SEALED_WITNESS,
            requirement_id=REQ_ID,
            base_outcome=WitnessOutcome.FAIL,
        )

        assert res.status == CausalSliceStatus.INCONCLUSIVE_INCOMPLETE
        assert res.completeness == SliceSearchCompleteness.PARTIAL_ABORTED

    def test_p12_05_08_ambiguous_bounded_slice(self) -> None:
        """8. Ambiguous bounded slice: proper subset encounters TIMEOUT/ERROR."""
        snap = _make_snapshot(TWO_HUNK_PATCH)

        def eval_cb(sub: TestedPatchSubset, scope: object) -> SubsetExecutionFact:
            if len(sub.retained_hunk_ids) == 2:
                return _make_fact(sub, scope, WitnessOutcome.PASS)
            return _make_fact(sub, scope, WitnessOutcome.TIMEOUT)

        minimizer = BoundedSubsetMinimizer(execution_callback=eval_cb)
        res = minimizer.minimize(
            snapshot=snap,
            frozen_contract_digest=FROZEN_CONTRACT,
            sealed_witness_digest=SEALED_WITNESS,
            requirement_id=REQ_ID,
            base_outcome=WitnessOutcome.FAIL,
        )

        assert res.status == CausalSliceStatus.AMBIGUOUS_SLICE
        assert res.completeness == SliceSearchCompleteness.PARTIAL_ABORTED

    def test_p12_05_09_no_reduction_possible(self) -> None:
        """9. No reduction possible: every proper subset strictly fails under witness."""
        snap = _make_snapshot(THREE_HUNK_PATCH)

        def eval_cb(sub: TestedPatchSubset, scope: object) -> SubsetExecutionFact:
            return _make_fact(
                sub,
                scope,
                WitnessOutcome.PASS if len(sub.retained_hunk_ids) == 3 else WitnessOutcome.FAIL,
            )

        minimizer = BoundedSubsetMinimizer(execution_callback=eval_cb)
        res = minimizer.minimize(
            snapshot=snap,
            frozen_contract_digest=FROZEN_CONTRACT,
            sealed_witness_digest=SEALED_WITNESS,
            requirement_id=REQ_ID,
            base_outcome=WitnessOutcome.FAIL,
        )

        assert res.status == CausalSliceStatus.NO_REDUCTION_FOUND
        assert res.minimal_subset is not None
        assert len(res.minimal_subset.retained_hunk_ids) == 3

    def test_p12_05_10_invalid_subset_materialization(self) -> None:
        """10. Attempting to materialize an empty subset fails closed."""
        parsed = parse_candidate_patch(TWO_HUNK_PATCH)
        with pytest.raises(EmptySubtractionError, match="at least one retained hunk"):
            create_tested_patch_subset_from_hunks(parsed, retained_hunk_ids=())

        with pytest.raises(InvalidSubsetError, match="is_empty=True"):
            TestedPatchSubset(
                subset_id="sub-empty",
                strategy_type=SubtractionStrategyType.HUNK_LEVEL_REVERT,
                retained_files=("src/calc.py",),
                retained_hunk_ids=("hunk-0",),
                subtracted_files=(),
                subtracted_hunk_ids=(),
                retained_patch_digest="1" * 64,
                subtracted_delta_digest="0" * 64,
                is_empty=True,  # VIOLATION
            )

    def test_p12_05_11_counterfactual_error(self) -> None:
        """11. Counterfactual ERROR: full candidate encounters ERROR (ERROR != FAIL)."""
        snap = _make_snapshot(SINGLE_HUNK_PATCH)
        minimizer = BoundedSubsetMinimizer(
            execution_callback=lambda sub, scope: _make_fact(sub, scope, WitnessOutcome.ERROR)
        )
        res = minimizer.minimize(
            snapshot=snap,
            frozen_contract_digest=FROZEN_CONTRACT,
            sealed_witness_digest=SEALED_WITNESS,
            requirement_id=REQ_ID,
            base_outcome=WitnessOutcome.FAIL,
        )

        assert res.status == CausalSliceStatus.INVALID_SUBSET

    def test_p12_05_12_counterfactual_timeout(self) -> None:
        """12. Counterfactual TIMEOUT: full candidate encounters TIMEOUT (TIMEOUT != FAIL)."""
        snap = _make_snapshot(SINGLE_HUNK_PATCH)
        minimizer = BoundedSubsetMinimizer(
            execution_callback=lambda sub, scope: _make_fact(sub, scope, WitnessOutcome.TIMEOUT)
        )
        res = minimizer.minimize(
            snapshot=snap,
            frozen_contract_digest=FROZEN_CONTRACT,
            sealed_witness_digest=SEALED_WITNESS,
            requirement_id=REQ_ID,
            base_outcome=WitnessOutcome.FAIL,
        )

        assert res.status == CausalSliceStatus.INVALID_SUBSET

    def test_p12_05_13_witness_mismatch(self) -> None:
        """13. Mismatched sealed_witness_digest fails closed with SliceIdentityMismatchError."""
        snap = _make_snapshot(SINGLE_HUNK_PATCH)
        scope = create_causal_slice_scope(
            snapshot=snap,
            frozen_contract_digest=FROZEN_CONTRACT,
            sealed_witness_digest=SEALED_WITNESS,
            requirement_id=REQ_ID,
        )
        parsed = parse_candidate_patch(SINGLE_HUNK_PATCH)
        h0 = parsed.files[0].hunks[0].hunk_id
        sub = create_tested_patch_subset_from_hunks(parsed, (h0,))
        slice_art = create_bounded_causal_slice(
            slice_id="slice-001",
            scope=scope,
            tested_subset=sub,
        )

        with pytest.raises(SliceIdentityMismatchError, match="sealed_witness_digest mismatch"):
            create_causal_slice_receipt(
                requirement_id=REQ_ID,
                frozen_contract_digest=FROZEN_CONTRACT,
                sealed_witness_digest="f" * 64,  # MISMATCH
                witness_id="wit-001",
                source_locator=REPO_LOCATOR,
                source_commit_id=BASE_COMMIT,
                candidate_id=snap.candidate_id,
                candidate_tree_digest=CAND_TREE,
                candidate_patch_digest=snap.patch_digest,
                slice_artifact=slice_art,
                search_budget=SliceSearchBudget(),
            )

    def test_p12_05_14_frozen_contract_mismatch(self) -> None:
        """14. Mismatched frozen_contract_digest fails closed with SliceIdentityMismatchError."""
        snap = _make_snapshot(SINGLE_HUNK_PATCH)
        scope = create_causal_slice_scope(
            snapshot=snap,
            frozen_contract_digest=FROZEN_CONTRACT,
            sealed_witness_digest=SEALED_WITNESS,
            requirement_id=REQ_ID,
        )
        parsed = parse_candidate_patch(SINGLE_HUNK_PATCH)
        h0 = parsed.files[0].hunks[0].hunk_id
        sub = create_tested_patch_subset_from_hunks(parsed, (h0,))
        slice_art = create_bounded_causal_slice(
            slice_id="slice-001",
            scope=scope,
            tested_subset=sub,
        )

        with pytest.raises(SliceIdentityMismatchError, match="frozen_contract_digest mismatch"):
            create_causal_slice_receipt(
                requirement_id=REQ_ID,
                frozen_contract_digest="9" * 64,  # MISMATCH
                sealed_witness_digest=SEALED_WITNESS,
                witness_id="wit-001",
                source_locator=REPO_LOCATOR,
                source_commit_id=BASE_COMMIT,
                candidate_id=snap.candidate_id,
                candidate_tree_digest=CAND_TREE,
                candidate_patch_digest=snap.patch_digest,
                slice_artifact=slice_art,
                search_budget=SliceSearchBudget(),
            )

    def test_p12_05_15_candidate_id_mismatch(self) -> None:
        """15. Candidate ID mismatch fails closed with SliceIdentityMismatchError."""
        snap = _make_snapshot(SINGLE_HUNK_PATCH)
        scope = create_causal_slice_scope(
            snapshot=snap,
            frozen_contract_digest=FROZEN_CONTRACT,
            sealed_witness_digest=SEALED_WITNESS,
            requirement_id=REQ_ID,
        )
        parsed = parse_candidate_patch(SINGLE_HUNK_PATCH)
        h0 = parsed.files[0].hunks[0].hunk_id
        sub = create_tested_patch_subset_from_hunks(parsed, (h0,))
        slice_art = create_bounded_causal_slice(
            slice_id="slice-001",
            scope=scope,
            tested_subset=sub,
        )

        with pytest.raises(SliceIdentityMismatchError, match="candidate_id mismatch"):
            create_causal_slice_receipt(
                requirement_id=REQ_ID,
                frozen_contract_digest=FROZEN_CONTRACT,
                sealed_witness_digest=SEALED_WITNESS,
                witness_id="wit-001",
                source_locator=REPO_LOCATOR,
                source_commit_id=BASE_COMMIT,
                candidate_id="cand-FORGED-999",  # MISMATCH
                candidate_tree_digest=CAND_TREE,
                candidate_patch_digest=snap.patch_digest,
                slice_artifact=slice_art,
                search_budget=SliceSearchBudget(),
            )

    def test_p12_05_16_tree_digest_mismatch(self) -> None:
        """16. Candidate tree digest mismatch fails closed."""
        snap = _make_snapshot(SINGLE_HUNK_PATCH)
        scope = create_causal_slice_scope(
            snapshot=snap,
            frozen_contract_digest=FROZEN_CONTRACT,
            sealed_witness_digest=SEALED_WITNESS,
            requirement_id=REQ_ID,
        )
        parsed = parse_candidate_patch(SINGLE_HUNK_PATCH)
        h0 = parsed.files[0].hunks[0].hunk_id
        sub = create_tested_patch_subset_from_hunks(parsed, (h0,))
        slice_art = create_bounded_causal_slice(
            slice_id="slice-001",
            scope=scope,
            tested_subset=sub,
        )

        with pytest.raises(SliceIdentityMismatchError, match="candidate_tree_digest mismatch"):
            create_causal_slice_receipt(
                requirement_id=REQ_ID,
                frozen_contract_digest=FROZEN_CONTRACT,
                sealed_witness_digest=SEALED_WITNESS,
                witness_id="wit-001",
                source_locator=REPO_LOCATOR,
                source_commit_id=BASE_COMMIT,
                candidate_id=snap.candidate_id,
                candidate_tree_digest="9" * 40,  # MISMATCH with slice_art's CAND_TREE
                candidate_patch_digest=snap.patch_digest,
                slice_artifact=slice_art,
                search_budget=SliceSearchBudget(),
            )

    def test_p12_05_17_patch_subset_digest_mismatch(self) -> None:
        """17. TestedPatchSubset with invalid hex digest raises validation error."""
        with pytest.raises(ValueError, match="hex chars"):
            TestedPatchSubset(
                subset_id="sub-01",
                strategy_type=SubtractionStrategyType.HUNK_LEVEL_REVERT,
                retained_files=("src/calc.py",),
                retained_hunk_ids=("hunk-0",),
                subtracted_files=(),
                subtracted_hunk_ids=(),
                retained_patch_digest="invalid-digest",  # NOT 64 HEX
                subtracted_delta_digest="0" * 64,
            )

    def test_p12_05_18_cache_key_collision_attempt(self) -> None:
        """18. Cache keys differing in any single identity dimension do not collide."""
        snap = _make_snapshot(SINGLE_HUNK_PATCH)
        scope_a = create_causal_slice_scope(
            snapshot=snap,
            frozen_contract_digest=FROZEN_CONTRACT,
            sealed_witness_digest="1" * 64,
            requirement_id="REQ-A",
        )
        scope_b = create_causal_slice_scope(
            snapshot=snap,
            frozen_contract_digest=FROZEN_CONTRACT,
            sealed_witness_digest="2" * 64,
            requirement_id="REQ-B",
        )
        parsed = parse_candidate_patch(SINGLE_HUNK_PATCH)
        h0 = parsed.files[0].hunks[0].hunk_id
        sub = create_tested_patch_subset_from_hunks(parsed, (h0,))

        key_a = create_execution_cache_key(
            source_locator=scope_a.source_locator,
            source_commit_id=scope_a.source_commit_id,
            source_subpath=scope_a.source_subpath,
            candidate_tree_digest=scope_a.candidate_tree_digest,
            retained_patch_digest=sub.retained_patch_digest,
            subtracted_delta_digest=sub.subtracted_delta_digest,
            frozen_contract_digest=scope_a.frozen_contract_digest,
            sealed_witness_digest=scope_a.sealed_witness_digest,
            requirement_id=scope_a.requirement_id,
            execution_command=("pytest",),
            provenance=scope_a.provenance,
        )
        key_b = create_execution_cache_key(
            source_locator=scope_b.source_locator,
            source_commit_id=scope_b.source_commit_id,
            source_subpath=scope_b.source_subpath,
            candidate_tree_digest=scope_b.candidate_tree_digest,
            retained_patch_digest=sub.retained_patch_digest,
            subtracted_delta_digest=sub.subtracted_delta_digest,
            frozen_contract_digest=scope_b.frozen_contract_digest,
            sealed_witness_digest=scope_b.sealed_witness_digest,
            requirement_id=scope_b.requirement_id,
            execution_command=("pytest",),
            provenance=scope_b.provenance,
        )

        assert key_a.key_digest != key_b.key_digest

    def test_p12_05_19_stale_cache_evidence(self) -> None:
        """19. Tampered cache entry fails cryptographic integrity check upon retrieval."""
        snap = _make_snapshot(SINGLE_HUNK_PATCH)
        scope = create_causal_slice_scope(
            snapshot=snap,
            frozen_contract_digest=FROZEN_CONTRACT,
            sealed_witness_digest=SEALED_WITNESS,
            requirement_id=REQ_ID,
        )
        parsed = parse_candidate_patch(SINGLE_HUNK_PATCH)
        h0 = parsed.files[0].hunks[0].hunk_id
        sub = create_tested_patch_subset_from_hunks(parsed, (h0,))

        key = create_execution_cache_key(
            source_locator=scope.source_locator,
            source_commit_id=scope.source_commit_id,
            source_subpath=scope.source_subpath,
            candidate_tree_digest=scope.candidate_tree_digest,
            retained_patch_digest=sub.retained_patch_digest,
            subtracted_delta_digest=sub.subtracted_delta_digest,
            frozen_contract_digest=scope.frozen_contract_digest,
            sealed_witness_digest=scope.sealed_witness_digest,
            requirement_id=scope.requirement_id,
            execution_command=("pytest",),
            provenance=scope.provenance,
        )
        entry = create_execution_cache_entry(key=key, outcome=WitnessOutcome.PASS)

        with pytest.raises(CacheTamperingError, match="entry_digest mismatch"):
            replace(entry, outcome=WitnessOutcome.FAIL)

    def test_p12_05_20_provenance_mismatch(self) -> None:
        """20. Cache strictly forbids substituting LOCAL_EXECUTION for LIVE_NEBIUS."""
        snap = _make_snapshot(SINGLE_HUNK_PATCH)
        cache = DeterministicExecutionCache()

        scope_local = create_causal_slice_scope(
            snapshot=snap,
            frozen_contract_digest=FROZEN_CONTRACT,
            sealed_witness_digest=SEALED_WITNESS,
            requirement_id=REQ_ID,
            provenance=EvidenceProvenance.LOCAL_EXECUTION,
        )
        parsed = parse_candidate_patch(SINGLE_HUNK_PATCH)
        h0 = parsed.files[0].hunks[0].hunk_id
        sub = create_tested_patch_subset_from_hunks(parsed, (h0,))
        entry = cache.store(subset=sub, scope=scope_local, outcome=WitnessOutcome.PASS)

        # 1. Entry level: cannot substitute provenance
        with pytest.raises(ForbiddenProvenanceSubstitutionError):
            replace(entry, provenance=EvidenceProvenance.LIVE_NEBIUS)

        # 2. Lookup level: requesting LIVE_NEBIUS rejects LOCAL_EXECUTION entry
        res = cache.lookup_by_key(entry.key, requested_provenance=EvidenceProvenance.LIVE_NEBIUS)
        assert res.hit is False
        assert res.rejection_reason == CacheRejectionReason.FORBIDDEN_PROVENANCE_SUBSTITUTION

    def test_p12_05_21_model_proposal_attempting_authority(self) -> None:
        """21. Model proposal asserting authority or claiming minimality fails closed."""
        with pytest.raises(SliceAuthorityError, match="is_authoritative must be False"):
            ModelSliceProposal(
                proposed_retained_hunks=("src/calc.py#hunk-0@abc",),
                is_authoritative=True,  # VIOLATION
            )

        with pytest.raises(SliceAuthorityError, match="claims_minimality must be False"):
            ModelSliceProposal(
                proposed_retained_hunks=("src/calc.py#hunk-0@abc",),
                claims_minimality=True,  # VIOLATION
            )

    def test_p12_05_22_protected_surface_interaction(self) -> None:
        """22. Patch touching protected repo surfaces is rejected immediately."""
        protected_patch = (
            "diff --git a/AGENTS.md b/AGENTS.md\n"
            "index 1111111..2222222 100644\n"
            "--- a/AGENTS.md\n"
            "+++ b/AGENTS.md\n"
            "@@ -1,2 +1,3 @@\n"
            " rule\n"
            "+modified\n"
            " rule\n"
        )
        parsed = parse_candidate_patch(protected_patch)
        h0 = parsed.files[0].hunks[0].hunk_id
        with pytest.raises(ProtectedSurfaceViolation):
            create_tested_patch_subset_from_hunks(parsed, retained_hunk_ids=(h0,))

    def test_p12_05_23_secret_policy_violation(self) -> None:
        """23. Patch containing secret material is rejected immediately."""
        secret_patch = (
            "diff --git a/src/config.py b/src/config.py\n"
            "index 1111111..2222222 100644\n"
            "--- a/src/config.py\n"
            "+++ b/src/config.py\n"
            "@@ -1,2 +1,3 @@\n"
            " config\n"
            "+api_key = 'synthetic_secret_value_xyz'\n"
            " config\n"
        )
        parsed = parse_candidate_patch(secret_patch)
        h0 = parsed.files[0].hunks[0].hunk_id
        with pytest.raises(SecretPersistenceError):
            create_tested_patch_subset_from_hunks(parsed, retained_hunk_ids=(h0,))

    def test_p12_05_24_serialization_tampering(self) -> None:
        """24. Tampering with serialized JSON payload fails integrity verification."""
        snap = _make_snapshot(SINGLE_HUNK_PATCH)
        scope = create_causal_slice_scope(
            snapshot=snap,
            frozen_contract_digest=FROZEN_CONTRACT,
            sealed_witness_digest=SEALED_WITNESS,
            requirement_id=REQ_ID,
        )
        parsed = parse_candidate_patch(SINGLE_HUNK_PATCH)
        h0 = parsed.files[0].hunks[0].hunk_id
        sub = create_tested_patch_subset_from_hunks(parsed, (h0,))
        slice_art = create_bounded_causal_slice(
            slice_id="slice-001",
            scope=scope,
            tested_subset=sub,
        )
        fact = create_subset_execution_fact(
            subset=sub,
            scope=scope,
            outcome=WitnessOutcome.PASS,
            exit_code=0,
        )
        receipt = create_causal_slice_receipt(
            requirement_id=REQ_ID,
            frozen_contract_digest=FROZEN_CONTRACT,
            sealed_witness_digest=SEALED_WITNESS,
            witness_id="wit-001",
            source_locator=REPO_LOCATOR,
            source_commit_id=BASE_COMMIT,
            candidate_id=snap.candidate_id,
            candidate_tree_digest=CAND_TREE,
            candidate_patch_digest=snap.patch_digest,
            slice_artifact=slice_art,
            search_budget=SliceSearchBudget(),
            completeness=slice_art.completeness,
            execution_facts=(fact,),
            tested_subsets=(sub,),
        )

        data = receipt.to_dict()
        data["receipt_digest"] = "f" * 64
        with pytest.raises(SliceReceiptTamperingError):
            CausalSliceReceipt.from_dict(data)

    def test_p12_05_25_incomplete_search_attempting_global_minimality_claim(self) -> None:
        """25. Attempting to claim global minimality fails closed."""
        snap = _make_snapshot(SINGLE_HUNK_PATCH)
        scope = create_causal_slice_scope(
            snapshot=snap,
            frozen_contract_digest=FROZEN_CONTRACT,
            sealed_witness_digest=SEALED_WITNESS,
            requirement_id=REQ_ID,
        )
        parsed = parse_candidate_patch(SINGLE_HUNK_PATCH)
        h0 = parsed.files[0].hunks[0].hunk_id
        sub = create_tested_patch_subset_from_hunks(parsed, (h0,))

        with pytest.raises(IncompleteSearchAuthorityError):
            BoundedCausalSlice(
                slice_id="slice-001",
                scope=scope,
                tested_subset=sub,
                status=CausalSliceStatus.TESTED_NECESSARY_SUBSET,
                completeness=SliceSearchCompleteness.EXHAUSTIVE_BOUNDED,
                summary_label="tested",
                disclaimer=NonFormalProofDisclaimer(),
                slice_digest="1" * 64,
                created_at_utc="2026-10-07T00:00:00Z",
                claims_global_minimality=True,  # VIOLATION
            )

    def test_p12_05_26_alternative_subset_discovered_after_greedy_candidate(self) -> None:
        """26. Discovering multiple minimal subsets prevents claiming unique minimality."""
        snap = _make_snapshot(TWO_HUNK_PATCH)
        minimizer = BoundedSubsetMinimizer(
            execution_callback=lambda sub, scope: _make_fact(sub, scope, WitnessOutcome.PASS)
        )
        res = minimizer.minimize(
            snapshot=snap,
            frozen_contract_digest=FROZEN_CONTRACT,
            sealed_witness_digest=SEALED_WITNESS,
            requirement_id=REQ_ID,
            base_outcome=WitnessOutcome.FAIL,
        )

        assert res.status == CausalSliceStatus.MULTIPLE_SUFFICIENT_SUBSETS
        assert len(res.alternative_subsets) == 2
        assert res.claims_global_minimality is False

    def test_p12_05_27_deterministic_repeatability_for_identical_search_inputs(self) -> None:
        """27. Two executions with identical inputs produce identical outcomes and digests."""
        snap = _make_snapshot(TWO_HUNK_PATCH)
        units = BoundedSubsetMinimizer.derive_patch_units(snap)
        h0 = units[0].hunk_id

        def eval_cb(sub: TestedPatchSubset, scope: object) -> SubsetExecutionFact:
            return _make_fact(
                sub,
                scope,
                WitnessOutcome.PASS if h0 in sub.retained_hunk_ids else WitnessOutcome.FAIL,
            )

        minimizer_1 = BoundedSubsetMinimizer(execution_callback=eval_cb)
        res_1 = minimizer_1.minimize(
            snapshot=snap,
            frozen_contract_digest=FROZEN_CONTRACT,
            sealed_witness_digest=SEALED_WITNESS,
            requirement_id=REQ_ID,
            base_outcome=WitnessOutcome.FAIL,
        )

        minimizer_2 = BoundedSubsetMinimizer(execution_callback=eval_cb)
        res_2 = minimizer_2.minimize(
            snapshot=snap,
            frozen_contract_digest=FROZEN_CONTRACT,
            sealed_witness_digest=SEALED_WITNESS,
            requirement_id=REQ_ID,
            base_outcome=WitnessOutcome.FAIL,
        )

        assert res_1.status == res_2.status
        assert res_1.iterations_used == res_2.iterations_used
        assert res_1.minimal_subset is not None and res_2.minimal_subset is not None
        assert res_1.minimal_subset.subset_id == res_2.minimal_subset.subset_id
        assert (
            res_1.minimal_subset.retained_patch_digest == res_2.minimal_subset.retained_patch_digest
        )
        assert [e.outcome for e in res_1.evaluated_subsets] == [
            e.outcome for e in res_2.evaluated_subsets
        ]
        assert [e.subset.subset_id for e in res_1.evaluated_subsets] == [
            e.subset.subset_id for e in res_2.evaluated_subsets
        ]


class TestP12RepairAdversarialSuite:
    """Focused adversarial tests A through O for P-12 surgical repair."""

    def test_case_a_different_runtime_config_no_cache_reuse(self) -> None:
        """A. Same subset/command but different runtime_config_digest => no cache reuse."""
        snap = _make_snapshot(SINGLE_HUNK_PATCH)
        scope = create_causal_slice_scope(
            snapshot=snap,
            frozen_contract_digest=FROZEN_CONTRACT,
            sealed_witness_digest=SEALED_WITNESS,
            requirement_id=REQ_ID,
        )
        parsed = parse_candidate_patch(SINGLE_HUNK_PATCH)
        h0 = parsed.files[0].hunks[0].hunk_id
        sub = create_tested_patch_subset_from_hunks(parsed, (h0,))

        config_1 = compute_runtime_config_digest({"timeout_seconds": 30, "python": "3.11"})
        config_2 = compute_runtime_config_digest({"timeout_seconds": 60, "python": "3.11"})
        assert config_1 != config_2

        cache = DeterministicExecutionCache()
        entry = cache.store(
            subset=sub,
            scope=scope,
            outcome=WitnessOutcome.PASS,
            runtime_config_digest=config_1,
            exit_code=0,
        )
        assert entry.key.runtime_config_digest == config_1

        miss = cache.lookup(
            subset=sub,
            scope=scope,
            runtime_config_digest=config_2,
        )
        assert miss.hit is False
        assert miss.entry is None
        assert miss.rejection_reason in (
            CacheRejectionReason.MISSING_ENTRY,
            CacheRejectionReason.RUNTIME_CONFIG_MISMATCH,
        )

    def test_case_b_caller_attempts_receipt_outcome_pass_while_real_record_fail(self) -> None:
        """B. Caller attempts receipt PASS while real minimizer record is FAIL => rejected."""
        snap = _make_snapshot(SINGLE_HUNK_PATCH)
        minimizer = BoundedSubsetMinimizer(
            execution_callback=lambda sub, scope: _make_fact(sub, scope, WitnessOutcome.FAIL)
        )
        res = minimizer.minimize(
            snapshot=snap,
            frozen_contract_digest=FROZEN_CONTRACT,
            sealed_witness_digest=SEALED_WITNESS,
            requirement_id=REQ_ID,
            base_outcome=WitnessOutcome.FAIL,
        )
        assert res.status == CausalSliceStatus.INCONCLUSIVE_INTERACTION

        scope = create_causal_slice_scope(
            snapshot=snap,
            frozen_contract_digest=FROZEN_CONTRACT,
            sealed_witness_digest=SEALED_WITNESS,
            requirement_id=REQ_ID,
        )
        parsed = parse_candidate_patch(SINGLE_HUNK_PATCH)
        h0 = parsed.files[0].hunks[0].hunk_id
        sub = create_tested_patch_subset_from_hunks(parsed, (h0,))
        slice_art = create_bounded_causal_slice(
            slice_id="slice-001",
            scope=scope,
            tested_subset=sub,
            status=res.status,
            completeness=res.completeness,
        )
        actual_fact = res.evaluated_subsets[0].execution_fact

        with pytest.raises(
            SliceIdentityMismatchError,
            match=r"evaluated_outcomes\[0\] mismatch",
        ):
            create_causal_slice_receipt(
                requirement_id=REQ_ID,
                frozen_contract_digest=FROZEN_CONTRACT,
                sealed_witness_digest=SEALED_WITNESS,
                witness_id="wit-001",
                source_locator=REPO_LOCATOR,
                source_commit_id=BASE_COMMIT,
                candidate_id=snap.candidate_id,
                candidate_tree_digest=CAND_TREE,
                candidate_patch_digest=snap.patch_digest,
                slice_artifact=slice_art,
                search_budget=res.search_budget,
                completeness=res.completeness,
                execution_facts=(actual_fact,),
                tested_subsets=(sub,),
                evaluated_outcomes=(WitnessOutcome.PASS,),
            )

    def test_case_c_caller_swaps_execution_records_between_two_subsets(self) -> None:
        """C. Caller swaps execution records between two subsets => rejected."""
        snap = _make_snapshot(TWO_HUNK_PATCH)
        scope = create_causal_slice_scope(
            snapshot=snap,
            frozen_contract_digest=FROZEN_CONTRACT,
            sealed_witness_digest=SEALED_WITNESS,
            requirement_id=REQ_ID,
        )
        parsed = parse_candidate_patch(TWO_HUNK_PATCH)
        h0 = parsed.files[0].hunks[0].hunk_id
        h1 = parsed.files[0].hunks[1].hunk_id
        sub_0 = create_tested_patch_subset_from_hunks(parsed, (h0,))
        sub_1 = create_tested_patch_subset_from_hunks(parsed, (h1,))

        fact_0 = create_subset_execution_fact(
            subset=sub_0, scope=scope, outcome=WitnessOutcome.PASS, exit_code=0
        )
        fact_1 = create_subset_execution_fact(
            subset=sub_1, scope=scope, outcome=WitnessOutcome.FAIL, exit_code=1
        )

        slice_art = create_bounded_causal_slice(
            slice_id="slice-swap",
            scope=scope,
            tested_subset=sub_0,
            status=CausalSliceStatus.TESTED_NECESSARY_SUBSET,
            completeness=SliceSearchCompleteness.EXHAUSTIVE_BOUNDED,
        )

        with pytest.raises(SliceIdentityMismatchError, match=r"(?i)subset id mismatch"):
            create_causal_slice_receipt(
                requirement_id=REQ_ID,
                frozen_contract_digest=FROZEN_CONTRACT,
                sealed_witness_digest=SEALED_WITNESS,
                witness_id="wit-001",
                source_locator=REPO_LOCATOR,
                source_commit_id=BASE_COMMIT,
                candidate_id=snap.candidate_id,
                candidate_tree_digest=CAND_TREE,
                candidate_patch_digest=snap.patch_digest,
                slice_artifact=slice_art,
                search_budget=SliceSearchBudget(),
                completeness=slice_art.completeness,
                execution_facts=(fact_1, fact_0),
                tested_subsets=(sub_0, sub_1),
            )

    def test_case_d_execution_fact_uses_different_sealed_witness(self) -> None:
        """D. Execution fact uses different sealed witness => rejected."""
        snap = _make_snapshot(SINGLE_HUNK_PATCH)
        parsed = parse_candidate_patch(SINGLE_HUNK_PATCH)
        h0 = parsed.files[0].hunks[0].hunk_id
        sub = create_tested_patch_subset_from_hunks(parsed, (h0,))

        tampered_scope = create_causal_slice_scope(
            snapshot=snap,
            frozen_contract_digest=FROZEN_CONTRACT,
            sealed_witness_digest="9" * 64,
            requirement_id=REQ_ID,
        )
        foreign_fact = create_subset_execution_fact(
            subset=sub, scope=tampered_scope, outcome=WitnessOutcome.PASS, exit_code=0
        )

        minimizer = BoundedSubsetMinimizer(execution_callback=lambda _s, _sc: foreign_fact)
        with pytest.raises(SliceIdentityMismatchError):
            minimizer.minimize(
                snapshot=snap,
                frozen_contract_digest=FROZEN_CONTRACT,
                sealed_witness_digest=SEALED_WITNESS,
                requirement_id=REQ_ID,
                base_outcome=WitnessOutcome.FAIL,
            )

    def test_case_e_execution_fact_uses_different_frozen_contract(self) -> None:
        """E. Execution fact uses different frozen contract => rejected."""
        snap = _make_snapshot(SINGLE_HUNK_PATCH)
        parsed = parse_candidate_patch(SINGLE_HUNK_PATCH)
        h0 = parsed.files[0].hunks[0].hunk_id
        sub = create_tested_patch_subset_from_hunks(parsed, (h0,))

        tampered_snap = _make_snapshot(SINGLE_HUNK_PATCH, frozen_contract="8" * 64)
        tampered_scope = create_causal_slice_scope(
            snapshot=tampered_snap,
            frozen_contract_digest="8" * 64,
            sealed_witness_digest=SEALED_WITNESS,
            requirement_id=REQ_ID,
        )
        foreign_fact = create_subset_execution_fact(
            subset=sub, scope=tampered_scope, outcome=WitnessOutcome.PASS, exit_code=0
        )

        minimizer = BoundedSubsetMinimizer(execution_callback=lambda _s, _sc: foreign_fact)
        with pytest.raises(SliceIdentityMismatchError):
            minimizer.minimize(
                snapshot=snap,
                frozen_contract_digest=FROZEN_CONTRACT,
                sealed_witness_digest=SEALED_WITNESS,
                requirement_id=REQ_ID,
                base_outcome=WitnessOutcome.FAIL,
            )

    def test_case_f_execution_fact_uses_different_scope_or_subset_digest(self) -> None:
        """F. Execution fact uses different scope/subset digest => rejected."""
        snap = _make_snapshot(SINGLE_HUNK_PATCH)
        parsed = parse_candidate_patch(SINGLE_HUNK_PATCH)
        h0 = parsed.files[0].hunks[0].hunk_id
        sub = create_tested_patch_subset_from_hunks(parsed, (h0,))
        scope = create_causal_slice_scope(
            snapshot=snap,
            frozen_contract_digest=FROZEN_CONTRACT,
            sealed_witness_digest=SEALED_WITNESS,
            requirement_id=REQ_ID,
        )
        fact = create_subset_execution_fact(
            subset=sub, scope=scope, outcome=WitnessOutcome.PASS, exit_code=0
        )

        with pytest.raises((SliceIdentityMismatchError, SliceScopeTamperingError)):
            replace(fact, scope_digest="0" * 64)

    def test_case_g_execution_fact_uses_different_candidate_or_tree_identity(self) -> None:
        """G. Execution fact uses different candidate/tree identity => rejected."""
        snap = _make_snapshot(SINGLE_HUNK_PATCH)
        foreign_snap = _make_snapshot(SINGLE_HUNK_PATCH, candidate_id="cand-FOREIGN-999")
        foreign_scope = create_causal_slice_scope(
            snapshot=foreign_snap,
            frozen_contract_digest=FROZEN_CONTRACT,
            sealed_witness_digest=SEALED_WITNESS,
            requirement_id=REQ_ID,
        )
        parsed = parse_candidate_patch(SINGLE_HUNK_PATCH)
        h0 = parsed.files[0].hunks[0].hunk_id
        sub = create_tested_patch_subset_from_hunks(parsed, (h0,))
        foreign_fact = create_subset_execution_fact(
            subset=sub, scope=foreign_scope, outcome=WitnessOutcome.PASS, exit_code=0
        )

        minimizer = BoundedSubsetMinimizer(execution_callback=lambda _s, _sc: foreign_fact)
        with pytest.raises(SliceIdentityMismatchError):
            minimizer.minimize(
                snapshot=snap,
                frozen_contract_digest=FROZEN_CONTRACT,
                sealed_witness_digest=SEALED_WITNESS,
                requirement_id=REQ_ID,
                base_outcome=WitnessOutcome.FAIL,
            )

    def test_case_h_evaluated_subset_count_order_mismatch(self) -> None:
        """H. Evaluated-subset count/order mismatch => rejected."""
        snap = _make_snapshot(SINGLE_HUNK_PATCH)
        scope = create_causal_slice_scope(
            snapshot=snap,
            frozen_contract_digest=FROZEN_CONTRACT,
            sealed_witness_digest=SEALED_WITNESS,
            requirement_id=REQ_ID,
        )
        parsed = parse_candidate_patch(SINGLE_HUNK_PATCH)
        h0 = parsed.files[0].hunks[0].hunk_id
        sub = create_tested_patch_subset_from_hunks(parsed, (h0,))
        fact = create_subset_execution_fact(
            subset=sub, scope=scope, outcome=WitnessOutcome.PASS, exit_code=0
        )
        slice_art = create_bounded_causal_slice(
            slice_id="slice-001",
            scope=scope,
            tested_subset=sub,
            status=CausalSliceStatus.TESTED_NECESSARY_SUBSET,
            completeness=SliceSearchCompleteness.EXHAUSTIVE_BOUNDED,
        )

        with pytest.raises(
            (SliceIdentityMismatchError, SliceReceiptIntegrityError), match="Count mismatch"
        ):
            create_causal_slice_receipt(
                requirement_id=REQ_ID,
                frozen_contract_digest=FROZEN_CONTRACT,
                sealed_witness_digest=SEALED_WITNESS,
                witness_id="wit-001",
                source_locator=REPO_LOCATOR,
                source_commit_id=BASE_COMMIT,
                candidate_id=snap.candidate_id,
                candidate_tree_digest=CAND_TREE,
                candidate_patch_digest=snap.patch_digest,
                slice_artifact=slice_art,
                search_budget=SliceSearchBudget(),
                completeness=slice_art.completeness,
                execution_facts=(fact,),
                tested_subsets=(sub, sub),
            )

        with pytest.raises(
            (SliceIdentityMismatchError, SliceReceiptIntegrityError), match="Count mismatch"
        ):
            create_causal_slice_receipt(
                requirement_id=REQ_ID,
                frozen_contract_digest=FROZEN_CONTRACT,
                sealed_witness_digest=SEALED_WITNESS,
                witness_id="wit-001",
                source_locator=REPO_LOCATOR,
                source_commit_id=BASE_COMMIT,
                candidate_id=snap.candidate_id,
                candidate_tree_digest=CAND_TREE,
                candidate_patch_digest=snap.patch_digest,
                slice_artifact=slice_art,
                search_budget=SliceSearchBudget(),
                completeness=slice_art.completeness,
                execution_facts=(fact,),
                tested_subsets=(sub,),
                evaluated_outcomes=(WitnessOutcome.PASS, WitnessOutcome.FAIL),
            )

    def test_case_i_receipt_status_differs_from_bounded_minimizer_result(self) -> None:
        """I. Receipt status differs from BoundedMinimizerResult => rejected."""
        snap = _make_snapshot(SINGLE_HUNK_PATCH)
        minimizer = BoundedSubsetMinimizer(
            execution_callback=lambda sub, scope: _make_fact(sub, scope, WitnessOutcome.PASS)
        )
        res = minimizer.minimize(
            snapshot=snap,
            frozen_contract_digest=FROZEN_CONTRACT,
            sealed_witness_digest=SEALED_WITNESS,
            requirement_id=REQ_ID,
            base_outcome=WitnessOutcome.FAIL,
        )
        assert res.status == CausalSliceStatus.TESTED_NECESSARY_SUBSET

        receipt = create_causal_slice_receipt_from_result(
            result=res,
            witness_id="wit-001",
        )
        assert receipt.status == res.status

        with pytest.raises(SliceIdentityMismatchError, match="status mismatch"):
            replace(receipt, status=CausalSliceStatus.INVALID_SUBSET)

    def test_case_j_receipt_completeness_differs_from_bounded_minimizer_result(self) -> None:
        """J. Receipt completeness differs from BoundedMinimizerResult => rejected."""
        snap = _make_snapshot(SINGLE_HUNK_PATCH)
        minimizer = BoundedSubsetMinimizer(
            execution_callback=lambda sub, scope: _make_fact(sub, scope, WitnessOutcome.PASS)
        )
        res = minimizer.minimize(
            snapshot=snap,
            frozen_contract_digest=FROZEN_CONTRACT,
            sealed_witness_digest=SEALED_WITNESS,
            requirement_id=REQ_ID,
            base_outcome=WitnessOutcome.FAIL,
        )
        receipt = create_causal_slice_receipt_from_result(
            result=res,
            witness_id="wit-001",
        )
        assert receipt.completeness == res.completeness

        with pytest.raises(SliceIdentityMismatchError, match="completeness mismatch"):
            create_causal_slice_receipt(
                requirement_id=REQ_ID,
                frozen_contract_digest=FROZEN_CONTRACT,
                sealed_witness_digest=SEALED_WITNESS,
                witness_id="wit-001",
                source_locator=receipt.source_locator,
                source_commit_id=receipt.source_commit_id,
                candidate_id=receipt.candidate_id,
                candidate_tree_digest=receipt.candidate_tree_digest,
                candidate_patch_digest=receipt.candidate_patch_digest,
                slice_artifact=receipt.slice_artifact,
                search_budget=receipt.search_budget,
                completeness=SliceSearchCompleteness.PARTIAL_ABORTED,
                execution_facts=receipt.execution_facts,
                tested_subsets=receipt.tested_subsets,
            )

    def test_case_k_cached_structured_execution_fact_retains_original_provenance(self) -> None:
        """K. Cached structured execution fact retains original provenance."""
        snap = _make_snapshot(SINGLE_HUNK_PATCH)
        scope = create_causal_slice_scope(
            snapshot=snap,
            frozen_contract_digest=FROZEN_CONTRACT,
            sealed_witness_digest=SEALED_WITNESS,
            requirement_id=REQ_ID,
            provenance=EvidenceProvenance.LOCAL_EXECUTION,
        )
        parsed = parse_candidate_patch(SINGLE_HUNK_PATCH)
        h0 = parsed.files[0].hunks[0].hunk_id
        sub = create_tested_patch_subset_from_hunks(parsed, (h0,))

        cache = DeterministicExecutionCache()
        entry = cache.store(
            subset=sub,
            scope=scope,
            outcome=WitnessOutcome.PASS,
            exit_code=0,
        )
        hit = cache.lookup(subset=sub, scope=scope)
        assert hit.hit is True
        assert hit.entry is not None
        cached_fact = hit.entry.to_execution_fact()
        assert cached_fact.provenance == EvidenceProvenance.LOCAL_EXECUTION
        assert hit.entry.execution_fact is not None
        assert cached_fact.execution_digest == hit.entry.execution_fact.execution_digest

        res = cache.lookup_by_key(entry.key, requested_provenance=EvidenceProvenance.LIVE_NEBIUS)
        assert res.hit is False
        assert res.rejection_reason in (
            CacheRejectionReason.FORBIDDEN_PROVENANCE_SUBSTITUTION,
            CacheRejectionReason.PROVENANCE_MISMATCH,
        )

        with pytest.raises(ForbiddenProvenanceSubstitutionError):
            cache.lookup(
                subset=sub,
                scope=scope,
                requested_provenance=EvidenceProvenance.LIVE_NEBIUS,
            )

    def test_case_l_error_timeout_cannot_transform_into_behavioral_fail(self) -> None:
        """L. ERROR/TIMEOUT cannot be transformed into behavioral FAIL."""
        snap = _make_snapshot(SINGLE_HUNK_PATCH)
        minimizer_err = BoundedSubsetMinimizer(
            execution_callback=lambda sub, scope: _make_fact(sub, scope, WitnessOutcome.ERROR)
        )
        res_err = minimizer_err.minimize(
            snapshot=snap,
            frozen_contract_digest=FROZEN_CONTRACT,
            sealed_witness_digest=SEALED_WITNESS,
            requirement_id=REQ_ID,
            base_outcome=WitnessOutcome.FAIL,
        )
        assert res_err.status == CausalSliceStatus.INVALID_SUBSET
        assert res_err.evaluated_subsets[0].outcome == WitnessOutcome.ERROR
        # Verify it was not transformed into behavioral FAIL
        outcome_val = res_err.evaluated_subsets[0].outcome.value
        assert outcome_val != WitnessOutcome.FAIL.value

        minimizer_to = BoundedSubsetMinimizer(
            execution_callback=lambda sub, scope: _make_fact(sub, scope, WitnessOutcome.TIMEOUT)
        )
        res_to = minimizer_to.minimize(
            snapshot=snap,
            frozen_contract_digest=FROZEN_CONTRACT,
            sealed_witness_digest=SEALED_WITNESS,
            requirement_id=REQ_ID,
            base_outcome=WitnessOutcome.FAIL,
        )
        assert res_to.status == CausalSliceStatus.INVALID_SUBSET
        assert res_to.evaluated_subsets[0].outcome == WitnessOutcome.TIMEOUT
        outcome_to_val = res_to.evaluated_subsets[0].outcome.value
        assert outcome_to_val != WitnessOutcome.FAIL.value

    def test_case_m_tampered_execution_or_result_digest_fails_closed(self) -> None:
        """M. Tampered execution/result digest fails closed."""
        snap = _make_snapshot(SINGLE_HUNK_PATCH)
        scope = create_causal_slice_scope(
            snapshot=snap,
            frozen_contract_digest=FROZEN_CONTRACT,
            sealed_witness_digest=SEALED_WITNESS,
            requirement_id=REQ_ID,
        )
        parsed = parse_candidate_patch(SINGLE_HUNK_PATCH)
        h0 = parsed.files[0].hunks[0].hunk_id
        sub = create_tested_patch_subset_from_hunks(parsed, (h0,))
        fact = create_subset_execution_fact(
            subset=sub, scope=scope, outcome=WitnessOutcome.PASS, exit_code=0
        )

        with pytest.raises(
            (SliceReceiptIntegrityError, SliceScopeTamperingError),
            match="execution_digest mismatch",
        ):
            replace(fact, execution_digest="0" * 64)

        with pytest.raises(
            (SliceReceiptIntegrityError, SliceScopeTamperingError),
            match="execution_digest mismatch",
        ):
            replace(fact, outcome=WitnessOutcome.FAIL)

    def test_case_n_naked_witness_outcome_rejected(self) -> None:
        """N. Naked WitnessOutcome is no longer sufficient for authentic minimizer evidence."""
        snap = _make_snapshot(SINGLE_HUNK_PATCH)
        minimizer = BoundedSubsetMinimizer(
            execution_callback=lambda _s, _sc: WitnessOutcome.PASS  # type: ignore[arg-type,return-value]
        )
        with pytest.raises(TypeError, match="naked WitnessOutcome is no longer sufficient"):
            minimizer.minimize(
                snapshot=snap,
                frozen_contract_digest=FROZEN_CONTRACT,
                sealed_witness_digest=SEALED_WITNESS,
                requirement_id=REQ_ID,
                base_outcome=WitnessOutcome.FAIL,
            )

    def test_case_o_deterministic_identical_inputs_produce_identical_identities(self) -> None:
        """O. Identical inputs/runtime produce identical relevant evidence identities."""
        snap = _make_snapshot(SINGLE_HUNK_PATCH)
        cfg = {"python_version": "3.11", "runner": "pytest"}
        cfg_digest = compute_runtime_config_digest(cfg)

        def eval_cb(sub: TestedPatchSubset, scope: Any) -> SubsetExecutionFact:
            return create_subset_execution_fact(
                subset=sub,
                scope=scope,
                outcome=WitnessOutcome.PASS,
                runtime_config_digest=cfg_digest,
                exit_code=0,
                created_at_utc="2026-10-08T00:00:00Z",
            )

        minimizer_1 = BoundedSubsetMinimizer(
            execution_callback=eval_cb,
            runtime_config_digest=cfg_digest,
        )
        res_1 = minimizer_1.minimize(
            snapshot=snap,
            frozen_contract_digest=FROZEN_CONTRACT,
            sealed_witness_digest=SEALED_WITNESS,
            requirement_id=REQ_ID,
            base_outcome=WitnessOutcome.FAIL,
            created_at_utc="2026-10-08T00:00:00Z",
        )
        receipt_1 = create_causal_slice_receipt_from_result(
            result=res_1,
            witness_id="wit-001",
            created_at_utc="2026-10-08T00:00:00Z",
        )

        minimizer_2 = BoundedSubsetMinimizer(
            execution_callback=eval_cb,
            runtime_config_digest=cfg_digest,
        )
        res_2 = minimizer_2.minimize(
            snapshot=snap,
            frozen_contract_digest=FROZEN_CONTRACT,
            sealed_witness_digest=SEALED_WITNESS,
            requirement_id=REQ_ID,
            base_outcome=WitnessOutcome.FAIL,
            created_at_utc="2026-10-08T00:00:00Z",
        )
        receipt_2 = create_causal_slice_receipt_from_result(
            result=res_2,
            witness_id="wit-001",
            created_at_utc="2026-10-08T00:00:00Z",
        )

        assert res_1.status == res_2.status
        assert res_1.runtime_config_digest == res_2.runtime_config_digest == cfg_digest
        assert receipt_1.receipt_digest == receipt_2.receipt_digest
        assert (
            receipt_1.execution_facts[0].execution_digest
            == receipt_2.execution_facts[0].execution_digest
        )
