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
    SliceSearchCompleteness,
    TestedPatchSubset,
    create_bounded_causal_slice,
    create_causal_slice_scope,
)
from basebreak.causal.slice_receipt import (
    CausalSliceReceipt,
    SliceReceiptTamperingError,
    create_causal_slice_receipt,
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


class TestP12AdversarialCoverage:
    """Complete 27-scenario adversarial and boundary verification suite for P-12."""

    def test_p12_05_01_one_necessary_hunk(self) -> None:
        """1. Candidate with 1 hunk: base failed, full candidate passes."""
        snap = _make_snapshot(SINGLE_HUNK_PATCH)
        minimizer = BoundedSubsetMinimizer(
            execution_callback=lambda sub, scope: WitnessOutcome.PASS
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

        def eval_cb(sub: TestedPatchSubset, scope: object) -> WitnessOutcome:
            return WitnessOutcome.PASS if h0 in sub.retained_hunk_ids else WitnessOutcome.FAIL

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

        def eval_cb(sub: TestedPatchSubset, scope: object) -> WitnessOutcome:
            return WitnessOutcome.PASS if len(sub.retained_hunk_ids) == 2 else WitnessOutcome.FAIL

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

        def eval_cb(sub: TestedPatchSubset, scope: object) -> WitnessOutcome:
            return WitnessOutcome.PASS

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

        def eval_cb(sub: TestedPatchSubset, scope: object) -> WitnessOutcome:
            retained = set(sub.retained_hunk_ids)
            if len(retained) == 3:
                return WitnessOutcome.PASS
            if retained in ({h0}, {h1}):
                return WitnessOutcome.PASS
            if retained == {h0, h1}:
                return WitnessOutcome.FAIL
            return WitnessOutcome.FAIL

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

        def eval_cb(sub: TestedPatchSubset, scope: object) -> WitnessOutcome:
            retained = set(sub.retained_hunk_ids)
            if len(retained) == 3:
                return WitnessOutcome.PASS
            if retained in ({h0}, {h1}):
                return WitnessOutcome.PASS
            if retained == {h0, h1}:
                return WitnessOutcome.FAIL
            return WitnessOutcome.FAIL

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
            execution_callback=lambda sub, scope: WitnessOutcome.PASS,
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

        def eval_cb(sub: TestedPatchSubset, scope: object) -> WitnessOutcome:
            if len(sub.retained_hunk_ids) == 2:
                return WitnessOutcome.PASS
            return WitnessOutcome.TIMEOUT

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

        def eval_cb(sub: TestedPatchSubset, scope: object) -> WitnessOutcome:
            return WitnessOutcome.PASS if len(sub.retained_hunk_ids) == 3 else WitnessOutcome.FAIL

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
            execution_callback=lambda sub, scope: WitnessOutcome.ERROR
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
            execution_callback=lambda sub, scope: WitnessOutcome.TIMEOUT
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
            execution_callback=lambda sub, scope: WitnessOutcome.PASS
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

        def eval_cb(sub: TestedPatchSubset, scope: object) -> WitnessOutcome:
            return WitnessOutcome.PASS if h0 in sub.retained_hunk_ids else WitnessOutcome.FAIL

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
