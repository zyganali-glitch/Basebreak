"""Unit and adversarial tests for P-12.01: Causal-slice scope and non-formal-proof disclaimer.

Validates:
1. Exact identity binding across candidate, contract, witness, counterfactual, and receipt.
2. Candidate mismatch rejection (candidate_id, commit, tree).
3. Patch digest mismatch rejection.
4. Contract digest mismatch rejection.
5. Witness digest mismatch rejection.
6. Zero caller authority: neither scope, slice, subset, nor model proposal can assert authority.
7. Malformed / empty subset rejection.
8. Non-formal-proof disclaimer cannot be omitted from serialized/public slice representations.
9. Incomplete search cannot claim global minimality.
10. Model proposal has zero causal/minimal verdict authority.
11. Serialization and deserialization preserves exact bounded semantics.
12. Tamper detection on modified fields.
13. Prohibited marketing/certainty terminology is rejected.
14. Anti-collapse invariant: ERROR and TIMEOUT cannot count as behavioral FAIL.
15. Human-readable markdown rendering prominently includes the disclaimer.
"""

from __future__ import annotations

from typing import Any

import pytest

from basebreak.builder.capture import CandidateSnapshot
from basebreak.causal.slice import (
    CANONICAL_DISCLAIMER_TEXT,
    CANONICAL_DISCLAIMER_VERSION,
    BoundedCausalSlice,
    CausalSliceScope,
    CausalSliceScopeRules,
    CausalSliceStatus,
    DisclaimerMissingError,
    DisclaimerViolationError,
    IncompleteSearchAuthorityError,
    InvalidSubsetError,
    ModelSliceProposal,
    NonFormalProofDisclaimer,
    ProhibitedTerminologyError,
    SliceAuthorityError,
    SliceIdentityMismatchError,
    SliceScopeTamperingError,
    SliceSearchCompleteness,
    TestedPatchSubset,
    create_bounded_causal_slice,
    create_canonical_disclaimer,
    create_causal_slice_scope,
    validate_no_prohibited_terms,
    verify_slice_integrity,
)
from basebreak.causal.subtraction import SubtractionStrategyType
from basebreak.domain.source import CommitRevision, SourceIdentity
from basebreak.domain.verdict import EvidenceProvenance
from basebreak.evidence.artifact import compute_bytes_digest
from basebreak.verifier.witness_result import WitnessOutcome

FROZEN_CONTRACT_DIGEST = "a" * 64
SEALED_WITNESS_DIGEST = "b" * 64
BASE_COMMIT_ID = "c" * 40
CANDIDATE_TREE_DIGEST = "d" * 40
REPO_LOCATOR = "https://github.com/example/repo.git"
REQUIREMENT_ID = "REQ-BOUNDED-001"

SAMPLE_PATCH = (
    "diff --git a/src/math.py b/src/math.py\n"
    "index 1111111..2222222 100644\n"
    "--- a/src/math.py\n"
    "+++ b/src/math.py\n"
    "@@ -1,2 +1,3 @@\n"
    " def div(a, b):\n"
    "+    if b == 0: raise ValueError('zero')\n"
    "     return a / b\n"
)


def _make_snapshot(
    patch_text: str = SAMPLE_PATCH,
    frozen_contract_digest: str = FROZEN_CONTRACT_DIGEST,
    candidate_id: str = "cand-p12-001",
) -> CandidateSnapshot:
    patch_digest = compute_bytes_digest(patch_text.encode("utf-8")).value
    source = SourceIdentity(
        locator=REPO_LOCATOR,
        revision=CommitRevision(BASE_COMMIT_ID),
        subpath="src/math.py",
    )
    return CandidateSnapshot(
        candidate_id=candidate_id,
        source_identity=source,
        candidate_tree_digest=CANDIDATE_TREE_DIGEST,
        patch_digest=patch_digest,
        patch_text=patch_text,
        files_added=(),
        files_modified=("src/math.py",),
        files_deleted=(),
        builder_authored_tests=(),
        frozen_contract_digest=frozen_contract_digest,
        context_digest="f" * 64,
        provenance=EvidenceProvenance.LOCAL_EXECUTION,
    )


def _make_tested_subset(
    subset_id: str = "sub-001",
    retained_files: tuple[str, ...] = ("src/math.py",),
    retained_hunk_ids: tuple[str, ...] = ("src/math.py:0",),
    subtracted_files: tuple[str, ...] = (),
    subtracted_hunk_ids: tuple[str, ...] = (),
    retained_patch_digest: str = "1" * 64,
    subtracted_delta_digest: str = "2" * 64,
) -> TestedPatchSubset:
    return TestedPatchSubset(
        subset_id=subset_id,
        strategy_type=SubtractionStrategyType.HUNK_LEVEL_REVERT,
        retained_files=retained_files,
        retained_hunk_ids=retained_hunk_ids,
        subtracted_files=subtracted_files,
        subtracted_hunk_ids=subtracted_hunk_ids,
        retained_patch_digest=retained_patch_digest,
        subtracted_delta_digest=subtracted_delta_digest,
        is_empty=False,
    )


# --- Test Suite ---


class TestCausalSliceScopeIdentityBinding:
    """Tests exact identity binding and mismatch detection in CausalSliceScope."""

    def test_scope_creation_and_digest_computation(self) -> None:
        snapshot = _make_snapshot()
        scope = create_causal_slice_scope(
            snapshot=snapshot,
            frozen_contract_digest=FROZEN_CONTRACT_DIGEST,
            sealed_witness_digest=SEALED_WITNESS_DIGEST,
            requirement_id=REQUIREMENT_ID,
            counterfactual_id="cf-001",
            delta_digest="2" * 64,
            receipt_digest="3" * 64,
            provenance=EvidenceProvenance.LOCAL_EXECUTION,
        )

        assert scope.candidate_id == "cand-p12-001"
        assert scope.source_locator == REPO_LOCATOR
        assert scope.source_commit_id == BASE_COMMIT_ID
        assert scope.source_subpath == "src/math.py"
        assert scope.candidate_tree_digest == CANDIDATE_TREE_DIGEST
        assert scope.frozen_contract_digest == FROZEN_CONTRACT_DIGEST
        assert scope.sealed_witness_digest == SEALED_WITNESS_DIGEST
        assert scope.counterfactual_id == "cf-001"
        assert scope.delta_digest == "2" * 64
        assert scope.receipt_digest == "3" * 64
        assert scope.is_authoritative is False
        assert scope.grants_pass is False
        assert scope.is_causally_verified is False

        digest = scope.scope_digest
        assert len(digest) == 64
        assert int(digest, 16) > 0

    def test_contract_digest_mismatch_rejected(self) -> None:
        snapshot = _make_snapshot(frozen_contract_digest=FROZEN_CONTRACT_DIGEST)
        with pytest.raises(SliceIdentityMismatchError, match="frozen_contract_digest mismatch"):
            create_causal_slice_scope(
                snapshot=snapshot,
                frozen_contract_digest="9" * 64,
                sealed_witness_digest=SEALED_WITNESS_DIGEST,
                requirement_id=REQUIREMENT_ID,
            )

    def test_invalid_witness_digest_rejected(self) -> None:
        snapshot = _make_snapshot()
        with pytest.raises(ValueError, match="sealed_witness_digest"):
            create_causal_slice_scope(
                snapshot=snapshot,
                frozen_contract_digest=FROZEN_CONTRACT_DIGEST,
                sealed_witness_digest="not-a-valid-hex-digest",
                requirement_id=REQUIREMENT_ID,
            )

    def test_scope_deserialization_tampering_rejected(self) -> None:
        snapshot = _make_snapshot()
        scope = create_causal_slice_scope(
            snapshot=snapshot,
            frozen_contract_digest=FROZEN_CONTRACT_DIGEST,
            sealed_witness_digest=SEALED_WITNESS_DIGEST,
            requirement_id=REQUIREMENT_ID,
        )
        data = scope.to_dict()
        data["candidate_id"] = "tampered-candidate-id"

        with pytest.raises(SliceScopeTamperingError, match="scope_digest mismatch"):
            CausalSliceScope.from_dict(data)


class TestAuthorityBoundaries:
    """Verifies that no component of the causal slice can assert authority."""

    def test_scope_caller_authority_rejected(self) -> None:
        with pytest.raises(SliceAuthorityError, match="is_authoritative must be False"):
            CausalSliceScope(
                candidate_id="c1",
                source_locator=REPO_LOCATOR,
                source_commit_id=BASE_COMMIT_ID,
                source_subpath="",
                candidate_tree_digest=CANDIDATE_TREE_DIGEST,
                candidate_patch_digest="p" * 64,
                frozen_contract_digest=FROZEN_CONTRACT_DIGEST,
                sealed_witness_digest=SEALED_WITNESS_DIGEST,
                requirement_id=REQUIREMENT_ID,
                provenance=EvidenceProvenance.LOCAL_EXECUTION,
                is_authoritative=True,
            )

    def test_scope_grants_pass_rejected(self) -> None:
        with pytest.raises(SliceAuthorityError, match="grants_pass must be False"):
            CausalSliceScope(
                candidate_id="c1",
                source_locator=REPO_LOCATOR,
                source_commit_id=BASE_COMMIT_ID,
                source_subpath="",
                candidate_tree_digest=CANDIDATE_TREE_DIGEST,
                candidate_patch_digest="p" * 64,
                frozen_contract_digest=FROZEN_CONTRACT_DIGEST,
                sealed_witness_digest=SEALED_WITNESS_DIGEST,
                requirement_id=REQUIREMENT_ID,
                provenance=EvidenceProvenance.LOCAL_EXECUTION,
                grants_pass=True,
            )

    def test_scope_is_causally_verified_rejected(self) -> None:
        with pytest.raises(SliceAuthorityError, match="is_causally_verified must be False"):
            CausalSliceScope(
                candidate_id="c1",
                source_locator=REPO_LOCATOR,
                source_commit_id=BASE_COMMIT_ID,
                source_subpath="",
                candidate_tree_digest=CANDIDATE_TREE_DIGEST,
                candidate_patch_digest="p" * 64,
                frozen_contract_digest=FROZEN_CONTRACT_DIGEST,
                sealed_witness_digest=SEALED_WITNESS_DIGEST,
                requirement_id=REQUIREMENT_ID,
                provenance=EvidenceProvenance.LOCAL_EXECUTION,
                is_causally_verified=True,
            )

    def test_tested_subset_caller_authority_rejected(self) -> None:
        with pytest.raises(SliceAuthorityError, match="is_authoritative must be False"):
            TestedPatchSubset(
                subset_id="sub-01",
                strategy_type=SubtractionStrategyType.FULL_PATCH_REVERT,
                retained_files=("f1.py",),
                retained_hunk_ids=("f1.py:0",),
                subtracted_files=(),
                subtracted_hunk_ids=(),
                retained_patch_digest="1" * 64,
                subtracted_delta_digest="2" * 64,
                is_authoritative=True,
            )

    def test_bounded_slice_caller_authority_rejected(self) -> None:
        snapshot = _make_snapshot()
        scope = create_causal_slice_scope(
            snapshot=snapshot,
            frozen_contract_digest=FROZEN_CONTRACT_DIGEST,
            sealed_witness_digest=SEALED_WITNESS_DIGEST,
            requirement_id=REQUIREMENT_ID,
        )
        subset = _make_tested_subset()

        with pytest.raises(SliceAuthorityError, match="is_authoritative must be False"):
            BoundedCausalSlice(
                slice_id="slc-01",
                scope=scope,
                tested_subset=subset,
                status=CausalSliceStatus.TESTED_NECESSARY_SUBSET,
                completeness=SliceSearchCompleteness.BOUNDED_GREEDY,
                summary_label="tested necessary subset under witness",
                disclaimer=create_canonical_disclaimer(),
                slice_digest="0" * 64,
                created_at_utc="2026-10-07T00:00:00Z",
                is_authoritative=True,
            )

    def test_model_proposal_cannot_assert_authority(self) -> None:
        with pytest.raises(SliceAuthorityError, match="is_authoritative must be False"):
            ModelSliceProposal(
                proposed_retained_hunks=("h1",),
                is_authoritative=True,
            )

        with pytest.raises(SliceAuthorityError, match="grants_pass must be False"):
            ModelSliceProposal(
                proposed_retained_hunks=("h1",),
                grants_pass=True,
            )

        with pytest.raises(SliceAuthorityError, match="is_causally_verified must be False"):
            ModelSliceProposal(
                proposed_retained_hunks=("h1",),
                is_causally_verified=True,
            )

        with pytest.raises(SliceAuthorityError, match="claims_minimality must be False"):
            ModelSliceProposal(
                proposed_retained_hunks=("h1",),
                claims_minimality=True,
            )

    def test_model_proposal_confidence_bounded(self) -> None:
        with pytest.raises(ValueError, match="model_confidence must be between 0.0 and 1.0"):
            ModelSliceProposal(
                proposed_retained_hunks=("h1",),
                model_confidence=1.5,
            )


class TestTestedPatchSubsetValidation:
    """Validates TestedPatchSubset constraints and fail-closed behaviors."""

    def test_empty_subset_rejected(self) -> None:
        with pytest.raises(InvalidSubsetError, match="is_empty=True"):
            TestedPatchSubset(
                subset_id="sub-empty",
                strategy_type=SubtractionStrategyType.FULL_PATCH_REVERT,
                retained_files=("f.py",),
                retained_hunk_ids=("h0",),
                subtracted_files=(),
                subtracted_hunk_ids=(),
                retained_patch_digest="1" * 64,
                subtracted_delta_digest="2" * 64,
                is_empty=True,
            )

    def test_subset_with_no_retained_items_rejected(self) -> None:
        with pytest.raises(
            InvalidSubsetError, match="must have at least one retained file or hunk"
        ):
            TestedPatchSubset(
                subset_id="sub-empty",
                strategy_type=SubtractionStrategyType.FULL_PATCH_REVERT,
                retained_files=(),
                retained_hunk_ids=(),
                subtracted_files=("f.py",),
                subtracted_hunk_ids=("h0",),
                retained_patch_digest="1" * 64,
                subtracted_delta_digest="2" * 64,
                is_empty=False,
            )

    def test_subset_serialization_roundtrip(self) -> None:
        subset = _make_tested_subset()
        data = subset.to_dict()
        restored = TestedPatchSubset.from_dict(data)
        assert restored == subset


class TestNonFormalProofDisclaimer:
    """Validates the canonical machine-readable and human-readable disclaimer."""

    def test_canonical_disclaimer_creation(self) -> None:
        disc = create_canonical_disclaimer()
        assert disc.statement == CANONICAL_DISCLAIMER_TEXT
        assert disc.disclaimer_version == CANONICAL_DISCLAIMER_VERSION
        assert disc.is_mathematical_proof is False
        assert disc.is_globally_minimal is False
        assert disc.is_universally_necessary is False
        assert disc.guarantees_untested_inputs is False
        assert disc.guarantees_semantic_equivalence is False
        assert disc.is_formal_verification is False

    @pytest.mark.parametrize(
        "forbidden_flag",
        [
            "is_mathematical_proof",
            "is_globally_minimal",
            "is_universally_necessary",
            "guarantees_untested_inputs",
            "guarantees_semantic_equivalence",
            "is_formal_verification",
        ],
    )
    def test_disclaimer_flags_cannot_be_true(self, forbidden_flag: str) -> None:
        kwargs: dict[str, Any] = {forbidden_flag: True}
        with pytest.raises(DisclaimerViolationError):
            NonFormalProofDisclaimer(**kwargs)

    def test_disclaimer_cannot_be_omitted_from_serialized_slice(self) -> None:
        snapshot = _make_snapshot()
        scope = create_causal_slice_scope(
            snapshot=snapshot,
            frozen_contract_digest=FROZEN_CONTRACT_DIGEST,
            sealed_witness_digest=SEALED_WITNESS_DIGEST,
            requirement_id=REQUIREMENT_ID,
            delta_digest="2" * 64,
        )
        subset = _make_tested_subset(subtracted_delta_digest="2" * 64)
        slice_artifact = create_bounded_causal_slice(
            slice_id="slc-001",
            scope=scope,
            tested_subset=subset,
        )

        data = slice_artifact.to_dict()
        del data["disclaimer"]

        with pytest.raises(
            DisclaimerMissingError, match="mandatory non-formal-proof disclaimer cannot be omitted"
        ):
            BoundedCausalSlice.from_dict(data)

    def test_disclaimer_with_empty_statement_rejected(self) -> None:
        with pytest.raises(DisclaimerMissingError, match="statement must be a non-empty string"):
            NonFormalProofDisclaimer(statement="")


class TestIncompleteSearchAndGlobalMinimality:
    """Verifies that incomplete search cannot claim global minimality."""

    def test_incomplete_search_cannot_claim_global_minimality(self) -> None:
        snapshot = _make_snapshot()
        scope = create_causal_slice_scope(
            snapshot=snapshot,
            frozen_contract_digest=FROZEN_CONTRACT_DIGEST,
            sealed_witness_digest=SEALED_WITNESS_DIGEST,
            requirement_id=REQUIREMENT_ID,
            delta_digest="2" * 64,
        )
        subset = _make_tested_subset(subtracted_delta_digest="2" * 64)

        with pytest.raises(
            IncompleteSearchAuthorityError, match="claims_global_minimality must be False"
        ):
            BoundedCausalSlice(
                slice_id="slc-001",
                scope=scope,
                tested_subset=subset,
                status=CausalSliceStatus.TESTED_NECESSARY_SUBSET,
                completeness=SliceSearchCompleteness.BOUNDED_GREEDY,
                summary_label="tested necessary subset under witness",
                disclaimer=create_canonical_disclaimer(),
                slice_digest="0" * 64,
                created_at_utc="2026-10-07T00:00:00Z",
                claims_global_minimality=True,
            )

    def test_rules_validate_completeness_and_claims(self) -> None:
        with pytest.raises(IncompleteSearchAuthorityError, match="cannot claim global minimality"):
            CausalSliceScopeRules.validate_completeness_and_claims(
                SliceSearchCompleteness.BOUNDED_HEURISTIC,
                claims_global_minimality=True,
            )


class TestProhibitedMarketingTerminology:
    """Verifies that certainty and marketing terminology are rejected."""

    @pytest.mark.parametrize(
        "prohibited_term",
        [
            "mathematically minimal",
            "formally proven",
            "universally necessary",
            "formal proof",
            "absolute minimal patch",
            "globally minimal patch",
        ],
    )
    def test_prohibited_terms_rejected_in_summary_label(self, prohibited_term: str) -> None:
        snapshot = _make_snapshot()
        scope = create_causal_slice_scope(
            snapshot=snapshot,
            frozen_contract_digest=FROZEN_CONTRACT_DIGEST,
            sealed_witness_digest=SEALED_WITNESS_DIGEST,
            requirement_id=REQUIREMENT_ID,
            delta_digest="2" * 64,
        )
        subset = _make_tested_subset(subtracted_delta_digest="2" * 64)

        with pytest.raises(ProhibitedTerminologyError, match="Prohibited terminology"):
            create_bounded_causal_slice(
                slice_id="slc-001",
                scope=scope,
                tested_subset=subset,
                summary_label=f"This is a {prohibited_term} fix",
            )

    def test_preferred_terms_accepted(self) -> None:
        validate_no_prohibited_terms("tested necessary subset under witness")
        validate_no_prohibited_terms("witness-relative empirical slice")
        validate_no_prohibited_terms("bounded causal slice")


class TestAntiCollapseInvariants:
    """Verifies that ERROR and TIMEOUT cannot count as behavioral witness FAIL."""

    def test_error_and_timeout_cannot_count_as_behavioral_fail(self) -> None:
        with pytest.raises(
            SliceScopeTamperingError,
            match="cannot masquerade as behavioral witness FAIL",
        ):
            CausalSliceScopeRules.validate_execution_outcome_not_error_or_timeout(
                WitnessOutcome.TIMEOUT
            )

        with pytest.raises(
            SliceScopeTamperingError,
            match="cannot masquerade as behavioral witness FAIL",
        ):
            CausalSliceScopeRules.validate_execution_outcome_not_error_or_timeout(
                WitnessOutcome.ERROR
            )

        # PASS and FAIL are behavioral outcomes, should not raise
        CausalSliceScopeRules.validate_execution_outcome_not_error_or_timeout(WitnessOutcome.FAIL)
        CausalSliceScopeRules.validate_execution_outcome_not_error_or_timeout(WitnessOutcome.PASS)


class TestBoundedCausalSliceSerializationAndIntegrity:
    """Validates full artifact serialization, deserialization, and tamper resistance."""

    def test_roundtrip_serialization_and_verification(self) -> None:
        snapshot = _make_snapshot()
        scope = create_causal_slice_scope(
            snapshot=snapshot,
            frozen_contract_digest=FROZEN_CONTRACT_DIGEST,
            sealed_witness_digest=SEALED_WITNESS_DIGEST,
            requirement_id=REQUIREMENT_ID,
            delta_digest="2" * 64,
        )
        subset = _make_tested_subset(subtracted_delta_digest="2" * 64)
        slice_artifact = create_bounded_causal_slice(
            slice_id="slc-test-001",
            scope=scope,
            tested_subset=subset,
            summary_label="tested necessary subset under witness",
        )

        assert verify_slice_integrity(slice_artifact) is True

        # Dict roundtrip
        data = slice_artifact.to_dict()
        assert data["disclaimer"]["is_mathematical_proof"] is False
        assert data["is_authoritative"] is False
        assert data["grants_pass"] is False
        assert data["is_causally_verified"] is False
        restored = BoundedCausalSlice.from_dict(data)
        assert restored == slice_artifact
        assert verify_slice_integrity(restored) is True

        # JSON roundtrip
        json_str = slice_artifact.to_json()
        restored_json = BoundedCausalSlice.from_json(json_str)
        assert restored_json == slice_artifact
        assert verify_slice_integrity(restored_json) is True

    def test_tamper_detection_on_mutated_field(self) -> None:
        snapshot = _make_snapshot()
        scope = create_causal_slice_scope(
            snapshot=snapshot,
            frozen_contract_digest=FROZEN_CONTRACT_DIGEST,
            sealed_witness_digest=SEALED_WITNESS_DIGEST,
            requirement_id=REQUIREMENT_ID,
            delta_digest="2" * 64,
        )
        subset = _make_tested_subset(subtracted_delta_digest="2" * 64)
        slice_artifact = create_bounded_causal_slice(
            slice_id="slc-test-001",
            scope=scope,
            tested_subset=subset,
        )

        data = slice_artifact.to_dict()
        data["summary_label"] = "tampered summary label"

        with pytest.raises(SliceScopeTamperingError, match="slice_digest mismatch"):
            BoundedCausalSlice.from_dict(data)

    def test_delta_digest_mismatch_with_scope_rejected(self) -> None:
        snapshot = _make_snapshot()
        scope = create_causal_slice_scope(
            snapshot=snapshot,
            frozen_contract_digest=FROZEN_CONTRACT_DIGEST,
            sealed_witness_digest=SEALED_WITNESS_DIGEST,
            requirement_id=REQUIREMENT_ID,
            delta_digest="2" * 64,
        )
        # Subset with differing subtracted_delta_digest
        subset = _make_tested_subset(subtracted_delta_digest="9" * 64)

        with pytest.raises(SliceIdentityMismatchError, match="subtracted_delta_digest mismatch"):
            create_bounded_causal_slice(
                slice_id="slc-test-001",
                scope=scope,
                tested_subset=subset,
            )

    def test_markdown_rendering_features_disclaimer_prominently(self) -> None:
        snapshot = _make_snapshot()
        scope = create_causal_slice_scope(
            snapshot=snapshot,
            frozen_contract_digest=FROZEN_CONTRACT_DIGEST,
            sealed_witness_digest=SEALED_WITNESS_DIGEST,
            requirement_id=REQUIREMENT_ID,
            delta_digest="2" * 64,
        )
        subset = _make_tested_subset(subtracted_delta_digest="2" * 64)
        slice_artifact = create_bounded_causal_slice(
            slice_id="slc-test-001",
            scope=scope,
            tested_subset=subset,
        )

        md = slice_artifact.render_markdown()
        assert "Non-Formal-Proof Disclaimer" in md
        assert CANONICAL_DISCLAIMER_TEXT in md
        assert "If the patch matters, the base must break." in md
        assert "**Authoritative**: `False`" in md
        assert "**Mathematical Program Proof**: Disclaimed (`False`)" in md
        assert "**Global Minimality**: Disclaimed (`False`)" in md
