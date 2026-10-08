"""Unit tests for cryptographically bound causal slice receipts (P-12.04).

Basebreak Thesis:
"If the patch matters, the base must break."

Covers:
- Unbroken deterministic cryptographic custody chain binding.
- Zero verdict authority invariants.
- Tamper detection across all bound facts.
- Identity binding against BoundedCausalSlice artifact.
- Serialization and deserialization round-trip with integrity validation.
- Upstream candidate verification compatibility (non-upgrading rule).
"""

from __future__ import annotations

from dataclasses import replace

import pytest

from basebreak.builder.capture import CandidateSnapshot
from basebreak.causal.minimizer import SliceSearchBudget
from basebreak.causal.slice import (
    LOCAL_TEST_RUNTIME_CONFIG_DIGEST,
    BoundedCausalSlice,
    CausalSliceStatus,
    DisclaimerMissingError,
    SliceAuthorityError,
    SliceIdentityMismatchError,
    SliceSearchCompleteness,
    TestedPatchSubset,
    create_bounded_causal_slice,
    create_causal_slice_scope,
    create_subset_execution_fact,
)
from basebreak.causal.slice_receipt import (
    CAUSAL_SLICE_RECEIPT_SCHEMA_VERSION,
    CausalSliceReceipt,
    SliceReceiptIntegrityError,
    SliceReceiptTamperingError,
    create_causal_slice_receipt,
    validate_upstream_evidence_compatibility,
    verify_slice_receipt_integrity,
)
from basebreak.causal.subtraction import SubtractionStrategyType
from basebreak.domain.source import CommitRevision, SourceIdentity
from basebreak.domain.verdict import EvidenceProvenance, PreliminaryVerdict
from basebreak.evidence.artifact import compute_bytes_digest
from basebreak.verifier.witness_result import WitnessOutcome

FROZEN_CONTRACT_DIGEST = "1" * 64
SEALED_WITNESS_DIGEST = "2" * 64
BASE_COMMIT_ID = "a" * 40
CANDIDATE_TREE_DIGEST = "b" * 40
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


def _build_test_candidate_snapshot() -> CandidateSnapshot:
    patch_digest = compute_bytes_digest(SAMPLE_PATCH.encode("utf-8")).value
    source = SourceIdentity(
        locator="https://github.com/example/repo.git",
        revision=CommitRevision(BASE_COMMIT_ID),
        subpath="src/math.py",
    )
    return CandidateSnapshot(
        candidate_id="cand-auth-001",
        source_identity=source,
        candidate_tree_digest=CANDIDATE_TREE_DIGEST,
        patch_digest=patch_digest,
        patch_text=SAMPLE_PATCH,
        files_added=(),
        files_modified=("src/math.py",),
        files_deleted=(),
        builder_authored_tests=(),
        frozen_contract_digest=FROZEN_CONTRACT_DIGEST,
        context_digest="f" * 64,
        provenance=EvidenceProvenance.LOCAL_EXECUTION,
    )


def _build_test_slice_artifact() -> BoundedCausalSlice:
    snapshot = _build_test_candidate_snapshot()
    subset = TestedPatchSubset(
        subset_id="sub-01",
        strategy_type=SubtractionStrategyType.HUNK_LEVEL_REVERT,
        retained_files=("src/math.py",),
        retained_hunk_ids=("src/math.py:0",),
        subtracted_files=(),
        subtracted_hunk_ids=(),
        retained_patch_digest="d" * 64,
        subtracted_delta_digest="e" * 64,
        is_empty=False,
    )
    scope = create_causal_slice_scope(
        snapshot=snapshot,
        frozen_contract_digest=FROZEN_CONTRACT_DIGEST,
        sealed_witness_digest=SEALED_WITNESS_DIGEST,
        requirement_id="REQ-AUTH-001",
    )
    return create_bounded_causal_slice(
        slice_id="slice-001",
        scope=scope,
        tested_subset=subset,
        status=CausalSliceStatus.TESTED_NECESSARY_SUBSET,
        completeness=SliceSearchCompleteness.EXHAUSTIVE_BOUNDED,
    )


def _build_valid_receipt() -> CausalSliceReceipt:
    slice_art = _build_test_slice_artifact()
    budget = SliceSearchBudget(
        max_iterations=10,
        max_subsets_tested=10,
        max_depth=3,
        allow_model_ordering=False,
    )
    fact = create_subset_execution_fact(
        subset=slice_art.tested_subset,
        scope=slice_art.scope,
        outcome=WitnessOutcome.PASS,
        exit_code=0,
    )
    return create_causal_slice_receipt(
        requirement_id="REQ-AUTH-001",
        frozen_contract_digest=FROZEN_CONTRACT_DIGEST,
        sealed_witness_digest=SEALED_WITNESS_DIGEST,
        witness_id="wit-001",
        source_locator="https://github.com/example/repo.git",
        source_commit_id=BASE_COMMIT_ID,
        source_subpath="src/math.py",
        candidate_id="cand-auth-001",
        candidate_tree_digest=CANDIDATE_TREE_DIGEST,
        candidate_patch_digest=slice_art.scope.candidate_patch_digest,
        slice_artifact=slice_art,
        search_budget=budget,
        execution_facts=(fact,),
        runtime_config_digest=LOCAL_TEST_RUNTIME_CONFIG_DIGEST,
        tested_subsets=(slice_art.tested_subset,),
        evaluated_outcomes=("PASS",),
        counterfactual_delta_digests=("e" * 64,),
        status=CausalSliceStatus.TESTED_NECESSARY_SUBSET,
        completeness=SliceSearchCompleteness.EXHAUSTIVE_BOUNDED,
        provenance=EvidenceProvenance.LOCAL_EXECUTION,
    )


class TestCausalSliceReceipt:
    """Validates CausalSliceReceipt custody chain, integrity, and non-authoritative bounds."""

    def test_p12_04_authentic_receipt_creation_and_integrity_check(self) -> None:
        """P-12.04: Receipt binds all custody dimensions and passes integrity."""
        receipt = _build_valid_receipt()

        assert receipt.schema_version == CAUSAL_SLICE_RECEIPT_SCHEMA_VERSION
        assert receipt.requirement_id == "REQ-AUTH-001"
        assert receipt.frozen_contract_digest == FROZEN_CONTRACT_DIGEST
        assert receipt.sealed_witness_digest == SEALED_WITNESS_DIGEST
        assert receipt.witness_id == "wit-001"
        assert receipt.source_commit_id == BASE_COMMIT_ID
        assert receipt.candidate_id == "cand-auth-001"
        assert receipt.candidate_tree_digest == CANDIDATE_TREE_DIGEST
        assert receipt.status == CausalSliceStatus.TESTED_NECESSARY_SUBSET
        assert receipt.completeness == SliceSearchCompleteness.EXHAUSTIVE_BOUNDED
        assert receipt.provenance == EvidenceProvenance.LOCAL_EXECUTION
        assert len(receipt.receipt_digest) == 64

        # Full verification passes
        assert verify_slice_receipt_integrity(receipt) is True

    def test_p12_04_zero_verdict_authority_invariants(self) -> None:
        """P-12.04: Receipt possesses ZERO verdict authority and cannot grant pass."""
        receipt = _build_valid_receipt()

        assert receipt.is_authoritative is False
        assert receipt.grants_pass is False
        assert receipt.is_causally_verified is False
        assert receipt.claims_global_minimality is False

        # Attempting to forge authoritative status raises SliceAuthorityError
        with pytest.raises(
            (SliceReceiptIntegrityError, SliceAuthorityError), match="is_authoritative"
        ):
            CausalSliceReceipt(
                requirement_id=receipt.requirement_id,
                frozen_contract_digest=receipt.frozen_contract_digest,
                sealed_witness_digest=receipt.sealed_witness_digest,
                witness_id=receipt.witness_id,
                source_locator=receipt.source_locator,
                source_commit_id=receipt.source_commit_id,
                source_subpath=receipt.source_subpath,
                candidate_id=receipt.candidate_id,
                candidate_tree_digest=receipt.candidate_tree_digest,
                candidate_patch_digest=receipt.candidate_patch_digest,
                slice_artifact=receipt.slice_artifact,
                search_budget=receipt.search_budget,
                tested_subsets=receipt.tested_subsets,
                evaluated_outcomes=receipt.evaluated_outcomes,
                counterfactual_delta_digests=receipt.counterfactual_delta_digests,
                execution_facts=receipt.execution_facts,
                runtime_config_digest=receipt.runtime_config_digest,
                status=receipt.status,
                completeness=receipt.completeness,
                provenance=receipt.provenance,
                disclaimer=receipt.disclaimer,
                created_at_utc=receipt.created_at_utc,
                receipt_digest=receipt.receipt_digest,
                schema_version=receipt.schema_version,
                is_authoritative=True,  # VIOLATION
                grants_pass=False,
                is_causally_verified=False,
                claims_global_minimality=False,
            )

        with pytest.raises((SliceReceiptIntegrityError, SliceAuthorityError), match="grants_pass"):
            CausalSliceReceipt(
                requirement_id=receipt.requirement_id,
                frozen_contract_digest=receipt.frozen_contract_digest,
                sealed_witness_digest=receipt.sealed_witness_digest,
                witness_id=receipt.witness_id,
                source_locator=receipt.source_locator,
                source_commit_id=receipt.source_commit_id,
                source_subpath=receipt.source_subpath,
                candidate_id=receipt.candidate_id,
                candidate_tree_digest=receipt.candidate_tree_digest,
                candidate_patch_digest=receipt.candidate_patch_digest,
                slice_artifact=receipt.slice_artifact,
                search_budget=receipt.search_budget,
                tested_subsets=receipt.tested_subsets,
                evaluated_outcomes=receipt.evaluated_outcomes,
                counterfactual_delta_digests=receipt.counterfactual_delta_digests,
                execution_facts=receipt.execution_facts,
                runtime_config_digest=receipt.runtime_config_digest,
                status=receipt.status,
                completeness=receipt.completeness,
                provenance=receipt.provenance,
                disclaimer=receipt.disclaimer,
                created_at_utc=receipt.created_at_utc,
                receipt_digest=receipt.receipt_digest,
                schema_version=receipt.schema_version,
                is_authoritative=False,
                grants_pass=True,  # VIOLATION
                is_causally_verified=False,
                claims_global_minimality=False,
            )

    def test_p12_04_tamper_detection_on_receipt_fields(self) -> None:
        """P-12.04: Any mutation of custody fields invalidates the receipt digest."""
        receipt = _build_valid_receipt()

        # Mutating requirement_id
        with pytest.raises((SliceReceiptTamperingError, SliceIdentityMismatchError)):
            replace(receipt, requirement_id="REQ-TAMPERED-999")

        # Mutating frozen_contract_digest
        with pytest.raises((SliceReceiptTamperingError, SliceIdentityMismatchError)):
            replace(receipt, frozen_contract_digest="9" * 64)

        # Mutating sealed_witness_digest
        with pytest.raises((SliceReceiptTamperingError, SliceIdentityMismatchError)):
            replace(receipt, sealed_witness_digest="9" * 64)

        # Mutating candidate_patch_digest
        with pytest.raises((SliceReceiptTamperingError, SliceIdentityMismatchError)):
            replace(receipt, candidate_patch_digest="9" * 64)

        # Mutating evaluated_outcomes
        with pytest.raises((SliceReceiptTamperingError, SliceIdentityMismatchError)):
            replace(receipt, evaluated_outcomes=("FAIL",))

        # Mutating receipt_digest directly
        with pytest.raises(SliceReceiptTamperingError):
            replace(receipt, receipt_digest="f" * 64)

    def test_p12_04_identity_mismatch_with_slice_artifact(self) -> None:
        """P-12.04: Receipt facts must match the underlying BoundedCausalSlice artifact."""
        slice_art = _build_test_slice_artifact()
        budget = SliceSearchBudget()

        # Mismatched requirement_id
        with pytest.raises(SliceIdentityMismatchError, match="requirement_id mismatch"):
            create_causal_slice_receipt(
                requirement_id="REQ-DIFFERENT-002",
                frozen_contract_digest=FROZEN_CONTRACT_DIGEST,
                sealed_witness_digest=SEALED_WITNESS_DIGEST,
                witness_id="wit-001",
                source_locator="https://github.com/example/repo.git",
                source_commit_id=BASE_COMMIT_ID,
                source_subpath="src/math.py",
                candidate_id="cand-auth-001",
                candidate_tree_digest=CANDIDATE_TREE_DIGEST,
                candidate_patch_digest=slice_art.scope.candidate_patch_digest,
                slice_artifact=slice_art,
                search_budget=budget,
            )

        # Mismatched frozen_contract_digest
        with pytest.raises(SliceIdentityMismatchError, match="frozen_contract_digest mismatch"):
            create_causal_slice_receipt(
                requirement_id="REQ-AUTH-001",
                frozen_contract_digest="9" * 64,
                sealed_witness_digest=SEALED_WITNESS_DIGEST,
                witness_id="wit-001",
                source_locator="https://github.com/example/repo.git",
                source_commit_id=BASE_COMMIT_ID,
                source_subpath="src/math.py",
                candidate_id="cand-auth-001",
                candidate_tree_digest=CANDIDATE_TREE_DIGEST,
                candidate_patch_digest=slice_art.scope.candidate_patch_digest,
                slice_artifact=slice_art,
                search_budget=budget,
            )

        # Mismatched candidate_id
        with pytest.raises(SliceIdentityMismatchError, match="candidate_id mismatch"):
            create_causal_slice_receipt(
                requirement_id="REQ-AUTH-001",
                frozen_contract_digest=FROZEN_CONTRACT_DIGEST,
                sealed_witness_digest=SEALED_WITNESS_DIGEST,
                witness_id="wit-001",
                source_locator="https://github.com/example/repo.git",
                source_commit_id=BASE_COMMIT_ID,
                source_subpath="src/math.py",
                candidate_id="cand-DIFFERENT-999",
                candidate_tree_digest=CANDIDATE_TREE_DIGEST,
                candidate_patch_digest=slice_art.scope.candidate_patch_digest,
                slice_artifact=slice_art,
                search_budget=budget,
            )

    def test_p12_04_serialization_and_deserialization_round_trip(self) -> None:
        """P-12.04: Receipt can serialize to canonical JSON and deserialize faithfully."""
        receipt = _build_valid_receipt()

        # Serialization to dict and JSON
        d = receipt.to_dict()
        assert d["schema_version"] == CAUSAL_SLICE_RECEIPT_SCHEMA_VERSION
        assert d["is_authoritative"] is False
        assert d["grants_pass"] is False
        assert d["is_causally_verified"] is False
        assert d["claims_global_minimality"] is False

        raw_json = receipt.to_json()
        assert isinstance(raw_json, str)

        # Deserialization from JSON
        restored = CausalSliceReceipt.from_json(raw_json)
        assert restored.receipt_digest == receipt.receipt_digest
        assert restored.requirement_id == receipt.requirement_id
        assert restored.frozen_contract_digest == receipt.frozen_contract_digest
        assert restored.status == receipt.status
        assert verify_slice_receipt_integrity(restored) is True

    def test_p12_04_deserialization_tampering_rejection(self) -> None:
        """P-12.04: Deserializing forged JSON payload claiming authority fails closed."""
        receipt = _build_valid_receipt()
        raw_dict = receipt.to_dict()

        # Attacker tampers JSON to claim is_authoritative = True
        raw_dict["is_authoritative"] = True
        with pytest.raises(SliceAuthorityError, match="is_authoritative"):
            CausalSliceReceipt.from_dict(raw_dict)

        # Attacker tampers JSON to claim grants_pass = True
        raw_dict["is_authoritative"] = False
        raw_dict["grants_pass"] = True
        with pytest.raises(SliceAuthorityError, match="grants_pass"):
            CausalSliceReceipt.from_dict(raw_dict)

        # Attacker removes disclaimer
        raw_dict["grants_pass"] = False
        del raw_dict["disclaimer"]
        with pytest.raises(DisclaimerMissingError):
            CausalSliceReceipt.from_dict(raw_dict)

    def test_p12_04_validate_upstream_evidence_compatibility(self) -> None:
        """P-12.04: Slice receipt cannot upgrade an unverified or failing upstream candidate."""
        receipt = _build_valid_receipt()

        # If candidate was VERIFIED upstream, receipt validity is checked and accepted
        assert (
            validate_upstream_evidence_compatibility(receipt, PreliminaryVerdict.VERIFIED) is True
        )

        # If candidate was CONTRADICTED, slice evidence CANNOT upgrade to verified
        assert (
            validate_upstream_evidence_compatibility(receipt, PreliminaryVerdict.CONTRADICTED)
            is False
        )

        # If candidate was PARTIALLY_VERIFIED, slice evidence CANNOT upgrade
        assert (
            validate_upstream_evidence_compatibility(receipt, PreliminaryVerdict.PARTIALLY_VERIFIED)
            is False
        )

        # If candidate was INCONCLUSIVE, slice evidence CANNOT upgrade
        assert (
            validate_upstream_evidence_compatibility(receipt, PreliminaryVerdict.INCONCLUSIVE)
            is False
        )

        # If candidate was NOT_RUN or BLOCKED, slice evidence CANNOT upgrade
        assert (
            validate_upstream_evidence_compatibility(receipt, PreliminaryVerdict.NOT_RUN) is False
        )
        assert (
            validate_upstream_evidence_compatibility(receipt, PreliminaryVerdict.BLOCKED) is False
        )

    def test_p12_04_render_markdown_summary(self) -> None:
        """P-12.04: Markdown summary clearly reflects non-authoritative bounds and disclaimers."""
        receipt = _build_valid_receipt()
        summary = receipt.render_markdown_summary()

        assert "Minimal Causal Slice Receipt" in summary
        assert "REQ-AUTH-001" in summary
        assert "cand-auth-001" in summary
        assert "Authoritative" in summary
        assert "Grants Pass" in summary
        assert "Non-Formal-Proof Disclaimer" in summary
