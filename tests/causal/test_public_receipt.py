"""Adversarial and functional test suite for Public Verification Receipt (P-18).

Tests:
- P-18.01: Define public receipt schema and JSON serialization.
- P-18.02: Bind base/candidate/counterfactual hashes, witnesses and outcomes.
- P-18.03: Include provenance, runtime identities, timing/cost and NOT_RUN.
- P-18.04: Add integrity digest/signature strategy appropriate to hackathon scope.
- P-18.05: Render human-readable receipt without losing machine truth.
"""

from __future__ import annotations

import pytest

from basebreak.causal.coverage import compute_causal_coverage
from basebreak.causal.public_receipt import (
    CANONICAL_RECEIPT_THESIS,
    PublicCounterfactualFact,
    PublicExecutionFact,
    PublicReceiptIntegrityError,
    PublicReceiptSecretLeakError,
    PublicReceiptTamperingError,
    PublicVerificationReceipt,
    PublicWitnessFact,
    create_public_verification_receipt,
    render_receipt_markdown,
    render_receipt_terminal,
    verify_public_receipt_integrity,
)
from basebreak.compiler.freeze import FrozenContract, FrozenRequirement
from basebreak.compiler.semantics import CertaintyLevel
from basebreak.domain.causal import ExecutionWorld
from basebreak.domain.execution import TerminationStatus
from basebreak.domain.semantics import ChangeClass
from basebreak.domain.verdict import EvidenceProvenance, PreliminaryVerdict
from basebreak.verifier.witness_result import WitnessOutcome


def _sample_receipt() -> PublicVerificationReceipt:
    req = FrozenRequirement(
        requirement_id="REQ-AUTH-01",
        statement="Enforce token validation",
        citation="token validation",
        citation_start=0,
        citation_end=16,
        rationale="Fix auth bug",
    )
    contract = object.__new__(FrozenContract)
    object.__setattr__(contract, "schema_version", "1.0.0")
    object.__setattr__(contract, "task_digest", "f" * 64)
    object.__setattr__(contract, "change_class", ChangeClass.BUG_FIX)
    object.__setattr__(contract, "certainty", CertaintyLevel.CONFIDENT)
    object.__setattr__(contract, "requirements", (req,))
    object.__setattr__(contract, "contract_digest", "c" * 64)

    coverage = compute_causal_coverage(
        frozen_contract=contract,
        results={
            "REQ-AUTH-01": {
                "verdict": PreliminaryVerdict.VERIFIED,
                "is_causally_verified": True,
                "rationale": "Base failed, candidate passed",
            }
        },
    )

    witness = PublicWitnessFact(
        witness_id="WIT-001",
        witness_digest="a" * 64,
        requirement_id="REQ-AUTH-01",
        execution_command=("pytest", "tests/witness.py"),
        timeout_seconds=20.0,
    )

    base_exec = PublicExecutionFact(
        world=ExecutionWorld.BASE,
        sandbox_id="sbx-base-123",
        source_commit_id="1" * 40,
        tree_digest="2" * 40,
        outcome=WitnessOutcome.FAIL,
        exit_code=1,
        termination_status=TerminationStatus.COMPLETED,
        stdout_digest="3" * 64,
        stderr_digest="4" * 64,
        duration_seconds=2.5,
    )

    cand_exec = PublicExecutionFact(
        world=ExecutionWorld.CANDIDATE,
        sandbox_id="sbx-cand-456",
        source_commit_id="1" * 40,
        tree_digest="5" * 40,
        outcome=WitnessOutcome.PASS,
        exit_code=0,
        termination_status=TerminationStatus.COMPLETED,
        stdout_digest="6" * 64,
        stderr_digest="7" * 64,
        duration_seconds=1.8,
    )

    return create_public_verification_receipt(
        frozen_contract_digest="c" * 64,
        task_id="TASK-AUTH-FIX",
        repo_locator="https://github.com/example/auth-service.git",
        source_commit_id="1" * 40,
        candidate_tree_digest="5" * 40,
        candidate_patch_digest="b" * 64,
        coverage_summary=coverage,
        executions=(base_exec, cand_exec),
        witnesses=(witness,),
        overall_verdict=PreliminaryVerdict.VERIFIED,
        provenance=EvidenceProvenance.LOCAL_EXECUTION,
        runtime_identities=("sbx-base-123", "sbx-cand-456"),
    )


class TestPublicVerificationReceiptP18:
    """Test suite covering P-18.01 through P-18.05."""

    def test_p18_01_public_receipt_schema_and_integrity(self) -> None:
        """P-18.01: Public receipt serializes canonically and passes integrity verification."""
        receipt = _sample_receipt()
        assert receipt.schema_version == "1.0.0"
        assert len(receipt.receipt_digest) == 64
        assert receipt.overall_verdict == PreliminaryVerdict.VERIFIED
        assert receipt.provenance == EvidenceProvenance.LOCAL_EXECUTION

        # Verify integrity
        verify_public_receipt_integrity(receipt)

        # JSON roundtrip
        json_str = receipt.to_json()
        assert "TASK-AUTH-FIX" in json_str
        assert "receipt_digest" in json_str

    def test_p18_02_bound_counterfactual_third_run(self) -> None:
        """P-18.02: Binds counterfactual facts accurately when present."""
        base_receipt = _sample_receipt()

        cf_exec = PublicExecutionFact(
            world=ExecutionWorld.COUNTERFACTUAL,
            sandbox_id="sbx-cf-789",
            source_commit_id="1" * 40,
            tree_digest="8" * 40,
            outcome=WitnessOutcome.FAIL,
            exit_code=1,
            termination_status=TerminationStatus.COMPLETED,
            stdout_digest="9" * 64,
            stderr_digest="0" * 64,
            duration_seconds=2.0,
        )
        cf_fact = PublicCounterfactualFact(
            is_required=True,
            candidate_tree_digest="8" * 40,
            delta_digest="d" * 64,
            outcome=WitnessOutcome.FAIL,
            execution_fact=cf_exec,
        )

        receipt_with_cf = create_public_verification_receipt(
            frozen_contract_digest=base_receipt.frozen_contract_digest,
            task_id=base_receipt.task_id,
            repo_locator=base_receipt.repo_locator,
            source_commit_id=base_receipt.source_commit_id,
            candidate_tree_digest=base_receipt.candidate_tree_digest,
            coverage_summary=base_receipt.coverage_summary,
            executions=(*base_receipt.executions, cf_exec),
            witnesses=base_receipt.witnesses,
            overall_verdict=PreliminaryVerdict.VERIFIED,
            provenance=EvidenceProvenance.LOCAL_EXECUTION,
            counterfactual=cf_fact,
        )

        assert receipt_with_cf.counterfactual is not None
        assert receipt_with_cf.counterfactual.is_required is True
        assert receipt_with_cf.counterfactual.delta_digest == "d" * 64
        verify_public_receipt_integrity(receipt_with_cf)

    def test_p18_03_timing_cost_and_not_run_obligations(self) -> None:
        """P-18.03: Includes timing, measured cost accounting, and explicit NOT_RUN."""
        base_receipt = _sample_receipt()
        receipt = create_public_verification_receipt(
            frozen_contract_digest=base_receipt.frozen_contract_digest,
            task_id=base_receipt.task_id,
            repo_locator=base_receipt.repo_locator,
            source_commit_id=base_receipt.source_commit_id,
            candidate_tree_digest=base_receipt.candidate_tree_digest,
            coverage_summary=base_receipt.coverage_summary,
            executions=base_receipt.executions,
            witnesses=base_receipt.witnesses,
            overall_verdict=PreliminaryVerdict.VERIFIED,
            provenance=EvidenceProvenance.LOCAL_EXECUTION,
            not_run_obligations=("Performance benchmark check NOT_RUN",),
            timing={"created_at_utc": "2026-10-10T21:00:00Z", "total_duration_seconds": 4.3},
        )

        assert "Performance benchmark check NOT_RUN" in receipt.not_run_obligations
        assert receipt.timing["total_duration_seconds"] == 4.3
        verify_public_receipt_integrity(receipt)

    def test_p18_04_tamper_detection_on_receipt_fields(self) -> None:
        """P-18.04: Any tampering with receipt fields is rejected fail-closed."""
        receipt = _sample_receipt()

        # Adversary alters candidate_tree_digest
        tampered_receipt = PublicVerificationReceipt(
            schema_version=receipt.schema_version,
            receipt_digest=receipt.receipt_digest,  # Old digest!
            frozen_contract_digest=receipt.frozen_contract_digest,
            task_id=receipt.task_id,
            repo_locator=receipt.repo_locator,
            source_commit_id=receipt.source_commit_id,
            candidate_tree_digest="f" * 40,  # Swapped tree digest!
            candidate_patch_digest=receipt.candidate_patch_digest,
            counterfactual=receipt.counterfactual,
            coverage_summary=receipt.coverage_summary,
            witnesses=receipt.witnesses,
            executions=receipt.executions,
            overall_verdict=receipt.overall_verdict,
            provenance=receipt.provenance,
            runtime_identities=receipt.runtime_identities,
            timing=receipt.timing,
            accounting=receipt.accounting,
            not_run_obligations=receipt.not_run_obligations,
            signature_strategy=receipt.signature_strategy,
            signature=receipt.signature,
            is_authoritative=receipt.is_authoritative,
            disclaimers=receipt.disclaimers,
        )

        with pytest.raises(PublicReceiptTamperingError, match="tampering detected"):
            verify_public_receipt_integrity(tampered_receipt)

    def test_p18_04_contract_digest_mismatch_rejected(self) -> None:
        """P-18.04: Coverage contract_digest must match receipt contract_digest."""
        receipt = _sample_receipt()
        with pytest.raises(PublicReceiptIntegrityError, match="does not match"):
            create_public_verification_receipt(
                frozen_contract_digest="0" * 64,  # Mismatched!
                task_id=receipt.task_id,
                repo_locator=receipt.repo_locator,
                source_commit_id=receipt.source_commit_id,
                candidate_tree_digest=receipt.candidate_tree_digest,
                coverage_summary=receipt.coverage_summary,
                executions=receipt.executions,
                witnesses=receipt.witnesses,
                overall_verdict=receipt.overall_verdict,
                provenance=receipt.provenance,
            )

    def test_p18_04_secret_leak_rejected(self) -> None:
        """P-18.04: Rejects receipt creation if secrets leak into text/fields."""
        receipt = _sample_receipt()
        with pytest.raises(PublicReceiptSecretLeakError, match="unredacted secrets"):
            create_public_verification_receipt(
                frozen_contract_digest=receipt.frozen_contract_digest,
                task_id=receipt.task_id,
                repo_locator="https://username:ghp_1234567890abcdef1234567890abcdef@github.com/repo",
                source_commit_id=receipt.source_commit_id,
                candidate_tree_digest=receipt.candidate_tree_digest,
                coverage_summary=receipt.coverage_summary,
                executions=receipt.executions,
                witnesses=receipt.witnesses,
                overall_verdict=receipt.overall_verdict,
                provenance=receipt.provenance,
            )

    def test_p18_05_render_markdown_and_terminal(self) -> None:
        """P-18.05: Renders human-readable markdown and terminal output accurately."""
        receipt = _sample_receipt()

        md = render_receipt_markdown(receipt)
        assert CANONICAL_RECEIPT_THESIS in md
        assert "TASK-AUTH-FIX" in md
        assert "REQ-AUTH-01" in md
        assert "100.0%" in md
        assert receipt.receipt_digest in md

        term = render_receipt_terminal(receipt)
        assert "BASEBREAK CAUSAL VERIFICATION RECEIPT" in term
        assert "TASK-AUTH-FIX" in term
        assert "100.0%" in term
