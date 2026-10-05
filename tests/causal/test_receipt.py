"""Unit tests for local causal verification receipt contracts and tamper detection (P-10.06)."""

from __future__ import annotations

import pytest

from basebreak.causal.receipt import (
    CausalReceiptIntegrityError,
    CausalReceiptTamperingError,
    LocalCausalReceipt,
    WorldExecutionFact,
    create_causal_receipt,
    verify_causal_receipt_integrity,
)
from basebreak.causal.reconciliation import CausalTransition
from basebreak.domain.causal import ExecutionWorld
from basebreak.domain.execution import TerminationStatus
from basebreak.domain.verdict import EvidenceProvenance, PreliminaryVerdict
from basebreak.verifier.witness_result import WitnessOutcome


def _build_test_facts() -> tuple[WorldExecutionFact, WorldExecutionFact]:
    base_fact = WorldExecutionFact(
        world=ExecutionWorld.BASE,
        sandbox_id="sbx-base-001",
        source_commit_id="a" * 40,
        tree_digest="1" * 40,
        outcome=WitnessOutcome.FAIL,
        exit_code=1,
        termination_status=TerminationStatus.COMPLETED,
        stdout_digest="b" * 64,
        stderr_digest="c" * 64,
        result_digest="d" * 64,
        duration_seconds=1.23,
    )
    cand_fact = WorldExecutionFact(
        world=ExecutionWorld.CANDIDATE,
        sandbox_id="sbx-cand-002",
        source_commit_id="a" * 40,
        tree_digest="2" * 40,
        outcome=WitnessOutcome.PASS,
        exit_code=0,
        termination_status=TerminationStatus.COMPLETED,
        stdout_digest="e" * 64,
        stderr_digest="f" * 64,
        result_digest="0" * 64,
        duration_seconds=0.98,
    )
    return base_fact, cand_fact


class TestCausalReceipt:
    """Validates LocalCausalReceipt integrity, serialization, and tamper resistance."""

    def test_p10_06_receipt_creation_and_integrity_verification(self) -> None:
        """P-10.06: Authentically created receipt verifies successfully with matching digest."""
        base_fact, cand_fact = _build_test_facts()
        receipt = create_causal_receipt(
            requirement_id="REQ-QUIET-001",
            frozen_contract_digest="c" * 64,
            witness_id="wit-quiet-001",
            witness_digest="a" * 64,
            lock_digest="b" * 64,
            base_execution=base_fact,
            candidate_execution=cand_fact,
            transition=CausalTransition.CAUSAL_BUG_FIX_VERIFIED,
            verdict=PreliminaryVerdict.VERIFIED,
            provenance=EvidenceProvenance.LOCAL_EXECUTION,
            narrative="Base failed and candidate passed under identical witness.",
        )

        assert receipt.is_causally_verified is True
        assert verify_causal_receipt_integrity(receipt) is True

        receipt_dict = receipt.to_dict()
        assert receipt_dict["requirement_id"] == "REQ-QUIET-001"
        assert receipt_dict["transition"] == "CAUSAL_BUG_FIX_VERIFIED"
        assert receipt_dict["verdict"] == "VERIFIED"
        assert receipt_dict["is_causally_verified"] is True

    def test_tamper_detection_on_mutated_field(self) -> None:
        """Tampering with any field in LocalCausalReceipt fails closed upon instantiation."""
        base_fact, cand_fact = _build_test_facts()
        authentic = create_causal_receipt(
            requirement_id="REQ-QUIET-001",
            frozen_contract_digest="c" * 64,
            witness_id="wit-quiet-001",
            witness_digest="a" * 64,
            lock_digest="b" * 64,
            base_execution=base_fact,
            candidate_execution=cand_fact,
            transition=CausalTransition.CAUSAL_BUG_FIX_VERIFIED,
            verdict=PreliminaryVerdict.VERIFIED,
            provenance=EvidenceProvenance.LOCAL_EXECUTION,
        )

        # Mutate requirement_id while retaining authentic receipt_digest
        with pytest.raises(CausalReceiptTamperingError, match="receipt_digest mismatch"):
            LocalCausalReceipt(
                schema_version=authentic.schema_version,
                requirement_id="REQ-FORGED-999",  # FORGERY
                frozen_contract_digest=authentic.frozen_contract_digest,
                witness_id=authentic.witness_id,
                witness_digest=authentic.witness_digest,
                lock_digest=authentic.lock_digest,
                base_execution=authentic.base_execution,
                candidate_execution=authentic.candidate_execution,
                transition=authentic.transition,
                verdict=authentic.verdict,
                provenance=authentic.provenance,
                created_at_utc=authentic.created_at_utc,
                receipt_digest=authentic.receipt_digest,
            )

        # Mutate verdict from INCONCLUSIVE to VERIFIED while keeping old digest
        with pytest.raises(CausalReceiptTamperingError, match="receipt_digest mismatch"):
            LocalCausalReceipt(
                schema_version=authentic.schema_version,
                requirement_id=authentic.requirement_id,
                frozen_contract_digest=authentic.frozen_contract_digest,
                witness_id=authentic.witness_id,
                witness_digest=authentic.witness_digest,
                lock_digest=authentic.lock_digest,
                base_execution=authentic.base_execution,
                candidate_execution=authentic.candidate_execution,
                transition=CausalTransition.UNVERIFIED_TRIVIAL_PASS,  # MUTATED
                verdict=PreliminaryVerdict.VERIFIED,
                provenance=authentic.provenance,
                created_at_utc=authentic.created_at_utc,
                receipt_digest=authentic.receipt_digest,
            )

    def test_invalid_world_assignment_rejected(self) -> None:
        """Assigning CANDIDATE fact to base_execution raises CausalReceiptIntegrityError."""
        base_fact, cand_fact = _build_test_facts()
        with pytest.raises(CausalReceiptIntegrityError, match="base_execution.world must be BASE"):
            create_causal_receipt(
                requirement_id="REQ-QUIET-001",
                frozen_contract_digest="c" * 64,
                witness_id="wit-quiet-001",
                witness_digest="a" * 64,
                lock_digest="b" * 64,
                base_execution=cand_fact,  # Wrong world
                candidate_execution=cand_fact,
                transition=CausalTransition.CAUSAL_BUG_FIX_VERIFIED,
                verdict=PreliminaryVerdict.VERIFIED,
                provenance=EvidenceProvenance.LOCAL_EXECUTION,
            )
