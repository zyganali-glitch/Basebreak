"""Unit and adversarial tests for P-13.01 FEATURE ABSENT->PRESENT verifier."""

from __future__ import annotations

import pytest

from basebreak.causal.feature import (
    FeatureAbsenceMechanism,
    FeatureObservation,
    FeatureState,
    detect_feature_state,
    reconcile_feature_transition,
    verify_feature,
)
from basebreak.causal.reconciliation import (
    CausalTransition,
    ChangeClassMismatchError,
)
from basebreak.causal.semantic_receipt import (
    SemanticReceiptTamperingError,
    verify_semantic_receipt_integrity,
)
from basebreak.compiler.freeze import FrozenContract, FrozenRequirement
from basebreak.compiler.semantics import CertaintyLevel
from basebreak.domain.causal import CandidateIdentity, ExecutionWorld
from basebreak.domain.execution import SandboxIdentity, TerminationStatus
from basebreak.domain.semantics import ChangeClass
from basebreak.domain.source import CommitRevision, SourceIdentity
from basebreak.domain.verdict import EvidenceProvenance, PreliminaryVerdict
from basebreak.verifier.context import VerifierContextEnvelope, VerifierExecutionPolicy
from basebreak.verifier.vacuity import VacuityCheckResult, VacuityStatus
from basebreak.verifier.witness_lock import create_witness_lock
from basebreak.verifier.witness_result import (
    NormalizedWitnessResult,
    WitnessOutcome,
    normalize_witness_execution,
)
from basebreak.verifier.witness_store import (
    TrustedWitnessVault,
    WitnessArtifact,
)


def _make_sample_contract(change_class: ChangeClass = ChangeClass.FEATURE) -> FrozenContract:
    """Helper to create a valid FrozenContract for testing."""
    req = FrozenRequirement(
        requirement_id="REQ-FEAT-001",
        statement="System shall support json output flag",
        citation="support json output flag",
        citation_start=0,
        citation_end=24,
    )
    # Using object.__new__ to construct directly for unit testing
    contract = object.__new__(FrozenContract)
    object.__setattr__(contract, "schema_version", "1.0.0")
    object.__setattr__(contract, "task_digest", "a" * 64)
    object.__setattr__(contract, "change_class", change_class)
    object.__setattr__(contract, "certainty", CertaintyLevel.CONFIDENT)
    object.__setattr__(contract, "requirements", (req,))
    object.__setattr__(contract, "contract_digest", "b" * 64)
    return contract


def _make_normalized_result(
    *,
    world: ExecutionWorld = ExecutionWorld.BASE,
    outcome: WitnessOutcome = WitnessOutcome.FAIL,
    exit_code: int | None = 1,
    stdout: str = "",
    stderr: str = "",
    status: TerminationStatus = TerminationStatus.COMPLETED,
    sandbox_id: str = "sbx-test-1",
) -> NormalizedWitnessResult:
    sbx = SandboxIdentity(
        sandbox_id=sandbox_id,
        description="test sandbox",
    )
    return normalize_witness_execution(
        witness_id="wit-001",
        witness_digest="c" * 64,
        frozen_contract_digest="b" * 64,
        requirement_id="REQ-FEAT-001",
        sandbox_identity=sbx,
        source_commit_id="d" * 40,
        world=world,
        status=status,
        exit_code=exit_code,
        stdout_raw=stdout,
        stderr_raw=stderr,
        duration_seconds=1.23,
        provenance=EvidenceProvenance.LOCAL_EXECUTION,
    )


class TestFeatureStateDetection:
    """Validates bounded evidence detection for capability absence vs presence."""

    def test_symbol_not_found_absence(self) -> None:
        """AttributeError mechanically indicates capability is ABSENT."""
        res = _make_normalized_result(
            outcome=WitnessOutcome.FAIL,
            exit_code=1,
            stderr="AttributeError: 'Client' object has no attribute 'export_json'",
        )
        obs = detect_feature_state(
            world=ExecutionWorld.BASE,
            result=res,
            expected_absence_mechanism=FeatureAbsenceMechanism.SYMBOL_NOT_FOUND,
        )
        assert obs.state == FeatureState.ABSENT
        assert obs.absence_mechanism == FeatureAbsenceMechanism.SYMBOL_NOT_FOUND
        assert "export_json" in obs.evidence_detail

    def test_input_rejected_as_unsupported_absence(self) -> None:
        """NotImplementedError mechanically indicates capability is ABSENT."""
        res = _make_normalized_result(
            outcome=WitnessOutcome.FAIL,
            exit_code=1,
            stderr="NotImplementedError: Format 'parquet' is not implemented",
        )
        obs = detect_feature_state(
            world=ExecutionWorld.BASE,
            result=res,
            expected_absence_mechanism=FeatureAbsenceMechanism.INPUT_REJECTED_AS_UNSUPPORTED,
        )
        assert obs.state == FeatureState.ABSENT
        assert obs.absence_mechanism == FeatureAbsenceMechanism.INPUT_REJECTED_AS_UNSUPPORTED

    def test_property_unavailable_absence(self) -> None:
        """KeyError mechanically indicates property/feature is ABSENT."""
        res = _make_normalized_result(
            outcome=WitnessOutcome.FAIL,
            exit_code=1,
            stderr="KeyError: 'streaming_mode'",
        )
        obs = detect_feature_state(
            world=ExecutionWorld.BASE,
            result=res,
            expected_absence_mechanism=FeatureAbsenceMechanism.PROPERTY_UNAVAILABLE,
        )
        assert obs.state == FeatureState.ABSENT
        assert obs.absence_mechanism == FeatureAbsenceMechanism.PROPERTY_UNAVAILABLE

    def test_mechanical_exit_code_absence(self) -> None:
        """Exit code 127 (command not found) mechanically indicates absence."""
        res = _make_normalized_result(
            outcome=WitnessOutcome.FAIL,
            exit_code=127,
            stderr="basebreak-audit: command not found",
        )
        obs = detect_feature_state(
            world=ExecutionWorld.BASE,
            result=res,
            expected_absence_mechanism=FeatureAbsenceMechanism.MECHANICAL_EXIT_CODE,
        )
        assert obs.state == FeatureState.ABSENT
        assert obs.absence_mechanism == FeatureAbsenceMechanism.MECHANICAL_EXIT_CODE

    def test_arbitrary_crash_does_not_collapse_to_absent(self) -> None:
        """CRITICAL INVARIANT: Arbitrary test failure (crash/syntax error) != ABSENT."""
        res = _make_normalized_result(
            outcome=WitnessOutcome.FAIL,
            exit_code=1,
            stderr="ZeroDivisionError: division by zero in utils.py line 42",
        )
        obs = detect_feature_state(
            world=ExecutionWorld.BASE,
            result=res,
            expected_absence_mechanism=FeatureAbsenceMechanism.SYMBOL_NOT_FOUND,
        )
        # Must resolve to ERROR, NEVER ABSENT!
        assert obs.state == FeatureState.ERROR
        assert obs.absence_mechanism is None
        assert "did not demonstrate mechanical absence" in obs.evidence_detail

    def test_clean_pass_is_present(self) -> None:
        """Clean PASS with exit 0 indicates capability is PRESENT."""
        res = _make_normalized_result(
            outcome=WitnessOutcome.PASS,
            exit_code=0,
            stdout="JSON export verified",
        )
        obs = detect_feature_state(
            world=ExecutionWorld.CANDIDATE,
            result=res,
            expected_absence_mechanism=FeatureAbsenceMechanism.SYMBOL_NOT_FOUND,
        )
        assert obs.state == FeatureState.PRESENT
        assert obs.absence_mechanism is None

    def test_timeout_is_not_absent(self) -> None:
        """Timeout must never collapse into ABSENT."""
        res = _make_normalized_result(
            outcome=WitnessOutcome.TIMEOUT,
            status=TerminationStatus.TIMED_OUT,
            exit_code=None,
        )
        obs = detect_feature_state(
            world=ExecutionWorld.BASE,
            result=res,
            expected_absence_mechanism=FeatureAbsenceMechanism.SYMBOL_NOT_FOUND,
        )
        assert obs.state == FeatureState.TIMEOUT


class TestFeatureReconciliation:
    """Validates deterministic reconciliation for FEATURE."""

    def test_feature_absent_to_present_verified(self) -> None:
        """BASE=ABSENT, CANDIDATE=PRESENT -> FEATURE_VERIFIED."""
        base_obs = FeatureObservation(
            world=ExecutionWorld.BASE,
            state=FeatureState.ABSENT,
            absence_mechanism=FeatureAbsenceMechanism.SYMBOL_NOT_FOUND,
            evidence_detail="AttributeError: method missing",
            exit_code=1,
            stdout_digest="0" * 64,
            stderr_digest="1" * 64,
        )
        cand_obs = FeatureObservation(
            world=ExecutionWorld.CANDIDATE,
            state=FeatureState.PRESENT,
            absence_mechanism=None,
            evidence_detail="Method executed successfully",
            exit_code=0,
            stdout_digest="0" * 64,
            stderr_digest="1" * 64,
        )
        contract = _make_sample_contract(ChangeClass.FEATURE)

        fact = reconcile_feature_transition(
            base_observation=base_obs,
            candidate_observation=cand_obs,
            frozen_contract=contract,
        )
        assert fact.transition == CausalTransition.FEATURE_VERIFIED
        assert fact.verdict == PreliminaryVerdict.VERIFIED
        assert fact.is_causally_verified is True
        assert "Feature capability verified" in fact.rationale

    def test_feature_already_present_is_inconclusive(self) -> None:
        """BASE=PRESENT, CANDIDATE=PRESENT -> UNVERIFIED_FEATURE_ALREADY_PRESENT."""
        base_obs = FeatureObservation(
            world=ExecutionWorld.BASE,
            state=FeatureState.PRESENT,
            absence_mechanism=None,
            evidence_detail="Already present",
            exit_code=0,
            stdout_digest="0" * 64,
            stderr_digest="1" * 64,
        )
        cand_obs = FeatureObservation(
            world=ExecutionWorld.CANDIDATE,
            state=FeatureState.PRESENT,
            absence_mechanism=None,
            evidence_detail="Present",
            exit_code=0,
            stdout_digest="0" * 64,
            stderr_digest="1" * 64,
        )
        fact = reconcile_feature_transition(
            base_observation=base_obs,
            candidate_observation=cand_obs,
        )
        assert fact.transition == CausalTransition.UNVERIFIED_FEATURE_ALREADY_PRESENT
        assert fact.verdict == PreliminaryVerdict.INCONCLUSIVE
        assert fact.is_causally_verified is False

    def test_feature_not_implemented_is_contradicted(self) -> None:
        """BASE=ABSENT, CANDIDATE=ABSENT -> UNVERIFIED_FEATURE_NOT_IMPLEMENTED."""
        base_obs = FeatureObservation(
            world=ExecutionWorld.BASE,
            state=FeatureState.ABSENT,
            absence_mechanism=FeatureAbsenceMechanism.SYMBOL_NOT_FOUND,
            evidence_detail="Missing on base",
            exit_code=1,
            stdout_digest="0" * 64,
            stderr_digest="1" * 64,
        )
        cand_obs = FeatureObservation(
            world=ExecutionWorld.CANDIDATE,
            state=FeatureState.ABSENT,
            absence_mechanism=FeatureAbsenceMechanism.SYMBOL_NOT_FOUND,
            evidence_detail="Still missing on candidate",
            exit_code=1,
            stdout_digest="0" * 64,
            stderr_digest="1" * 64,
        )
        fact = reconcile_feature_transition(
            base_observation=base_obs,
            candidate_observation=cand_obs,
        )
        assert fact.transition == CausalTransition.UNVERIFIED_FEATURE_NOT_IMPLEMENTED
        assert fact.verdict == PreliminaryVerdict.CONTRADICTED
        assert fact.is_causally_verified is False

    def test_feature_regression_is_contradicted(self) -> None:
        """BASE=PRESENT, CANDIDATE=ABSENT -> UNVERIFIED_FEATURE_REGRESSION."""
        base_obs = FeatureObservation(
            world=ExecutionWorld.BASE,
            state=FeatureState.PRESENT,
            absence_mechanism=None,
            evidence_detail="Present on base",
            exit_code=0,
            stdout_digest="0" * 64,
            stderr_digest="1" * 64,
        )
        cand_obs = FeatureObservation(
            world=ExecutionWorld.CANDIDATE,
            state=FeatureState.ABSENT,
            absence_mechanism=FeatureAbsenceMechanism.SYMBOL_NOT_FOUND,
            evidence_detail="Disappeared on candidate",
            exit_code=1,
            stdout_digest="0" * 64,
            stderr_digest="1" * 64,
        )
        fact = reconcile_feature_transition(
            base_observation=base_obs,
            candidate_observation=cand_obs,
        )
        assert fact.transition == CausalTransition.UNVERIFIED_FEATURE_REGRESSION
        assert fact.verdict == PreliminaryVerdict.CONTRADICTED
        assert fact.is_causally_verified is False

    def test_wrong_change_class_fails_closed(self) -> None:
        """BUG_FIX contract rejected by FEATURE verifier with ChangeClassMismatchError."""
        bug_contract = _make_sample_contract(ChangeClass.BUG_FIX)
        base_obs = FeatureObservation(
            world=ExecutionWorld.BASE,
            state=FeatureState.ABSENT,
            absence_mechanism=FeatureAbsenceMechanism.SYMBOL_NOT_FOUND,
            evidence_detail="Missing",
            exit_code=1,
            stdout_digest="0" * 64,
            stderr_digest="1" * 64,
        )
        cand_obs = FeatureObservation(
            world=ExecutionWorld.CANDIDATE,
            state=FeatureState.PRESENT,
            absence_mechanism=None,
            evidence_detail="Present",
            exit_code=0,
            stdout_digest="0" * 64,
            stderr_digest="1" * 64,
        )
        with pytest.raises(ChangeClassMismatchError, match="expected ChangeClass.FEATURE"):
            reconcile_feature_transition(
                base_observation=base_obs,
                candidate_observation=cand_obs,
                frozen_contract=bug_contract,
            )

    def test_vacuous_witness_fails_to_inconclusive(self) -> None:
        """Vacuous witness on BASE or CANDIDATE prevents FEATURE verification."""
        base_obs = FeatureObservation(
            world=ExecutionWorld.BASE,
            state=FeatureState.ABSENT,
            absence_mechanism=FeatureAbsenceMechanism.SYMBOL_NOT_FOUND,
            evidence_detail="Missing",
            exit_code=1,
            stdout_digest="0" * 64,
            stderr_digest="1" * 64,
        )
        cand_obs = FeatureObservation(
            world=ExecutionWorld.CANDIDATE,
            state=FeatureState.PRESENT,
            absence_mechanism=None,
            evidence_detail="Present",
            exit_code=0,
            stdout_digest="0" * 64,
            stderr_digest="1" * 64,
        )
        vacuity = VacuityCheckResult(
            status=VacuityStatus.VACUOUS_NO_ASSERTIONS,
            is_vacuous=True,
            details="Test had no assert statements",
            assertion_count=0,
            target_symbols_referenced=(),
        )
        fact = reconcile_feature_transition(
            base_observation=base_obs,
            candidate_observation=cand_obs,
            base_vacuity=vacuity,
        )
        assert fact.transition == CausalTransition.NON_VERIFIED_VACUOUS
        assert fact.verdict == PreliminaryVerdict.INCONCLUSIVE
        assert fact.is_causally_verified is False


class TestFeatureEndToEndVerification:
    """Validates verify_feature end-to-end receipt generation and tamper detection."""

    def test_verify_feature_produces_tamper_proof_receipt(self) -> None:
        """End-to-end FEATURE verification binds contract, lock, executions, and receipt."""
        contract = _make_sample_contract(ChangeClass.FEATURE)
        source_id = SourceIdentity(
            locator="github.com/repo/test",
            revision=CommitRevision(commit_id="d" * 40),
        )
        candidate_identity = CandidateIdentity(
            candidate_id="cand-feat-1",
            source=source_id,
            patch_digest="a" * 64,
        )
        context = VerifierContextEnvelope.create(
            frozen_contract=contract,
            source_identity=source_id,
            candidate_identity=candidate_identity,
            candidate_tree_digest="1" * 40,
            execution_policy=VerifierExecutionPolicy(timeout_seconds=30),
        )
        art = WitnessArtifact.from_text(
            path="tests/test_feature.py",
            content="def test_feat(): assert True",
        )
        vault = TrustedWitnessVault()
        sealed = vault.seal_witness(
            witness_id="wit-feat-1",
            requirement_id="REQ-FEAT-001",
            frozen_contract_digest=contract.contract_digest,
            source_commit_id=source_id.resolved_commit_id,
            artifacts=(art,),
        )
        lock = create_witness_lock(
            record=sealed,
            vault=vault,
        )

        base_res = _make_normalized_result(
            world=ExecutionWorld.BASE,
            outcome=WitnessOutcome.FAIL,
            exit_code=1,
            stderr="AttributeError: 'Service' object has no attribute 'new_endpoint'",
            sandbox_id="sbx-base-1",
        )
        cand_res = _make_normalized_result(
            world=ExecutionWorld.CANDIDATE,
            outcome=WitnessOutcome.PASS,
            exit_code=0,
            stdout="new_endpoint returned 200 OK",
            sandbox_id="sbx-cand-2",
        )

        receipt = verify_feature(
            context_envelope=context,
            sealed_record=sealed,
            witness_lock=lock,
            base_result=base_res,
            candidate_result=cand_res,
            base_tree_digest="0" * 40,
            candidate_tree_digest="1" * 40,
            expected_absence_mechanism=FeatureAbsenceMechanism.SYMBOL_NOT_FOUND,
        )

        assert receipt.change_class == ChangeClass.FEATURE
        assert receipt.transition == CausalTransition.FEATURE_VERIFIED
        assert receipt.verdict == PreliminaryVerdict.VERIFIED
        assert receipt.is_causally_verified is True
        assert receipt.class_specific_payload["absence_mechanism"] == "SYMBOL_NOT_FOUND"
        assert receipt.class_specific_payload["base_state"] == "ABSENT"
        assert receipt.class_specific_payload["candidate_state"] == "PRESENT"

        # Cryptographic integrity check
        assert verify_semantic_receipt_integrity(receipt) is True

        # Tampering detection test
        tampered_dict = receipt.to_dict()
        tampered_dict["class_specific_payload"]["base_state"] = "PRESENT"
        with pytest.raises(SemanticReceiptTamperingError):
            verify_semantic_receipt_integrity(receipt.__class__.from_dict(tampered_dict))
