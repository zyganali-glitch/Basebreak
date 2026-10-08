"""Unit and adversarial tests for P-13.02 SECURITY_FIX EXPLOITABLE->BLOCKED verifier."""

from __future__ import annotations

import pytest

from basebreak.causal.reconciliation import (
    CausalTransition,
    ChangeClassMismatchError,
)
from basebreak.causal.security import (
    SecurityBlockingMechanism,
    SecurityObservation,
    SecurityState,
    detect_security_state,
    reconcile_security_transition,
    verify_security_fix,
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


def _make_security_contract(change_class: ChangeClass = ChangeClass.SECURITY_FIX) -> FrozenContract:
    """Helper to create a valid FrozenContract for security tests."""
    req = FrozenRequirement(
        requirement_id="REQ-SEC-001",
        statement="System shall block unauthorized admin access",
        citation="block unauthorized admin access",
        citation_start=0,
        citation_end=35,
    )
    contract = object.__new__(FrozenContract)
    object.__setattr__(contract, "schema_version", "1.0.0")
    object.__setattr__(contract, "task_digest", "a" * 64)
    object.__setattr__(contract, "change_class", change_class)
    object.__setattr__(contract, "certainty", CertaintyLevel.CONFIDENT)
    object.__setattr__(contract, "requirements", (req,))
    object.__setattr__(contract, "contract_digest", "b" * 64)
    return contract


def _make_security_result(
    *,
    world: ExecutionWorld = ExecutionWorld.BASE,
    outcome: WitnessOutcome = WitnessOutcome.PASS,
    exit_code: int | None = 0,
    stdout: str = "",
    stderr: str = "",
    status: TerminationStatus = TerminationStatus.COMPLETED,
    sandbox_id: str = "sbx-sec-1",
) -> NormalizedWitnessResult:
    sbx = SandboxIdentity(
        sandbox_id=sandbox_id,
        description="security test sandbox",
    )
    return normalize_witness_execution(
        witness_id="wit-sec-001",
        witness_digest="c" * 64,
        frozen_contract_digest="b" * 64,
        requirement_id="REQ-SEC-001",
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


class TestSecurityStateDetection:
    """Validates detection of EXPLOITABLE, BLOCKED, CRASH, TIMEOUT, and UNRELATED_EXCEPTION."""

    def test_exploit_succeeded_is_exploitable(self) -> None:
        """Exploit script passing indicates system is EXPLOITABLE."""
        res = _make_security_result(
            outcome=WitnessOutcome.PASS,
            exit_code=0,
            stdout="EXPLOIT_PAYLOAD_EXECUTED: admin token dumped",
        )
        obs = detect_security_state(
            world=ExecutionWorld.BASE,
            result=res,
            expected_blocking_mechanism=SecurityBlockingMechanism.AUTH_REJECTED,
        )
        assert obs.state == SecurityState.EXPLOITABLE
        assert obs.blocking_mechanism is None

    def test_clean_auth_rejection_is_blocked(self) -> None:
        """HTTP 403 Forbidden indicates exploit is cleanly BLOCKED."""
        res = _make_security_result(
            outcome=WitnessOutcome.FAIL,
            exit_code=1,
            stderr="HTTP/1.1 403 Forbidden: PermissionDenied for anonymous role",
        )
        obs = detect_security_state(
            world=ExecutionWorld.CANDIDATE,
            result=res,
            expected_blocking_mechanism=SecurityBlockingMechanism.AUTH_REJECTED,
        )
        assert obs.state == SecurityState.BLOCKED
        assert obs.blocking_mechanism == SecurityBlockingMechanism.AUTH_REJECTED
        assert "403 Forbidden" in obs.evidence_detail

    def test_input_validation_error_is_blocked(self) -> None:
        """SecurityValidationError indicates exploit is cleanly BLOCKED."""
        res = _make_security_result(
            outcome=WitnessOutcome.FAIL,
            exit_code=1,
            stderr="SecurityValidationError: dangerous character detected in path parameter",
        )
        obs = detect_security_state(
            world=ExecutionWorld.CANDIDATE,
            result=res,
            expected_blocking_mechanism=SecurityBlockingMechanism.INPUT_VALIDATION_ERROR,
        )
        assert obs.state == SecurityState.BLOCKED
        assert obs.blocking_mechanism == SecurityBlockingMechanism.INPUT_VALIDATION_ERROR

    def test_crash_sigsegv_never_counts_as_blocked(self) -> None:
        """CRITICAL INVARIANT: Crash (SIGSEGV / exit 139) must NEVER count as BLOCKED."""
        res = _make_security_result(
            outcome=WitnessOutcome.FAIL,
            exit_code=139,
            stderr="Segmentation fault (core dumped)",
        )
        obs = detect_security_state(
            world=ExecutionWorld.CANDIDATE,
            result=res,
            expected_blocking_mechanism=SecurityBlockingMechanism.AUTH_REJECTED,
        )
        assert obs.state == SecurityState.CRASH
        assert obs.blocking_mechanism is None
        assert "crashes never count as BLOCKED" in obs.evidence_detail

    def test_unrelated_exception_never_counts_as_blocked(self) -> None:
        """CRITICAL INVARIANT: Unhandled exception (e.g. ZeroDivisionError) != BLOCKED."""
        res = _make_security_result(
            outcome=WitnessOutcome.FAIL,
            exit_code=1,
            stderr="ZeroDivisionError: division by zero in auth_handler.py",
        )
        obs = detect_security_state(
            world=ExecutionWorld.CANDIDATE,
            result=res,
            expected_blocking_mechanism=SecurityBlockingMechanism.AUTH_REJECTED,
        )
        assert obs.state == SecurityState.UNRELATED_EXCEPTION
        assert obs.blocking_mechanism is None
        assert "unrelated exceptions never count as BLOCKED" in obs.evidence_detail

    def test_timeout_never_counts_as_blocked(self) -> None:
        """CRITICAL INVARIANT: Timeout must NEVER count as BLOCKED."""
        res = _make_security_result(
            outcome=WitnessOutcome.TIMEOUT,
            status=TerminationStatus.TIMED_OUT,
            exit_code=None,
        )
        obs = detect_security_state(
            world=ExecutionWorld.CANDIDATE,
            result=res,
            expected_blocking_mechanism=SecurityBlockingMechanism.AUTH_REJECTED,
        )
        assert obs.state == SecurityState.TIMEOUT
        assert obs.blocking_mechanism is None


class TestSecurityReconciliation:
    """Validates deterministic reconciliation for SECURITY_FIX."""

    def test_exploitable_to_blocked_verified(self) -> None:
        """BASE=EXPLOITABLE, CANDIDATE=BLOCKED (legitimate preserved) -> SECURITY_FIX_VERIFIED."""
        base_obs = SecurityObservation(
            world=ExecutionWorld.BASE,
            state=SecurityState.EXPLOITABLE,
            blocking_mechanism=None,
            evidence_detail="Exploit executed",
            exit_code=0,
            stdout_digest="0" * 64,
            stderr_digest="1" * 64,
        )
        cand_obs = SecurityObservation(
            world=ExecutionWorld.CANDIDATE,
            state=SecurityState.BLOCKED,
            blocking_mechanism=SecurityBlockingMechanism.AUTH_REJECTED,
            evidence_detail="HTTP 403 Forbidden",
            exit_code=1,
            stdout_digest="0" * 64,
            stderr_digest="1" * 64,
        )
        contract = _make_security_contract(ChangeClass.SECURITY_FIX)

        fact = reconcile_security_transition(
            base_observation=base_obs,
            candidate_observation=cand_obs,
            legitimate_preserved=True,
            frozen_contract=contract,
        )
        assert fact.transition == CausalTransition.SECURITY_FIX_VERIFIED
        assert fact.verdict == PreliminaryVerdict.VERIFIED
        assert fact.is_causally_verified is True
        assert "Security fix verified" in fact.rationale

    def test_broken_legitimate_behavior_is_regression(self) -> None:
        """Exploit blocked but legitimate behavior broken -> UNVERIFIED_SECURITY_FIX_REGRESSION."""
        base_obs = SecurityObservation(
            world=ExecutionWorld.BASE,
            state=SecurityState.EXPLOITABLE,
            blocking_mechanism=None,
            evidence_detail="Exploit executed",
            exit_code=0,
            stdout_digest="0" * 64,
            stderr_digest="1" * 64,
        )
        cand_obs = SecurityObservation(
            world=ExecutionWorld.CANDIDATE,
            state=SecurityState.BLOCKED,
            blocking_mechanism=SecurityBlockingMechanism.AUTH_REJECTED,
            evidence_detail="HTTP 403 Forbidden",
            exit_code=1,
            stdout_digest="0" * 64,
            stderr_digest="1" * 64,
        )
        fact = reconcile_security_transition(
            base_observation=base_obs,
            candidate_observation=cand_obs,
            legitimate_preserved=False,  # Broken!
        )
        assert fact.transition == CausalTransition.UNVERIFIED_SECURITY_FIX_REGRESSION
        assert fact.verdict == PreliminaryVerdict.CONTRADICTED
        assert fact.is_causally_verified is False
        assert "security fix regression" in fact.rationale

    def test_crash_on_candidate_is_non_verified_crash(self) -> None:
        """Crash on candidate resolves to NON_VERIFIED_CRASH_OR_UNHANDLED_EXCEPTION."""
        base_obs = SecurityObservation(
            world=ExecutionWorld.BASE,
            state=SecurityState.EXPLOITABLE,
            blocking_mechanism=None,
            evidence_detail="Exploit executed",
            exit_code=0,
            stdout_digest="0" * 64,
            stderr_digest="1" * 64,
        )
        cand_obs = SecurityObservation(
            world=ExecutionWorld.CANDIDATE,
            state=SecurityState.CRASH,
            blocking_mechanism=None,
            evidence_detail="SIGSEGV 139",
            exit_code=139,
            stdout_digest="0" * 64,
            stderr_digest="1" * 64,
        )
        fact = reconcile_security_transition(
            base_observation=base_obs,
            candidate_observation=cand_obs,
        )
        assert fact.transition == CausalTransition.NON_VERIFIED_CRASH_OR_UNHANDLED_EXCEPTION
        assert fact.verdict == PreliminaryVerdict.INCONCLUSIVE
        assert fact.is_causally_verified is False

    def test_exploit_persists_is_contradicted(self) -> None:
        """BASE=EXPLOITABLE, CANDIDATE=EXPLOITABLE -> UNVERIFIED_EXPLOIT_PERSISTS."""
        base_obs = SecurityObservation(
            world=ExecutionWorld.BASE,
            state=SecurityState.EXPLOITABLE,
            blocking_mechanism=None,
            evidence_detail="Exploit executed",
            exit_code=0,
            stdout_digest="0" * 64,
            stderr_digest="1" * 64,
        )
        cand_obs = SecurityObservation(
            world=ExecutionWorld.CANDIDATE,
            state=SecurityState.EXPLOITABLE,
            blocking_mechanism=None,
            evidence_detail="Exploit still works",
            exit_code=0,
            stdout_digest="0" * 64,
            stderr_digest="1" * 64,
        )
        fact = reconcile_security_transition(
            base_observation=base_obs,
            candidate_observation=cand_obs,
        )
        assert fact.transition == CausalTransition.UNVERIFIED_EXPLOIT_PERSISTS
        assert fact.verdict == PreliminaryVerdict.CONTRADICTED
        assert fact.is_causally_verified is False

    def test_vulnerability_not_reproduced_on_base_is_inconclusive(self) -> None:
        """BASE=BLOCKED -> UNVERIFIED_VULNERABILITY_NOT_REPRODUCED."""
        base_obs = SecurityObservation(
            world=ExecutionWorld.BASE,
            state=SecurityState.BLOCKED,
            blocking_mechanism=SecurityBlockingMechanism.AUTH_REJECTED,
            evidence_detail="Already blocked",
            exit_code=1,
            stdout_digest="0" * 64,
            stderr_digest="1" * 64,
        )
        cand_obs = SecurityObservation(
            world=ExecutionWorld.CANDIDATE,
            state=SecurityState.BLOCKED,
            blocking_mechanism=SecurityBlockingMechanism.AUTH_REJECTED,
            evidence_detail="Blocked",
            exit_code=1,
            stdout_digest="0" * 64,
            stderr_digest="1" * 64,
        )
        fact = reconcile_security_transition(
            base_observation=base_obs,
            candidate_observation=cand_obs,
        )
        assert fact.transition == CausalTransition.UNVERIFIED_VULNERABILITY_NOT_REPRODUCED
        assert fact.verdict == PreliminaryVerdict.INCONCLUSIVE
        assert fact.is_causally_verified is False

    def test_wrong_change_class_fails_closed(self) -> None:
        """FEATURE contract passed to SECURITY_FIX verifier raises ChangeClassMismatchError."""
        feat_contract = _make_security_contract(ChangeClass.FEATURE)
        base_obs = SecurityObservation(
            world=ExecutionWorld.BASE,
            state=SecurityState.EXPLOITABLE,
            blocking_mechanism=None,
            evidence_detail="Exploit",
            exit_code=0,
            stdout_digest="0" * 64,
            stderr_digest="1" * 64,
        )
        cand_obs = SecurityObservation(
            world=ExecutionWorld.CANDIDATE,
            state=SecurityState.BLOCKED,
            blocking_mechanism=SecurityBlockingMechanism.AUTH_REJECTED,
            evidence_detail="Blocked",
            exit_code=1,
            stdout_digest="0" * 64,
            stderr_digest="1" * 64,
        )
        with pytest.raises(ChangeClassMismatchError, match="expected ChangeClass.SECURITY_FIX"):
            reconcile_security_transition(
                base_observation=base_obs,
                candidate_observation=cand_obs,
                frozen_contract=feat_contract,
            )


class TestSecurityEndToEndVerification:
    """Validates verify_security_fix end-to-end receipt generation and tamper resistance."""

    def test_verify_security_fix_produces_tamper_proof_receipt(self) -> None:
        """End-to-end SECURITY_FIX verification produces verified receipt."""
        contract = _make_security_contract(ChangeClass.SECURITY_FIX)
        source_id = SourceIdentity(
            locator="github.com/repo/test",
            revision=CommitRevision(commit_id="d" * 40),
        )
        candidate_identity = CandidateIdentity(
            candidate_id="cand-sec-1",
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
            path="tests/test_exploit.py",
            content="def test_exploit(): pass",
        )
        vault = TrustedWitnessVault()
        sealed = vault.seal_witness(
            witness_id="wit-sec-1",
            requirement_id="REQ-SEC-001",
            frozen_contract_digest=contract.contract_digest,
            source_commit_id=source_id.resolved_commit_id,
            artifacts=(art,),
        )
        lock = create_witness_lock(
            record=sealed,
            vault=vault,
        )

        base_res = _make_security_result(
            world=ExecutionWorld.BASE,
            outcome=WitnessOutcome.PASS,
            exit_code=0,
            stdout="EXPLOIT_PAYLOAD_EXECUTED",
            sandbox_id="sbx-base-sec",
        )
        cand_res = _make_security_result(
            world=ExecutionWorld.CANDIDATE,
            outcome=WitnessOutcome.FAIL,
            exit_code=1,
            stderr="403 Forbidden: PermissionDenied",
            sandbox_id="sbx-cand-sec",
        )
        cand_legit_res = _make_security_result(
            world=ExecutionWorld.CANDIDATE,
            outcome=WitnessOutcome.PASS,
            exit_code=0,
            stdout="Legitimate query succeeded 200 OK",
            sandbox_id="sbx-cand-legit",
        )

        receipt = verify_security_fix(
            context_envelope=context,
            sealed_record=sealed,
            witness_lock=lock,
            base_result=base_res,
            candidate_result=cand_res,
            base_tree_digest="0" * 40,
            candidate_tree_digest="1" * 40,
            expected_blocking_mechanism=SecurityBlockingMechanism.AUTH_REJECTED,
            candidate_legitimate_result=cand_legit_res,
        )

        assert receipt.change_class == ChangeClass.SECURITY_FIX
        assert receipt.transition == CausalTransition.SECURITY_FIX_VERIFIED
        assert receipt.verdict == PreliminaryVerdict.VERIFIED
        assert receipt.is_causally_verified is True
        assert receipt.class_specific_payload["base_state"] == "EXPLOITABLE"
        assert receipt.class_specific_payload["candidate_state"] == "BLOCKED"
        assert receipt.class_specific_payload["legitimate_behavior_preserved"] is True

        assert verify_semantic_receipt_integrity(receipt) is True

        # Tampering check
        tampered_dict = receipt.to_dict()
        tampered_dict["class_specific_payload"]["legitimate_behavior_preserved"] = False
        with pytest.raises(SemanticReceiptTamperingError):
            verify_semantic_receipt_integrity(receipt.__class__.from_dict(tampered_dict))
