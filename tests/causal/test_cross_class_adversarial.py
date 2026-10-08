"""Deterministic cross-class isolation and adversarial anti-collapse tests (P-13.06).

Rigorous adversarial tests proving that semantic change classes cannot collapse into
each other, evidence cannot be replayed cross-class, models cannot override frozen facts,
and infrastructure outcomes (ERROR, TIMEOUT) never masquerade as behavioral PASS or FAIL.
"""

from __future__ import annotations

from dataclasses import replace

import pytest

from basebreak.causal.dep_api import (
    DepApiChangeType,
    MigrationSpecification,
    verify_dep_api_change,
)
from basebreak.causal.feature import (
    FeatureAbsenceMechanism,
    FeatureState,
    detect_feature_state,
    verify_feature,
)
from basebreak.causal.performance import (
    NoisePolicy,
    PerformanceBenchmarkSpec,
    PerformanceMetric,
    verify_performance,
)
from basebreak.causal.reconciliation import (
    CausalTransition,
    ChangeClassMismatchError,
    reconcile_causal_transition,
)
from basebreak.causal.refactor import (
    verify_refactor,
)
from basebreak.causal.security import (
    SecurityBlockingMechanism,
    SecurityState,
    detect_security_state,
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
from basebreak.verifier.witness_lock import (
    ImmutableWitnessLock,
    WitnessLockError,
    create_witness_lock,
)
from basebreak.verifier.witness_result import (
    NormalizedWitnessResult,
    WitnessOutcome,
    normalize_witness_execution,
)
from basebreak.verifier.witness_store import (
    SealedWitnessRecord,
    TrustedWitnessVault,
    WitnessArtifact,
)


def _make_contract(
    change_class: ChangeClass,
    req_id: str = "REQ-CROSS-001",
) -> FrozenContract:
    """Helper to create a valid FrozenContract for any ChangeClass."""
    req = FrozenRequirement(
        requirement_id=req_id,
        statement=f"Cross-class requirement for {change_class.value}",
        citation=f"citation for {change_class.value}",
        citation_start=0,
        citation_end=20,
    )
    contract = object.__new__(FrozenContract)
    object.__setattr__(contract, "schema_version", "1.0.0")
    object.__setattr__(contract, "task_digest", "a" * 64)
    object.__setattr__(contract, "change_class", change_class)
    object.__setattr__(contract, "certainty", CertaintyLevel.CONFIDENT)
    object.__setattr__(contract, "requirements", (req,))
    object.__setattr__(contract, "contract_digest", "b" * 64)
    return contract


def _make_context_envelope(
    contract: FrozenContract,
    source_commit: str = "a" * 40,
    candidate_tree: str = "b" * 40,
) -> VerifierContextEnvelope:
    source_id = SourceIdentity(
        locator="https://github.com/test/repo.git",
        revision=CommitRevision(commit_id=source_commit),
    )
    cand_id = CandidateIdentity(
        candidate_id="cand-cross-1",
        source=source_id,
        patch_digest="c" * 64,
    )
    return VerifierContextEnvelope.create(
        frozen_contract=contract,
        source_identity=source_id,
        candidate_identity=cand_id,
        candidate_tree_digest=candidate_tree,
        execution_policy=VerifierExecutionPolicy(timeout_seconds=30),
    )


def _make_sealed_witness_and_lock(
    contract: FrozenContract,
    source_commit: str = "a" * 40,
    witness_id: str = "wit-cross-1",
) -> tuple[SealedWitnessRecord, ImmutableWitnessLock]:
    vault = TrustedWitnessVault()
    art = WitnessArtifact.from_text(
        path="tests/test_cross.py",
        content="def test_contract(): pass",
    )
    sealed = vault.seal_witness(
        witness_id=witness_id,
        requirement_id=contract.requirements[0].requirement_id,
        frozen_contract_digest=contract.contract_digest,
        source_commit_id=source_commit,
        artifacts=(art,),
    )
    lock = create_witness_lock(record=sealed, vault=vault)
    return sealed, lock


def _make_result(
    outcome: WitnessOutcome = WitnessOutcome.PASS,
    stdout: str = "PASS",
    stderr: str = "",
    exit_code: int | None = 0,
    sandbox_id: str = "sbx-base",
    status: TerminationStatus = TerminationStatus.COMPLETED,
    world: ExecutionWorld = ExecutionWorld.BASE,
    witness_id: str = "wit-cross-1",
) -> NormalizedWitnessResult:
    sbx = SandboxIdentity(
        sandbox_id=sandbox_id,
        description="test sandbox",
    )
    return normalize_witness_execution(
        witness_id=witness_id,
        witness_digest="c" * 64,
        frozen_contract_digest="b" * 64,
        requirement_id="REQ-CROSS-001",
        sandbox_identity=sbx,
        source_commit_id="a" * 40,
        world=world,
        status=status,
        exit_code=exit_code,
        stdout_raw=stdout,
        stderr_raw=stderr,
        duration_seconds=1.23,
        provenance=EvidenceProvenance.LOCAL_EXECUTION,
    )


class TestCrossClassAdversarialInvariants:
    """Rigorous tests covering the 17 P-13.06 cross-class negative invariants."""

    def test_01_bug_fix_evidence_cannot_satisfy_feature_verifier(self) -> None:
        """1. BUG_FIX evidence (e.g. AssertionError) cannot satisfy FEATURE verifier."""
        bug_contract = _make_contract(ChangeClass.BUG_FIX)
        envelope = _make_context_envelope(bug_contract)
        sealed, lock = _make_sealed_witness_and_lock(bug_contract)

        base_res = _make_result(
            outcome=WitnessOutcome.FAIL,
            exit_code=1,
            stderr="AssertionError: assert 42 == 0",
            sandbox_id="sbx-base",
        )
        cand_res = _make_result(
            outcome=WitnessOutcome.PASS,
            exit_code=0,
            stdout="PASS",
            sandbox_id="sbx-cand",
        )

        # Anti-collapse: detect_feature_state classifies AssertionError as ERROR, NOT ABSENT
        obs = detect_feature_state(
            world=ExecutionWorld.BASE,
            result=base_res,
            expected_absence_mechanism=FeatureAbsenceMechanism.SYMBOL_NOT_FOUND,
        )
        assert obs.state == FeatureState.ERROR
        assert obs.absence_mechanism is None

        # Contract mismatch: verify_feature raises ChangeClassMismatchError
        with pytest.raises(ChangeClassMismatchError, match="expected ChangeClass.FEATURE"):
            verify_feature(
                context_envelope=envelope,
                sealed_record=sealed,
                witness_lock=lock,
                base_result=base_res,
                candidate_result=cand_res,
                base_tree_digest="a" * 64,
                candidate_tree_digest="b" * 64,
                expected_absence_mechanism=FeatureAbsenceMechanism.SYMBOL_NOT_FOUND,
            )

    def test_02_feature_absent_present_cannot_masquerade_as_fail_pass_without_explicit_mapping(
        self,
    ) -> None:
        """2. FEATURE ABSENT/PRESENT cannot masquerade as FAIL/PASS without mapping."""
        # Generic FAIL to PASS in BUG_FIX does not verify a FEATURE contract
        fact = reconcile_causal_transition(
            base_outcome=WitnessOutcome.FAIL,
            candidate_outcome=WitnessOutcome.PASS,
        )
        # It verifies CAUSAL_BUG_FIX_VERIFIED, NOT FEATURE_VERIFIED
        assert fact.transition == CausalTransition.CAUSAL_BUG_FIX_VERIFIED

        # An arbitrary exception (e.g. SyntaxError) never counts as ABSENT in FEATURE verifier
        arbitrary_res = _make_result(
            outcome=WitnessOutcome.FAIL,
            exit_code=1,
            stderr="SyntaxError: invalid syntax in parser.py",
        )
        obs = detect_feature_state(
            world=ExecutionWorld.BASE,
            result=arbitrary_res,
            expected_absence_mechanism=FeatureAbsenceMechanism.INPUT_REJECTED_AS_UNSUPPORTED,
        )
        assert obs.state == FeatureState.ERROR

    def test_03_security_crash_never_counts_as_blocked(self) -> None:
        """3. SECURITY crash (exit 139 / SIGSEGV) cannot count as BLOCKED."""
        crash_res = _make_result(
            outcome=WitnessOutcome.FAIL,
            exit_code=139,
            stderr="Segmentation fault (core dumped)",
            sandbox_id="sbx-cand",
        )
        obs = detect_security_state(
            world=ExecutionWorld.CANDIDATE,
            result=crash_res,
            expected_blocking_mechanism=SecurityBlockingMechanism.AUTH_REJECTED,
        )
        assert obs.state == SecurityState.CRASH
        assert "crashes never count as BLOCKED" in obs.evidence_detail

    def test_04_security_timeout_never_counts_as_blocked(self) -> None:
        """4. SECURITY timeout cannot count as BLOCKED."""
        timeout_res = _make_result(
            outcome=WitnessOutcome.TIMEOUT,
            status=TerminationStatus.TIMED_OUT,
            exit_code=None,
            sandbox_id="sbx-cand",
        )
        obs = detect_security_state(
            world=ExecutionWorld.CANDIDATE,
            result=timeout_res,
            expected_blocking_mechanism=SecurityBlockingMechanism.AUTH_REJECTED,
        )
        assert obs.state == SecurityState.TIMEOUT

    def test_05_refactor_changed_behavior_cannot_verify(self) -> None:
        """5. REFACTOR changed output or exit semantics cannot verify."""
        contract = _make_contract(ChangeClass.REFACTOR)
        envelope = _make_context_envelope(contract)
        sealed, lock = _make_sealed_witness_and_lock(contract)

        base_res = _make_result(
            outcome=WitnessOutcome.PASS,
            stdout="Original AST: Node(1)",
            sandbox_id="sbx-base",
        )
        cand_res = _make_result(
            outcome=WitnessOutcome.PASS,
            stdout="Modified AST: Node(1, 2)",  # Changed observable behavior!
            sandbox_id="sbx-cand",
        )

        receipt = verify_refactor(
            context_envelope=envelope,
            sealed_record=sealed,
            witness_lock=lock,
            base_result=base_res,
            candidate_result=cand_res,
            base_tree_digest="a" * 64,
            candidate_tree_digest="b" * 64,
        )
        assert receipt.transition == CausalTransition.UNVERIFIED_BEHAVIOR_CHANGED
        assert receipt.verdict == PreliminaryVerdict.CONTRADICTED
        assert receipt.is_causally_verified is False

    def test_06_performance_faster_but_wrong_candidate_cannot_verify(self) -> None:
        """6. PERFORMANCE faster-but-wrong candidate cannot verify."""
        contract = _make_contract(ChangeClass.PERFORMANCE)
        envelope = _make_context_envelope(contract)
        sealed, lock = _make_sealed_witness_and_lock(contract)

        spec = PerformanceBenchmarkSpec(
            metric=PerformanceMetric.WALL_CLOCK_SECONDS,
            units="seconds",
            target_delta_fraction=0.10,
            noise_policy=NoisePolicy(min_sample_count=3),
        )

        base_res = _make_result(sandbox_id="sbx-base")
        # Candidate runs 10x faster, BUT broke functional correctness!
        cand_res = _make_result(
            outcome=WitnessOutcome.FAIL,
            exit_code=1,
            sandbox_id="sbx-cand",
        )

        receipt = verify_performance(
            context_envelope=envelope,
            sealed_record=sealed,
            witness_lock=lock,
            base_functional_result=base_res,
            candidate_functional_result=cand_res,
            base_samples=(10.0, 10.0, 10.0),
            candidate_samples=(1.0, 1.0, 1.0),
            benchmark_spec=spec,
            base_tree_digest="a" * 64,
            candidate_tree_digest="b" * 64,
        )
        assert receipt.transition == CausalTransition.UNVERIFIED_PERFORMANCE_PARITY_FAILED
        assert receipt.verdict == PreliminaryVerdict.CONTRADICTED
        assert receipt.is_causally_verified is False

    def test_07_performance_correct_but_not_improved_cannot_verify(self) -> None:
        """7. PERFORMANCE correct-but-not-improved candidate cannot verify."""
        contract = _make_contract(ChangeClass.PERFORMANCE)
        envelope = _make_context_envelope(contract)
        sealed, lock = _make_sealed_witness_and_lock(contract)

        spec = PerformanceBenchmarkSpec(
            metric=PerformanceMetric.WALL_CLOCK_SECONDS,
            units="seconds",
            target_delta_fraction=0.20,  # 20% required
            noise_policy=NoisePolicy(min_sample_count=3),
        )

        base_res = _make_result(sandbox_id="sbx-base")
        cand_res = _make_result(sandbox_id="sbx-cand")

        # Only 2% improvement
        receipt = verify_performance(
            context_envelope=envelope,
            sealed_record=sealed,
            witness_lock=lock,
            base_functional_result=base_res,
            candidate_functional_result=cand_res,
            base_samples=(10.0, 10.0, 10.0),
            candidate_samples=(9.8, 9.8, 9.8),
            benchmark_spec=spec,
            base_tree_digest="a" * 64,
            candidate_tree_digest="b" * 64,
        )
        assert receipt.transition == CausalTransition.UNVERIFIED_PERFORMANCE_DELTA_NOT_MET
        assert receipt.verdict == PreliminaryVerdict.CONTRADICTED
        assert receipt.is_causally_verified is False

    def test_08_dep_api_new_contract_works_but_regression_breaks_not_verified(self) -> None:
        """8. DEP/API new contract works but required regression breaks => not verified."""
        contract = _make_contract(ChangeClass.DEP_API_CHANGE)
        envelope = _make_context_envelope(contract)
        sealed, lock = _make_sealed_witness_and_lock(contract)

        spec = MigrationSpecification(
            change_type=DepApiChangeType.DEPENDENCY_UPGRADE,
            target_dependency_or_api="database-connector",
            new_version_or_signature=">=3.0",
        )

        base_new = _make_result(sandbox_id="sbx-base-new", world=ExecutionWorld.BASE)
        base_reg = _make_result(sandbox_id="sbx-base-reg", world=ExecutionWorld.BASE)

        # New contract works, but regression suite fails!
        cand_new = _make_result(sandbox_id="sbx-cand-new", world=ExecutionWorld.CANDIDATE)
        cand_reg = _make_result(
            outcome=WitnessOutcome.FAIL,
            exit_code=1,
            sandbox_id="sbx-cand-reg",
            world=ExecutionWorld.CANDIDATE,
        )

        receipt = verify_dep_api_change(
            context_envelope=envelope,
            sealed_record=sealed,
            witness_lock=lock,
            base_new_contract_result=base_new,
            base_regression_result=base_reg,
            candidate_new_contract_result=cand_new,
            candidate_regression_result=cand_reg,
            migration_spec=spec,
            base_tree_digest="a" * 64,
            candidate_tree_digest="b" * 64,
        )
        assert receipt.transition == CausalTransition.UNVERIFIED_REGRESSION_DETECTED
        assert receipt.verdict == PreliminaryVerdict.CONTRADICTED
        assert receipt.is_causally_verified is False

    @pytest.mark.parametrize(
        "wrong_class",
        [
            ChangeClass.BUG_FIX,
            ChangeClass.SECURITY_FIX,
            ChangeClass.REFACTOR,
            ChangeClass.PERFORMANCE,
            ChangeClass.DEP_API_CHANGE,
        ],
    )
    def test_09_wrong_change_class_verifier_invocation_fails_closed(
        self,
        wrong_class: ChangeClass,
    ) -> None:
        """9. Wrong change-class verifier invocation fails closed with ChangeClassMismatchError."""
        contract = _make_contract(wrong_class)
        envelope = _make_context_envelope(contract)
        sealed, lock = _make_sealed_witness_and_lock(contract)

        base_res = _make_result(sandbox_id="sbx-base")
        cand_res = _make_result(sandbox_id="sbx-cand")

        # Feature verifier must reject any class other than FEATURE
        if wrong_class != ChangeClass.FEATURE:
            with pytest.raises(ChangeClassMismatchError, match="expected ChangeClass.FEATURE"):
                verify_feature(
                    context_envelope=envelope,
                    sealed_record=sealed,
                    witness_lock=lock,
                    base_result=base_res,
                    candidate_result=cand_res,
                    base_tree_digest="a" * 64,
                    candidate_tree_digest="b" * 64,
                    expected_absence_mechanism=FeatureAbsenceMechanism.SYMBOL_NOT_FOUND,
                )

        # Refactor verifier must reject any class other than REFACTOR
        if wrong_class != ChangeClass.REFACTOR:
            with pytest.raises(ChangeClassMismatchError, match="expected ChangeClass.REFACTOR"):
                verify_refactor(
                    context_envelope=envelope,
                    sealed_record=sealed,
                    witness_lock=lock,
                    base_result=base_res,
                    candidate_result=cand_res,
                    base_tree_digest="a" * 64,
                    candidate_tree_digest="b" * 64,
                )

    def test_10_frozen_semantic_class_mismatch_rejected(self) -> None:
        """10. Frozen semantic class mismatch rejected deterministically."""
        contract = _make_contract(ChangeClass.FEATURE)
        envelope = _make_context_envelope(contract)
        sealed, lock = _make_sealed_witness_and_lock(contract)
        base_res = _make_result(sandbox_id="sbx-base")
        cand_res = _make_result(sandbox_id="sbx-cand")

        # Attempting to call verify_security_fix with a FEATURE contract
        with pytest.raises(ChangeClassMismatchError, match="expected ChangeClass.SECURITY_FIX"):
            verify_security_fix(
                context_envelope=envelope,
                sealed_record=sealed,
                witness_lock=lock,
                base_result=base_res,
                candidate_result=cand_res,
                base_tree_digest="a" * 64,
                candidate_tree_digest="b" * 64,
                expected_blocking_mechanism=SecurityBlockingMechanism.AUTH_REJECTED,
            )

    def test_11_model_prose_cannot_reclassify_change_after_freeze(self) -> None:
        """11. Model prose / prompt explanation cannot reclassify change after contract freeze."""
        feature_contract = _make_contract(ChangeClass.FEATURE)
        envelope = _make_context_envelope(feature_contract)
        sealed, lock = _make_sealed_witness_and_lock(feature_contract)

        base_res = _make_result(
            outcome=WitnessOutcome.FAIL,
            exit_code=1,
            stderr="AttributeError: object has no attribute 'new_feat'",
            sandbox_id="sbx-base",
        )
        cand_res = _make_result(
            outcome=WitnessOutcome.PASS,
            exit_code=0,
            stdout="Feature initialized successfully",
            sandbox_id="sbx-cand",
        )

        receipt = verify_feature(
            context_envelope=envelope,
            sealed_record=sealed,
            witness_lock=lock,
            base_result=base_res,
            candidate_result=cand_res,
            base_tree_digest="a" * 64,
            candidate_tree_digest="b" * 64,
            expected_absence_mechanism=FeatureAbsenceMechanism.SYMBOL_NOT_FOUND,
        )
        assert receipt.change_class == ChangeClass.FEATURE
        assert receipt.is_causally_verified is True

        # Even if an external actor/model attempts to alter narrative to claim BUG_FIX:
        tampered_narrative = replace(
            receipt,
            narrative="Model reclassified this as a CAUSAL_BUG_FIX_VERIFIED",
        )
        # Cryptographic digest of receipt fails immediately!
        with pytest.raises(SemanticReceiptTamperingError):
            verify_semantic_receipt_integrity(tampered_narrative)

    def test_12_evidence_from_one_semantic_class_cannot_be_replayed_as_another(self) -> None:
        """12. Evidence from one semantic class cannot be replayed as another."""
        feature_contract = _make_contract(ChangeClass.FEATURE)
        envelope = _make_context_envelope(feature_contract)
        sealed, lock = _make_sealed_witness_and_lock(feature_contract)

        base_res = _make_result(
            outcome=WitnessOutcome.FAIL,
            exit_code=1,
            stderr="AttributeError: object has no attribute 'new_feat'",
            sandbox_id="sbx-base",
        )
        cand_res = _make_result(
            outcome=WitnessOutcome.PASS,
            exit_code=0,
            stdout="Feature initialized",
            sandbox_id="sbx-cand",
        )

        receipt = verify_feature(
            context_envelope=envelope,
            sealed_record=sealed,
            witness_lock=lock,
            base_result=base_res,
            candidate_result=cand_res,
            base_tree_digest="a" * 64,
            candidate_tree_digest="b" * 64,
            expected_absence_mechanism=FeatureAbsenceMechanism.SYMBOL_NOT_FOUND,
        )

        # Attempt to replay this receipt as SECURITY_FIX
        replayed = replace(receipt, change_class=ChangeClass.SECURITY_FIX)
        with pytest.raises(SemanticReceiptTamperingError):
            verify_semantic_receipt_integrity(replayed)

    def test_13_receipt_serialization_tampering_rejected(self) -> None:
        """13. Receipt serialization tampering rejected fail-closed."""
        refactor_contract = _make_contract(ChangeClass.REFACTOR)
        envelope = _make_context_envelope(refactor_contract)
        sealed, lock = _make_sealed_witness_and_lock(refactor_contract)

        base_res = _make_result(stdout="Same output", sandbox_id="sbx-base")
        cand_res = _make_result(stdout="Same output", sandbox_id="sbx-cand")

        receipt = verify_refactor(
            context_envelope=envelope,
            sealed_record=sealed,
            witness_lock=lock,
            base_result=base_res,
            candidate_result=cand_res,
            base_tree_digest="a" * 64,
            candidate_tree_digest="b" * 64,
        )

        # Tampering with verdict and causally_verified flag
        tampered_verdict = replace(
            receipt,
            verdict=PreliminaryVerdict.INCONCLUSIVE,
            is_causally_verified=False,
        )
        with pytest.raises(SemanticReceiptTamperingError):
            verify_semantic_receipt_integrity(tampered_verdict)

        # Modifying candidate_tree_digest violates cryptographic digest
        tampered_tree = replace(receipt, candidate_tree_digest="e" * 64)
        with pytest.raises(SemanticReceiptTamperingError):
            verify_semantic_receipt_integrity(tampered_tree)

    def test_14_provenance_mismatch_rejected(self) -> None:
        """14. Provenance mismatch (e.g. claiming LIVE_NEBIUS on fixture) rejected."""
        contract = _make_contract(ChangeClass.REFACTOR)
        envelope = _make_context_envelope(contract)
        sealed, lock = _make_sealed_witness_and_lock(contract)

        base_res = _make_result(stdout="Same", sandbox_id="sbx-base")
        cand_res = _make_result(stdout="Same", sandbox_id="sbx-cand")

        receipt = verify_refactor(
            context_envelope=envelope,
            sealed_record=sealed,
            witness_lock=lock,
            base_result=base_res,
            candidate_result=cand_res,
            base_tree_digest="a" * 64,
            candidate_tree_digest="b" * 64,
            provenance=EvidenceProvenance.LOCAL_EXECUTION,
        )

        tampered_prov = replace(receipt, provenance=EvidenceProvenance.LIVE_NEBIUS)
        with pytest.raises(SemanticReceiptTamperingError):
            verify_semantic_receipt_integrity(tampered_prov)

    def test_15_candidate_hash_mismatch_rejected(self) -> None:
        """15. Candidate tree digest or source commit mismatch rejected."""
        contract = _make_contract(ChangeClass.REFACTOR)
        envelope = _make_context_envelope(contract)
        sealed, lock = _make_sealed_witness_and_lock(contract)

        base_res = _make_result(stdout="Same", sandbox_id="sbx-base")
        cand_res = _make_result(stdout="Same", sandbox_id="sbx-cand")

        receipt = verify_refactor(
            context_envelope=envelope,
            sealed_record=sealed,
            witness_lock=lock,
            base_result=base_res,
            candidate_result=cand_res,
            base_tree_digest="a" * 64,
            candidate_tree_digest="b" * 64,
        )

        tampered_cand = replace(receipt, candidate_tree_digest="9" * 64)
        with pytest.raises(SemanticReceiptTamperingError):
            verify_semantic_receipt_integrity(tampered_cand)

    def test_16_witness_contract_mismatch_rejected(self) -> None:
        """16. Witness locked against contract A fails custody check against contract B."""
        contract_a = _make_contract(ChangeClass.SECURITY_FIX, req_id="REQ-A")
        contract_b = _make_contract(ChangeClass.SECURITY_FIX, req_id="REQ-B")

        # Sealed and locked against contract A
        sealed_a, lock_a = _make_sealed_witness_and_lock(contract_a)

        # Context envelope configured with contract B
        envelope_b = _make_context_envelope(contract_b)

        base_res = _make_result(sandbox_id="sbx-base")
        cand_res = _make_result(sandbox_id="sbx-cand")

        # Unbroken chain of custody check must raise WitnessLockError
        with pytest.raises(WitnessLockError):
            verify_security_fix(
                context_envelope=envelope_b,
                sealed_record=sealed_a,
                witness_lock=lock_a,
                base_result=base_res,
                candidate_result=cand_res,
                base_tree_digest="a" * 64,
                candidate_tree_digest="b" * 64,
                expected_blocking_mechanism=SecurityBlockingMechanism.AUTH_REJECTED,
            )

    @pytest.mark.parametrize(
        "change_class",
        [
            ChangeClass.FEATURE,
            ChangeClass.SECURITY_FIX,
            ChangeClass.REFACTOR,
        ],
    )
    def test_17_error_and_timeout_remain_non_behavioral_infrastructure_outcomes(
        self,
        change_class: ChangeClass,
    ) -> None:
        """17. ERROR/TIMEOUT remain non-behavioral infrastructure outcomes across all classes."""
        contract = _make_contract(change_class)
        envelope = _make_context_envelope(contract)
        sealed, lock = _make_sealed_witness_and_lock(contract)

        base_clean = _make_result(
            outcome=WitnessOutcome.FAIL
            if change_class != ChangeClass.REFACTOR
            else WitnessOutcome.PASS,
            exit_code=1 if change_class != ChangeClass.REFACTOR else 0,
            sandbox_id="sbx-base",
            stderr="AttributeError: absent" if change_class == ChangeClass.FEATURE else "",
        )
        cand_timeout = _make_result(
            outcome=WitnessOutcome.TIMEOUT,
            status=TerminationStatus.TIMED_OUT,
            exit_code=None,
            sandbox_id="sbx-cand",
        )

        if change_class == ChangeClass.FEATURE:
            receipt = verify_feature(
                context_envelope=envelope,
                sealed_record=sealed,
                witness_lock=lock,
                base_result=base_clean,
                candidate_result=cand_timeout,
                base_tree_digest="a" * 64,
                candidate_tree_digest="b" * 64,
                expected_absence_mechanism=FeatureAbsenceMechanism.SYMBOL_NOT_FOUND,
            )
            assert receipt.transition == CausalTransition.NON_VERIFIED_TIMEOUT
            assert receipt.verdict == PreliminaryVerdict.INCONCLUSIVE
            assert receipt.is_causally_verified is False

        elif change_class == ChangeClass.SECURITY_FIX:
            receipt = verify_security_fix(
                context_envelope=envelope,
                sealed_record=sealed,
                witness_lock=lock,
                base_result=base_clean,
                candidate_result=cand_timeout,
                base_tree_digest="a" * 64,
                candidate_tree_digest="b" * 64,
                expected_blocking_mechanism=SecurityBlockingMechanism.AUTH_REJECTED,
            )
            assert receipt.transition == CausalTransition.NON_VERIFIED_TIMEOUT
            assert receipt.verdict == PreliminaryVerdict.INCONCLUSIVE
            assert receipt.is_causally_verified is False

        elif change_class == ChangeClass.REFACTOR:
            receipt = verify_refactor(
                context_envelope=envelope,
                sealed_record=sealed,
                witness_lock=lock,
                base_result=base_clean,
                candidate_result=cand_timeout,
                base_tree_digest="a" * 64,
                candidate_tree_digest="b" * 64,
            )
            assert receipt.transition == CausalTransition.NON_VERIFIED_TIMEOUT
            assert receipt.verdict == PreliminaryVerdict.INCONCLUSIVE
            assert receipt.is_causally_verified is False
