"""Unit and adversarial tests for P-13.04 PERFORMANCE parity and benchmark-delta verifier."""

from __future__ import annotations

from dataclasses import replace

import pytest

from basebreak.causal.performance import (
    AggregationRule,
    NoisePolicy,
    OptimizationDirection,
    PerformanceBenchmarkSpec,
    PerformanceMetric,
    aggregate_samples,
    compute_relative_noise,
    verify_performance,
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
from basebreak.verifier.witness_lock import ImmutableWitnessLock, create_witness_lock
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


def _make_perf_contract(
    change_class: ChangeClass = ChangeClass.PERFORMANCE,
) -> FrozenContract:
    """Helper to create a valid FrozenContract for performance tests."""
    req = FrozenRequirement(
        requirement_id="REQ-PERF-001",
        statement="Optimize query engine throughput by at least 15% with zero regressions",
        citation="optimize query engine",
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
        candidate_id="cand-perf-1",
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
    content: str = "def test_query_engine(): assert query('x') == 'result_x'",
) -> tuple[SealedWitnessRecord, ImmutableWitnessLock]:
    vault = TrustedWitnessVault()
    art = WitnessArtifact.from_text(
        path="tests/test_perf_correctness.py",
        content=content,
    )
    sealed = vault.seal_witness(
        witness_id="wit-perf-1",
        requirement_id=contract.requirements[0].requirement_id,
        frozen_contract_digest=contract.contract_digest,
        source_commit_id=source_commit,
        artifacts=(art,),
    )
    lock = create_witness_lock(record=sealed, vault=vault)
    return sealed, lock


def _make_result(
    outcome: WitnessOutcome = WitnessOutcome.PASS,
    stdout: str = "PASS: query engine output matches\nTests: 1 passed",
    stderr: str = "",
    exit_code: int | None = 0,
    sandbox_id: str = "sbx-base",
    status: TerminationStatus = TerminationStatus.COMPLETED,
    world: ExecutionWorld = ExecutionWorld.BASE,
) -> NormalizedWitnessResult:
    sbx = SandboxIdentity(
        sandbox_id=sandbox_id,
        description="test sandbox",
    )
    return normalize_witness_execution(
        witness_id="wit-perf-1",
        witness_digest="c" * 64,
        frozen_contract_digest="b" * 64,
        requirement_id="REQ-PERF-001",
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


def _make_benchmark_spec(
    metric: PerformanceMetric = PerformanceMetric.WALL_CLOCK_SECONDS,
    units: str = "seconds",
    target_delta_fraction: float = 0.15,
    direction: OptimizationDirection = OptimizationDirection.LOWER_IS_BETTER,
    aggregation_rule: AggregationRule = AggregationRule.MEDIAN,
    sample_count: int = 5,
    warmup_count: int = 1,
    max_relative_variance: float = 0.15,
) -> PerformanceBenchmarkSpec:
    return PerformanceBenchmarkSpec(
        metric=metric,
        units=units,
        target_delta_fraction=target_delta_fraction,
        direction=direction,
        aggregation_rule=aggregation_rule,
        sample_count=sample_count,
        warmup_count=warmup_count,
        noise_policy=NoisePolicy(
            max_relative_variance=max_relative_variance,
            min_sample_count=3,
        ),
    )


class TestPerformanceVerifier:
    def test_aggregation_and_noise_computation(self) -> None:
        samples = (10.0, 10.2, 9.8, 10.1, 9.9)
        assert aggregate_samples(samples, AggregationRule.MEDIAN) == 10.0
        assert aggregate_samples(samples, AggregationRule.MIN) == 9.8
        assert aggregate_samples(samples, AggregationRule.MAX) == 10.2
        noise = compute_relative_noise(samples)
        assert 0.0 < noise < 0.05  # Low noise

    def test_performance_clean_verification_success(self) -> None:
        """Parity preserved and measured improvement (20% >= 15%) succeeds."""
        contract = _make_perf_contract()
        envelope = _make_context_envelope(contract)
        sealed, lock = _make_sealed_witness_and_lock(contract)
        spec = _make_benchmark_spec(target_delta_fraction=0.15)

        base_res = _make_result(sandbox_id="sbx-base")
        cand_res = _make_result(sandbox_id="sbx-cand")

        # BASE median: 10.0s, CANDIDATE median: 8.0s -> 20% improvement
        base_samples = (10.0, 10.1, 9.9, 10.0, 10.2)
        cand_samples = (8.0, 7.9, 8.1, 8.0, 8.0)

        receipt = verify_performance(
            context_envelope=envelope,
            sealed_record=sealed,
            witness_lock=lock,
            base_functional_result=base_res,
            candidate_functional_result=cand_res,
            base_samples=base_samples,
            candidate_samples=cand_samples,
            benchmark_spec=spec,
            base_tree_digest="a" * 64,
            candidate_tree_digest="b" * 64,
        )

        assert receipt.transition == CausalTransition.PERFORMANCE_VERIFIED
        assert receipt.verdict == PreliminaryVerdict.VERIFIED
        assert receipt.is_causally_verified is True
        assert receipt.change_class == ChangeClass.PERFORMANCE
        assert receipt.class_specific_payload["functional_parity_preserved"] is True
        assert receipt.class_specific_payload["measured_delta_fraction"] == pytest.approx(
            0.20, abs=0.01
        )
        assert receipt.class_specific_payload["threshold_fraction"] == 0.15

        assert verify_semantic_receipt_integrity(receipt) is True

    def test_performance_higher_is_better_throughput_success(self) -> None:
        """Throughput metric (HIGHER_IS_BETTER) verified when meeting target delta."""
        contract = _make_perf_contract()
        envelope = _make_context_envelope(contract)
        sealed, lock = _make_sealed_witness_and_lock(contract)
        spec = _make_benchmark_spec(
            metric=PerformanceMetric.THROUGHPUT_OPS_PER_SEC,
            units="ops/sec",
            target_delta_fraction=0.25,
            direction=OptimizationDirection.HIGHER_IS_BETTER,
        )

        base_res = _make_result(sandbox_id="sbx-base")
        cand_res = _make_result(sandbox_id="sbx-cand")

        # BASE median: 1000 ops/s, CANDIDATE median: 1300 ops/s -> 30% improvement
        base_samples = (1000.0, 1010.0, 990.0, 1000.0, 1005.0)
        cand_samples = (1300.0, 1290.0, 1310.0, 1300.0, 1305.0)

        receipt = verify_performance(
            context_envelope=envelope,
            sealed_record=sealed,
            witness_lock=lock,
            base_functional_result=base_res,
            candidate_functional_result=cand_res,
            base_samples=base_samples,
            candidate_samples=cand_samples,
            benchmark_spec=spec,
            base_tree_digest="a" * 64,
            candidate_tree_digest="b" * 64,
        )

        assert receipt.transition == CausalTransition.PERFORMANCE_VERIFIED
        assert receipt.verdict == PreliminaryVerdict.VERIFIED
        assert receipt.is_causally_verified is True

    def test_faster_but_wrong_candidate_rejected(self) -> None:
        """CRITICAL INVARIANT: Faster-but-wrong candidate MUST NEVER verify."""
        contract = _make_perf_contract()
        envelope = _make_context_envelope(contract)
        sealed, lock = _make_sealed_witness_and_lock(contract)
        spec = _make_benchmark_spec(target_delta_fraction=0.15)

        base_res = _make_result(sandbox_id="sbx-base")
        # Candidate is 2x faster, BUT broke functional correctness!
        cand_res = _make_result(
            outcome=WitnessOutcome.FAIL,
            exit_code=1,
            sandbox_id="sbx-cand",
        )

        base_samples = (10.0, 10.0, 10.0)
        cand_samples = (5.0, 5.0, 5.0)  # 50% faster, but WRONG!

        receipt = verify_performance(
            context_envelope=envelope,
            sealed_record=sealed,
            witness_lock=lock,
            base_functional_result=base_res,
            candidate_functional_result=cand_res,
            base_samples=base_samples,
            candidate_samples=cand_samples,
            benchmark_spec=spec,
            base_tree_digest="a" * 64,
            candidate_tree_digest="b" * 64,
        )

        assert receipt.transition == CausalTransition.UNVERIFIED_PERFORMANCE_PARITY_FAILED
        assert receipt.verdict == PreliminaryVerdict.CONTRADICTED
        assert receipt.is_causally_verified is False
        assert receipt.class_specific_payload["functional_parity_preserved"] is False

    def test_correct_but_unimproved_candidate_rejected(self) -> None:
        """CRITICAL INVARIANT: Correct candidate that fails performance threshold rejected."""
        contract = _make_perf_contract()
        envelope = _make_context_envelope(contract)
        sealed, lock = _make_sealed_witness_and_lock(contract)
        spec = _make_benchmark_spec(target_delta_fraction=0.15)  # 15% required

        base_res = _make_result(sandbox_id="sbx-base")
        cand_res = _make_result(sandbox_id="sbx-cand")

        # BASE median: 10.0s, CANDIDATE median: 9.8s -> only 2% improvement
        base_samples = (10.0, 10.0, 10.0)
        cand_samples = (9.8, 9.8, 9.8)

        receipt = verify_performance(
            context_envelope=envelope,
            sealed_record=sealed,
            witness_lock=lock,
            base_functional_result=base_res,
            candidate_functional_result=cand_res,
            base_samples=base_samples,
            candidate_samples=cand_samples,
            benchmark_spec=spec,
            base_tree_digest="a" * 64,
            candidate_tree_digest="b" * 64,
        )

        assert receipt.transition == CausalTransition.UNVERIFIED_PERFORMANCE_DELTA_NOT_MET
        assert receipt.verdict == PreliminaryVerdict.CONTRADICTED
        assert receipt.is_causally_verified is False

    def test_high_noise_rejected_as_inconclusive(self) -> None:
        """Excessive measurement noise must be rejected as INCONCLUSIVE."""
        contract = _make_perf_contract()
        envelope = _make_context_envelope(contract)
        sealed, lock = _make_sealed_witness_and_lock(contract)
        spec = _make_benchmark_spec(max_relative_variance=0.10)  # 10% max variance

        base_res = _make_result(sandbox_id="sbx-base")
        cand_res = _make_result(sandbox_id="sbx-cand")

        # CANDIDATE has wildly oscillating measurements (high variance)
        base_samples = (10.0, 10.1, 9.9)
        cand_samples = (5.0, 15.0, 8.0, 18.0)

        receipt = verify_performance(
            context_envelope=envelope,
            sealed_record=sealed,
            witness_lock=lock,
            base_functional_result=base_res,
            candidate_functional_result=cand_res,
            base_samples=base_samples,
            candidate_samples=cand_samples,
            benchmark_spec=spec,
            base_tree_digest="a" * 64,
            candidate_tree_digest="b" * 64,
        )

        assert receipt.transition == CausalTransition.UNVERIFIED_PERFORMANCE_NOISY_OR_INCONCLUSIVE
        assert receipt.verdict == PreliminaryVerdict.INCONCLUSIVE
        assert receipt.is_causally_verified is False

    def test_insufficient_samples_inconclusive(self) -> None:
        """Less than minimum required samples fails as inconclusive."""
        contract = _make_perf_contract()
        envelope = _make_context_envelope(contract)
        sealed, lock = _make_sealed_witness_and_lock(contract)
        spec = _make_benchmark_spec()  # min_sample_count = 3

        base_res = _make_result(sandbox_id="sbx-base")
        cand_res = _make_result(sandbox_id="sbx-cand")

        base_samples = (10.0, 10.0)  # Only 2 samples
        cand_samples = (8.0, 8.0)

        receipt = verify_performance(
            context_envelope=envelope,
            sealed_record=sealed,
            witness_lock=lock,
            base_functional_result=base_res,
            candidate_functional_result=cand_res,
            base_samples=base_samples,
            candidate_samples=cand_samples,
            benchmark_spec=spec,
            base_tree_digest="a" * 64,
            candidate_tree_digest="b" * 64,
        )

        assert receipt.transition == CausalTransition.UNVERIFIED_PERFORMANCE_NOISY_OR_INCONCLUSIVE
        assert receipt.verdict == PreliminaryVerdict.INCONCLUSIVE
        assert receipt.is_causally_verified is False

    def test_performance_timeout_fails_closed(self) -> None:
        contract = _make_perf_contract()
        envelope = _make_context_envelope(contract)
        sealed, lock = _make_sealed_witness_and_lock(contract)
        spec = _make_benchmark_spec()

        base_res = _make_result(sandbox_id="sbx-base")
        cand_res = _make_result(
            outcome=WitnessOutcome.TIMEOUT,
            status=TerminationStatus.TIMED_OUT,
            exit_code=None,
            sandbox_id="sbx-cand",
        )

        receipt = verify_performance(
            context_envelope=envelope,
            sealed_record=sealed,
            witness_lock=lock,
            base_functional_result=base_res,
            candidate_functional_result=cand_res,
            base_samples=(10.0, 10.0, 10.0),
            candidate_samples=(8.0, 8.0, 8.0),
            benchmark_spec=spec,
            base_tree_digest="a" * 64,
            candidate_tree_digest="b" * 64,
        )

        assert receipt.transition == CausalTransition.NON_VERIFIED_TIMEOUT
        assert receipt.verdict == PreliminaryVerdict.INCONCLUSIVE
        assert receipt.is_causally_verified is False

    def test_performance_infrastructure_failure_fails_closed(self) -> None:
        contract = _make_perf_contract()
        envelope = _make_context_envelope(contract)
        sealed, lock = _make_sealed_witness_and_lock(contract)
        spec = _make_benchmark_spec()

        base_res = _make_result(sandbox_id="sbx-base")
        cand_res = _make_result(
            outcome=WitnessOutcome.ERROR,
            status=TerminationStatus.CANCELLED,
            exit_code=None,
            sandbox_id="sbx-cand",
        )

        receipt = verify_performance(
            context_envelope=envelope,
            sealed_record=sealed,
            witness_lock=lock,
            base_functional_result=base_res,
            candidate_functional_result=cand_res,
            base_samples=(10.0, 10.0, 10.0),
            candidate_samples=(8.0, 8.0, 8.0),
            benchmark_spec=spec,
            base_tree_digest="a" * 64,
            candidate_tree_digest="b" * 64,
        )

        assert receipt.transition == CausalTransition.NON_VERIFIED_EXECUTION_ERROR
        assert receipt.verdict == PreliminaryVerdict.INCONCLUSIVE
        assert receipt.is_causally_verified is False

    def test_performance_change_class_mismatch_raises(self) -> None:
        contract = _make_perf_contract(change_class=ChangeClass.REFACTOR)
        envelope = _make_context_envelope(contract)
        sealed, lock = _make_sealed_witness_and_lock(contract)
        spec = _make_benchmark_spec()

        base_res = _make_result(sandbox_id="sbx-base")
        cand_res = _make_result(sandbox_id="sbx-cand")

        with pytest.raises(ChangeClassMismatchError, match="expected ChangeClass.PERFORMANCE"):
            verify_performance(
                context_envelope=envelope,
                sealed_record=sealed,
                witness_lock=lock,
                base_functional_result=base_res,
                candidate_functional_result=cand_res,
                base_samples=(10.0, 10.0, 10.0),
                candidate_samples=(8.0, 8.0, 8.0),
                benchmark_spec=spec,
                base_tree_digest="a" * 64,
                candidate_tree_digest="b" * 64,
            )

    def test_performance_empty_patch_fails_closed(self) -> None:
        contract = _make_perf_contract()
        envelope = _make_context_envelope(contract)
        sealed, lock = _make_sealed_witness_and_lock(contract)
        spec = _make_benchmark_spec()

        base_res = _make_result(sandbox_id="sbx-base")
        cand_res = _make_result(sandbox_id="sbx-cand")

        same_digest = "f" * 64
        receipt = verify_performance(
            context_envelope=envelope,
            sealed_record=sealed,
            witness_lock=lock,
            base_functional_result=base_res,
            candidate_functional_result=cand_res,
            base_samples=(10.0, 10.0, 10.0),
            candidate_samples=(8.0, 8.0, 8.0),
            benchmark_spec=spec,
            base_tree_digest=same_digest,
            candidate_tree_digest=same_digest,
        )

        assert receipt.transition == CausalTransition.NON_VERIFIED_TAMPERING_OR_INTEGRITY_FAILURE
        assert receipt.verdict == PreliminaryVerdict.CONTRADICTED

    def test_performance_sandbox_reuse_fails_closed(self) -> None:
        contract = _make_perf_contract()
        envelope = _make_context_envelope(contract)
        sealed, lock = _make_sealed_witness_and_lock(contract)
        spec = _make_benchmark_spec()

        base_res = _make_result(sandbox_id="sbx-reused")
        cand_res = _make_result(sandbox_id="sbx-reused")

        receipt = verify_performance(
            context_envelope=envelope,
            sealed_record=sealed,
            witness_lock=lock,
            base_functional_result=base_res,
            candidate_functional_result=cand_res,
            base_samples=(10.0, 10.0, 10.0),
            candidate_samples=(8.0, 8.0, 8.0),
            benchmark_spec=spec,
            base_tree_digest="a" * 64,
            candidate_tree_digest="b" * 64,
        )

        assert receipt.transition == CausalTransition.NON_VERIFIED_TAMPERING_OR_INTEGRITY_FAILURE
        assert receipt.verdict == PreliminaryVerdict.CONTRADICTED

    def test_performance_vacuous_witness_fails_closed(self) -> None:
        contract = _make_perf_contract()
        envelope = _make_context_envelope(contract)
        sealed, lock = _make_sealed_witness_and_lock(contract)
        spec = _make_benchmark_spec()

        base_res = _make_result(sandbox_id="sbx-base")
        cand_res = _make_result(sandbox_id="sbx-cand")

        vacuity = VacuityCheckResult(
            status=VacuityStatus.VACUOUS_NO_ASSERTIONS,
            is_vacuous=True,
            details="Functional parity witness had zero assertions",
            assertion_count=0,
            target_symbols_referenced=(),
        )

        receipt = verify_performance(
            context_envelope=envelope,
            sealed_record=sealed,
            witness_lock=lock,
            base_functional_result=base_res,
            candidate_functional_result=cand_res,
            base_samples=(10.0, 10.0, 10.0),
            candidate_samples=(8.0, 8.0, 8.0),
            benchmark_spec=spec,
            base_tree_digest="a" * 64,
            candidate_tree_digest="b" * 64,
            candidate_vacuity=vacuity,
        )

        assert receipt.transition == CausalTransition.NON_VERIFIED_VACUOUS
        assert receipt.verdict == PreliminaryVerdict.INCONCLUSIVE
        assert receipt.is_causally_verified is False

    def test_performance_receipt_tampering_rejected(self) -> None:
        contract = _make_perf_contract()
        envelope = _make_context_envelope(contract)
        sealed, lock = _make_sealed_witness_and_lock(contract)
        spec = _make_benchmark_spec()

        base_res = _make_result(sandbox_id="sbx-base")
        cand_res = _make_result(sandbox_id="sbx-cand")

        receipt = verify_performance(
            context_envelope=envelope,
            sealed_record=sealed,
            witness_lock=lock,
            base_functional_result=base_res,
            candidate_functional_result=cand_res,
            base_samples=(10.0, 10.0, 10.0),
            candidate_samples=(8.0, 8.0, 8.0),
            benchmark_spec=spec,
            base_tree_digest="a" * 64,
            candidate_tree_digest="b" * 64,
        )

        tampered = replace(receipt, transition=CausalTransition.REFACTOR_VERIFIED)
        with pytest.raises(SemanticReceiptTamperingError):
            verify_semantic_receipt_integrity(tampered)
