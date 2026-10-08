"""Deterministic PERFORMANCE verification semantics: Parity + Measured Delta.

P-13.04: PERFORMANCE parity and benchmark-delta verifier.

Core Invariants:
1. Dual verification requirement:
   - Functional / behavioral parity must be satisfied (candidate must NOT break functionality).
   - Deterministic measured performance improvement must meet or exceed target threshold.
2. Anti-collapse invariants:
   - Faster-but-wrong candidate -> UNVERIFIED_PERFORMANCE_PARITY_FAILED (CONTRADICTED).
   - Correct-but-unimproved candidate -> UNVERIFIED_PERFORMANCE_DELTA_NOT_MET (CONTRADICTED).
   - High noise / excessive variance -> UNVERIFIED_PERFORMANCE_NOISY_OR_INCONCLUSIVE (INCONCLUSIVE).
   - Insufficient samples (< min_sample_count) -> UNVERIFIED_PERFORMANCE_NOISY_OR_INCONCLUSIVE.
3. No arbitrary single wall-clock claims:
   - Performance evidence requires multiple samples, warmup handling, and deterministic aggregation
     (MEDIAN/MEAN) unless single-sample is explicitly permitted by frozen contract.
4. Frozen contract authority: The contract must be frozen as ChangeClass.PERFORMANCE;
   mismatched change-class invocation fails closed with ChangeClassMismatchError.
5. Zero model authority: Model explanations cannot override measured benchmark facts.
"""

from __future__ import annotations

import statistics
from collections.abc import Sequence
from dataclasses import dataclass, field
from enum import Enum
from typing import Any

from basebreak.causal.receipt import WorldExecutionFact
from basebreak.causal.reconciliation import (
    CausalTransition,
    ChangeClassMismatchError,
    ReconciliationFact,
)
from basebreak.causal.semantic_receipt import (
    SemanticVerificationReceipt,
    create_semantic_receipt,
)
from basebreak.compiler.freeze import FrozenContract
from basebreak.domain.causal import ExecutionWorld
from basebreak.domain.execution import TerminationStatus
from basebreak.domain.semantics import ChangeClass
from basebreak.domain.verdict import EvidenceProvenance, PreliminaryVerdict
from basebreak.verifier.context import VerifierContextEnvelope
from basebreak.verifier.vacuity import VacuityCheckResult
from basebreak.verifier.witness_lock import (
    ImmutableWitnessLock,
    verify_witness_lock_chain,
)
from basebreak.verifier.witness_result import NormalizedWitnessResult, WitnessOutcome
from basebreak.verifier.witness_store import SealedWitnessRecord


class PerformanceMetric(str, Enum):
    """Supported performance metric categories."""

    WALL_CLOCK_SECONDS = "WALL_CLOCK_SECONDS"
    CPU_SECONDS = "CPU_SECONDS"
    PEAK_MEMORY_BYTES = "PEAK_MEMORY_BYTES"
    THROUGHPUT_OPS_PER_SEC = "THROUGHPUT_OPS_PER_SEC"
    LATENCY_MS = "LATENCY_MS"


class AggregationRule(str, Enum):
    """Deterministic mathematical rule for aggregating multiple measurement samples."""

    MEDIAN = "MEDIAN"
    MEAN = "MEAN"
    MIN = "MIN"
    MAX = "MAX"


class OptimizationDirection(str, Enum):
    """Direction of improvement for the benchmark metric."""

    LOWER_IS_BETTER = "LOWER_IS_BETTER"  # e.g. latency, execution time, memory
    HIGHER_IS_BETTER = "HIGHER_IS_BETTER"  # e.g. throughput, ops/sec


@dataclass(frozen=True, slots=True)
class NoisePolicy:
    """Bounded noise and sample count policy for performance measurement."""

    max_relative_variance: float = 0.20  # Max acceptable relative std dev (20%)
    min_sample_count: int = 3
    allow_single_sample: bool = False

    def __post_init__(self) -> None:
        if self.max_relative_variance < 0:
            raise ValueError("max_relative_variance must be non-negative")
        if self.min_sample_count < 1:
            raise ValueError("min_sample_count must be at least 1")


@dataclass(frozen=True, slots=True)
class PerformanceBenchmarkSpec:
    """Deterministic specification for benchmark execution and threshold evaluation."""

    metric: PerformanceMetric
    units: str
    target_delta_fraction: float  # e.g. 0.10 for 10% improvement
    direction: OptimizationDirection = OptimizationDirection.LOWER_IS_BETTER
    aggregation_rule: AggregationRule = AggregationRule.MEDIAN
    sample_count: int = 5
    warmup_count: int = 1
    noise_policy: NoisePolicy = field(default_factory=NoisePolicy)
    environmental_constraints: dict[str, str] = field(default_factory=dict)

    def __post_init__(self) -> None:
        if not self.units.strip():
            raise ValueError("units must be a non-empty string")
        if self.target_delta_fraction <= 0:
            raise ValueError("target_delta_fraction must be strictly positive")


def aggregate_samples(samples: Sequence[float], rule: AggregationRule) -> float:
    """Deterministically aggregate a non-empty sequence of sample values."""
    if not samples:
        raise ValueError("Cannot aggregate empty sample set")
    if rule == AggregationRule.MEDIAN:
        return float(statistics.median(samples))
    if rule == AggregationRule.MEAN:
        return float(statistics.mean(samples))
    if rule == AggregationRule.MIN:
        return float(min(samples))
    if rule == AggregationRule.MAX:
        return float(max(samples))
    raise ValueError(f"Unsupported aggregation rule: {rule}")


def compute_relative_noise(samples: Sequence[float]) -> float:
    """Compute relative standard deviation (std_dev / mean) across samples."""
    if len(samples) <= 1:
        return 0.0
    mean_val = statistics.mean(samples)
    if abs(mean_val) < 1e-9:
        return 0.0
    std_val = statistics.stdev(samples)
    return float(std_val / abs(mean_val))


@dataclass(frozen=True, slots=True)
class PerformanceObservation:
    """Deterministic behavioral and benchmark observation for an execution world."""

    world: ExecutionWorld
    functional_outcome: WitnessOutcome
    functional_exit_code: int | None
    termination_status: TerminationStatus
    samples: tuple[float, ...]
    warmup_samples: tuple[float, ...]
    aggregated_value: float
    relative_noise: float
    is_functional_passed: bool
    is_noisy: bool
    runtime_environment: dict[str, str] = field(default_factory=dict)


def detect_performance_observation(
    *,
    world: ExecutionWorld,
    functional_result: NormalizedWitnessResult,
    samples: Sequence[float],
    spec: PerformanceBenchmarkSpec,
    warmup_samples: Sequence[float] = (),
    runtime_environment: dict[str, str] | None = None,
) -> PerformanceObservation:
    """Extract deterministic functional parity and benchmark measurements."""
    clean_samples = tuple(float(s) for s in samples)
    clean_warmup = tuple(float(s) for s in warmup_samples)

    if not clean_samples:
        raise ValueError("Performance observation requires at least one measurement sample")

    agg_val = aggregate_samples(clean_samples, spec.aggregation_rule)
    rel_noise = compute_relative_noise(clean_samples)
    is_noisy = rel_noise > spec.noise_policy.max_relative_variance

    is_functional_passed = (
        functional_result.outcome == WitnessOutcome.PASS
        and functional_result.exit_code == 0
        and functional_result.termination_status == TerminationStatus.COMPLETED
    )

    return PerformanceObservation(
        world=world,
        functional_outcome=functional_result.outcome,
        functional_exit_code=functional_result.exit_code,
        termination_status=functional_result.termination_status,
        samples=clean_samples,
        warmup_samples=clean_warmup,
        aggregated_value=agg_val,
        relative_noise=rel_noise,
        is_functional_passed=is_functional_passed,
        is_noisy=is_noisy,
        runtime_environment=runtime_environment or {},
    )


def reconcile_performance_transition(
    *,
    base_obs: PerformanceObservation,
    candidate_obs: PerformanceObservation,
    benchmark_spec: PerformanceBenchmarkSpec,
    frozen_contract: FrozenContract,
    base_vacuity: VacuityCheckResult | None = None,
    candidate_vacuity: VacuityCheckResult | None = None,
    integrity_failure_reason: str | None = None,
) -> tuple[ReconciliationFact, float]:
    """Reconcile PERFORMANCE parity and measured benchmark delta between worlds.

    Returns:
        tuple[ReconciliationFact, measured_delta_fraction]
    """
    # 1. Integrity failure
    if integrity_failure_reason:
        return (
            ReconciliationFact(
                transition=CausalTransition.NON_VERIFIED_TAMPERING_OR_INTEGRITY_FAILURE,
                verdict=PreliminaryVerdict.CONTRADICTED,
                is_causally_verified=False,
                rationale=f"Integrity check failed: {integrity_failure_reason}",
            ),
            0.0,
        )

    # 2. Vacuity failure
    if base_vacuity and base_vacuity.is_vacuous:
        return (
            ReconciliationFact(
                transition=CausalTransition.NON_VERIFIED_VACUOUS,
                verdict=PreliminaryVerdict.INCONCLUSIVE,
                is_causally_verified=False,
                rationale=f"BASE functional parity witness was vacuous: {base_vacuity.details}",
            ),
            0.0,
        )
    if candidate_vacuity and candidate_vacuity.is_vacuous:
        return (
            ReconciliationFact(
                transition=CausalTransition.NON_VERIFIED_VACUOUS,
                verdict=PreliminaryVerdict.INCONCLUSIVE,
                is_causally_verified=False,
                rationale=(
                    f"CANDIDATE functional parity witness was vacuous: {candidate_vacuity.details}"
                ),
            ),
            0.0,
        )

    # 3. Timeouts
    if (
        base_obs.termination_status == TerminationStatus.TIMED_OUT
        or candidate_obs.termination_status == TerminationStatus.TIMED_OUT
    ):
        return (
            ReconciliationFact(
                transition=CausalTransition.NON_VERIFIED_TIMEOUT,
                verdict=PreliminaryVerdict.INCONCLUSIVE,
                is_causally_verified=False,
                rationale="Functional parity or benchmark execution timed out.",
            ),
            0.0,
        )

    # 4. Abnormal execution
    abnormal = (TerminationStatus.CANCELLED, TerminationStatus.FAILED_TO_START)
    if base_obs.termination_status in abnormal or candidate_obs.termination_status in abnormal:
        return (
            ReconciliationFact(
                transition=CausalTransition.NON_VERIFIED_EXECUTION_ERROR,
                verdict=PreliminaryVerdict.INCONCLUSIVE,
                is_causally_verified=False,
                rationale="Process terminated abnormally during functional parity execution.",
            ),
            0.0,
        )

    # 5. Functional Parity Check
    # Candidate MUST pass functional parity (FASTER-BUT-WRONG candidate rejected!)
    if not candidate_obs.is_functional_passed:
        return (
            ReconciliationFact(
                transition=CausalTransition.UNVERIFIED_PERFORMANCE_PARITY_FAILED,
                verdict=PreliminaryVerdict.CONTRADICTED,
                is_causally_verified=False,
                rationale=(
                    f"Candidate failed functional parity requirements (outcome="
                    f"{candidate_obs.functional_outcome.value}, "
                    f"exit_code={candidate_obs.functional_exit_code}). "
                    f"A faster-but-wrong candidate cannot be verified."
                ),
            ),
            0.0,
        )

    if not base_obs.is_functional_passed:
        return (
            ReconciliationFact(
                transition=CausalTransition.UNVERIFIED_PERFORMANCE_PARITY_FAILED,
                verdict=PreliminaryVerdict.INCONCLUSIVE,
                is_causally_verified=False,
                rationale=(
                    f"BASE failed functional parity (outcome={base_obs.functional_outcome.value}, "
                    f"exit={base_obs.functional_exit_code}); valid baseline required."
                ),
            ),
            0.0,
        )

    # 6. Sample Count Check
    min_samples = benchmark_spec.noise_policy.min_sample_count
    if (
        len(candidate_obs.samples) < min_samples or len(base_obs.samples) < min_samples
    ) and not benchmark_spec.noise_policy.allow_single_sample:
        return (
            ReconciliationFact(
                transition=CausalTransition.UNVERIFIED_PERFORMANCE_NOISY_OR_INCONCLUSIVE,
                verdict=PreliminaryVerdict.INCONCLUSIVE,
                is_causally_verified=False,
                rationale=(
                    f"Insufficient measurement samples (BASE={len(base_obs.samples)}, "
                    f"CANDIDATE={len(candidate_obs.samples)}, required={min_samples}). "
                    f"Cannot distinguish improvement from noise."
                ),
            ),
            0.0,
        )

    # 7. Noise / Variance Check
    if base_obs.is_noisy or candidate_obs.is_noisy:
        return (
            ReconciliationFact(
                transition=CausalTransition.UNVERIFIED_PERFORMANCE_NOISY_OR_INCONCLUSIVE,
                verdict=PreliminaryVerdict.INCONCLUSIVE,
                is_causally_verified=False,
                rationale=(
                    f"Measurement noise exceeds policy threshold "
                    f"({benchmark_spec.noise_policy.max_relative_variance:.1%}): "
                    f"BASE noise={base_obs.relative_noise:.1%}, "
                    f"CANDIDATE noise={candidate_obs.relative_noise:.1%}. "
                    f"Result is inconclusive."
                ),
            ),
            0.0,
        )

    # 8. Benchmark Delta Calculation
    base_val = base_obs.aggregated_value
    cand_val = candidate_obs.aggregated_value

    if abs(base_val) < 1e-9:
        return (
            ReconciliationFact(
                transition=CausalTransition.UNVERIFIED_PERFORMANCE_NOISY_OR_INCONCLUSIVE,
                verdict=PreliminaryVerdict.INCONCLUSIVE,
                is_causally_verified=False,
                rationale="Baseline measurement negligible; cannot compute relative delta.",
            ),
            0.0,
        )

    if benchmark_spec.direction == OptimizationDirection.LOWER_IS_BETTER:
        # e.g. latency/time: improvement = (base - cand) / base
        delta_fraction = (base_val - cand_val) / base_val
    else:
        # e.g. throughput: improvement = (cand - base) / base
        delta_fraction = (cand_val - base_val) / base_val

    # 9. Threshold Check
    if delta_fraction < benchmark_spec.target_delta_fraction:
        return (
            ReconciliationFact(
                transition=CausalTransition.UNVERIFIED_PERFORMANCE_DELTA_NOT_MET,
                verdict=PreliminaryVerdict.CONTRADICTED,
                is_causally_verified=False,
                rationale=(
                    f"Measured performance improvement ({delta_fraction:.2%}) does not meet "
                    f"required threshold ({benchmark_spec.target_delta_fraction:.2%}). "
                    f"BASE={base_val:.4f} {benchmark_spec.units}, "
                    f"CANDIDATE={cand_val:.4f} {benchmark_spec.units}."
                ),
            ),
            delta_fraction,
        )

    # 10. Clean positive transition: PERFORMANCE_VERIFIED
    return (
        ReconciliationFact(
            transition=CausalTransition.PERFORMANCE_VERIFIED,
            verdict=PreliminaryVerdict.VERIFIED,
            is_causally_verified=True,
            rationale=(
                f"Performance verified: Functional parity preserved; "
                f"measured delta {delta_fraction:.2%} meets required threshold "
                f"{benchmark_spec.target_delta_fraction:.2%} "
                f"({base_val:.4f} -> {cand_val:.4f} {benchmark_spec.units}, "
                f"rule={benchmark_spec.aggregation_rule.value})."
            ),
        ),
        delta_fraction,
    )


def verify_performance(
    *,
    context_envelope: VerifierContextEnvelope,
    sealed_record: SealedWitnessRecord,
    witness_lock: ImmutableWitnessLock,
    base_functional_result: NormalizedWitnessResult,
    candidate_functional_result: NormalizedWitnessResult,
    base_samples: Sequence[float],
    candidate_samples: Sequence[float],
    benchmark_spec: PerformanceBenchmarkSpec,
    base_tree_digest: str,
    candidate_tree_digest: str,
    base_warmup_samples: Sequence[float] = (),
    candidate_warmup_samples: Sequence[float] = (),
    base_vacuity: VacuityCheckResult | None = None,
    candidate_vacuity: VacuityCheckResult | None = None,
    provenance: EvidenceProvenance = EvidenceProvenance.LOCAL_EXECUTION,
) -> SemanticVerificationReceipt:
    """Coordinate deterministic PERFORMANCE verification and generate tamper-proof receipt.

    Binds:
    - contract change_class == ChangeClass.PERFORMANCE
    - witness lock unbroken chain of custody
    - functional parity observations on BASE and CANDIDATE
    - deterministic benchmark measurements and aggregation
    - bounded noise evaluation
    - target delta threshold compliance
    - SemanticVerificationReceipt
    """
    # Step 1: Validate contract change_class
    if context_envelope.frozen_contract.change_class != ChangeClass.PERFORMANCE:
        raise ChangeClassMismatchError(
            f"Contract change_class is {context_envelope.frozen_contract.change_class.value}, "
            f"expected ChangeClass.PERFORMANCE"
        )

    # Step 2: Validate witness lock chain of custody
    verify_witness_lock_chain(
        lock=witness_lock,
        frozen_contract=context_envelope.frozen_contract,
        base_record=sealed_record,
        candidate_record=sealed_record,
    )

    # Step 3: Integrity checks
    integrity_failure_reason: str | None = None
    if base_functional_result.sandbox_id == candidate_functional_result.sandbox_id:
        integrity_failure_reason = "BASE and CANDIDATE reused the same sandbox identity"
    if base_tree_digest.lower() == candidate_tree_digest.lower():
        integrity_failure_reason = (
            "Candidate tree digest is identical to base tree digest (empty patch)"
        )

    # Step 4: Detect performance observations
    base_obs = detect_performance_observation(
        world=ExecutionWorld.BASE,
        functional_result=base_functional_result,
        samples=base_samples,
        spec=benchmark_spec,
        warmup_samples=base_warmup_samples,
    )
    cand_obs = detect_performance_observation(
        world=ExecutionWorld.CANDIDATE,
        functional_result=candidate_functional_result,
        samples=candidate_samples,
        spec=benchmark_spec,
        warmup_samples=candidate_warmup_samples,
    )

    # Step 5: Reconcile transition
    reconciliation, measured_delta = reconcile_performance_transition(
        base_obs=base_obs,
        candidate_obs=cand_obs,
        benchmark_spec=benchmark_spec,
        frozen_contract=context_envelope.frozen_contract,
        base_vacuity=base_vacuity,
        candidate_vacuity=candidate_vacuity,
        integrity_failure_reason=integrity_failure_reason,
    )

    # Step 6: Create execution facts
    base_exec = WorldExecutionFact.from_normalized_result(
        base_functional_result,
        tree_digest=base_tree_digest,
    )
    candidate_exec = WorldExecutionFact.from_normalized_result(
        candidate_functional_result,
        tree_digest=candidate_tree_digest,
    )

    class_payload: dict[str, Any] = {
        "metric": benchmark_spec.metric.value,
        "units": benchmark_spec.units,
        "sample_count": benchmark_spec.sample_count,
        "warmup_count": benchmark_spec.warmup_count,
        "aggregation_rule": benchmark_spec.aggregation_rule.value,
        "direction": benchmark_spec.direction.value,
        "baseline_measurement": base_obs.aggregated_value,
        "candidate_measurement": cand_obs.aggregated_value,
        "measured_delta_fraction": measured_delta,
        "threshold_fraction": benchmark_spec.target_delta_fraction,
        "baseline_relative_noise": base_obs.relative_noise,
        "candidate_relative_noise": cand_obs.relative_noise,
        "environmental_constraints": benchmark_spec.environmental_constraints,
        "functional_parity_preserved": cand_obs.is_functional_passed,
    }

    # Step 7: Build and return authentic SemanticVerificationReceipt
    return create_semantic_receipt(
        change_class=ChangeClass.PERFORMANCE,
        requirement_id=sealed_record.requirement_id,
        frozen_contract_digest=context_envelope.frozen_contract.contract_digest,
        witness_id=sealed_record.witness_id,
        witness_digest=sealed_record.seal_digest,
        lock_digest=witness_lock.lock_digest,
        source_commit_id=context_envelope.source_identity.resolved_commit_id,
        candidate_tree_digest=candidate_tree_digest,
        base_execution=base_exec,
        candidate_execution=candidate_exec,
        class_specific_payload=class_payload,
        transition=reconciliation.transition,
        verdict=reconciliation.verdict,
        is_causally_verified=reconciliation.is_causally_verified,
        provenance=provenance,
        narrative=reconciliation.rationale,
    )
