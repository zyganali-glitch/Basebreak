"""Comprehensive test suite for Phase P-26 Performance, Cost & Model Routing.

Exercises all micro-tasks and repair invariants:
- P-26.01: Latency, token, and sandbox cost measurement instrumentation
- P-26.02: Builder workload model comparison benchmarks (offline fixture vs NOT_RUN live)
- P-26.03: Verifier / witness workload model strategy comparison
- P-26.04: Deterministic model and strategy routing with fail-closed negative tests
- P-26.05: Causal verification overhead benchmark relative to baseline
"""

from __future__ import annotations

import time

import pytest

from basebreak.adapters.nebius.models import (
    CANDIDATE_DEEP_MODEL,
    DEFAULT_PRIMARY_MODEL,
)
from basebreak.domain.semantics import ChangeClass
from basebreak.performance.benchmarks import (
    BenchmarkExecutionMode,
    BenchmarkStatus,
    BuilderModelBenchmark,
    VerifierStrategyBenchmark,
)
from basebreak.performance.overhead import compute_causal_overhead
from basebreak.performance.router import (
    ModelRouter,
    RiskTier,
    UnmeasuredOptimalityError,
    UnsupportedModelError,
    WorkloadProfile,
)
from basebreak.performance.telemetry import TelemetryCollector


class TestP26PerformanceAndRouting:
    """Rigorous tests covering the complete P-26 performance and routing matrix."""

    # -------------------------------------------------------------------------
    # P-26.01: Latency, token, and sandbox cost measurement instrumentation
    # -------------------------------------------------------------------------
    def test_p26_01_telemetry_collector(self) -> None:
        """P-26.01: Telemetry collector captures phase latency, tokens, and sandbox metrics."""
        collector = TelemetryCollector(run_id="run-telemetry-01", is_verified_zero_cost=True)

        collector.start_phase("contract_freeze")
        time.sleep(0.01)
        p1 = collector.stop_phase("contract_freeze")
        assert p1.phase_name == "contract_freeze"
        assert p1.duration_ms >= 5.0

        collector.record_tokens(prompt_tokens=1500, completion_tokens=350, cached_tokens=500)
        collector.record_sandbox(duration_seconds=2.5, count=1)

        telemetry = collector.finalize()
        assert telemetry.run_id == "run-telemetry-01"
        assert telemetry.total_tokens == 1850
        assert telemetry.prompt_tokens == 1500
        assert telemetry.completion_tokens == 350
        assert telemetry.cached_tokens == 500
        assert telemetry.sandbox_count == 1
        assert telemetry.sandbox_duration_seconds == 2.5
        assert telemetry.is_verified_zero_cost is True
        assert len(telemetry.phases) == 1

    # -------------------------------------------------------------------------
    # P-26.02: Builder workload model comparison benchmarks
    # -------------------------------------------------------------------------
    def test_p26_02_builder_model_benchmark_offline_and_live(self) -> None:
        """P-26.02: Offline benchmark calculates metrics; live benchmark is honestly NOT_RUN."""
        evals = [
            {
                "valid_syntax": True,
                "test_pass": True,
                "causal_pass": True,
                "prompt_tokens": 1200,
                "completion_tokens": 300,
                "latency_ms": 450.0,
            },
            {
                "valid_syntax": True,
                "test_pass": False,
                "causal_pass": False,
                "prompt_tokens": 1100,
                "completion_tokens": 250,
                "latency_ms": 410.0,
            },
        ]

        model_id = DEFAULT_PRIMARY_MODEL
        offline_res = BuilderModelBenchmark.run_offline_benchmark(model_id, evals)
        assert offline_res.mode == BenchmarkExecutionMode.OFFLINE_FIXTURE
        assert offline_res.status == BenchmarkStatus.COMPLETED
        assert offline_res.metrics["syntax_validity_rate"] == 1.0
        assert offline_res.metrics["pass_at_1_rate"] == 0.5
        assert offline_res.metrics["causal_witness_pass_rate"] == 0.5
        assert "Does NOT represent live Nebius" in offline_res.notes

        # Live benchmark status must be OPERATOR_AUTHORIZATION_REQUIRED under Zero-Cost Law
        live_res = BuilderModelBenchmark.get_live_benchmark_status(model_id)
        assert live_res.mode == BenchmarkExecutionMode.LIVE_EXTERNAL
        assert live_res.status == BenchmarkStatus.OPERATOR_AUTHORIZATION_REQUIRED
        assert "NOT_RUN" in live_res.notes

    def test_p26_02_builder_benchmark_unsupported_model_fails_closed(self) -> None:
        """P-26.02 negative test: Benchmark on unverified model raises UnsupportedModelError."""
        with pytest.raises(UnsupportedModelError, match="Must be one of verified models"):
            BuilderModelBenchmark.run_offline_benchmark("unverified/speculative-model-xyz", [])

        with pytest.raises(UnsupportedModelError, match="not an eligible provider model"):
            BuilderModelBenchmark.get_live_benchmark_status("unverified/speculative-model-xyz")

    # -------------------------------------------------------------------------
    # P-26.03: Verifier / witness workload model strategy comparison
    # -------------------------------------------------------------------------
    def test_p26_03_verifier_strategy_benchmark(self) -> None:
        """P-26.03: Strategy benchmark evaluates vacuity rejection and assertion density."""
        trials = [
            {
                "vacuity_status": "VALID",
                "counterfactual_failed": True,
                "assertion_count": 3,
            },
            {
                "vacuity_status": "VACUOUS_TRIVIAL_PASS",
                "counterfactual_failed": False,
                "assertion_count": 1,
            },
        ]

        res = VerifierStrategyBenchmark.evaluate_strategy("TEMPLATE_GUIDED", trials)
        assert res.metrics["sample_count"] == 2
        assert res.metrics["valid_witness_rate"] == 0.5
        assert res.metrics["vacuity_rejection_rate"] == 0.5
        assert res.metrics["counterfactual_sensitivity_rate"] == 0.5
        assert res.metrics["avg_assertion_density"] == 2.0

        with pytest.raises(ValueError, match="Unknown strategy"):
            VerifierStrategyBenchmark.evaluate_strategy("INVALID_UNKNOWN_STRATEGY", trials)

    # -------------------------------------------------------------------------
    # P-26.04: Model routing decision logic based strictly on measured facts
    # -------------------------------------------------------------------------
    def test_p26_04_model_routing_decisions(self) -> None:
        """P-26.04: Model router makes deterministic choices bound to verified provider models."""
        # 1. Critical risk / security boundary -> Verified primary + Template Guided
        prof_crit = WorkloadProfile(
            change_class=ChangeClass.BUG_FIX,
            risk_tier=RiskTier.CRITICAL,
            has_security_boundary_impact=True,
        )
        dec_crit = ModelRouter.route_workload(prof_crit)
        assert dec_crit.builder_model_id == DEFAULT_PRIMARY_MODEL
        assert dec_crit.verifier_strategy == "TEMPLATE_GUIDED"
        assert dec_crit.temperature == 0.0
        assert dec_crit.is_empirically_optimal is False
        assert dec_crit.model_eligibility == "LIVE_PROVEN"

        # 2. High risk + deep reasoning -> Verified primary + Multi-turn reflection
        prof_reasoning = WorkloadProfile(
            change_class=ChangeClass.BUG_FIX,
            risk_tier=RiskTier.HIGH,
            requires_deep_reasoning=True,
        )
        dec_reasoning = ModelRouter.route_workload(prof_reasoning)
        assert dec_reasoning.builder_model_id == DEFAULT_PRIMARY_MODEL
        assert dec_reasoning.verifier_strategy == "MULTI_TURN_REFLECTION"
        assert dec_reasoning.is_empirically_optimal is False

        # 3. Explicitly requested catalog-confirmed model
        prof_deep = WorkloadProfile(
            change_class=ChangeClass.BUG_FIX,
            risk_tier=RiskTier.HIGH,
            requested_model_id=CANDIDATE_DEEP_MODEL,
        )
        dec_deep = ModelRouter.route_workload(prof_deep)
        assert dec_deep.builder_model_id == CANDIDATE_DEEP_MODEL
        assert dec_deep.model_eligibility == "CATALOG_CONFIRMED"

        # 4. Low risk refactor -> Single shot
        prof_low = WorkloadProfile(
            change_class=ChangeClass.REFACTOR,
            risk_tier=RiskTier.LOW,
        )
        dec_low = ModelRouter.route_workload(prof_low)
        assert dec_low.builder_model_id == DEFAULT_PRIMARY_MODEL
        assert dec_low.verifier_strategy == "SINGLE_SHOT"
        assert dec_low.is_empirically_optimal is False

    def test_p26_04_unsupported_model_fails_closed(self) -> None:
        """P-26.04 negative test: Requesting an unverified model ID raises UnsupportedModelError."""
        prof_invalid = WorkloadProfile(
            change_class=ChangeClass.BUG_FIX,
            risk_tier=RiskTier.HIGH,
            requested_model_id="deepseek-ai/deepseek-r1",
        )
        with pytest.raises(UnsupportedModelError, match="is not verified or supported"):
            ModelRouter.route_workload(prof_invalid)

    def test_p26_04_attempted_optimality_claim_fails_closed(self) -> None:
        """P-26.04 negative test: Claiming empirical optimality raises UnmeasuredOptimalityError."""
        prof = WorkloadProfile(
            change_class=ChangeClass.BUG_FIX,
            risk_tier=RiskTier.MEDIUM,
        )
        with pytest.raises(UnmeasuredOptimalityError, match="Cannot claim empirical optimality"):
            ModelRouter.route_workload(prof, claim_empirical_optimality=True)

    # -------------------------------------------------------------------------
    # P-26.05: Causal verification overhead benchmark relative to baseline
    # -------------------------------------------------------------------------
    def test_p26_05_causal_overhead_calculation(self) -> None:
        """P-26.05: Calculates causal verification overhead multiplier against baseline CI."""
        overhead = compute_causal_overhead(
            baseline_ci_ms=100.0,
            contract_freeze_ms=10.0,
            base_execution_ms=80.0,
            candidate_execution_ms=85.0,
            counterfactual_execution_ms=85.0,
            reconciliation_ms=10.0,
            causal_break_proven=True,
            vacuous_pass_detected=False,
        )

        assert overhead.baseline_ci_ms == 100.0
        assert overhead.causal_verification_ms == 270.0
        assert overhead.overhead_multiplier == 2.7
        assert overhead.has_counterfactual is True
        assert overhead.causal_break_proven is True
