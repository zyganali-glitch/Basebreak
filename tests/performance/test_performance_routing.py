"""Comprehensive test suite for Phase P-26 Performance, Cost & Model Routing.

Exercises all micro-tasks:
- P-26.01: Latency, token, and sandbox cost measurement instrumentation
- P-26.02: Builder workload model comparison benchmarks
- P-26.03: Verifier / witness workload model strategy comparison
- P-26.04: Model routing decision logic based strictly on measured facts
- P-26.05: Causal verification overhead benchmark relative to baseline
"""

from __future__ import annotations

import time

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

        # Measure phase 1
        collector.start_phase("contract_freeze")
        time.sleep(0.01)
        p1 = collector.stop_phase("contract_freeze")
        assert p1.phase_name == "contract_freeze"
        assert p1.duration_ms >= 5.0

        # Record tokens
        collector.record_tokens(prompt_tokens=1500, completion_tokens=350, cached_tokens=500)

        # Record sandbox
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

        model_id = "nvidia/llama-3.1-nemotron-70b-instruct"
        offline_res = BuilderModelBenchmark.run_offline_benchmark(model_id, evals)
        assert offline_res.mode == BenchmarkExecutionMode.OFFLINE_FIXTURE
        assert offline_res.status == BenchmarkStatus.COMPLETED
        assert offline_res.metrics["syntax_validity_rate"] == 1.0
        assert offline_res.metrics["pass_at_1_rate"] == 0.5
        assert offline_res.metrics["causal_witness_pass_rate"] == 0.5

        # Live benchmark status must be OPERATOR_AUTHORIZATION_REQUIRED under Zero-Cost Law
        live_res = BuilderModelBenchmark.get_live_benchmark_status(model_id)
        assert live_res.mode == BenchmarkExecutionMode.LIVE_EXTERNAL
        assert live_res.status == BenchmarkStatus.OPERATOR_AUTHORIZATION_REQUIRED
        assert "NOT_RUN" in live_res.notes

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

    # -------------------------------------------------------------------------
    # P-26.04: Model routing decision logic based strictly on measured facts
    # -------------------------------------------------------------------------
    def test_p26_04_model_routing_decisions(self) -> None:
        """P-26.04: Model router makes deterministic choices based on risk and workload facts."""
        # 1. Critical risk / security boundary -> Nemotron 70B + Template Guided
        prof_crit = WorkloadProfile(
            change_class=ChangeClass.BUG_FIX,
            risk_tier=RiskTier.CRITICAL,
            has_security_boundary_impact=True,
        )
        dec_crit = ModelRouter.route_workload(prof_crit)
        assert dec_crit.builder_model_id == ModelRouter.MODEL_NEMOTRON_70B
        assert dec_crit.verifier_strategy == "TEMPLATE_GUIDED"
        assert dec_crit.temperature == 0.0

        # 2. High risk + deep reasoning -> DeepSeek R1 + Multi-turn reflection
        prof_reasoning = WorkloadProfile(
            change_class=ChangeClass.BUG_FIX,
            risk_tier=RiskTier.HIGH,
            requires_deep_reasoning=True,
        )
        dec_reasoning = ModelRouter.route_workload(prof_reasoning)
        assert dec_reasoning.builder_model_id == ModelRouter.MODEL_REASONING_R1
        assert dec_reasoning.verifier_strategy == "MULTI_TURN_REFLECTION"

        # 3. Low risk refactor -> Llama 3.3 70B + Single shot
        prof_low = WorkloadProfile(
            change_class=ChangeClass.REFACTOR,
            risk_tier=RiskTier.LOW,
        )
        dec_low = ModelRouter.route_workload(prof_low)
        assert dec_low.builder_model_id == ModelRouter.MODEL_LLAMA_70B
        assert dec_low.verifier_strategy == "SINGLE_SHOT"

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
