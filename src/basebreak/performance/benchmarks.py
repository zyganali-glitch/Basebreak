"""Builder model comparison and verifier strategy benchmark frameworks.

P-26.02: Builder workload model comparison benchmarks.
P-26.03: Verifier / witness workload model strategy comparison.
Documents benchmark methodology and metrics while enforcing Zero-Cost Law.
Live external benchmark evaluations remain strictly OPERATOR_AUTHORIZATION_REQUIRED / NOT_RUN
until authorized by the operator.
"""

from __future__ import annotations

from dataclasses import asdict, dataclass
from enum import Enum
from typing import Any


class BenchmarkExecutionMode(str, Enum):
    """Execution modality for benchmarks."""

    OFFLINE_FIXTURE = "OFFLINE_FIXTURE"
    LOCAL_EXECUTION = "LOCAL_EXECUTION"
    LIVE_EXTERNAL = "LIVE_EXTERNAL"


class BenchmarkStatus(str, Enum):
    """Status of a benchmark execution."""

    COMPLETED = "COMPLETED"
    OPERATOR_AUTHORIZATION_REQUIRED = "OPERATOR_AUTHORIZATION_REQUIRED"
    NOT_RUN = "NOT_RUN"


@dataclass(frozen=True, slots=True)
class BenchmarkRunResult:
    """Outcome metrics for a benchmark trial."""

    benchmark_id: str
    target_name: str
    mode: BenchmarkExecutionMode
    status: BenchmarkStatus
    metrics: dict[str, Any]
    notes: str = ""

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


class BuilderModelBenchmark:
    """Benchmark comparing candidate patch generation across LLM models (P-26.02).

    Metrics:
    - syntax_validity_rate: proportion of outputs parsing to valid Python AST
    - diff_well_formed_rate: proportion of unified diffs that parse cleanly
    - pass_at_1: proportion of candidates passing ordinary existing test suite
    - causal_witness_pass_rate: proportion of candidates passing the causal witness
    - avg_prompt_tokens / avg_completion_tokens
    - avg_latency_ms
    """

    SUPPORTED_MODELS = (
        "nvidia/llama-3.1-nemotron-70b-instruct",
        "meta-llama/llama-3.3-70b-instruct",
        "deepseek-ai/deepseek-r1",
    )

    @classmethod
    def run_offline_benchmark(
        cls,
        model_id: str,
        synthetic_evaluations: list[dict[str, Any]],
    ) -> BenchmarkRunResult:
        """Evaluate builder model performance using offline recorded/fixture trials."""
        if model_id not in cls.SUPPORTED_MODELS:
            raise ValueError(
                f"Unsupported model: {model_id}. Must be one of {cls.SUPPORTED_MODELS}"
            )

        total = len(synthetic_evaluations)
        if total == 0:
            return BenchmarkRunResult(
                benchmark_id="builder-workload-comparison",
                target_name=model_id,
                mode=BenchmarkExecutionMode.OFFLINE_FIXTURE,
                status=BenchmarkStatus.COMPLETED,
                metrics={"sample_count": 0},
                notes="No evaluation cases provided",
            )

        syntax_ok = sum(1 for e in synthetic_evaluations if e.get("valid_syntax", False))
        pass_at_1 = sum(1 for e in synthetic_evaluations if e.get("test_pass", False))
        causal_pass = sum(1 for e in synthetic_evaluations if e.get("causal_pass", False))
        total_prompt_tokens = sum(e.get("prompt_tokens", 0) for e in synthetic_evaluations)
        total_comp_tokens = sum(e.get("completion_tokens", 0) for e in synthetic_evaluations)
        total_latency = sum(e.get("latency_ms", 0.0) for e in synthetic_evaluations)

        metrics = {
            "sample_count": total,
            "syntax_validity_rate": round(syntax_ok / total, 3),
            "pass_at_1_rate": round(pass_at_1 / total, 3),
            "causal_witness_pass_rate": round(causal_pass / total, 3),
            "avg_prompt_tokens": round(total_prompt_tokens / total, 1),
            "avg_completion_tokens": round(total_comp_tokens / total, 1),
            "avg_latency_ms": round(total_latency / total, 1),
        }

        return BenchmarkRunResult(
            benchmark_id="builder-workload-comparison",
            target_name=model_id,
            mode=BenchmarkExecutionMode.OFFLINE_FIXTURE,
            status=BenchmarkStatus.COMPLETED,
            metrics=metrics,
            notes="Offline fixture benchmark",
        )

    @classmethod
    def get_live_benchmark_status(cls, model_id: str) -> BenchmarkRunResult:
        """Return factual status for live Nebius model benchmark (unauthorized -> NOT_RUN)."""
        return BenchmarkRunResult(
            benchmark_id="builder-workload-comparison",
            target_name=model_id,
            mode=BenchmarkExecutionMode.LIVE_EXTERNAL,
            status=BenchmarkStatus.OPERATOR_AUTHORIZATION_REQUIRED,
            metrics={},
            notes="Live execution held at OPERATOR_AUTHORIZATION_REQUIRED / NOT_RUN.",
        )


class VerifierStrategyBenchmark:
    """Benchmark comparing witness generation strategies (P-26.03).

    Strategies:
    - SINGLE_SHOT: generate witness in a single inference call
    - MULTI_TURN_REFLECTION: generate, analyze vacuity, refine witness if vacuous
    - TEMPLATE_GUIDED: constrain generation to verified invariant templates
    """

    STRATEGIES = ("SINGLE_SHOT", "MULTI_TURN_REFLECTION", "TEMPLATE_GUIDED")

    @classmethod
    def evaluate_strategy(
        cls,
        strategy_name: str,
        trials: list[dict[str, Any]],
    ) -> BenchmarkRunResult:
        """Evaluate verifier strategy against vacuity and counterfactual metrics."""
        if strategy_name not in cls.STRATEGIES:
            raise ValueError(f"Unknown strategy: {strategy_name}")

        total = len(trials)
        if total == 0:
            return BenchmarkRunResult(
                benchmark_id="verifier-strategy-comparison",
                target_name=strategy_name,
                mode=BenchmarkExecutionMode.OFFLINE_FIXTURE,
                status=BenchmarkStatus.COMPLETED,
                metrics={"sample_count": 0},
            )

        valid_witnesses = sum(1 for t in trials if t.get("vacuity_status") == "VALID")
        vacuous_count = sum(1 for t in trials if t.get("vacuity_status") != "VALID")
        counterfactual_sensitive = sum(1 for t in trials if t.get("counterfactual_failed", False))
        avg_assertions = sum(t.get("assertion_count", 0) for t in trials) / total

        metrics = {
            "sample_count": total,
            "valid_witness_rate": round(valid_witnesses / total, 3),
            "vacuity_rejection_rate": round(vacuous_count / total, 3),
            "counterfactual_sensitivity_rate": round(counterfactual_sensitive / total, 3),
            "avg_assertion_density": round(avg_assertions, 2),
        }

        return BenchmarkRunResult(
            benchmark_id="verifier-strategy-comparison",
            target_name=strategy_name,
            mode=BenchmarkExecutionMode.OFFLINE_FIXTURE,
            status=BenchmarkStatus.COMPLETED,
            metrics=metrics,
            notes=f"Evaluation of verifier strategy {strategy_name}",
        )
