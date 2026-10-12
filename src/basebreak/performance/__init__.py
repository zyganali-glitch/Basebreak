"""Basebreak Performance, Telemetry, and Model Routing Subsystem.

P-26: Performance, Cost & Model Routing.
- P-26.01: Latency, token, and sandbox cost measurement instrumentation.
- P-26.02: Builder workload model comparison benchmarks.
- P-26.03: Verifier / witness workload model strategy comparison.
- P-26.04: Model routing decision logic based strictly on measured facts.
- P-26.05: Causal verification overhead benchmark relative to baseline.
- P-26.06: Factual performance and cost limits documentation.
"""

from __future__ import annotations

from basebreak.performance.benchmarks import (
    BenchmarkRunResult,
    BuilderModelBenchmark,
    VerifierStrategyBenchmark,
)
from basebreak.performance.overhead import (
    CausalOverheadMetrics,
    compute_causal_overhead,
)
from basebreak.performance.router import (
    ModelRouteDecision,
    ModelRouter,
    WorkloadProfile,
)
from basebreak.performance.telemetry import (
    ExecutionTelemetry,
    PhaseLatencyRecord,
    TelemetryCollector,
)

__all__ = [
    "BenchmarkRunResult",
    "BuilderModelBenchmark",
    "CausalOverheadMetrics",
    "ExecutionTelemetry",
    "ModelRouteDecision",
    "ModelRouter",
    "PhaseLatencyRecord",
    "TelemetryCollector",
    "VerifierStrategyBenchmark",
    "WorkloadProfile",
    "compute_causal_overhead",
]
