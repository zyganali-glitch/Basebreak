"""Causal verification overhead benchmarks and metrics.

P-26.05: Causal verification overhead benchmark relative to baseline.
Measures the computational and latency multiplier of full 3-world causal verification
(BASE + CANDIDATE + COUNTERFACTUAL + RECONCILIATION) relative to traditional single-run CI
using provided execution timings (measured locally or derived from sandbox metrics).
Does NOT represent unverified live cloud claims.
"""

from __future__ import annotations

from dataclasses import asdict, dataclass
from typing import Any


@dataclass(frozen=True, slots=True)
class CausalOverheadMetrics:
    """Quantitative comparison of causal verification versus standard baseline CI."""

    baseline_ci_ms: float
    causal_verification_ms: float
    overhead_multiplier: float
    contract_freeze_ms: float
    base_execution_ms: float
    candidate_execution_ms: float
    counterfactual_execution_ms: float
    reconciliation_ms: float
    has_counterfactual: bool
    causal_break_proven: bool
    vacuous_pass_detected: bool

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


def compute_causal_overhead(
    *,
    baseline_ci_ms: float,
    contract_freeze_ms: float,
    base_execution_ms: float,
    candidate_execution_ms: float,
    counterfactual_execution_ms: float = 0.0,
    reconciliation_ms: float = 5.0,
    causal_break_proven: bool = True,
    vacuous_pass_detected: bool = False,
) -> CausalOverheadMetrics:
    """Calculate the overhead multiplier of causal verification over standard CI.

    Args:
        baseline_ci_ms: Wall-clock time for standard single-pass test run.
        contract_freeze_ms: Time spent compiling and freezing acceptance contract.
        base_execution_ms: Time spent executing witness against unmodified BASE.
        candidate_execution_ms: Time spent executing witness against CANDIDATE.
        counterfactual_execution_ms: Time spent on counterfactual delta execution.
        reconciliation_ms: Time spent reconciling facts and generating signed receipt.
        causal_break_proven: Whether BASE=FAIL was deterministically verified.
        vacuous_pass_detected: Whether AST vacuity check caught an unasserted pass.

    Returns:
        CausalOverheadMetrics recording the precise overhead multiplier and guarantees.
    """
    total_causal_ms = (
        contract_freeze_ms
        + base_execution_ms
        + candidate_execution_ms
        + counterfactual_execution_ms
        + reconciliation_ms
    )

    clean_baseline = max(1.0, baseline_ci_ms)
    multiplier = round(total_causal_ms / clean_baseline, 2)

    return CausalOverheadMetrics(
        baseline_ci_ms=round(baseline_ci_ms, 2),
        causal_verification_ms=round(total_causal_ms, 2),
        overhead_multiplier=multiplier,
        contract_freeze_ms=round(contract_freeze_ms, 2),
        base_execution_ms=round(base_execution_ms, 2),
        candidate_execution_ms=round(candidate_execution_ms, 2),
        counterfactual_execution_ms=round(counterfactual_execution_ms, 2),
        reconciliation_ms=round(reconciliation_ms, 2),
        has_counterfactual=counterfactual_execution_ms > 0.0,
        causal_break_proven=causal_break_proven,
        vacuous_pass_detected=vacuous_pass_detected,
    )
