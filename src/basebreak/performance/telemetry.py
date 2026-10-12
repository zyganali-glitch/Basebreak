"""Latency, token, and sandbox cost measurement instrumentation.

P-26.01: Latency, token, and sandbox cost measurement instrumentation.
Tracks wall-clock latency per phase, token counts (prompt, completion, cached),
sandbox execution durations, and estimated costs while enforcing honest zero-cost reporting.
"""

from __future__ import annotations

import time
from dataclasses import asdict, dataclass
from datetime import datetime, timezone
from typing import Any


@dataclass(frozen=True, slots=True)
class PhaseLatencyRecord:
    """Measurement record for a discrete pipeline execution phase."""

    phase_name: str
    duration_ms: float
    start_time_iso: str
    end_time_iso: str

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


@dataclass(frozen=True, slots=True)
class ExecutionTelemetry:
    """Comprehensive resource, timing, and cost snapshot for a verification run."""

    run_id: str
    total_wall_clock_ms: float
    phases: tuple[PhaseLatencyRecord, ...]
    prompt_tokens: int = 0
    completion_tokens: int = 0
    cached_tokens: int = 0
    total_tokens: int = 0
    sandbox_duration_seconds: float = 0.0
    sandbox_count: int = 0
    estimated_inference_cost_usd: float = 0.0
    estimated_sandbox_cost_usd: float = 0.0
    total_estimated_cost_usd: float = 0.0
    is_verified_zero_cost: bool = True

    def to_dict(self) -> dict[str, Any]:
        d = asdict(self)
        d["phases"] = [p.to_dict() for p in self.phases]
        return d


class TelemetryCollector:
    """Gathers timing, token consumption, and sandbox metrics across execution phases."""

    def __init__(self, run_id: str, *, is_verified_zero_cost: bool = True) -> None:
        self.run_id = run_id
        self.is_verified_zero_cost = is_verified_zero_cost
        self._start_perf = time.perf_counter()
        self._phases: list[PhaseLatencyRecord] = []
        self._open_phase_starts: dict[str, tuple[float, str]] = {}
        self._prompt_tokens: int = 0
        self._completion_tokens: int = 0
        self._cached_tokens: int = 0
        self._sandbox_duration_seconds: float = 0.0
        self._sandbox_count: int = 0
        self._estimated_inference_cost_usd: float = 0.0
        self._estimated_sandbox_cost_usd: float = 0.0

    def start_phase(self, phase_name: str) -> None:
        """Begin measuring latency for a named execution phase."""
        now_perf = time.perf_counter()
        now_iso = datetime.now(timezone.utc).isoformat()
        self._open_phase_starts[phase_name] = (now_perf, now_iso)

    def stop_phase(self, phase_name: str) -> PhaseLatencyRecord:
        """Complete measurement for a named phase and record its duration."""
        now_perf = time.perf_counter()
        now_iso = datetime.now(timezone.utc).isoformat()

        if phase_name not in self._open_phase_starts:
            # Fallback for unstarted phase: record as instantaneous
            rec = PhaseLatencyRecord(
                phase_name=phase_name,
                duration_ms=0.0,
                start_time_iso=now_iso,
                end_time_iso=now_iso,
            )
            self._phases.append(rec)
            return rec

        start_perf, start_iso = self._open_phase_starts.pop(phase_name)
        duration_ms = max(0.0, (now_perf - start_perf) * 1000.0)
        rec = PhaseLatencyRecord(
            phase_name=phase_name,
            duration_ms=round(duration_ms, 2),
            start_time_iso=start_iso,
            end_time_iso=now_iso,
        )
        self._phases.append(rec)
        return rec

    def record_tokens(
        self,
        prompt_tokens: int,
        completion_tokens: int,
        cached_tokens: int = 0,
        estimated_cost_usd: float = 0.0,
    ) -> None:
        """Accumulate token counts and estimated inference cost."""
        self._prompt_tokens += max(0, prompt_tokens)
        self._completion_tokens += max(0, completion_tokens)
        self._cached_tokens += max(0, cached_tokens)
        self._estimated_inference_cost_usd += max(0.0, estimated_cost_usd)

    def record_sandbox(
        self,
        duration_seconds: float,
        count: int = 1,
        estimated_cost_usd: float = 0.0,
    ) -> None:
        """Accumulate sandbox container runtime and instance counts."""
        self._sandbox_duration_seconds += max(0.0, duration_seconds)
        self._sandbox_count += max(0, count)
        self._estimated_sandbox_cost_usd += max(0.0, estimated_cost_usd)

    def finalize(self) -> ExecutionTelemetry:
        """Produce finalized execution telemetry record."""
        total_wall_clock_ms = round(max(0.0, (time.perf_counter() - self._start_perf) * 1000.0), 2)
        total_tokens = self._prompt_tokens + self._completion_tokens
        total_cost = self._estimated_inference_cost_usd + self._estimated_sandbox_cost_usd

        return ExecutionTelemetry(
            run_id=self.run_id,
            total_wall_clock_ms=total_wall_clock_ms,
            phases=tuple(self._phases),
            prompt_tokens=self._prompt_tokens,
            completion_tokens=self._completion_tokens,
            cached_tokens=self._cached_tokens,
            total_tokens=total_tokens,
            sandbox_duration_seconds=round(self._sandbox_duration_seconds, 2),
            sandbox_count=self._sandbox_count,
            estimated_inference_cost_usd=round(self._estimated_inference_cost_usd, 6),
            estimated_sandbox_cost_usd=round(self._estimated_sandbox_cost_usd, 6),
            total_estimated_cost_usd=round(total_cost, 6),
            is_verified_zero_cost=self.is_verified_zero_cost,
        )
