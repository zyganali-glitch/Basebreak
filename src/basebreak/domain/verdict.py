"""Evidence provenance and preliminary verdict domain contracts.

Defines provider-neutral immutable abstractions separating WHERE/HOW evidence was
produced (provenance) from WHAT deterministic evaluation concluded (verdict).
"""

from __future__ import annotations

import math
from dataclasses import dataclass
from enum import Enum

from basebreak.domain.causal import CausalBinding


class EvidenceProvenance(str, Enum):
    """Provenance describing where and how evidence was produced.

    Answers WHERE/HOW evidence was produced.
    Exactly four values are recognized:
    - FIXTURE: Statically defined test fixture or benchmark artifact.
    - LOCAL_EXECUTION: Produced by local execution on the operator host.
    - LIVE_NEBIUS: Produced by live Nebius Token Factory inference or sandbox execution.
    - RECORDED_LIVE: Recorded from a prior real live execution, replayed without invocation.

    No aliases. No silent mapping. Provenance never implies verdict.
    """

    FIXTURE = "FIXTURE"
    LOCAL_EXECUTION = "LOCAL_EXECUTION"
    LIVE_NEBIUS = "LIVE_NEBIUS"
    RECORDED_LIVE = "RECORDED_LIVE"


class PreliminaryVerdict(str, Enum):
    """Deterministic preliminary verdict concluded by evaluation against a witness.

    Answers WHAT deterministic evaluation concluded.
    Exactly six values are recognized:
    - VERIFIED: Invariants deterministically proven under the executed witness.
    - PARTIALLY_VERIFIED: Some but not all required invariants were satisfied.
    - CONTRADICTED: Direct evidence contradicts the required invariant.
    - INCONCLUSIVE: Evidence is contradictory, indeterminate, or degraded without clear failure.
    - NOT_RUN: Execution was not performed. NOT_RUN must never be treated as VERIFIED.
    - BLOCKED: Execution could not proceed due to an explicit unmet prerequisite.

    Verdict never implies provenance. Model confidence scores cannot override verdicts.
    """

    VERIFIED = "VERIFIED"
    PARTIALLY_VERIFIED = "PARTIALLY_VERIFIED"
    CONTRADICTED = "CONTRADICTED"
    INCONCLUSIVE = "INCONCLUSIVE"
    NOT_RUN = "NOT_RUN"
    BLOCKED = "BLOCKED"


def _validate_identifier(value: str, field_name: str) -> None:
    """Validate a non-empty stripped identifier string."""
    if not isinstance(value, str):
        tname = type(value).__name__
        raise TypeError(f"{field_name} must be a string, got {tname}")
    cleaned = value.strip()
    if not cleaned:
        raise ValueError(f"{field_name} must not be empty")
    if cleaned != value:
        raise ValueError(f"{field_name} must not contain leading or trailing whitespace")


@dataclass(frozen=True, slots=True)
class PreliminaryVerdictRecord:
    """Immutable record binding a deterministic preliminary verdict with its evidence provenance.

    Maintains separation between WHERE/HOW evidence was produced (provenance) and WHAT
    evaluation concluded (verdict). Model prose or confidence scores cannot override
    the deterministic verdict.
    """

    verdict: PreliminaryVerdict
    provenance: EvidenceProvenance
    requirement_id: str
    causal_binding: CausalBinding | None = None
    narrative: str = ""
    model_confidence: float | None = None

    def __post_init__(self) -> None:
        if not isinstance(self.verdict, PreliminaryVerdict):
            tname = type(self.verdict).__name__
            raise TypeError(f"verdict must be an instance of PreliminaryVerdict, got {tname}")
        if not isinstance(self.provenance, EvidenceProvenance):
            tname = type(self.provenance).__name__
            raise TypeError(f"provenance must be an instance of EvidenceProvenance, got {tname}")

        _validate_identifier(self.requirement_id, "requirement_id")

        if self.causal_binding is not None:
            if not isinstance(self.causal_binding, CausalBinding):
                tname = type(self.causal_binding).__name__
                raise TypeError(f"causal_binding must be CausalBinding or None, got {tname}")
            if self.causal_binding.requirement_id != self.requirement_id:
                raise ValueError(
                    f"causal_binding.requirement_id ({self.causal_binding.requirement_id!r}) "
                    f"does not match requirement_id ({self.requirement_id!r})"
                )

        if not isinstance(self.narrative, str):
            tname = type(self.narrative).__name__
            raise TypeError(f"narrative must be a string, got {tname}")

        if self.model_confidence is not None:
            if isinstance(self.model_confidence, bool) or not isinstance(
                self.model_confidence, (int, float)
            ):
                tname = type(self.model_confidence).__name__
                raise TypeError(f"model_confidence must be a number or None, got {tname}")
            if not math.isfinite(self.model_confidence):
                raise ValueError("model_confidence must be a finite number")
            if not (0.0 <= self.model_confidence <= 1.0):
                raise ValueError("model_confidence must be between 0.0 and 1.0 inclusive")

    @property
    def is_verified(self) -> bool:
        """True strictly when the deterministic verdict is VERIFIED.

        Model confidence or narrative prose cannot cause this to return True.
        """
        return self.verdict == PreliminaryVerdict.VERIFIED

    @property
    def is_blocked(self) -> bool:
        """True strictly when the verdict is BLOCKED."""
        return self.verdict == PreliminaryVerdict.BLOCKED

    @property
    def is_not_run(self) -> bool:
        """True strictly when the verdict is NOT_RUN."""
        return self.verdict == PreliminaryVerdict.NOT_RUN

    @property
    def is_contradicted(self) -> bool:
        """True strictly when the verdict is CONTRADICTED."""
        return self.verdict == PreliminaryVerdict.CONTRADICTED

    @property
    def is_live(self) -> bool:
        """True strictly when evidence was produced via LIVE_NEBIUS."""
        return self.provenance == EvidenceProvenance.LIVE_NEBIUS

    def __str__(self) -> str:
        return f"[{self.provenance.value}] {self.requirement_id}: {self.verdict.value}"
