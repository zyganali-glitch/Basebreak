"""Evidence provenance validation and forbidden state transition enforcement.

Implements provider-neutral deterministic verification that evidence provenance
is an immutable factual property, preventing provenance laundering, silent upgrades,
and conflation of historical recordings with current live execution.
"""

from __future__ import annotations

from basebreak.domain.verdict import EvidenceProvenance, PreliminaryVerdict
from basebreak.evidence.append_model import (
    EvidenceError,
    EvidenceIdentity,
    EvidenceRecord,
)


class ProvenanceTransitionError(EvidenceError):
    """Raised when an illegal or forbidden provenance transition or derivation is attempted."""


class ProvenanceLaunderingError(ProvenanceTransitionError):
    """Raised when attempting to upgrade or reclassify provenance to a higher authority level."""


def validate_provenance_transition(
    source_provenance: EvidenceProvenance,
    target_provenance: EvidenceProvenance,
) -> None:
    """Validate whether an in-place or same-fact provenance transition is allowed.

    In Basebreak, evidence provenance is an immutable deterministic fact.
    Any direct transition or relabeling from one provenance to a different provenance
    is forbidden (provenance laundering).
    """
    if not isinstance(source_provenance, EvidenceProvenance):
        raise TypeError(
            f"source_provenance must be EvidenceProvenance, got {type(source_provenance).__name__}"
        )
    if not isinstance(target_provenance, EvidenceProvenance):
        raise TypeError(
            f"target_provenance must be EvidenceProvenance, got {type(target_provenance).__name__}"
        )
    if source_provenance != target_provenance:
        raise ProvenanceLaunderingError(
            f"Forbidden provenance transition: cannot transform '{source_provenance.value}' "
            f"into '{target_provenance.value}'. Provenance is an immutable factual property."
        )


def validate_provenance_derivation(
    source_provenance: EvidenceProvenance,
    derived_provenance: EvidenceProvenance,
    source_id: EvidenceIdentity,
    derived_id: EvidenceIdentity,
) -> None:
    """Validate derivation of evidence from a source record.

    Ensures:
    - derived evidence receives a distinct EvidenceIdentity;
    - provenance cannot be laundered/upgraded (e.g. FIXTURE cannot derive LIVE_NEBIUS,
      LOCAL_EXECUTION cannot derive LIVE_NEBIUS, RECORDED_LIVE cannot derive LIVE_NEBIUS);
    - provenance hierarchy is strictly non-upgrading.
    """
    if not isinstance(source_id, EvidenceIdentity):
        raise TypeError(f"source_id must be EvidenceIdentity, got {type(source_id).__name__}")
    if not isinstance(derived_id, EvidenceIdentity):
        raise TypeError(f"derived_id must be EvidenceIdentity, got {type(derived_id).__name__}")
    if source_id == derived_id:
        raise ProvenanceTransitionError(
            f"Derived evidence cannot reuse source evidence_id '{source_id.evidence_id}'"
        )
    if not isinstance(source_provenance, EvidenceProvenance):
        raise TypeError(
            f"source_provenance must be EvidenceProvenance, got {type(source_provenance).__name__}"
        )
    if not isinstance(derived_provenance, EvidenceProvenance):
        tname = type(derived_provenance).__name__
        raise TypeError(f"derived_provenance must be EvidenceProvenance, got {tname}")

    # FIXTURE can never derive non-FIXTURE
    if (
        source_provenance == EvidenceProvenance.FIXTURE
        and derived_provenance != EvidenceProvenance.FIXTURE
    ):
        raise ProvenanceLaunderingError(
            f"Cannot derive '{derived_provenance.value}' from FIXTURE source. "
            "Fixture-derived facts remain FIXTURE."
        )

    # LIVE_NEBIUS can only come from live execution, never derived from non-live
    if (
        derived_provenance == EvidenceProvenance.LIVE_NEBIUS
        and source_provenance != EvidenceProvenance.LIVE_NEBIUS
    ):
        raise ProvenanceLaunderingError(
            f"Cannot derive LIVE_NEBIUS from non-live source '{source_provenance.value}'. "
            "LIVE_NEBIUS requires fresh live platform execution."
        )

    # RECORDED_LIVE cannot be derived from FIXTURE or LOCAL_EXECUTION
    if derived_provenance == EvidenceProvenance.RECORDED_LIVE and source_provenance in (
        EvidenceProvenance.FIXTURE,
        EvidenceProvenance.LOCAL_EXECUTION,
    ):
        raise ProvenanceLaunderingError(
            f"Cannot derive RECORDED_LIVE from '{source_provenance.value}'. "
            "RECORDED_LIVE requires recorded historical live execution."
        )


def is_live_execution(provenance: EvidenceProvenance) -> bool:
    """Return True strictly if provenance represents an active live Nebius execution.

    RECORDED_LIVE is NOT live execution; it is historical recorded replay.
    Only LIVE_NEBIUS returns True.
    """
    if not isinstance(provenance, EvidenceProvenance):
        raise TypeError(f"provenance must be EvidenceProvenance, got {type(provenance).__name__}")
    return provenance == EvidenceProvenance.LIVE_NEBIUS


def is_recorded_live(provenance: EvidenceProvenance) -> bool:
    """Return True if provenance represents recorded historical live execution."""
    if not isinstance(provenance, EvidenceProvenance):
        raise TypeError(f"provenance must be EvidenceProvenance, got {type(provenance).__name__}")
    return provenance == EvidenceProvenance.RECORDED_LIVE


def has_execution_result(record: EvidenceRecord) -> bool:
    """Return True if an evidence record contains an execution result."""
    if not isinstance(record, EvidenceRecord):
        raise TypeError(f"record must be EvidenceRecord, got {type(record).__name__}")
    return record.result is not None


def is_successful_execution(record: EvidenceRecord) -> bool:
    """Determine if an evidence record represents a successfully executed command.

    Returns True only when an ExecutionResult is present, status is COMPLETED,
    and exit_code == 0.
    result=None returns False.
    """
    if not isinstance(record, EvidenceRecord):
        raise TypeError(f"record must be EvidenceRecord, got {type(record).__name__}")
    if record.result is None:
        return False
    return record.result.is_completed and record.result.exit_code == 0


def assert_provenance_not_verdict(
    provenance: EvidenceProvenance,
    verdict: PreliminaryVerdict,
) -> None:
    """Validate that provenance does not imply or dictate a verdict.

    Provenance describes WHERE/HOW evidence was produced.
    Verdict describes WHAT evaluation concluded.
    They are orthogonal deterministic facts.
    """
    if not isinstance(provenance, EvidenceProvenance):
        raise TypeError(f"provenance must be EvidenceProvenance, got {type(provenance).__name__}")
    if not isinstance(verdict, PreliminaryVerdict):
        raise TypeError(f"verdict must be PreliminaryVerdict, got {type(verdict).__name__}")
