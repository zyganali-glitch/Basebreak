"""Change semantics enum and per-class verification requirement domain contracts.

Defines the exact six canonical change classes and their deterministic
verification requirements according to Basebreak causal verification laws.
"""

from __future__ import annotations

from dataclasses import dataclass
from enum import Enum


class ChangeClass(str, Enum):
    """Canonical change classes recognized by Basebreak.

    Exactly six classes are supported. No aliases or silent additions are permitted.
    """

    BUG_FIX = "BUG_FIX"
    FEATURE = "FEATURE"
    SECURITY_FIX = "SECURITY_FIX"
    REFACTOR = "REFACTOR"
    PERFORMANCE = "PERFORMANCE"
    DEP_API_CHANGE = "DEP_API_CHANGE"


@dataclass(frozen=True, slots=True)
class ClassVerificationRequirement:
    """Deterministic verification requirement for a specific change class.

    Specifies what the BASE world must exhibit, what the CANDIDATE world must
    satisfy, and whether additional dimensions (e.g. behavioral equivalence,
    measured performance delta, or regression safety) are required.
    """

    change_class: ChangeClass
    base_expectation: str
    candidate_expectation: str
    requires_equivalence: bool = False
    requires_measured_delta: bool = False
    requires_regression_safety: bool = False
    description: str = ""

    def __post_init__(self) -> None:
        if not isinstance(self.change_class, ChangeClass):
            tname = type(self.change_class).__name__
            raise TypeError(f"change_class must be an instance of ChangeClass, got {tname}")
        if not self.base_expectation or not self.base_expectation.strip():
            raise ValueError("base_expectation must be a non-empty string")
        if not self.candidate_expectation or not self.candidate_expectation.strip():
            raise ValueError("candidate_expectation must be a non-empty string")


# Deterministic per-class verification requirement specifications
_REQUIREMENTS_MAP: dict[ChangeClass, ClassVerificationRequirement] = {
    ChangeClass.BUG_FIX: ClassVerificationRequirement(
        change_class=ChangeClass.BUG_FIX,
        base_expectation="FAIL",
        candidate_expectation="PASS",
        description="BASE exhibits required failure/defect; CANDIDATE satisfies required behavior.",
    ),
    ChangeClass.FEATURE: ClassVerificationRequirement(
        change_class=ChangeClass.FEATURE,
        base_expectation="ABSENT",
        candidate_expectation="PRESENT",
        description="Required capability is ABSENT on BASE; PRESENT on CANDIDATE.",
    ),
    ChangeClass.SECURITY_FIX: ClassVerificationRequirement(
        change_class=ChangeClass.SECURITY_FIX,
        base_expectation="EXPLOITABLE",
        candidate_expectation="BLOCKED",
        description=(
            "BASE is EXPLOITABLE under the accepted witness; "
            "CANDIDATE is BLOCKED / NOT EXPLOITABLE under that witness."
        ),
    ),
    ChangeClass.REFACTOR: ClassVerificationRequirement(
        change_class=ChangeClass.REFACTOR,
        base_expectation="EQUIVALENT",
        candidate_expectation="EQUIVALENT",
        requires_equivalence=True,
        description=(
            "Externally relevant BEFORE behavior is equivalent to AFTER behavior "
            "under the accepted contract."
        ),
    ),
    ChangeClass.PERFORMANCE: ClassVerificationRequirement(
        change_class=ChangeClass.PERFORMANCE,
        base_expectation="PARITY",
        candidate_expectation="PARITY",
        requires_measured_delta=True,
        description=(
            "Correctness/parity requirement remains satisfied; "
            "measured performance delta is required without an arbitrary threshold."
        ),
    ),
    ChangeClass.DEP_API_CHANGE: ClassVerificationRequirement(
        change_class=ChangeClass.DEP_API_CHANGE,
        base_expectation="BASELINE",
        candidate_expectation="NEW_CONTRACT_SATISFIED",
        requires_regression_safety=True,
        description=(
            "New contract must be satisfied; regression safety must be represented separately."
        ),
    ),
}


def get_verification_requirements(
    change_class: ChangeClass,
) -> ClassVerificationRequirement:
    """Get the deterministic verification requirements for a canonical change class."""
    if not isinstance(change_class, ChangeClass):
        tname = type(change_class).__name__
        raise TypeError(f"Expected ChangeClass enum, got {tname}")
    return _REQUIREMENTS_MAP[change_class]
