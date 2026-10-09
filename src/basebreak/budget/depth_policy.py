"""Deterministic risk-adaptive verification depth mapping.

P-15.02: Map low/medium/high risk to verification depth under the
Basebreak causal verification authority model.

Authority Model & Invariants:
1. Basebreak Causal Invariant:
   BASE_EXECUTION and CANDIDATE_EXECUTION are strictly MANDATORY for all change classes
   across all risk levels. Ordinary green tests alone never constitute causal evidence.
2. Risk Monotonicity:
   HIGH risk never receives weaker verification than MEDIUM or LOW risk for the same contract.
   The mandatory actions of LOW are a subset of MEDIUM, which are a subset of HIGH.
3. Separation of Concerns:
   - Mandatory verification obligations: required for any PASS verdict.
   - Budget-dependent work: executed if budget permits; if skipped, documented honestly.
   - Optional additional confidence checks: non-essential enhancement.
   - Explicitly skipped checks: inspectable record with clear rationale.
4. Semantic Preservation:
   Does not silently downgrade or alter change semantics or frozen contract obligations.
5. Deterministic, inspectable, and reproducible depth records with SHA-256 digests.
"""

from __future__ import annotations

import hashlib
import re
from collections.abc import Mapping
from dataclasses import dataclass
from enum import Enum
from typing import Any

from basebreak.budget.risk_features import (
    RiskClassification,
    RiskFeatureError,
    RiskLevel,
    canonical_risk_bytes,
    verify_risk_classification_integrity,
)
from basebreak.compiler.semantics import ChangeClass

DEPTH_POLICY_SCHEMA_VERSION: str = "1.0.0"

_DIGEST_PATTERN = re.compile(r"^[0-9a-f]{64}$")


class VerificationAction(str, Enum):
    """Canonical verification action types recognized by Basebreak."""

    BASE_EXECUTION = "BASE_EXECUTION"
    CANDIDATE_EXECUTION = "CANDIDATE_EXECUTION"
    COUNTERFACTUAL_EXECUTION = "COUNTERFACTUAL_EXECUTION"
    CAUSAL_SLICING = "CAUSAL_SLICING"
    REGRESSION_SUITE_EXECUTION = "REGRESSION_SUITE_EXECUTION"
    EQUIVALENCE_VERIFICATION = "EQUIVALENCE_VERIFICATION"
    PERFORMANCE_MEASUREMENT = "PERFORMANCE_MEASUREMENT"
    DEPENDENCY_MIGRATION_CHECK = "DEPENDENCY_MIGRATION_CHECK"


class DepthPolicyError(Exception):
    """Base exception for depth policy errors."""


class InvalidDepthPolicyError(DepthPolicyError):
    """Raised when depth policy input or state is invalid."""


class DepthPolicyTamperingError(DepthPolicyError):
    """Raised when verification depth record fails integrity verification."""


@dataclass(frozen=True, slots=True)
class SkippedCheckRecord:
    """Deterministic record of an intentionally skipped optional check."""

    action: VerificationAction
    reason: str

    def __post_init__(self) -> None:
        if not isinstance(self.action, VerificationAction):
            raise InvalidDepthPolicyError(
                f"action must be VerificationAction, got {type(self.action).__name__}"
            )
        if not self.reason or not self.reason.strip():
            raise InvalidDepthPolicyError("reason must be a non-empty string")

    def to_dict(self) -> dict[str, str]:
        return {"action": self.action.value, "reason": self.reason}


@dataclass(frozen=True, slots=True)
class VerificationDepth:
    """Deterministic verification depth specification mapped from risk classification."""

    schema_version: str
    risk_level: RiskLevel
    change_class: ChangeClass
    depth_name: str
    mandatory_actions: tuple[VerificationAction, ...]
    optional_actions: tuple[VerificationAction, ...]
    budget_dependent_actions: tuple[VerificationAction, ...]
    skipped_optional_checks: tuple[SkippedCheckRecord, ...]
    min_sandboxes_required: int
    min_verifier_executions_required: int
    rationale: str
    depth_digest: str

    def __post_init__(self) -> None:
        if self.schema_version != DEPTH_POLICY_SCHEMA_VERSION:
            exp = DEPTH_POLICY_SCHEMA_VERSION
            raise InvalidDepthPolicyError(
                f"Unsupported schema_version {self.schema_version!r}, expected {exp!r}"
            )
        if not isinstance(self.risk_level, RiskLevel):
            raise InvalidDepthPolicyError(
                f"risk_level must be RiskLevel, got {type(self.risk_level).__name__}"
            )
        if not isinstance(self.change_class, ChangeClass):
            raise InvalidDepthPolicyError(
                f"change_class must be ChangeClass, got {type(self.change_class).__name__}"
            )
        if not self.depth_name or not self.depth_name.strip():
            raise InvalidDepthPolicyError("depth_name must be a non-empty string")

        # Invariant: BASE and CANDIDATE are strictly mandatory
        if VerificationAction.BASE_EXECUTION not in self.mandatory_actions:
            raise InvalidDepthPolicyError("BASE_EXECUTION is strictly mandatory across all depths")
        if VerificationAction.CANDIDATE_EXECUTION not in self.mandatory_actions:
            raise InvalidDepthPolicyError(
                "CANDIDATE_EXECUTION is strictly mandatory across all depths"
            )

        # Invariant: Minimum resource bounds
        if self.min_sandboxes_required < 2:
            raise InvalidDepthPolicyError("min_sandboxes_required must be >= 2 (BASE + CANDIDATE)")
        if self.min_verifier_executions_required < 2:
            raise InvalidDepthPolicyError("min_verifier_executions_required must be >= 2")

        if not _DIGEST_PATTERN.match(self.depth_digest):
            raise InvalidDepthPolicyError(
                f"depth_digest must be a 64-char lowercase hex string, got {self.depth_digest!r}"
            )

    def to_dict(self) -> dict[str, Any]:
        """Serialize verification depth to deterministic dictionary."""
        return {
            "budget_dependent_actions": [a.value for a in self.budget_dependent_actions],
            "change_class": self.change_class.value,
            "depth_digest": self.depth_digest,
            "depth_name": self.depth_name,
            "mandatory_actions": [a.value for a in self.mandatory_actions],
            "min_sandboxes_required": self.min_sandboxes_required,
            "min_verifier_executions_required": self.min_verifier_executions_required,
            "optional_actions": [a.value for a in self.optional_actions],
            "rationale": self.rationale,
            "risk_level": self.risk_level.value,
            "schema_version": self.schema_version,
            "skipped_optional_checks": [c.to_dict() for c in self.skipped_optional_checks],
        }


def compute_depth_digest(payload: Mapping[str, Any]) -> str:
    """Compute SHA-256 digest over canonical payload excluding depth_digest."""
    clean = {k: v for k, v in payload.items() if k != "depth_digest"}
    return hashlib.sha256(canonical_risk_bytes(clean)).hexdigest()


def resolve_verification_depth(
    classification: RiskClassification,
    *,
    allow_optional_checks: bool = True,
) -> VerificationDepth:
    """Deterministically map RiskClassification to VerificationDepth.

    Policy Matrix:
    - ALL CLASSES & ALL TIERS:
      BASE_EXECUTION and CANDIDATE_EXECUTION are MANDATORY.
    - CLASS-SPECIFIC MANDATORY ACTIONS:
      REFACTOR -> EQUIVALENCE_VERIFICATION
      PERFORMANCE -> PERFORMANCE_MEASUREMENT
      DEP_API_CHANGE -> DEPENDENCY_MIGRATION_CHECK
    - RISK SCALING:
      LOW:
        Mandatory: Base + Candidate + Semantic-specific
        Budget-dependent: CAUSAL_SLICING
        Optional: COUNTERFACTUAL_EXECUTION
        min_sandboxes: 2, min_verifier_executions: 2
      MEDIUM:
        Mandatory: LOW mandatory actions +
          (for BUG_FIX / SECURITY_FIX: COUNTERFACTUAL_EXECUTION)
        Budget-dependent: CAUSAL_SLICING, REGRESSION_SUITE_EXECUTION
        min_sandboxes: 3, min_verifier_executions: 3
      HIGH:
        Mandatory: MEDIUM mandatory actions + REGRESSION_SUITE_EXECUTION +
          (for multi-file or security fixes: CAUSAL_SLICING)
        Budget-dependent: deep slicing
        min_sandboxes: 4, min_verifier_executions: 4
    """
    if not isinstance(classification, RiskClassification):
        raise InvalidDepthPolicyError(
            f"classification must be RiskClassification, got {type(classification).__name__}"
        )

    try:
        verify_risk_classification_integrity(classification)
    except RiskFeatureError as exc:
        raise DepthPolicyTamperingError(
            f"Risk classification integrity verification failed: {exc}"
        ) from exc

    risk_level = classification.risk_level
    change_class = classification.features.change_class

    mandatory: list[VerificationAction] = [
        VerificationAction.BASE_EXECUTION,
        VerificationAction.CANDIDATE_EXECUTION,
    ]
    budget_dep: list[VerificationAction] = []
    optional: list[VerificationAction] = []
    skipped: list[SkippedCheckRecord] = []

    # Semantic-specific additions
    match change_class:
        case ChangeClass.REFACTOR:
            mandatory.append(VerificationAction.EQUIVALENCE_VERIFICATION)
        case ChangeClass.PERFORMANCE:
            mandatory.append(VerificationAction.PERFORMANCE_MEASUREMENT)
        case ChangeClass.DEP_API_CHANGE:
            mandatory.append(VerificationAction.DEPENDENCY_MIGRATION_CHECK)
        case _:
            pass

    match risk_level:
        case RiskLevel.LOW:
            depth_name = "MINIMAL_CAUSAL"
            min_sandboxes = 2
            min_executions = 2
            rationale = (
                f"Low risk {change_class.value}: requires mandatory two-world verification "
                "with optional counterfactual and budget-dependent slicing."
            )
            if allow_optional_checks:
                optional.append(VerificationAction.COUNTERFACTUAL_EXECUTION)
            else:
                skipped.append(
                    SkippedCheckRecord(
                        action=VerificationAction.COUNTERFACTUAL_EXECUTION,
                        reason="Skipped in low-risk mode to conserve budget",
                    )
                )
            budget_dep.append(VerificationAction.CAUSAL_SLICING)

        case RiskLevel.MEDIUM:
            depth_name = "STANDARD_CAUSAL"
            min_sandboxes = 3
            min_executions = 3
            rationale = (
                f"Medium risk {change_class.value}: elevates counterfactual execution "
                "for behavioral defects and requires budget-dependent slicing and checks."
            )
            # In medium risk, behavioral fixes require counterfactual witness
            if change_class in (ChangeClass.BUG_FIX, ChangeClass.SECURITY_FIX):
                mandatory.append(VerificationAction.COUNTERFACTUAL_EXECUTION)
            else:
                budget_dep.append(VerificationAction.COUNTERFACTUAL_EXECUTION)

            budget_dep.append(VerificationAction.CAUSAL_SLICING)
            budget_dep.append(VerificationAction.REGRESSION_SUITE_EXECUTION)

        case RiskLevel.HIGH:
            depth_name = "DEEP_CAUSAL"
            min_sandboxes = 4
            min_executions = 4
            rationale = (
                f"High risk {change_class.value}: mandates full triplet verification, "
                "regression suite safety, and causal slice validation."
            )
            # High risk mandates counterfactual execution across behavioral and security fixes
            if VerificationAction.COUNTERFACTUAL_EXECUTION not in mandatory:
                mandatory.append(VerificationAction.COUNTERFACTUAL_EXECUTION)

            # High risk mandates regression suite execution
            if VerificationAction.REGRESSION_SUITE_EXECUTION not in mandatory:
                mandatory.append(VerificationAction.REGRESSION_SUITE_EXECUTION)

            # If multi-file or security fix, causal slicing is also mandatory
            if (
                classification.features.changed_files_count > 1
                or change_class == ChangeClass.SECURITY_FIX
                or bool(classification.features.touched_protected_surfaces)
            ):
                if VerificationAction.CAUSAL_SLICING not in mandatory:
                    mandatory.append(VerificationAction.CAUSAL_SLICING)
            else:
                budget_dep.append(VerificationAction.CAUSAL_SLICING)

    # Deterministic tuple construction
    mandatory_tuple = tuple(mandatory)
    budget_dep_tuple = tuple(budget_dep)
    optional_tuple = tuple(optional)
    skipped_tuple = tuple(skipped)

    raw_payload: dict[str, Any] = {
        "budget_dependent_actions": [a.value for a in budget_dep_tuple],
        "change_class": change_class.value,
        "depth_name": depth_name,
        "mandatory_actions": [a.value for a in mandatory_tuple],
        "min_sandboxes_required": min_sandboxes,
        "min_verifier_executions_required": min_executions,
        "optional_actions": [a.value for a in optional_tuple],
        "rationale": rationale,
        "risk_level": risk_level.value,
        "schema_version": DEPTH_POLICY_SCHEMA_VERSION,
        "skipped_optional_checks": [c.to_dict() for c in skipped_tuple],
    }
    digest = compute_depth_digest(raw_payload)

    return VerificationDepth(
        schema_version=DEPTH_POLICY_SCHEMA_VERSION,
        risk_level=risk_level,
        change_class=change_class,
        depth_name=depth_name,
        mandatory_actions=mandatory_tuple,
        optional_actions=optional_tuple,
        budget_dependent_actions=budget_dep_tuple,
        skipped_optional_checks=skipped_tuple,
        min_sandboxes_required=min_sandboxes,
        min_verifier_executions_required=min_executions,
        rationale=rationale,
        depth_digest=digest,
    )


def verify_verification_depth_integrity(depth: VerificationDepth) -> None:
    """Verify cryptographic integrity of VerificationDepth record."""
    if not isinstance(depth, VerificationDepth):
        raise InvalidDepthPolicyError(
            f"depth must be VerificationDepth, got {type(depth).__name__}"
        )
    recomputed = compute_depth_digest(depth.to_dict())
    if depth.depth_digest != recomputed:
        dd = depth.depth_digest
        raise DepthPolicyTamperingError(
            f"Verification depth digest mismatch: declared {dd}, recomputed {recomputed}"
        )
