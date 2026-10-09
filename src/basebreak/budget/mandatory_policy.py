"""Deterministic policy governing mandatory counterrun and causal slicing obligations.

P-15.04: Add policy for when counterrun/slicing is mandatory under the
Basebreak causal verification authority model.

Authority Model & Invariants:
1. Frozen Contract & Semantic Primacy:
   Mandatory obligations are derived strictly from the frozen contract, canonical
   change semantics, risk classification, and deterministic patch facts.
2. Semantic Preservation:
   Does not force identical shapes on all change classes; respects distinct verification
   profiles for BUG_FIX, SECURITY_FIX, REFACTOR, PERFORMANCE, and DEP_API_CHANGE.
3. Execution Obligation Enforcement:
   Where a counterrun is mandatory, PASS requires its actual independent execution
   and verified counterfactual outcome.
4. Non-fabrication & Slicing Truth:
   Where causal slicing is mandatory, budget exhaustion or incomplete search
   must NEVER be interpreted as successful slicing.
5. Immunity to Model Prose & Cost Tampering:
   Model claims or reduced cost estimates cannot waive mandatory verification obligations.
"""

from __future__ import annotations

import hashlib
import re
from collections.abc import Mapping
from dataclasses import dataclass
from typing import Any

from basebreak.budget.depth_policy import (
    VerificationAction,
    resolve_verification_depth,
)
from basebreak.budget.risk_features import (
    RiskClassification,
    RiskFeatureError,
    RiskLevel,
    canonical_risk_bytes,
    verify_risk_classification_integrity,
)
from basebreak.compiler.freeze import FrozenContract
from basebreak.compiler.semantics import ChangeClass

MANDATORY_POLICY_SCHEMA_VERSION: str = "1.0.0"

_DIGEST_PATTERN = re.compile(r"^[0-9a-f]{64}$")


class MandatoryPolicyError(Exception):
    """Base exception for mandatory policy errors."""


class InvalidMandatoryPolicyInputError(MandatoryPolicyError):
    """Raised when input to mandatory policy resolution is invalid."""


class MandatoryObligationViolationError(MandatoryPolicyError):
    """Raised when a mandatory verification obligation was not executed or failed."""


class MandatoryPolicyTamperingError(MandatoryPolicyError):
    """Raised when mandatory obligations digest fails cryptographic verification."""


@dataclass(frozen=True, slots=True)
class MandatoryVerificationObligations:
    """Deterministic specification of mandatory counterrun and slicing obligations."""

    schema_version: str
    counterrun_mandatory: bool
    slicing_mandatory: bool
    counterrun_reasons: tuple[str, ...]
    slicing_reasons: tuple[str, ...]
    policy_digest: str

    def __post_init__(self) -> None:
        if self.schema_version != MANDATORY_POLICY_SCHEMA_VERSION:
            exp = MANDATORY_POLICY_SCHEMA_VERSION
            raise InvalidMandatoryPolicyInputError(
                f"Unsupported schema_version {self.schema_version!r}, expected {exp!r}"
            )
        if not isinstance(self.counterrun_mandatory, bool):
            raise InvalidMandatoryPolicyInputError("counterrun_mandatory must be a boolean")
        if not isinstance(self.slicing_mandatory, bool):
            raise InvalidMandatoryPolicyInputError("slicing_mandatory must be a boolean")
        if not isinstance(self.counterrun_reasons, tuple):
            raise InvalidMandatoryPolicyInputError("counterrun_reasons must be a tuple")
        if not isinstance(self.slicing_reasons, tuple):
            raise InvalidMandatoryPolicyInputError("slicing_reasons must be a tuple")
        if not _DIGEST_PATTERN.match(self.policy_digest):
            raise InvalidMandatoryPolicyInputError(
                f"policy_digest must be a 64-char lowercase hex string, got {self.policy_digest!r}"
            )

    def to_dict(self) -> dict[str, Any]:
        """Serialize obligations to deterministic dictionary."""
        return {
            "counterrun_mandatory": self.counterrun_mandatory,
            "counterrun_reasons": list(self.counterrun_reasons),
            "policy_digest": self.policy_digest,
            "schema_version": self.schema_version,
            "slicing_mandatory": self.slicing_mandatory,
            "slicing_reasons": list(self.slicing_reasons),
        }


def compute_mandatory_digest(payload: Mapping[str, Any]) -> str:
    """Compute SHA-256 digest over canonical payload excluding policy_digest."""
    clean = {k: v for k, v in payload.items() if k != "policy_digest"}
    return hashlib.sha256(canonical_risk_bytes(clean)).hexdigest()


def resolve_mandatory_obligations(
    classification: RiskClassification,
    *,
    contract: FrozenContract | None = None,
    patch_hunk_count: int = 1,
    explicit_contract_demands_counterrun: bool = False,
    explicit_contract_demands_slicing: bool = False,
) -> MandatoryVerificationObligations:
    """Deterministically determine when counterrun and causal slicing are strictly mandatory."""
    if not isinstance(classification, RiskClassification):
        raise InvalidMandatoryPolicyInputError(
            f"classification must be RiskClassification, got {type(classification).__name__}"
        )

    try:
        verify_risk_classification_integrity(classification)
    except RiskFeatureError as exc:
        raise MandatoryPolicyTamperingError(
            f"Risk classification integrity verification failed: {exc}"
        ) from exc

    if (
        isinstance(patch_hunk_count, bool)
        or not isinstance(patch_hunk_count, int)
        or patch_hunk_count < 0
    ):
        raise InvalidMandatoryPolicyInputError(
            f"patch_hunk_count must be a non-negative int, got {patch_hunk_count!r}"
        )

    depth = resolve_verification_depth(classification)

    risk_level = classification.risk_level
    features = classification.features
    change_class = features.change_class

    cr_reasons: list[str] = []
    slice_reasons: list[str] = []

    # Check contract-level explicit demands
    if explicit_contract_demands_counterrun:
        cr_reasons.append("Frozen contract explicitly mandates counterfactual execution")
    elif contract is not None:
        # Inspect requirement statements for counterfactual keywords
        for req in contract.requirements:
            stmt = req.statement.lower()
            if any(k in stmt for k in ("counterfactual", "third run", "base mutation", "triplet")):
                cr_reasons.append(
                    f"Requirement {req.requirement_id} explicitly demands counterrun verification"
                )
                break

    if explicit_contract_demands_slicing:
        slice_reasons.append("Frozen contract explicitly mandates minimal causal slicing")
    elif contract is not None:
        for req in contract.requirements:
            stmt = req.statement.lower()
            if any(
                k in stmt
                for k in ("causal slice", "minimal subset", "hunk minimization", "necessary subset")
            ):
                slice_reasons.append(
                    f"Requirement {req.requirement_id} explicitly demands causal slicing"
                )
                break

    # Depth policy alignment: no required action from depth policy may disappear
    if VerificationAction.COUNTERFACTUAL_EXECUTION in depth.mandatory_actions:
        if risk_level == RiskLevel.MEDIUM and change_class in (
            ChangeClass.BUG_FIX,
            ChangeClass.SECURITY_FIX,
        ):
            cr_reasons.append(
                f"MEDIUM risk {change_class.value} mandates counterrun for "
                "behavioral defect verification under depth policy"
            )
        elif risk_level == RiskLevel.HIGH:
            cr_reasons.append(
                f"HIGH risk {change_class.value} mandates counterrun "
                "verification under depth policy"
            )
        else:
            cr_reasons.append(
                f"Verification depth mandates counterrun execution for "
                f"{change_class.value} at {risk_level.value} risk"
            )

    if VerificationAction.CAUSAL_SLICING in depth.mandatory_actions:
        slice_reasons.append(
            f"Verification depth mandates causal slicing for "
            f"{change_class.value} at {risk_level.value} risk"
        )

    # Policy triggers for Counterrun
    if risk_level == RiskLevel.HIGH and change_class in (ChangeClass.BUG_FIX, ChangeClass.FEATURE):
        cr_reasons.append(
            f"HIGH risk {change_class.value} mandates counterrun to rule out placebo patches"
        )

    if change_class == ChangeClass.SECURITY_FIX and risk_level in (
        RiskLevel.MEDIUM,
        RiskLevel.HIGH,
    ):
        cr_reasons.append(
            "SECURITY_FIX at MEDIUM/HIGH risk mandates counterrun to prove exploit persistence"
        )

    if features.touched_protected_surfaces:
        cr_reasons.append("Modification touches protected surfaces: counterrun mandatory")

    if features.touched_security_sensitive_paths and change_class in (
        ChangeClass.BUG_FIX,
        ChangeClass.SECURITY_FIX,
    ):
        cr_reasons.append("Touches security-sensitive paths: counterrun mandatory")

    # Policy triggers for Causal Slicing
    if patch_hunk_count > 1 and risk_level == RiskLevel.HIGH:
        slice_reasons.append(
            f"Multi-hunk patch ({patch_hunk_count} hunks) at HIGH risk mandates causal slicing"
        )

    if patch_hunk_count > 1 and change_class == ChangeClass.SECURITY_FIX:
        slice_reasons.append(
            f"Multi-hunk security patch ({patch_hunk_count} hunks) mandates causal slicing"
        )

    if patch_hunk_count > 3 and risk_level == RiskLevel.MEDIUM:
        slice_reasons.append(
            f"Multi-hunk patch ({patch_hunk_count} hunks) at MEDIUM risk mandates causal slicing"
        )

    if features.touched_protected_surfaces and patch_hunk_count > 1:
        slice_reasons.append(
            "Touches protected surfaces with multiple hunks: causal slicing mandatory"
        )

    # Deduplicate reasons preserving order
    cr_reasons_clean: list[str] = []
    for r in cr_reasons:
        if r not in cr_reasons_clean:
            cr_reasons_clean.append(r)

    slice_reasons_clean: list[str] = []
    for r in slice_reasons:
        if r not in slice_reasons_clean:
            slice_reasons_clean.append(r)

    counterrun_mandatory = len(cr_reasons_clean) > 0
    slicing_mandatory = len(slice_reasons_clean) > 0

    cr_tuple = tuple(cr_reasons_clean)
    slice_tuple = tuple(slice_reasons_clean)

    raw_payload: dict[str, Any] = {
        "counterrun_mandatory": counterrun_mandatory,
        "counterrun_reasons": list(cr_tuple),
        "schema_version": MANDATORY_POLICY_SCHEMA_VERSION,
        "slicing_mandatory": slicing_mandatory,
        "slicing_reasons": list(slice_tuple),
    }
    digest = compute_mandatory_digest(raw_payload)

    return MandatoryVerificationObligations(
        schema_version=MANDATORY_POLICY_SCHEMA_VERSION,
        counterrun_mandatory=counterrun_mandatory,
        slicing_mandatory=slicing_mandatory,
        counterrun_reasons=cr_tuple,
        slicing_reasons=slice_tuple,
        policy_digest=digest,
    )


def verify_mandatory_obligations_integrity(obligations: MandatoryVerificationObligations) -> None:
    """Verify cryptographic integrity of MandatoryVerificationObligations record."""
    if not isinstance(obligations, MandatoryVerificationObligations):
        cls_name = type(obligations).__name__
        raise InvalidMandatoryPolicyInputError(
            f"obligations must be MandatoryVerificationObligations, got {cls_name}"
        )
    recomputed = compute_mandatory_digest(obligations.to_dict())
    if obligations.policy_digest != recomputed:
        pd = obligations.policy_digest
        raise MandatoryPolicyTamperingError(
            f"Mandatory obligations digest mismatch: declared {pd}, recomputed {recomputed}"
        )


def validate_executed_obligations(
    obligations: MandatoryVerificationObligations,
    *,
    counterrun_executed: bool,
    counterrun_passed: bool,
    slicing_executed: bool,
    slicing_passed: bool,
) -> None:
    """Validate that mandatory obligations were actually executed and satisfied.

    Raises MandatoryObligationViolationError if any mandatory obligation was skipped or failed.
    """
    if obligations.counterrun_mandatory:
        if not counterrun_executed:
            raise MandatoryObligationViolationError(
                "Mandatory counterrun execution was not executed: cannot award PASS"
            )
        if not counterrun_passed:
            raise MandatoryObligationViolationError(
                "Mandatory counterrun failed or yielded contradictory outcome: cannot award PASS"
            )

    if obligations.slicing_mandatory:
        if not slicing_executed:
            raise MandatoryObligationViolationError(
                "Mandatory causal slicing was not executed: cannot award PASS"
            )
        if not slicing_passed:
            raise MandatoryObligationViolationError(
                "Mandatory causal slicing search failed or was incomplete: cannot award PASS"
            )
