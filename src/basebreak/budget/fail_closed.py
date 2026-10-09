"""Fail-closed budget admission and exhaustion handling.

P-15.05: Add fail-closed behavior when required budget cannot execute under
the Basebreak causal verification authority model.

Authority Model & Invariants:
1. Zero Silent Degradation:
   Never silently replace required real executions with fixtures or mocks.
   Never downgrade required verification depth merely to fit an insufficient budget.
2. Honest Classification:
   On resource exhaustion, returns an honest BLOCKED, INCONCLUSIVE, or NOT_RUN verdict.
   PASS is strictly prohibited when mandatory verification has not executed.
3. Pre-execution Admission Gate:
   Checks sufficient capacity BEFORE launching expensive or irreversible sandboxes.
4. Witness Failure Governance:
   Deterministic witness failure always governs; budget exhaustion CANNOT mask or overwrite
   a genuine witness failure (remains CONTRADICTED).
5. Evidence Preservation:
   Preserves all verified execution evidence digests produced prior to exhaustion.
6. Zero Builder/Model Authority:
   Neither builder prose nor model confidence can bypass fail-closed enforcement.
"""

from __future__ import annotations

import hashlib
import re
from collections.abc import Mapping, Sequence
from dataclasses import dataclass
from enum import Enum
from typing import Any

from basebreak.budget.accounting import BudgetLedger
from basebreak.budget.depth_policy import VerificationAction, VerificationDepth
from basebreak.budget.mandatory_policy import MandatoryVerificationObligations
from basebreak.budget.risk_features import canonical_risk_bytes
from basebreak.domain.verdict import PreliminaryVerdict

FAIL_CLOSED_SCHEMA_VERSION: str = "1.0.0"

_DIGEST_PATTERN = re.compile(r"^[0-9a-f]{64}$")


class FailClosedError(Exception):
    """Base exception for fail-closed budget errors."""


class InvalidGateInputError(FailClosedError):
    """Raised when gate input or state is malformed."""


class BudgetGateTamperingError(FailClosedError):
    """Raised when BudgetGateResult digest does not match recomputed SHA-256."""


class BudgetGateStatus(str, Enum):
    """Classification of budget admission and termination state."""

    ADMITTED = "ADMITTED"
    INSUFFICIENT_RESERVATION = "INSUFFICIENT_RESERVATION"
    EXHAUSTED = "EXHAUSTED"
    UNVERIFIABLE_BUDGET = "UNVERIFIABLE_BUDGET"
    CONTRADICTED_WITNESS = "CONTRADICTED_WITNESS"


@dataclass(frozen=True, slots=True)
class UnexecutedObligation:
    """Record of an unexecuted verification obligation and its deterministic rationale."""

    action: VerificationAction
    is_mandatory: bool
    reason: str

    def __post_init__(self) -> None:
        if not isinstance(self.action, VerificationAction):
            raise InvalidGateInputError(
                f"action must be VerificationAction, got {type(self.action).__name__}"
            )
        if not isinstance(self.is_mandatory, bool):
            raise InvalidGateInputError("is_mandatory must be a boolean")
        if not self.reason or not self.reason.strip():
            raise InvalidGateInputError("reason must be a non-empty string")

    def to_dict(self) -> dict[str, Any]:
        return {
            "action": self.action.value,
            "is_mandatory": self.is_mandatory,
            "reason": self.reason,
        }


@dataclass(frozen=True, slots=True)
class BudgetGateResult:
    """Tamper-evident receipt capturing budget admission, exhaustion, or termination."""

    schema_version: str
    gate_status: BudgetGateStatus
    preliminary_verdict: PreliminaryVerdict
    is_causally_verified: bool
    grants_pass: bool
    unexecuted_obligations: tuple[UnexecutedObligation, ...]
    preserved_evidence_digests: tuple[str, ...]
    rationale: str
    receipt_digest: str
    is_authoritative: bool = False  # Zero unverified authority

    def __post_init__(self) -> None:
        if self.schema_version != FAIL_CLOSED_SCHEMA_VERSION:
            exp = FAIL_CLOSED_SCHEMA_VERSION
            raise InvalidGateInputError(
                f"Unsupported schema_version {self.schema_version!r}, expected {exp!r}"
            )
        if not isinstance(self.gate_status, BudgetGateStatus):
            raise InvalidGateInputError(
                f"gate_status must be BudgetGateStatus, got {type(self.gate_status).__name__}"
            )
        if not isinstance(self.preliminary_verdict, PreliminaryVerdict):
            pv_type = type(self.preliminary_verdict).__name__
            raise InvalidGateInputError(
                f"preliminary_verdict must be PreliminaryVerdict, got {pv_type}"
            )

        # If gate status is not ADMITTED, grants_pass and is_causally_verified must be False
        if self.gate_status != BudgetGateStatus.ADMITTED:
            if self.grants_pass is not False:
                raise InvalidGateInputError(
                    "grants_pass must be False when budget gate is not ADMITTED"
                )
            if self.is_causally_verified is not False:
                raise InvalidGateInputError(
                    "is_causally_verified must be False when budget gate is not ADMITTED"
                )

        # VERIFIED preliminary verdict is forbidden unless gate admitted and executed
        if (
            self.preliminary_verdict == PreliminaryVerdict.VERIFIED
            and self.gate_status != BudgetGateStatus.ADMITTED
        ):
            raise InvalidGateInputError(
                "Cannot award VERIFIED preliminary verdict on budget rejection or exhaustion"
            )

        if not _DIGEST_PATTERN.match(self.receipt_digest):
            raise InvalidGateInputError(
                f"receipt_digest must be 64-char hex, got {self.receipt_digest!r}"
            )
        if self.is_authoritative is not False:
            raise InvalidGateInputError(
                "is_authoritative must be False; gate receipt cannot self-certify"
            )

    def to_dict(self) -> dict[str, Any]:
        """Serialize gate receipt to deterministic dictionary."""
        return {
            "gate_status": self.gate_status.value,
            "grants_pass": self.grants_pass,
            "is_authoritative": self.is_authoritative,
            "is_causally_verified": self.is_causally_verified,
            "preliminary_verdict": self.preliminary_verdict.value,
            "preserved_evidence_digests": list(self.preserved_evidence_digests),
            "rationale": self.rationale,
            "receipt_digest": self.receipt_digest,
            "schema_version": self.schema_version,
            "unexecuted_obligations": [o.to_dict() for o in self.unexecuted_obligations],
        }


def compute_gate_digest(payload: Mapping[str, Any]) -> str:
    """Compute SHA-256 digest over canonical payload excluding receipt_digest."""
    clean = {k: v for k, v in payload.items() if k != "receipt_digest"}
    return hashlib.sha256(canonical_risk_bytes(clean)).hexdigest()


def calculate_minimum_required_resources(
    depth: VerificationDepth,
    obligations: MandatoryVerificationObligations,
) -> tuple[int, int]:
    """Calculate minimum sandboxes and verifier executions needed for all mandatory actions.

    Returns (min_sandboxes, min_verifier_executions).
    """
    sbx_count = depth.min_sandboxes_required
    exec_count = depth.min_verifier_executions_required

    # Counterrun adds 1 sandbox and 1 verifier execution if mandatory
    if (
        obligations.counterrun_mandatory
        and VerificationAction.COUNTERFACTUAL_EXECUTION not in depth.mandatory_actions
    ):
        sbx_count += 1
        exec_count += 1

    # Causal slicing adds at least 2 sandboxes and 2 verifier executions if mandatory
    if (
        obligations.slicing_mandatory
        and VerificationAction.CAUSAL_SLICING not in depth.mandatory_actions
    ):
        sbx_count += 2
        exec_count += 2

    return sbx_count, exec_count


def preflight_budget_admission(
    ledger: BudgetLedger,
    depth: VerificationDepth,
    obligations: MandatoryVerificationObligations,
    *,
    min_required_seconds: float = 10.0,
    requires_financial_authorization: bool = False,
    is_cost_consuming: bool = False,
) -> BudgetGateResult:
    """Preflight check determining whether available budget can support mandatory verification.

    Fails closed if hard capacities are unconfigured/unbounded, resources are insufficient,
    or financial exposure is unknown/unverifiable.
    """
    if not isinstance(ledger, BudgetLedger):
        raise InvalidGateInputError(f"ledger must be BudgetLedger, got {type(ledger).__name__}")
    if not isinstance(depth, VerificationDepth):
        raise InvalidGateInputError(f"depth must be VerificationDepth, got {type(depth).__name__}")
    if not isinstance(obligations, MandatoryVerificationObligations):
        cls_name = type(obligations).__name__
        raise InvalidGateInputError(
            f"obligations must be MandatoryVerificationObligations, got {cls_name}"
        )

    # 1. Check for unverifiable or contradictory ledger state
    try:
        ledger.consumption.validate()
    except Exception as exc:
        raw_payload = {
            "gate_status": BudgetGateStatus.UNVERIFIABLE_BUDGET.value,
            "grants_pass": False,
            "is_authoritative": False,
            "is_causally_verified": False,
            "preliminary_verdict": PreliminaryVerdict.BLOCKED.value,
            "preserved_evidence_digests": [],
            "rationale": f"Corrupt or unverifiable budget consumption state: {exc}",
            "schema_version": FAIL_CLOSED_SCHEMA_VERSION,
            "unexecuted_obligations": [],
        }
        digest = compute_gate_digest(raw_payload)
        return BudgetGateResult(
            schema_version=FAIL_CLOSED_SCHEMA_VERSION,
            gate_status=BudgetGateStatus.UNVERIFIABLE_BUDGET,
            preliminary_verdict=PreliminaryVerdict.BLOCKED,
            is_causally_verified=False,
            grants_pass=False,
            unexecuted_obligations=(),
            preserved_evidence_digests=(),
            rationale=f"Corrupt or unverifiable budget consumption state: {exc}",
            receipt_digest=digest,
        )

    required_sbx, required_exec = calculate_minimum_required_resources(depth, obligations)

    unexecuted: list[UnexecutedObligation] = []
    shortfall_reasons: list[str] = []
    is_unverifiable = False

    # Check sandbox executions limit (must be explicitly configured and sufficient)
    if ledger.limits.max_sandbox_executions is None:
        if required_sbx > 0:
            shortfall_reasons.append(
                f"Unverifiable budget: max_sandbox_executions must be explicitly configured "
                f"(requires at least {required_sbx})"
            )
            is_unverifiable = True
    else:
        available_sbx = ledger.limits.max_sandbox_executions - (
            ledger.consumption.sandbox_executions + ledger.get_active_reserved_sandboxes()
        )
        if available_sbx < required_sbx:
            limit_sbx = ledger.limits.max_sandbox_executions
            shortfall_reasons.append(
                f"Insufficient sandbox executions: requires {required_sbx}, "
                f"available {available_sbx} (limit {limit_sbx})"
            )

    # Check verifier executions limit (must be explicitly configured and sufficient)
    if ledger.limits.max_verifier_executions is None:
        if required_exec > 0:
            shortfall_reasons.append(
                f"Unverifiable budget: max_verifier_executions must be explicitly configured "
                f"(requires at least {required_exec})"
            )
            is_unverifiable = True
    else:
        available_ver = ledger.limits.max_verifier_executions - (
            ledger.consumption.verifier_executions
            + ledger.get_active_reserved_verifier_executions()
        )
        if available_ver < required_exec:
            limit_ver = ledger.limits.max_verifier_executions
            shortfall_reasons.append(
                f"Insufficient verifiers: requires {required_exec}, available {available_ver} "
                f"(limit {limit_ver})"
            )

    # Check time limit
    if ledger.limits.max_elapsed_seconds is not None:
        elapsed = max(ledger.consumption.elapsed_seconds, ledger.elapsed_wall_clock_seconds)
        if elapsed + min_required_seconds > ledger.limits.max_elapsed_seconds:
            shortfall_reasons.append(
                f"Insufficient time budget: requires {min_required_seconds}s, "
                f"remaining {ledger.limits.max_elapsed_seconds - elapsed:.1f}s"
            )

    # Check financial exposure & authorization
    has_unknown = ledger.consumption.has_unknown_financial_cost
    is_zero = ledger.consumption.is_verified_zero_cost
    if has_unknown and not is_zero:
        shortfall_reasons.append(
            "Unknown financial exposure: ledger contains unknown cost and cannot certify bounds"
        )
        is_unverifiable = True

    if requires_financial_authorization or is_cost_consuming:
        if ledger.consumption.has_unknown_financial_cost:
            shortfall_reasons.append(
                "Missing trustworthy financial cost facts for cost-consuming operation"
            )
            is_unverifiable = True
        elif ledger.limits.max_estimated_cost_usd is None:
            shortfall_reasons.append(
                "Unknown financial exposure: cost-consuming operation requires "
                "explicitly configured max_estimated_cost_usd"
            )
            is_unverifiable = True

    # If capacity is deficient or unverifiable, build fail-closed receipt
    if shortfall_reasons:
        gate_status = (
            BudgetGateStatus.UNVERIFIABLE_BUDGET
            if is_unverifiable
            else BudgetGateStatus.INSUFFICIENT_RESERVATION
        )
        for action in depth.mandatory_actions:
            unexecuted.append(
                UnexecutedObligation(
                    action=action,
                    is_mandatory=True,
                    reason="Preflight admission denied: " + "; ".join(shortfall_reasons),
                )
            )
        if (
            obligations.counterrun_mandatory
            and VerificationAction.COUNTERFACTUAL_EXECUTION not in depth.mandatory_actions
        ):
            unexecuted.append(
                UnexecutedObligation(
                    action=VerificationAction.COUNTERFACTUAL_EXECUTION,
                    is_mandatory=True,
                    reason="Preflight admission denied: " + "; ".join(shortfall_reasons),
                )
            )
        if (
            obligations.slicing_mandatory
            and VerificationAction.CAUSAL_SLICING not in depth.mandatory_actions
        ):
            unexecuted.append(
                UnexecutedObligation(
                    action=VerificationAction.CAUSAL_SLICING,
                    is_mandatory=True,
                    reason="Preflight admission denied: " + "; ".join(shortfall_reasons),
                )
            )

        unexecuted_tuple = tuple(unexecuted)
        raw_payload = {
            "gate_status": gate_status.value,
            "grants_pass": False,
            "is_authoritative": False,
            "is_causally_verified": False,
            "preliminary_verdict": PreliminaryVerdict.BLOCKED.value,
            "preserved_evidence_digests": [],
            "rationale": "Preflight budget admission denied: " + "; ".join(shortfall_reasons),
            "schema_version": FAIL_CLOSED_SCHEMA_VERSION,
            "unexecuted_obligations": [o.to_dict() for o in unexecuted_tuple],
        }
        digest = compute_gate_digest(raw_payload)

        return BudgetGateResult(
            schema_version=FAIL_CLOSED_SCHEMA_VERSION,
            gate_status=gate_status,
            preliminary_verdict=PreliminaryVerdict.BLOCKED,
            is_causally_verified=False,
            grants_pass=False,
            unexecuted_obligations=unexecuted_tuple,
            preserved_evidence_digests=(),
            rationale="Preflight budget admission denied: " + "; ".join(shortfall_reasons),
            receipt_digest=digest,
        )

    # Budget is sufficient: Admit
    raw_payload = {
        "gate_status": BudgetGateStatus.ADMITTED.value,
        "grants_pass": False,
        "is_authoritative": False,
        "is_causally_verified": False,
        "preliminary_verdict": PreliminaryVerdict.INCONCLUSIVE.value,
        "preserved_evidence_digests": [],
        "rationale": (
            f"Preflight admission passed: sufficient budget for {required_sbx} sandboxes "
            f"and {required_exec} executions."
        ),
        "schema_version": FAIL_CLOSED_SCHEMA_VERSION,
        "unexecuted_obligations": [],
    }
    digest = compute_gate_digest(raw_payload)

    return BudgetGateResult(
        schema_version=FAIL_CLOSED_SCHEMA_VERSION,
        gate_status=BudgetGateStatus.ADMITTED,
        preliminary_verdict=PreliminaryVerdict.INCONCLUSIVE,
        is_causally_verified=False,
        grants_pass=False,
        unexecuted_obligations=(),
        preserved_evidence_digests=(),
        rationale=(
            f"Preflight admission passed: sufficient budget for {required_sbx} sandboxes "
            f"and {required_exec} executions."
        ),
        receipt_digest=digest,
    )


def handle_budget_exhaustion(
    ledger: BudgetLedger,
    depth: VerificationDepth,
    obligations: MandatoryVerificationObligations,
    *,
    executed_actions: Sequence[VerificationAction] = (),
    preserved_evidence_digests: Sequence[str] = (),
    witness_failure_observed: bool = False,
    exhaustion_detail: str = "Resource budget exhausted during verification",
) -> BudgetGateResult:
    """Handle resource exhaustion during verification execution.

    Invariants Enforced:
    1. Witness Failure Governance: If witness failure was already observed, preliminary verdict
       remains CONTRADICTED; exhaustion does not mask failure.
    2. Fail-Closed Verdict: If no witness failure was observed but mandatory actions remain
       unexecuted, preliminary verdict is BLOCKED; grants_pass is False.
    3. Evidence Preservation: Preserves all valid execution evidence digests.
    4. Honest Accounting: Records precisely which required checks were unexecuted and why.
    """
    if not isinstance(depth, VerificationDepth):
        raise InvalidGateInputError(f"depth must be VerificationDepth, got {type(depth).__name__}")
    if not isinstance(obligations, MandatoryVerificationObligations):
        cls_name = type(obligations).__name__
        raise InvalidGateInputError(
            f"obligations must be MandatoryVerificationObligations, got {cls_name}"
        )

    executed_set = set(executed_actions)
    unexecuted: list[UnexecutedObligation] = []

    # Check mandatory actions from depth
    for action in depth.mandatory_actions:
        if action not in executed_set:
            unexecuted.append(
                UnexecutedObligation(
                    action=action,
                    is_mandatory=True,
                    reason=f"Action {action.value} unexecuted: {exhaustion_detail}",
                )
            )

    # Check mandatory counterrun
    if (
        obligations.counterrun_mandatory
        and VerificationAction.COUNTERFACTUAL_EXECUTION not in executed_set
    ):
        if not any(u.action == VerificationAction.COUNTERFACTUAL_EXECUTION for u in unexecuted):
            unexecuted.append(
                UnexecutedObligation(
                    action=VerificationAction.COUNTERFACTUAL_EXECUTION,
                    is_mandatory=True,
                    reason="Mandatory counterrun unexecuted due to budget exhaustion: "
                    + exhaustion_detail,
                )
            )

    # Check mandatory slicing
    if obligations.slicing_mandatory and VerificationAction.CAUSAL_SLICING not in executed_set:
        if not any(u.action == VerificationAction.CAUSAL_SLICING for u in unexecuted):
            unexecuted.append(
                UnexecutedObligation(
                    action=VerificationAction.CAUSAL_SLICING,
                    is_mandatory=True,
                    reason="Mandatory causal slicing unexecuted due to budget exhaustion: "
                    + exhaustion_detail,
                )
            )

    # Check budget-dependent actions
    for action in depth.budget_dependent_actions:
        if action not in executed_set:
            unexecuted.append(
                UnexecutedObligation(
                    action=action,
                    is_mandatory=False,
                    reason=f"Check {action.value} omitted due to exhaustion: {exhaustion_detail}",
                )
            )

    unexecuted_tuple = tuple(unexecuted)
    preserved_tuple = tuple(sorted(set(preserved_evidence_digests)))

    # Invariant: Witness failure governs over budget exhaustion
    if witness_failure_observed:
        gate_status = BudgetGateStatus.CONTRADICTED_WITNESS
        verdict = PreliminaryVerdict.CONTRADICTED
        rationale = (
            "Deterministic witness failure observed prior to budget exhaustion. "
            "Exhaustion does not mask or overwrite witness contradiction: " + exhaustion_detail
        )
    else:
        gate_status = BudgetGateStatus.EXHAUSTED
        verdict = PreliminaryVerdict.BLOCKED
        rationale = (
            f"Budget exhausted with {len(unexecuted)} unexecuted check(s) "
            f"({sum(1 for u in unexecuted if u.is_mandatory)} mandatory): {exhaustion_detail}"
        )

    raw_payload: dict[str, Any] = {
        "gate_status": gate_status.value,
        "grants_pass": False,
        "is_authoritative": False,
        "is_causally_verified": False,
        "preliminary_verdict": verdict.value,
        "preserved_evidence_digests": list(preserved_tuple),
        "rationale": rationale,
        "schema_version": FAIL_CLOSED_SCHEMA_VERSION,
        "unexecuted_obligations": [u.to_dict() for u in unexecuted_tuple],
    }
    digest = compute_gate_digest(raw_payload)

    return BudgetGateResult(
        schema_version=FAIL_CLOSED_SCHEMA_VERSION,
        gate_status=gate_status,
        preliminary_verdict=verdict,
        is_causally_verified=False,
        grants_pass=False,
        unexecuted_obligations=unexecuted_tuple,
        preserved_evidence_digests=preserved_tuple,
        rationale=rationale,
        receipt_digest=digest,
    )


def verify_budget_gate_result_integrity(result: BudgetGateResult) -> None:
    """Verify cryptographic integrity of BudgetGateResult."""
    if not isinstance(result, BudgetGateResult):
        raise InvalidGateInputError(f"result must be BudgetGateResult, got {type(result).__name__}")
    recomputed = compute_gate_digest(result.to_dict())
    if result.receipt_digest != recomputed:
        rd = result.receipt_digest
        raise BudgetGateTamperingError(
            f"Budget gate receipt digest mismatch: declared {rd}, recomputed {recomputed}"
        )
