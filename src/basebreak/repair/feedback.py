"""Bounded failure feedback schema and contracts for sealed repair.

P-14.01: Define bounded failure-feedback schema.

Core Invariants:
1. Provider-neutral deterministic contracts for verifier -> Builder repair feedback.
2. Carries only minimally necessary failure facts (requirement_id, change_class,
   failed_condition, observed_behavior, expected_behavior, sanitized counterexample,
   permitted patch regions).
3. Explicit disclosure classification: marked with DisclosureClassification.SAFE_TO_DISCLOSE.
4. Zero verdict authority:
   is_authoritative = False
   grants_pass = False
   is_causally_verified = False
   Caller-asserted authority fails closed.
5. Cryptographic integrity: feedback_digest is computed over canonical JSON bytes;
   tampering fails closed.
"""

from __future__ import annotations

import hashlib
import json
import re
import uuid
from collections.abc import Mapping, Sequence
from dataclasses import dataclass
from enum import Enum
from typing import Any

from basebreak.domain.execution import TerminationStatus
from basebreak.domain.semantics import ChangeClass
from basebreak.domain.verdict import EvidenceProvenance, PreliminaryVerdict
from basebreak.verifier.witness_result import WitnessOutcome

REPAIR_FEEDBACK_SCHEMA_VERSION: str = "1.0.0"

_HEX_40_OR_64_PATTERN = re.compile(r"^([0-9a-f]{40}|[0-9a-f]{64})$")
_HEX_64_PATTERN = re.compile(r"^[0-9a-f]{64}$")
_IDENTIFIER_PATTERN = re.compile(r"^[A-Za-z0-9_\-\.:/]+$")

VALID_FAILING_WITNESS_OUTCOMES: frozenset[WitnessOutcome] = frozenset(
    {
        WitnessOutcome.FAIL,
        WitnessOutcome.ERROR,
        WitnessOutcome.TIMEOUT,
        WitnessOutcome.INVALID_PRECONDITION,
    }
)

VALID_FAILING_VERDICTS: frozenset[PreliminaryVerdict] = frozenset(
    {
        PreliminaryVerdict.CONTRADICTED,
        PreliminaryVerdict.INCONCLUSIVE,
        PreliminaryVerdict.BLOCKED,
    }
)

VALID_FAILING_OUTCOMES: frozenset[WitnessOutcome | PreliminaryVerdict] = (
    VALID_FAILING_WITNESS_OUTCOMES | VALID_FAILING_VERDICTS
)

FORBIDDEN_PASSING_OUTCOMES: frozenset[WitnessOutcome | PreliminaryVerdict] = frozenset(
    {
        WitnessOutcome.PASS,
        PreliminaryVerdict.VERIFIED,
        PreliminaryVerdict.PARTIALLY_VERIFIED,
    }
)


class RepairFeedbackError(Exception):
    """Base exception for all repair feedback errors."""


class RepairFeedbackIntegrityError(RepairFeedbackError):
    """Raised when repair feedback facts violate domain constraints or format."""


class RepairFeedbackAuthorityError(RepairFeedbackError):
    """Raised when feedback object claims unauthorized verdict or certification authority."""


class RepairFeedbackTamperingError(RepairFeedbackError):
    """Raised when repair feedback facts do not match the cryptographic feedback digest."""


class RepairFeedbackDisclosureError(RepairFeedbackError):
    """Raised when feedback contains forbidden or unsafe disclosure items."""


class DisclosureClassification(str, Enum):
    """Deterministic disclosure classification for verifier-emitted feedback."""

    SAFE_TO_DISCLOSE = "SAFE_TO_DISCLOSE"
    REDACTED = "REDACTED"
    FORBIDDEN = "FORBIDDEN"


class FailureConditionCategory(str, Enum):
    """Deterministic categorization of verifier failure conditions."""

    BEHAVIORAL_ASSERTION_FAILED = "BEHAVIORAL_ASSERTION_FAILED"
    STATE_TRANSITION_FAILED = "STATE_TRANSITION_FAILED"
    SECURITY_NOT_BLOCKED = "SECURITY_NOT_BLOCKED"
    REFACTOR_BEHAVIOR_DIVERGED = "REFACTOR_BEHAVIOR_DIVERGED"
    PERFORMANCE_UNIMPROVED = "PERFORMANCE_UNIMPROVED"
    DEP_API_REGRESSION = "DEP_API_REGRESSION"
    UNEXPECTED_TERMINATION = "UNEXPECTED_TERMINATION"
    NON_BEHAVIORAL_FAILURE = "NON_BEHAVIORAL_FAILURE"


def _validate_non_empty_str(val: str, field_name: str) -> None:
    if not isinstance(val, str):
        raise TypeError(f"{field_name} must be str, got {type(val).__name__}")
    if not val.strip():
        raise RepairFeedbackIntegrityError(f"{field_name} must not be empty or whitespace-only")


def is_dummy_or_invalid_digest(digest: str | None) -> bool:
    """Deterministic check rejecting missing, malformed, or dummy all-zero digests."""
    if not digest or not isinstance(digest, str):
        return True
    digest_clean = digest.strip()
    if len(digest_clean) not in (40, 64):
        return True
    if not _HEX_40_OR_64_PATTERN.match(digest_clean):
        return True
    if set(digest_clean) == {"0"}:
        return True
    return False


def _validate_hex_digest(digest: str, field_name: str, allow_40: bool = False) -> None:
    _validate_non_empty_str(digest, field_name)
    pat = _HEX_40_OR_64_PATTERN if allow_40 else _HEX_64_PATTERN
    if not pat.match(digest):
        expected = "40 or 64" if allow_40 else "64"
        raise RepairFeedbackIntegrityError(
            f"{field_name} must be a {expected} hex character string, got {digest!r}"
        )
    if set(digest.strip()) == {"0"}:
        raise RepairFeedbackIntegrityError(
            f"{field_name} cannot be a dummy all-zero digest: {digest!r}"
        )


@dataclass(frozen=True, slots=True)
class FailedExecutionFacts:
    """Deterministic, provider-neutral facts from a failed candidate execution.

    Used to derive bounded, sanitized failure feedback for Builder repair.
    Contains zero private witness source, assertions, or vault secrets.
    """

    exit_code: int | None = None
    termination_status: TerminationStatus = TerminationStatus.COMPLETED
    failure_message: str = ""
    sandbox_id: str | None = None
    execution_digest: str | None = None
    condition_category: FailureConditionCategory = (
        FailureConditionCategory.BEHAVIORAL_ASSERTION_FAILED
    )
    duration_seconds: float | None = None
    counterexample_input: str | None = None
    counterexample_actual: str | None = None
    counterexample_expected: str | None = None
    deterministic_failure_justification: str | None = None
    failing_outcome: WitnessOutcome | PreliminaryVerdict | None = None

    def __post_init__(self) -> None:
        if self.exit_code is not None and not isinstance(self.exit_code, int):
            raise TypeError("exit_code must be an integer or None")
        if not isinstance(self.termination_status, TerminationStatus):
            raise TypeError("termination_status must be a TerminationStatus")
        if not isinstance(self.condition_category, FailureConditionCategory):
            raise TypeError("condition_category must be a FailureConditionCategory")
        if self.duration_seconds is not None and (
            isinstance(self.duration_seconds, bool)
            or not isinstance(self.duration_seconds, (int, float))
        ):
            raise TypeError("duration_seconds must be a float or None")
        if self.sandbox_id is not None and (
            not isinstance(self.sandbox_id, str) or not self.sandbox_id.strip()
        ):
            raise RepairFeedbackIntegrityError("sandbox_id must be a non-empty string or None")
        if self.execution_digest is not None:
            if not isinstance(self.execution_digest, str) or is_dummy_or_invalid_digest(
                self.execution_digest
            ):
                raise RepairFeedbackIntegrityError(
                    f"execution_digest cannot be a dummy or invalid hex digest: "
                    f"{self.execution_digest!r}"
                )

        # Validate failing_outcome if provided
        if self.failing_outcome is not None:
            if not isinstance(self.failing_outcome, (WitnessOutcome, PreliminaryVerdict)):
                raise RepairFeedbackIntegrityError(
                    "failing_outcome must be a typed WitnessOutcome or PreliminaryVerdict enum "
                    f"instance, got {type(self.failing_outcome).__name__} "
                    f"({self.failing_outcome!r}). "
                    "Arbitrary strings and fabricated outcome names cannot authorize repair."
                )
            if self.failing_outcome in FORBIDDEN_PASSING_OUTCOMES:
                raise RepairFeedbackIntegrityError(
                    f"Passing or partially passing outcome {self.failing_outcome.value!r} "
                    "cannot justify failed execution."
                )
            if self.failing_outcome == PreliminaryVerdict.NOT_RUN:
                raise RepairFeedbackIntegrityError(
                    "Non-execution verdict NOT_RUN cannot justify failed execution."
                )
            if self.failing_outcome not in VALID_FAILING_OUTCOMES:
                raise RepairFeedbackIntegrityError(
                    f"Unsupported outcome {self.failing_outcome!r} cannot justify failed execution."
                )

        # Repair A: Reject exit_code=0 as evidence of failed execution unless backed
        # by a genuine validated deterministic failing witness/verdict outcome bound
        # to the same execution identity. Free-form justification text is not proof.
        if self.exit_code == 0:
            if self.failing_outcome is None:
                raise RepairFeedbackIntegrityError(
                    "exit_code=0 cannot be accepted as evidence of failed execution "
                    "without a genuine validated deterministic failing witness/verdict outcome "
                    "(WitnessOutcome or PreliminaryVerdict). Free-form justification text "
                    "cannot authorize repair."
                )
            if self.execution_digest is None or is_dummy_or_invalid_digest(self.execution_digest):
                raise RepairFeedbackIntegrityError(
                    f"exit_code=0 requires a valid non-dummy execution_digest bound to the "
                    f"deterministic failing outcome, got {self.execution_digest!r}"
                )
            if self.termination_status != TerminationStatus.COMPLETED:
                raise RepairFeedbackIntegrityError(
                    f"Contradictory execution state: exit_code=0 with "
                    f"termination_status={self.termination_status.value}"
                )
            if self.failing_outcome == WitnessOutcome.TIMEOUT:
                raise RepairFeedbackIntegrityError(
                    "Contradictory execution state: exit_code=0 cannot be combined with "
                    "WitnessOutcome.TIMEOUT"
                )

        # Contradiction check: TIMED_OUT status cannot collapse into WitnessOutcome.FAIL
        if (
            self.termination_status == TerminationStatus.TIMED_OUT
            and self.failing_outcome == WitnessOutcome.FAIL
        ):
            raise RepairFeedbackIntegrityError(
                "Contradictory execution state: TIMED_OUT termination status cannot collapse "
                "into WitnessOutcome.FAIL"
            )

        # Ensure that if exit_code is None and termination_status is COMPLETED,
        # there is explicit failure indication
        if (
            self.exit_code is None
            and self.termination_status == TerminationStatus.COMPLETED
            and not (self.failure_message and self.failure_message.strip())
            and (self.failing_outcome is None or self.failing_outcome not in VALID_FAILING_OUTCOMES)
        ):
            raise RepairFeedbackIntegrityError(
                "FailedExecutionFacts cannot be constructed without evidence of execution failure."
            )

    @classmethod
    def from_reproduction_receipt(cls, receipt: Any) -> FailedExecutionFacts:
        """Derive failed execution facts from a failed RepairedVerificationReceipt."""
        if receipt is None:
            raise RepairFeedbackIntegrityError(
                "Cannot derive failed execution facts from missing reproduction receipt."
            )
        if getattr(receipt, "grants_pass", False) is True:
            raise RepairFeedbackIntegrityError(
                "Cannot derive failed execution facts from passing reproduction receipt "
                "(grants_pass=True)."
            )
        witness_outcome = getattr(receipt, "witness_outcome", None)
        if witness_outcome is None:
            raise RepairFeedbackIntegrityError(
                "Malformed reproduction receipt: missing witness_outcome."
            )
        outcome_str = getattr(witness_outcome, "value", str(witness_outcome))
        if outcome_str == "PASS" or witness_outcome == WitnessOutcome.PASS:
            raise RepairFeedbackIntegrityError(
                "Cannot derive failed execution facts from passing reproduction receipt "
                "(witness_outcome=PASS)."
            )
        if getattr(receipt, "preliminary_verdict", None) == PreliminaryVerdict.VERIFIED:
            raise RepairFeedbackIntegrityError(
                "Cannot derive failed execution facts from verified reproduction receipt "
                "(preliminary_verdict=VERIFIED)."
            )
        if getattr(receipt, "preliminary_verdict", None) == PreliminaryVerdict.PARTIALLY_VERIFIED:
            raise RepairFeedbackIntegrityError(
                "Cannot derive failed execution facts from partially verified reproduction receipt "
                "(preliminary_verdict=PARTIALLY_VERIFIED)."
            )

        if not isinstance(witness_outcome, WitnessOutcome):
            raise RepairFeedbackIntegrityError(
                f"Reproduction receipt witness_outcome must be a WitnessOutcome instance, "
                f"got {type(witness_outcome).__name__}"
            )
        if witness_outcome not in VALID_FAILING_WITNESS_OUTCOMES:
            raise RepairFeedbackIntegrityError(
                f"Reproduction receipt has unsupported outcome: {witness_outcome!r}"
            )

        exit_code = getattr(receipt, "exit_code", None)
        justification = f"Deterministic reproduction failure outcome validated: {outcome_str}"

        category = FailureConditionCategory.BEHAVIORAL_ASSERTION_FAILED
        if outcome_str in ("TIMEOUT", "ERROR"):
            category = FailureConditionCategory.UNEXPECTED_TERMINATION

        receipt_digest = getattr(receipt, "receipt_digest", None)
        if not receipt_digest or is_dummy_or_invalid_digest(receipt_digest):
            raise RepairFeedbackIntegrityError(
                f"Reproduction receipt has missing or dummy receipt_digest: {receipt_digest!r}"
            )

        sandbox_id = getattr(receipt, "sandbox_id", None)
        if not sandbox_id or not str(sandbox_id).strip():
            raise RepairFeedbackIntegrityError(
                f"Reproduction receipt has missing or empty sandbox_id: {sandbox_id!r}"
            )

        return cls(
            exit_code=exit_code,
            failure_message=f"Reproduction outcome: {outcome_str}",
            sandbox_id=sandbox_id,
            execution_digest=receipt_digest,
            condition_category=category,
            duration_seconds=getattr(receipt, "duration_seconds", None),
            deterministic_failure_justification=justification,
            failing_outcome=witness_outcome,
        )

    @classmethod
    def from_witness_result(cls, result: Any) -> FailedExecutionFacts:
        """Derive failed execution facts from a NormalizedWitnessResult."""
        if result is None:
            raise RepairFeedbackIntegrityError(
                "Cannot derive failed execution facts from missing witness result."
            )
        outcome = getattr(result, "outcome", None)
        if outcome is None:
            raise RepairFeedbackIntegrityError(
                "Malformed witness result: missing outcome attribute."
            )
        outcome_str = getattr(outcome, "value", str(outcome))
        if outcome_str == "PASS" or outcome == WitnessOutcome.PASS:
            raise RepairFeedbackIntegrityError(
                f"Cannot derive failed execution facts from successful witness result "
                f"(outcome={outcome_str})."
            )

        if not isinstance(outcome, WitnessOutcome):
            raise RepairFeedbackIntegrityError(
                f"Witness result outcome must be a WitnessOutcome instance, "
                f"got {type(outcome).__name__}"
            )
        if outcome not in VALID_FAILING_WITNESS_OUTCOMES:
            raise RepairFeedbackIntegrityError(
                f"Witness result has unsupported outcome: {outcome!r}"
            )

        exit_code = getattr(result, "exit_code", None)
        justification = f"Deterministic witness failure outcome validated: {outcome_str}"

        category = FailureConditionCategory.BEHAVIORAL_ASSERTION_FAILED
        if outcome_str in ("TIMEOUT", "ERROR"):
            category = FailureConditionCategory.UNEXPECTED_TERMINATION
        term_status = getattr(result, "termination_status", TerminationStatus.COMPLETED)

        result_digest = getattr(result, "result_digest", None)
        if not result_digest or is_dummy_or_invalid_digest(result_digest):
            raise RepairFeedbackIntegrityError(
                f"Witness result has missing or dummy result_digest: {result_digest!r}"
            )

        sandbox_id = getattr(result, "sandbox_id", None)
        if not sandbox_id or not str(sandbox_id).strip():
            raise RepairFeedbackIntegrityError(
                f"Witness result has missing or empty sandbox_id: {sandbox_id!r}"
            )

        return cls(
            exit_code=exit_code,
            termination_status=term_status,
            failure_message=f"Witness outcome: {outcome_str}",
            sandbox_id=sandbox_id,
            execution_digest=result_digest,
            condition_category=category,
            duration_seconds=getattr(result, "duration_seconds", None),
            deterministic_failure_justification=justification,
            failing_outcome=outcome,
        )

    @classmethod
    def from_execution(
        cls,
        *,
        exit_code: int | None,
        failure_indicator: str = "",
        sandbox_id: str | None = None,
        execution_digest: str | None = None,
        condition_category: FailureConditionCategory = (
            FailureConditionCategory.BEHAVIORAL_ASSERTION_FAILED
        ),
        duration_seconds: float | None = None,
        counterexample_input: str | None = None,
        counterexample_actual: str | None = None,
        counterexample_expected: str | None = None,
        termination_status: TerminationStatus = TerminationStatus.COMPLETED,
        deterministic_failure_justification: str | None = None,
        failing_outcome: WitnessOutcome | PreliminaryVerdict | None = None,
    ) -> FailedExecutionFacts:
        if exit_code == 0:
            if failing_outcome is None:
                raise RepairFeedbackIntegrityError(
                    "Cannot derive failed execution facts from successful execution (exit_code=0) "
                    "without a genuine validated deterministic failing outcome "
                    "(WitnessOutcome or PreliminaryVerdict). "
                    "Free-form justification text cannot authorize repair."
                )
            if not isinstance(failing_outcome, (WitnessOutcome, PreliminaryVerdict)):
                raise RepairFeedbackIntegrityError(
                    "failing_outcome must be a typed WitnessOutcome or PreliminaryVerdict enum "
                    f"instance, got {type(failing_outcome).__name__} ({failing_outcome!r}). "
                    "Arbitrary strings and fabricated outcome names cannot authorize repair."
                )
            if failing_outcome in FORBIDDEN_PASSING_OUTCOMES:
                raise RepairFeedbackIntegrityError(
                    f"Passing or partially passing outcome {failing_outcome.value!r} "
                    "cannot justify failed execution."
                )
            if failing_outcome == PreliminaryVerdict.NOT_RUN:
                raise RepairFeedbackIntegrityError(
                    "Non-execution verdict NOT_RUN cannot justify failed execution."
                )
            if failing_outcome not in VALID_FAILING_OUTCOMES:
                raise RepairFeedbackIntegrityError(
                    f"Unsupported outcome {failing_outcome!r} cannot justify failed execution."
                )
            if execution_digest is None or is_dummy_or_invalid_digest(execution_digest):
                raise RepairFeedbackIntegrityError(
                    "exit_code=0 requires a valid execution_digest bound to the "
                    f"deterministic failing outcome, got {execution_digest!r}"
                )

        if (
            exit_code is None
            and termination_status == TerminationStatus.COMPLETED
            and not (failure_indicator and failure_indicator.strip())
            and (failing_outcome is None or failing_outcome not in VALID_FAILING_OUTCOMES)
        ):
            raise RepairFeedbackIntegrityError(
                "Cannot derive failed execution facts without non-zero exit code or "
                "failure indicator or validated deterministic failing outcome."
            )
        if execution_digest is not None and is_dummy_or_invalid_digest(execution_digest):
            raise RepairFeedbackIntegrityError(
                f"execution_digest cannot be dummy or invalid: {execution_digest!r}"
            )
        return cls(
            exit_code=exit_code,
            termination_status=termination_status,
            failure_message=failure_indicator,
            sandbox_id=sandbox_id,
            execution_digest=execution_digest,
            condition_category=condition_category,
            duration_seconds=duration_seconds,
            counterexample_input=counterexample_input,
            counterexample_actual=counterexample_actual,
            counterexample_expected=counterexample_expected,
            deterministic_failure_justification=deterministic_failure_justification,
            failing_outcome=failing_outcome,
        )


@dataclass(frozen=True, slots=True)
class SanitizedCounterexample:
    """Bounded, sanitized counterexample details safe for Builder disclosure.

    Contains no witness code, no private assertion code, no secret values, and no
    verifier internal paths.
    """

    input_summary: str
    expected_output_summary: str
    actual_output_summary: str
    input_category: str = ""
    exit_code: int | None = None
    is_sanitized: bool = True
    classification: DisclosureClassification = DisclosureClassification.SAFE_TO_DISCLOSE

    def __post_init__(self) -> None:
        _validate_non_empty_str(self.input_summary, "input_summary")
        _validate_non_empty_str(self.expected_output_summary, "expected_output_summary")
        _validate_non_empty_str(self.actual_output_summary, "actual_output_summary")
        if not isinstance(self.input_category, str):
            raise TypeError(f"input_category must be str, got {type(self.input_category).__name__}")
        if self.exit_code is not None and not isinstance(self.exit_code, int):
            raise TypeError(f"exit_code must be int or None, got {type(self.exit_code).__name__}")
        if not self.is_sanitized:
            raise RepairFeedbackDisclosureError(
                "SanitizedCounterexample cannot have is_sanitized=False"
            )
        if self.classification != DisclosureClassification.SAFE_TO_DISCLOSE:
            cls_name = self.classification.value
            raise RepairFeedbackDisclosureError(
                f"SanitizedCounterexample classification must be SAFE_TO_DISCLOSE, got {cls_name}"
            )

    def to_canonical_dict(self) -> dict[str, Any]:
        """Convert to canonical dictionary representation for hashing."""
        return {
            "actual_output_summary": self.actual_output_summary,
            "classification": self.classification.value,
            "exit_code": self.exit_code,
            "expected_output_summary": self.expected_output_summary,
            "input_category": self.input_category,
            "input_summary": self.input_summary,
            "is_sanitized": self.is_sanitized,
        }


@dataclass(frozen=True, slots=True)
class SafeRepairFeedback:
    """Bounded failure feedback emitted by verifier to guide Builder repair.

    Possesses ZERO verdict authority and cannot grant verification or PASS.
    """

    feedback_id: str
    candidate_id: str
    requirement_id: str
    change_class: ChangeClass
    failed_condition: FailureConditionCategory
    observed_behavior: str
    expected_behavior: str
    permitted_patch_region: tuple[str, ...]
    provenance: EvidenceProvenance
    originating_receipt_digest: str
    feedback_round: int
    feedback_digest: str
    counterexample: SanitizedCounterexample | None = None
    schema_version: str = REPAIR_FEEDBACK_SCHEMA_VERSION
    is_authoritative: bool = False
    grants_pass: bool = False
    is_causally_verified: bool = False
    disclosure_classification: DisclosureClassification = DisclosureClassification.SAFE_TO_DISCLOSE

    def __post_init__(self) -> None:
        _validate_non_empty_str(self.feedback_id, "feedback_id")
        _validate_non_empty_str(self.candidate_id, "candidate_id")
        _validate_non_empty_str(self.requirement_id, "requirement_id")
        if not isinstance(self.change_class, ChangeClass):
            raise TypeError(
                f"change_class must be ChangeClass, got {type(self.change_class).__name__}"
            )
        if not isinstance(self.failed_condition, FailureConditionCategory):
            fc_type = type(self.failed_condition).__name__
            raise TypeError(f"failed_condition must be FailureConditionCategory, got {fc_type}")
        _validate_non_empty_str(self.observed_behavior, "observed_behavior")
        _validate_non_empty_str(self.expected_behavior, "expected_behavior")

        if not isinstance(self.permitted_patch_region, tuple):
            if isinstance(self.permitted_patch_region, Sequence):
                object.__setattr__(
                    self, "permitted_patch_region", tuple(self.permitted_patch_region)
                )
            else:
                seq_type = type(self.permitted_patch_region).__name__
                raise TypeError(
                    f"permitted_patch_region must be a sequence of strings, got {seq_type}"
                )
        for path in self.permitted_patch_region:
            _validate_non_empty_str(path, "permitted_patch_region element")

        if not isinstance(self.provenance, EvidenceProvenance):
            raise TypeError(
                f"provenance must be EvidenceProvenance, got {type(self.provenance).__name__}"
            )
        _validate_hex_digest(self.originating_receipt_digest, "originating_receipt_digest")

        if not isinstance(self.feedback_round, int) or self.feedback_round < 1:
            raise RepairFeedbackIntegrityError(
                f"feedback_round must be a positive integer, got {self.feedback_round!r}"
            )

        _validate_hex_digest(self.feedback_digest, "feedback_digest")

        if self.counterexample is not None and not isinstance(
            self.counterexample, SanitizedCounterexample
        ):
            ce_type = type(self.counterexample).__name__
            raise TypeError(
                f"counterexample must be SanitizedCounterexample or None, got {ce_type}"
            )

        # STRICT ZERO-AUTHORITY ENFORCEMENT
        if self.is_authoritative:
            raise RepairFeedbackAuthorityError(
                "SafeRepairFeedback cannot have is_authoritative=True; feedback has zero authority"
            )
        if self.grants_pass:
            raise RepairFeedbackAuthorityError(
                "SafeRepairFeedback cannot have grants_pass=True; feedback cannot grant pass"
            )
        if self.is_causally_verified:
            raise RepairFeedbackAuthorityError(
                "SafeRepairFeedback cannot have is_causally_verified=True"
            )
        if self.disclosure_classification != DisclosureClassification.SAFE_TO_DISCLOSE:
            cls_name = self.disclosure_classification.value
            raise RepairFeedbackDisclosureError(
                f"SafeRepairFeedback must have SAFE_TO_DISCLOSE classification, got {cls_name}"
            )


def build_canonical_repair_feedback_payload(
    *,
    schema_version: str,
    feedback_id: str,
    candidate_id: str,
    requirement_id: str,
    change_class: ChangeClass,
    failed_condition: FailureConditionCategory,
    observed_behavior: str,
    expected_behavior: str,
    permitted_patch_region: tuple[str, ...],
    provenance: EvidenceProvenance,
    originating_receipt_digest: str,
    feedback_round: int,
    counterexample: SanitizedCounterexample | None = None,
    disclosure_classification: DisclosureClassification = (
        DisclosureClassification.SAFE_TO_DISCLOSE
    ),
    is_authoritative: bool = False,
    grants_pass: bool = False,
    is_causally_verified: bool = False,
) -> dict[str, Any]:
    """Construct deterministic canonical payload dictionary for repair feedback hashing."""
    ce_dict = counterexample.to_canonical_dict() if counterexample is not None else None
    return {
        "candidate_id": candidate_id,
        "change_class": change_class.value,
        "counterexample": ce_dict,
        "disclosure_classification": disclosure_classification.value,
        "expected_behavior": expected_behavior,
        "failed_condition": failed_condition.value,
        "feedback_id": feedback_id,
        "feedback_round": feedback_round,
        "grants_pass": grants_pass,
        "is_authoritative": is_authoritative,
        "is_causally_verified": is_causally_verified,
        "observed_behavior": observed_behavior,
        "originating_receipt_digest": originating_receipt_digest,
        "permitted_patch_region": sorted(permitted_patch_region),
        "provenance": provenance.value,
        "requirement_id": requirement_id,
        "schema_version": schema_version,
    }


def compute_repair_feedback_digest(payload: Mapping[str, Any]) -> str:
    """Compute deterministic SHA-256 digest from canonical JSON representation."""
    canonical_json = json.dumps(
        payload,
        ensure_ascii=False,
        sort_keys=True,
        separators=(",", ":"),
    )
    return hashlib.sha256(canonical_json.encode("utf-8")).hexdigest()


def create_safe_repair_feedback(
    *,
    feedback_id: str,
    candidate_id: str,
    requirement_id: str,
    change_class: ChangeClass,
    failed_condition: FailureConditionCategory,
    observed_behavior: str,
    expected_behavior: str,
    originating_receipt_digest: str,
    feedback_round: int,
    provenance: EvidenceProvenance,
    permitted_patch_region: Sequence[str] = (),
    counterexample: SanitizedCounterexample | None = None,
) -> SafeRepairFeedback:
    """Deterministic factory constructing a SafeRepairFeedback with verified digest."""
    sorted_permitted = tuple(sorted(permitted_patch_region))

    payload = build_canonical_repair_feedback_payload(
        schema_version=REPAIR_FEEDBACK_SCHEMA_VERSION,
        feedback_id=feedback_id,
        candidate_id=candidate_id,
        requirement_id=requirement_id,
        change_class=change_class,
        failed_condition=failed_condition,
        observed_behavior=observed_behavior,
        expected_behavior=expected_behavior,
        permitted_patch_region=sorted_permitted,
        provenance=provenance,
        originating_receipt_digest=originating_receipt_digest,
        feedback_round=feedback_round,
        counterexample=counterexample,
        disclosure_classification=DisclosureClassification.SAFE_TO_DISCLOSE,
        is_authoritative=False,
        grants_pass=False,
        is_causally_verified=False,
    )
    digest = compute_repair_feedback_digest(payload)

    return SafeRepairFeedback(
        feedback_id=feedback_id,
        candidate_id=candidate_id,
        requirement_id=requirement_id,
        change_class=change_class,
        failed_condition=failed_condition,
        observed_behavior=observed_behavior,
        expected_behavior=expected_behavior,
        permitted_patch_region=sorted_permitted,
        provenance=provenance,
        originating_receipt_digest=originating_receipt_digest,
        feedback_round=feedback_round,
        feedback_digest=digest,
        counterexample=counterexample,
        schema_version=REPAIR_FEEDBACK_SCHEMA_VERSION,
        is_authoritative=False,
        grants_pass=False,
        is_causally_verified=False,
        disclosure_classification=DisclosureClassification.SAFE_TO_DISCLOSE,
    )


def verify_repair_feedback_integrity(feedback: SafeRepairFeedback) -> bool:
    """Verify cryptographic integrity and authority boundaries of repair feedback.

    Fails closed (returns False or raises exception on tampering/authority violations).
    """
    if feedback.is_authoritative or feedback.grants_pass or feedback.is_causally_verified:
        raise RepairFeedbackAuthorityError("Repair feedback cannot possess verdict authority")

    if feedback.disclosure_classification != DisclosureClassification.SAFE_TO_DISCLOSE:
        return False

    payload = build_canonical_repair_feedback_payload(
        schema_version=feedback.schema_version,
        feedback_id=feedback.feedback_id,
        candidate_id=feedback.candidate_id,
        requirement_id=feedback.requirement_id,
        change_class=feedback.change_class,
        failed_condition=feedback.failed_condition,
        observed_behavior=feedback.observed_behavior,
        expected_behavior=feedback.expected_behavior,
        permitted_patch_region=feedback.permitted_patch_region,
        provenance=feedback.provenance,
        originating_receipt_digest=feedback.originating_receipt_digest,
        feedback_round=feedback.feedback_round,
        counterexample=feedback.counterexample,
        disclosure_classification=feedback.disclosure_classification,
        is_authoritative=feedback.is_authoritative,
        grants_pass=feedback.grants_pass,
        is_causally_verified=feedback.is_causally_verified,
    )
    computed_digest = compute_repair_feedback_digest(payload)
    if feedback.feedback_digest != computed_digest:
        raise RepairFeedbackTamperingError(
            f"Feedback digest mismatch: recorded {feedback.feedback_digest!r} "
            f"!= computed {computed_digest!r}"
        )
    return True


def derive_safe_repair_feedback(
    *,
    candidate_id: str,
    requirement_id: str,
    change_class: ChangeClass,
    failed_facts: FailedExecutionFacts,
    sanitizer: Any,
    originating_receipt_digest: str,
    feedback_round: int,
    permitted_patch_region: Sequence[str] = (),
    provenance: EvidenceProvenance,
    requirement_statement: str | None = None,
) -> SafeRepairFeedback:
    """Derive bounded, sanitized failure feedback from actual failed execution facts.

    Enforces:
    1. Originates strictly from deterministic execution facts (exit_code, status,
       sanitized failure indicator).
    2. Originating execution identity and receipt digest are bound and traceable.
    3. Hidden witness source, assertion text, private paths, and vault data are
       sanitized and inaccessible.
    4. Missing counterexample evidence is NEVER fabricated (counterexample=None).
    5. Zero verdict authority (is_authoritative=False, grants_pass=False).
    """
    if is_dummy_or_invalid_digest(originating_receipt_digest):
        raise RepairFeedbackIntegrityError(
            f"originating_receipt_digest must be a valid genuine hex digest, "
            f"got {originating_receipt_digest!r}"
        )

    if not isinstance(failed_facts, FailedExecutionFacts):
        raise TypeError(
            f"failed_facts must be a FailedExecutionFacts instance, "
            f"got {type(failed_facts).__name__}"
        )

    if failed_facts.execution_digest is not None:
        if is_dummy_or_invalid_digest(failed_facts.execution_digest):
            raise RepairFeedbackIntegrityError(
                f"failed_facts.execution_digest cannot be dummy or invalid: "
                f"{failed_facts.execution_digest!r}"
            )
        if failed_facts.execution_digest != originating_receipt_digest:
            raise RepairFeedbackIntegrityError(
                f"Mismatched execution identity: failed_facts.execution_digest "
                f"({failed_facts.execution_digest!r}) != originating_receipt_digest "
                f"({originating_receipt_digest!r})"
            )

    if failed_facts.exit_code == 0:
        if (
            failed_facts.failing_outcome is None
            or failed_facts.failing_outcome not in VALID_FAILING_OUTCOMES
        ):
            raise RepairFeedbackIntegrityError(
                "Cannot derive repair feedback from execution with exit_code=0 "
                "without a validated deterministic failing outcome bound to execution identity."
            )
        if failed_facts.execution_digest is None or is_dummy_or_invalid_digest(
            failed_facts.execution_digest
        ):
            raise RepairFeedbackIntegrityError(
                "Cannot derive repair feedback from execution with exit_code=0 "
                "without a valid execution_digest bound to the deterministic failing outcome."
            )

    # 1. Derive observed behavior from actual execution facts
    if failed_facts.exit_code == 0:
        cond_category = failed_facts.condition_category
        assert failed_facts.failing_outcome is not None
        outcome_val = (
            failed_facts.failing_outcome.value
            if hasattr(failed_facts.failing_outcome, "value")
            else str(failed_facts.failing_outcome)
        )
        detail = (
            f" ({failed_facts.deterministic_failure_justification.strip()})"
            if failed_facts.deterministic_failure_justification
            else ""
        )
        raw_observed = (
            "Execution exited 0 with validated deterministic failing outcome: "
            f"{outcome_val}{detail}"
        )
    elif failed_facts.termination_status == TerminationStatus.TIMED_OUT:
        cond_category = FailureConditionCategory.UNEXPECTED_TERMINATION
        dur_info = (
            f" after {failed_facts.duration_seconds:.2f}s"
            if failed_facts.duration_seconds is not None
            else ""
        )
        raw_observed = f"Execution timed out{dur_info} (status=TIMED_OUT)"
    elif failed_facts.exit_code is not None:
        cond_category = failed_facts.condition_category
        detail = f" with {failed_facts.failure_message}" if failed_facts.failure_message else ""
        raw_observed = f"Execution failed with non-zero exit code {failed_facts.exit_code}{detail}"
    else:
        cond_category = failed_facts.condition_category
        detail = f" with {failed_facts.failure_message}" if failed_facts.failure_message else ""
        raw_observed = (
            f"Execution failed with status {failed_facts.termination_status.value}{detail}"
        )

    # 2. Derive expected behavior from requirement/contract
    if requirement_statement and requirement_statement.strip():
        raw_expected = (
            f"Process must exit with status 0 satisfying requirement: "
            f"{requirement_statement.strip()}"
        )
    else:
        raw_expected = "Process must exit with status 0 satisfying specification"

    # 3. Mechanically sanitize observed and expected text
    san_observed = sanitizer.sanitize_text(raw_observed)
    san_expected = sanitizer.sanitize_text(raw_expected)

    # 4. Handle counterexample without fabrication
    ce: SanitizedCounterexample | None = None
    if (
        failed_facts.counterexample_input is not None
        and failed_facts.counterexample_actual is not None
        and failed_facts.counterexample_expected is not None
        and failed_facts.counterexample_input.strip()
        and failed_facts.counterexample_actual.strip()
        and failed_facts.counterexample_expected.strip()
    ):
        san_input = sanitizer.sanitize_text(failed_facts.counterexample_input.strip())
        san_actual = sanitizer.sanitize_text(failed_facts.counterexample_actual.strip())
        san_expected_out = sanitizer.sanitize_text(failed_facts.counterexample_expected.strip())
        ce = SanitizedCounterexample(
            input_summary=san_input,
            actual_output_summary=san_actual,
            expected_output_summary=san_expected_out,
            exit_code=failed_facts.exit_code,
        )

    # 5. Bind execution identity / digest to genuine originating receipt digest
    effective_orig_digest = originating_receipt_digest

    feedback_id = f"FB-R{feedback_round}-{uuid.uuid4().hex[:8]}"
    feedback = create_safe_repair_feedback(
        feedback_id=feedback_id,
        candidate_id=candidate_id,
        requirement_id=requirement_id,
        change_class=change_class,
        failed_condition=cond_category,
        observed_behavior=san_observed,
        expected_behavior=san_expected,
        originating_receipt_digest=effective_orig_digest,
        feedback_round=feedback_round,
        provenance=provenance,
        permitted_patch_region=list(permitted_patch_region),
        counterexample=ce,
    )
    verify_repair_feedback_integrity(feedback)
    return feedback
