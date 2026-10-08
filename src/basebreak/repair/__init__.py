"""Sealed repair loop architecture and contracts.

P-14: Sealed Repair Loop.

Provides bounded failure feedback, counterexample sanitization, fresh Builder
repair context isolation, candidate lineage tracking, fresh verifier reproduction,
and budget-capped repair loop orchestration.
"""

from __future__ import annotations

from basebreak.repair.feedback import (
    DisclosureClassification,
    FailureConditionCategory,
    RepairFeedbackAuthorityError,
    RepairFeedbackDisclosureError,
    RepairFeedbackError,
    RepairFeedbackIntegrityError,
    RepairFeedbackTamperingError,
    SafeRepairFeedback,
    SanitizedCounterexample,
    build_canonical_repair_feedback_payload,
    compute_repair_feedback_digest,
    create_safe_repair_feedback,
    verify_repair_feedback_integrity,
)

__all__: list[str] = [
    "DisclosureClassification",
    "FailureConditionCategory",
    "RepairFeedbackAuthorityError",
    "RepairFeedbackDisclosureError",
    "RepairFeedbackError",
    "RepairFeedbackIntegrityError",
    "RepairFeedbackTamperingError",
    "SafeRepairFeedback",
    "SanitizedCounterexample",
    "build_canonical_repair_feedback_payload",
    "compute_repair_feedback_digest",
    "create_safe_repair_feedback",
    "verify_repair_feedback_integrity",
]
