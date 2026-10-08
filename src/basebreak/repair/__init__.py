"""Sealed repair loop architecture and contracts.

P-14: Sealed Repair Loop.

Provides bounded failure feedback, counterexample sanitization, fresh Builder
repair context isolation, candidate lineage tracking, fresh verifier reproduction,
and budget-capped repair loop orchestration.
"""

from __future__ import annotations

from basebreak.repair.context import (
    BuilderRepairContextEnvelope,
    BuilderRepairContextError,
    RepairContextBudgetExceededError,
    RepairContextMismatchedCandidateError,
    RepairContextMismatchedContractError,
    RepairContextProtectedSurfaceError,
    RepairContextTamperingError,
    VerifierStateLeakError,
    build_canonical_repair_context_payload,
    compute_repair_context_digest,
    create_builder_repair_context,
    verify_builder_repair_context_integrity,
)
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
from basebreak.repair.sanitizer import (
    DisclosureSanitizer,
    DisclosureSanitizerError,
    UnsafeDisclosureError,
)

__all__: list[str] = [
    "BuilderRepairContextEnvelope",
    "BuilderRepairContextError",
    "DisclosureClassification",
    "DisclosureSanitizer",
    "DisclosureSanitizerError",
    "FailureConditionCategory",
    "RepairContextBudgetExceededError",
    "RepairContextMismatchedCandidateError",
    "RepairContextMismatchedContractError",
    "RepairContextProtectedSurfaceError",
    "RepairContextTamperingError",
    "RepairFeedbackAuthorityError",
    "RepairFeedbackDisclosureError",
    "RepairFeedbackError",
    "RepairFeedbackIntegrityError",
    "RepairFeedbackTamperingError",
    "SafeRepairFeedback",
    "SanitizedCounterexample",
    "UnsafeDisclosureError",
    "VerifierStateLeakError",
    "build_canonical_repair_context_payload",
    "build_canonical_repair_feedback_payload",
    "compute_repair_context_digest",
    "compute_repair_feedback_digest",
    "create_builder_repair_context",
    "create_safe_repair_feedback",
    "verify_builder_repair_context_integrity",
    "verify_repair_feedback_integrity",
]
