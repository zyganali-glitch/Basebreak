"""Risk-Adaptive Verification Budget package for Basebreak.

P-15: Risk-Adaptive Verification Budget implementation:
- P-15.01: Deterministic risk features and policy levels
  (RiskLevel, RiskFeatureSet, RiskClassification)
- P-15.02: Risk-adaptive verification depth mapping
  (VerificationAction, VerificationDepth, resolve_verification_depth)
- P-15.03: Cost, token, and sandbox budget accounting
  (ResourceLimits, ResourceConsumption, BudgetLedger, FinancialCostEstimate)
- P-15.04: Mandatory counterrun and slicing policy
  (MandatoryVerificationObligations, resolve_mandatory_obligations)
- P-15.05: Fail-closed budget admission and exhaustion handling
  (BudgetGateStatus, BudgetGateResult, preflight_budget_admission, handle_budget_exhaustion)
"""

from __future__ import annotations

from basebreak.budget.accounting import (
    ACCOUNTING_SCHEMA_VERSION,
    AccountingError,
    BudgetExhaustedError,
    BudgetLedger,
    DuplicateOperationError,
    FinancialCostEstimate,
    InvalidAccountingValueError,
    ReservationError,
    ReservationStatus,
    ResourceConsumption,
    ResourceLimits,
    ResourceReservation,
)
from basebreak.budget.depth_policy import (
    DEPTH_POLICY_SCHEMA_VERSION,
    DepthPolicyError,
    DepthPolicyTamperingError,
    InvalidDepthPolicyError,
    SkippedCheckRecord,
    VerificationAction,
    VerificationDepth,
    compute_depth_digest,
    resolve_verification_depth,
    verify_verification_depth_integrity,
)
from basebreak.budget.fail_closed import (
    FAIL_CLOSED_SCHEMA_VERSION,
    BudgetGateResult,
    BudgetGateStatus,
    BudgetGateTamperingError,
    FailClosedError,
    InvalidGateInputError,
    UnexecutedObligation,
    calculate_minimum_required_resources,
    compute_gate_digest,
    handle_budget_exhaustion,
    preflight_budget_admission,
    verify_budget_gate_result_integrity,
)
from basebreak.budget.mandatory_policy import (
    MANDATORY_POLICY_SCHEMA_VERSION,
    InvalidMandatoryPolicyInputError,
    MandatoryObligationViolationError,
    MandatoryPolicyError,
    MandatoryPolicyTamperingError,
    MandatoryVerificationObligations,
    compute_mandatory_digest,
    resolve_mandatory_obligations,
    validate_executed_obligations,
    verify_mandatory_obligations_integrity,
)
from basebreak.budget.risk_features import (
    RISK_POLICY_SCHEMA_VERSION,
    InvalidRiskInputError,
    RiskClassification,
    RiskFeatureError,
    RiskFeatureSet,
    RiskLevel,
    RiskTamperingError,
    canonical_risk_bytes,
    classify_risk,
    compute_risk_digest,
    extract_risk_features,
    extract_risk_features_from_contract,
    is_dependency_path,
    is_public_api_path,
    is_security_sensitive_path,
    verify_risk_classification_integrity,
)

__all__ = [
    # Schema versions
    "ACCOUNTING_SCHEMA_VERSION",
    "DEPTH_POLICY_SCHEMA_VERSION",
    "FAIL_CLOSED_SCHEMA_VERSION",
    "MANDATORY_POLICY_SCHEMA_VERSION",
    "RISK_POLICY_SCHEMA_VERSION",
    # P-15.01 Risk Features & Levels
    "InvalidRiskInputError",
    "RiskClassification",
    "RiskFeatureError",
    "RiskFeatureSet",
    "RiskLevel",
    "RiskTamperingError",
    "canonical_risk_bytes",
    "classify_risk",
    "compute_risk_digest",
    "extract_risk_features",
    "extract_risk_features_from_contract",
    "is_dependency_path",
    "is_public_api_path",
    "is_security_sensitive_path",
    "verify_risk_classification_integrity",
    # P-15.02 Depth Policy
    "DepthPolicyError",
    "DepthPolicyTamperingError",
    "InvalidDepthPolicyError",
    "SkippedCheckRecord",
    "VerificationAction",
    "VerificationDepth",
    "compute_depth_digest",
    "resolve_verification_depth",
    "verify_verification_depth_integrity",
    # P-15.03 Accounting
    "AccountingError",
    "BudgetExhaustedError",
    "BudgetLedger",
    "DuplicateOperationError",
    "FinancialCostEstimate",
    "InvalidAccountingValueError",
    "ReservationError",
    "ReservationStatus",
    "ResourceConsumption",
    "ResourceLimits",
    "ResourceReservation",
    # P-15.04 Mandatory Policy
    "InvalidMandatoryPolicyInputError",
    "MandatoryObligationViolationError",
    "MandatoryPolicyError",
    "MandatoryPolicyTamperingError",
    "MandatoryVerificationObligations",
    "compute_mandatory_digest",
    "resolve_mandatory_obligations",
    "validate_executed_obligations",
    "verify_mandatory_obligations_integrity",
    # P-15.05 Fail Closed
    "BudgetGateResult",
    "BudgetGateStatus",
    "BudgetGateTamperingError",
    "FailClosedError",
    "InvalidGateInputError",
    "UnexecutedObligation",
    "calculate_minimum_required_resources",
    "compute_gate_digest",
    "handle_budget_exhaustion",
    "preflight_budget_admission",
    "verify_budget_gate_result_integrity",
]
