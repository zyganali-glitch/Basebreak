"""Tests for P-15.02: Risk-adaptive verification depth mapping."""

from __future__ import annotations

import pytest

from basebreak.budget.depth_policy import (
    DEPTH_POLICY_SCHEMA_VERSION,
    DepthPolicyTamperingError,
    InvalidDepthPolicyError,
    VerificationAction,
    VerificationDepth,
    resolve_verification_depth,
    verify_verification_depth_integrity,
)
from basebreak.budget.risk_features import (
    RiskClassification,
    RiskFeatureSet,
    RiskLevel,
    classify_risk,
    extract_risk_features,
)
from basebreak.compiler.semantics import ChangeClass


@pytest.mark.parametrize("change_class", list(ChangeClass))
@pytest.mark.parametrize("risk_level", list(RiskLevel))
def test_policy_matrix_all_classes_and_levels(
    change_class: ChangeClass, risk_level: RiskLevel
) -> None:
    """Every combination of (ChangeClass, RiskLevel) must produce a valid VerificationDepth.

    Core Invariant: BASE_EXECUTION and CANDIDATE_EXECUTION are strictly MANDATORY in every case.
    """
    # Create synthetic classification for this combination
    features = RiskFeatureSet(
        change_class=change_class,
        changed_files_count=1
        if risk_level == RiskLevel.LOW
        else (4 if risk_level == RiskLevel.MEDIUM else 12),
    )
    raw_classification = classify_risk(features)

    # Force the specific target risk level for the test cell
    synth_classification = RiskClassification(
        schema_version=raw_classification.schema_version,
        risk_level=risk_level,
        features=features,
        elevation_reasons=raw_classification.elevation_reasons,
        classification_digest=raw_classification.classification_digest,
        is_authoritative=False,
    )

    depth = resolve_verification_depth(synth_classification)
    assert depth.schema_version == DEPTH_POLICY_SCHEMA_VERSION
    assert depth.risk_level == risk_level
    assert depth.change_class == change_class

    # Basebreak Thesis Invariant: Two-world execution is ALWAYS mandatory
    assert VerificationAction.BASE_EXECUTION in depth.mandatory_actions
    assert VerificationAction.CANDIDATE_EXECUTION in depth.mandatory_actions

    # Minimum resource requirements
    assert depth.min_sandboxes_required >= 2
    assert depth.min_verifier_executions_required >= 2

    # Cryptographic integrity check
    verify_verification_depth_integrity(depth)


def test_semantic_specific_mandatory_actions() -> None:
    """Semantic-specific verification requirements must be strictly preserved across all levels."""
    for level in (RiskLevel.LOW, RiskLevel.MEDIUM, RiskLevel.HIGH):
        # REFACTOR requires EQUIVALENCE_VERIFICATION
        ref_feat = RiskFeatureSet(change_class=ChangeClass.REFACTOR)
        ref_class = RiskClassification(
            schema_version=DEPTH_POLICY_SCHEMA_VERSION,
            risk_level=level,
            features=ref_feat,
            elevation_reasons=("Test",),
            classification_digest="0" * 64,
            is_authoritative=False,
        )
        ref_depth = resolve_verification_depth(ref_class)
        assert VerificationAction.EQUIVALENCE_VERIFICATION in ref_depth.mandatory_actions

        # PERFORMANCE requires PERFORMANCE_MEASUREMENT
        perf_feat = RiskFeatureSet(change_class=ChangeClass.PERFORMANCE)
        perf_class = RiskClassification(
            schema_version=DEPTH_POLICY_SCHEMA_VERSION,
            risk_level=level,
            features=perf_feat,
            elevation_reasons=("Test",),
            classification_digest="0" * 64,
            is_authoritative=False,
        )
        perf_depth = resolve_verification_depth(perf_class)
        assert VerificationAction.PERFORMANCE_MEASUREMENT in perf_depth.mandatory_actions

        # DEP_API_CHANGE requires DEPENDENCY_MIGRATION_CHECK
        dep_feat = RiskFeatureSet(change_class=ChangeClass.DEP_API_CHANGE)
        dep_class = RiskClassification(
            schema_version=DEPTH_POLICY_SCHEMA_VERSION,
            risk_level=level,
            features=dep_feat,
            elevation_reasons=("Test",),
            classification_digest="0" * 64,
            is_authoritative=False,
        )
        dep_depth = resolve_verification_depth(dep_class)
        assert VerificationAction.DEPENDENCY_MIGRATION_CHECK in dep_depth.mandatory_actions


def test_depth_monotonicity_across_risk_levels() -> None:
    """For any change class, HIGH risk must require >= mandatory checks than LOW/MEDIUM."""
    for cc in ChangeClass:
        feats = RiskFeatureSet(change_class=cc)
        depths = {}
        for level in (RiskLevel.LOW, RiskLevel.MEDIUM, RiskLevel.HIGH):
            classification = RiskClassification(
                schema_version=DEPTH_POLICY_SCHEMA_VERSION,
                risk_level=level,
                features=feats,
                elevation_reasons=("Test",),
                classification_digest="0" * 64,
                is_authoritative=False,
            )
            depths[level] = resolve_verification_depth(classification)

        low = depths[RiskLevel.LOW]
        med = depths[RiskLevel.MEDIUM]
        high = depths[RiskLevel.HIGH]

        # Mandatory actions subset property: low <= med <= high
        assert set(low.mandatory_actions).issubset(set(med.mandatory_actions))
        assert set(med.mandatory_actions).issubset(set(high.mandatory_actions))

        # Resource ceilings monotonicity
        assert (
            low.min_sandboxes_required <= med.min_sandboxes_required <= high.min_sandboxes_required
        )
        assert (
            low.min_verifier_executions_required
            <= med.min_verifier_executions_required
            <= high.min_verifier_executions_required
        )


def test_skipped_checks_tracking() -> None:
    """When optional checks are skipped in low risk, they must be recorded with clear rationale."""
    feats = extract_risk_features(
        change_class=ChangeClass.BUG_FIX,
        changed_files=("src/calc.py",),
    )
    classification = classify_risk(feats)
    assert classification.risk_level == RiskLevel.LOW

    depth = resolve_verification_depth(classification, allow_optional_checks=False)
    assert len(depth.skipped_optional_checks) > 0
    skipped = depth.skipped_optional_checks[0]
    assert skipped.action == VerificationAction.COUNTERFACTUAL_EXECUTION
    assert "conserve budget" in skipped.reason


def test_tamper_detection_on_depth() -> None:
    """Tampering with VerificationDepth fields or digest must raise DepthPolicyTamperingError."""
    feats = extract_risk_features(change_class=ChangeClass.BUG_FIX, changed_files=("src/calc.py",))
    classification = classify_risk(feats)
    depth = resolve_verification_depth(classification)

    tampered = VerificationDepth(
        schema_version=depth.schema_version,
        risk_level=depth.risk_level,
        change_class=depth.change_class,
        depth_name=depth.depth_name,
        mandatory_actions=depth.mandatory_actions,
        optional_actions=depth.optional_actions,
        budget_dependent_actions=depth.budget_dependent_actions,
        skipped_optional_checks=depth.skipped_optional_checks,
        min_sandboxes_required=depth.min_sandboxes_required,
        min_verifier_executions_required=depth.min_verifier_executions_required,
        rationale=depth.rationale,
        depth_digest="b" * 64,  # Corrupt digest
    )

    with pytest.raises(DepthPolicyTamperingError, match="digest mismatch"):
        verify_verification_depth_integrity(tampered)


def test_invalid_depth_construction() -> None:
    """Missing BASE/CANDIDATE executions or invalid bounds must fail closed."""
    # Omitting BASE_EXECUTION
    with pytest.raises(InvalidDepthPolicyError, match="BASE_EXECUTION is strictly mandatory"):
        VerificationDepth(
            schema_version=DEPTH_POLICY_SCHEMA_VERSION,
            risk_level=RiskLevel.LOW,
            change_class=ChangeClass.BUG_FIX,
            depth_name="INVALID",
            mandatory_actions=(VerificationAction.CANDIDATE_EXECUTION,),
            optional_actions=(),
            budget_dependent_actions=(),
            skipped_optional_checks=(),
            min_sandboxes_required=2,
            min_verifier_executions_required=2,
            rationale="Test",
            depth_digest="0" * 64,
        )

    # Omitting CANDIDATE_EXECUTION
    with pytest.raises(InvalidDepthPolicyError, match="CANDIDATE_EXECUTION is strictly mandatory"):
        VerificationDepth(
            schema_version=DEPTH_POLICY_SCHEMA_VERSION,
            risk_level=RiskLevel.LOW,
            change_class=ChangeClass.BUG_FIX,
            depth_name="INVALID",
            mandatory_actions=(VerificationAction.BASE_EXECUTION,),
            optional_actions=(),
            budget_dependent_actions=(),
            skipped_optional_checks=(),
            min_sandboxes_required=2,
            min_verifier_executions_required=2,
            rationale="Test",
            depth_digest="0" * 64,
        )

    # Sandbox count < 2
    with pytest.raises(InvalidDepthPolicyError, match="min_sandboxes_required must be >= 2"):
        VerificationDepth(
            schema_version=DEPTH_POLICY_SCHEMA_VERSION,
            risk_level=RiskLevel.LOW,
            change_class=ChangeClass.BUG_FIX,
            depth_name="INVALID",
            mandatory_actions=(
                VerificationAction.BASE_EXECUTION,
                VerificationAction.CANDIDATE_EXECUTION,
            ),
            optional_actions=(),
            budget_dependent_actions=(),
            skipped_optional_checks=(),
            min_sandboxes_required=1,
            min_verifier_executions_required=2,
            rationale="Test",
            depth_digest="0" * 64,
        )
