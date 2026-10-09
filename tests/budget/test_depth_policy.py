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
    RiskLevel,
    classify_risk,
    compute_risk_digest,
    extract_risk_features,
)
from basebreak.compiler.semantics import ChangeClass

VALID_POLICY_MATRIX = [
    (ChangeClass.BUG_FIX, RiskLevel.LOW, 1, 10),
    (ChangeClass.BUG_FIX, RiskLevel.MEDIUM, 4, 100),
    (ChangeClass.BUG_FIX, RiskLevel.HIGH, 12, 600),
    (ChangeClass.FEATURE, RiskLevel.LOW, 1, 10),
    (ChangeClass.FEATURE, RiskLevel.MEDIUM, 4, 100),
    (ChangeClass.FEATURE, RiskLevel.HIGH, 12, 600),
    (ChangeClass.REFACTOR, RiskLevel.LOW, 1, 10),
    (ChangeClass.REFACTOR, RiskLevel.MEDIUM, 4, 100),
    (ChangeClass.REFACTOR, RiskLevel.HIGH, 12, 600),
    (ChangeClass.PERFORMANCE, RiskLevel.MEDIUM, 1, 10),
    (ChangeClass.PERFORMANCE, RiskLevel.HIGH, 12, 600),
    (ChangeClass.DEP_API_CHANGE, RiskLevel.MEDIUM, 1, 10),
    (ChangeClass.DEP_API_CHANGE, RiskLevel.HIGH, 12, 600),
    (ChangeClass.SECURITY_FIX, RiskLevel.HIGH, 1, 10),
]


@pytest.mark.parametrize(
    "change_class,target_risk_level,files_count,lines_count",
    VALID_POLICY_MATRIX,
)
def test_policy_matrix_all_classes_and_levels(
    change_class: ChangeClass,
    target_risk_level: RiskLevel,
    files_count: int,
    lines_count: int,
) -> None:
    """Every valid combination of (ChangeClass, RiskLevel) must produce a valid VerificationDepth.

    Core Invariant: BASE_EXECUTION and CANDIDATE_EXECUTION are strictly MANDATORY in every case.
    """
    files = tuple(f"src/file_{i}.py" for i in range(files_count))
    features = extract_risk_features(
        change_class=change_class,
        changed_files=files,
        changed_lines_count=lines_count,
    )
    classification = classify_risk(features)
    assert classification.risk_level == target_risk_level

    depth = resolve_verification_depth(classification)
    assert depth.schema_version == DEPTH_POLICY_SCHEMA_VERSION
    assert depth.risk_level == target_risk_level
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
    # REFACTOR at LOW, MEDIUM, HIGH requires EQUIVALENCE_VERIFICATION
    for fc, lc in [(1, 10), (4, 100), (12, 600)]:
        feats = extract_risk_features(
            change_class=ChangeClass.REFACTOR,
            changed_files=tuple(f"src/file_{i}.py" for i in range(fc)),
            changed_lines_count=lc,
        )
        depth = resolve_verification_depth(classify_risk(feats))
        assert VerificationAction.EQUIVALENCE_VERIFICATION in depth.mandatory_actions

    # PERFORMANCE at MEDIUM, HIGH requires PERFORMANCE_MEASUREMENT
    for fc, lc in [(1, 10), (12, 600)]:
        feats = extract_risk_features(
            change_class=ChangeClass.PERFORMANCE,
            changed_files=tuple(f"src/file_{i}.py" for i in range(fc)),
            changed_lines_count=lc,
        )
        depth = resolve_verification_depth(classify_risk(feats))
        assert VerificationAction.PERFORMANCE_MEASUREMENT in depth.mandatory_actions

    # DEP_API_CHANGE at MEDIUM, HIGH requires DEPENDENCY_MIGRATION_CHECK
    for fc, lc in [(1, 10), (12, 600)]:
        feats = extract_risk_features(
            change_class=ChangeClass.DEP_API_CHANGE,
            changed_files=tuple(f"src/file_{i}.py" for i in range(fc)),
            changed_lines_count=lc,
        )
        depth = resolve_verification_depth(classify_risk(feats))
        assert VerificationAction.DEPENDENCY_MIGRATION_CHECK in depth.mandatory_actions


def test_depth_monotonicity_across_risk_levels() -> None:
    """For any change class, HIGH risk must require >= mandatory checks than LOW/MEDIUM."""
    # Classes spanning LOW, MEDIUM, HIGH
    for cc in (ChangeClass.BUG_FIX, ChangeClass.FEATURE, ChangeClass.REFACTOR):
        d_low = resolve_verification_depth(
            classify_risk(extract_risk_features(change_class=cc, changed_files=("src/calc.py",)))
        )
        d_med = resolve_verification_depth(
            classify_risk(
                extract_risk_features(
                    change_class=cc,
                    changed_files=tuple(f"src/file_{i}.py" for i in range(4)),
                    changed_lines_count=100,
                )
            )
        )
        d_high = resolve_verification_depth(
            classify_risk(
                extract_risk_features(
                    change_class=cc,
                    changed_files=tuple(f"src/file_{i}.py" for i in range(12)),
                    changed_lines_count=600,
                )
            )
        )

        assert set(d_low.mandatory_actions).issubset(set(d_med.mandatory_actions))
        assert set(d_med.mandatory_actions).issubset(set(d_high.mandatory_actions))
        assert (
            d_low.min_sandboxes_required
            <= d_med.min_sandboxes_required
            <= d_high.min_sandboxes_required
        )
        assert (
            d_low.min_verifier_executions_required
            <= d_med.min_verifier_executions_required
            <= d_high.min_verifier_executions_required
        )

    # Classes starting at MEDIUM (PERFORMANCE, DEP_API_CHANGE)
    for cc in (ChangeClass.PERFORMANCE, ChangeClass.DEP_API_CHANGE):
        d_med = resolve_verification_depth(
            classify_risk(extract_risk_features(change_class=cc, changed_files=("src/calc.py",)))
        )
        d_high = resolve_verification_depth(
            classify_risk(
                extract_risk_features(
                    change_class=cc,
                    changed_files=tuple(f"src/file_{i}.py" for i in range(12)),
                    changed_lines_count=600,
                )
            )
        )
        assert set(d_med.mandatory_actions).issubset(set(d_high.mandatory_actions))
        assert d_med.min_sandboxes_required <= d_high.min_sandboxes_required
        assert d_med.min_verifier_executions_required <= d_high.min_verifier_executions_required


def test_adversarial_classification_downgrade_rejected() -> None:
    """Caller-fabricated downgraded risk classification records must fail closed."""
    # 1. SECURITY_FIX downgraded to LOW even when caller computes valid digest for fake record
    sec_features = extract_risk_features(
        change_class=ChangeClass.SECURITY_FIX, changed_files=("src/calc.py",)
    )
    legit_sec = classify_risk(sec_features)
    assert legit_sec.risk_level == RiskLevel.HIGH

    raw_sec_downgrade = {
        "classification_digest": "",
        "elevation_reasons": list(legit_sec.elevation_reasons),
        "features": sec_features.to_dict(),
        "is_authoritative": False,
        "risk_level": RiskLevel.LOW.value,
        "schema_version": legit_sec.schema_version,
    }
    signed_sec_downgrade = RiskClassification(
        schema_version=legit_sec.schema_version,
        risk_level=RiskLevel.LOW,  # Forged downgrade
        features=sec_features,
        elevation_reasons=legit_sec.elevation_reasons,
        classification_digest=compute_risk_digest(raw_sec_downgrade),
        is_authoritative=False,
    )
    with pytest.raises(
        DepthPolicyTamperingError,
        match="Risk level LOW contradicts deterministic derivation HIGH",
    ):
        resolve_verification_depth(signed_sec_downgrade)

    # 2. Corrupt digest without recomputation
    tampered_digest = RiskClassification(
        schema_version=legit_sec.schema_version,
        risk_level=legit_sec.risk_level,
        features=sec_features,
        elevation_reasons=legit_sec.elevation_reasons,
        classification_digest="a" * 64,  # Corrupt digest
        is_authoritative=False,
    )
    with pytest.raises(DepthPolicyTamperingError, match="digest mismatch"):
        resolve_verification_depth(tampered_digest)

    # 3. Large blast radius downgraded to LOW with signed digest
    wide_features = extract_risk_features(
        change_class=ChangeClass.BUG_FIX,
        changed_files=tuple(f"src/file_{i}.py" for i in range(15)),
        changed_lines_count=800,
    )
    legit_wide = classify_risk(wide_features)
    assert legit_wide.risk_level == RiskLevel.HIGH

    raw_wide_downgrade = {
        "classification_digest": "",
        "elevation_reasons": list(legit_wide.elevation_reasons),
        "features": wide_features.to_dict(),
        "is_authoritative": False,
        "risk_level": RiskLevel.LOW.value,
        "schema_version": legit_wide.schema_version,
    }
    signed_wide_downgrade = RiskClassification(
        schema_version=legit_wide.schema_version,
        risk_level=RiskLevel.LOW,
        features=wide_features,
        elevation_reasons=legit_wide.elevation_reasons,
        classification_digest=compute_risk_digest(raw_wide_downgrade),
        is_authoritative=False,
    )
    with pytest.raises(
        DepthPolicyTamperingError,
        match="Risk level LOW contradicts deterministic derivation HIGH",
    ):
        resolve_verification_depth(signed_wide_downgrade)


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
