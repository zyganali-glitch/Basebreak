"""Tests for P-15.01: Deterministic risk features and policy levels."""

from __future__ import annotations

from typing import cast

import pytest

from basebreak.budget.risk_features import (
    RISK_POLICY_SCHEMA_VERSION,
    InvalidRiskInputError,
    RiskClassification,
    RiskFeatureSet,
    RiskLevel,
    RiskTamperingError,
    classify_risk,
    extract_risk_features,
    is_dependency_path,
    is_public_api_path,
    is_security_sensitive_path,
    verify_risk_classification_integrity,
)
from basebreak.compiler.semantics import CertaintyLevel, ChangeClass


def test_risk_level_total_ordering() -> None:
    """RiskLevel must enforce strict total ordering: LOW < MEDIUM < HIGH."""
    assert RiskLevel.LOW < RiskLevel.MEDIUM < RiskLevel.HIGH
    assert RiskLevel.HIGH > RiskLevel.MEDIUM > RiskLevel.LOW
    assert RiskLevel.LOW <= RiskLevel.LOW
    assert RiskLevel.HIGH >= RiskLevel.HIGH
    assert sorted([RiskLevel.HIGH, RiskLevel.LOW, RiskLevel.MEDIUM]) == [
        RiskLevel.LOW,
        RiskLevel.MEDIUM,
        RiskLevel.HIGH,
    ]


def test_risk_feature_set_validation() -> None:
    """RiskFeatureSet must reject negative counts, unsorted tuples, and invalid types."""
    # Negative files count
    with pytest.raises(InvalidRiskInputError, match="changed_files_count"):
        RiskFeatureSet(change_class=ChangeClass.BUG_FIX, changed_files_count=-1)

    # Negative lines count
    with pytest.raises(InvalidRiskInputError, match="changed_lines_count"):
        RiskFeatureSet(change_class=ChangeClass.BUG_FIX, changed_lines_count=-5)

    # Boolean passed as integer count
    with pytest.raises(InvalidRiskInputError, match="changed_files_count"):
        RiskFeatureSet(change_class=ChangeClass.BUG_FIX, changed_files_count=cast(int, True))

    # Invalid change class
    with pytest.raises(InvalidRiskInputError, match="change_class"):
        RiskFeatureSet(change_class="INVALID")  # type: ignore[arg-type]

    # Unsorted touched paths
    with pytest.raises(InvalidRiskInputError, match="sorted without duplicates"):
        RiskFeatureSet(
            change_class=ChangeClass.BUG_FIX,
            touched_paths=("b.py", "a.py"),
        )


def test_path_classifiers() -> None:
    """Path classifier helpers must correctly identify security, dependency, and API files."""
    assert is_security_sensitive_path("src/auth/tokens.py")
    assert is_security_sensitive_path("basebreak/security/sandbox_policy.py")
    assert is_security_sensitive_path("crypto/certs.pem")
    assert not is_security_sensitive_path("src/demo/calculator.py")

    assert is_dependency_path("requirements.txt")
    assert is_dependency_path("pyproject.toml")
    assert is_dependency_path("package.json")
    assert not is_dependency_path("src/main.py")

    assert is_public_api_path("src/__init__.py")
    assert is_public_api_path("src/api/routes.py")
    assert is_public_api_path("openapi.json")
    assert not is_public_api_path("src/internal/helper.py")


def test_low_risk_classification() -> None:
    """Isolated, confident bug fix with small blast radius must classify as LOW risk."""
    features = extract_risk_features(
        change_class=ChangeClass.BUG_FIX,
        certainty=CertaintyLevel.CONFIDENT,
        changed_files=("src/calc.py",),
        changed_lines_count=10,
    )
    result = classify_risk(features)
    assert result.risk_level == RiskLevel.LOW
    assert result.schema_version == RISK_POLICY_SCHEMA_VERSION
    assert result.is_authoritative is False
    assert len(result.classification_digest) == 64
    assert "Localized scope" in result.elevation_reasons[0]
    verify_risk_classification_integrity(result)


def test_fail_closed_elevation_on_untrusted_or_contradictory_metadata() -> None:
    """Untrusted metadata or contradictory signals must fail closed to HIGH risk."""
    # Untrusted metadata
    f1 = extract_risk_features(
        change_class=ChangeClass.BUG_FIX,
        changed_files=("src/calc.py",),
        has_untrusted_metadata=True,
    )
    r1 = classify_risk(f1)
    assert r1.risk_level == RiskLevel.HIGH
    assert any("Untrusted metadata detected" in reason for reason in r1.elevation_reasons)
    verify_risk_classification_integrity(r1)

    # Contradictory signals
    f2 = extract_risk_features(
        change_class=ChangeClass.BUG_FIX,
        changed_files=("src/calc.py",),
        has_contradictory_signals=True,
    )
    r2 = classify_risk(f2)
    assert r2.risk_level == RiskLevel.HIGH
    assert any("Contradictory classification signals" in reason for reason in r2.elevation_reasons)

    # UNKNOWN certainty
    f3 = extract_risk_features(
        change_class=ChangeClass.BUG_FIX,
        certainty=CertaintyLevel.UNKNOWN,
        changed_files=("src/calc.py",),
    )
    r3 = classify_risk(f3)
    assert r3.risk_level == RiskLevel.HIGH
    assert any("UNKNOWN" in reason for reason in r3.elevation_reasons)


def test_protected_surfaces_elevation() -> None:
    """Touching protected surfaces must elevate to HIGH risk."""
    features = extract_risk_features(
        change_class=ChangeClass.BUG_FIX,
        changed_files=("AGENTS.md", "src/calc.py"),
    )
    assert len(features.touched_protected_surfaces) > 0
    result = classify_risk(features)
    assert result.risk_level == RiskLevel.HIGH
    assert any("protected surface" in reason for reason in result.elevation_reasons)


def test_security_fix_inherently_high_risk() -> None:
    """SECURITY_FIX changes must always be classified as HIGH risk regardless of size."""
    features = extract_risk_features(
        change_class=ChangeClass.SECURITY_FIX,
        changed_files=("src/calc.py",),
        changed_lines_count=2,
    )
    result = classify_risk(features)
    assert result.risk_level == RiskLevel.HIGH
    assert any("SECURITY_FIX" in reason for reason in result.elevation_reasons)


def test_security_sensitive_paths_elevation() -> None:
    """Touching security-sensitive paths must elevate to HIGH risk."""
    features = extract_risk_features(
        change_class=ChangeClass.BUG_FIX,
        changed_files=("src/auth/jwt_handler.py",),
    )
    result = classify_risk(features)
    assert result.risk_level == RiskLevel.HIGH
    assert any("security-sensitive" in reason for reason in result.elevation_reasons)


def test_wide_blast_radius_elevation() -> None:
    """Wide blast radius (files >= 10 or lines >= 500) must elevate to HIGH risk."""
    # 10 files
    files = tuple(f"src/mod_{i}.py" for i in range(10))
    f1 = extract_risk_features(
        change_class=ChangeClass.FEATURE,
        changed_files=files,
    )
    r1 = classify_risk(f1)
    assert r1.risk_level == RiskLevel.HIGH
    assert any("blast radius" in reason for reason in r1.elevation_reasons)

    # 500 lines
    f2 = extract_risk_features(
        change_class=ChangeClass.FEATURE,
        changed_files=("src/large.py",),
        changed_lines_count=500,
    )
    r2 = classify_risk(f2)
    assert r2.risk_level == RiskLevel.HIGH
    assert any("blast radius" in reason for reason in r2.elevation_reasons)


def test_medium_risk_classification() -> None:
    """Moderate scope (files >= 3, API impact, dependency impact) must classify as MEDIUM."""
    # 3 files
    f1 = extract_risk_features(
        change_class=ChangeClass.BUG_FIX,
        changed_files=("src/a.py", "src/b.py", "src/c.py"),
        changed_lines_count=20,
    )
    assert classify_risk(f1).risk_level == RiskLevel.MEDIUM

    # Ambiguous certainty
    f2 = extract_risk_features(
        change_class=ChangeClass.BUG_FIX,
        certainty=CertaintyLevel.AMBIGUOUS,
        changed_files=("src/a.py",),
    )
    assert classify_risk(f2).risk_level == RiskLevel.MEDIUM

    # Public API impact
    f3 = extract_risk_features(
        change_class=ChangeClass.FEATURE,
        changed_files=("src/__init__.py",),
    )
    assert classify_risk(f3).risk_level == RiskLevel.MEDIUM

    # Dependency impact
    f4 = extract_risk_features(
        change_class=ChangeClass.FEATURE,
        changed_files=("pyproject.toml",),
    )
    assert classify_risk(f4).risk_level == RiskLevel.MEDIUM

    # PERFORMANCE class
    f5 = extract_risk_features(
        change_class=ChangeClass.PERFORMANCE,
        changed_files=("src/fast.py",),
    )
    assert classify_risk(f5).risk_level == RiskLevel.MEDIUM

    # DEP_API_CHANGE class
    f6 = extract_risk_features(
        change_class=ChangeClass.DEP_API_CHANGE,
        changed_files=("src/adapter.py",),
    )
    assert classify_risk(f6).risk_level == RiskLevel.MEDIUM


def test_risk_monotonicity() -> None:
    """Adding risk features must never decrease the risk level (monotonicity invariant)."""
    base = extract_risk_features(
        change_class=ChangeClass.BUG_FIX,
        changed_files=("src/calc.py",),
        changed_lines_count=10,
    )
    base_level = classify_risk(base).risk_level
    assert base_level == RiskLevel.LOW

    # Adding files
    more_files = extract_risk_features(
        change_class=ChangeClass.BUG_FIX,
        changed_files=("src/calc.py", "src/b.py", "src/c.py"),
        changed_lines_count=10,
    )
    assert classify_risk(more_files).risk_level >= base_level

    # Adding public API
    api_impact = extract_risk_features(
        change_class=ChangeClass.BUG_FIX,
        changed_files=("src/calc.py", "src/__init__.py"),
    )
    assert classify_risk(api_impact).risk_level >= base_level

    # Adding security path
    sec_impact = extract_risk_features(
        change_class=ChangeClass.BUG_FIX,
        changed_files=("src/calc.py", "src/auth/login.py"),
    )
    assert classify_risk(sec_impact).risk_level == RiskLevel.HIGH


def test_tamper_detection() -> None:
    """Tampering with classification payload or digest must raise RiskTamperingError."""
    features = extract_risk_features(
        change_class=ChangeClass.BUG_FIX,
        changed_files=("src/calc.py",),
    )
    result = classify_risk(features)

    # Tampered digest
    tampered_digest = RiskClassification(
        schema_version=result.schema_version,
        risk_level=result.risk_level,
        features=result.features,
        elevation_reasons=result.elevation_reasons,
        classification_digest="a" * 64,
        is_authoritative=False,
    )
    with pytest.raises(RiskTamperingError, match="digest mismatch"):
        verify_risk_classification_integrity(tampered_digest)

    # Attempting to declare is_authoritative=True fails closed in constructor
    with pytest.raises(InvalidRiskInputError, match="is_authoritative must be False"):
        RiskClassification(
            schema_version=result.schema_version,
            risk_level=result.risk_level,
            features=result.features,
            elevation_reasons=result.elevation_reasons,
            classification_digest=result.classification_digest,
            is_authoritative=True,  # Forbidden
        )


def test_defect_1_inconsistent_risk_features_rejected() -> None:
    """Defect 1: Inconsistent or manipulated risk features must fail closed at boundary."""
    # 1. src/auth/login.py with empty security-path indicators must be rejected
    with pytest.raises(
        InvalidRiskInputError, match="Inconsistent risk features.*touched_security_sensitive_paths"
    ):
        RiskFeatureSet(
            change_class=ChangeClass.BUG_FIX,
            touched_paths=("src/auth/login.py",),
            touched_security_sensitive_paths=(),  # Forged omission
            changed_files_count=1,
        )

    # 2. Protected surface omitted from touched_protected_surfaces must be rejected
    with pytest.raises(
        InvalidRiskInputError, match="Inconsistent risk features.*touched_protected_surfaces"
    ):
        RiskFeatureSet(
            change_class=ChangeClass.BUG_FIX,
            touched_paths=("AGENTS.md",),
            touched_protected_surfaces=(),  # Forged omission
            changed_files_count=1,
        )

    # 3. changed_files_count contradicts touched_paths
    with pytest.raises(InvalidRiskInputError, match="Incomplete change-scope facts"):
        RiskFeatureSet(
            change_class=ChangeClass.BUG_FIX,
            touched_paths=(),
            changed_files_count=5,  # Contradiction
        )

    with pytest.raises(InvalidRiskInputError, match="contradicts.*touched_paths count"):
        RiskFeatureSet(
            change_class=ChangeClass.BUG_FIX,
            touched_paths=("src/calc.py",),
            changed_files_count=3,  # Contradiction
        )

    # 4. Genuine zero-file scenario is valid and preserved
    zero_files = RiskFeatureSet(
        change_class=ChangeClass.BUG_FIX,
        touched_paths=(),
        changed_files_count=0,
    )
    assert zero_files.changed_files_count == 0
    classification = classify_risk(zero_files)
    assert classification.risk_level == RiskLevel.LOW

    # 5. Regression: src/auth/login.py properly extracted is HIGH risk
    auth_features = extract_risk_features(
        change_class=ChangeClass.BUG_FIX,
        changed_files=("src/auth/login.py",),
    )
    assert auth_features.touched_security_sensitive_paths == ("src/auth/login.py",)
    auth_class = classify_risk(auth_features)
    assert auth_class.risk_level == RiskLevel.HIGH
