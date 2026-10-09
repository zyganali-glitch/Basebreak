"""Tests for P-15.04: Mandatory counterrun and slicing policy."""

from __future__ import annotations

import pytest

from basebreak.budget.mandatory_policy import (
    MandatoryObligationViolationError,
    MandatoryPolicyTamperingError,
    MandatoryVerificationObligations,
    resolve_mandatory_obligations,
    validate_executed_obligations,
    verify_mandatory_obligations_integrity,
)
from basebreak.budget.risk_features import (
    RiskLevel,
    classify_risk,
    extract_risk_features,
)
from basebreak.compiler.semantics import ChangeClass


def test_counterrun_mandatory_triggers() -> None:
    """Counterrun must be mandatory for HIGH risk bug fixes and security fixes."""
    # 1. HIGH risk BUG_FIX (due to wide blast radius)
    files = tuple(f"src/file_{i}.py" for i in range(10))
    f_high_bug = extract_risk_features(change_class=ChangeClass.BUG_FIX, changed_files=files)
    c_high_bug = classify_risk(f_high_bug)
    assert c_high_bug.risk_level == RiskLevel.HIGH
    ob_high_bug = resolve_mandatory_obligations(c_high_bug)
    assert ob_high_bug.counterrun_mandatory is True
    assert any("HIGH risk BUG_FIX" in r for r in ob_high_bug.counterrun_reasons)

    # 2. SECURITY_FIX (inherently HIGH risk)
    f_sec = extract_risk_features(
        change_class=ChangeClass.SECURITY_FIX, changed_files=("src/calc.py",)
    )
    c_sec = classify_risk(f_sec)
    ob_sec = resolve_mandatory_obligations(c_sec)
    assert ob_sec.counterrun_mandatory is True
    assert any("SECURITY_FIX" in r for r in ob_sec.counterrun_reasons)

    # 3. Touched protected surfaces
    f_prot = extract_risk_features(change_class=ChangeClass.BUG_FIX, changed_files=("AGENTS.md",))
    c_prot = classify_risk(f_prot)
    ob_prot = resolve_mandatory_obligations(c_prot)
    assert ob_prot.counterrun_mandatory is True
    assert any("protected surface" in r for r in ob_prot.counterrun_reasons)

    # 4. Explicit contract demand
    f_low = extract_risk_features(change_class=ChangeClass.BUG_FIX, changed_files=("src/calc.py",))
    c_low = classify_risk(f_low)
    ob_explicit = resolve_mandatory_obligations(c_low, explicit_contract_demands_counterrun=True)
    assert ob_explicit.counterrun_mandatory is True
    assert any("explicitly mandates" in r for r in ob_explicit.counterrun_reasons)

    # 5. Clean LOW risk BUG_FIX does NOT mandate counterrun by default
    ob_clean = resolve_mandatory_obligations(c_low)
    assert ob_clean.counterrun_mandatory is False


def test_causal_slicing_mandatory_triggers() -> None:
    """Causal slicing must be mandatory for multi-hunk high risk or security patches."""
    # 1. Multi-hunk patch at HIGH risk
    f_high = extract_risk_features(change_class=ChangeClass.FEATURE, has_untrusted_metadata=True)
    c_high = classify_risk(f_high)
    assert c_high.risk_level == RiskLevel.HIGH
    ob_high_multi = resolve_mandatory_obligations(c_high, patch_hunk_count=3)
    assert ob_high_multi.slicing_mandatory is True
    assert any("Multi-hunk patch" in r for r in ob_high_multi.slicing_reasons)

    # 2. Multi-hunk SECURITY_FIX
    f_sec = extract_risk_features(change_class=ChangeClass.SECURITY_FIX)
    c_sec = classify_risk(f_sec)
    ob_sec_multi = resolve_mandatory_obligations(c_sec, patch_hunk_count=2)
    assert ob_sec_multi.slicing_mandatory is True
    assert any("Multi-hunk security patch" in r for r in ob_sec_multi.slicing_reasons)

    # 3. Multi-hunk (> 3 hunks) at MEDIUM risk
    f_med = extract_risk_features(
        change_class=ChangeClass.FEATURE, changed_files=("src/a.py", "src/b.py", "src/c.py")
    )
    c_med = classify_risk(f_med)
    assert c_med.risk_level == RiskLevel.MEDIUM
    ob_med_multi = resolve_mandatory_obligations(c_med, patch_hunk_count=4)
    assert ob_med_multi.slicing_mandatory is True

    # 4. Single-hunk clean patch does NOT mandate slicing
    f_low = extract_risk_features(change_class=ChangeClass.BUG_FIX, changed_files=("src/calc.py",))
    c_low = classify_risk(f_low)
    ob_single = resolve_mandatory_obligations(c_low, patch_hunk_count=1)
    assert ob_single.slicing_mandatory is False

    # 5. Explicit contract demand forces slicing
    ob_explicit = resolve_mandatory_obligations(
        c_low, patch_hunk_count=1, explicit_contract_demands_slicing=True
    )
    assert ob_explicit.slicing_mandatory is True


def test_semantic_differences_preserved() -> None:
    """REFACTOR and PERFORMANCE do not mandate counterruns unless explicitly contracted."""
    f_ref = extract_risk_features(change_class=ChangeClass.REFACTOR, changed_files=("src/calc.py",))
    c_ref = classify_risk(f_ref)
    ob_ref = resolve_mandatory_obligations(c_ref)
    assert ob_ref.counterrun_mandatory is False

    f_perf = extract_risk_features(
        change_class=ChangeClass.PERFORMANCE, changed_files=("src/calc.py",)
    )
    c_perf = classify_risk(f_perf)
    ob_perf = resolve_mandatory_obligations(c_perf)
    assert ob_perf.counterrun_mandatory is False


def test_validate_executed_obligations() -> None:
    """validate_executed_obligations must fail closed if mandatory obligations were not executed."""
    f_high = extract_risk_features(change_class=ChangeClass.SECURITY_FIX)
    c_high = classify_risk(f_high)
    obligations = resolve_mandatory_obligations(c_high, patch_hunk_count=2)
    assert obligations.counterrun_mandatory is True
    assert obligations.slicing_mandatory is True

    # 1. Counterrun not executed
    with pytest.raises(
        MandatoryObligationViolationError, match="counterrun execution was not executed"
    ):
        validate_executed_obligations(
            obligations,
            counterrun_executed=False,
            counterrun_passed=False,
            slicing_executed=True,
            slicing_passed=True,
        )

    # 2. Counterrun executed but failed
    with pytest.raises(MandatoryObligationViolationError, match="counterrun failed"):
        validate_executed_obligations(
            obligations,
            counterrun_executed=True,
            counterrun_passed=False,
            slicing_executed=True,
            slicing_passed=True,
        )

    # 3. Slicing not executed
    with pytest.raises(MandatoryObligationViolationError, match="causal slicing was not executed"):
        validate_executed_obligations(
            obligations,
            counterrun_executed=True,
            counterrun_passed=True,
            slicing_executed=False,
            slicing_passed=False,
        )

    # 4. Slicing executed but failed/incomplete
    with pytest.raises(MandatoryObligationViolationError, match="causal slicing search failed"):
        validate_executed_obligations(
            obligations,
            counterrun_executed=True,
            counterrun_passed=True,
            slicing_executed=True,
            slicing_passed=False,
        )

    # 5. All mandatory obligations executed and passed
    validate_executed_obligations(
        obligations,
        counterrun_executed=True,
        counterrun_passed=True,
        slicing_executed=True,
        slicing_passed=True,
    )


def test_tamper_detection_on_mandatory_obligations() -> None:
    """Tampering with obligations digest must raise MandatoryPolicyTamperingError."""
    f = extract_risk_features(change_class=ChangeClass.BUG_FIX, changed_files=("src/calc.py",))
    c = classify_risk(f)
    ob = resolve_mandatory_obligations(c)
    verify_mandatory_obligations_integrity(ob)

    tampered = MandatoryVerificationObligations(
        schema_version=ob.schema_version,
        counterrun_mandatory=ob.counterrun_mandatory,
        slicing_mandatory=ob.slicing_mandatory,
        counterrun_reasons=ob.counterrun_reasons,
        slicing_reasons=ob.slicing_reasons,
        policy_digest="c" * 64,
    )
    with pytest.raises(MandatoryPolicyTamperingError, match="digest mismatch"):
        verify_mandatory_obligations_integrity(tampered)
