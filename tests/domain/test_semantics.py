"""Focused tests for change-semantics enum and per-class verification requirements."""

from dataclasses import FrozenInstanceError

import pytest

from basebreak.domain.semantics import (
    ChangeClass,
    ClassVerificationRequirement,
    get_verification_requirements,
)


class TestChangeClass:
    """Tests for ChangeClass enum."""

    def test_all_six_exact_classes_exist(self) -> None:
        expected = {
            "BUG_FIX",
            "FEATURE",
            "SECURITY_FIX",
            "REFACTOR",
            "PERFORMANCE",
            "DEP_API_CHANGE",
        }
        actual = {member.value for member in ChangeClass}
        assert actual == expected
        assert len(ChangeClass) == 6

    def test_no_duplicate_or_alias_ambiguity(self) -> None:
        values = [member.value for member in ChangeClass]
        names = [member.name for member in ChangeClass]
        assert len(values) == len(set(values)) == 6
        assert len(names) == len(set(names)) == 6

    def test_string_membership_and_construction(self) -> None:
        for val in (
            "BUG_FIX",
            "FEATURE",
            "SECURITY_FIX",
            "REFACTOR",
            "PERFORMANCE",
            "DEP_API_CHANGE",
        ):
            assert ChangeClass(val).value == val

        with pytest.raises(ValueError):
            ChangeClass("UNKNOWN_CLASS")

        with pytest.raises(ValueError):
            ChangeClass("bug_fix")  # strictly uppercase


class TestPerClassVerificationRequirements:
    """Tests for deterministic per-class verification requirements."""

    def test_each_class_maps_deterministically(self) -> None:
        for change_class in ChangeClass:
            req = get_verification_requirements(change_class)
            assert isinstance(req, ClassVerificationRequirement)
            assert req.change_class == change_class
            assert isinstance(req.base_expectation, str) and req.base_expectation
            assert isinstance(req.candidate_expectation, str) and req.candidate_expectation

    def test_invalid_type_raises_type_error(self) -> None:
        with pytest.raises(TypeError, match="ChangeClass"):
            get_verification_requirements("BUG_FIX")  # type: ignore[arg-type]

    def test_bug_fix_semantics_preserve_fail_to_pass(self) -> None:
        req = get_verification_requirements(ChangeClass.BUG_FIX)
        assert req.base_expectation == "FAIL"
        assert req.candidate_expectation == "PASS"
        assert not req.requires_equivalence
        assert not req.requires_measured_delta
        assert not req.requires_regression_safety

    def test_feature_semantics_preserve_absent_to_present(self) -> None:
        req = get_verification_requirements(ChangeClass.FEATURE)
        assert req.base_expectation == "ABSENT"
        assert req.candidate_expectation == "PRESENT"
        assert not req.requires_equivalence
        assert not req.requires_measured_delta
        assert not req.requires_regression_safety

    def test_security_fix_semantics_preserve_exploitable_to_blocked(self) -> None:
        req = get_verification_requirements(ChangeClass.SECURITY_FIX)
        assert req.base_expectation == "EXPLOITABLE"
        assert req.candidate_expectation == "BLOCKED"
        assert not req.requires_equivalence
        assert not req.requires_measured_delta
        assert not req.requires_regression_safety

    def test_refactor_expresses_equivalence(self) -> None:
        req = get_verification_requirements(ChangeClass.REFACTOR)
        assert req.base_expectation == "EQUIVALENT"
        assert req.candidate_expectation == "EQUIVALENT"
        assert req.requires_equivalence is True
        assert not req.requires_measured_delta
        assert not req.requires_regression_safety

    def test_performance_expresses_parity_and_measured_delta(self) -> None:
        req = get_verification_requirements(ChangeClass.PERFORMANCE)
        assert req.base_expectation == "PARITY"
        assert req.candidate_expectation == "PARITY"
        assert req.requires_measured_delta is True
        assert not req.requires_equivalence
        assert not req.requires_regression_safety

    def test_dep_api_change_expresses_new_contract_and_regression_safety(self) -> None:
        req = get_verification_requirements(ChangeClass.DEP_API_CHANGE)
        assert req.base_expectation == "BASELINE"
        assert req.candidate_expectation == "NEW_CONTRACT_SATISFIED"
        assert req.requires_regression_safety is True
        assert not req.requires_equivalence
        assert not req.requires_measured_delta

    def test_frozen_immutability(self) -> None:
        req = get_verification_requirements(ChangeClass.BUG_FIX)
        with pytest.raises(FrozenInstanceError):
            req.base_expectation = "PASS"  # type: ignore[misc]
        with pytest.raises(FrozenInstanceError):
            req.candidate_expectation = "FAIL"  # type: ignore[misc]
