"""Unit tests for P-14.01: Bounded failure-feedback schema and contracts."""

from __future__ import annotations

import dataclasses

import pytest

from basebreak.domain.semantics import ChangeClass
from basebreak.domain.verdict import EvidenceProvenance
from basebreak.repair.feedback import (
    DisclosureClassification,
    FailureConditionCategory,
    RepairFeedbackAuthorityError,
    RepairFeedbackIntegrityError,
    RepairFeedbackTamperingError,
    SanitizedCounterexample,
    create_safe_repair_feedback,
    verify_repair_feedback_integrity,
)

SAMPLE_RECEIPT_DIGEST = "a" * 64


def test_create_valid_safe_repair_feedback() -> None:
    counterexample = SanitizedCounterexample(
        input_summary='{"name": "Alice"}',
        expected_output_summary='{"status": "ok", "user": "Alice"}',
        actual_output_summary="KeyError: user",
        input_category="json_payload",
        exit_code=1,
    )

    feedback = create_safe_repair_feedback(
        feedback_id="FB-001",
        candidate_id="cand-1234",
        requirement_id="REQ-BUG-01",
        change_class=ChangeClass.BUG_FIX,
        failed_condition=FailureConditionCategory.BEHAVIORAL_ASSERTION_FAILED,
        observed_behavior="Uncaught KeyError when processing payload with user field missing",
        expected_behavior="Handler should return user dict inside status wrapper",
        originating_receipt_digest=SAMPLE_RECEIPT_DIGEST,
        feedback_round=1,
        provenance=EvidenceProvenance.LOCAL_EXECUTION,
        permitted_patch_region=["src/demo/handler.py"],
        counterexample=counterexample,
    )

    assert feedback.feedback_id == "FB-001"
    assert feedback.candidate_id == "cand-1234"
    assert feedback.requirement_id == "REQ-BUG-01"
    assert feedback.change_class == ChangeClass.BUG_FIX
    assert feedback.failed_condition == FailureConditionCategory.BEHAVIORAL_ASSERTION_FAILED
    assert feedback.feedback_round == 1
    assert feedback.is_authoritative is False
    assert feedback.grants_pass is False
    assert feedback.is_causally_verified is False
    assert feedback.disclosure_classification == DisclosureClassification.SAFE_TO_DISCLOSE
    assert len(feedback.feedback_digest) == 64
    assert verify_repair_feedback_integrity(feedback) is True


def test_feedback_authority_rejection() -> None:
    counterexample = SanitizedCounterexample(
        input_summary="x=1",
        expected_output_summary="2",
        actual_output_summary="1",
    )
    feedback = create_safe_repair_feedback(
        feedback_id="FB-002",
        candidate_id="cand-1234",
        requirement_id="REQ-BUG-01",
        change_class=ChangeClass.BUG_FIX,
        failed_condition=FailureConditionCategory.BEHAVIORAL_ASSERTION_FAILED,
        observed_behavior="Wrong result",
        expected_behavior="Right result",
        originating_receipt_digest=SAMPLE_RECEIPT_DIGEST,
        feedback_round=1,
        provenance=EvidenceProvenance.LOCAL_EXECUTION,
        counterexample=counterexample,
    )

    # Authority smuggling attempts must raise RepairFeedbackAuthorityError
    with pytest.raises(RepairFeedbackAuthorityError):
        dataclasses.replace(feedback, is_authoritative=True)

    with pytest.raises(RepairFeedbackAuthorityError):
        dataclasses.replace(feedback, grants_pass=True)

    with pytest.raises(RepairFeedbackAuthorityError):
        dataclasses.replace(feedback, is_causally_verified=True)


def test_feedback_tampering_detection() -> None:
    feedback = create_safe_repair_feedback(
        feedback_id="FB-003",
        candidate_id="cand-1234",
        requirement_id="REQ-BUG-01",
        change_class=ChangeClass.BUG_FIX,
        failed_condition=FailureConditionCategory.BEHAVIORAL_ASSERTION_FAILED,
        observed_behavior="Wrong result",
        expected_behavior="Right result",
        originating_receipt_digest=SAMPLE_RECEIPT_DIGEST,
        feedback_round=1,
        provenance=EvidenceProvenance.LOCAL_EXECUTION,
    )

    tampered_feedback = dataclasses.replace(
        feedback,
        observed_behavior="Tampered behavior text",
    )
    with pytest.raises(RepairFeedbackTamperingError):
        verify_repair_feedback_integrity(tampered_feedback)


def test_feedback_field_validations() -> None:
    with pytest.raises(RepairFeedbackIntegrityError):
        create_safe_repair_feedback(
            feedback_id="",
            candidate_id="cand-1",
            requirement_id="REQ-1",
            change_class=ChangeClass.BUG_FIX,
            failed_condition=FailureConditionCategory.BEHAVIORAL_ASSERTION_FAILED,
            observed_behavior="obs",
            expected_behavior="exp",
            originating_receipt_digest=SAMPLE_RECEIPT_DIGEST,
            feedback_round=1,
            provenance=EvidenceProvenance.LOCAL_EXECUTION,
        )

    with pytest.raises(RepairFeedbackIntegrityError):
        create_safe_repair_feedback(
            feedback_id="FB-1",
            candidate_id="cand-1",
            requirement_id="REQ-1",
            change_class=ChangeClass.BUG_FIX,
            failed_condition=FailureConditionCategory.BEHAVIORAL_ASSERTION_FAILED,
            observed_behavior="obs",
            expected_behavior="exp",
            originating_receipt_digest="bad_digest",
            feedback_round=1,
            provenance=EvidenceProvenance.LOCAL_EXECUTION,
        )

    with pytest.raises(RepairFeedbackIntegrityError):
        create_safe_repair_feedback(
            feedback_id="FB-1",
            candidate_id="cand-1",
            requirement_id="REQ-1",
            change_class=ChangeClass.BUG_FIX,
            failed_condition=FailureConditionCategory.BEHAVIORAL_ASSERTION_FAILED,
            observed_behavior="obs",
            expected_behavior="exp",
            originating_receipt_digest=SAMPLE_RECEIPT_DIGEST,
            feedback_round=0,  # round must be >= 1
            provenance=EvidenceProvenance.LOCAL_EXECUTION,
        )


def test_provider_purity() -> None:
    import inspect

    import basebreak.repair.feedback as fb_module

    source = inspect.getsource(fb_module)
    assert "basebreak.adapters" not in source
    assert "nebius" not in source.lower()
    assert "openai" not in source.lower()
    assert "nemotron" not in source.lower()
