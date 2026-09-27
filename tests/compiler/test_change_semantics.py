"""Acceptance tests for P-06.03: Classify change semantics and uncertainty.

Tests requirements:
A. all six canonical classes;
B. no duplicate ChangeClass definition;
C. clear deterministic classification for representative cases;
D. ambiguous mixed-class task remains AMBIGUOUS;
E. insufficient evidence becomes UNKNOWN;
F. invalid model class fails closed;
G. malformed model JSON fails closed;
H. wrong types fail closed;
I. unsupported/verbatim-invalid citation fails closed;
J. model confident assertion cannot override conflicting deterministic fact;
K. provider purity across compiler production tree;
L. injected model client contract matches real complete(...) interface;
M. no async pytest/plugin dependency;
N. secret-bearing malformed provider response does not leak secret text;
O. stable serialization/round-trip.
"""

from __future__ import annotations

import json
from pathlib import Path
from unittest.mock import MagicMock

import pytest

from basebreak.compiler.ingestion import ingest_task
from basebreak.compiler.requirements import UnsupportedCitationError
from basebreak.compiler.semantics import (
    DEFAULT_SEMANTICS_MODEL,
    CertaintyLevel,
    ChangeSemanticsClassification,
    DeterministicClassificationFact,
    InvalidModelConfigurationError,
    MalformedModelSemanticsError,
    ModelChangeProposal,
    NemotronSemanticsClassifier,
    classify_semantics_deterministically,
    parse_and_validate_semantics_proposal,
    reconcile_semantics,
)
from basebreak.domain.semantics import ChangeClass, get_verification_requirements


class MockModelResult:
    """Mock result conforming to ModelClientResult contract."""

    def __init__(
        self,
        content: str,
        returned_model: str = DEFAULT_SEMANTICS_MODEL,
        prompt_tokens: int = 50,
        completion_tokens: int = 30,
        total_tokens: int = 80,
        telemetry_digest: str | None = "mock_telemetry_digest",
    ) -> None:
        self.content = content
        self.returned_model = returned_model
        self.usage = MagicMock(
            prompt_tokens=prompt_tokens,
            completion_tokens=completion_tokens,
            total_tokens=total_tokens,
        )
        self.telemetry_digest = telemetry_digest


class TestChangeSemanticsP0603:
    """Test suite for P-06.03 change semantics classification and uncertainty."""

    # A. All six canonical classes exist and are supported
    def test_a_all_six_canonical_classes(self) -> None:
        expected_classes = {
            "BUG_FIX",
            "FEATURE",
            "SECURITY_FIX",
            "REFACTOR",
            "PERFORMANCE",
            "DEP_API_CHANGE",
        }
        actual_classes = {c.value for c in ChangeClass}
        assert actual_classes == expected_classes
        assert len(ChangeClass) == 6

        # Every class has a valid ClassVerificationRequirement
        for cc in ChangeClass:
            req = get_verification_requirements(cc)
            assert req.change_class == cc
            assert req.base_expectation
            assert req.candidate_expectation

    # B. No duplicate ChangeClass definition
    def test_b_no_duplicate_change_class_definition(self) -> None:
        import basebreak.compiler.semantics as comp_semantics
        import basebreak.domain.semantics as dom_semantics

        # The compiler semantics module imports canonical ChangeClass directly
        assert comp_semantics.ChangeClass is dom_semantics.ChangeClass

        # Verify source code does not define a duplicate class ChangeClass
        semantics_path = Path(comp_semantics.__file__)
        code = semantics_path.read_text(encoding="utf-8")
        assert "class ChangeClass(" not in code
        assert "class ChangeClass:" not in code

    # C. Clear deterministic classification for representative cases
    @pytest.mark.parametrize(
        ("task_text", "expected_class"),
        [
            (
                "Fix critical null pointer exception crash and traceback in auth handler.",
                ChangeClass.BUG_FIX,
            ),
            (
                "Add support for YAML formatted outputs and new capability to filter by tag.",
                ChangeClass.FEATURE,
            ),
            (
                (
                    "Fix critical vulnerability CVE-2026-9999 remote code execution "
                    "and untrusted input."
                ),
                ChangeClass.SECURITY_FIX,
            ),
            (
                (
                    "Optimize query throughput to speed up benchmark latency "
                    "and eliminate memory leak."
                ),
                ChangeClass.PERFORMANCE,
            ),
            (
                (
                    "Refactor internal pipeline structure with no functional change "
                    "to simplify modularize."
                ),
                ChangeClass.REFACTOR,
            ),
            (
                "Upgrade dependency to astral uv 0.5.0 and migrate deprecated api signature.",
                ChangeClass.DEP_API_CHANGE,
            ),
        ],
    )
    def test_c_clear_deterministic_classification(
        self, task_text: str, expected_class: ChangeClass
    ) -> None:
        task = ingest_task(task_text)
        result = classify_semantics_deterministically(task)

        assert result.change_class == expected_class
        assert result.certainty == CertaintyLevel.CONFIDENT
        assert result.is_confident is True
        assert result.confidence > 0.0
        assert result.verification_requirement is not None
        assert result.verification_requirement.change_class == expected_class
        assert len(result.evidence_citations) > 0
        for citation in result.evidence_citations:
            assert citation in task.normalized_text

    # D. Ambiguous mixed-class task remains AMBIGUOUS
    def test_d_ambiguous_mixed_class_remains_ambiguous(self) -> None:
        task = ingest_task(
            "Fix crash exception bug while also adding support for new feature and "
            "optimize throughput latency."
        )
        result = classify_semantics_deterministically(task)

        assert result.certainty == CertaintyLevel.AMBIGUOUS
        assert result.is_confident is False
        assert len(result.alternative_classes) > 0

        # Model proposal with confident assertion CANNOT force AMBIGUOUS to CONFIDENT
        model_json = json.dumps(
            {
                "change_class": "FEATURE",
                "certainty": "CONFIDENT",
                "confidence": 0.99,
                "alternative_classes": [],
                "rationale": "Model unilaterally claims FEATURE",
                "evidence_citations": ["adding support for new feature"],
            }
        )
        proposal = parse_and_validate_semantics_proposal(model_json, task, "test-model")
        reconciled = reconcile_semantics(task, result.deterministic_facts, proposal)

        assert reconciled.certainty == CertaintyLevel.AMBIGUOUS
        assert reconciled.is_confident is False
        assert "AMBIGUOUS" in reconciled.rationale

    # E. Insufficient evidence becomes UNKNOWN
    def test_e_insufficient_evidence_becomes_unknown(self) -> None:
        task = ingest_task("Hello world this is some random text without technical direction.")
        result = classify_semantics_deterministically(task)

        assert result.certainty == CertaintyLevel.UNKNOWN
        assert result.change_class is None
        assert result.confidence == 0.0
        assert result.is_confident is False

        # Model proposal cannot manufacture authority when task evidence is insufficient
        model_json = json.dumps(
            {
                "change_class": "BUG_FIX",
                "certainty": "CONFIDENT",
                "confidence": 0.95,
                "alternative_classes": [],
                "rationale": "Model guessed BUG_FIX",
                "evidence_citations": ["Hello world"],
            }
        )
        proposal = parse_and_validate_semantics_proposal(model_json, task, "test-model")
        reconciled = reconcile_semantics(task, result.deterministic_facts, proposal)

        assert reconciled.certainty == CertaintyLevel.UNKNOWN
        assert reconciled.change_class is None
        assert reconciled.is_confident is False
        assert "UNKNOWN" in reconciled.rationale

    # F. Invalid model class fails closed
    def test_f_invalid_model_class_fails_closed(self) -> None:
        task = ingest_task("Fix crash on startup.")
        invalid_json = json.dumps(
            {
                "change_class": "CHORE",  # Not a canonical class
                "certainty": "CONFIDENT",
                "confidence": 0.9,
                "alternative_classes": [],
                "rationale": "Chore",
                "evidence_citations": ["Fix crash"],
            }
        )
        with pytest.raises(MalformedModelSemanticsError, match="Unsupported change class 'CHORE'"):
            parse_and_validate_semantics_proposal(invalid_json, task, "test-model")

    # G. Malformed model JSON fails closed
    def test_g_malformed_model_json_fails_closed(self) -> None:
        task = ingest_task("Fix crash on startup.")
        bad_json = "This is not JSON at all, { incomplete: true"
        with pytest.raises(MalformedModelSemanticsError, match="Model output is not valid JSON"):
            parse_and_validate_semantics_proposal(bad_json, task, "test-model")

        empty_output = "   \n\t  "
        with pytest.raises(MalformedModelSemanticsError, match="empty or whitespace-only"):
            parse_and_validate_semantics_proposal(empty_output, task, "test-model")

    # H. Wrong types fail closed
    def test_h_wrong_types_fail_closed(self) -> None:
        task = ingest_task("Fix crash on startup.")

        # confidence is str instead of float
        payload_bad_conf_str = json.dumps(
            {
                "change_class": "BUG_FIX",
                "confidence": "high",
                "rationale": "Test",
                "evidence_citations": ["Fix crash"],
            }
        )
        with pytest.raises(MalformedModelSemanticsError, match="'confidence' must be float or int"):
            parse_and_validate_semantics_proposal(payload_bad_conf_str, task, "test-model")

        # confidence is boolean
        payload_bad_conf_bool = json.dumps(
            {
                "change_class": "BUG_FIX",
                "confidence": True,
                "rationale": "Test",
                "evidence_citations": ["Fix crash"],
            }
        )
        with pytest.raises(MalformedModelSemanticsError, match="'confidence' must be float or int"):
            parse_and_validate_semantics_proposal(payload_bad_conf_bool, task, "test-model")

        # confidence out of bounds
        payload_conf_bounds = json.dumps(
            {
                "change_class": "BUG_FIX",
                "confidence": 1.5,
                "rationale": "Test",
                "evidence_citations": ["Fix crash"],
            }
        )
        with pytest.raises(MalformedModelSemanticsError, match="Confidence out of bounds: 1.5"):
            parse_and_validate_semantics_proposal(payload_conf_bounds, task, "test-model")

        # change_class is int
        payload_bad_class_int = json.dumps(
            {
                "change_class": 42,
                "confidence": 0.8,
                "rationale": "Test",
                "evidence_citations": ["Fix crash"],
            }
        )
        with pytest.raises(
            MalformedModelSemanticsError, match="'change_class' must be str or null"
        ):
            parse_and_validate_semantics_proposal(payload_bad_class_int, task, "test-model")

        # alternative_classes is not a list
        payload_bad_alts = json.dumps(
            {
                "change_class": "BUG_FIX",
                "alternative_classes": "FEATURE",
                "confidence": 0.8,
                "rationale": "Test",
                "evidence_citations": ["Fix crash"],
            }
        )
        with pytest.raises(
            MalformedModelSemanticsError, match="'alternative_classes' must be list"
        ):
            parse_and_validate_semantics_proposal(payload_bad_alts, task, "test-model")

    # I. Unsupported/verbatim-invalid citation fails closed
    def test_i_unsupported_citation_fails_closed(self) -> None:
        task = ingest_task("Fix crash on empty list in token balancer.")
        unsupported_cit_json = json.dumps(
            {
                "change_class": "BUG_FIX",
                "certainty": "CONFIDENT",
                "confidence": 0.9,
                "alternative_classes": [],
                "rationale": "Test",
                "evidence_citations": ["This phrase does not exist in the task text"],
            }
        )
        with pytest.raises(
            UnsupportedCitationError, match="Evidence citation is not present in task text"
        ):
            parse_and_validate_semantics_proposal(unsupported_cit_json, task, "test-model")

    # J. Model confident assertion cannot override conflicting deterministic fact
    def test_j_model_confident_assertion_cannot_override_deterministic_fact(self) -> None:
        # Clear BUG_FIX task
        task = ingest_task("Fix critical crash and null pointer exception in auth handler.")
        det_result = classify_semantics_deterministically(task)
        assert det_result.change_class == ChangeClass.BUG_FIX
        assert det_result.certainty == CertaintyLevel.CONFIDENT

        # Model confidently claims it is a FEATURE
        model_json = json.dumps(
            {
                "change_class": "FEATURE",
                "certainty": "CONFIDENT",
                "confidence": 0.99,
                "alternative_classes": [],
                "rationale": "Model claims this is a new feature",
                "evidence_citations": ["Fix critical crash"],
            }
        )
        proposal = parse_and_validate_semantics_proposal(model_json, task, "test-model")
        reconciled = reconcile_semantics(task, det_result.deterministic_facts, proposal)

        # Deterministic fact WINS!
        assert reconciled.change_class == ChangeClass.BUG_FIX
        assert reconciled.certainty == CertaintyLevel.CONFIDENT
        assert reconciled.deterministic_facts.inferred_class == ChangeClass.BUG_FIX
        assert reconciled.model_proposal is not None
        assert reconciled.model_proposal.proposed_class == ChangeClass.FEATURE
        assert "overridden by deterministic fact authority" in reconciled.rationale

    # K. Provider purity across compiler production tree
    def test_k_provider_purity_across_compiler_tree(self) -> None:
        compiler_dir = (
            Path(__file__).resolve().parent.parent.parent / "src" / "basebreak" / "compiler"
        )
        assert compiler_dir.is_dir()

        py_files = list(compiler_dir.glob("*.py"))
        assert len(py_files) >= 3

        for py_file in py_files:
            content = py_file.read_text(encoding="utf-8")
            assert "basebreak.adapters" not in content, (
                f"Provider impurity found in {py_file.name}: "
                f"contains reference to basebreak.adapters"
            )
            assert "LIVE_NEBIUS" not in content, (
                f"Provenance leak found in {py_file.name}: contains LIVE_NEBIUS"
            )

    # L. Injected model client contract matches real complete(...) interface
    def test_l_injected_model_client_contract_matches_complete(self) -> None:
        task = ingest_task("Fix crash on empty list in token balancer.")
        expected_json = json.dumps(
            {
                "change_class": "BUG_FIX",
                "certainty": "CONFIDENT",
                "confidence": 0.95,
                "alternative_classes": [],
                "rationale": "Fixes empty list crash",
                "evidence_citations": ["Fix crash on empty list"],
            }
        )

        mock_client = MagicMock()
        mock_client.complete = MagicMock(return_value=MockModelResult(content=expected_json))
        mock_client.config = MagicMock(model=DEFAULT_SEMANTICS_MODEL)

        classifier = NemotronSemanticsClassifier(mock_client)
        result = classifier.classify(task)

        assert mock_client.complete.called
        assert result.change_class == ChangeClass.BUG_FIX
        assert result.certainty == CertaintyLevel.CONFIDENT
        assert result.model_proposal is not None
        assert result.model_proposal.proposed_class == ChangeClass.BUG_FIX

        # Client model mismatch fails closed
        mock_bad_client = MagicMock()
        mock_bad_client.config = MagicMock(model="wrong/model-id")
        with pytest.raises(InvalidModelConfigurationError, match="does not match classifier model"):
            NemotronSemanticsClassifier(mock_bad_client)

    # M. No async pytest/plugin dependency
    def test_m_no_async_dependency(self) -> None:
        import basebreak.compiler.semantics as comp_semantics

        source_file = Path(comp_semantics.__file__)
        code = source_file.read_text(encoding="utf-8")

        assert "async def " not in code, "Semantics module must not define async functions"
        assert "await " not in code, "Semantics module must not use await"

    # N. Secret-bearing malformed provider response does not leak secret text
    def test_n_secret_bearing_malformed_response_does_not_leak(self) -> None:
        task = ingest_task("Fix crash in parser.")
        secret = "Bearer test_secret_token_123456789012345678901234567890"

        # Malformed JSON with secret
        bad_json_with_secret = f"{secret} is definitely not valid json"
        with pytest.raises(MalformedModelSemanticsError) as exc_info:
            parse_and_validate_semantics_proposal(bad_json_with_secret, task, "test-model")

        error_message = str(exc_info.value)
        assert secret not in error_message
        assert "[REDACTED]" in error_message

        # Unsupported citation with secret
        bad_cit_with_secret = json.dumps(
            {
                "change_class": "BUG_FIX",
                "evidence_citations": [secret],
            }
        )
        with pytest.raises(UnsupportedCitationError) as exc_info_cit:
            parse_and_validate_semantics_proposal(bad_cit_with_secret, task, "test-model")

        cit_error_message = str(exc_info_cit.value)
        assert secret not in cit_error_message
        assert "[REDACTED]" in cit_error_message

    # O. Stable serialization / round-trip
    def test_o_stable_serialization_round_trip(self) -> None:
        task = ingest_task("Fix crash on empty list in token balancer.")
        model_json = json.dumps(
            {
                "change_class": "BUG_FIX",
                "certainty": "CONFIDENT",
                "confidence": 0.95,
                "alternative_classes": [],
                "rationale": "Fixes empty list crash",
                "evidence_citations": ["Fix crash on empty list"],
            }
        )
        proposal = parse_and_validate_semantics_proposal(model_json, task, "test-model")
        proposal_dict = proposal.to_dict()
        restored_proposal = ModelChangeProposal.from_dict(proposal_dict)
        assert restored_proposal == proposal

        det_result = classify_semantics_deterministically(task)
        det_dict = det_result.deterministic_facts.to_dict()
        restored_det = DeterministicClassificationFact.from_dict(det_dict)
        assert restored_det == det_result.deterministic_facts

        reconciled = reconcile_semantics(task, det_result.deterministic_facts, proposal)
        reconciled_dict = reconciled.to_dict()
        restored_reconciled = ChangeSemanticsClassification.from_dict(reconciled_dict)
        assert restored_reconciled == reconciled
        assert restored_reconciled.verification_requirement == reconciled.verification_requirement
