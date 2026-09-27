"""Acceptance tests for P-06.03: Classify change semantics and uncertainty.

Tests requirements:
A. all six canonical ChangeClass values reuse domain enum;
B. compiler production tree contains zero provider-specific identifiers:
   Nebius, NVIDIA, Nemotron, Token Factory, LIVE_NEBIUS, basebreak.adapters;
C. no production compiler class directly calls a provider/model;
D. deterministic clear BUG_FIX case remains correct;
E. deterministic clear FEATURE case remains correct;
F. all six representative canonical classes covered;
G. mixed signals remain AMBIGUOUS;
H. insufficient signals remain UNKNOWN;
I. malformed JSON fails closed;
J. every missing required model-proposal field fails closed;
K. wrong field types fail closed;
L. unsupported citation fails closed;
M. model conflict cannot change authoritative fields;
N. model agreement cannot increase authoritative confidence;
O. model citations cannot enter authoritative evidence_citations;
P. model alternative classes cannot enter authoritative alternative_classes;
Q. direct ModelChangeProposal(is_authoritative=True) fails closed;
R. from_dict wrong types fail closed without coercion;
S. stable strict round-trip succeeds for valid objects;
T. secret-bearing malformed proposal does not leak secret;
U. no async/plugin dependency introduced.
"""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from basebreak.compiler.ingestion import ingest_task
from basebreak.compiler.requirements import UnsupportedCitationError
from basebreak.compiler.semantics import (
    SEMANTICS_SYSTEM_PROMPT,
    CertaintyLevel,
    ChangeSemanticsClassification,
    DeterministicClassificationFact,
    MalformedModelSemanticsError,
    ModelChangeProposal,
    classify_semantics_deterministically,
    parse_and_validate_semantics_proposal,
    reconcile_semantics,
)
from basebreak.domain.semantics import ChangeClass, get_verification_requirements


class TestChangeSemanticsP0603:
    """Test suite for P-06.03 change semantics classification and uncertainty."""

    # A. All six canonical ChangeClass values reuse domain enum
    def test_a_all_six_canonical_classes_reuse_domain_enum(self) -> None:
        import basebreak.compiler.semantics as comp_semantics
        import basebreak.domain.semantics as dom_semantics

        # Compiler semantics module directly reuses domain ChangeClass
        assert comp_semantics.ChangeClass is dom_semantics.ChangeClass

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

        # Source code does not define a duplicate ChangeClass enum
        semantics_path = Path(comp_semantics.__file__)
        code = semantics_path.read_text(encoding="utf-8")
        assert "class ChangeClass(" not in code
        assert "class ChangeClass:" not in code

        # Every class has a valid ClassVerificationRequirement
        for cc in ChangeClass:
            req = get_verification_requirements(cc)
            assert req.change_class == cc
            assert req.base_expectation
            assert req.candidate_expectation
            assert cc.value in SEMANTICS_SYSTEM_PROMPT

    # B. Compiler production tree contains zero provider-specific identifiers
    def test_b_compiler_production_tree_provider_neutrality(self) -> None:
        compiler_dir = (
            Path(__file__).resolve().parent.parent.parent / "src" / "basebreak" / "compiler"
        )
        assert compiler_dir.is_dir()

        semantics_file = compiler_dir / "semantics.py"
        assert semantics_file.is_file()
        semantics_content = semantics_file.read_text(encoding="utf-8").lower()

        # semantics.py must contain zero provider-specific concepts
        forbidden_in_semantics = [
            "nebius",
            "nvidia",
            "nemotron",
            "token factory",
            "live_nebius",
            "basebreak.adapters",
        ]
        for term in forbidden_in_semantics:
            assert term not in semantics_content, (
                f"Provider-specific identifier '{term}' found in semantics.py"
            )

        # Compiler production files must contain zero adapter imports or LIVE_NEBIUS
        for py_file in compiler_dir.glob("*.py"):
            content = py_file.read_text(encoding="utf-8")
            assert "basebreak.adapters" not in content, (
                f"Adapter leakage detected in {py_file.name}"
            )
            assert "LIVE_NEBIUS" not in content, (
                f"LIVE_NEBIUS provenance leak detected in {py_file.name}"
            )

    # C. No production compiler class directly calls a provider/model
    def test_c_no_production_compiler_class_calls_provider_model(self) -> None:
        import basebreak.compiler.semantics as comp_semantics

        # NemotronSemanticsClassifier must be completely absent from compiler core
        assert not hasattr(comp_semantics, "NemotronSemanticsClassifier")

        # Inspect all classes defined in semantics.py
        for attr_name in comp_semantics.__all__:
            obj = getattr(comp_semantics, attr_name)
            if isinstance(obj, type):
                assert not hasattr(obj, "complete"), (
                    f"Class {attr_name} must not have complete() method"
                )
                assert not hasattr(obj, "infer"), f"Class {attr_name} must not have infer() method"
                assert not hasattr(obj, "model_client"), (
                    f"Class {attr_name} must not have model_client attribute"
                )

    # D. Deterministic clear BUG_FIX case remains correct
    def test_d_deterministic_clear_bug_fix(self) -> None:
        task = ingest_task(
            "Fix critical null pointer exception crash and traceback in auth handler."
        )
        result = classify_semantics_deterministically(task)

        assert result.change_class == ChangeClass.BUG_FIX
        assert result.certainty == CertaintyLevel.CONFIDENT
        assert result.is_confident is True
        assert result.confidence > 0.0
        assert result.verification_requirement is not None
        assert result.verification_requirement.change_class == ChangeClass.BUG_FIX
        assert len(result.evidence_citations) > 0
        for citation in result.evidence_citations:
            assert citation in task.normalized_text

    # E. Deterministic clear FEATURE case remains correct
    def test_e_deterministic_clear_feature(self) -> None:
        task = ingest_task(
            "Add support for YAML formatted outputs and new capability to filter by tag."
        )
        result = classify_semantics_deterministically(task)

        assert result.change_class == ChangeClass.FEATURE
        assert result.certainty == CertaintyLevel.CONFIDENT
        assert result.is_confident is True
        assert result.confidence > 0.0
        assert result.verification_requirement is not None
        assert result.verification_requirement.change_class == ChangeClass.FEATURE
        assert len(result.evidence_citations) > 0
        for citation in result.evidence_citations:
            assert citation in task.normalized_text

    # F. All six representative canonical classes covered
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
    def test_f_all_six_canonical_classes_covered(
        self, task_text: str, expected_class: ChangeClass
    ) -> None:
        task = ingest_task(task_text)
        result = classify_semantics_deterministically(task)

        assert result.change_class == expected_class
        assert result.certainty == CertaintyLevel.CONFIDENT
        assert result.is_confident is True
        assert result.verification_requirement is not None
        assert result.verification_requirement.change_class == expected_class

    # G. Mixed signals remain AMBIGUOUS
    def test_g_mixed_signals_remain_ambiguous(self) -> None:
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

    # H. Insufficient signals remain UNKNOWN
    def test_h_insufficient_signals_remain_unknown(self) -> None:
        task = ingest_task("Hello world this is some random text without technical direction.")
        result = classify_semantics_deterministically(task)

        assert result.certainty == CertaintyLevel.UNKNOWN
        assert result.change_class is None
        assert result.confidence == 0.0
        assert result.is_confident is False

        # Model proposal cannot manufacture authority when task evidence is insufficient
        model_json = json.dumps(
            {
                "change_class": None,
                "certainty": "UNKNOWN",
                "confidence": 0.0,
                "alternative_classes": [],
                "rationale": "Model recognizes UNKNOWN",
                "evidence_citations": ["Hello world"],
            }
        )
        proposal = parse_and_validate_semantics_proposal(model_json, task, "test-model")
        reconciled = reconcile_semantics(task, result.deterministic_facts, proposal)

        assert reconciled.certainty == CertaintyLevel.UNKNOWN
        assert reconciled.change_class is None
        assert reconciled.is_confident is False
        assert "UNKNOWN" in reconciled.rationale

    # I. Malformed JSON fails closed
    def test_i_malformed_json_fails_closed(self) -> None:
        task = ingest_task("Fix crash on startup.")
        with pytest.raises(MalformedModelSemanticsError, match="Model output is not valid JSON"):
            parse_and_validate_semantics_proposal("not json { broken", task, "test-model")

        with pytest.raises(MalformedModelSemanticsError, match="empty or whitespace-only"):
            parse_and_validate_semantics_proposal("   \n\t ", task, "test-model")

        with pytest.raises(MalformedModelSemanticsError, match="Expected JSON object"):
            parse_and_validate_semantics_proposal('["BUG_FIX"]', task, "test-model")

    # J. Every missing required model-proposal field fails closed
    @pytest.mark.parametrize(
        "missing_key",
        [
            "change_class",
            "certainty",
            "confidence",
            "alternative_classes",
            "rationale",
            "evidence_citations",
        ],
    )
    def test_j_missing_required_model_proposal_fields_fails_closed(self, missing_key: str) -> None:
        task = ingest_task("Fix crash on startup.")
        valid_payload = {
            "change_class": "BUG_FIX",
            "certainty": "CONFIDENT",
            "confidence": 0.95,
            "alternative_classes": [],
            "rationale": "Fixes startup crash",
            "evidence_citations": ["Fix crash"],
        }
        del valid_payload[missing_key]
        raw_json = json.dumps(valid_payload)

        with pytest.raises(MalformedModelSemanticsError, match="missing required schema field"):
            parse_and_validate_semantics_proposal(raw_json, task, "test-model")

    # K. Wrong field types fail closed
    def test_k_wrong_field_types_fail_closed(self) -> None:
        task = ingest_task("Fix crash on startup.")

        base_valid = {
            "change_class": "BUG_FIX",
            "certainty": "CONFIDENT",
            "confidence": 0.9,
            "alternative_classes": [],
            "rationale": "Valid rationale",
            "evidence_citations": ["Fix crash"],
        }

        # 1. change_class bad type
        bad_cc = {**base_valid, "change_class": 42}
        with pytest.raises(
            MalformedModelSemanticsError, match="'change_class' must be str or null"
        ):
            parse_and_validate_semantics_proposal(json.dumps(bad_cc), task, "test-model")

        # 2. certainty bad type (bool)
        bad_cert_bool = {**base_valid, "certainty": True}
        with pytest.raises(MalformedModelSemanticsError, match="'certainty' must be str"):
            parse_and_validate_semantics_proposal(json.dumps(bad_cert_bool), task, "test-model")

        # 3. certainty unsupported value
        bad_cert_val = {**base_valid, "certainty": "MAYBE"}
        with pytest.raises(MalformedModelSemanticsError, match="Unsupported certainty 'MAYBE'"):
            parse_and_validate_semantics_proposal(json.dumps(bad_cert_val), task, "test-model")

        # 4. confidence is string
        bad_conf_str = {**base_valid, "confidence": "0.9"}
        with pytest.raises(MalformedModelSemanticsError, match="'confidence' must be float or int"):
            parse_and_validate_semantics_proposal(json.dumps(bad_conf_str), task, "test-model")

        # 5. confidence is bool
        bad_conf_bool = {**base_valid, "confidence": True}
        with pytest.raises(MalformedModelSemanticsError, match="'confidence' must be float or int"):
            parse_and_validate_semantics_proposal(json.dumps(bad_conf_bool), task, "test-model")

        # 6. confidence out of bounds
        bad_conf_bounds = {**base_valid, "confidence": 1.5}
        with pytest.raises(MalformedModelSemanticsError, match="Confidence out of bounds"):
            parse_and_validate_semantics_proposal(json.dumps(bad_conf_bounds), task, "test-model")

        # 7. alternative_classes not list
        bad_alts_str = {**base_valid, "alternative_classes": "FEATURE"}
        with pytest.raises(
            MalformedModelSemanticsError, match="'alternative_classes' must be list"
        ):
            parse_and_validate_semantics_proposal(json.dumps(bad_alts_str), task, "test-model")

        # 8. alternative_classes item not string
        bad_alts_item = {**base_valid, "alternative_classes": [123]}
        with pytest.raises(
            MalformedModelSemanticsError, match="alternative_classes items must be str"
        ):
            parse_and_validate_semantics_proposal(json.dumps(bad_alts_item), task, "test-model")

        # 9. rationale not string
        bad_rat = {**base_valid, "rationale": 123}
        with pytest.raises(MalformedModelSemanticsError, match="'rationale' must be str"):
            parse_and_validate_semantics_proposal(json.dumps(bad_rat), task, "test-model")

        # 10. evidence_citations not list
        bad_cits = {**base_valid, "evidence_citations": "Fix crash"}
        with pytest.raises(MalformedModelSemanticsError, match="'evidence_citations' must be list"):
            parse_and_validate_semantics_proposal(json.dumps(bad_cits), task, "test-model")

        # 11. CONFIDENT with null change_class fails closed
        conf_null_class = {**base_valid, "change_class": None, "certainty": "CONFIDENT"}
        with pytest.raises(
            MalformedModelSemanticsError,
            match="change_class cannot be null when certainty is CONFIDENT",
        ):
            parse_and_validate_semantics_proposal(json.dumps(conf_null_class), task, "test-model")

        # 12. CONFIDENT with non-empty alternative_classes fails closed
        conf_with_alts = {
            **base_valid,
            "certainty": "CONFIDENT",
            "alternative_classes": ["FEATURE"],
        }
        with pytest.raises(
            MalformedModelSemanticsError,
            match="alternative_classes must be empty when certainty is CONFIDENT",
        ):
            parse_and_validate_semantics_proposal(json.dumps(conf_with_alts), task, "test-model")

        # 13. UNKNOWN with non-null change_class fails closed
        unknown_with_class = {
            **base_valid,
            "change_class": "BUG_FIX",
            "certainty": "UNKNOWN",
        }
        with pytest.raises(
            MalformedModelSemanticsError,
            match="change_class must be null when certainty is UNKNOWN",
        ):
            parse_and_validate_semantics_proposal(
                json.dumps(unknown_with_class), task, "test-model"
            )

    # L. Unsupported citation fails closed
    def test_l_unsupported_citation_fails_closed(self) -> None:
        task = ingest_task("Fix crash on empty list in token balancer.")
        unsupported_json = json.dumps(
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
            parse_and_validate_semantics_proposal(unsupported_json, task, "test-model")

    # M. Model conflict cannot change authoritative fields
    def test_m_model_conflict_cannot_change_authoritative_fields(self) -> None:
        task = ingest_task("Fix critical crash and null pointer exception in auth handler.")
        det_result = classify_semantics_deterministically(task)
        assert det_result.change_class == ChangeClass.BUG_FIX
        assert det_result.certainty == CertaintyLevel.CONFIDENT

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

        # Invariant: identical task + deterministic facts -> all authoritative fields identical
        assert reconciled.change_class == det_result.change_class
        assert reconciled.certainty == det_result.certainty
        assert reconciled.confidence == det_result.confidence
        assert reconciled.alternative_classes == det_result.alternative_classes
        assert reconciled.evidence_citations == det_result.evidence_citations
        assert reconciled.verification_requirement == det_result.verification_requirement

        # Model proposal retained purely as advisory metadata
        assert reconciled.model_proposal is not None
        assert reconciled.model_proposal.proposed_class == ChangeClass.FEATURE
        assert "overridden by deterministic fact authority" in reconciled.rationale

    # N. Model agreement cannot increase authoritative confidence
    def test_n_model_agreement_cannot_increase_authoritative_confidence(self) -> None:
        task = ingest_task("Fix critical null pointer exception crash.")
        det_result = classify_semantics_deterministically(task)
        det_conf = det_result.confidence

        # Model proposes same class with 1.0 confidence
        model_json = json.dumps(
            {
                "change_class": "BUG_FIX",
                "certainty": "CONFIDENT",
                "confidence": 1.0,
                "alternative_classes": [],
                "rationale": "Agrees with BUG_FIX with maximum confidence",
                "evidence_citations": ["Fix critical null pointer"],
            }
        )
        proposal = parse_and_validate_semantics_proposal(model_json, task, "test-model")
        reconciled = reconcile_semantics(task, det_result.deterministic_facts, proposal)

        # Confidence MUST NOT be boosted by model proposal
        assert reconciled.confidence == det_conf
        assert reconciled.confidence == det_result.confidence

    # O. Model citations cannot enter authoritative evidence_citations
    def test_o_model_citations_cannot_enter_authoritative_citations(self) -> None:
        task = ingest_task("Fix crash in auth handler and also add support for JSON logging.")
        det_result = classify_semantics_deterministically(task)
        det_citations = det_result.evidence_citations

        model_json = json.dumps(
            {
                "change_class": "BUG_FIX",
                "certainty": "CONFIDENT",
                "confidence": 0.9,
                "alternative_classes": [],
                "rationale": "Model with different citation",
                "evidence_citations": ["add support for JSON logging"],
            }
        )
        proposal = parse_and_validate_semantics_proposal(model_json, task, "test-model")
        reconciled = reconcile_semantics(task, det_result.deterministic_facts, proposal)

        # Model citations must NEVER enter authoritative citations
        assert reconciled.evidence_citations == det_citations
        assert "add support for JSON logging" not in reconciled.evidence_citations

    # P. Model alternative classes cannot enter authoritative alternative_classes
    def test_p_model_alternatives_cannot_enter_authoritative_alternatives(self) -> None:
        task = ingest_task(
            "Fix crash exception bug while also adding support for new feature and "
            "optimize throughput latency."
        )
        det_result = classify_semantics_deterministically(task)
        det_alts = det_result.alternative_classes

        model_json = json.dumps(
            {
                "change_class": "BUG_FIX",
                "certainty": "AMBIGUOUS",
                "confidence": 0.5,
                "alternative_classes": ["SECURITY_FIX", "DEP_API_CHANGE"],
                "rationale": "Model proposes extra alternatives",
                "evidence_citations": ["Fix crash"],
            }
        )
        proposal = parse_and_validate_semantics_proposal(model_json, task, "test-model")
        reconciled = reconcile_semantics(task, det_result.deterministic_facts, proposal)

        # Model alternative classes must NEVER contaminate authoritative alternative_classes
        assert reconciled.alternative_classes == det_alts
        assert ChangeClass.SECURITY_FIX not in reconciled.alternative_classes
        assert ChangeClass.DEP_API_CHANGE not in reconciled.alternative_classes

    # Q. Direct ModelChangeProposal(is_authoritative=True) fails closed
    def test_q_direct_model_change_proposal_is_authoritative_true_fails_closed(self) -> None:
        with pytest.raises(ValueError, match="ModelChangeProposal cannot be authoritative"):
            ModelChangeProposal(
                proposed_class=ChangeClass.BUG_FIX,
                certainty=CertaintyLevel.CONFIDENT,
                confidence=0.9,
                alternative_classes=(),
                rationale="Attempted authoritative",
                evidence_citations=(),
                raw_response="{}",
                model_id="test-model",
                is_authoritative=True,
            )

        # Also from_dict must reject is_authoritative=True (never coerce)
        bad_dict = {
            "proposed_class": "BUG_FIX",
            "certainty": "CONFIDENT",
            "confidence": 0.9,
            "alternative_classes": [],
            "rationale": "Attempted",
            "evidence_citations": [],
            "raw_response": "{}",
            "model_id": "test-model",
            "is_authoritative": True,
        }
        with pytest.raises(ValueError, match="ModelChangeProposal cannot be authoritative"):
            ModelChangeProposal.from_dict(bad_dict)

    # R. from_dict wrong types fail closed without coercion
    def test_r_from_dict_wrong_types_fail_closed_without_coercion(self) -> None:
        base_proposal = {
            "proposed_class": "BUG_FIX",
            "certainty": "CONFIDENT",
            "confidence": 0.9,
            "alternative_classes": [],
            "rationale": "Test",
            "evidence_citations": [],
            "raw_response": "{}",
            "model_id": "test-model",
        }

        # 1. confidence=True (bool) rejected without coercion to 1.0
        with pytest.raises(TypeError, match="confidence must be float or int"):
            ModelChangeProposal.from_dict({**base_proposal, "confidence": True})

        # 2. confidence="0.9" rejected without float() coercion
        with pytest.raises(TypeError, match="confidence must be float or int"):
            ModelChangeProposal.from_dict({**base_proposal, "confidence": "0.9"})

        # 3. prompt_tokens=True (bool) rejected
        with pytest.raises(TypeError, match="prompt_tokens must be a non-negative int"):
            ModelChangeProposal.from_dict({**base_proposal, "prompt_tokens": True})

        # 4. prompt_tokens="10" rejected
        with pytest.raises(TypeError, match="prompt_tokens must be a non-negative int"):
            ModelChangeProposal.from_dict({**base_proposal, "prompt_tokens": "10"})

        # 5. rationale=123 rejected
        with pytest.raises(TypeError, match="rationale must be str"):
            ModelChangeProposal.from_dict({**base_proposal, "rationale": 123})

        # 6. model_id=123 rejected
        with pytest.raises(TypeError, match="model_id must be str"):
            ModelChangeProposal.from_dict({**base_proposal, "model_id": 123})

        # 7. evidence_citations not a sequence of str
        with pytest.raises(TypeError, match="evidence_citations items must be str"):
            ModelChangeProposal.from_dict({**base_proposal, "evidence_citations": [123]})

        # 8. DeterministicClassificationFact.from_dict wrong types
        base_fact = {
            "inferred_class": "BUG_FIX",
            "certainty": "CONFIDENT",
            "confidence": 0.8,
            "rationale": "Fact",
        }
        with pytest.raises(TypeError, match="confidence must be float or int"):
            DeterministicClassificationFact.from_dict({**base_fact, "confidence": False})

        with pytest.raises(TypeError, match="confidence must be float or int"):
            DeterministicClassificationFact.from_dict({**base_fact, "confidence": "0.8"})

        # 9. ChangeSemanticsClassification.from_dict wrong types
        det_fact_obj = DeterministicClassificationFact.from_dict(base_fact)
        base_classif = {
            "task_digest": "abcd1234abcd1234",
            "change_class": "BUG_FIX",
            "certainty": "CONFIDENT",
            "confidence": 0.8,
            "rationale": "Classif",
            "deterministic_facts": det_fact_obj.to_dict(),
        }
        with pytest.raises(ValueError, match="task_digest must be a non-empty string"):
            ChangeSemanticsClassification.from_dict({**base_classif, "task_digest": 123})

        with pytest.raises(TypeError, match="confidence must be float or int"):
            ChangeSemanticsClassification.from_dict({**base_classif, "confidence": "0.8"})

        with pytest.raises(TypeError, match="deterministic_facts must be a mapping"):
            ChangeSemanticsClassification.from_dict(
                {**base_classif, "deterministic_facts": "not-map"}
            )

    # S. Stable strict round-trip succeeds for valid objects
    def test_s_stable_strict_round_trip(self) -> None:
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

    # T. Secret-bearing malformed proposal does not leak secret
    def test_t_secret_bearing_malformed_proposal_does_not_leak_secret(self) -> None:
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
                "certainty": "CONFIDENT",
                "confidence": 0.9,
                "alternative_classes": [],
                "rationale": "Secret test",
                "evidence_citations": [secret],
            }
        )
        with pytest.raises(UnsupportedCitationError) as exc_info_cit:
            parse_and_validate_semantics_proposal(bad_cit_with_secret, task, "test-model")

        cit_error_message = str(exc_info_cit.value)
        assert secret not in cit_error_message
        assert "[REDACTED]" in cit_error_message

    # U. No async/plugin dependency introduced
    def test_u_no_async_plugin_dependency(self) -> None:
        import basebreak.compiler.semantics as comp_semantics

        source_file = Path(comp_semantics.__file__)
        code = source_file.read_text(encoding="utf-8")

        assert "async def " not in code, "Semantics module must not define async functions"
        assert "await " not in code, "Semantics module must not use await"

    # Step 3 Invariant Verification: Identical task + facts -> invariant authoritative fields
    def test_model_non_authority_complete_invariant(self) -> None:
        task = ingest_task("Fix critical crash and null pointer exception in auth handler.")
        det_result = classify_semantics_deterministically(task)

        # Baseline: reconcile with no model proposal
        base_reconciled = reconcile_semantics(task, det_result.deterministic_facts, None)

        # Proposal 1: agreeing proposal with high confidence
        prop_agree = parse_and_validate_semantics_proposal(
            json.dumps(
                {
                    "change_class": "BUG_FIX",
                    "certainty": "CONFIDENT",
                    "confidence": 0.99,
                    "alternative_classes": [],
                    "rationale": "High confidence agreeing",
                    "evidence_citations": ["Fix critical crash"],
                }
            ),
            task,
            "model-1",
        )
        reconciled_agree = reconcile_semantics(task, det_result.deterministic_facts, prop_agree)

        # Proposal 2: conflicting proposal with different class
        prop_conflict = parse_and_validate_semantics_proposal(
            json.dumps(
                {
                    "change_class": "FEATURE",
                    "certainty": "CONFIDENT",
                    "confidence": 0.95,
                    "alternative_classes": [],
                    "rationale": "Conflicting",
                    "evidence_citations": ["Fix critical crash"],
                }
            ),
            task,
            "model-2",
        )
        reconciled_conflict = reconcile_semantics(
            task, det_result.deterministic_facts, prop_conflict
        )

        # Proposal 3: ambiguous proposal
        prop_ambig = parse_and_validate_semantics_proposal(
            json.dumps(
                {
                    "change_class": "BUG_FIX",
                    "certainty": "AMBIGUOUS",
                    "confidence": 0.4,
                    "alternative_classes": ["PERFORMANCE"],
                    "rationale": "Ambiguous",
                    "evidence_citations": ["Fix critical crash"],
                }
            ),
            task,
            "model-3",
        )
        reconciled_ambig = reconcile_semantics(task, det_result.deterministic_facts, prop_ambig)

        # Invariant check: ALL authoritative classification fields MUST be bit-for-bit identical
        for rec in (reconciled_agree, reconciled_conflict, reconciled_ambig):
            assert rec.change_class == base_reconciled.change_class
            assert rec.certainty == base_reconciled.certainty
            assert rec.confidence == base_reconciled.confidence
            assert rec.alternative_classes == base_reconciled.alternative_classes
            assert rec.evidence_citations == base_reconciled.evidence_citations
            assert rec.verification_requirement == base_reconciled.verification_requirement
