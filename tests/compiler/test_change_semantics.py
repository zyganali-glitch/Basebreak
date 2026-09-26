"""Tests for change semantics classification and uncertainty handling (P-06.03)."""

from __future__ import annotations

from typing import Any

import pytest

from basebreak.compiler.ingestion import ingest_task
from basebreak.compiler.semantics import (
    AmbiguousSemanticsError,
    CertaintyLevel,
    ChangeSemanticsClassification,
    InvalidChangeClassError,
    MalformedClassificationOutputError,
    NemotronSemanticsClassifier,
    UnsupportedCitationError,
    classify_semantics_deterministically,
    parse_and_validate_classification,
)
from basebreak.domain.semantics import ChangeClass


class DummyModelResult:
    def __init__(self, content: str) -> None:
        self.content = content


class MockModelClient:
    def __init__(self, response_text: str) -> None:
        self.response_text = response_text
        self.calls: list[dict[str, Any]] = []

    async def generate(self, **kwargs: Any) -> DummyModelResult:
        self.calls.append(kwargs)
        return DummyModelResult(self.response_text)


class TestChangeSemanticsClassificationModel:
    """Tests for the ChangeSemanticsClassification dataclass."""

    def test_valid_confident_classification(self) -> None:
        classification = ChangeSemanticsClassification(
            change_class=ChangeClass.BUG_FIX,
            certainty=CertaintyLevel.CONFIDENT,
            confidence=0.95,
            alternative_classes=(),
            rationale="Fixes a crash when parsing corrupted headers.",
            evidence_citations=("Fixes a crash",),
        )
        assert classification.is_confident is True
        assert classification.is_ambiguous is False
        assert classification.is_unknown is False
        assert classification.change_class == ChangeClass.BUG_FIX
        assert classification.require_definite_class() == ChangeClass.BUG_FIX
        assert classification.verification_requirement is not None
        assert classification.verification_requirement.base_expectation == "FAIL"
        assert classification.verification_requirement.candidate_expectation == "PASS"

    def test_invalid_confidence_raises_error(self) -> None:
        with pytest.raises(ValueError, match="confidence must be a float between 0.0 and 1.0"):
            ChangeSemanticsClassification(
                change_class=ChangeClass.FEATURE,
                certainty=CertaintyLevel.CONFIDENT,
                confidence=1.5,
                alternative_classes=(),
                rationale="Invalid",
                evidence_citations=(),
            )

        with pytest.raises(ValueError, match="confidence must be a float between 0.0 and 1.0"):
            ChangeSemanticsClassification(
                change_class=ChangeClass.FEATURE,
                certainty=CertaintyLevel.CONFIDENT,
                confidence=-0.1,
                alternative_classes=(),
                rationale="Invalid",
                evidence_citations=(),
            )

    def test_invalid_certainty_type(self) -> None:
        with pytest.raises(TypeError, match="certainty must be CertaintyLevel"):
            ChangeSemanticsClassification(
                change_class=ChangeClass.BUG_FIX,
                certainty="HIGH",  # type: ignore[arg-type]
                confidence=0.9,
                alternative_classes=(),
                rationale="Invalid",
                evidence_citations=(),
            )

    def test_ambiguous_classification_blocks_definite_class(self) -> None:
        classification = ChangeSemanticsClassification(
            change_class=ChangeClass.BUG_FIX,
            certainty=CertaintyLevel.AMBIGUOUS,
            confidence=0.55,
            alternative_classes=(ChangeClass.FEATURE,),
            rationale="Task both fixes a bug and introduces new options.",
            evidence_citations=(),
        )
        assert classification.is_ambiguous is True
        assert classification.is_confident is False
        with pytest.raises(AmbiguousSemanticsError, match="Change semantics are ambiguous"):
            classification.require_definite_class()

    def test_unknown_classification_blocks_definite_class(self) -> None:
        classification = ChangeSemanticsClassification(
            change_class=None,
            certainty=CertaintyLevel.UNKNOWN,
            confidence=0.1,
            alternative_classes=(),
            rationale="Vague task description with no identifiable keywords.",
            evidence_citations=(),
        )
        assert classification.is_unknown is True
        with pytest.raises(AmbiguousSemanticsError, match="Cannot obtain definite change class"):
            classification.require_definite_class()

    def test_secret_redaction_in_repr(self) -> None:
        secret_token = "sk-nebius-live-abcdef1234567890abcdef123456"
        classification = ChangeSemanticsClassification(
            change_class=ChangeClass.SECURITY_FIX,
            certainty=CertaintyLevel.CONFIDENT,
            confidence=0.99,
            alternative_classes=(),
            rationale=f"Remediates leak of api_key={secret_token}",
            evidence_citations=(),
        )
        rep = repr(classification)
        assert secret_token not in rep
        assert "[REDACTED" in rep


class TestDeterministicHeuristicClassifier:
    """Tests for the deterministic rule-based semantics classifier."""

    def test_classifies_bug_fix(self) -> None:
        task = ingest_task(
            "Fix the critical bug where null pointer exception causes engine to crash."
        )
        result = classify_semantics_deterministically(task)
        assert result.change_class == ChangeClass.BUG_FIX
        assert result.is_confident is True
        assert len(result.evidence_citations) > 0
        for cit in result.evidence_citations:
            assert cit in task.normalized_text

    def test_classifies_feature(self) -> None:
        task = ingest_task(
            "Add support for YAML formatted outputs and new capability to filter by tag."
        )
        result = classify_semantics_deterministically(task)
        assert result.change_class == ChangeClass.FEATURE
        assert result.is_confident is True
        assert len(result.evidence_citations) > 0
        for cit in result.evidence_citations:
            assert cit in task.normalized_text

    def test_classifies_security_fix(self) -> None:
        task = ingest_task(
            "Fix critical vulnerability CVE-2026-9999 remote code execution and untrusted input."
        )
        result = classify_semantics_deterministically(task)
        assert result.change_class == ChangeClass.SECURITY_FIX
        assert result.is_confident is True
        assert len(result.evidence_citations) > 0
        for cit in result.evidence_citations:
            assert cit in task.normalized_text

    def test_classifies_performance(self) -> None:
        task = ingest_task(
            "Optimize query throughput to speed up benchmark latency and eliminate memory leak."
        )
        result = classify_semantics_deterministically(task)
        assert result.change_class == ChangeClass.PERFORMANCE
        assert result.is_confident is True
        assert len(result.evidence_citations) > 0
        for cit in result.evidence_citations:
            assert cit in task.normalized_text

    def test_classifies_refactor(self) -> None:
        task = ingest_task(
            "Refactor internal pipeline structure with no functional change to simplify modularize."
        )
        result = classify_semantics_deterministically(task)
        assert result.change_class == ChangeClass.REFACTOR
        assert result.is_confident is True
        assert len(result.evidence_citations) > 0
        for cit in result.evidence_citations:
            assert cit in task.normalized_text

    def test_classifies_dep_api_change(self) -> None:
        task = ingest_task(
            "Upgrade dependency to astral uv 0.5.0 and migrate deprecated api signature."
        )
        result = classify_semantics_deterministically(task)
        assert result.change_class == ChangeClass.DEP_API_CHANGE
        assert result.is_confident is True
        assert len(result.evidence_citations) > 0
        for cit in result.evidence_citations:
            assert cit in task.normalized_text

    def test_detects_ambiguity_on_competing_signals(self) -> None:
        task = ingest_task(
            "Fix crash exception bug while also adding support for new feature and "
            "optimize throughput latency."
        )
        result = classify_semantics_deterministically(task)
        assert result.certainty == CertaintyLevel.AMBIGUOUS
        assert len(result.alternative_classes) > 0

    def test_unclassifiable_text_returns_unknown(self) -> None:
        task = ingest_task("Hello world this is some random text without technical direction.")
        result = classify_semantics_deterministically(task)
        assert result.certainty == CertaintyLevel.UNKNOWN
        assert result.change_class is None
        assert result.confidence == 0.0


class TestParseAndValidateClassification:
    """Tests for deterministic parsing and validation of model outputs."""

    def test_valid_json_parsing(self) -> None:
        task = ingest_task("Fix crash on empty list in token balancer.")
        raw_json = """{
            "change_class": "BUG_FIX",
            "certainty": "CONFIDENT",
            "confidence": 0.95,
            "alternative_classes": [],
            "rationale": "Task specifies fixing an empty list crash.",
            "evidence_citations": ["Fix crash on empty list"]
        }"""
        result = parse_and_validate_classification(raw_json, task)
        assert result.change_class == ChangeClass.BUG_FIX
        assert result.certainty == CertaintyLevel.CONFIDENT
        assert result.confidence == 0.95
        assert result.evidence_citations == ("Fix crash on empty list",)

    def test_markdown_code_fence_parsing(self) -> None:
        task = ingest_task("Add support for async streaming.")
        raw_output = """Here is the classification:
```json
{
    "change_class": "FEATURE",
    "certainty": "CONFIDENT",
    "confidence": 0.9,
    "alternative_classes": [],
    "rationale": "Adds new feature",
    "evidence_citations": ["Add support for async streaming"]
}
```
Hope this helps!"""
        result = parse_and_validate_classification(raw_output, task)
        assert result.change_class == ChangeClass.FEATURE
        assert result.certainty == CertaintyLevel.CONFIDENT

    def test_invalid_change_class_fails_closed(self) -> None:
        task = ingest_task("Clean up comments.")
        raw_json = """{
            "change_class": "CHORE",
            "certainty": "CONFIDENT",
            "confidence": 0.8,
            "alternative_classes": [],
            "rationale": "Chore",
            "evidence_citations": []
        }"""
        with pytest.raises(InvalidChangeClassError, match="Unsupported change class 'CHORE'"):
            parse_and_validate_classification(raw_json, task)

    def test_unsupported_citation_fails_closed(self) -> None:
        task = ingest_task("Fix crash in parser.")
        raw_json = """{
            "change_class": "BUG_FIX",
            "certainty": "CONFIDENT",
            "confidence": 0.95,
            "alternative_classes": [],
            "rationale": "Fix crash",
            "evidence_citations": ["Invented quotation that is not in the task text"]
        }"""
        with pytest.raises(
            UnsupportedCitationError, match="Evidence citation is not present in task text"
        ):
            parse_and_validate_classification(raw_json, task)

    def test_malformed_json_fails_closed(self) -> None:
        task = ingest_task("Fix bug.")
        raw_text = "This is not json at all."
        with pytest.raises(MalformedClassificationOutputError):
            parse_and_validate_classification(raw_text, task)

    def test_out_of_bounds_confidence_fails_closed(self) -> None:
        task = ingest_task("Fix bug.")
        raw_json = """{
            "change_class": "BUG_FIX",
            "confidence": 1.5,
            "rationale": "High confidence"
        }"""
        with pytest.raises(MalformedClassificationOutputError, match="Confidence out of bounds"):
            parse_and_validate_classification(raw_json, task)


class TestNemotronSemanticsClassifier:
    """Tests for NemotronSemanticsClassifier with mock client."""

    @pytest.mark.anyio
    async def test_successful_classification(self) -> None:
        task = ingest_task("Remediate SQL injection vulnerability in user login endpoint.")
        response_json = """{
            "change_class": "SECURITY_FIX",
            "certainty": "CONFIDENT",
            "confidence": 0.98,
            "alternative_classes": [],
            "rationale": "Task addresses SQL injection vulnerability.",
            "evidence_citations": ["Remediate SQL injection vulnerability"]
        }"""
        client = MockModelClient(response_json)
        classifier = NemotronSemanticsClassifier(model_client=client)

        result = await classifier.classify(task)

        assert len(client.calls) == 1
        assert client.calls[0]["model"] == "nvidia/Nemotron-3_5-Lightning"
        assert result.change_class == ChangeClass.SECURITY_FIX
        assert result.is_confident is True
        assert result.confidence == 0.98
        assert result.verification_requirement is not None
        assert result.verification_requirement.base_expectation == "EXPLOITABLE"
        assert result.verification_requirement.candidate_expectation == "BLOCKED"
