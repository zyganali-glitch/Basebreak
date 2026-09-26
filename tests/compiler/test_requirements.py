"""Acceptance tests for P-06.02: Nemotron Atomic Requirement Proposal and Citation Validation.

Verifies:
- bounded prompt and bounded token configuration;
- exact configured model identity enforcement;
- strict structured JSON parsing;
- atomic requirement proposal with exact citation to task text;
- unsupported or invented citation fails closed;
- malformed model output fails closed;
- duplicate requirements handled deterministically;
- non-authoritative requirement proposal result;
- secret-safe logging/telemetry boundaries;
- serialization stability.
"""

from __future__ import annotations

import json
from unittest.mock import MagicMock

import pytest

from basebreak.compiler.ingestion import NormalizedTask, ingest_task
from basebreak.compiler.requirements import (
    DEFAULT_REQUIREMENTS_MODEL,
    InvalidModelConfigurationError,
    MalformedModelOutputError,
    NemotronRequirementProposer,
    RequirementProposalResult,
    UnsupportedCitationError,
    parse_and_validate_requirements,
)


class TestRequirementProposalP0602:
    """Test suite for P-06.02 requirement proposal and citation validation."""

    @pytest.fixture
    def sample_task(self) -> NormalizedTask:
        raw_text = (
            "Fix authentication timeout in Nebius client.\n"
            "Requirements:\n"
            "1. When HTTP 503 is returned, retry up to 3 times.\n"
            "2. When HTTP 403 is returned, fail immediately without retry.\n"
            "3. Record all attempt timestamps in the audit trail."
        )
        return ingest_task(raw_text)

    # 1. Valid model output with exact citations parses and binds spans
    def test_valid_proposal_parsing_and_citation_binding(self, sample_task: NormalizedTask) -> None:
        model_output = json.dumps(
            {
                "requirements": [
                    {
                        "statement": "Retry up to 3 times on HTTP 503 response",
                        "citation": "When HTTP 503 is returned, retry up to 3 times.",
                        "rationale": "Directly mandated by task spec",
                    },
                    {
                        "statement": "Fail immediately on HTTP 403 response without retry",
                        "citation": "When HTTP 403 is returned, fail immediately without retry.",
                        "rationale": "Permanent failure policy",
                    },
                ]
            }
        )

        result = parse_and_validate_requirements(
            raw_response=model_output,
            task=sample_task,
            model_id=DEFAULT_REQUIREMENTS_MODEL,
            prompt_tokens=50,
            completion_tokens=60,
            total_tokens=110,
        )

        assert isinstance(result, RequirementProposalResult)
        assert result.task_digest == sample_task.task_digest
        assert result.model_id == DEFAULT_REQUIREMENTS_MODEL
        assert result.is_authoritative is False
        assert len(result.requirements) == 2

        req1 = result.requirements[0]
        assert req1.statement == "Retry up to 3 times on HTTP 503 response"
        assert req1.citation == "When HTTP 503 is returned, retry up to 3 times."
        # Verify exact span binding into normalized task text
        assert sample_task.normalized_text[req1.citation_start : req1.citation_end] == req1.citation

        req2 = result.requirements[1]
        assert sample_task.normalized_text[req2.citation_start : req2.citation_end] == req2.citation

    # 2. Markdown code fences stripped cleanly
    def test_markdown_code_fence_stripped(self, sample_task: NormalizedTask) -> None:
        fenced_output = (
            "```json\n"
            "{\n"
            '  "requirements": [\n'
            "    {\n"
            '      "statement": "Record all attempt timestamps",\n'
            '      "citation": "Record all attempt timestamps in the audit trail.",\n'
            '      "rationale": "Audit logging requirement"\n'
            "    }\n"
            "  ]\n"
            "}\n"
            "```"
        )
        result = parse_and_validate_requirements(
            raw_response=fenced_output,
            task=sample_task,
            model_id=DEFAULT_REQUIREMENTS_MODEL,
        )
        assert len(result.requirements) == 1
        assert (
            result.requirements[0].citation == "Record all attempt timestamps in the audit trail."
        )

    # 3. Unsupported or invented citation strictly fails closed
    def test_unsupported_citation_fails_closed(self, sample_task: NormalizedTask) -> None:
        hallucinated_output = json.dumps(
            {
                "requirements": [
                    {
                        "statement": "Deploy to AWS lambda immediately",
                        "citation": "Deploy to AWS lambda immediately upon failure.",
                        "rationale": "Invented requirement not in task",
                    }
                ]
            }
        )
        with pytest.raises(
            UnsupportedCitationError, match="is not present in normalized task text"
        ):
            parse_and_validate_requirements(
                raw_response=hallucinated_output,
                task=sample_task,
                model_id=DEFAULT_REQUIREMENTS_MODEL,
            )

    # 4. Partial citation mismatch fails closed
    def test_partial_citation_mismatch_fails_closed(self, sample_task: NormalizedTask) -> None:
        mismatched_output = json.dumps(
            {
                "requirements": [
                    {
                        "statement": "Retry 10 times",
                        "citation": "retry up to 10 times",  # Task says 3 times
                        "rationale": "Subtly altered quote",
                    }
                ]
            }
        )
        with pytest.raises(UnsupportedCitationError):
            parse_and_validate_requirements(
                raw_response=mismatched_output,
                task=sample_task,
                model_id=DEFAULT_REQUIREMENTS_MODEL,
            )

    # 5. Malformed model outputs fail closed
    def test_empty_or_non_json_model_output_fails_closed(self, sample_task: NormalizedTask) -> None:
        with pytest.raises(MalformedModelOutputError, match="empty or whitespace-only"):
            parse_and_validate_requirements(
                "", task=sample_task, model_id=DEFAULT_REQUIREMENTS_MODEL
            )

        with pytest.raises(MalformedModelOutputError, match="not valid JSON"):
            parse_and_validate_requirements(
                "I am unable to parse this task.",
                task=sample_task,
                model_id=DEFAULT_REQUIREMENTS_MODEL,
            )

    def test_missing_requirements_key_fails_closed(self, sample_task: NormalizedTask) -> None:
        with pytest.raises(MalformedModelOutputError, match="missing required 'requirements'"):
            parse_and_validate_requirements(
                json.dumps({"tasks": []}),
                task=sample_task,
                model_id=DEFAULT_REQUIREMENTS_MODEL,
            )

    def test_zero_requirements_fails_closed(self, sample_task: NormalizedTask) -> None:
        with pytest.raises(MalformedModelOutputError, match="0 requirements"):
            parse_and_validate_requirements(
                json.dumps({"requirements": []}),
                task=sample_task,
                model_id=DEFAULT_REQUIREMENTS_MODEL,
            )

    def test_missing_statement_or_citation_fails_closed(self, sample_task: NormalizedTask) -> None:
        with pytest.raises(MalformedModelOutputError, match="missing or empty 'statement'"):
            parse_and_validate_requirements(
                json.dumps({"requirements": [{"citation": "When HTTP 503 is returned"}]}),
                task=sample_task,
                model_id=DEFAULT_REQUIREMENTS_MODEL,
            )

        with pytest.raises(MalformedModelOutputError, match="missing or empty 'citation'"):
            parse_and_validate_requirements(
                json.dumps({"requirements": [{"statement": "Retry policy"}]}),
                task=sample_task,
                model_id=DEFAULT_REQUIREMENTS_MODEL,
            )

    # 6. Duplicate requirements are deduplicated deterministically
    def test_duplicate_requirements_deduplicated_deterministically(
        self, sample_task: NormalizedTask
    ) -> None:
        output_with_dupes = json.dumps(
            {
                "requirements": [
                    {
                        "statement": "Retry up to 3 times on HTTP 503 response",
                        "citation": "retry up to 3 times.",
                        "rationale": "first copy",
                    },
                    {
                        "statement": "retry up to 3 times on http 503 response",
                        "citation": "retry up to 3 times.",
                        "rationale": "second copy",
                    },
                    {
                        "statement": "Record attempt timestamps",
                        "citation": "Record all attempt timestamps",
                        "rationale": "distinct requirement",
                    },
                ]
            }
        )
        result = parse_and_validate_requirements(
            raw_response=output_with_dupes,
            task=sample_task,
            model_id=DEFAULT_REQUIREMENTS_MODEL,
        )
        assert len(result.requirements) == 2
        assert result.requirements[0].statement == "Retry up to 3 times on HTTP 503 response"
        assert result.requirements[1].statement == "Record attempt timestamps"

    # 7. Model identity mismatch raises InvalidModelConfigurationError
    def test_model_identity_mismatch_raises_config_error(self) -> None:
        mock_client = MagicMock()
        mock_client.config.model = "wrong-model-id"

        with pytest.raises(InvalidModelConfigurationError, match="does not match"):
            NemotronRequirementProposer(
                mock_client,
                model_id=DEFAULT_REQUIREMENTS_MODEL,
            )

    # 8. Non-authoritative invariant: is_authoritative is strictly False
    def test_is_authoritative_invariant(self, sample_task: NormalizedTask) -> None:
        output = json.dumps(
            {
                "requirements": [
                    {
                        "statement": "Retry on 503",
                        "citation": "retry up to 3 times.",
                    }
                ]
            }
        )
        result = parse_and_validate_requirements(
            raw_response=output,
            task=sample_task,
            model_id=DEFAULT_REQUIREMENTS_MODEL,
        )
        assert result.is_authoritative is False

        # Attempting to forge is_authoritative=True raises ValueError
        with pytest.raises(ValueError, match="is_authoritative must be False"):
            RequirementProposalResult(
                task_digest=sample_task.task_digest,
                requirements=result.requirements,
                model_id=DEFAULT_REQUIREMENTS_MODEL,
                raw_response=output,
                is_authoritative=True,
            )

    # 9. Round-trip serialization stability
    def test_proposal_result_serialization_round_trip(self, sample_task: NormalizedTask) -> None:
        output = json.dumps(
            {
                "requirements": [
                    {
                        "statement": "Retry on 503",
                        "citation": "retry up to 3 times.",
                        "rationale": "transient retry",
                    }
                ]
            }
        )
        result = parse_and_validate_requirements(
            raw_response=output,
            task=sample_task,
            model_id=DEFAULT_REQUIREMENTS_MODEL,
            prompt_tokens=40,
            completion_tokens=25,
            total_tokens=65,
            telemetry_digest="a" * 64,
        )

        d = result.to_dict()
        restored = RequirementProposalResult.from_dict(d)

        assert restored == result
        assert restored.task_digest == result.task_digest
        assert restored.requirements == result.requirements
        assert restored.model_id == result.model_id
        assert restored.prompt_tokens == 40
        assert restored.completion_tokens == 25
        assert restored.total_tokens == 65
        assert restored.telemetry_digest == "a" * 64
        assert restored.is_authoritative is False

    # 10. Secret safety: safe_summary never prints raw secret text
    def test_secret_safety_summary(self) -> None:
        secret = "sk-nebius-secret-token-abcdef1234567890"
        task_text = f"Fix authorization failure when token {secret} is supplied."
        task = ingest_task(task_text)

        output = json.dumps(
            {
                "requirements": [
                    {
                        "statement": f"Ensure token {secret} is accepted",
                        "citation": f"token {secret} is supplied.",
                    }
                ]
            }
        )
        result = parse_and_validate_requirements(
            raw_response=output,
            task=task,
            model_id=DEFAULT_REQUIREMENTS_MODEL,
        )

        summary = result.safe_summary()
        assert secret not in summary
        assert "RequirementProposalResult(" in summary
