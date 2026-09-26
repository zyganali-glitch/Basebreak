"""Nemotron requirement extraction and deterministic citation validation.

P-06.02: Propose atomic acceptance requirements using Nebius/Nemotron with
strict citations to normalized task text.

Architectural invariants:
- Model role is PROPOSAL ONLY.
- Deterministic code validates structure, bounds, and citations.
- Every atomic requirement must cite a verbatim substring in the normalized task text.
- Invented or unsupported citations fail closed.
- Duplicate requirements are handled deterministically.
- Telemetry remains non-authoritative.
- Zero secret leakage in logs or diagnostics.
"""

from __future__ import annotations

import json
import re
from collections.abc import Mapping, Sequence
from dataclasses import dataclass
from typing import Any

from basebreak.compiler.ingestion import NormalizedTask
from basebreak.security.secret_policy import redact_log_text

PROPOSAL_SYSTEM_PROMPT = """You are the Basebreak Requirement Extraction Engine.
Your role is to propose atomic acceptance requirements from the provided engineering task.
RULES:
1. Every proposed requirement MUST be directly supported by the task text.
2. For every requirement, you MUST provide an exact, verbatim quotation ('citation')
   copied directly from the task text.
3. Do not invent requirements or cite text that does not exist in the task text.
4. Output MUST be valid JSON with the exact structure:
{
  "requirements": [
    {
      "statement": "Clear, atomic, verifiable acceptance statement",
      "citation": "Exact verbatim substring from the task text",
      "rationale": "Brief rationale"
    }
  ]
}
Do not include any commentary or explanation outside the JSON object."""

DEFAULT_REQUIREMENTS_MODEL: str = "nvidia/Nemotron-3_5-Lightning"
DEFAULT_PROPOSAL_MAX_TOKENS: int = 2048


class RequirementProposalError(Exception):
    """Base exception for requirement proposal and validation failures."""


class MalformedModelOutputError(RequirementProposalError):
    """Raised when model response is not valid JSON or lacks required schema."""


class UnsupportedCitationError(RequirementProposalError):
    """Raised when a proposed requirement cites text not present in the task text."""


class InvalidModelConfigurationError(RequirementProposalError):
    """Raised when model client configuration violates verified constraints."""


@dataclass(frozen=True, slots=True)
class ProposedRequirement:
    """Atomic acceptance requirement proposed by model with verified source citation.

    Attributes:
        statement: Verifiable requirement statement.
        citation: Exact verbatim substring from normalized task text.
        citation_start: 0-indexed character start offset in normalized task text.
        citation_end: 0-indexed character end offset in normalized task text.
        rationale: Brief justification or explanation.
    """

    statement: str
    citation: str
    citation_start: int
    citation_end: int
    rationale: str = ""

    def __post_init__(self) -> None:
        if not isinstance(self.statement, str):
            raise TypeError(f"statement must be str, got {type(self.statement).__name__}")
        stmt = self.statement.strip()
        if not stmt:
            raise ValueError("statement must not be empty or whitespace-only")
        if stmt != self.statement:
            object.__setattr__(self, "statement", stmt)

        if not isinstance(self.citation, str):
            raise TypeError(f"citation must be str, got {type(self.citation).__name__}")
        cit = self.citation.strip()
        if not cit:
            raise ValueError("citation must not be empty or whitespace-only")

        if not isinstance(self.citation_start, int) or isinstance(self.citation_start, bool):
            raise TypeError(f"citation_start must be int, got {type(self.citation_start).__name__}")
        if not isinstance(self.citation_end, int) or isinstance(self.citation_end, bool):
            raise TypeError(f"citation_end must be int, got {type(self.citation_end).__name__}")
        if self.citation_start < 0 or self.citation_end < self.citation_start:
            raise ValueError(f"Invalid citation span: [{self.citation_start}:{self.citation_end}]")
        if not isinstance(self.rationale, str):
            raise TypeError(f"rationale must be str, got {type(self.rationale).__name__}")

    def to_dict(self) -> dict[str, Any]:
        """Deterministic dictionary serialization."""
        return {
            "statement": self.statement,
            "citation": self.citation,
            "citation_start": self.citation_start,
            "citation_end": self.citation_end,
            "rationale": self.rationale,
        }

    @classmethod
    def from_dict(cls, data: Mapping[str, Any]) -> ProposedRequirement:
        """Construct from dictionary with validation."""
        required = {"statement", "citation", "citation_start", "citation_end"}
        missing = required - set(data.keys())
        if missing:
            raise ValueError(f"Missing required fields for ProposedRequirement: {sorted(missing)}")
        return cls(
            statement=data["statement"],
            citation=data["citation"],
            citation_start=data["citation_start"],
            citation_end=data["citation_end"],
            rationale=data.get("rationale", ""),
        )


@dataclass(frozen=True, slots=True)
class RequirementProposalResult:
    """Encapsulates the complete requirement proposal result for a normalized task.

    Attributes:
        task_digest: SHA-256 digest of the normalized task text.
        requirements: Deterministically ordered, validated atomic requirements.
        model_id: Identifier of model used for proposal.
        raw_response: Raw response string from model.
        prompt_tokens: Number of prompt tokens reported.
        completion_tokens: Number of completion tokens reported.
        total_tokens: Total tokens reported.
        telemetry_digest: Cryptographic digest of telemetry record if captured.
        is_authoritative: Always False; model proposals are strictly advisory.
    """

    task_digest: str
    requirements: tuple[ProposedRequirement, ...]
    model_id: str
    raw_response: str
    prompt_tokens: int = 0
    completion_tokens: int = 0
    total_tokens: int = 0
    telemetry_digest: str | None = None
    is_authoritative: bool = False

    def __post_init__(self) -> None:
        if not isinstance(self.task_digest, str) or len(self.task_digest) != 64:
            raise ValueError("task_digest must be a 64-character hexadecimal SHA-256 string")
        if not isinstance(self.model_id, str) or not self.model_id.strip():
            raise ValueError("model_id must be a non-empty string")
        if not isinstance(self.raw_response, str):
            raise TypeError("raw_response must be a string")

        if not isinstance(self.requirements, tuple):
            if isinstance(self.requirements, Sequence):
                object.__setattr__(self, "requirements", tuple(self.requirements))
            else:
                raise TypeError("requirements must be a sequence of ProposedRequirement")

        for idx, req in enumerate(self.requirements):
            if not isinstance(req, ProposedRequirement):
                raise TypeError(
                    f"Requirement at index {idx} must be ProposedRequirement, "
                    f"got {type(req).__name__}"
                )

        # Enforce that is_authoritative is never True
        if self.is_authoritative is not False:
            raise ValueError("is_authoritative must be False for model proposals")

    def safe_summary(self) -> str:
        """Deterministic secret-safe summary for logging."""
        count = len(self.requirements)
        return (
            f"RequirementProposalResult(task_digest={self.task_digest[:16]}..., "
            f"model={self.model_id!r}, requirements_count={count}, "
            f"tokens={self.total_tokens})"
        )

    def to_dict(self) -> dict[str, Any]:
        """Deterministic dictionary serialization."""
        return {
            "task_digest": self.task_digest,
            "requirements": [r.to_dict() for r in self.requirements],
            "model_id": self.model_id,
            "raw_response": self.raw_response,
            "prompt_tokens": self.prompt_tokens,
            "completion_tokens": self.completion_tokens,
            "total_tokens": self.total_tokens,
            "telemetry_digest": self.telemetry_digest,
            "is_authoritative": False,
        }

    @classmethod
    def from_dict(cls, data: Mapping[str, Any]) -> RequirementProposalResult:
        """Construct from dictionary with strict validation."""
        required = {"task_digest", "requirements", "model_id", "raw_response"}
        missing = required - set(data.keys())
        if missing:
            raise ValueError(
                f"Missing required fields for RequirementProposalResult: {sorted(missing)}"
            )

        reqs_raw = data["requirements"]
        if not isinstance(reqs_raw, Sequence):
            raise TypeError(f"requirements must be a sequence, got {type(reqs_raw).__name__}")

        reqs = tuple(
            ProposedRequirement.from_dict(r) if isinstance(r, Mapping) else r for r in reqs_raw
        )

        return cls(
            task_digest=data["task_digest"],
            requirements=reqs,
            model_id=data["model_id"],
            raw_response=data["raw_response"],
            prompt_tokens=int(data.get("prompt_tokens", 0)),
            completion_tokens=int(data.get("completion_tokens", 0)),
            total_tokens=int(data.get("total_tokens", 0)),
            telemetry_digest=data.get("telemetry_digest"),
            is_authoritative=False,
        )


def _strip_markdown_code_fence(text: str) -> str:
    """Safely extract JSON object from markdown code fences or embedded response."""
    stripped = text.strip()
    # 1. Match code fence anywhere in text
    fence_match = re.search(
        r"```(?:json)?\s*\n?(\{.*?\})\s*\n?```", stripped, re.DOTALL | re.IGNORECASE
    )
    if fence_match:
        return fence_match.group(1).strip()

    # 2. Match outermost JSON object { ... }
    brace_match = re.search(r"(\{.*\})", stripped, re.DOTALL)
    if brace_match:
        return brace_match.group(1).strip()

    return stripped


def _repair_unquoted_json_strings(json_str: str) -> str:
    """Repair common model output flaw where string values after colon are not wrapped in quotes."""

    def repl(m: re.Match[str]) -> str:
        key_prefix = m.group(1)
        val = m.group(2).strip()
        if val in ("true", "false", "null") or re.match(r"^-?\d+(?:\.\d+)?$", val):
            return f"{key_prefix}{val}"
        safe_val = val.replace('"', '\\"')
        return f'{key_prefix}"{safe_val}"'

    pattern = re.compile(r'("(?:\w+)"\s*:\s*)(?!["\[{])([^,\n\}\]]+)')
    return pattern.sub(repl, json_str)


def parse_and_validate_requirements(
    raw_response: str,
    task: NormalizedTask,
    model_id: str,
    *,
    prompt_tokens: int = 0,
    completion_tokens: int = 0,
    total_tokens: int = 0,
    telemetry_digest: str | None = None,
) -> RequirementProposalResult:
    """Deterministically parse and validate requirement proposals from model output.

    Validation rules:
    1. Response must not be empty.
    2. Response must be valid JSON object with "requirements" list.
    3. At least one requirement must be proposed.
    4. Each requirement must have non-empty "statement" and "citation".
    5. Each "citation" MUST exist as a verbatim substring in normalized task text.
    6. Citation spans [start:end] are deterministically bound to task text.
    7. Duplicate requirement statements are deduplicated deterministically (first wins).

    Raises:
        MalformedModelOutputError: If JSON is invalid or schema is violated.
        UnsupportedCitationError: If any citation cannot be found in task text.
    """
    if not isinstance(raw_response, str) or not raw_response.strip():
        raise MalformedModelOutputError("Model returned empty or whitespace-only response")

    cleaned = _strip_markdown_code_fence(raw_response)

    try:
        data = json.loads(cleaned)
    except json.JSONDecodeError:
        repaired = _repair_unquoted_json_strings(cleaned)
        try:
            data = json.loads(repaired)
        except json.JSONDecodeError as exc:
            sanitized_snippet = redact_log_text(cleaned[:200])
            raise MalformedModelOutputError(
                f"Model output is not valid JSON: {exc}. Cleaned content: {sanitized_snippet!r}"
            ) from exc

    if not isinstance(data, dict):
        raise MalformedModelOutputError(
            f"Expected JSON object at top level, got {type(data).__name__}"
        )

    if "requirements" not in data:
        raise MalformedModelOutputError("JSON object missing required 'requirements' field")

    req_list = data["requirements"]
    if not isinstance(req_list, list):
        raise MalformedModelOutputError(
            f"'requirements' field must be a list, got {type(req_list).__name__}"
        )

    if len(req_list) == 0:
        raise MalformedModelOutputError("Model returned 0 requirements")

    normalized_task_text = task.normalized_text
    validated_reqs: list[ProposedRequirement] = []
    seen_statement_keys: set[str] = set()

    for idx, item in enumerate(req_list):
        if not isinstance(item, dict):
            raise MalformedModelOutputError(
                f"Requirement item at index {idx} must be a dict, got {type(item).__name__}"
            )

        statement = item.get("statement")
        if not isinstance(statement, str) or not statement.strip():
            raise MalformedModelOutputError(
                f"Requirement at index {idx} has missing or empty 'statement'"
            )
        statement = statement.strip()

        citation = item.get("citation")
        if not isinstance(citation, str) or not citation.strip():
            raise MalformedModelOutputError(
                f"Requirement at index {idx} has missing or empty 'citation'"
            )
        citation = citation.strip()

        rationale = item.get("rationale", "")
        if not isinstance(rationale, str):
            rationale = str(rationale)

        # Enforce citation binding to normalized task text
        citation_start = normalized_task_text.find(citation)
        if citation_start == -1:
            raise UnsupportedCitationError(
                f"Proposed requirement {idx} citation {citation!r} is not present in "
                f"normalized task text"
            )
        citation_end = citation_start + len(citation)

        # Deduplicate requirements deterministically based on normalized statement key
        stmt_key = re.sub(r"\s+", " ", statement.lower())
        if stmt_key in seen_statement_keys:
            # Deterministically skip duplicate requirement
            continue
        seen_statement_keys.add(stmt_key)

        validated_reqs.append(
            ProposedRequirement(
                statement=statement,
                citation=citation,
                citation_start=citation_start,
                citation_end=citation_end,
                rationale=rationale,
            )
        )

    if not validated_reqs:
        raise MalformedModelOutputError("All proposed requirements were duplicates")

    return RequirementProposalResult(
        task_digest=task.task_digest,
        requirements=tuple(validated_reqs),
        model_id=model_id,
        raw_response=raw_response,
        prompt_tokens=prompt_tokens,
        completion_tokens=completion_tokens,
        total_tokens=total_tokens,
        telemetry_digest=telemetry_digest,
        is_authoritative=False,
    )


class NemotronRequirementProposer:
    """Bounded, fail-closed requirement extraction client using Nebius/Nemotron."""

    def __init__(
        self,
        model_client: Any,
        *,
        model_id: str = DEFAULT_REQUIREMENTS_MODEL,
        max_tokens: int = DEFAULT_PROPOSAL_MAX_TOKENS,
    ) -> None:
        self.model_client = model_client
        self.model_id = model_id
        self.max_tokens = max_tokens

        # Validate model identity
        if hasattr(model_client, "config") and hasattr(model_client.config, "model"):
            client_model = model_client.config.model
            if client_model != self.model_id:
                raise InvalidModelConfigurationError(
                    f"Configured model client model '{client_model}' does not match "
                    f"proposer model '{self.model_id}'"
                )

    def propose_requirements(self, task: NormalizedTask) -> RequirementProposalResult:
        """Extract atomic acceptance requirements for a normalized task via Nemotron."""
        messages = [
            {"role": "system", "content": PROPOSAL_SYSTEM_PROMPT},
            {
                "role": "user",
                "content": f"Engineering Task:\n{task.normalized_text}",
            },
        ]

        result = self.model_client.complete(messages)

        prompt_tokens = getattr(result.usage, "prompt_tokens", 0)
        completion_tokens = getattr(result.usage, "completion_tokens", 0)
        total_tokens = getattr(result.usage, "total_tokens", 0)

        # Telemetry digest if attached by adapter/client
        telemetry_digest = getattr(result, "telemetry_digest", None)

        raw_text = getattr(result, "content", getattr(result, "raw_text", str(result)))
        return parse_and_validate_requirements(
            raw_response=raw_text,
            task=task,
            model_id=result.returned_model,
            prompt_tokens=prompt_tokens,
            completion_tokens=completion_tokens,
            total_tokens=total_tokens,
            telemetry_digest=telemetry_digest,
        )
