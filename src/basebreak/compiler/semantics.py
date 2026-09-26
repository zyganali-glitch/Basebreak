"""Change semantics classification and uncertainty handling.

P-06.03: Classify change semantics of engineering tasks into canonical Basebreak
change classes with deterministic validation, citation checking, and explicit
uncertainty handling.

Architectural invariants:
- Canonical classes are strictly the six in ChangeClass (BUG_FIX, FEATURE,
  SECURITY_FIX, REFACTOR, PERFORMANCE, DEP_API_CHANGE).
- Unsupported or hallucinated change classes fail closed.
- Uncertainty is explicitly modeled: CONFIDENT, AMBIGUOUS, UNKNOWN.
- Model role is PROPOSAL ONLY; deterministic validation governs.
- Every evidence citation must be a verbatim substring in normalized task text.
- Zero secret leakage in logs, diagnostics, or error strings.
"""

from __future__ import annotations

import json
import re
from collections.abc import Mapping, Sequence
from dataclasses import dataclass
from enum import Enum
from typing import Any

from basebreak.compiler.ingestion import NormalizedTask
from basebreak.domain.semantics import (
    ChangeClass,
    ClassVerificationRequirement,
    get_verification_requirements,
)
from basebreak.security.secret_policy import redact_log_text

DEFAULT_SEMANTICS_MODEL: str = "nvidia/Nemotron-3_5-Lightning"
DEFAULT_SEMANTICS_MAX_TOKENS: int = 2048


class CertaintyLevel(str, Enum):
    """Certainty level of a semantics classification."""

    CONFIDENT = "CONFIDENT"
    AMBIGUOUS = "AMBIGUOUS"
    UNKNOWN = "UNKNOWN"


class SemanticsClassificationError(Exception):
    """Base exception for semantics classification errors."""


class InvalidChangeClassError(SemanticsClassificationError):
    """Raised when an invalid or unsupported change class is encountered."""


class UnsupportedCitationError(SemanticsClassificationError):
    """Raised when cited evidence is not present verbatim in task text."""


class MalformedClassificationOutputError(SemanticsClassificationError):
    """Raised when model output cannot be parsed into valid classification schema."""


class AmbiguousSemanticsError(SemanticsClassificationError):
    """Raised when unambiguous semantics are required but classification is ambiguous."""


SEMANTICS_SYSTEM_PROMPT = """You are the Basebreak Semantics Classification Engine.
Your role is to classify the engineering change described in the task into exactly ONE of the six
canonical Basebreak change classes, or identify uncertainty/ambiguity.

CANONICAL CHANGE CLASSES:
1. BUG_FIX: Repairing a defect, bug, crash, or regression.
   Verification law: BASE=FAIL, CANDIDATE=PASS.
2. FEATURE: Adding new capability or functionality.
   Verification law: BASE=ABSENT, CANDIDATE=PRESENT.
3. SECURITY_FIX: Remediating a security vulnerability, CVE, or exploit.
   Verification law: BASE=EXPLOITABLE, CANDIDATE=BLOCKED.
4. REFACTOR: Code restructuring without changing external behavior.
   Verification law: BASE=EQUIVALENT, CANDIDATE=EQUIVALENT.
5. PERFORMANCE: Improving latency, throughput, memory, or CPU efficiency.
   Verification law: BASE=PARITY, CANDIDATE=PARITY with measured delta.
6. DEP_API_CHANGE: Updating dependencies or adapting to external API changes.
   Verification law: BASE=BASELINE, CANDIDATE=NEW_CONTRACT_SATISFIED.

CERTAINTY RULES:
- If the task clearly targets one class: certainty="CONFIDENT", change_class="<CLASS>".
- If the task has conflicting goals (e.g. bug fix AND refactor AND new feature):
  certainty="AMBIGUOUS", list alternative_classes.
- If the task is unclear, contradictory, or lacks details: certainty="UNKNOWN", change_class=null.

RULES:
1. change_class MUST be null or one of:
   "BUG_FIX", "FEATURE", "SECURITY_FIX", "REFACTOR", "PERFORMANCE", "DEP_API_CHANGE".
2. confidence MUST be a float between 0.0 and 1.0.
3. Every citation in evidence_citations MUST be an EXACT, verbatim quotation from the task text.
4. Output MUST be valid JSON with the exact structure:
{
  "change_class": "BUG_FIX",
  "certainty": "CONFIDENT",
  "confidence": 0.95,
  "alternative_classes": [],
  "rationale": "Clear rationale explaining the classification",
  "evidence_citations": ["Exact verbatim substring from task"]
}
Do not include any commentary or explanation outside the JSON object."""


@dataclass(frozen=True, slots=True)
class ChangeSemanticsClassification:
    """Immutable, validated change semantics classification result."""

    change_class: ChangeClass | None
    certainty: CertaintyLevel
    confidence: float
    alternative_classes: tuple[ChangeClass, ...]
    rationale: str
    evidence_citations: tuple[str, ...]
    verification_requirement: ClassVerificationRequirement | None = None

    def __post_init__(self) -> None:
        if not isinstance(self.certainty, CertaintyLevel):
            tname = type(self.certainty).__name__
            raise TypeError(f"certainty must be CertaintyLevel, got {tname}")

        if not isinstance(self.confidence, (int, float)) or not (
            0.0 <= float(self.confidence) <= 1.0
        ):
            raise ValueError(
                f"confidence must be a float between 0.0 and 1.0, got {self.confidence!r}"
            )

        if self.change_class is not None:
            if not isinstance(self.change_class, ChangeClass):
                tname = type(self.change_class).__name__
                raise TypeError(f"change_class must be ChangeClass or None, got {tname}")

        for alt in self.alternative_classes:
            if not isinstance(alt, ChangeClass):
                tname = type(alt).__name__
                raise TypeError(f"alternative_classes items must be ChangeClass, got {tname}")

        for cit in self.evidence_citations:
            if not isinstance(cit, str) or not cit.strip():
                raise ValueError("evidence_citations must be non-empty strings")

        # Deterministic verification requirement binding
        expected_req = (
            get_verification_requirements(self.change_class) if self.change_class else None
        )
        if self.verification_requirement != expected_req:
            object.__setattr__(self, "verification_requirement", expected_req)

    @property
    def is_confident(self) -> bool:
        """True if classification is unambiguous and confident."""
        return self.certainty == CertaintyLevel.CONFIDENT and self.change_class is not None

    @property
    def is_ambiguous(self) -> bool:
        """True if classification is ambiguous between multiple classes."""
        return self.certainty == CertaintyLevel.AMBIGUOUS

    @property
    def is_unknown(self) -> bool:
        """True if classification cannot be determined."""
        return self.certainty == CertaintyLevel.UNKNOWN or self.change_class is None

    def require_definite_class(self) -> ChangeClass:
        """Return canonical change class, raising AmbiguousSemanticsError if uncertain."""
        if self.change_class is None:
            raise AmbiguousSemanticsError(
                f"Cannot obtain definite change class: certainty is {self.certainty.value}, "
                f"confidence={self.confidence:.2f}: {self.rationale}"
            )
        if self.certainty == CertaintyLevel.AMBIGUOUS:
            alts = ", ".join(c.value for c in self.alternative_classes)
            raise AmbiguousSemanticsError(
                f"Change semantics are ambiguous between {self.change_class.value} and [{alts}]: "
                f"{self.rationale}"
            )
        return self.change_class

    def __repr__(self) -> str:
        safe_rat = redact_log_text(self.rationale)
        return (
            f"ChangeSemanticsClassification(change_class={self.change_class}, "
            f"certainty={self.certainty}, confidence={self.confidence:.2f}, "
            f"alternative_classes={self.alternative_classes}, rationale={safe_rat!r})"
        )


def _strip_markdown_code_fence(text: str) -> str:
    """Extract clean JSON text from potential markdown code fences or conversational output."""
    stripped = text.strip()
    match = re.search(r"```(?:json)?\s*(\{.*?\})\s*```", stripped, re.DOTALL)
    if match:
        return match.group(1).strip()
    match_any = re.search(r"(\{.*\})", stripped, re.DOTALL)
    if match_any:
        return match_any.group(1).strip()
    return stripped


def parse_and_validate_classification(
    raw_output: str,
    normalized_task: NormalizedTask,
) -> ChangeSemanticsClassification:
    """Deterministically parse and validate semantics classification output.

    Enforces:
    - JSON parsing from plain or fenced output.
    - Canonical ChangeClass validation (fail-closed on unknown classes).
    - Confidence bounds [0.0, 1.0].
    - Verbatim existence of all citations in normalized task text (fail-closed on hallucination).
    """
    cleaned = _strip_markdown_code_fence(raw_output)
    try:
        data = json.loads(cleaned)
    except json.JSONDecodeError as exc:
        raise MalformedClassificationOutputError(
            f"Failed to parse classification output as JSON: {exc}"
        ) from exc

    if not isinstance(data, Mapping):
        raise MalformedClassificationOutputError(
            f"Expected JSON object for classification, got {type(data).__name__}"
        )

    # 1. Parse change_class
    raw_class = data.get("change_class")
    change_class: ChangeClass | None = None
    if raw_class is not None and str(raw_class).strip():
        class_str = str(raw_class).strip()
        if class_str.upper() in ("UNKNOWN", "NONE", "NULL"):
            change_class = None
        else:
            try:
                change_class = ChangeClass(class_str)
            except ValueError as exc:
                allowed = [c.value for c in ChangeClass]
                raise InvalidChangeClassError(
                    f"Unsupported change class {raw_class!r}. Must be one of {allowed} or null."
                ) from exc

    # 2. Parse certainty
    raw_certainty = data.get("certainty", CertaintyLevel.CONFIDENT.value)
    certainty_str = (
        str(raw_certainty).strip().upper() if raw_certainty else CertaintyLevel.UNKNOWN.value
    )
    try:
        certainty = CertaintyLevel(certainty_str)
    except ValueError:
        certainty = CertaintyLevel.UNKNOWN

    # 3. Parse confidence
    raw_confidence = data.get("confidence", 0.0)
    try:
        confidence = float(raw_confidence)
    except (ValueError, TypeError) as exc:
        raise MalformedClassificationOutputError(
            f"Invalid confidence value {raw_confidence!r}: must be float"
        ) from exc

    if not (0.0 <= confidence <= 1.0):
        raise MalformedClassificationOutputError(
            f"Confidence out of bounds [0.0, 1.0]: {confidence}"
        )

    # 4. Parse alternative classes
    raw_alts = data.get("alternative_classes", [])
    if not isinstance(raw_alts, Sequence) or isinstance(raw_alts, (str, bytes)):
        raw_alts = []
    alt_classes: list[ChangeClass] = []
    for raw_alt in raw_alts:
        alt_str = str(raw_alt).strip()
        if alt_str:
            try:
                c = ChangeClass(alt_str)
                if c != change_class and c not in alt_classes:
                    alt_classes.append(c)
            except ValueError as exc:
                raise InvalidChangeClassError(
                    f"Unsupported alternative change class {raw_alt!r}."
                ) from exc

    # 5. Parse rationale
    rationale = str(data.get("rationale", "")).strip()

    # 6. Parse and validate evidence citations
    raw_citations = data.get("evidence_citations", [])
    if not isinstance(raw_citations, Sequence) or isinstance(raw_citations, (str, bytes)):
        raw_citations = []

    validated_citations: list[str] = []
    for cit in raw_citations:
        cit_str = str(cit).strip()
        if not cit_str:
            continue
        # Strict citation check: must be verbatim substring in normalized task text
        if cit_str not in normalized_task.normalized_text:
            raise UnsupportedCitationError(
                f"Evidence citation is not present in task text: {cit_str!r}"
            )
        if cit_str not in validated_citations:
            validated_citations.append(cit_str)

    # If change_class is None, certainty must be UNKNOWN
    if change_class is None and certainty == CertaintyLevel.CONFIDENT:
        certainty = CertaintyLevel.UNKNOWN

    # If alternative classes exist, certainty must be AMBIGUOUS
    if alt_classes and certainty == CertaintyLevel.CONFIDENT:
        certainty = CertaintyLevel.AMBIGUOUS

    return ChangeSemanticsClassification(
        change_class=change_class,
        certainty=certainty,
        confidence=confidence,
        alternative_classes=tuple(alt_classes),
        rationale=rationale,
        evidence_citations=tuple(validated_citations),
    )


# Heuristic keyword profiles for deterministic baseline classification
_KEYWORD_PROFILES: dict[ChangeClass, tuple[tuple[str, float], ...]] = {
    ChangeClass.SECURITY_FIX: (
        ("vulnerability", 3.0),
        ("cve-", 4.0),
        ("cve", 3.0),
        ("exploit", 3.0),
        ("xss", 3.0),
        ("csrf", 3.0),
        ("sqli", 3.0),
        ("sql injection", 3.5),
        ("command injection", 3.5),
        ("rce", 3.5),
        ("remote code execution", 4.0),
        ("security advisory", 3.5),
        ("denial of service", 3.0),
        ("buffer overflow", 3.0),
        ("path traversal", 3.5),
        ("untrusted input", 2.5),
        ("sanitize", 2.0),
    ),
    ChangeClass.PERFORMANCE: (
        ("speed up", 3.0),
        ("latency", 3.0),
        ("throughput", 3.0),
        ("memory leak", 3.5),
        ("cpu usage", 3.0),
        ("high cpu", 3.0),
        ("optimize", 2.5),
        ("optimization", 2.5),
        ("benchmark", 2.5),
        ("bottleneck", 3.0),
        ("slow", 2.0),
        ("overhead", 2.0),
    ),
    ChangeClass.DEP_API_CHANGE: (
        ("upgrade dependency", 3.5),
        ("bump dependency", 3.5),
        ("update dependency", 3.0),
        ("breaking api", 3.5),
        ("breaking change", 3.0),
        ("api change", 3.0),
        ("deprecated api", 3.0),
        ("deprecation", 2.5),
        ("upgrade to", 2.5),
        ("migrate to", 2.5),
    ),
    ChangeClass.REFACTOR: (
        ("refactor", 3.5),
        ("restructure", 3.0),
        ("reorganize", 2.5),
        ("clean up", 2.0),
        ("cleanup", 2.0),
        ("no functional change", 3.5),
        ("no behavioral change", 3.5),
        ("simplify", 2.0),
        ("modularize", 2.5),
        ("rename", 2.0),
    ),
    ChangeClass.BUG_FIX: (
        ("fix", 2.0),
        ("bug", 2.5),
        ("crash", 3.0),
        ("error", 2.0),
        ("exception", 2.5),
        ("defect", 2.5),
        ("failure", 2.0),
        ("regression", 3.0),
        ("broken", 2.5),
        ("hang", 2.5),
        ("traceback", 3.0),
        ("infinite loop", 3.0),
    ),
    ChangeClass.FEATURE: (
        ("add support", 3.0),
        ("add feature", 3.5),
        ("new feature", 3.5),
        ("implement", 2.5),
        ("introduce", 2.5),
        ("support for", 2.0),
        ("extend", 2.0),
        ("new capability", 3.0),
        ("allow user to", 2.5),
    ),
}


def classify_semantics_deterministically(
    normalized_task: NormalizedTask,
) -> ChangeSemanticsClassification:
    """Classify task semantics using deterministic keyword and structure heuristics.

    Does not call any external model. Extracts verbatim substrings from the task
    text as evidence citations.
    """
    text_lower = normalized_task.normalized_text.lower()
    scores: dict[ChangeClass, float] = {c: 0.0 for c in ChangeClass}
    citations_by_class: dict[ChangeClass, list[str]] = {c: [] for c in ChangeClass}

    for change_class, profiles in _KEYWORD_PROFILES.items():
        for keyword, weight in profiles:
            idx = text_lower.find(keyword)
            if idx != -1:
                scores[change_class] += weight
                # Extract verbatim excerpt around the keyword matching original casing
                start = max(0, idx - 10)
                end = min(len(normalized_task.normalized_text), idx + len(keyword) + 15)
                # Align to nearest spaces where possible
                excerpt = normalized_task.normalized_text[start:end].strip()
                if (
                    excerpt
                    and excerpt in normalized_task.normalized_text
                    and excerpt not in citations_by_class[change_class]
                ):
                    citations_by_class[change_class].append(excerpt)

    # Find classes with non-zero scores sorted descending
    ranked = sorted(
        [(cls, score) for cls, score in scores.items() if score > 0.0],
        key=lambda item: item[1],
        reverse=True,
    )

    if not ranked:
        return ChangeSemanticsClassification(
            change_class=None,
            certainty=CertaintyLevel.UNKNOWN,
            confidence=0.0,
            alternative_classes=(),
            rationale="No clear change semantics indicators identified in task text.",
            evidence_citations=(),
        )

    top_class, top_score = ranked[0]
    total_score = sum(s for _, s in ranked)
    confidence = min(1.0, round(top_score / max(1.0, total_score), 2))

    # Check for ambiguity: runner-up has score >= 70% of top score
    alternatives: list[ChangeClass] = []
    is_ambiguous = False
    for alt_class, alt_score in ranked[1:]:
        if alt_score >= 0.7 * top_score:
            is_ambiguous = True
            alternatives.append(alt_class)

    certainty = CertaintyLevel.AMBIGUOUS if is_ambiguous else CertaintyLevel.CONFIDENT
    citations = tuple(citations_by_class[top_class][:3])

    rationale = (
        f"Deterministic heuristic classification identified {top_class.value} "
        f"(score={top_score:.1f}, confidence={confidence:.2f})"
    )
    if is_ambiguous:
        alt_str = ", ".join(a.value for a in alternatives)
        rationale += f" with competing signals for [{alt_str}]."

    return ChangeSemanticsClassification(
        change_class=top_class,
        certainty=certainty,
        confidence=confidence,
        alternative_classes=tuple(alternatives),
        rationale=rationale,
        evidence_citations=citations,
    )


class NemotronSemanticsClassifier:
    """Classifies task change semantics using Nemotron with deterministic validation."""

    def __init__(
        self,
        model_client: Any,
        model: str = DEFAULT_SEMANTICS_MODEL,
        max_tokens: int = DEFAULT_SEMANTICS_MAX_TOKENS,
    ) -> None:
        self._client = model_client
        self._model = model
        self._max_tokens = max_tokens

    async def classify(
        self,
        normalized_task: NormalizedTask,
    ) -> ChangeSemanticsClassification:
        """Query Nemotron and return deterministically validated classification."""
        user_prompt = (
            f"Classify the change semantics of the following engineering task:\n\n"
            f"--- TASK TEXT ---\n"
            f"{normalized_task.normalized_text}\n"
            f"--- END TASK TEXT ---\n\n"
            f"Remember: change_class must be one of the six canonical classes or null. "
            f"Every quotation in evidence_citations must be verbatim."
        )

        messages = [
            {"role": "system", "content": SEMANTICS_SYSTEM_PROMPT},
            {"role": "user", "content": user_prompt},
        ]

        result = await self._client.generate(
            model=self._model,
            messages=messages,
            temperature=0.0,
            max_tokens=self._max_tokens,
        )

        raw_output = getattr(result, "content", "")
        return parse_and_validate_classification(raw_output, normalized_task)
