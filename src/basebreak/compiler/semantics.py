"""Change semantics classification and uncertainty reasoning.

P-06.03: Classify task change semantics and uncertainty under the Basebreak
causal verification authority model.

Authority Model:
1. Deterministic classification facts derived from normalized task text govern.
2. Model classification proposals are strictly PROPOSAL ONLY (never final authority).
3. Where deterministic facts do not resolve a unique class:
   represent AMBIGUOUS or UNKNOWN honestly. A model proposal cannot force certainty.
4. Where deterministic facts contradict a model proposal:
   deterministic facts win.
5. All evidence citations must be verbatim substrings in normalized task text.
   Unsupported citations fail closed.
6. Compiler core is strictly provider-neutral (no adapter imports).
"""

from __future__ import annotations

import json
import re
from collections.abc import Mapping
from dataclasses import dataclass
from enum import Enum
from typing import Any

from basebreak.compiler.ingestion import NormalizedTask
from basebreak.compiler.requirements import (
    UnsupportedCitationError,
    _strip_markdown_code_fence,
)
from basebreak.domain.semantics import (
    ChangeClass,
    ClassVerificationRequirement,
    get_verification_requirements,
)
from basebreak.security.secret_policy import redact_log_text

__all__ = [
    "DEFAULT_SEMANTICS_MAX_TOKENS",
    "DEFAULT_SEMANTICS_MODEL",
    "CertaintyLevel",
    "ChangeClass",
    "ChangeSemanticsClassification",
    "ChangeSemanticsError",
    "DeterministicClassificationFact",
    "InvalidModelConfigurationError",
    "MalformedModelSemanticsError",
    "ModelChangeProposal",
    "NemotronSemanticsClassifier",
    "classify_semantics_deterministically",
    "parse_and_validate_semantics_proposal",
    "reconcile_semantics",
]

# System prompt for model semantics proposal
SEMANTICS_SYSTEM_PROMPT = """You are the Basebreak Change Semantics Engine.
Your role is to propose the change semantics classification of the given engineering task.

CANONICAL CHANGE CLASSES:
1. BUG_FIX: Repairing a defect, bug, crash, or regression.
2. FEATURE: Introducing a new capability, endpoint, or feature.
3. SECURITY_FIX: Remediating a security vulnerability or exploit.
4. REFACTOR: Restructuring code without changing external behavior.
5. PERFORMANCE: Improving efficiency, throughput, latency, or resource usage.
6. DEP_API_CHANGE: Updating dependencies or adapting to external API changes.

RULES:
1. You MUST propose one of the six canonical classes, or null if unclassifiable.
2. Every quotation in 'evidence_citations' MUST be an exact, verbatim substring from the task text.
3. If there are competing signals, classify certainty as 'AMBIGUOUS' and list alternative classes.
4. Output MUST be valid JSON with the exact structure:
{
  "change_class": "BUG_FIX",
  "certainty": "CONFIDENT",
  "confidence": 0.95,
  "alternative_classes": [],
  "rationale": "Brief rationale",
  "evidence_citations": ["Exact verbatim substring from task text"]
}
Do not include any commentary or explanation outside the JSON object."""

DEFAULT_SEMANTICS_MODEL: str = "nvidia/Nemotron-3_5-Lightning"
DEFAULT_SEMANTICS_MAX_TOKENS: int = 1024


class CertaintyLevel(str, Enum):
    """Certainty level for change semantics classification."""

    CONFIDENT = "CONFIDENT"
    AMBIGUOUS = "AMBIGUOUS"
    UNKNOWN = "UNKNOWN"


class ChangeSemanticsError(Exception):
    """Base exception for change semantics classification errors."""


class MalformedModelSemanticsError(ChangeSemanticsError):
    """Raised when model output is invalid JSON, violates schema, or contains invalid types."""


class InvalidModelConfigurationError(ChangeSemanticsError):
    """Raised when injected model client configuration is invalid."""


@dataclass(frozen=True, slots=True)
class ModelChangeProposal:
    """Model-suggested classification proposal. Strictly NON-AUTHORITATIVE."""

    proposed_class: ChangeClass | None
    certainty: CertaintyLevel
    confidence: float
    alternative_classes: tuple[ChangeClass, ...]
    rationale: str
    evidence_citations: tuple[str, ...]
    raw_response: str
    model_id: str
    prompt_tokens: int = 0
    completion_tokens: int = 0
    total_tokens: int = 0
    telemetry_digest: str | None = None
    is_authoritative: bool = False  # Invariant: model proposal is NEVER authoritative

    def to_dict(self) -> dict[str, Any]:
        """Deterministic dictionary serialization."""
        return {
            "proposed_class": self.proposed_class.value if self.proposed_class else None,
            "certainty": self.certainty.value,
            "confidence": self.confidence,
            "alternative_classes": [c.value for c in self.alternative_classes],
            "rationale": self.rationale,
            "evidence_citations": list(self.evidence_citations),
            "raw_response": self.raw_response,
            "model_id": self.model_id,
            "prompt_tokens": self.prompt_tokens,
            "completion_tokens": self.completion_tokens,
            "total_tokens": self.total_tokens,
            "telemetry_digest": self.telemetry_digest,
            "is_authoritative": False,
        }

    @classmethod
    def from_dict(cls, data: Mapping[str, Any]) -> ModelChangeProposal:
        """Construct from dictionary with strict schema validation."""
        required = {"proposed_class", "certainty", "confidence", "model_id", "raw_response"}
        missing = required - set(data.keys())
        if missing:
            raise ValueError(f"Missing required fields for ModelChangeProposal: {sorted(missing)}")

        raw_class = data["proposed_class"]
        proposed_class = ChangeClass(raw_class) if raw_class is not None else None
        certainty = CertaintyLevel(data["certainty"])

        alt_raw = data.get("alternative_classes", ())
        alt_classes = tuple(ChangeClass(c) for c in alt_raw)

        citations_raw = data.get("evidence_citations", ())
        citations = tuple(str(c) for c in citations_raw)

        return cls(
            proposed_class=proposed_class,
            certainty=certainty,
            confidence=float(data["confidence"]),
            alternative_classes=alt_classes,
            rationale=str(data.get("rationale", "")),
            evidence_citations=citations,
            raw_response=str(data["raw_response"]),
            model_id=str(data["model_id"]),
            prompt_tokens=int(data.get("prompt_tokens", 0)),
            completion_tokens=int(data.get("completion_tokens", 0)),
            total_tokens=int(data.get("total_tokens", 0)),
            telemetry_digest=data.get("telemetry_digest"),
            is_authoritative=False,
        )


@dataclass(frozen=True, slots=True)
class DeterministicClassificationFact:
    """Authoritative deterministic classification facts derived from task text."""

    inferred_class: ChangeClass | None
    certainty: CertaintyLevel
    confidence: float
    alternative_classes: tuple[ChangeClass, ...]
    rationale: str
    evidence_citations: tuple[str, ...]
    matched_signals: tuple[str, ...]

    def to_dict(self) -> dict[str, Any]:
        """Deterministic dictionary serialization."""
        return {
            "inferred_class": self.inferred_class.value if self.inferred_class else None,
            "certainty": self.certainty.value,
            "confidence": self.confidence,
            "alternative_classes": [c.value for c in self.alternative_classes],
            "rationale": self.rationale,
            "evidence_citations": list(self.evidence_citations),
            "matched_signals": list(self.matched_signals),
        }

    @classmethod
    def from_dict(cls, data: Mapping[str, Any]) -> DeterministicClassificationFact:
        """Construct from dictionary with strict schema validation."""
        required = {"inferred_class", "certainty", "confidence", "rationale"}
        missing = required - set(data.keys())
        if missing:
            raise ValueError(
                f"Missing required fields for DeterministicClassificationFact: {sorted(missing)}"
            )

        raw_class = data["inferred_class"]
        inferred_class = ChangeClass(raw_class) if raw_class is not None else None
        certainty = CertaintyLevel(data["certainty"])

        alt_raw = data.get("alternative_classes", ())
        alt_classes = tuple(ChangeClass(c) for c in alt_raw)

        citations_raw = data.get("evidence_citations", ())
        citations = tuple(str(c) for c in citations_raw)

        signals_raw = data.get("matched_signals", ())
        signals = tuple(str(s) for s in signals_raw)

        return cls(
            inferred_class=inferred_class,
            certainty=certainty,
            confidence=float(data["confidence"]),
            alternative_classes=alt_classes,
            rationale=str(data["rationale"]),
            evidence_citations=citations,
            matched_signals=signals,
        )


@dataclass(frozen=True, slots=True)
class ChangeSemanticsClassification:
    """Canonical reconciled change semantics classification for a task.

    Distinguishes deterministic facts, model proposals, and final resolved uncertainty.
    """

    task_digest: str
    change_class: ChangeClass | None
    certainty: CertaintyLevel
    confidence: float
    alternative_classes: tuple[ChangeClass, ...]
    rationale: str
    evidence_citations: tuple[str, ...]
    deterministic_facts: DeterministicClassificationFact
    model_proposal: ModelChangeProposal | None = None
    verification_requirement: ClassVerificationRequirement | None = None

    def __post_init__(self) -> None:
        if not isinstance(self.task_digest, str) or not self.task_digest:
            raise ValueError("task_digest must be a non-empty string")
        if self.change_class is not None and not isinstance(self.change_class, ChangeClass):
            raise TypeError(
                f"change_class must be ChangeClass or None, got {type(self.change_class).__name__}"
            )
        if not isinstance(self.certainty, CertaintyLevel):
            raise TypeError(
                f"certainty must be CertaintyLevel, got {type(self.certainty).__name__}"
            )
        if self.change_class is None and self.certainty == CertaintyLevel.CONFIDENT:
            raise ValueError("change_class cannot be None when certainty is CONFIDENT")

        # Automatically bind verification requirement if change_class is resolved
        if self.change_class is not None and self.verification_requirement is None:
            object.__setattr__(
                self,
                "verification_requirement",
                get_verification_requirements(self.change_class),
            )

    @property
    def is_confident(self) -> bool:
        """Returns True if classification is confident and change_class is resolved."""
        return self.certainty == CertaintyLevel.CONFIDENT and self.change_class is not None

    def to_dict(self) -> dict[str, Any]:
        """Deterministic dictionary serialization."""
        return {
            "task_digest": self.task_digest,
            "change_class": self.change_class.value if self.change_class else None,
            "certainty": self.certainty.value,
            "confidence": self.confidence,
            "alternative_classes": [c.value for c in self.alternative_classes],
            "rationale": self.rationale,
            "evidence_citations": list(self.evidence_citations),
            "deterministic_facts": self.deterministic_facts.to_dict(),
            "model_proposal": self.model_proposal.to_dict() if self.model_proposal else None,
            "verification_requirement": (
                {
                    "change_class": self.verification_requirement.change_class.value,
                    "base_expectation": self.verification_requirement.base_expectation,
                    "candidate_expectation": (self.verification_requirement.candidate_expectation),
                    "requires_equivalence": (self.verification_requirement.requires_equivalence),
                    "requires_measured_delta": (
                        self.verification_requirement.requires_measured_delta
                    ),
                    "requires_regression_safety": (
                        self.verification_requirement.requires_regression_safety
                    ),
                    "description": self.verification_requirement.description,
                }
                if self.verification_requirement
                else None
            ),
        }

    @classmethod
    def from_dict(cls, data: Mapping[str, Any]) -> ChangeSemanticsClassification:
        """Construct from dictionary with strict schema validation."""
        required = {
            "task_digest",
            "change_class",
            "certainty",
            "confidence",
            "rationale",
            "deterministic_facts",
        }
        missing = required - set(data.keys())
        if missing:
            raise ValueError(
                f"Missing required fields for ChangeSemanticsClassification: {sorted(missing)}"
            )

        raw_class = data["change_class"]
        change_class = ChangeClass(raw_class) if raw_class is not None else None
        certainty = CertaintyLevel(data["certainty"])

        alt_raw = data.get("alternative_classes", ())
        alt_classes = tuple(ChangeClass(c) for c in alt_raw)

        citations_raw = data.get("evidence_citations", ())
        citations = tuple(str(c) for c in citations_raw)

        det_facts_raw = data["deterministic_facts"]
        if not isinstance(det_facts_raw, Mapping):
            raise TypeError("deterministic_facts must be a mapping")
        det_facts = DeterministicClassificationFact.from_dict(det_facts_raw)

        model_prop_raw = data.get("model_proposal")
        model_proposal = (
            ModelChangeProposal.from_dict(model_prop_raw)
            if isinstance(model_prop_raw, Mapping)
            else None
        )

        return cls(
            task_digest=str(data["task_digest"]),
            change_class=change_class,
            certainty=certainty,
            confidence=float(data["confidence"]),
            alternative_classes=alt_classes,
            rationale=str(data["rationale"]),
            evidence_citations=citations,
            deterministic_facts=det_facts,
            model_proposal=model_proposal,
        )


# Keyword and phrase signals for deterministic analysis
_KEYWORD_PATTERNS: dict[ChangeClass, tuple[tuple[str, float], ...]] = {
    ChangeClass.SECURITY_FIX: (
        (r"\b(?:cve-\d+-\d+|cve\b)", 4.0),
        (r"\b(?:remote code execution|command injection|sql injection|sqli)\b", 3.5),
        (r"\b(?:vulnerability|vulnerabilities|exploit|exploits|xss|csrf|rce)\b", 3.0),
        (r"\b(?:security advisory|path traversal|buffer overflow)\b", 3.0),
        (r"\b(?:untrusted input|sanitize)\b", 2.0),
    ),
    ChangeClass.PERFORMANCE: (
        (r"\b(?:memory leak|high cpu|speed up|latency|throughput)\b", 3.5),
        (r"\b(?:optimize|optimization|benchmark|bottleneck)\b", 3.0),
        (r"\b(?:cpu usage|performance overhead)\b", 2.5),
    ),
    ChangeClass.DEP_API_CHANGE: (
        (r"\b(?:upgrade dependency|bump dependency|update dependency)\b", 3.5),
        (r"\b(?:breaking api|breaking change|deprecated api|deprecation)\b", 3.5),
        (r"\b(?:upgrade to|migrate to|api change)\b", 2.5),
    ),
    ChangeClass.REFACTOR: (
        (r"\b(?:no functional change|no behavioral change)\b", 3.5),
        (r"\b(?:refactor|restructure|reorganize)\b", 3.0),
        (r"\b(?:clean up|cleanup|modularize|simplify)\b", 2.5),
    ),
    ChangeClass.BUG_FIX: (
        (r"\b(?:infinite loop|null pointer|traceback|panic)\b", 3.0),
        (r"\b(?:fix|fixes|fixed|crash|crashes|defect|defects|regression|broken|hang|hangs)\b", 2.5),
        (r"\b(?:bug|bugs|error|exception|failure)\b", 2.0),
    ),
    ChangeClass.FEATURE: (
        (r"\b(?:add feature|new feature|new capability)\b", 3.5),
        (r"\b(?:add support|implement|introduce|support for|allow user to)\b", 2.5),
        (r"\b(?:extend capability|extend)\b", 2.0),
    ),
}


def _extract_citation_excerpt(text: str, start_idx: int, end_idx: int) -> str:
    """Extract a clean, whitespace-aligned verbatim substring from text containing span."""
    # Expand slightly around match up to whitespace boundaries
    s = max(0, start_idx - 15)
    e = min(len(text), end_idx + 15)

    # Align to word boundaries without exceeding text bounds
    while s > 0 and not text[s - 1].isspace() and (start_idx - s) < 30:
        s -= 1
    while e < len(text) and not text[e].isspace() and (e - end_idx) < 30:
        e += 1

    candidate = text[s:e].strip()
    if candidate and candidate in text:
        return candidate
    # Fallback to exact match span which is guaranteed verbatim
    return text[start_idx:end_idx]


def _compute_deterministic_facts(
    normalized_task: NormalizedTask,
) -> DeterministicClassificationFact:
    """Compute authoritative deterministic classification facts from task text."""
    text = normalized_task.normalized_text
    scores: dict[ChangeClass, float] = {c: 0.0 for c in ChangeClass}
    citations_by_class: dict[ChangeClass, list[str]] = {c: [] for c in ChangeClass}
    signals_by_class: dict[ChangeClass, list[str]] = {c: [] for c in ChangeClass}

    for change_class, patterns in _KEYWORD_PATTERNS.items():
        for regex_pattern, weight in patterns:
            for match in re.finditer(regex_pattern, text, re.IGNORECASE):
                scores[change_class] += weight
                signal = match.group(0)
                if signal not in signals_by_class[change_class]:
                    signals_by_class[change_class].append(signal)

                excerpt = _extract_citation_excerpt(text, match.start(), match.end())
                if excerpt and excerpt not in citations_by_class[change_class]:
                    citations_by_class[change_class].append(excerpt)

    # Rank classes with non-zero score descending
    ranked = sorted(
        [(cls, score) for cls, score in scores.items() if score > 0.0],
        key=lambda item: item[1],
        reverse=True,
    )

    if not ranked:
        return DeterministicClassificationFact(
            inferred_class=None,
            certainty=CertaintyLevel.UNKNOWN,
            confidence=0.0,
            alternative_classes=(),
            rationale="No clear technical change semantics signals identified in task text.",
            evidence_citations=(),
            matched_signals=(),
        )

    top_class, top_score = ranked[0]
    total_score = sum(s for _, s in ranked)
    confidence = min(1.0, round(top_score / max(1.0, total_score), 2))

    # Check for ambiguity: runner-up has score >= 60% of top score
    alternatives: list[ChangeClass] = []
    is_ambiguous = False
    for alt_class, alt_score in ranked[1:]:
        if alt_score >= 0.6 * top_score:
            is_ambiguous = True
            alternatives.append(alt_class)

    certainty = CertaintyLevel.AMBIGUOUS if is_ambiguous else CertaintyLevel.CONFIDENT
    citations = tuple(citations_by_class[top_class][:3])
    signals = tuple(signals_by_class[top_class])

    rationale = (
        f"Deterministic signal analysis identified {top_class.value} "
        f"(score={top_score:.1f}, confidence={confidence:.2f})"
    )
    if is_ambiguous:
        alt_str = ", ".join(a.value for a in alternatives)
        rationale += f" with competing signals for [{alt_str}]."

    return DeterministicClassificationFact(
        inferred_class=top_class,
        certainty=certainty,
        confidence=confidence,
        alternative_classes=tuple(alternatives),
        rationale=rationale,
        evidence_citations=citations,
        matched_signals=signals,
    )


def classify_semantics_deterministically(
    normalized_task: NormalizedTask,
) -> ChangeSemanticsClassification:
    """Classify task semantics using deterministic signal analysis alone.

    Does not call any external model. Guarantees 100% deterministic facts.
    """
    det_facts = _compute_deterministic_facts(normalized_task)
    return reconcile_semantics(
        task=normalized_task,
        deterministic_facts=det_facts,
        model_proposal=None,
    )


def parse_and_validate_semantics_proposal(
    raw_response: str,
    task: NormalizedTask,
    model_id: str,
    *,
    prompt_tokens: int = 0,
    completion_tokens: int = 0,
    total_tokens: int = 0,
    telemetry_digest: str | None = None,
) -> ModelChangeProposal:
    """Deterministically parse and validate a model semantics proposal.

    Fails closed on malformed JSON, schema violations, invalid types, or invalid citations.
    Zero secret leakage in exceptions.
    """
    if not isinstance(raw_response, str) or not raw_response.strip():
        raise MalformedModelSemanticsError("Model returned empty or whitespace-only response")

    cleaned = _strip_markdown_code_fence(raw_response)

    try:
        data = json.loads(cleaned)
    except json.JSONDecodeError as exc:
        sanitized_snippet = redact_log_text(cleaned[:200])
        safe_exc_msg = redact_log_text(str(exc))
        raise MalformedModelSemanticsError(
            f"Model output is not valid JSON: {safe_exc_msg}. "
            f"Cleaned content: {sanitized_snippet!r}"
        ) from None

    if not isinstance(data, dict):
        raise MalformedModelSemanticsError(
            f"Expected JSON object at top level, got {type(data).__name__}"
        )

    # Validate change_class
    if "change_class" not in data:
        raise MalformedModelSemanticsError("JSON missing required 'change_class' field")

    raw_class = data["change_class"]
    proposed_class: ChangeClass | None = None
    if raw_class is not None:
        if not isinstance(raw_class, str):
            raise MalformedModelSemanticsError(
                f"'change_class' must be str or null, got {type(raw_class).__name__}"
            )
        try:
            proposed_class = ChangeClass(raw_class)
        except ValueError:
            valid_classes = [c.value for c in ChangeClass]
            raise MalformedModelSemanticsError(
                f"Unsupported change class '{redact_log_text(raw_class)}'. "
                f"Must be one of {valid_classes} or null"
            ) from None

    # Validate certainty
    certainty = CertaintyLevel.UNKNOWN
    if "certainty" in data and data["certainty"] is not None:
        raw_cert = data["certainty"]
        if not isinstance(raw_cert, str):
            raise MalformedModelSemanticsError(
                f"'certainty' must be str, got {type(raw_cert).__name__}"
            )
        try:
            certainty = CertaintyLevel(raw_cert)
        except ValueError:
            valid_certainties = [c.value for c in CertaintyLevel]
            raise MalformedModelSemanticsError(
                f"Unsupported certainty '{raw_cert}'. Must be one of {valid_certainties}"
            ) from None
    elif proposed_class is not None:
        certainty = CertaintyLevel.CONFIDENT

    # Validate confidence
    confidence = 0.0
    if "confidence" in data and data["confidence"] is not None:
        raw_conf = data["confidence"]
        if isinstance(raw_conf, bool) or not isinstance(raw_conf, (int, float)):
            raise MalformedModelSemanticsError(
                f"'confidence' must be float or int, got {type(raw_conf).__name__}"
            )
        confidence = float(raw_conf)
        if not (0.0 <= confidence <= 1.0):
            raise MalformedModelSemanticsError(f"Confidence out of bounds: {confidence}")

    # Validate alternative_classes
    alt_classes: list[ChangeClass] = []
    if "alternative_classes" in data and data["alternative_classes"] is not None:
        raw_alts = data["alternative_classes"]
        if not isinstance(raw_alts, list):
            raise MalformedModelSemanticsError(
                f"'alternative_classes' must be list, got {type(raw_alts).__name__}"
            )
        for alt_item in raw_alts:
            if not isinstance(alt_item, str):
                raise MalformedModelSemanticsError(
                    f"alternative_classes items must be str, got {type(alt_item).__name__}"
                )
            try:
                alt_class = ChangeClass(alt_item)
                if alt_class not in alt_classes and alt_class != proposed_class:
                    alt_classes.append(alt_class)
            except ValueError:
                raise MalformedModelSemanticsError(
                    f"Unsupported alternative change class '{alt_item}'"
                ) from None

    # Validate rationale
    rationale = ""
    if "rationale" in data and data["rationale"] is not None:
        raw_rat = data["rationale"]
        if not isinstance(raw_rat, str):
            raise MalformedModelSemanticsError(
                f"'rationale' must be str, got {type(raw_rat).__name__}"
            )
        rationale = raw_rat.strip()

    # Validate evidence_citations
    citations: list[str] = []
    if "evidence_citations" in data and data["evidence_citations"] is not None:
        raw_cits = data["evidence_citations"]
        if not isinstance(raw_cits, list):
            raise MalformedModelSemanticsError(
                f"'evidence_citations' must be list, got {type(raw_cits).__name__}"
            )
        for cit_item in raw_cits:
            if not isinstance(cit_item, str):
                raise MalformedModelSemanticsError(
                    f"evidence_citations items must be str, got {type(cit_item).__name__}"
                )
            cit_str = cit_item.strip()
            if not cit_str:
                continue
            # Citation must be verbatim substring in normalized task text
            if cit_str not in task.normalized_text:
                safe_cit = redact_log_text(cit_str)
                raise UnsupportedCitationError(
                    f"Evidence citation is not present in task text: {safe_cit!r}"
                )
            if cit_str not in citations:
                citations.append(cit_str)

    # Invariants for proposal
    if proposed_class is None and certainty == CertaintyLevel.CONFIDENT:
        certainty = CertaintyLevel.UNKNOWN

    if alt_classes and certainty == CertaintyLevel.CONFIDENT:
        certainty = CertaintyLevel.AMBIGUOUS

    return ModelChangeProposal(
        proposed_class=proposed_class,
        certainty=certainty,
        confidence=confidence,
        alternative_classes=tuple(alt_classes),
        rationale=rationale,
        evidence_citations=tuple(citations),
        raw_response=raw_response,
        model_id=model_id,
        prompt_tokens=prompt_tokens,
        completion_tokens=completion_tokens,
        total_tokens=total_tokens,
        telemetry_digest=telemetry_digest,
        is_authoritative=False,
    )


def reconcile_semantics(
    task: NormalizedTask,
    deterministic_facts: DeterministicClassificationFact,
    model_proposal: ModelChangeProposal | None = None,
) -> ChangeSemanticsClassification:
    """Reconcile deterministic classification facts and optional model proposal.

    Authority Hierarchy:
    1. Deterministic facts have final authority over canonical change class.
    2. Model proposal is strictly advisory metadata.
    3. Confident deterministic facts override conflicting model proposals.
    4. Ambiguous deterministic facts cannot be converted into CONFIDENT by model.
    5. Unknown deterministic facts cannot be converted into CONFIDENT by model.
    """
    task_digest = task.task_digest

    if deterministic_facts.certainty == CertaintyLevel.CONFIDENT:
        # Deterministic analysis is confident in inferred_class
        change_class = deterministic_facts.inferred_class
        certainty = CertaintyLevel.CONFIDENT
        confidence = deterministic_facts.confidence
        alt_classes = deterministic_facts.alternative_classes
        citations = list(deterministic_facts.evidence_citations)

        if model_proposal is not None:
            # Check for conflict or agreement
            if model_proposal.proposed_class == change_class:
                confidence = max(confidence, model_proposal.confidence)
                for cit in model_proposal.evidence_citations:
                    if cit not in citations:
                        citations.append(cit)
                rationale = (
                    f"{deterministic_facts.rationale} "
                    f"Confirmed by model proposal ({model_proposal.model_id})."
                )
            else:
                # Deterministic authority overrides model conflict
                rationale = (
                    f"{deterministic_facts.rationale} "
                    f"Model proposed conflicting class '{model_proposal.proposed_class}', "
                    f"which was overridden by deterministic fact authority."
                )
        else:
            rationale = deterministic_facts.rationale

        return ChangeSemanticsClassification(
            task_digest=task_digest,
            change_class=change_class,
            certainty=certainty,
            confidence=confidence,
            alternative_classes=alt_classes,
            rationale=rationale,
            evidence_citations=tuple(citations),
            deterministic_facts=deterministic_facts,
            model_proposal=model_proposal,
        )

    if deterministic_facts.certainty == CertaintyLevel.AMBIGUOUS:
        # Deterministic analysis found competing signals
        certainty = CertaintyLevel.AMBIGUOUS
        confidence = deterministic_facts.confidence
        citations = list(deterministic_facts.evidence_citations)
        ambig_alt_classes = list(deterministic_facts.alternative_classes)

        if model_proposal is not None:
            for cit in model_proposal.evidence_citations:
                if cit not in citations:
                    citations.append(cit)
            for ac in model_proposal.alternative_classes:
                if ac not in ambig_alt_classes and ac != deterministic_facts.inferred_class:
                    ambig_alt_classes.append(ac)
            rationale = (
                f"{deterministic_facts.rationale} "
                f"Model proposal suggests '{model_proposal.proposed_class}', but task signals "
                f"remain ambiguous. Certainty preserved as AMBIGUOUS."
            )
        else:
            rationale = deterministic_facts.rationale

        return ChangeSemanticsClassification(
            task_digest=task_digest,
            change_class=deterministic_facts.inferred_class,
            certainty=certainty,
            confidence=confidence,
            alternative_classes=tuple(ambig_alt_classes),
            rationale=rationale,
            evidence_citations=tuple(citations),
            deterministic_facts=deterministic_facts,
            model_proposal=model_proposal,
        )

    # UNKNOWN deterministic facts: insufficient meaningful class evidence
    citations = list(deterministic_facts.evidence_citations)
    if model_proposal is not None:
        rationale = (
            f"Insufficient meaningful evidence in task text to establish change class. "
            f"Model proposed '{model_proposal.proposed_class}', but cannot manufacture "
            f"authority without underlying task facts. Preserved as UNKNOWN."
        )
    else:
        rationale = deterministic_facts.rationale

    return ChangeSemanticsClassification(
        task_digest=task_digest,
        change_class=None,
        certainty=CertaintyLevel.UNKNOWN,
        confidence=0.0,
        alternative_classes=(),
        rationale=rationale,
        evidence_citations=tuple(citations),
        deterministic_facts=deterministic_facts,
        model_proposal=model_proposal,
    )


class NemotronSemanticsClassifier:
    """Bounded, fail-closed change semantics classifier using Nebius/Nemotron."""

    def __init__(
        self,
        model_client: Any,
        *,
        model_id: str = DEFAULT_SEMANTICS_MODEL,
        max_tokens: int = DEFAULT_SEMANTICS_MAX_TOKENS,
    ) -> None:
        self.model_client = model_client
        self.model_id = model_id
        self.max_tokens = max_tokens

        # Validate model identity if client has config
        if hasattr(model_client, "config") and hasattr(model_client.config, "model"):
            client_model = model_client.config.model
            if client_model != self.model_id:
                raise InvalidModelConfigurationError(
                    f"Configured model client model '{client_model}' does not match "
                    f"classifier model '{self.model_id}'"
                )

    def classify(self, task: NormalizedTask) -> ChangeSemanticsClassification:
        """Classify change semantics with deterministic validation and reconciliation."""
        deterministic_facts = classify_semantics_deterministically(task).deterministic_facts

        messages = [
            {"role": "system", "content": SEMANTICS_SYSTEM_PROMPT},
            {
                "role": "user",
                "content": (
                    f"Engineering Task:\n{task.normalized_text}\n\n"
                    f"Classify change semantics for this task. Remember that change_class must be "
                    f"one of the canonical six classes or null, and all citations must be verbatim."
                ),
            },
        ]

        result = self.model_client.complete(messages)

        usage = getattr(result, "usage", None)
        prompt_tokens = getattr(usage, "prompt_tokens", 0) if usage is not None else 0
        completion_tokens = getattr(usage, "completion_tokens", 0) if usage is not None else 0
        total_tokens = getattr(usage, "total_tokens", 0) if usage is not None else 0
        telemetry_digest = getattr(result, "telemetry_digest", None)

        raw_text = getattr(result, "content", getattr(result, "raw_text", str(result)))
        model_id = getattr(result, "returned_model", self.model_id)

        proposal = parse_and_validate_semantics_proposal(
            raw_response=raw_text,
            task=task,
            model_id=model_id,
            prompt_tokens=prompt_tokens,
            completion_tokens=completion_tokens,
            total_tokens=total_tokens,
            telemetry_digest=telemetry_digest,
        )

        return reconcile_semantics(
            task=task,
            deterministic_facts=deterministic_facts,
            model_proposal=proposal,
        )
