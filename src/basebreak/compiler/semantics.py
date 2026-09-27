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
5. Model proposal cannot alter any authoritative classification field:
   change_class, certainty, confidence, alternative_classes, evidence_citations,
   verification_requirement.
6. All evidence citations must be verbatim substrings in normalized task text.
   Unsupported citations fail closed.
7. Compiler core is strictly provider-neutral:
   zero provider-specific identifiers, zero provider model IDs, zero adapter imports.
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
    "CertaintyLevel",
    "ChangeClass",
    "ChangeSemanticsClassification",
    "ChangeSemanticsError",
    "DeterministicClassificationFact",
    "MalformedModelSemanticsError",
    "ModelChangeProposal",
    "SEMANTICS_SYSTEM_PROMPT",
    "classify_semantics_deterministically",
    "parse_and_validate_semantics_proposal",
    "reconcile_semantics",
]

# Provider-neutral system prompt template for model semantics proposal
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


class CertaintyLevel(str, Enum):
    """Certainty level for change semantics classification."""

    CONFIDENT = "CONFIDENT"
    AMBIGUOUS = "AMBIGUOUS"
    UNKNOWN = "UNKNOWN"


class ChangeSemanticsError(Exception):
    """Base exception for change semantics classification errors."""


class MalformedModelSemanticsError(ChangeSemanticsError):
    """Raised when model output is invalid JSON, violates schema, or contains invalid types."""


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

    def __post_init__(self) -> None:
        if self.is_authoritative is not False:
            raise ValueError(
                "ModelChangeProposal cannot be authoritative (is_authoritative must be False)"
            )
        if self.proposed_class is not None and not isinstance(self.proposed_class, ChangeClass):
            cls_name = type(self.proposed_class).__name__
            raise TypeError(f"proposed_class must be ChangeClass or None, got {cls_name}")
        if not isinstance(self.certainty, CertaintyLevel):
            raise TypeError(
                f"certainty must be CertaintyLevel, got {type(self.certainty).__name__}"
            )
        if isinstance(self.confidence, bool) or not isinstance(self.confidence, (int, float)):
            raise TypeError(
                f"confidence must be float or int (not bool), got {type(self.confidence).__name__}"
            )
        if not (0.0 <= self.confidence <= 1.0):
            raise ValueError(f"confidence out of bounds: {self.confidence}")
        if not isinstance(self.alternative_classes, tuple):
            raise TypeError("alternative_classes must be a tuple")
        for ac in self.alternative_classes:
            if not isinstance(ac, ChangeClass):
                raise TypeError(
                    f"alternative_classes item must be ChangeClass, got {type(ac).__name__}"
                )
        if not isinstance(self.rationale, str):
            raise TypeError(f"rationale must be str, got {type(self.rationale).__name__}")
        if not isinstance(self.evidence_citations, tuple):
            raise TypeError("evidence_citations must be a tuple")
        for ec in self.evidence_citations:
            if not isinstance(ec, str):
                raise TypeError(f"evidence_citations item must be str, got {type(ec).__name__}")
        if not isinstance(self.raw_response, str):
            raise TypeError(f"raw_response must be str, got {type(self.raw_response).__name__}")
        if not isinstance(self.model_id, str):
            raise TypeError(f"model_id must be str, got {type(self.model_id).__name__}")
        for t_name in ("prompt_tokens", "completion_tokens", "total_tokens"):
            val = getattr(self, t_name)
            if isinstance(val, bool) or not isinstance(val, int) or val < 0:
                raise TypeError(f"{t_name} must be a non-negative int (not bool), got {val!r}")
        if self.telemetry_digest is not None and not isinstance(self.telemetry_digest, str):
            raise TypeError(
                f"telemetry_digest must be str or None, got {type(self.telemetry_digest).__name__}"
            )

    def to_dict(self) -> dict[str, Any]:
        """Deterministic dictionary serialization."""
        return {
            "proposed_class": self.proposed_class.value
            if self.proposed_class is not None
            else None,
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
        """Construct from dictionary with strict schema validation without coercion."""
        if not isinstance(data, Mapping):
            raise TypeError(f"Expected mapping for ModelChangeProposal, got {type(data).__name__}")

        if "is_authoritative" in data and data["is_authoritative"] is not False:
            raise ValueError(
                "ModelChangeProposal cannot be authoritative: 'is_authoritative' must be False"
            )

        required = {"proposed_class", "certainty", "confidence", "model_id", "raw_response"}
        missing = required - set(data.keys())
        if missing:
            raise ValueError(f"Missing required fields for ModelChangeProposal: {sorted(missing)}")

        raw_class = data["proposed_class"]
        if raw_class is not None and not isinstance(raw_class, str):
            raise TypeError(f"proposed_class must be str or None, got {type(raw_class).__name__}")
        proposed_class: ChangeClass | None = None
        if isinstance(raw_class, str):
            try:
                proposed_class = ChangeClass(raw_class)
            except ValueError:
                raise ValueError(f"Invalid ChangeClass: {raw_class}") from None

        raw_cert = data["certainty"]
        if not isinstance(raw_cert, str):
            raise TypeError(f"certainty must be str, got {type(raw_cert).__name__}")
        try:
            certainty = CertaintyLevel(raw_cert)
        except ValueError:
            raise ValueError(f"Invalid CertaintyLevel: {raw_cert}") from None

        raw_conf = data["confidence"]
        if isinstance(raw_conf, bool) or not isinstance(raw_conf, (int, float)):
            raise TypeError(
                f"confidence must be float or int (not bool), got {type(raw_conf).__name__}"
            )
        confidence = float(raw_conf)
        if not (0.0 <= confidence <= 1.0):
            raise ValueError(f"confidence out of bounds: {confidence}")

        raw_model_id = data["model_id"]
        if not isinstance(raw_model_id, str):
            raise TypeError(f"model_id must be str, got {type(raw_model_id).__name__}")

        raw_response = data["raw_response"]
        if not isinstance(raw_response, str):
            raise TypeError(f"raw_response must be str, got {type(raw_response).__name__}")

        alt_raw = data.get("alternative_classes", ())
        if not isinstance(alt_raw, (list, tuple)):
            raise TypeError(
                f"alternative_classes must be list or tuple, got {type(alt_raw).__name__}"
            )
        alt_classes: list[ChangeClass] = []
        for c in alt_raw:
            if not isinstance(c, str):
                raise TypeError(f"alternative_classes items must be str, got {type(c).__name__}")
            try:
                alt_classes.append(ChangeClass(c))
            except ValueError:
                raise ValueError(f"Invalid ChangeClass in alternative_classes: {c}") from None

        raw_rat = data.get("rationale", "")
        if not isinstance(raw_rat, str):
            raise TypeError(f"rationale must be str, got {type(raw_rat).__name__}")

        citations_raw = data.get("evidence_citations", ())
        if not isinstance(citations_raw, (list, tuple)):
            raise TypeError(
                f"evidence_citations must be list or tuple, got {type(citations_raw).__name__}"
            )
        citations: list[str] = []
        for c in citations_raw:
            if not isinstance(c, str):
                raise TypeError(f"evidence_citations items must be str, got {type(c).__name__}")
            citations.append(c)

        prompt_tokens = data.get("prompt_tokens", 0)
        completion_tokens = data.get("completion_tokens", 0)
        total_tokens = data.get("total_tokens", 0)
        for t_name, val in [
            ("prompt_tokens", prompt_tokens),
            ("completion_tokens", completion_tokens),
            ("total_tokens", total_tokens),
        ]:
            if isinstance(val, bool) or not isinstance(val, int) or val < 0:
                raise TypeError(f"{t_name} must be a non-negative int (not bool), got {val!r}")

        telemetry_digest = data.get("telemetry_digest")
        if telemetry_digest is not None and not isinstance(telemetry_digest, str):
            raise TypeError(
                f"telemetry_digest must be str or None, got {type(telemetry_digest).__name__}"
            )

        return cls(
            proposed_class=proposed_class,
            certainty=certainty,
            confidence=confidence,
            alternative_classes=tuple(alt_classes),
            rationale=raw_rat,
            evidence_citations=tuple(citations),
            raw_response=raw_response,
            model_id=raw_model_id,
            prompt_tokens=prompt_tokens,
            completion_tokens=completion_tokens,
            total_tokens=total_tokens,
            telemetry_digest=telemetry_digest,
            is_authoritative=False,
        )


@dataclass(frozen=True, slots=True)
class DeterministicClassificationFact:
    """Authoritative deterministic classification result derived from task text signals."""

    inferred_class: ChangeClass | None
    certainty: CertaintyLevel
    confidence: float
    alternative_classes: tuple[ChangeClass, ...]
    rationale: str
    evidence_citations: tuple[str, ...]
    matched_signals: tuple[str, ...]

    def __post_init__(self) -> None:
        if self.inferred_class is not None and not isinstance(self.inferred_class, ChangeClass):
            cls_name = type(self.inferred_class).__name__
            raise TypeError(f"inferred_class must be ChangeClass or None, got {cls_name}")
        if not isinstance(self.certainty, CertaintyLevel):
            raise TypeError(
                f"certainty must be CertaintyLevel, got {type(self.certainty).__name__}"
            )
        if isinstance(self.confidence, bool) or not isinstance(self.confidence, (int, float)):
            raise TypeError(
                f"confidence must be float or int (not bool), got {type(self.confidence).__name__}"
            )
        if not (0.0 <= self.confidence <= 1.0):
            raise ValueError(f"confidence out of bounds: {self.confidence}")
        if not isinstance(self.alternative_classes, tuple):
            raise TypeError("alternative_classes must be a tuple")
        for ac in self.alternative_classes:
            if not isinstance(ac, ChangeClass):
                raise TypeError(
                    f"alternative_classes item must be ChangeClass, got {type(ac).__name__}"
                )
        if not isinstance(self.rationale, str):
            raise TypeError(f"rationale must be str, got {type(self.rationale).__name__}")
        if not isinstance(self.evidence_citations, tuple):
            raise TypeError("evidence_citations must be a tuple")
        for ec in self.evidence_citations:
            if not isinstance(ec, str):
                raise TypeError(f"evidence_citations item must be str, got {type(ec).__name__}")
        if not isinstance(self.matched_signals, tuple):
            raise TypeError("matched_signals must be a tuple")
        for ms in self.matched_signals:
            if not isinstance(ms, str):
                raise TypeError(f"matched_signals item must be str, got {type(ms).__name__}")

    def to_dict(self) -> dict[str, Any]:
        """Deterministic dictionary serialization."""
        return {
            "inferred_class": self.inferred_class.value
            if self.inferred_class is not None
            else None,
            "certainty": self.certainty.value,
            "confidence": self.confidence,
            "alternative_classes": [c.value for c in self.alternative_classes],
            "rationale": self.rationale,
            "evidence_citations": list(self.evidence_citations),
            "matched_signals": list(self.matched_signals),
        }

    @classmethod
    def from_dict(cls, data: Mapping[str, Any]) -> DeterministicClassificationFact:
        """Construct from dictionary with strict schema validation without coercion."""
        if not isinstance(data, Mapping):
            raise TypeError(
                f"Expected mapping for DeterministicClassificationFact, got {type(data).__name__}"
            )

        required = {"inferred_class", "certainty", "confidence", "rationale"}
        missing = required - set(data.keys())
        if missing:
            raise ValueError(
                f"Missing required fields for DeterministicClassificationFact: {sorted(missing)}"
            )

        raw_class = data["inferred_class"]
        if raw_class is not None and not isinstance(raw_class, str):
            raise TypeError(f"inferred_class must be str or None, got {type(raw_class).__name__}")
        inferred_class: ChangeClass | None = None
        if isinstance(raw_class, str):
            try:
                inferred_class = ChangeClass(raw_class)
            except ValueError:
                raise ValueError(f"Invalid ChangeClass: {raw_class}") from None

        raw_cert = data["certainty"]
        if not isinstance(raw_cert, str):
            raise TypeError(f"certainty must be str, got {type(raw_cert).__name__}")
        try:
            certainty = CertaintyLevel(raw_cert)
        except ValueError:
            raise ValueError(f"Invalid CertaintyLevel: {raw_cert}") from None

        raw_conf = data["confidence"]
        if isinstance(raw_conf, bool) or not isinstance(raw_conf, (int, float)):
            raise TypeError(
                f"confidence must be float or int (not bool), got {type(raw_conf).__name__}"
            )
        confidence = float(raw_conf)
        if not (0.0 <= confidence <= 1.0):
            raise ValueError(f"confidence out of bounds: {confidence}")

        raw_rat = data["rationale"]
        if not isinstance(raw_rat, str):
            raise TypeError(f"rationale must be str, got {type(raw_rat).__name__}")

        alt_raw = data.get("alternative_classes", ())
        if not isinstance(alt_raw, (list, tuple)):
            raise TypeError(
                f"alternative_classes must be list or tuple, got {type(alt_raw).__name__}"
            )
        alt_classes: list[ChangeClass] = []
        for c in alt_raw:
            if not isinstance(c, str):
                raise TypeError(f"alternative_classes items must be str, got {type(c).__name__}")
            try:
                alt_classes.append(ChangeClass(c))
            except ValueError:
                raise ValueError(f"Invalid ChangeClass in alternative_classes: {c}") from None

        citations_raw = data.get("evidence_citations", ())
        if not isinstance(citations_raw, (list, tuple)):
            raise TypeError(
                f"evidence_citations must be list or tuple, got {type(citations_raw).__name__}"
            )
        citations: list[str] = []
        for c in citations_raw:
            if not isinstance(c, str):
                raise TypeError(f"evidence_citations items must be str, got {type(c).__name__}")
            citations.append(c)

        signals_raw = data.get("matched_signals", ())
        if not isinstance(signals_raw, (list, tuple)):
            raise TypeError(
                f"matched_signals must be list or tuple, got {type(signals_raw).__name__}"
            )
        signals: list[str] = []
        for s in signals_raw:
            if not isinstance(s, str):
                raise TypeError(f"matched_signals items must be str, got {type(s).__name__}")
            signals.append(s)

        return cls(
            inferred_class=inferred_class,
            certainty=certainty,
            confidence=confidence,
            alternative_classes=tuple(alt_classes),
            rationale=raw_rat,
            evidence_citations=tuple(citations),
            matched_signals=tuple(signals),
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
        if isinstance(self.confidence, bool) or not isinstance(self.confidence, (int, float)):
            raise TypeError(
                f"confidence must be float or int (not bool), got {type(self.confidence).__name__}"
            )
        if not (0.0 <= self.confidence <= 1.0):
            raise ValueError(f"confidence out of bounds: {self.confidence}")
        if not isinstance(self.alternative_classes, tuple):
            raise TypeError("alternative_classes must be a tuple")
        for ac in self.alternative_classes:
            if not isinstance(ac, ChangeClass):
                raise TypeError(
                    f"alternative_classes item must be ChangeClass, got {type(ac).__name__}"
                )
        if not isinstance(self.rationale, str):
            raise TypeError(f"rationale must be str, got {type(self.rationale).__name__}")
        if not isinstance(self.evidence_citations, tuple):
            raise TypeError("evidence_citations must be a tuple")
        for ec in self.evidence_citations:
            if not isinstance(ec, str):
                raise TypeError(f"evidence_citations item must be str, got {type(ec).__name__}")
        if not isinstance(self.deterministic_facts, DeterministicClassificationFact):
            raise TypeError(
                f"deterministic_facts must be DeterministicClassificationFact, "
                f"got {type(self.deterministic_facts).__name__}"
            )
        if self.model_proposal is not None and not isinstance(
            self.model_proposal, ModelChangeProposal
        ):
            raise TypeError(
                f"model_proposal must be ModelChangeProposal or None, "
                f"got {type(self.model_proposal).__name__}"
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
            "change_class": self.change_class.value if self.change_class is not None else None,
            "certainty": self.certainty.value,
            "confidence": self.confidence,
            "alternative_classes": [c.value for c in self.alternative_classes],
            "rationale": self.rationale,
            "evidence_citations": list(self.evidence_citations),
            "deterministic_facts": self.deterministic_facts.to_dict(),
            "model_proposal": (
                self.model_proposal.to_dict() if self.model_proposal is not None else None
            ),
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
                if self.verification_requirement is not None
                else None
            ),
        }

    @classmethod
    def from_dict(cls, data: Mapping[str, Any]) -> ChangeSemanticsClassification:
        """Construct from dictionary with strict schema validation without coercion."""
        if not isinstance(data, Mapping):
            raise TypeError(
                f"Expected mapping for ChangeSemanticsClassification, got {type(data).__name__}"
            )

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

        task_digest = data["task_digest"]
        if not isinstance(task_digest, str) or not task_digest:
            raise ValueError("task_digest must be a non-empty string")

        raw_class = data["change_class"]
        if raw_class is not None and not isinstance(raw_class, str):
            raise TypeError(f"change_class must be str or None, got {type(raw_class).__name__}")
        change_class: ChangeClass | None = None
        if isinstance(raw_class, str):
            try:
                change_class = ChangeClass(raw_class)
            except ValueError:
                raise ValueError(f"Invalid ChangeClass: {raw_class}") from None

        raw_cert = data["certainty"]
        if not isinstance(raw_cert, str):
            raise TypeError(f"certainty must be str, got {type(raw_cert).__name__}")
        try:
            certainty = CertaintyLevel(raw_cert)
        except ValueError:
            raise ValueError(f"Invalid CertaintyLevel: {raw_cert}") from None

        raw_conf = data["confidence"]
        if isinstance(raw_conf, bool) or not isinstance(raw_conf, (int, float)):
            raise TypeError(
                f"confidence must be float or int (not bool), got {type(raw_conf).__name__}"
            )
        confidence = float(raw_conf)
        if not (0.0 <= confidence <= 1.0):
            raise ValueError(f"confidence out of bounds: {confidence}")

        raw_rat = data["rationale"]
        if not isinstance(raw_rat, str):
            raise TypeError(f"rationale must be str, got {type(raw_rat).__name__}")

        alt_raw = data.get("alternative_classes", ())
        if not isinstance(alt_raw, (list, tuple)):
            raise TypeError(
                f"alternative_classes must be list or tuple, got {type(alt_raw).__name__}"
            )
        alt_classes: list[ChangeClass] = []
        for c in alt_raw:
            if not isinstance(c, str):
                raise TypeError(f"alternative_classes items must be str, got {type(c).__name__}")
            try:
                alt_classes.append(ChangeClass(c))
            except ValueError:
                raise ValueError(f"Invalid ChangeClass in alternative_classes: {c}") from None

        citations_raw = data.get("evidence_citations", ())
        if not isinstance(citations_raw, (list, tuple)):
            raise TypeError(
                f"evidence_citations must be list or tuple, got {type(citations_raw).__name__}"
            )
        citations: list[str] = []
        for c in citations_raw:
            if not isinstance(c, str):
                raise TypeError(f"evidence_citations items must be str, got {type(c).__name__}")
            citations.append(c)

        det_facts_raw = data["deterministic_facts"]
        if not isinstance(det_facts_raw, Mapping):
            raise TypeError("deterministic_facts must be a mapping")
        det_facts = DeterministicClassificationFact.from_dict(det_facts_raw)

        model_prop_raw = data.get("model_proposal")
        model_proposal: ModelChangeProposal | None = None
        if model_prop_raw is not None:
            if not isinstance(model_prop_raw, Mapping):
                raise TypeError("model_proposal must be a mapping or None")
            model_proposal = ModelChangeProposal.from_dict(model_prop_raw)

        return cls(
            task_digest=task_digest,
            change_class=change_class,
            certainty=certainty,
            confidence=confidence,
            alternative_classes=tuple(alt_classes),
            rationale=raw_rat,
            evidence_citations=tuple(citations),
            deterministic_facts=det_facts,
            model_proposal=model_proposal,
        )


# Keyword and phrase signals for bounded deterministic analysis
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
    s = max(0, start_idx - 15)
    e = min(len(text), end_idx + 15)

    while s > 0 and not text[s - 1].isspace() and (start_idx - s) < 30:
        s -= 1
    while e < len(text) and not text[e].isspace() and (e - end_idx) < 30:
        e += 1

    candidate = text[s:e].strip()
    if candidate and candidate in text:
        return candidate
    return text[start_idx:end_idx]


def _compute_deterministic_facts(
    normalized_task: NormalizedTask,
) -> DeterministicClassificationFact:
    """Extract deterministic classification evidence and signals from normalized task text."""
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
    """Classify task semantics using bounded deterministic signal analysis alone.

    Does not call any external model. Guarantees deterministic classification.
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

    Fails closed on malformed JSON, schema violations, missing required fields,
    invalid types, internal inconsistencies, or invalid citations.
    Zero secret leakage in exceptions.
    """
    if not isinstance(raw_response, str) or not raw_response.strip():
        raise MalformedModelSemanticsError("Model returned empty or whitespace-only response")

    if not isinstance(model_id, str) or not model_id.strip():
        raise MalformedModelSemanticsError("model_id must be a non-empty string")

    for t_name, val in [
        ("prompt_tokens", prompt_tokens),
        ("completion_tokens", completion_tokens),
        ("total_tokens", total_tokens),
    ]:
        if isinstance(val, bool) or not isinstance(val, int) or val < 0:
            raise MalformedModelSemanticsError(f"{t_name} must be a non-negative int (not bool)")

    if telemetry_digest is not None and not isinstance(telemetry_digest, str):
        raise MalformedModelSemanticsError("telemetry_digest must be str or None")

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

    # All 6 declared structured proposal fields are strictly required:
    required_fields = (
        "change_class",
        "certainty",
        "confidence",
        "alternative_classes",
        "rationale",
        "evidence_citations",
    )
    missing = [f for f in required_fields if f not in data]
    if missing:
        raise MalformedModelSemanticsError(
            f"Model output missing required schema field(s): {missing}"
        )

    # 1. Validate change_class
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

    # 2. Validate certainty (no default)
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

    # 3. Validate confidence (no default, float/int not bool, in [0.0, 1.0])
    raw_conf = data["confidence"]
    if isinstance(raw_conf, bool) or not isinstance(raw_conf, (int, float)):
        raise MalformedModelSemanticsError(
            f"'confidence' must be float or int, got {type(raw_conf).__name__}"
        )
    confidence = float(raw_conf)
    if not (0.0 <= confidence <= 1.0):
        raise MalformedModelSemanticsError(f"Confidence out of bounds: {confidence}")

    # 4. Validate alternative_classes (no default, must be list of strings)
    raw_alts = data["alternative_classes"]
    if not isinstance(raw_alts, list):
        raise MalformedModelSemanticsError(
            f"'alternative_classes' must be list, got {type(raw_alts).__name__}"
        )
    alt_classes: list[ChangeClass] = []
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

    # 5. Validate rationale (no default, must be str)
    raw_rat = data["rationale"]
    if not isinstance(raw_rat, str):
        raise MalformedModelSemanticsError(f"'rationale' must be str, got {type(raw_rat).__name__}")
    rationale = raw_rat.strip()

    # 6. Validate evidence_citations (no default, must be list of strings)
    raw_cits = data["evidence_citations"]
    if not isinstance(raw_cits, list):
        raise MalformedModelSemanticsError(
            f"'evidence_citations' must be list, got {type(raw_cits).__name__}"
        )
    citations: list[str] = []
    for cit_item in raw_cits:
        if not isinstance(cit_item, str):
            raise MalformedModelSemanticsError(
                f"evidence_citations items must be str, got {type(cit_item).__name__}"
            )
        cit_str = cit_item.strip()
        if not cit_str:
            continue
        if cit_str not in task.normalized_text:
            safe_cit = redact_log_text(cit_str)
            raise UnsupportedCitationError(
                f"Evidence citation is not present in task text: {safe_cit!r}"
            )
        if cit_str not in citations:
            citations.append(cit_str)

    # 7. Internal consistency validation
    if certainty == CertaintyLevel.CONFIDENT:
        if proposed_class is None:
            raise MalformedModelSemanticsError(
                "change_class cannot be null when certainty is CONFIDENT"
            )
        if alt_classes:
            raise MalformedModelSemanticsError(
                "alternative_classes must be empty when certainty is CONFIDENT"
            )

    if certainty == CertaintyLevel.UNKNOWN:
        if proposed_class is not None:
            raise MalformedModelSemanticsError(
                "change_class must be null when certainty is UNKNOWN"
            )

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
    """Reconcile deterministic classification facts and optional advisory model proposal.

    Authority Hierarchy:
    1. Deterministic facts have EXCLUSIVE authority over all canonical fields:
       - change_class
       - certainty
       - confidence
       - alternative_classes
       - evidence_citations
       - verification_requirement
    2. Model proposal is strictly advisory metadata (MODEL = PROPOSAL ONLY).
    3. Model proposal MUST NOT alter any canonical classification field under any circumstance.
    4. Rationale may mention model agreement/disagreement for audit/review context without
       altering underlying deterministic facts.
    """
    task_digest = task.task_digest

    change_class = deterministic_facts.inferred_class
    certainty = deterministic_facts.certainty
    confidence = deterministic_facts.confidence
    alt_classes = deterministic_facts.alternative_classes
    citations = deterministic_facts.evidence_citations

    if model_proposal is None:
        rationale = deterministic_facts.rationale
    else:
        if deterministic_facts.certainty == CertaintyLevel.CONFIDENT:
            if model_proposal.proposed_class == change_class:
                rationale = (
                    f"{deterministic_facts.rationale} "
                    f"Advisory model proposal agrees with deterministic classification "
                    f"({model_proposal.model_id})."
                )
            else:
                rationale = (
                    f"{deterministic_facts.rationale} "
                    f"Advisory model proposal suggested '{model_proposal.proposed_class}', "
                    f"which was overridden by deterministic fact authority."
                )
        elif deterministic_facts.certainty == CertaintyLevel.AMBIGUOUS:
            rationale = (
                f"{deterministic_facts.rationale} "
                f"Advisory model proposal suggests '{model_proposal.proposed_class}', "
                f"but task signals remain ambiguous. Certainty preserved as AMBIGUOUS."
            )
        else:  # UNKNOWN
            rationale = (
                f"Insufficient meaningful evidence in task text to establish change class. "
                f"Advisory model proposed '{model_proposal.proposed_class}', but cannot "
                f"manufacture authority without underlying task facts. Preserved as UNKNOWN."
            )

    return ChangeSemanticsClassification(
        task_digest=task_digest,
        change_class=change_class,
        certainty=certainty,
        confidence=confidence,
        alternative_classes=alt_classes,
        rationale=rationale,
        evidence_citations=citations,
        deterministic_facts=deterministic_facts,
        model_proposal=model_proposal,
    )
