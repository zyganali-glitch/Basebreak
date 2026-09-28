"""Deterministic verification contract validator.

P-06.04: Deterministically validate requirement IDs, scope, forbidden actions,
and contradictions under the Basebreak causal verification authority model.

Authority Model:
1. Model authority = ZERO. Purely deterministic validation.
2. Zero model calls, zero Nebius/provider imports, zero sandbox calls.
3. Strict typing: wrong types fail closed; no permissive str/int/bool coercions.
4. Requirement IDs: deterministic, immutable, bounded, and fail-closed.
   Algorithm: content-derived SHA-256 digest prefix of canonical requirement content:
   REQ-<first 8 hex characters uppercase>.
5. Citation / source binding: every citation must exist verbatim in normalized task text
   at the exact [citation_start:citation_end] slice.
6. Scope validation: deterministic scope alignment and protected-surface checks.
7. Forbidden actions: rejects demands to weaken tests, bypass security, exfiltrate
   secrets, disable verification, or execute destructive commands.
   Protective and verification framing (e.g. "Add a test proving rm -rf / fails")
   is distinguished from demands and accepted.
8. Contradiction detection: bounded, explicit deterministic contradiction classes
   with stable rule IDs and trigger/scope comparison.
9. Change-class authority: consumes canonical ChangeClass. AMBIGUOUS/UNKNOWN
   certainty is never silently promoted.
10. ABSOLUTE P-06.06 BOUNDARY:
    Zero final contract digest! No contract_digest, validation_digest, frozen_digest,
    builder_digest, or evidence_root_digest.
"""

from __future__ import annotations

import hashlib
import json
import re
from collections.abc import Mapping, Sequence
from dataclasses import dataclass
from typing import Any

from basebreak.compiler.ingestion import NormalizedTask
from basebreak.compiler.requirements import ProposedRequirement
from basebreak.compiler.semantics import CertaintyLevel, ChangeSemanticsClassification
from basebreak.domain.semantics import ChangeClass
from basebreak.security.protected_surfaces import (
    PathSecurityError,
    ProtectedSurfaceManifest,
    get_canonical_basebreak_protected_manifest,
    match_protected_surface,
    normalize_repo_path,
)
from basebreak.security.secret_policy import redact_log_text

__all__ = [
    "MAX_CITATION_LENGTH",
    "MAX_RATIONALE_LENGTH",
    "MAX_REQUIREMENT_ID_LENGTH",
    "MAX_REQUIREMENTS_COUNT",
    "MAX_STATEMENT_LENGTH",
    "MIN_REQUIREMENTS_COUNT",
    "ContradictoryRequirementsError",
    "ContractValidationError",
    "DuplicateRequirementIdError",
    "ForbiddenActionViolationError",
    "InvalidCitationError",
    "InvalidRequirementIdError",
    "MissingRequirementIdError",
    "RequirementCountLimitExceededError",
    "RequirementIdCollisionError",
    "RequirementSizeLimitExceededError",
    "UnresolvedChangeClassError",
    "UnsupportedScopeError",
    "ValidatedContract",
    "ValidatedRequirement",
    "derive_requirement_id",
    "validate_contract",
]

# --- Constants & Ceilings ---

MIN_REQUIREMENTS_COUNT: int = 1
MAX_REQUIREMENTS_COUNT: int = 50

MAX_STATEMENT_LENGTH: int = 2000
MAX_CITATION_LENGTH: int = 4000
MAX_RATIONALE_LENGTH: int = 2000
MAX_REQUIREMENT_ID_LENGTH: int = 64

_REQUIREMENT_ID_PATTERN = re.compile(r"^[A-Za-z0-9_\-]+$")

# --- Exception Hierarchy ---


class ContractValidationError(Exception):
    """Base exception for all contract validation errors."""


class MissingRequirementIdError(ContractValidationError):
    """Raised when a requirement is missing an ID and derivation is disabled."""


class DuplicateRequirementIdError(ContractValidationError):
    """Raised when duplicate requirement IDs are detected."""


class RequirementIdCollisionError(ContractValidationError):
    """Raised when distinct requirements collide on derived requirement ID."""


class InvalidRequirementIdError(ContractValidationError):
    """Raised when a requirement ID does not conform to deterministic format."""


class RequirementCountLimitExceededError(ContractValidationError):
    """Raised when requirements count is 0 or exceeds allowable ceiling."""


class RequirementSizeLimitExceededError(ContractValidationError):
    """Raised when statement, citation, or rationale length exceeds allowable bounds."""


class InvalidCitationError(ContractValidationError):
    """Raised when citation or citation span is invalid or unsupported by task text."""


class UnsupportedScopeError(ContractValidationError):
    """Raised when requirement scope is not supported by task text or violates task scope."""


class ForbiddenActionViolationError(ContractValidationError):
    """Raised when a requirement demands a forbidden action or protected surface mutation."""

    def __init__(self, rule_id: str, requirement_id: str, detail: str) -> None:
        safe_detail = redact_log_text(detail)
        super().__init__(
            f"[{rule_id}] Requirement {requirement_id!r} violated "
            f"forbidden action policy: {safe_detail}"
        )
        self.rule_id = rule_id
        self.requirement_id = requirement_id
        self.detail = safe_detail


class ContradictoryRequirementsError(ContractValidationError):
    """Raised when deterministically provable contradictory requirements are detected."""

    def __init__(
        self,
        rule_id: str,
        req_id_a: str,
        req_id_b: str,
        detail: str,
    ) -> None:
        safe_detail = redact_log_text(detail)
        super().__init__(
            f"[{rule_id}] Contradiction detected between {req_id_a!r} "
            f"and {req_id_b!r}: {safe_detail}"
        )
        self.rule_id = rule_id
        self.req_id_a = req_id_a
        self.req_id_b = req_id_b
        self.detail = safe_detail


class UnresolvedChangeClassError(ContractValidationError):
    """Raised when an operation strictly requiring a resolved ChangeClass encounters
    AMBIGUOUS or UNKNOWN."""


# --- Requirement ID Derivation ---


def derive_requirement_id(
    statement: str,
    citation: str = "",
    citation_start: int = 0,
    citation_end: int = 0,
) -> str:
    """Deterministically derive a content-addressed requirement ID from canonical content.

    Algorithm:
    1. Strip leading and trailing whitespace from statement and citation.
    2. Encode canonical tuple (statement, citation, citation_start, citation_end)
       with null-byte separators as UTF-8.
    3. Compute SHA-256 digest of canonical bytes.
    4. Format identifier as 'REQ-<first 8 hex characters uppercase>'.

    This ensures identical requirement content yields the exact same ID regardless of
    list ordering or surrounding context.
    """
    if not isinstance(statement, str):
        raise TypeError(f"statement must be str, got {type(statement).__name__}")
    if not isinstance(citation, str):
        raise TypeError(f"citation must be str, got {type(citation).__name__}")
    if isinstance(citation_start, bool) or not isinstance(citation_start, int):
        raise TypeError(
            f"citation_start must be int (not bool), got {type(citation_start).__name__}"
        )
    if isinstance(citation_end, bool) or not isinstance(citation_end, int):
        raise TypeError(f"citation_end must be int (not bool), got {type(citation_end).__name__}")

    stmt = statement.strip()
    cit = citation.strip()
    canonical_repr = f"{stmt}\0{cit}\0{citation_start}\0{citation_end}".encode("utf-8")
    digest_prefix = hashlib.sha256(canonical_repr).hexdigest()[:8].upper()
    return f"REQ-{digest_prefix}"


# --- Validated Domain Objects ---


@dataclass(frozen=True, slots=True)
class ValidatedRequirement:
    """A deterministically validated atomic acceptance requirement.

    Attributes:
        requirement_id: Deterministic, non-empty identifier (e.g. REQ-A1B2C3D4).
        statement: Verifiable requirement statement bounded by size.
        citation: Exact verbatim substring from normalized task text.
        citation_start: 0-indexed character start offset in normalized task text.
        citation_end: 0-indexed character end offset in normalized task text.
        rationale: Brief justification or explanation.
    """

    requirement_id: str
    statement: str
    citation: str
    citation_start: int
    citation_end: int
    rationale: str = ""

    def __post_init__(self) -> None:
        if not isinstance(self.requirement_id, str):
            raise TypeError(f"requirement_id must be str, got {type(self.requirement_id).__name__}")
        req_id = self.requirement_id.strip()
        if not req_id:
            raise InvalidRequirementIdError("requirement_id must not be empty or whitespace-only")
        if req_id != self.requirement_id:
            raise InvalidRequirementIdError(
                "requirement_id must not have leading or trailing whitespace"
            )
        if len(self.requirement_id) > MAX_REQUIREMENT_ID_LENGTH:
            raise InvalidRequirementIdError(
                f"requirement_id exceeds maximum length "
                f"({len(self.requirement_id)} > {MAX_REQUIREMENT_ID_LENGTH})"
            )
        if not _REQUIREMENT_ID_PATTERN.match(self.requirement_id):
            raise InvalidRequirementIdError(
                f"requirement_id {self.requirement_id!r} does not match allowed pattern"
            )

        if not isinstance(self.statement, str):
            raise TypeError(f"statement must be str, got {type(self.statement).__name__}")
        stmt = self.statement.strip()
        if not stmt:
            raise ValueError("statement must not be empty or whitespace-only")
        if stmt != self.statement:
            object.__setattr__(self, "statement", stmt)
        if len(self.statement) > MAX_STATEMENT_LENGTH:
            raise RequirementSizeLimitExceededError(
                f"statement length exceeds maximum allowed "
                f"({len(self.statement)} > {MAX_STATEMENT_LENGTH})"
            )

        if not isinstance(self.citation, str):
            raise TypeError(f"citation must be str, got {type(self.citation).__name__}")
        cit = self.citation.strip()
        if not cit:
            raise ValueError("citation must not be empty or whitespace-only")
        if len(self.citation) > MAX_CITATION_LENGTH:
            raise RequirementSizeLimitExceededError(
                f"citation length exceeds maximum allowed "
                f"({len(self.citation)} > {MAX_CITATION_LENGTH})"
            )

        if isinstance(self.citation_start, bool) or not isinstance(self.citation_start, int):
            raise TypeError(
                f"citation_start must be int (not bool), got {type(self.citation_start).__name__}"
            )
        if isinstance(self.citation_end, bool) or not isinstance(self.citation_end, int):
            raise TypeError(
                f"citation_end must be int (not bool), got {type(self.citation_end).__name__}"
            )
        if self.citation_start < 0 or self.citation_end < self.citation_start:
            raise ValueError(f"Invalid citation span: [{self.citation_start}:{self.citation_end}]")

        if not isinstance(self.rationale, str):
            raise TypeError(f"rationale must be str, got {type(self.rationale).__name__}")
        if len(self.rationale) > MAX_RATIONALE_LENGTH:
            raise RequirementSizeLimitExceededError(
                f"rationale length exceeds maximum allowed "
                f"({len(self.rationale)} > {MAX_RATIONALE_LENGTH})"
            )

    def to_dict(self) -> dict[str, Any]:
        """Deterministic dictionary serialization."""
        return {
            "requirement_id": self.requirement_id,
            "statement": self.statement,
            "citation": self.citation,
            "citation_start": self.citation_start,
            "citation_end": self.citation_end,
            "rationale": self.rationale,
        }

    @classmethod
    def from_dict(cls, data: Mapping[str, Any]) -> ValidatedRequirement:
        """Construct from dictionary with strict schema validation without coercion."""
        if not isinstance(data, Mapping):
            raise TypeError(f"Expected mapping for ValidatedRequirement, got {type(data).__name__}")
        required = {"requirement_id", "statement", "citation", "citation_start", "citation_end"}
        missing = required - set(data.keys())
        if missing:
            raise ValueError(f"Missing required fields for ValidatedRequirement: {sorted(missing)}")

        req_id = data["requirement_id"]
        if not isinstance(req_id, str):
            raise TypeError(f"requirement_id must be str, got {type(req_id).__name__}")

        stmt = data["statement"]
        if not isinstance(stmt, str):
            raise TypeError(f"statement must be str, got {type(stmt).__name__}")

        cit = data["citation"]
        if not isinstance(cit, str):
            raise TypeError(f"citation must be str, got {type(cit).__name__}")

        c_start = data["citation_start"]
        if isinstance(c_start, bool) or not isinstance(c_start, int):
            raise TypeError(f"citation_start must be int (not bool), got {type(c_start).__name__}")

        c_end = data["citation_end"]
        if isinstance(c_end, bool) or not isinstance(c_end, int):
            raise TypeError(f"citation_end must be int (not bool), got {type(c_end).__name__}")

        rationale = data.get("rationale", "")
        if not isinstance(rationale, str):
            raise TypeError(f"rationale must be str, got {type(rationale).__name__}")

        return cls(
            requirement_id=req_id,
            statement=stmt,
            citation=cit,
            citation_start=c_start,
            citation_end=c_end,
            rationale=rationale,
        )


@dataclass(frozen=True, slots=True)
class ValidatedContract:
    """A deterministically validated verification contract.

    Carries verified engineering task identity, canonical change semantics,
    and deterministically validated acceptance requirements with source citations.

    ABSOLUTE P-06.06 INVARIANT:
    Zero final contract digest! This class does NOT compute or carry contract_digest,
    validation_digest, frozen_digest, builder_digest, or evidence_root_digest.
    """

    task_digest: str
    change_class: ChangeClass | None
    certainty: CertaintyLevel | None
    requirements: tuple[ValidatedRequirement, ...]
    validation_rules_passed: tuple[str, ...]
    is_valid: bool = True

    def __post_init__(self) -> None:
        if not isinstance(self.task_digest, str) or not self.task_digest:
            raise ValueError("task_digest must be a non-empty string")
        if len(self.task_digest) != 64 or not re.fullmatch(r"^[0-9a-f]{64}$", self.task_digest):
            raise ValueError(
                f"task_digest must be a 64-character lowercase hex SHA-256 string, "
                f"got {self.task_digest!r}"
            )

        if self.change_class is not None and not isinstance(self.change_class, ChangeClass):
            raise TypeError(
                f"change_class must be ChangeClass or None, got {type(self.change_class).__name__}"
            )

        if self.certainty is not None and not isinstance(self.certainty, CertaintyLevel):
            raise TypeError(
                f"certainty must be CertaintyLevel or None, got {type(self.certainty).__name__}"
            )

        if not isinstance(self.requirements, tuple):
            if isinstance(self.requirements, Sequence):
                object.__setattr__(self, "requirements", tuple(self.requirements))
            else:
                raise TypeError(
                    "requirements must be a tuple of ValidatedRequirement, "
                    f"got {type(self.requirements).__name__}"
                )

        if not (MIN_REQUIREMENTS_COUNT <= len(self.requirements) <= MAX_REQUIREMENTS_COUNT):
            raise RequirementCountLimitExceededError(
                f"Requirements count ({len(self.requirements)}) outside allowable bounds "
                f"[{MIN_REQUIREMENTS_COUNT}:{MAX_REQUIREMENTS_COUNT}]"
            )

        seen_ids: set[str] = set()
        for idx, req in enumerate(self.requirements):
            if not isinstance(req, ValidatedRequirement):
                raise TypeError(
                    f"Requirement at index {idx} must be ValidatedRequirement, "
                    f"got {type(req).__name__}"
                )
            if req.requirement_id in seen_ids:
                raise DuplicateRequirementIdError(
                    f"Duplicate requirement ID: {req.requirement_id!r}"
                )
            seen_ids.add(req.requirement_id)

        if not isinstance(self.validation_rules_passed, tuple):
            if isinstance(self.validation_rules_passed, Sequence):
                object.__setattr__(
                    self, "validation_rules_passed", tuple(self.validation_rules_passed)
                )
            else:
                raise TypeError("validation_rules_passed must be a tuple of str")
        for r in self.validation_rules_passed:
            if not isinstance(r, str):
                raise TypeError(
                    f"validation_rules_passed items must be str, got {type(r).__name__}"
                )

        if not isinstance(self.is_valid, bool) or self.is_valid is not True:
            raise ValueError(f"is_valid must be True for ValidatedContract, got {self.is_valid!r}")

    def to_dict(self) -> dict[str, Any]:
        """Deterministic dictionary serialization."""
        return {
            "task_digest": self.task_digest,
            "change_class": self.change_class.value if self.change_class is not None else None,
            "certainty": self.certainty.value if self.certainty is not None else None,
            "requirements": [r.to_dict() for r in self.requirements],
            "validation_rules_passed": list(self.validation_rules_passed),
            "is_valid": self.is_valid,
        }

    def to_json(self) -> str:
        """Deterministic JSON serialization with sorted keys and indentation."""
        return json.dumps(self.to_dict(), indent=2, sort_keys=True)

    @classmethod
    def from_dict(cls, data: Mapping[str, Any]) -> ValidatedContract:
        """Construct from dictionary with strict schema validation."""
        if not isinstance(data, Mapping):
            raise TypeError(f"Expected mapping for ValidatedContract, got {type(data).__name__}")

        # P-06.06 invariant: check that forbidden digests are NOT present
        for forbidden in (
            "contract_digest",
            "validation_digest",
            "frozen_digest",
            "builder_digest",
            "evidence_root_digest",
        ):
            if forbidden in data:
                raise ValueError(
                    f"Forbidden P-06.06 digest field '{forbidden}' "
                    "must not be present in P-06.04 contract"
                )

        required = {
            "task_digest",
            "change_class",
            "certainty",
            "requirements",
            "validation_rules_passed",
        }
        missing = required - set(data.keys())
        if missing:
            raise ValueError(f"Missing required fields for ValidatedContract: {sorted(missing)}")

        raw_td = data["task_digest"]
        if not isinstance(raw_td, str):
            raise TypeError(f"task_digest must be str, got {type(raw_td).__name__}")

        raw_cc = data["change_class"]
        change_class: ChangeClass | None = None
        if raw_cc is not None:
            if not isinstance(raw_cc, str):
                raise TypeError(f"change_class must be str or None, got {type(raw_cc).__name__}")
            try:
                change_class = ChangeClass(raw_cc)
            except ValueError:
                raise ValueError(f"Invalid ChangeClass: {raw_cc}") from None

        raw_cert = data["certainty"]
        certainty: CertaintyLevel | None = None
        if raw_cert is not None:
            if not isinstance(raw_cert, str):
                raise TypeError(f"certainty must be str or None, got {type(raw_cert).__name__}")
            try:
                certainty = CertaintyLevel(raw_cert)
            except ValueError:
                raise ValueError(f"Invalid CertaintyLevel: {raw_cert}") from None

        raw_reqs = data["requirements"]
        if not isinstance(raw_reqs, (list, tuple)):
            raise TypeError(f"requirements must be list or tuple, got {type(raw_reqs).__name__}")
        requirements = [ValidatedRequirement.from_dict(r) for r in raw_reqs]

        raw_rules = data["validation_rules_passed"]
        if not isinstance(raw_rules, (list, tuple)):
            raise TypeError(
                f"validation_rules_passed must be list or tuple, got {type(raw_rules).__name__}"
            )
        rules_passed = []
        for r in raw_rules:
            if not isinstance(r, str):
                raise TypeError(f"validation_rules_passed item must be str, got {type(r).__name__}")
            rules_passed.append(r)

        raw_valid = data.get("is_valid", True)
        if not isinstance(raw_valid, bool) or raw_valid is not True:
            raise ValueError(f"is_valid must be True, got {raw_valid!r}")

        return cls(
            task_digest=raw_td,
            change_class=change_class,
            certainty=certainty,
            requirements=tuple(requirements),
            validation_rules_passed=tuple(rules_passed),
            is_valid=True,
        )

    @classmethod
    def from_json(cls, json_str: str) -> ValidatedContract:
        """Construct from JSON string with strict schema validation."""
        if not isinstance(json_str, str):
            raise TypeError(f"json_str must be str, got {type(json_str).__name__}")
        data = json.loads(json_str)
        return cls.from_dict(data)


# --- Defensive Negative Constraint & Negation-Binding Detection (Blocker 1) ---

# Inverted defensive patterns: negation of defensive verbs (e.g., "never block", "must not prevent")
# means the dangerous action is permitted or demanded, NOT prohibited.
_INVERTED_DEFENSIVE_PATTERN = re.compile(
    r"\b(?:never|must\s+not|shall\s+not|cannot|can\s+not|do\s+not|don't|should\s+not|not)\s+"
    r"(?:block|prevent|forbid|reject|disallow|prohibit|stop|refuse)\b",
    re.IGNORECASE,
)

# Rule 1: Test weakening defensive patterns
_DEFENSIVE_TEST_WEAKEN_PATTERN = re.compile(
    r"\b(?:never|do\s+not|don't|must\s+not|shall\s+not|cannot|can\s+not)\s+"
    r"(?:delete|remove|weaken|relax|disable|bypass|ignore|drop|strip)\s+(?:failing\s+)?(?:tests?|assertions?)\b|"
    r"\b(?:tests?|assertions?|failing\s+tests?)\s+(?:must\s+not|shall\s+not|cannot|can\s+not|are\s+not\s+to|must\s+never)\s+be\s+(?:deleted|removed|weakened|relaxed|disabled|bypassed|ignored)\b|"
    r"\b(?:deleting|removing|weakening|relaxing|disabling|bypassing|ignoring)\s+(?:failing\s+)?(?:tests?|assertions?)\s+(?:must\s+not\s+be\s+allowed|is\s+(?:forbidden|prohibited|blocked|rejected|disallowed|prevented|not\s+allowed|refused)|cannot\s+be\s+allowed)\b|"
    r"\b(?:prevent|block|forbid|prohibit|disallow|reject|detect|catch|trap)\s+(?:any\s+)?(?:attempts?\s+to\s+)?(?:deleting|weakening|removing|bypassing|disabling)\s+(?:failing\s+)?(?:tests?|assertions?)\b|"
    r"\b(?:ensure|assert|verify|check|test)\s+that\s+(?:failing\s+)?(?:tests?|assertions?)\s+(?:are\s+not|cannot\s+be|must\s+not\s+be)\s+(?:deleted|weakened|removed|bypassed)\b",
    re.IGNORECASE,
)


def _is_defensive_test_weaken(text: str) -> bool:
    """Return True if text deterministically negates or prohibits test weakening."""
    if _INVERTED_DEFENSIVE_PATTERN.search(text):
        return False
    return bool(_DEFENSIVE_TEST_WEAKEN_PATTERN.search(text))


# Rule 2: Protected surface mutation defensive patterns
_DEFENSIVE_PROTECTED_MUTATION_PATTERN = re.compile(
    r"\b(?:modification|mutation|editing|changing|deletion|overwriting|removal)\s+of\s+.*?\b(?:is|must\s+be|shall\s+be|to\s+be)?\s*(?:rejected|blocked|forbidden|prohibited|disallowed|prevented|refused|not\s+allowed)\b|"
    r"\b(?:never|do\s+not|don't|must\s+not|shall\s+not|cannot|can\s+not)\s+(?:modify|edit|mutate|change|delete|remove|overwrite|patch|alter)\b|"
    r"\b(?:cannot|can\s+not|must\s+not|shall\s+not|must\s+never|shall\s+never|is\s+never)\s+be\s+(?:modified|edited|mutated|changed|deleted|removed|overwritten|patched|altered)\b|"
    r"\b(?:is|are)\s+not\s+(?:to\s+be\s+)?(?:modified|edited|mutated|changed|deleted|removed|overwritten|patched|altered)\b|"
    r"\b(?:protected\s+(?:files?|surfaces?|manifests?|workflows?))\s+(?:cannot|must\s+not|shall\s+not|must\s+never)\s+be\s+(?:modified|edited|deleted|overwritten)\b|"
    r"\b(?:test|ensure|verify|assert|check)\s+that\s+.*?\b(?:cannot\s+be\s+modified|is\s+rejected|is\s+blocked|is\s+forbidden|cannot\s+be\s+changed)\b|"
    r"\b(?:block|prevent|forbid|prohibit|disallow|reject|intercept)\s+(?:any\s+)?(?:mutation|modification|changes?|edits?|deletion|overwriting)\s+(?:of|to)\b",
    re.IGNORECASE,
)


def _is_defensive_protected_mutation(text: str) -> bool:
    """Return True if text deterministically negates or prohibits protected surface mutation."""
    if _INVERTED_DEFENSIVE_PATTERN.search(text):
        return False
    return bool(_DEFENSIVE_PROTECTED_MUTATION_PATTERN.search(text))


# Rule 3: Secret exfiltration defensive patterns
_DEFENSIVE_SECRET_EXFIL_PATTERN = re.compile(
    r"\b(?:uploading|sending|leaking|exfiltrating|posting|transmitting)\s+.*?(?:api[_\-\s]?keys?|secrets?|credentials?|tokens?|private[_\-\s]?keys?).*?\b(?:must\s+be|is|are|shall\s+be)?\s*(?:blocked|rejected|prevented|forbidden|prohibited|disallowed|refused|not\s+allowed)\b|"
    r"\b(?:api[_\-\s]?keys?|secrets?|credentials?|tokens?|private[_\-\s]?keys?).*?\b(?:must\s+never|shall\s+never|cannot|can\s+not|must\s+not|shall\s+not|are\s+never|is\s+never)\s+be\s+(?:uploaded|sent|exfiltrated|leaked|posted|transmitted|printed|logged|exposed)\b|"
    r"\b(?:api[_\-\s]?keys?|secrets?|credentials?|tokens?|private[_\-\s]?keys?).*?\b(?:are|is|must\s+be|shall\s+be)\s+(?:redacted|stripped|masked|hidden)\b|"
    r"\b(?:never|do\s+not|don't|must\s+not|shall\s+not|cannot|can\s+not)\s+(?:upload|send|exfiltrate|leak|post|transmit|print|log|expose)\s+.*?(?:api[_\-\s]?keys?|secrets?|credentials?|tokens?|private[_\-\s]?keys?)\b|"
    r"\b(?:ensure|verify|assert|check|test)\s+that\s+.*?(?:api[_\-\s]?keys?|secrets?|credentials?|tokens?).*?\b(?:are\s+(?:never|not)|cannot\s+be|are\s+redacted|are\s+masked)\b|"
    r"\b(?:ensure|verify|assert|check)\s+secrets\s+are\s+never\s+printed\s+to\s+logs\b|"
    r"\b(?:block|prevent|forbid|prohibit|disallow|reject|intercept|detect)\s+(?:any\s+)?(?:attempts?\s+to\s+)?(?:upload|send|exfiltrate|leak|post|transmit)\s+.*?(?:api[_\-\s]?keys?|secrets?|credentials?|tokens?)\b",
    re.IGNORECASE,
)


def _is_defensive_secret_exfil(text: str) -> bool:
    """Return True if text deterministically negates or prohibits credential/secret exfiltration."""
    if _INVERTED_DEFENSIVE_PATTERN.search(text):
        return False
    return bool(_DEFENSIVE_SECRET_EXFIL_PATTERN.search(text))


# Rule 4: Verification bypass defensive patterns
_DEFENSIVE_VERIFICATION_BYPASS_PATTERN = re.compile(
    r"\b(?:security\s+(?:checks?|validation|policy)|deterministic\s+verification|contract\s+validation|verification)\s+(?:cannot|can\s+not|must\s+not|shall\s+not)\s+be\s+(?:bypassed|disabled|skipped|turned\s+off|deactivated)\b|"
    r"\b(?:bypassing|disabling|skipping)\s+(?:security\s+(?:checks?|validation|policy)|verification)\s+(?:is|must\s+be|shall\s+be)?\s*(?:forbidden|prohibited|blocked|rejected|disallowed|prevented|refused|not\s+allowed)\b|"
    r"\b(?:never|do\s+not|don't|must\s+not|shall\s+not|cannot|can\s+not)\s+(?:bypass|disable|skip|deactivate|turn\s+off)\s+(?:security\s+(?:checks?|validation|policy)|deterministic\s+verification|verification)\b|"
    r"\b(?:detect|catch|trap|prevent|block|forbid|prohibit|disallow)\s+(?:any\s+)?(?:attempts?\s+to\s+)?(?:bypass|disable|skip|deactivate)\s+(?:security\s+(?:checks?|validation|policy)|verification)\b|"
    r"\b(?:assert|ensure|verify|check|test)\s+that\s+(?:security\s+(?:checks?|validation|policy)|verification)\s+(?:cannot\s+be|must\s+not\s+be|is\s+not)\s+(?:bypassed|disabled|skipped)\b",
    re.IGNORECASE,
)


def _is_defensive_verification_bypass(text: str) -> bool:
    """Return True if text deterministically negates or prohibits
    verification or security check bypass.
    """
    if _INVERTED_DEFENSIVE_PATTERN.search(text):
        return False
    return bool(_DEFENSIVE_VERIFICATION_BYPASS_PATTERN.search(text))


# Rule 5: Destructive command execution defensive patterns
_DEFENSIVE_DESTRUCTIVE_EXEC_PATTERN = re.compile(
    r"\brm\s+-rf\s+[/~]\s+(?:must\s+never|shall\s+never|cannot|can\s+not|must\s+not|shall\s+not|is\s+never)\s+be\s+(?:executed|run|called)\b|"
    r"\b(?:execution|running)\s+of\s+rm\s+-rf\s+[/~]\s+(?:is|must\s+be|shall\s+be)?\s*(?:blocked|rejected|forbidden|prohibited|disallowed|prevented|refused|not\s+allowed)\b|"
    r"\b(?:never|do\s+not|don't|must\s+not|shall\s+not|cannot|can\s+not)\s+(?:run|execute|call)\s+rm\s+-rf\s+[/~]\b|"
    r"\b(?:test|prove|proving|ensure|assert|verify|check)\s+(?:that\s+)?rm\s+-rf\s+[/~]\s+(?:is\s+(?:rejected|blocked|forbidden|prevented|refused)|fails|cannot\s+be\s+run|cannot\s+be\s+executed)\b|"
    r"\b(?:prevent|block|forbid|prohibit|disallow|reject|intercept|detect)\s+(?:any\s+)?(?:executions?\s+of|running\s+of|attempts?\s+to\s+run)\s+rm\s+-rf\s+[/~]\b",
    re.IGNORECASE,
)


def _is_defensive_destructive_exec(text: str) -> bool:
    """Return True if text deterministically negates or prohibits destructive execution."""
    if _INVERTED_DEFENSIVE_PATTERN.search(text):
        return False
    return bool(_DEFENSIVE_DESTRUCTIVE_EXEC_PATTERN.search(text))


# General behavior preservation patterns (for REFACTOR / PERFORMANCE contradictions)
_DEFENSIVE_BEHAVIOR_PRESERVATION_PATTERN = re.compile(
    r"\b(?:never|do\s+not|don't|must\s+not|shall\s+not|cannot|can\s+not)\s+"
    r"(?:change|modify|alter|break|introduce)\b|"
    r"\b(?:ensure|assert|verify|check)\s+that\s+.*?\b(?:is\s+not\s+(?:changed|altered|broken)|remains\s+unchanged)\b",
    re.IGNORECASE,
)


def _is_defensive_behavior_preservation(text: str) -> bool:
    """Return True if text deterministically expresses preservation of existing behavior."""
    if _INVERTED_DEFENSIVE_PATTERN.search(text):
        return False
    return bool(_DEFENSIVE_BEHAVIOR_PRESERVATION_PATTERN.search(text))


def _is_defensively_constrained(text: str) -> bool:
    """Return True if text deterministically expresses that a forbidden or dangerous action
    must be blocked, rejected, prevented, forbidden, impossible, redacted,
    not executed, not exposed, or otherwise negatively constrained.
    """
    if _INVERTED_DEFENSIVE_PATTERN.search(text):
        return False
    return (
        _is_defensive_test_weaken(text)
        or _is_defensive_protected_mutation(text)
        or _is_defensive_secret_exfil(text)
        or _is_defensive_verification_bypass(text)
        or _is_defensive_destructive_exec(text)
        or _is_defensive_behavior_preservation(text)
    )


def _is_protective_or_testing_statement(text: str) -> bool:
    """Backward-compatible alias for _is_defensively_constrained."""
    return _is_defensively_constrained(text)


# --- Protected Surface Mutation & Path Extraction (Blocker 2 & 3) ---

_MUTATION_VERBS = frozenset(
    {
        "modify",
        "modifying",
        "modification",
        "edit",
        "editing",
        "update",
        "updating",
        "change",
        "changing",
        "delete",
        "deleting",
        "deletion",
        "remove",
        "removing",
        "removal",
        "overwrite",
        "overwriting",
        "patch",
        "patching",
        "mutate",
        "mutating",
        "mutation",
        "rewrite",
        "rewriting",
        "alter",
        "altering",
        "truncate",
        "truncating",
        "wipe",
        "wiping",
    }
)

_CONCEPTUAL_PROTECTED_MUTATION = re.compile(
    r"\b(?:modify|edit|update|change|delete|remove|overwrite|patch|mutate|rewrite|alter)\s+"
    r"(?:a|an|the|any)?\s*(?:canonical\s+)?protected\s+(?:workflow|surface|file|manifest|governance|policy)\b",
    re.IGNORECASE,
)

_REPO_PATH_CANDIDATE_PATTERN = re.compile(
    r"(?:(?<=\s)|^|['\"`(\[])(?:(?:\.\./)+[A-Za-z0-9_.\-/]+|[A-Za-z0-9_.\-]+/[A-Za-z0-9_.\-/]+|[A-Za-z0-9_\-]+\.[A-Za-z0-9]+)\b"
)


def _extract_repo_path_candidates(text: str) -> list[str]:
    """Extract repository path candidate strings from text.

    Identifies tokens containing slashes, directory traversals ('..'),
    standard repository directories, or file extensions.
    """
    candidates: list[str] = []
    for match in _REPO_PATH_CANDIDATE_PATTERN.finditer(text):
        token = match.group(0).strip(" \t\r\n'\"`.,;:!?)(")
        # Skip API endpoints and URLs
        if token.startswith("/") or "://" in token:
            continue
        # Skip numeric decimals like 1.0 or 3.11
        if re.match(r"^\d+\.\d+$", token):
            continue
        candidates.append(token)
    return candidates


def _demands_mutation_of_path(statement: str, path_token: str, norm_path: str) -> bool:
    """Return True if statement deterministically demands mutation directed at path_token."""
    clean_stmt = statement.strip()
    pattern = re.escape(path_token)
    matches = list(re.finditer(pattern, clean_stmt, re.IGNORECASE))
    if not matches and norm_path != path_token:
        pattern = re.escape(norm_path)
        matches = list(re.finditer(pattern, clean_stmt, re.IGNORECASE))

    for m in matches:
        start_idx = m.start()
        end_idx = m.end()

        # Check preceding text (up to 8 words)
        preceding = clean_stmt[:start_idx].strip()
        prec_tokens = re.findall(r"\b[a-zA-Z_\-]+\b", preceding)
        if prec_tokens:
            noise_words = {
                "the",
                "a",
                "an",
                "this",
                "that",
                "file",
                "files",
                "directory",
                "path",
                "surface",
                "protected",
                "canonical",
                "in",
                "at",
                "to",
            }
            for token in reversed(prec_tokens[-6:]):
                t_lower = token.lower()
                if t_lower in _MUTATION_VERBS:
                    return True
                if t_lower not in noise_words:
                    break

        # Check following text (passive mutation: "AGENTS.md must be modified")
        following = clean_stmt[end_idx:].strip()
        if re.search(
            r"^\s*(?:must\s+be|should\s+be|shall\s+be|is\s+to\s+be|is|was|to\s+be)\s*"
            r"(?:modified|edited|updated|changed|deleted|removed|overwritten|patched|mutated|rewritten|altered|truncated)\b",
            following,
            re.IGNORECASE,
        ):
            return True

    return False


# --- Forbidden Action Validation ---

_FORBIDDEN_TEST_WEAKEN = re.compile(
    r"\b(?:(?:delete|deleting|remove|removing|drop|dropping|strip|stripping|commenting\s+out|comment\s+out)\s+(?:failing\s+)?(?:tests?|assertions?)|"
    r"(?:weaken|weakening|relax|relaxing|disable|disabling|bypass|bypassing|ignore|ignoring)\s+(?:failing\s+)?(?:test\s+assertions?|assertions?|tests?)|"
    r"(?:make|get)\s+tests?\s+green\s+by\s+(?:removing|deleting|weakening|disabling)|"
    r"bypass\s+test\s+failures|"
    r"ignore\s+(?:failing\s+tests?|test\s+failures))\b",
    re.IGNORECASE,
)

_FORBIDDEN_SECRET_EXFIL = re.compile(
    r"\b(?:(?:send|sending|exfiltrate|exfiltrating|leak|leaking|post|posting|upload|uploading|transmit|transmitting)\s+.*?(?:api[_\-\s]?keys?|secrets?|credentials?|tokens?|private[_\-\s]?keys?)\s+to\s+|"
    r"(?:api[_\-\s]?keys?|secrets?|credentials?|tokens?|private[_\-\s]?keys?)\s+.*?(?:are|is|get|were|being)?\s*(?:uploaded|sent|exfiltrated|leaked|posted|transmitted)\s+to\s+|"
    r"(?:print|log|dump|display|output)\s+.*(?:api[_\-\s]?keys?|secrets?|credentials?|tokens?|private[_\-\s]?keys?)\s+to\s+(?:stdout|console|log|file)|"
    r"exfiltrate\s+(?:secrets?|credentials?|keys?|tokens?))\b",
    re.IGNORECASE,
)

_FORBIDDEN_VERIFICATION_BYPASS = re.compile(
    r"\b(?:(?:disable|disabling|turn\s+off|turning\s+off|bypass|bypassing|skip|skipping|deactivate|deactivating)\s+(?:required\s+)?(?:deterministic\s+)?verification|"
    r"(?:disable|disabling|bypass|bypassing|skip|skipping)\s+security\s+(?:checks?|validation|policy)|"
    r"security\s+(?:checks?|validation|policy)\s+(?:can\s+be|are|is|to\s+be|could\s+be)?\s*bypassed|"
    r"(?:deterministic\s+)?verification\s+(?:can\s+be|is|are|to\s+be)?\s*(?:bypassed|disabled|skipped)|"
    r"(?:bypass|bypassing|disable|disabling)\s+contract\s+validation)\b",
    re.IGNORECASE,
)

_FORBIDDEN_DESTRUCTIVE_EXEC = re.compile(
    r"\b(?:(?:run|running|execute|execution\s+of|executing|call|calling)\s+rm\s+-rf\s+[/~]|"
    r"(?:wipe|format|destroy)\s+(?:disk|filesystem|root|database)|"
    r"rm\s+-rf\s+[/~])",
    re.IGNORECASE,
)


def _check_forbidden_actions(req: ValidatedRequirement, manifest: ProtectedSurfaceManifest) -> None:
    """Validate a single requirement against forbidden action rules.

    Rules:
    FORBIDDEN-001: Test weakening / deletion
    FORBIDDEN-002: Protected surface mutation (canonical manifest authority)
    FORBIDDEN-003: Credential / secret exfiltration
    FORBIDDEN-004: Verification / security check bypass
    FORBIDDEN-005: Destructive command execution
    """
    statement = req.statement

    # Check rule 1: Test weakening
    if _FORBIDDEN_TEST_WEAKEN.search(statement):
        if not _is_defensive_test_weaken(statement):
            raise ForbiddenActionViolationError(
                rule_id="FORBIDDEN-001",
                requirement_id=req.requirement_id,
                detail=f"Requirement demands weakening or deleting tests to pass: {statement}",
            )

    # Check rule 2: Protected surface mutation
    # A. Conceptual protected surface mutation
    if _CONCEPTUAL_PROTECTED_MUTATION.search(statement):
        if not _is_defensive_protected_mutation(statement):
            raise ForbiddenActionViolationError(
                rule_id="FORBIDDEN-002",
                requirement_id=req.requirement_id,
                detail=f"Requirement demands mutation of canonical protected surface: {statement}",
            )

    # B. Canonical manifest authority check
    candidates = _extract_repo_path_candidates(statement)
    for cand in candidates:
        clean_cand = cand.strip(" \t\r\n'\"`.,;:!?)(")
        if not clean_cand:
            continue
        try:
            norm_path = normalize_repo_path(clean_cand)
            match = match_protected_surface(norm_path, manifest)
            if match is not None:
                # Fact A: path is protected by manifest.
                # Fact B: Does the requirement demand mutation of this path?
                if _demands_mutation_of_path(statement, clean_cand, norm_path):
                    if not _is_defensive_protected_mutation(statement):
                        raise ForbiddenActionViolationError(
                            rule_id="FORBIDDEN-002",
                            requirement_id=req.requirement_id,
                            detail=(
                                f"Requirement demands mutation of protected repository surface "
                                f"'{norm_path}': {statement}"
                            ),
                        )
        except PathSecurityError:
            # Traversal or invalid path candidate
            if _demands_mutation_of_path(statement, clean_cand, clean_cand):
                if not _is_defensive_protected_mutation(statement):
                    raise ForbiddenActionViolationError(
                        rule_id="FORBIDDEN-002",
                        requirement_id=req.requirement_id,
                        detail=(
                            f"Requirement demands mutation of unsafe or traversal repository path "
                            f"'{clean_cand}': {statement}"
                        ),
                    )

    # Check rule 3: Credential / secret exfiltration
    if _FORBIDDEN_SECRET_EXFIL.search(statement):
        if not _is_defensive_secret_exfil(statement):
            raise ForbiddenActionViolationError(
                rule_id="FORBIDDEN-003",
                requirement_id=req.requirement_id,
                detail=f"Requirement demands credential or secret exfiltration: {statement}",
            )

    # Check rule 4: Disabling deterministic verification
    if _FORBIDDEN_VERIFICATION_BYPASS.search(statement):
        if not _is_defensive_verification_bypass(statement):
            raise ForbiddenActionViolationError(
                rule_id="FORBIDDEN-004",
                requirement_id=req.requirement_id,
                detail=(
                    "Requirement demands bypassing or disabling deterministic verification: "
                    f"{statement}"
                ),
            )

    # Check rule 5: Destructive command execution
    if _FORBIDDEN_DESTRUCTIVE_EXEC.search(statement):
        if not _is_defensive_destructive_exec(statement):
            raise ForbiddenActionViolationError(
                rule_id="FORBIDDEN-005",
                requirement_id=req.requirement_id,
                detail=f"Requirement demands destructive execution: {statement}",
            )


# --- Contradiction Detection ---

# Retry patterns
_RETRY_POSITIVE_PATTERN = re.compile(
    r"\b(?:always\s+)?retry\s+(?:on|for|when)?\s*([a-zA-Z0-9_\-\s]+)",
    re.IGNORECASE,
)
_RETRY_NEGATIVE_PATTERN = re.compile(
    r"\b(?:do\s+not|don't|never|must\s+not)\s+retry\s+(?:on|for|when)?\s*([a-zA-Z0-9_\-\s]+)",
    re.IGNORECASE,
)

# HTTP status patterns
_HTTP_STATUS_P1 = re.compile(
    r"\b(?:return|respond\s+with|send|status\s+(?:code\s+)?(?:is\s+)?)\s*(?:HTTP\s+)?(\d{3})\s+(?:on|for|when|if)\s+([^.,;]+)",
    re.IGNORECASE,
)
_HTTP_STATUS_P2 = re.compile(
    r"\b(?:on|for|when|if)\s+([^.,;]+)[,:]\s*(?:return|respond\s+with|send|status\s+(?:code\s+)?(?:is\s+)?)\s*(?:HTTP\s+)?(\d{3})",
    re.IGNORECASE,
)

# Auth patterns
_AUTH_REQUIRED = re.compile(
    r"\b(?:require|mandate|enforce)\s+(?:auth|authentication|login)\s+(?:for|on)\s+([/\w\-]+)",
    re.IGNORECASE,
)
_AUTH_ANONYMOUS = re.compile(
    r"\b(?:allow|permit)\s+(?:anonymous|unauthenticated|guest)\s+(?:access\s+)?(?:for|on|to)\s+([/\w\-]+)",
    re.IGNORECASE,
)

# Cache patterns
_CACHE_ENABLE = re.compile(
    r"\b(?:enable|allow|use)\s+caching\s+(?:for|on)\s+([/\w\-\s]+)",
    re.IGNORECASE,
)
_CACHE_DISABLE = re.compile(
    r"\b(?:disable|forbid|prevent|do\s+not\s+allow)\s+caching\s+(?:for|on)\s+([/\w\-\s]+)",
    re.IGNORECASE,
)

# ChangeClass refactor / performance laws
_REFACTOR_BEHAVIOR_CHANGE = re.compile(
    r"\b(?:change|modify|alter|break)\s+(?:external\s+behavior|public\s+api|endpoint\s+contract|api\s+response\s+format|return\s+type)\b|"
    r"\b(?:add|introduce)\s+(?:breaking\s+changes?|new\s+endpoints?|new\s+features?)\b",
    re.IGNORECASE,
)

_PERFORMANCE_OUTPUT_CHANGE = re.compile(
    r"\b(?:change|modify|alter)\s+(?:functional\s+output|calculation\s+results?|business\s+logic\s+results?|output\s+format)\b",
    re.IGNORECASE,
)


def _normalize_condition(cond: str) -> str:
    """Normalize trigger/scope condition text for deterministic comparison."""
    # Lowercase, strip, remove leading noise words
    c = cond.lower().strip()
    c = re.sub(r"^(?:on|for|when|if|the|a|an|all|any)\s+", "", c)
    c = re.sub(r"\s+", " ", c)
    return c.strip(" .;,")


def _check_contradictions(
    requirements: Sequence[ValidatedRequirement],
    change_class: ChangeClass | None,
) -> None:
    """Evaluate pairwise and semantic contradictions across validated requirements."""
    # 1. Pairwise contradiction checks
    for i, req_a in enumerate(requirements):
        stmt_a = req_a.statement

        # Retry check
        pos_match = _RETRY_POSITIVE_PATTERN.search(stmt_a)
        # HTTP status check
        http_m1 = _HTTP_STATUS_P1.search(stmt_a)
        http_m2 = _HTTP_STATUS_P2.search(stmt_a)
        status_a = (
            int(http_m1.group(1)) if http_m1 else (int(http_m2.group(2)) if http_m2 else None)
        )
        cond_a = _normalize_condition(
            http_m1.group(2) if http_m1 else (http_m2.group(1) if http_m2 else "")
        )

        # Auth check
        auth_req_m = _AUTH_REQUIRED.search(stmt_a)
        # Cache check
        cache_en_m = _CACHE_ENABLE.search(stmt_a)

        for j in range(i + 1, len(requirements)):
            req_b = requirements[j]
            stmt_b = req_b.statement

            # CONTRADICTION-RETRY
            if pos_match:
                neg_match = _RETRY_NEGATIVE_PATTERN.search(stmt_b)
                if neg_match:
                    cond_pos = _normalize_condition(pos_match.group(1))
                    cond_neg = _normalize_condition(neg_match.group(1))
                    if cond_pos and cond_neg and cond_pos == cond_neg:
                        raise ContradictoryRequirementsError(
                            rule_id="CONTRADICTION-RETRY",
                            req_id_a=req_a.requirement_id,
                            req_id_b=req_b.requirement_id,
                            detail=(
                                f"Requirement {req_a.requirement_id!r} demands retry on "
                                f"{cond_pos!r} while {req_b.requirement_id!r} forbids it"
                            ),
                        )

            # Check symmetric negative on A, positive on B
            neg_match_a = _RETRY_NEGATIVE_PATTERN.search(stmt_a)
            if neg_match_a:
                pos_match_b = _RETRY_POSITIVE_PATTERN.search(stmt_b)
                if pos_match_b:
                    cond_neg = _normalize_condition(neg_match_a.group(1))
                    cond_pos = _normalize_condition(pos_match_b.group(1))
                    if cond_neg and cond_pos and cond_neg == cond_pos:
                        raise ContradictoryRequirementsError(
                            rule_id="CONTRADICTION-RETRY",
                            req_id_a=req_a.requirement_id,
                            req_id_b=req_b.requirement_id,
                            detail=(
                                f"Requirement {req_a.requirement_id!r} forbids retry on "
                                f"{cond_neg!r} while {req_b.requirement_id!r} demands it"
                            ),
                        )

            # CONTRADICTION-HTTP-STATUS
            if status_a is not None and cond_a:
                http_b1 = _HTTP_STATUS_P1.search(stmt_b)
                http_b2 = _HTTP_STATUS_P2.search(stmt_b)
                status_b = (
                    int(http_b1.group(1))
                    if http_b1
                    else (int(http_b2.group(2)) if http_b2 else None)
                )
                cond_b = _normalize_condition(
                    http_b1.group(2) if http_b1 else (http_b2.group(1) if http_b2 else "")
                )
                if status_b is not None and cond_b and cond_a == cond_b and status_a != status_b:
                    raise ContradictoryRequirementsError(
                        rule_id="CONTRADICTION-HTTP-STATUS",
                        req_id_a=req_a.requirement_id,
                        req_id_b=req_b.requirement_id,
                        detail=(
                            f"Conflicting HTTP status codes for condition {cond_a!r}: "
                            f"{status_a} vs {status_b}"
                        ),
                    )

            # CONTRADICTION-AUTH
            if auth_req_m:
                scope_a = _normalize_condition(auth_req_m.group(1))
                auth_anon_b = _AUTH_ANONYMOUS.search(stmt_b)
                if auth_anon_b:
                    scope_b = _normalize_condition(auth_anon_b.group(1))
                    if scope_a and scope_b and scope_a == scope_b:
                        raise ContradictoryRequirementsError(
                            rule_id="CONTRADICTION-AUTH",
                            req_id_a=req_a.requirement_id,
                            req_id_b=req_b.requirement_id,
                            detail=(
                                f"Requirement {req_a.requirement_id!r} mandates auth "
                                f"on {scope_a!r} while {req_b.requirement_id!r} "
                                f"permits anonymous access"
                            ),
                        )

            auth_anon_a = _AUTH_ANONYMOUS.search(stmt_a)
            if auth_anon_a:
                scope_a = _normalize_condition(auth_anon_a.group(1))
                auth_req_b = _AUTH_REQUIRED.search(stmt_b)
                if auth_req_b:
                    scope_b = _normalize_condition(auth_req_b.group(1))
                    if scope_a and scope_b and scope_a == scope_b:
                        raise ContradictoryRequirementsError(
                            rule_id="CONTRADICTION-AUTH",
                            req_id_a=req_a.requirement_id,
                            req_id_b=req_b.requirement_id,
                            detail=(
                                f"Requirement {req_a.requirement_id!r} permits anonymous access on "
                                f"{scope_a!r} while {req_b.requirement_id!r} mandates auth"
                            ),
                        )

            # CONTRADICTION-CACHE
            if cache_en_m:
                scope_a = _normalize_condition(cache_en_m.group(1))
                cache_dis_b = _CACHE_DISABLE.search(stmt_b)
                if cache_dis_b:
                    scope_b = _normalize_condition(cache_dis_b.group(1))
                    if scope_a and scope_b and scope_a == scope_b:
                        raise ContradictoryRequirementsError(
                            rule_id="CONTRADICTION-CACHE",
                            req_id_a=req_a.requirement_id,
                            req_id_b=req_b.requirement_id,
                            detail=(
                                f"Requirement {req_a.requirement_id!r} enables caching on "
                                f"{scope_a!r} while {req_b.requirement_id!r} disables it"
                            ),
                        )

            cache_dis_a = _CACHE_DISABLE.search(stmt_a)
            if cache_dis_a:
                scope_a = _normalize_condition(cache_dis_a.group(1))
                cache_en_b = _CACHE_ENABLE.search(stmt_b)
                if cache_en_b:
                    scope_b = _normalize_condition(cache_en_b.group(1))
                    if scope_a and scope_b and scope_a == scope_b:
                        raise ContradictoryRequirementsError(
                            rule_id="CONTRADICTION-CACHE",
                            req_id_a=req_a.requirement_id,
                            req_id_b=req_b.requirement_id,
                            detail=(
                                f"Requirement {req_a.requirement_id!r} disables caching on "
                                f"{scope_a!r} while {req_b.requirement_id!r} enables it"
                            ),
                        )

    # 2. Contradiction against ChangeClass causal verification laws
    if change_class == ChangeClass.REFACTOR:
        for req in requirements:
            if not _is_defensive_behavior_preservation(req.statement):
                if _REFACTOR_BEHAVIOR_CHANGE.search(req.statement):
                    raise ContradictoryRequirementsError(
                        rule_id="CONTRADICTION-REFACTOR-BEHAVIOR",
                        req_id_a=req.requirement_id,
                        req_id_b="ChangeClass.REFACTOR",
                        detail=(
                            f"Requirement {req.requirement_id!r} demands external behavior "
                            f"change which contradicts REFACTOR equivalence law: {req.statement}"
                        ),
                    )

    elif change_class == ChangeClass.PERFORMANCE:
        for req in requirements:
            if not _is_defensive_behavior_preservation(req.statement):
                if _PERFORMANCE_OUTPUT_CHANGE.search(req.statement):
                    raise ContradictoryRequirementsError(
                        rule_id="CONTRADICTION-PERFORMANCE-OUTPUT",
                        req_id_a=req.requirement_id,
                        req_id_b="ChangeClass.PERFORMANCE",
                        detail=(
                            f"Requirement {req.requirement_id!r} demands altering functional "
                            f"output which contradicts PERFORMANCE parity law: {req.statement}"
                        ),
                    )


# --- Scope Validation ---

# Explicit Scope Syntax Patterns (Blocker 4)
# 1. API / endpoint path syntax: e.g. /api/catalog, /api/admin, /v1/checkout, /health
_API_ENDPOINT_PATTERN = re.compile(
    r"(?<![a-zA-Z0-9_\-\.])/(?:[a-zA-Z0-9_\-]+(?:/[a-zA-Z0-9_\-]+)*)"
)

# 2. Repository path token syntax: e.g. src/..., docs/..., AGENTS.md, foo/../../ci.yml
_REPO_PATH_TOKEN_PATTERN = re.compile(
    r"(?:(?<=\s)|^|['\"`(\[])(?:(?:\.\./)+[a-zA-Z0-9_.\-/]+|(?:src|docs|plans|tests|\.github)/[a-zA-Z0-9_.\-/]+|"
    r"[a-zA-Z0-9_.\-]+/[a-zA-Z0-9_.\-/]+\.[a-zA-Z0-9]+|"
    r"[a-zA-Z0-9_\-]+\.(?:md|py|toml|json|ya?ml|txt|sh|rs|ts|js|go|c|h|cpp)|"
    r"Makefile|Dockerfile)\b",
    re.IGNORECASE,
)


def _extract_explicit_scopes(text: str) -> tuple[tuple[str, ...], tuple[str, ...]]:
    r"""Extract deterministically identifiable explicit scopes from text.

    Supported explicit scope syntaxes:
    1. API / endpoint paths: e.g. /api/catalog, /api/admin, /v1/users, /health
       Syntax: /(?:[a-zA-Z0-9_\-]+(?:/[a-zA-Z0-9_\-]+)*)
    2. Repository-relative paths: e.g. src/..., docs/..., AGENTS.md, tests/...
       Syntax: Paths rooted at standard repository directories or files with extensions.
    """
    clean = text.strip()
    endpoints: list[str] = []
    for m in _API_ENDPOINT_PATTERN.finditer(clean):
        ep = m.group(0).rstrip(".,;:!?)(")
        # Ignore bare root slash or malformed
        if len(ep) > 1 and not ep.endswith("/"):
            endpoints.append(ep)

    repo_paths: list[str] = []
    for m in _REPO_PATH_TOKEN_PATTERN.finditer(clean):
        rp = m.group(0).rstrip(".,;:!?)(")
        if rp and not rp.startswith("/"):
            repo_paths.append(rp)

    return tuple(endpoints), tuple(repo_paths)


def _validate_scope(
    req: ValidatedRequirement,
    task: NormalizedTask,
    manifest: ProtectedSurfaceManifest,
) -> None:
    """Validate requirement scope deterministically against task text and protected surfaces.

    Deterministic Scope Rules:
    1. Exact citation span and content support in normalized task text.
    2. Explicit endpoint scope consistency: If citation explicitly scopes the
       requirement to an explicit target (e.g. /api/catalog) and the statement introduces
       or substitutes a conflicting explicit target (e.g. /api/admin), fail closed with
       UnsupportedScopeError.
    3. Explicit repository path scope consistency (Blocker 2): If citation contains one
       or more explicit repo-path scopes, every explicit repo path introduced by the
       requirement statement must be supported by that citation. If citation lacks repo
       paths, any statement repo path must be supported somewhere in normalized task text.
    4. Path security fail-closed: If any repository path candidate is unsafe
       or attempts directory traversal, fail closed with UnsupportedScopeError without
       swallowing.
    5. Protected surface modification boundary: Reject any requirement
       demanding mutation of protected surfaces.
    """
    # 1. Exact citation span and content support in normalized task text
    if not (0 <= req.citation_start <= req.citation_end <= len(task.normalized_text)):
        raise InvalidCitationError(
            f"Citation span [{req.citation_start}:{req.citation_end}] "
            f"exceeds task bounds [0:{len(task.normalized_text)}]"
        )
    slice_text = task.normalized_text[req.citation_start : req.citation_end]
    if slice_text != req.citation:
        raise InvalidCitationError(
            f"Citation mismatch at span [{req.citation_start}:{req.citation_end}]: "
            f"expected {req.citation!r}, got {slice_text!r}"
        )

    # 2. Explicit scope extraction and alignment
    stmt_endpoints, stmt_repo_paths = _extract_explicit_scopes(req.statement)
    cit_endpoints, cit_repo_paths = _extract_explicit_scopes(req.citation)
    task_endpoints, task_repo_paths = _extract_explicit_scopes(task.normalized_text)

    # Endpoint scope validation:
    if stmt_endpoints:
        for ep in stmt_endpoints:
            # If citation has explicit endpoint scopes, statement must match one of them
            if cit_endpoints and ep not in cit_endpoints:
                raise UnsupportedScopeError(
                    f"Requirement {req.requirement_id!r} introduces explicit endpoint scope "
                    f"{ep!r} which conflicts with citation scope {cit_endpoints!r}"
                )
            # Statement endpoint must be supported in task text
            if ep not in task_endpoints and ep not in task.normalized_text:
                raise UnsupportedScopeError(
                    f"Requirement {req.requirement_id!r} introduces explicit endpoint scope "
                    f"{ep!r} not supported by task text"
                )

    # Repository path scope validation:
    # A. Unsafe / traversal candidate check across statement candidates
    all_path_candidates = _extract_repo_path_candidates(req.statement)
    for token in all_path_candidates:
        clean_token = token.strip(" \t\r\n'\"`.,;:!?)(")
        if not clean_token:
            continue
        try:
            norm_path = normalize_repo_path(clean_token)
        except PathSecurityError as exc:
            # Blocker 3: FAIL CLOSED. Never swallow PathSecurityError!
            raise UnsupportedScopeError(
                f"Requirement {req.requirement_id!r} contains unsafe or traversal repository "
                f"path candidate: {redact_log_text(str(exc))}"
            ) from None

        # Check if normalized path is protected
        match = match_protected_surface(norm_path, manifest)
        if match is not None:
            if not _is_defensive_protected_mutation(req.statement):
                if _demands_mutation_of_path(req.statement, clean_token, norm_path):
                    raise ForbiddenActionViolationError(
                        rule_id="FORBIDDEN-002",
                        requirement_id=req.requirement_id,
                        detail=(
                            f"Requirement {req.requirement_id!r} demands mutation of protected "
                            f"surface '{norm_path}': {req.statement}"
                        ),
                    )

    # B. Explicit repository path scope alignment (Blocker 2)
    norm_cit_repo_paths: set[str] = set()
    for rp in cit_repo_paths:
        try:
            norm_cit_repo_paths.add(normalize_repo_path(rp))
        except PathSecurityError as exc:
            raise UnsupportedScopeError(
                f"Citation contains unsafe or traversal repository path candidate: "
                f"{redact_log_text(str(exc))}"
            ) from None

    norm_task_repo_paths: set[str] = set()
    for rp in task_repo_paths:
        try:
            norm_task_repo_paths.add(normalize_repo_path(rp))
        except PathSecurityError:
            pass

    if stmt_repo_paths:
        for rp in stmt_repo_paths:
            try:
                norm_rp = normalize_repo_path(rp)
            except PathSecurityError as exc:
                raise UnsupportedScopeError(
                    f"Requirement {req.requirement_id!r} contains unsafe or traversal repository "
                    f"path candidate: {redact_log_text(str(exc))}"
                ) from None

            if norm_cit_repo_paths:
                # If citation contains one or more explicit repo-path scopes, every explicit
                # repo path introduced by requirement statement must be in that citation.
                if norm_rp not in norm_cit_repo_paths:
                    raise UnsupportedScopeError(
                        f"Requirement {req.requirement_id!r} introduces explicit repository "
                        f"path scope {norm_rp!r} which conflicts with citation scope "
                        f"{sorted(norm_cit_repo_paths)!r}"
                    )
            else:
                # Citation itself has no repo-path token:
                # Require any statement repo path not present in citation to at least be
                # explicitly supported somewhere in normalized task text.
                if (
                    norm_rp not in norm_task_repo_paths
                    and rp not in task.normalized_text
                    and norm_rp not in task.normalized_text
                ):
                    raise UnsupportedScopeError(
                        f"Requirement {req.requirement_id!r} introduces explicit repository "
                        f"path scope {norm_rp!r} not supported by task text"
                    )


# --- Main Validation Function ---


def validate_contract(
    task: NormalizedTask,
    requirements: Sequence[ProposedRequirement | ValidatedRequirement | Mapping[str, Any]],
    change_class: ChangeClass | ChangeSemanticsClassification | str | None = None,
    allow_derivation: bool = True,
    manifest: ProtectedSurfaceManifest | None = None,
) -> ValidatedContract:
    """Deterministically validate requirement IDs, scope, forbidden actions, and contradictions.

    Authority Law: Model authority = ZERO.
    Provider Neutrality: ZERO provider/adapter imports, ZERO model calls.
    ABSOLUTE P-06.06 BOUNDARY: Zero contract/validation/frozen digest computation.

    Args:
        task: NormalizedTask object from P-06.01.
        requirements: Sequence of ProposedRequirement, ValidatedRequirement, or raw dictionaries.
        change_class: Canonical ChangeClass, ChangeSemanticsClassification, string, or None.
        allow_derivation: If True, derive requirement IDs using content-addressed hash.
                          If False, require explicit valid requirement_id on all items.
        manifest: ProtectedSurfaceManifest to enforce (defaults to canonical Basebreak manifest).

    Returns:
        ValidatedContract object representing the verified contract draft.
    """
    # 1. Validate task input
    if not isinstance(task, NormalizedTask):
        raise TypeError(f"task must be NormalizedTask, got {type(task).__name__}")

    # 2. Validate requirements sequence
    if not isinstance(requirements, Sequence) or isinstance(requirements, (str, bytes)):
        raise TypeError(f"requirements must be a sequence, got {type(requirements).__name__}")

    if not (MIN_REQUIREMENTS_COUNT <= len(requirements) <= MAX_REQUIREMENTS_COUNT):
        raise RequirementCountLimitExceededError(
            f"Requirements count ({len(requirements)}) outside allowable bounds "
            f"[{MIN_REQUIREMENTS_COUNT}:{MAX_REQUIREMENTS_COUNT}]"
        )

    active_manifest = (
        manifest if manifest is not None else get_canonical_basebreak_protected_manifest()
    )

    # 3. Resolve change class and certainty
    resolved_class: ChangeClass | None = None
    resolved_certainty: CertaintyLevel | None = None

    if isinstance(change_class, ChangeSemanticsClassification):
        # Blocker 5: AMBIGUOUS and UNKNOWN must fail closed!
        if change_class.certainty in (CertaintyLevel.AMBIGUOUS, CertaintyLevel.UNKNOWN):
            raise UnresolvedChangeClassError(
                f"Change semantics classification certainty is {change_class.certainty.value!r}; "
                "cannot validate contract with unresolved change semantics"
            )
        if change_class.change_class is None:
            raise UnresolvedChangeClassError(
                "Change semantics classification lacks authoritative change_class"
            )
        resolved_class = change_class.change_class
        resolved_certainty = change_class.certainty
    elif isinstance(change_class, ChangeClass):
        resolved_class = change_class
        resolved_certainty = CertaintyLevel.CONFIDENT
    elif isinstance(change_class, str):
        try:
            resolved_class = ChangeClass(change_class)
            resolved_certainty = CertaintyLevel.CONFIDENT
        except ValueError:
            raise ValueError(f"Invalid ChangeClass string: {change_class!r}") from None
    elif change_class is None:
        # Component-level class-neutral validation mode.
        # NOTE: change_class=None does NOT represent a resolved P-06 verification contract
        # and must not be used to bypass P-06.03 semantics resolution.
        resolved_class = None
        resolved_certainty = None
    else:
        raise TypeError(
            "change_class must be ChangeClass, ChangeSemanticsClassification, str, or None, "
            f"got {type(change_class).__name__}"
        )

    # 4. Parse and normalize each requirement into ValidatedRequirement
    validated_reqs: list[ValidatedRequirement] = []
    seen_ids: dict[str, tuple[str, str, int, int]] = {}

    for idx, item in enumerate(requirements):
        req_id: str | None = None
        stmt: str
        cit: str
        c_start: int
        c_end: int
        rat: str = ""

        if isinstance(item, ValidatedRequirement):
            req_id = item.requirement_id
            stmt = item.statement
            cit = item.citation
            c_start = item.citation_start
            c_end = item.citation_end
            rat = item.rationale

        elif isinstance(item, ProposedRequirement):
            stmt = item.statement
            cit = item.citation
            c_start = item.citation_start
            c_end = item.citation_end
            rat = item.rationale
            if allow_derivation:
                req_id = derive_requirement_id(stmt, cit, c_start, c_end)
            else:
                raise MissingRequirementIdError(
                    f"Requirement at index {idx} lacks requirement_id and derivation is disabled"
                )

        elif isinstance(item, Mapping):
            raw_id = item.get("requirement_id")
            raw_stmt = item.get("statement")
            raw_cit = item.get("citation")
            raw_start = item.get("citation_start")
            raw_end = item.get("citation_end")
            raw_rat = item.get("rationale", "")

            if not isinstance(raw_stmt, str):
                raise TypeError(
                    f"statement at index {idx} must be str, got {type(raw_stmt).__name__}"
                )
            if not isinstance(raw_cit, str):
                raise TypeError(
                    f"citation at index {idx} must be str, got {type(raw_cit).__name__}"
                )
            if isinstance(raw_start, bool) or not isinstance(raw_start, int):
                raise TypeError(
                    f"citation_start at index {idx} must be int, got {type(raw_start).__name__}"
                )
            if isinstance(raw_end, bool) or not isinstance(raw_end, int):
                raise TypeError(
                    f"citation_end at index {idx} must be int, got {type(raw_end).__name__}"
                )
            if not isinstance(raw_rat, str):
                raise TypeError(
                    f"rationale at index {idx} must be str, got {type(raw_rat).__name__}"
                )

            stmt = raw_stmt
            cit = raw_cit
            c_start = raw_start
            c_end = raw_end
            rat = raw_rat

            if raw_id is not None:
                if not isinstance(raw_id, str):
                    raise TypeError(
                        f"requirement_id at index {idx} must be str, got {type(raw_id).__name__}"
                    )
                req_id = raw_id
            elif allow_derivation:
                req_id = derive_requirement_id(stmt, cit, c_start, c_end)
            else:
                raise MissingRequirementIdError(
                    f"Requirement at index {idx} lacks requirement_id and derivation is disabled"
                )
        else:
            raise TypeError(
                f"Requirement at index {idx} must be ValidatedRequirement, "
                f"ProposedRequirement, or Mapping, got {type(item).__name__}"
            )

        assert req_id is not None

        content_key = (stmt, cit, c_start, c_end)
        if req_id in seen_ids:
            if seen_ids[req_id] == content_key:
                raise DuplicateRequirementIdError(f"Duplicate requirement ID: {req_id!r}")
            else:
                raise RequirementIdCollisionError(
                    f"Derived requirement ID collision on {req_id!r} between distinct requirements"
                )
        seen_ids[req_id] = content_key

        val_req = ValidatedRequirement(
            requirement_id=req_id,
            statement=stmt,
            citation=cit,
            citation_start=c_start,
            citation_end=c_end,
            rationale=rat,
        )

        # 5. Validate forbidden actions for this requirement
        _check_forbidden_actions(val_req, active_manifest)

        # 6. Validate scope for this requirement
        _validate_scope(val_req, task, active_manifest)

        validated_reqs.append(val_req)

    # 7. Deterministic stable ordering by requirement_id
    sorted_reqs = tuple(sorted(validated_reqs, key=lambda r: r.requirement_id))

    # 8. Check contradictions across requirements and against change class laws
    _check_contradictions(sorted_reqs, resolved_class)

    # 9. Record passed validation rules
    rules_passed: tuple[str, ...] = (
        "SCOPE-001",
        "SCOPE-002",
        "SCOPE-003",
        "SCOPE-004",
        "FORBIDDEN-001",
        "FORBIDDEN-002",
        "FORBIDDEN-003",
        "FORBIDDEN-004",
        "FORBIDDEN-005",
        "CONTRADICTION-RETRY",
        "CONTRADICTION-HTTP-STATUS",
        "CONTRADICTION-AUTH",
        "CONTRADICTION-CACHE",
    )
    if resolved_class == ChangeClass.REFACTOR:
        rules_passed += ("CONTRADICTION-REFACTOR-BEHAVIOR",)
    elif resolved_class == ChangeClass.PERFORMANCE:
        rules_passed += ("CONTRADICTION-PERFORMANCE-OUTPUT",)

    # 10. Construct ValidatedContract (ABSOLUTE P-06.06 INVARIANT: zero contract digest)
    return ValidatedContract(
        task_digest=task.task_digest,
        change_class=resolved_class,
        certainty=resolved_certainty,
        requirements=sorted_reqs,
        validation_rules_passed=rules_passed,
        is_valid=True,
    )
