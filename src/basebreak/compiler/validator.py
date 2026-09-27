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


# --- Helper: Protective or Testing Intent Detection ---

_PROTECTIVE_PATTERNS = [
    re.compile(
        r"^(?:add\s+(?:a\s+)?test|test\s+(?:that|proving|whether)|assert\s+(?:that)?|verify\s+(?:that)?|check\s+(?:that)?)\b",
        re.IGNORECASE,
    ),
    re.compile(
        r"^(?:ensure\s+(?:that\s+)?.*(?:\bnever\b|\bnot\b|\bcannot\b|\bno\b|\bblocked\b|\brejected\b|\bprevented\b|\bforbidden\b|\bdisallowed\b))",
        re.IGNORECASE,
    ),
    re.compile(
        r"^(?:prevent|detect|block|forbid|reject|disallow)\s+.*",
        re.IGNORECASE,
    ),
    re.compile(
        r"\bproving\s+.*(?:\bis\s+rejected\b|\bfails\b|\bis\s+blocked\b|\bis\s+forbidden\b)",
        re.IGNORECASE,
    ),
    re.compile(
        r"\bcannot\s+be\s+(?:modified|edited|deleted|bypassed|weakened|exfiltrated|accessed)\b",
        re.IGNORECASE,
    ),
    re.compile(
        r"\b(?:never|not)\s+(?:printed|logged|exposed|leaked|exfiltrated|sent|modified|deleted)\b",
        re.IGNORECASE,
    ),
    re.compile(
        r"\bredacted\s+(?:from\s+logs?)?\b",
        re.IGNORECASE,
    ),
    re.compile(
        r"\b(?:blocked|prevented|rejected|forbidden|disallowed)\s+(?:from|by)?\b",
        re.IGNORECASE,
    ),
]


def _is_protective_or_testing_statement(text: str) -> bool:
    """Return True if text expresses protective, defensive, or verification intent."""
    clean = text.strip()
    return any(pattern.search(clean) is not None for pattern in _PROTECTIVE_PATTERNS)


# --- Forbidden Action Validation ---

_FORBIDDEN_TEST_WEAKEN = re.compile(
    r"\b(?:(?:delete|remove|drop|strip|comment\s+out)\s+(?:failing\s+)?tests?\s+(?:to\s+(?:make|get|obtain)\s+green|so\s+tests?\s+pass)|"
    r"(?:weaken|relax|disable|bypass|ignore)\s+(?:test\s+assertions?|assertions?|tests?)\s+(?:to\s+(?:pass|get\s+green)|so\s+tests?\s+pass)|"
    r"(?:make|get)\s+tests?\s+green\s+by\s+(?:removing|deleting|weakening|disabling)|"
    r"bypass\s+test\s+failures|"
    r"ignore\s+(?:failing\s+tests?|test\s+failures))\b",
    re.IGNORECASE,
)

_FORBIDDEN_PROTECTED_SURFACE = re.compile(
    r"\b(?:modify|edit|update|change|delete|remove|overwrite|patch|mutate|re-write|rewrite)\s+.*"
    r"(?:AGENTS\.md|BASEBREAK_MASTER_EXECUTION_PLAN\.md|SECURITY_BOUNDARY\.md|DONOR_MANIFEST\.md|"
    r"OPERATOR_REQUIREMENTS\.md|COMPETITION_FEEDBACK_LOG\.md|src/basebreak/(?:domain|evidence|security))\b",
    re.IGNORECASE,
)

_FORBIDDEN_SECRET_EXFIL = re.compile(
    r"\b(?:(?:send|exfiltrate|leak|post|upload|transmit)\s+.*(?:api[_-]?key|secret|credential|token|private[_-]?key)\s+to\s+|"
    r"(?:print|log|dump|display|output)\s+.*(?:api[_-]?key|secret|credentials?|token|private[_-]?key)\s+to\s+(?:stdout|console|log|file)|"
    r"exfiltrate\s+(?:secrets?|credentials?|keys?|tokens?))\b",
    re.IGNORECASE,
)

_FORBIDDEN_VERIFICATION_BYPASS = re.compile(
    r"\b(?:(?:disable|turn\s+off|bypass|skip|deactivate)\s+(?:required\s+)?(?:deterministic\s+)?verification|"
    r"(?:disable|bypass|skip)\s+security\s+(?:checks?|validation|policy)|"
    r"(?:bypass|disable)\s+contract\s+validation)\b",
    re.IGNORECASE,
)

_FORBIDDEN_DESTRUCTIVE_EXEC = re.compile(
    r"\b(?:(?:run|execute|call)\s+rm\s+-rf\s+[/~]|"
    r"(?:wipe|format|destroy)\s+(?:disk|filesystem|root|database)|"
    r"rm\s+-rf\s+/(?:\s|$))\b",
    re.IGNORECASE,
)


def _check_forbidden_actions(req: ValidatedRequirement, manifest: ProtectedSurfaceManifest) -> None:
    """Validate a single requirement against forbidden action rules."""
    statement = req.statement

    # If the statement is framed defensively or as a test/protection, it does NOT violate policy
    if _is_protective_or_testing_statement(statement):
        return

    # Check rule 1: Test weakening
    if _FORBIDDEN_TEST_WEAKEN.search(statement):
        raise ForbiddenActionViolationError(
            rule_id="FORBIDDEN-001",
            requirement_id=req.requirement_id,
            detail=f"Requirement demands weakening or deleting tests to pass: {statement}",
        )

    # Check rule 2: Protected surface mutation
    if _FORBIDDEN_PROTECTED_SURFACE.search(statement):
        raise ForbiddenActionViolationError(
            rule_id="FORBIDDEN-002",
            requirement_id=req.requirement_id,
            detail=f"Requirement demands mutation of protected repository surfaces: {statement}",
        )

    # Check rule 3: Credential / secret exfiltration
    if _FORBIDDEN_SECRET_EXFIL.search(statement):
        raise ForbiddenActionViolationError(
            rule_id="FORBIDDEN-003",
            requirement_id=req.requirement_id,
            detail=f"Requirement demands credential or secret exfiltration: {statement}",
        )

    # Check rule 4: Disabling deterministic verification
    if _FORBIDDEN_VERIFICATION_BYPASS.search(statement):
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
            if not _is_protective_or_testing_statement(req.statement):
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
            if not _is_protective_or_testing_statement(req.statement):
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


def _validate_scope(
    req: ValidatedRequirement,
    task: NormalizedTask,
    manifest: ProtectedSurfaceManifest,
) -> None:
    """Validate requirement scope deterministically against task text and protected surfaces."""
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

    # 2. Check for explicit path mentions in statement to ensure no protected surfaces are targeted
    # Look for file-path-like tokens (e.g. src/..., docs/..., AGENTS.md)
    path_tokens = re.findall(
        r"\b(?:[A-Za-z0-9_.\-]+/[A-Za-z0-9_.\-/]+|AGENTS\.md)\b", req.statement
    )
    for token in path_tokens:
        try:
            norm_path = normalize_repo_path(token)
            match = match_protected_surface(norm_path, manifest)
            if match is not None:
                # If path is protected, check if requirement demands modifying it
                if not _is_protective_or_testing_statement(req.statement):
                    raise UnsupportedScopeError(
                        f"Requirement {req.requirement_id!r} introduces protected surface "
                        f"'{norm_path}' into modification scope"
                    )
        except Exception as exc:
            # If token cannot be normalized as repo path, it's not a repo path; ignore
            if isinstance(exc, UnsupportedScopeError):
                raise


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
        # Do NOT guess or promote AMBIGUOUS/UNKNOWN to concrete authoritative class
        if change_class.certainty in (CertaintyLevel.AMBIGUOUS, CertaintyLevel.UNKNOWN):
            resolved_class = None
            resolved_certainty = change_class.certainty
        else:
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
