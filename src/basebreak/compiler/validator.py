"""Deterministic contract validation layer.

P-06.04: Deterministically validate requirement IDs, scope, forbidden actions,
and contradictions under Basebreak causal verification laws.

Authority Model:
- Pure deterministic verification (ZERO model authority).
- Rigid fail-closed policy.
- Bounded requirement count and statement/citation sizes.
- Exact citation binding to normalized task text.
- Protected surface defense against forbidden mutation requests.
- Proven contradiction detection without speculative NLP illusions.
- Deterministic requirement ordering and stable serialization.
"""

from __future__ import annotations

import hashlib
import json
import re
from collections.abc import Mapping, Sequence
from dataclasses import dataclass
from typing import Any

from basebreak.compiler.ingestion import NormalizedTask
from basebreak.compiler.requirements import ProposedRequirement, UnsupportedCitationError
from basebreak.domain.semantics import ChangeClass
from basebreak.domain.task import AcceptanceRequirement
from basebreak.security.secret_policy import redact_log_text

# Bounds constants
MIN_REQUIREMENTS_COUNT: int = 1
MAX_REQUIREMENTS_COUNT: int = 20
MIN_STATEMENT_LENGTH: int = 3
MAX_STATEMENT_LENGTH: int = 1000
MAX_CITATION_LENGTH: int = 2000

# Canonical requirement ID pattern: e.g. REQ-01, REQ-100, SEC-01
_REQUIREMENT_ID_PATTERN = re.compile(r"^[A-Z0-9_\-]+$")


# --- Exception Hierarchy ---


class ContractValidationError(Exception):
    """Base exception for all contract validation errors."""


class MissingRequirementIdError(ContractValidationError):
    """Raised when a requirement is missing an ID."""


class DuplicateRequirementIdError(ContractValidationError):
    """Raised when duplicate requirement IDs are detected."""


class InvalidRequirementIdError(ContractValidationError):
    """Raised when a requirement ID does not conform to deterministic format."""


class RequirementCountLimitExceededError(ContractValidationError):
    """Raised when requirements count is 0 or exceeds allowable ceiling."""


class RequirementSizeLimitExceededError(ContractValidationError):
    """Raised when statement or citation length exceeds allowable bounds."""


class UnsupportedScopeError(ContractValidationError):
    """Raised when requirement scope is not supported by task text."""


class ForbiddenActionViolationError(ContractValidationError):
    """Raised when a requirement demands a forbidden action or protected surface mutation."""

    def __init__(self, rule_id: str, requirement_id: str, detail: str) -> None:
        super().__init__(
            f"[{rule_id}] Forbidden action in requirement '{requirement_id}': {detail}"
        )
        self.rule_id = rule_id
        self.requirement_id = requirement_id
        self.detail = detail


class ContradictoryRequirementsError(ContractValidationError):
    """Raised when deterministically provable contradictory requirements are detected."""


class InvalidChangeClassError(ContractValidationError):
    """Raised when change class is invalid or unclassifiable."""


# --- Data Contracts ---


@dataclass(frozen=True, slots=True)
class ValidatedRequirement:
    """A deterministically validated atomic acceptance requirement.

    Attributes:
        requirement_id: Deterministic, non-empty identifier (e.g. REQ-01).
        statement: Verifiable requirement statement bounded by size.
        citation: Exact verbatim substring from task text (optional for manually authored).
        citation_span: Optional (start, end) offsets in normalized task text.
        rationale: Explanatory metadata.
    """

    requirement_id: str
    statement: str
    citation: str = ""
    citation_span: tuple[int, int] | None = None
    rationale: str = ""

    def __post_init__(self) -> None:
        if not isinstance(self.requirement_id, str):
            raise TypeError(f"requirement_id must be str, got {type(self.requirement_id).__name__}")
        req_id = self.requirement_id.strip()
        if not req_id:
            raise MissingRequirementIdError("requirement_id must not be empty or whitespace-only")
        if not _REQUIREMENT_ID_PATTERN.match(req_id):
            raise InvalidRequirementIdError(
                f"requirement_id '{req_id}' does not match allowed pattern ^[A-Z0-9_-]+$"
            )
        if req_id != self.requirement_id:
            object.__setattr__(self, "requirement_id", req_id)

        if not isinstance(self.statement, str):
            raise TypeError(f"statement must be str, got {type(self.statement).__name__}")
        stmt = self.statement.strip()
        if len(stmt) < MIN_STATEMENT_LENGTH:
            raise RequirementSizeLimitExceededError(
                f"statement length {len(stmt)} is below minimum {MIN_STATEMENT_LENGTH}"
            )
        if len(stmt) > MAX_STATEMENT_LENGTH:
            raise RequirementSizeLimitExceededError(
                f"statement length {len(stmt)} exceeds maximum {MAX_STATEMENT_LENGTH}"
            )
        if stmt != self.statement:
            object.__setattr__(self, "statement", stmt)

        if not isinstance(self.citation, str):
            raise TypeError(f"citation must be str, got {type(self.citation).__name__}")
        cit = self.citation.strip()
        if len(cit) > MAX_CITATION_LENGTH:
            raise RequirementSizeLimitExceededError(
                f"citation length {len(cit)} exceeds maximum {MAX_CITATION_LENGTH}"
            )
        if cit != self.citation:
            object.__setattr__(self, "citation", cit)

        if self.citation_span is not None:
            if not isinstance(self.citation_span, tuple) or len(self.citation_span) != 2:
                raise TypeError(f"citation_span must be a 2-tuple, got {self.citation_span!r}")
            start, end = self.citation_span
            if isinstance(start, bool) or not isinstance(start, int):
                raise TypeError("citation_span start must be int")
            if isinstance(end, bool) or not isinstance(end, int):
                raise TypeError("citation_span end must be int")
            if start < 0 or end < start:
                raise ValueError(f"Invalid citation_span: ({start}, {end})")

        if not isinstance(self.rationale, str):
            raise TypeError(f"rationale must be str, got {type(self.rationale).__name__}")

    def to_dict(self) -> dict[str, Any]:
        """Deterministic dictionary serialization."""
        return {
            "requirement_id": self.requirement_id,
            "statement": self.statement,
            "citation": self.citation,
            "citation_span": list(self.citation_span) if self.citation_span else None,
            "rationale": self.rationale,
        }

    @classmethod
    def from_dict(cls, data: Mapping[str, Any]) -> ValidatedRequirement:
        """Construct from dictionary with strict schema validation."""
        required = {"requirement_id", "statement"}
        missing = required - set(data.keys())
        if missing:
            raise ValueError(f"Missing required fields for ValidatedRequirement: {sorted(missing)}")

        span_raw = data.get("citation_span")
        span: tuple[int, int] | None = None
        if span_raw is not None:
            if isinstance(span_raw, (list, tuple)) and len(span_raw) == 2:
                span = (int(span_raw[0]), int(span_raw[1]))
            else:
                raise TypeError(f"Invalid citation_span in dict: {span_raw!r}")

        return cls(
            requirement_id=str(data["requirement_id"]),
            statement=str(data["statement"]),
            citation=str(data.get("citation", "")),
            citation_span=span,
            rationale=str(data.get("rationale", "")),
        )


@dataclass(frozen=True, slots=True)
class ValidatedContract:
    """A deterministically validated verification contract.

    Attributes:
        task_digest: SHA-256 digest of the normalized task text.
        change_class: Canonical change class.
        requirements: Stably ordered tuple of ValidatedRequirement instances.
        validation_digest: Deterministic SHA-256 digest of contract validation facts.
        is_valid: Invariant True when instantiated.
    """

    task_digest: str
    change_class: ChangeClass
    requirements: tuple[ValidatedRequirement, ...]
    validation_digest: str
    is_valid: bool = True

    def __post_init__(self) -> None:
        if not isinstance(self.task_digest, str) or not self.task_digest:
            raise ValueError("task_digest must be a non-empty string")
        if not isinstance(self.change_class, ChangeClass):
            raise TypeError(
                f"change_class must be ChangeClass, got {type(self.change_class).__name__}"
            )
        if not isinstance(self.requirements, tuple):
            raise TypeError("requirements must be a tuple")
        for r in self.requirements:
            if not isinstance(r, ValidatedRequirement):
                raise TypeError(
                    f"requirements item must be ValidatedRequirement, got {type(r).__name__}"
                )
        if not isinstance(self.validation_digest, str) or not self.validation_digest:
            raise ValueError("validation_digest must be a non-empty string")

    def to_dict(self) -> dict[str, Any]:
        """Deterministic dictionary serialization."""
        return {
            "task_digest": self.task_digest,
            "change_class": self.change_class.value,
            "requirements": [r.to_dict() for r in self.requirements],
            "validation_digest": self.validation_digest,
            "is_valid": self.is_valid,
        }

    @classmethod
    def from_dict(cls, data: Mapping[str, Any]) -> ValidatedContract:
        """Construct from dictionary with strict schema validation."""
        required = {"task_digest", "change_class", "requirements", "validation_digest"}
        missing = required - set(data.keys())
        if missing:
            raise ValueError(f"Missing required fields for ValidatedContract: {sorted(missing)}")

        reqs_raw = data["requirements"]
        if not isinstance(reqs_raw, Sequence):
            raise TypeError("requirements must be a sequence")

        validated_reqs = tuple(
            ValidatedRequirement.from_dict(r) if isinstance(r, Mapping) else r for r in reqs_raw
        )

        return cls(
            task_digest=str(data["task_digest"]),
            change_class=ChangeClass(data["change_class"]),
            requirements=validated_reqs,
            validation_digest=str(data["validation_digest"]),
            is_valid=bool(data.get("is_valid", True)),
        )


# --- Deterministic ID Generation ---


def derive_requirement_id(index: int, prefix: str = "REQ") -> str:
    """Deterministically derive a stable requirement ID from 1-based index."""
    if not isinstance(index, int) or isinstance(index, bool) or index < 1:
        raise ValueError(f"index must be a positive integer >= 1, got {index!r}")
    if not isinstance(prefix, str) or not prefix.strip():
        raise ValueError("prefix must be a non-empty string")
    return f"{prefix.strip()}-{index:02d}"


def assign_deterministic_requirement_ids(
    requirements: Sequence[
        ValidatedRequirement | ProposedRequirement | AcceptanceRequirement | Mapping[str, Any] | str
    ],
    prefix: str = "REQ",
) -> list[ValidatedRequirement]:
    """Deterministically assign sequential requirement IDs to an ordered sequence.

    Uses deterministic sequential numbering without random UUIDs, time, or process ordering.
    """
    validated: list[ValidatedRequirement] = []
    for idx, item in enumerate(requirements, start=1):
        req_id = derive_requirement_id(idx, prefix)
        if isinstance(item, ValidatedRequirement):
            validated.append(
                ValidatedRequirement(
                    requirement_id=req_id,
                    statement=item.statement,
                    citation=item.citation,
                    citation_span=item.citation_span,
                    rationale=item.rationale,
                )
            )
        elif isinstance(item, ProposedRequirement):
            validated.append(
                ValidatedRequirement(
                    requirement_id=req_id,
                    statement=item.statement,
                    citation=item.citation,
                    citation_span=(item.citation_start, item.citation_end),
                    rationale=item.rationale,
                )
            )
        elif isinstance(item, AcceptanceRequirement):
            validated.append(
                ValidatedRequirement(
                    requirement_id=req_id,
                    statement=item.statement,
                )
            )
        elif isinstance(item, Mapping):
            validated.append(
                ValidatedRequirement(
                    requirement_id=req_id,
                    statement=str(item["statement"]),
                    citation=str(item.get("citation", "")),
                    rationale=str(item.get("rationale", "")),
                )
            )
        elif isinstance(item, str):
            validated.append(
                ValidatedRequirement(
                    requirement_id=req_id,
                    statement=item,
                )
            )
        else:
            raise TypeError(
                f"Unsupported requirement item type at index {idx}: {type(item).__name__}"
            )
    return validated


# --- Forbidden Action Rules ---

_PROTECTED_PATHS_PATTERN = (
    r"(?:AGENTS\.md|(?:plans/)?BASEBREAK_MASTER_EXECUTION_PLAN(?:\.md)?|"
    r"(?:docs/)?SECURITY_BOUNDARY(?:\.md)?|(?:docs/)?DONOR_MANIFEST(?:\.md)?|"
    r"(?:docs/)?OPERATOR_REQUIREMENTS(?:\.md)?|(?:docs/)?COMPETITION_FEEDBACK_LOG(?:\.md)?|"
    r"src/basebreak/(?:domain|evidence|security))"
)

_FORBIDDEN_RULES: tuple[tuple[str, re.Pattern[str], str], ...] = (
    (
        "FORBID-01",
        re.compile(
            rf"\b(?:modify|edit|update|delete|remove|overwrite|patch|"
            rf"tamper with|bypass|disable|strip)"
            rf"\s+(?:the\s+)?(?:protected\s+)?(?:files?\s+|paths?\s+|surfaces?\s+)?"
            rf"{_PROTECTED_PATHS_PATTERN}\b",
            flags=re.IGNORECASE,
        ),
        "Direct attempt to mutate, overwrite, delete, or bypass protected governance/security path",
    ),
    (
        "FORBID-02",
        re.compile(
            r"\b(?:weaken|disable|skip|remove|delete|comment out)\s+"
            r"(?:the\s+)?(?:existing\s+)?(?:failing\s+)?(?:test\s+)?"
            r"(?:assertions?|tests?|checks?|validations?|suites?)\s+"
            r"(?:to\s+(?:make\s+(?:them\s+)?pass|get\s+green|bypass|silence|suppress))\b|"
            r"\b(?:weaken\s+assertions?|delete\s+failing\s+tests?)\b",
            flags=re.IGNORECASE,
        ),
        "Direct attempt to weaken assertions, delete failing tests, or falsify green test results",
    ),
    (
        "FORBID-03",
        re.compile(
            r"\b(?:print|log|dump|expose|exfiltrate|leak|send|transmit|commit)\s+"
            r"(?:the\s+)?(?:api[_\s]?key|credentials?|secrets?|auth\s+tokens?|private\s+keys?|passwords?)\s+"
            r"(?:to\s+(?:stdout|stderr|logs?|console|external|server|chat|remote))\b|"
            r"\b(?:disable|bypass|remove)\s+(?:secret\s+)?redaction\b",
            flags=re.IGNORECASE,
        ),
        "Direct attempt to exfiltrate, print, or log credentials or bypass secret redaction",
    ),
    (
        "FORBID-04",
        re.compile(
            r"\b(?:execute|run|spawn)\s+(?:a\s+)?(?:fork\s*bomb|rm\s+-rf\s+/|disk\s+wipe)\b|"
            r"\b(?:disable|bypass)\s+sandbox\s+(?:isolation|network\s+policy|security\s+boundary)\b",
            flags=re.IGNORECASE,
        ),
        "Destructive command execution, fork bomb attempt, or sandbox escape request",
    ),
)


def _check_forbidden_actions(req: ValidatedRequirement) -> None:
    """Validate a single requirement against structurally bounded forbidden action rules."""
    text = req.statement
    for rule_id, pattern, explanation in _FORBIDDEN_RULES:
        if pattern.search(text):
            safe_detail = redact_log_text(f"{explanation} (matched rule {rule_id})")
            raise ForbiddenActionViolationError(
                rule_id=rule_id,
                requirement_id=req.requirement_id,
                detail=safe_detail,
            )


# --- Proven Contradiction Rules ---

_CONTRADICTION_DIRECTIVE_PAIRS: tuple[tuple[str, re.Pattern[str], re.Pattern[str]], ...] = (
    (
        "caching_policy",
        re.compile(
            r"\b(?:must\s+cache|enable\s+caching|cache\s+all\s+responses?|caching\s+is\s+required)\b",
            flags=re.IGNORECASE,
        ),
        re.compile(
            r"\b(?:must\s+not\s+cache|disable\s+caching|do\s+not\s+cache|never\s+cache|forbid\s+caching)\b",
            flags=re.IGNORECASE,
        ),
    ),
    (
        "retry_policy",
        re.compile(
            r"\b(?:must\s+retry|enable\s+retries|retry\s+failed\s+requests|retries\s+are\s+required)\b",
            flags=re.IGNORECASE,
        ),
        re.compile(
            r"\b(?:must\s+not\s+retry|disable\s+retries|do\s+not\s+retry|never\s+retry|forbid\s+retries)\b",
            flags=re.IGNORECASE,
        ),
    ),
    (
        "execution_mode",
        re.compile(
            r"\b(?:execute\s+synchronously|must\s+be\s+synchronous|synchronous\s+execution\s+only)\b",
            flags=re.IGNORECASE,
        ),
        re.compile(
            r"\b(?:execute\s+asynchronously|must\s+be\s+asynchronous|asynchronous\s+execution\s+only)\b",
            flags=re.IGNORECASE,
        ),
    ),
    (
        "authentication_requirement",
        re.compile(
            r"\b(?:require\s+authentication\s+for\s+all|all\s+requests\s+must\s+be\s+authenticated)\b",
            flags=re.IGNORECASE,
        ),
        re.compile(
            r"\b(?:allow\s+unauthenticated\s+access\s+for\s+all|all\s+requests\s+may\s+be\s+unauthenticated)\b",
            flags=re.IGNORECASE,
        ),
    ),
)

_HTTP_STATUS_PATTERN = re.compile(
    r"(?:when|if|on)\s+([^,]+),\s*(?:return|respond with)\s+(?:HTTP\s+)?(\d{3})",
    flags=re.IGNORECASE,
)


def _extract_target_scope(text: str) -> str | None:
    """Extract condition or scope target from statement if specified with 'for/on/when/if'."""
    match = re.search(r"\b(?:for|on|when|if)\s+([^,.;]+)", text, re.IGNORECASE)
    if match:
        return re.sub(r"\s+", " ", match.group(1).strip().lower())
    return None


def _check_contradictions(
    requirements: Sequence[ValidatedRequirement],
    change_class: ChangeClass,
) -> None:
    """Deterministically check for proven logical contradictions.

    Supported proven contradiction rules:
    1. Pairwise mutually exclusive directive pairs on same subject
       (caching, retries, sync/async, auth).
       Distinguishes different conditions (e.g. retries for network timeouts vs client errors).
    2. Mutually exclusive HTTP status codes for identical trigger conditions.
    3. Requirements contradicting ChangeClass causal verification laws:
       - REFACTOR requiring behavioral changes or breaking changes (violates equivalence).
       - PERFORMANCE requiring breaking changes or functional alterations (violates parity).
    """
    # 1. Pairwise directly opposing directive pairs
    for concept, pos_pattern, neg_pattern in _CONTRADICTION_DIRECTIVE_PAIRS:
        pos_reqs = [r for r in requirements if pos_pattern.search(r.statement)]
        neg_reqs = [r for r in requirements if neg_pattern.search(r.statement)]
        if pos_reqs and neg_reqs:
            for p_req in pos_reqs:
                for n_req in neg_reqs:
                    scope_p = _extract_target_scope(p_req.statement)
                    scope_n = _extract_target_scope(n_req.statement)
                    # If both have explicit different scopes and neither is "all",
                    # they are not contradictory
                    if (
                        scope_p
                        and scope_n
                        and scope_p != scope_n
                        and "all" not in scope_p
                        and "all" not in scope_n
                    ):
                        continue
                    raise ContradictoryRequirementsError(
                        f"Contradictory requirements detected for concept '{concept}': "
                        f"'{p_req.requirement_id}' opposes '{n_req.requirement_id}'."
                    )

    # 2. Conflicting status codes for identical trigger conditions
    condition_to_code: dict[
        str, tuple[str, str]
    ] = {}  # normalized_condition -> (req_id, status_code)
    for r in requirements:
        for match in _HTTP_STATUS_PATTERN.finditer(r.statement):
            cond_raw, code = match.group(1).strip().lower(), match.group(2)
            # Normalize whitespace in condition
            norm_cond = re.sub(r"\s+", " ", cond_raw)
            if norm_cond in condition_to_code:
                prior_id, prior_code = condition_to_code[norm_cond]
                if prior_code != code:
                    raise ContradictoryRequirementsError(
                        f"Conflicting status codes for condition '{norm_cond}': "
                        f"'{prior_id}' returns HTTP {prior_code} while "
                        f"'{r.requirement_id}' returns HTTP {code}."
                    )
            else:
                condition_to_code[norm_cond] = (r.requirement_id, code)

    # 3. Contradictions against ChangeClass causal laws
    if change_class == ChangeClass.REFACTOR:
        # Refactor law: requires_equivalence=True (no external behavioral changes)
        refactor_violation_pattern = re.compile(
            r"\b(?:breaking\s+(?:change|api)|modify\s+public\s+api|"
            r"change\s+(?:external\s+|observable\s+)?behavior|add\s+new\s+(?:feature|endpoint|capability))\b",
            flags=re.IGNORECASE,
        )
        for r in requirements:
            if refactor_violation_pattern.search(r.statement):
                raise ContradictoryRequirementsError(
                    f"Requirement '{r.requirement_id}' demands observable behavioral or breaking "
                    f"changes, which contradicts REFACTOR semantics (mandates behavioral "
                    f"equivalence)."
                )

    if change_class == ChangeClass.PERFORMANCE:
        # Performance law: parity required (no breaking changes or altered functional contracts)
        perf_violation_pattern = re.compile(
            r"\b(?:breaking\s+(?:change|api)|change\s+(?:functional\s+)?output|"
            r"alter\s+behavioral\s+contracts?)\b",
            flags=re.IGNORECASE,
        )
        for r in requirements:
            if perf_violation_pattern.search(r.statement):
                raise ContradictoryRequirementsError(
                    f"Requirement '{r.requirement_id}' demands breaking changes or altered "
                    f"functional output, which contradicts PERFORMANCE semantics (mandates parity)."
                )


# --- Digest Computation ---


def _compute_validation_digest(
    task_digest: str,
    change_class: ChangeClass,
    requirements: tuple[ValidatedRequirement, ...],
) -> str:
    """Compute deterministic SHA-256 digest of validated contract components."""
    canonical_repr = {
        "change_class": change_class.value,
        "requirements": [
            {
                "citation": req.citation,
                "citation_span": list(req.citation_span) if req.citation_span else None,
                "rationale": req.rationale,
                "requirement_id": req.requirement_id,
                "statement": req.statement,
            }
            for req in requirements
        ],
        "task_digest": task_digest,
    }
    encoded = json.dumps(canonical_repr, sort_keys=True, separators=(",", ":")).encode("utf-8")
    return hashlib.sha256(encoded).hexdigest()


# --- Validation Entry Point ---


def validate_contract(
    requirements: Sequence[
        ValidatedRequirement | ProposedRequirement | AcceptanceRequirement | Mapping[str, Any]
    ],
    task: NormalizedTask,
    change_class: ChangeClass,
    *,
    allow_id_derivation: bool = False,
) -> ValidatedContract:
    """Deterministically validate requirement IDs, scope, forbidden actions, and contradictions.

    Validation Pipeline:
    1. Validate task and change_class instances.
    2. Enforce bounded requirement count: MIN_REQUIREMENTS_COUNT <= count <= MAX_REQUIREMENTS_COUNT.
    3. Normalize and validate individual requirement instances (size, format, IDs).
    4. Enforce requirement ID presence and uniqueness.
    5. Enforce verbatim citation binding to normalized task text.
    6. Run structurally bounded forbidden action checks.
    7. Run proven contradiction checks (pairwise and against ChangeClass laws).
    8. Stably sort requirements by requirement_id for deterministic representation.
    9. Compute deterministic validation digest.

    Returns:
        ValidatedContract instance ready for review.
    """
    if not isinstance(task, NormalizedTask):
        raise TypeError(f"task must be NormalizedTask, got {type(task).__name__}")
    if not isinstance(change_class, ChangeClass):
        raise InvalidChangeClassError(
            f"change_class must be a valid ChangeClass enum instance, got {change_class!r}"
        )

    if not requirements or len(requirements) < MIN_REQUIREMENTS_COUNT:
        count = len(requirements) if requirements else 0
        raise RequirementCountLimitExceededError(
            f"Requirements count {count} is below minimum {MIN_REQUIREMENTS_COUNT}"
        )

    if len(requirements) > MAX_REQUIREMENTS_COUNT:
        count = len(requirements)
        raise RequirementCountLimitExceededError(
            f"Requirements count {count} exceeds allowable maximum {MAX_REQUIREMENTS_COUNT}"
        )

    validated_list: list[ValidatedRequirement] = []
    seen_ids: set[str] = set()

    for idx, item in enumerate(requirements):
        # 1. Convert to ValidatedRequirement
        if isinstance(item, ValidatedRequirement):
            val_req = item
        elif isinstance(item, ProposedRequirement):
            if allow_id_derivation:
                req_id = derive_requirement_id(idx + 1)
            else:
                raise MissingRequirementIdError(
                    f"ProposedRequirement at index {idx} lacks requirement_id, "
                    f"and allow_id_derivation is False"
                )
            val_req = ValidatedRequirement(
                requirement_id=req_id,
                statement=item.statement,
                citation=item.citation,
                citation_span=(item.citation_start, item.citation_end),
                rationale=item.rationale,
            )
        elif isinstance(item, AcceptanceRequirement):
            val_req = ValidatedRequirement(
                requirement_id=item.requirement_id,
                statement=item.statement,
            )
        elif isinstance(item, Mapping):
            raw_id = item.get("requirement_id")
            if not raw_id:
                if allow_id_derivation:
                    raw_id = derive_requirement_id(idx + 1)
                else:
                    raise MissingRequirementIdError(
                        f"Requirement dict at index {idx} missing 'requirement_id'"
                    )
            val_req = ValidatedRequirement(
                requirement_id=str(raw_id),
                statement=str(item.get("statement", "")),
                citation=str(item.get("citation", "")),
                rationale=str(item.get("rationale", "")),
            )
        else:
            raise TypeError(
                f"Requirement item at index {idx} has invalid type {type(item).__name__}"
            )

        # 2. Check ID uniqueness
        if val_req.requirement_id in seen_ids:
            raise DuplicateRequirementIdError(
                f"Duplicate requirement_id detected: '{val_req.requirement_id}'"
            )
        seen_ids.add(val_req.requirement_id)

        # 3. Enforce verbatim citation binding to task text if citation is present
        if val_req.citation:
            if val_req.citation not in task.normalized_text:
                safe_cit = redact_log_text(val_req.citation)
                raise UnsupportedCitationError(
                    f"Citation in requirement '{val_req.requirement_id}' is not present "
                    f"in normalized task text: {safe_cit!r}"
                )
            # If citation_span is present, verify exact character slice
            if val_req.citation_span is not None:
                start, end = val_req.citation_span
                expected_slice = task.normalized_text[start:end]
                if expected_slice != val_req.citation:
                    raise UnsupportedCitationError(
                        f"Citation span [{start}:{end}] in requirement '{val_req.requirement_id}' "
                        f"does not match citation text: expected {val_req.citation!r}, "
                        f"got {expected_slice!r}"
                    )

        # 4. Forbidden action checks
        _check_forbidden_actions(val_req)

        validated_list.append(val_req)

    # 5. Deterministic sorting by requirement_id
    sorted_requirements = tuple(sorted(validated_list, key=lambda r: r.requirement_id))

    # 6. Proven contradiction checks
    _check_contradictions(sorted_requirements, change_class)

    # 7. Compute deterministic validation digest
    validation_digest = _compute_validation_digest(
        task_digest=task.task_digest,
        change_class=change_class,
        requirements=sorted_requirements,
    )

    return ValidatedContract(
        task_digest=task.task_digest,
        change_class=change_class,
        requirements=sorted_requirements,
        validation_digest=validation_digest,
        is_valid=True,
    )
