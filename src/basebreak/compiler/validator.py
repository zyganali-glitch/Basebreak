"""Deterministic validation of requirement IDs, scope, forbidden actions, and contradictions.

P-06.04: Deterministically validates requirement IDs, bounds contract scope,
enforces forbidden action policies, and detects logical and semantic contradictions.

Architectural invariants:
- Model output is UNTRUSTED. Deterministic code is the sole authority for validation.
- Requirement IDs must be non-empty, valid identifier format, and strictly unique.
- Scope bounds are enforced: minimum and maximum requirement count and statement lengths.
- Forbidden actions (mutating protected surfaces, disabling security, deleting tests,
  destructive actions, prompt injections) fail closed.
- Contradictions between requirements or against declared ChangeClass fail closed.
- Zero secret leakage in logs, diagnostics, or error messages.
- Provider neutrality: zero dependencies on external provider adapters.
"""

from __future__ import annotations

import hashlib
import json
import re
from collections.abc import Sequence
from dataclasses import dataclass

from basebreak.compiler.ingestion import NormalizedTask
from basebreak.compiler.requirements import ProposedRequirement
from basebreak.domain.semantics import ChangeClass
from basebreak.domain.task import AcceptanceRequirement
from basebreak.security.secret_policy import redact_log_text

# Scope boundaries
MIN_REQUIREMENTS_COUNT: int = 1
MAX_REQUIREMENTS_COUNT: int = 32
MIN_STATEMENT_LENGTH: int = 5
MAX_STATEMENT_LENGTH: int = 1024
MAX_REQUIREMENT_ID_LENGTH: int = 64

# Requirement ID regex pattern (alphanumeric with hyphens/underscores, e.g. REQ-01, REQ-BUG-01)
_REQUIREMENT_ID_PATTERN = re.compile(r"^[A-Za-z0-9][A-Za-z0-9_-]{0,63}$")


class ContractValidationError(Exception):
    """Base exception for contract and requirement validation failures."""


class InvalidRequirementIdError(ContractValidationError):
    """Raised when a requirement ID is malformed, empty, or exceeds length limit."""


class DuplicateRequirementIdError(ContractValidationError):
    """Raised when duplicate requirement IDs are detected within a contract."""


class ContractScopeExceededError(ContractValidationError):
    """Raised when contract scope boundaries are violated (count, length, out-of-scope)."""


class ForbiddenActionViolationError(ContractValidationError):
    """Raised when a requirement demands a forbidden action or policy bypass."""

    def __init__(self, rule_id: str, requirement_id: str, detail: str) -> None:
        self.rule_id = rule_id
        self.requirement_id = requirement_id
        self.detail = detail
        super().__init__(
            f"Forbidden action [{rule_id}] detected in requirement '{requirement_id}': {detail}"
        )


class ContradictoryRequirementsError(ContractValidationError):
    """Raised when mutually contradictory requirements or semantics conflicts are detected."""


# Forbidden action rules: (rule_id, regex_pattern, failure_explanation)
_FORBIDDEN_ACTION_RULES: tuple[tuple[str, re.Pattern[str], str], ...] = (
    (
        "PROMPT_INJECTION",
        re.compile(
            r"(?i)\b(?:ignore (?:all )?(?:previous|above) instructions|act as (?:a |an )?judge|"
            r"system prompt override|you are now in developer mode|jailbreak)\b"
        ),
        "Requirement contains prompt injection or agent override attempt.",
    ),
    (
        "DISABLE_SECURITY",
        re.compile(
            r"(?i)\b(?:disable (?:sandbox|security|isolation|timeout|safeguards?)|"
            r"bypass (?:security|sandbox|auth|authorization|verification)|"
            r"grant (?:root|unrestricted|full) access|run without (?:isolation|sandbox))\b"
        ),
        "Requirement attempts to disable or bypass security isolation.",
    ),
    (
        "MUTATE_PROTECTED_SURFACE",
        re.compile(
            r"(?i)(?:(?:alter|modify|delete|rewrite|bypass|overwrite)[\s\S]*?"
            r"(?:\.basebreak|\.github[/\\]workflows|tests[/\\]verifier|src[/\\]basebreak[/\\]security)|"
            r"(?:\.basebreak|\.github[/\\]workflows|tests[/\\]verifier|src[/\\]basebreak[/\\]security)[\s\S]*?"
            r"(?:alter|modify|delete|rewrite|bypass|overwrite))"
        ),
        "Requirement attempts to mutate or bypass a protected repository surface.",
    ),
    (
        "WEAKEN_TESTS",
        re.compile(
            r"(?i)\b(?:delete (?:existing |failing )?tests?|remove (?:test )?assertions?|"
            r"suppress (?:assertion|test) failures?|"
            r"pass (?:tests? )?without (?:verification|fixing)|"
            r"make tests? always pass|ignore failing tests?)\b"
        ),
        "Requirement attempts to weaken, suppress, or delete verification tests.",
    ),
    (
        "DESTRUCTIVE_ACTIONS",
        re.compile(
            r"(?i)\b(?:rm\s+-rf|drop\s+database|format\s+(?:c:|disk|drive)|"
            r"delete\s+all\s+files|fork\s+bomb|:\(\)\s*\{|kill\s+-9\s+1)\b"
        ),
        "Requirement attempts destructive host or operating system actions.",
    ),
    (
        "EXTERNAL_EXFILTRATION",
        re.compile(
            r"(?i)\b(?:upload (?:secrets?|keys?|credentials?|tokens?)|"
            r"send (?:secrets?|tokens?|keys?) to|exfiltrate|post data to external)\b"
        ),
        "Requirement attempts credential exfiltration or unauthorized egress.",
    ),
)


# Pairwise contradiction patterns: (concept_name, positive_regex, negative_regex)
_CONTRADICTION_PATTERNS: tuple[tuple[str, re.Pattern[str], re.Pattern[str]], ...] = (
    (
        "AUTHENTICATION",
        re.compile(r"(?i)\b(?:require|enforce|mandatory) (?:auth|authentication|login)\b"),
        re.compile(r"(?i)\b(?:allow|permit) (?:anonymous|unauthenticated|public|no auth)\b"),
    ),
    (
        "CACHING",
        re.compile(r"(?i)\b(?:enable|use|turn on) (?:cache|caching)\b"),
        re.compile(r"(?i)\b(?:disable|bypass|turn off|never use) (?:cache|caching)\b"),
    ),
    (
        "STRICT_MODE",
        re.compile(r"(?i)\b(?:enable|enforce|strict mode)\b"),
        re.compile(r"(?i)\b(?:disable strict mode|lenient mode|permissive mode)\b"),
    ),
    (
        "ENCRYPTION",
        re.compile(r"(?i)\b(?:encrypt|encryption at rest|encrypted)\b"),
        re.compile(r"(?i)\b(?:plaintext|unencrypted|store in raw text)\b"),
    ),
)


@dataclass(frozen=True, slots=True)
class ValidatedRequirement:
    """An immutable, deterministically validated acceptance requirement."""

    requirement_id: str
    statement: str
    citation: str = ""
    citation_span: tuple[int, int] | None = None

    def __post_init__(self) -> None:
        if not isinstance(self.requirement_id, str):
            raise TypeError(f"requirement_id must be str, got {type(self.requirement_id).__name__}")
        if not _REQUIREMENT_ID_PATTERN.match(self.requirement_id):
            raise InvalidRequirementIdError(
                f"Invalid requirement_id format '{self.requirement_id}'. Must match "
                f"alphanumeric/hyphen/underscore format and be <= 64 chars."
            )

        if not isinstance(self.statement, str):
            raise TypeError(f"statement must be str, got {type(self.statement).__name__}")
        stmt = self.statement.strip()
        if len(stmt) < MIN_STATEMENT_LENGTH:
            raise ContractScopeExceededError(
                f"Requirement statement too short ({len(stmt)} < {MIN_STATEMENT_LENGTH}): {stmt!r}"
            )
        if len(stmt) > MAX_STATEMENT_LENGTH:
            raise ContractScopeExceededError(
                f"Requirement statement exceeds maximum length "
                f"({len(stmt)} > {MAX_STATEMENT_LENGTH})"
            )
        if stmt != self.statement:
            object.__setattr__(self, "statement", stmt)

    def to_acceptance_requirement(self) -> AcceptanceRequirement:
        """Convert to domain AcceptanceRequirement contract."""
        return AcceptanceRequirement(
            requirement_id=self.requirement_id,
            statement=self.statement,
        )

    def __repr__(self) -> str:
        safe_stmt = redact_log_text(self.statement)
        return f"ValidatedRequirement(id={self.requirement_id!r}, statement={safe_stmt!r})"


@dataclass(frozen=True, slots=True)
class ValidatedContract:
    """Complete, immutable validated contract with deterministic verification digest."""

    task_digest: str
    change_class: ChangeClass
    requirements: tuple[ValidatedRequirement, ...]
    contract_digest: str
    warnings: tuple[str, ...] = ()

    @property
    def requirement_ids(self) -> tuple[str, ...]:
        """Ordered sequence of requirement IDs."""
        return tuple(r.requirement_id for r in self.requirements)

    def get_requirement(self, requirement_id: str) -> ValidatedRequirement | None:
        """Lookup a validated requirement by ID."""
        for r in self.requirements:
            if r.requirement_id == requirement_id:
                return r
        return None

    def __repr__(self) -> str:
        return (
            f"ValidatedContract(task_digest={self.task_digest[:16]}..., "
            f"change_class={self.change_class.value}, "
            f"requirements_count={len(self.requirements)}, "
            f"contract_digest={self.contract_digest[:16]}...)"
        )


def _compute_contract_digest(
    task_digest: str,
    change_class: ChangeClass,
    requirements: Sequence[ValidatedRequirement],
) -> str:
    """Compute deterministic SHA-256 digest of validated contract components."""
    canonical_repr = {
        "task_digest": task_digest,
        "change_class": change_class.value,
        "requirements": [
            {
                "requirement_id": req.requirement_id,
                "statement": req.statement,
                "citation": req.citation,
            }
            for req in requirements
        ],
    }
    encoded = json.dumps(canonical_repr, sort_keys=True, separators=(",", ":")).encode("utf-8")
    return hashlib.sha256(encoded).hexdigest()


def assign_deterministic_requirement_ids(
    requirements: Sequence[ProposedRequirement | AcceptanceRequirement | str],
    prefix: str = "REQ",
) -> list[ValidatedRequirement]:
    """Deterministically assign sequential requirement IDs (e.g. REQ-01, REQ-02)."""
    validated: list[ValidatedRequirement] = []
    for idx, item in enumerate(requirements, start=1):
        req_id = f"{prefix}-{idx:02d}"
        if isinstance(item, ProposedRequirement):
            validated.append(
                ValidatedRequirement(
                    requirement_id=req_id,
                    statement=item.statement,
                    citation=item.citation,
                    citation_span=(item.citation_start, item.citation_end),
                )
            )
        elif isinstance(item, AcceptanceRequirement):
            validated.append(
                ValidatedRequirement(
                    requirement_id=req_id,
                    statement=item.statement,
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
            raise TypeError(f"Unsupported requirement item type: {type(item).__name__}")
    return validated


def _check_forbidden_actions(req: ValidatedRequirement) -> None:
    """Check a single requirement statement against forbidden action rules."""
    text = req.statement
    for rule_id, pattern, explanation in _FORBIDDEN_ACTION_RULES:
        if pattern.search(text):
            safe_detail = redact_log_text(f"{explanation} (matched rule {rule_id})")
            raise ForbiddenActionViolationError(
                rule_id=rule_id,
                requirement_id=req.requirement_id,
                detail=safe_detail,
            )


def _check_contradictions(
    requirements: Sequence[ValidatedRequirement],
    change_class: ChangeClass,
) -> None:
    """Check for logical contradictions within requirements and against change class."""
    # 1. Intra-requirement pairwise contradiction check
    for concept, pos_pat, neg_pat in _CONTRADICTION_PATTERNS:
        pos_reqs = [r for r in requirements if pos_pat.search(r.statement)]
        neg_reqs = [r for r in requirements if neg_pat.search(r.statement)]
        if pos_reqs and neg_reqs:
            p_id = pos_reqs[0].requirement_id
            n_id = neg_reqs[0].requirement_id
            raise ContradictoryRequirementsError(
                f"Contradictory requirements detected for concept '{concept}': "
                f"'{p_id}' conflicts with '{n_id}'."
            )

    # 2. Check for conflicting HTTP status codes for same condition
    http_pattern = re.compile(r"(?i)\b(?:return|status code|response)\s+(?:HTTP\s+)?(\d{3})\b")
    for r in requirements:
        matches = http_pattern.findall(r.statement)
        if len(matches) > 1 and len(set(matches)) > 1:
            codes_str = ", ".join(matches)
            raise ContradictoryRequirementsError(
                f"Requirement '{r.requirement_id}' contains contradictory "
                f"status codes: [{codes_str}]."
            )

    # 3. Contradictions against ChangeClass laws
    if change_class == ChangeClass.REFACTOR:
        # Refactor law: BASE=EQUIVALENT, CANDIDATE=EQUIVALENT.
        # Demanding behavioral changes or breaking changes contradicts refactor semantics.
        refactor_violation_pattern = re.compile(
            r"(?i)\b(?:change (?:external |api |public )?behavior|"
            r"breaking change|remove public (?:api|method|endpoint)|"
            r"add new (?:endpoint|feature|api))\b"
        )
        for r in requirements:
            if refactor_violation_pattern.search(r.statement):
                raise ContradictoryRequirementsError(
                    f"Requirement '{r.requirement_id}' demands observable behavioral/API change, "
                    f"which contradicts REFACTOR semantics (requires equivalence)."
                )


def validate_contract(
    requirements: Sequence[ValidatedRequirement | ProposedRequirement | AcceptanceRequirement],
    task: NormalizedTask,
    change_class: ChangeClass,
) -> ValidatedContract:
    """Deterministically validate requirement IDs, scope, forbidden actions, and contradictions.

    Validation pipeline:
    1. Count boundaries: MIN_REQUIREMENTS_COUNT <= count <= MAX_REQUIREMENTS_COUNT.
    2. Convert/validate individual ValidatedRequirement instances.
    3. Requirement ID uniqueness check.
    4. Forbidden action checks on every requirement statement.
    5. Contradiction checks (intra-requirement and against ChangeClass).
    6. Deterministic contract digest computation.

    Returns:
        ValidatedContract ready for review and downstream compilation.
    """
    if not isinstance(task, NormalizedTask):
        raise TypeError(f"task must be NormalizedTask, got {type(task).__name__}")
    if not isinstance(change_class, ChangeClass):
        raise TypeError(f"change_class must be ChangeClass, got {type(change_class).__name__}")

    if not requirements:
        raise ContractScopeExceededError("Contract must contain at least one requirement")

    if len(requirements) < MIN_REQUIREMENTS_COUNT:
        raise ContractScopeExceededError(
            f"Requirements count {len(requirements)} is below minimum {MIN_REQUIREMENTS_COUNT}"
        )

    if len(requirements) > MAX_REQUIREMENTS_COUNT:
        raise ContractScopeExceededError(
            f"Requirements count {len(requirements)} exceeds ceiling {MAX_REQUIREMENTS_COUNT}"
        )

    # Normalize to ValidatedRequirement instances
    validated_list: list[ValidatedRequirement] = []
    seen_ids: set[str] = set()

    for idx, item in enumerate(requirements):
        if isinstance(item, ValidatedRequirement):
            val_req = item
        elif isinstance(item, ProposedRequirement):
            req_id = f"REQ-{idx + 1:02d}"
            val_req = ValidatedRequirement(
                requirement_id=req_id,
                statement=item.statement,
                citation=item.citation,
                citation_span=(item.citation_start, item.citation_end),
            )
        elif isinstance(item, AcceptanceRequirement):
            val_req = ValidatedRequirement(
                requirement_id=item.requirement_id,
                statement=item.statement,
            )
        else:
            raise TypeError(f"Requirement at index {idx} has invalid type {type(item).__name__}")

        # ID uniqueness check
        if val_req.requirement_id in seen_ids:
            raise DuplicateRequirementIdError(
                f"Duplicate requirement_id detected: '{val_req.requirement_id}'"
            )
        seen_ids.add(val_req.requirement_id)

        # Forbidden action check
        _check_forbidden_actions(val_req)

        validated_list.append(val_req)

    # Sort requirements stably by requirement_id for deterministic representation
    validated_sorted = tuple(sorted(validated_list, key=lambda r: r.requirement_id))

    # Contradiction check
    _check_contradictions(validated_sorted, change_class)

    # Compute deterministic contract digest
    contract_digest = _compute_contract_digest(
        task_digest=task.task_digest,
        change_class=change_class,
        requirements=validated_sorted,
    )

    return ValidatedContract(
        task_digest=task.task_digest,
        change_class=change_class,
        requirements=validated_sorted,
        contract_digest=contract_digest,
    )
