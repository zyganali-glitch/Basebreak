"""Deterministic verification contract review session and primitives.

P-06.05: Human-editable contract review surface under the Basebreak causal
verification authority model.

Authority Model:
1. P-06.04 validator remains final deterministic authority over:
   - requirement IDs;
   - citation/span binding;
   - scope;
   - protected surfaces;
   - forbidden actions;
   - contradictions;
   - resolved change semantics.
2. Human review MUST NOT bypass P-06.01-P-06.04 authority.
3. ValidatedContract.from_dict()/from_json() is serialization only;
   any human-edited requirement content MUST go back through validate_contract().
4. Requirement IDs are content-derived: editing statement or citation
   re-derives canonical ID via P-06.04; stale old IDs cannot retain authority.
5. Task identity and canonical change semantics are IMMUTABLE during review.
6. Approval means READY_FOR_FREEZE (ready for P-06.06); it does NOT freeze.
7. ABSOLUTE P-06.06 BOUNDARY:
   Zero final contract digest! No contract_digest, validation_digest,
   frozen_digest, builder_digest, or evidence_root_digest.
8. Zero model calls, zero provider imports, zero sandbox calls, zero network calls.
"""

from __future__ import annotations

import json
from collections.abc import Mapping, Sequence
from dataclasses import dataclass
from enum import Enum
from typing import Any

from basebreak.compiler.ingestion import NormalizedTask
from basebreak.compiler.requirements import ProposedRequirement
from basebreak.compiler.semantics import (
    CertaintyLevel,
    ChangeSemanticsClassification,
)
from basebreak.compiler.validator import (
    ContractValidationError,
    UnresolvedChangeClassError,
    ValidatedContract,
    ValidatedRequirement,
    derive_requirement_id,
    validate_contract,
)
from basebreak.security.protected_surfaces import (
    ProtectedSurfaceManifest,
    get_canonical_basebreak_protected_manifest,
)
from basebreak.security.secret_policy import redact_log_text

# Bounded forbidden field names from P-06.06 and future phases
FORBIDDEN_P0606_FIELDS: frozenset[str] = frozenset(
    {
        "contract_digest",
        "validation_digest",
        "frozen_digest",
        "builder_digest",
        "evidence_root_digest",
    }
)


class ReviewDecision(str, Enum):
    """Explicit bounded decision for reviewed contract draft."""

    APPROVED = "APPROVED"
    REJECTED = "REJECTED"


class ReviewStatus(str, Enum):
    """Lifecycle status of a review artifact."""

    DRAFT = "DRAFT"
    READY_FOR_FREEZE = "READY_FOR_FREEZE"
    REJECTED = "REJECTED"


class ReviewExitCode(int, Enum):
    """Deterministic, stable CLI exit codes."""

    SUCCESS = 0
    VALIDATION_ERROR = 1
    SCHEMA_ERROR = 2
    INVALID_OPERATION = 3
    SEMANTICS_UNRESOLVED = 4
    IO_ERROR = 5


class ReviewError(Exception):
    """Base exception for review errors."""


class ReviewSchemaError(ReviewError):
    """Raised when review bundle or review result schema is malformed or invalid."""


class ReviewOperationError(ReviewError):
    """Raised when an edit operation violates constraints (e.g. index out of range)."""


class ReviewApprovalError(ReviewError):
    """Raised when approval fails due to invalid contract or unresolved semantics."""


@dataclass(frozen=True, slots=True)
class ReviewBundle:
    """Authoritative source information bundle for deterministic review.

    Carries immutable task identity, canonical change semantics,
    and editable acceptance requirement proposals.
    """

    task: NormalizedTask
    semantics: ChangeSemanticsClassification
    requirements: tuple[ProposedRequirement, ...]

    def __post_init__(self) -> None:
        if not isinstance(self.task, NormalizedTask):
            raise TypeError(f"task must be NormalizedTask, got {type(self.task).__name__}")
        if not isinstance(self.semantics, ChangeSemanticsClassification):
            raise TypeError(
                "semantics must be ChangeSemanticsClassification, "
                f"got {type(self.semantics).__name__}"
            )
        if not isinstance(self.requirements, tuple):
            if isinstance(self.requirements, Sequence) and not isinstance(
                self.requirements, (str, bytes)
            ):
                object.__setattr__(self, "requirements", tuple(self.requirements))
            else:
                raise TypeError(
                    "requirements must be tuple of ProposedRequirement, "
                    f"got {type(self.requirements).__name__}"
                )

        for idx, req in enumerate(self.requirements):
            if not isinstance(req, ProposedRequirement):
                raise TypeError(
                    f"requirement at index {idx} must be ProposedRequirement, "
                    f"got {type(req).__name__}"
                )

        # Invariant: task digest must match between task and semantics
        if self.task.task_digest != self.semantics.task_digest:
            raise ValueError(
                f"task_digest mismatch between task ({self.task.task_digest}) "
                f"and semantics ({self.semantics.task_digest})"
            )

    def to_dict(self) -> dict[str, Any]:
        """Deterministic dictionary serialization with sorted keys."""
        return {
            "requirements": [r.to_dict() for r in self.requirements],
            "semantics": self.semantics.to_dict(),
            "task": self.task.to_dict(),
        }

    def to_json(self) -> str:
        """Deterministic JSON string serialization with 2-space indentation."""
        return json.dumps(self.to_dict(), indent=2, sort_keys=True)

    @classmethod
    def from_dict(cls, data: Mapping[str, Any]) -> ReviewBundle:
        """Construct from dictionary with strict schema validation without coercion."""
        if not isinstance(data, Mapping):
            raise ReviewSchemaError(f"Expected mapping for ReviewBundle, got {type(data).__name__}")

        # Strict schema: reject forbidden P-06.06 fields
        for forbidden in FORBIDDEN_P0606_FIELDS:
            if forbidden in data:
                raise ReviewSchemaError(
                    f"Forbidden P-06.06 digest field '{forbidden}' "
                    "must not be present in ReviewBundle"
                )

        required_keys = {"task", "semantics", "requirements"}
        data_keys = set(data.keys())
        missing = required_keys - data_keys
        if missing:
            raise ReviewSchemaError(f"Missing required fields for ReviewBundle: {sorted(missing)}")

        unknown = data_keys - required_keys
        if unknown:
            raise ReviewSchemaError(f"Unknown fields in ReviewBundle: {sorted(unknown)}")

        raw_task = data["task"]
        if not isinstance(raw_task, Mapping):
            raise ReviewSchemaError(f"task must be mapping, got {type(raw_task).__name__}")
        try:
            task = NormalizedTask.from_dict(raw_task)
        except Exception as e:
            raise ReviewSchemaError(f"Failed to parse task: {e}") from e

        raw_semantics = data["semantics"]
        if not isinstance(raw_semantics, Mapping):
            raise ReviewSchemaError(
                f"semantics must be mapping, got {type(raw_semantics).__name__}"
            )
        try:
            semantics = ChangeSemanticsClassification.from_dict(raw_semantics)
        except Exception as e:
            raise ReviewSchemaError(f"Failed to parse semantics: {e}") from e

        raw_reqs = data["requirements"]
        if not isinstance(raw_reqs, (list, tuple)):
            raise ReviewSchemaError(
                f"requirements must be list or tuple, got {type(raw_reqs).__name__}"
            )

        requirements: list[ProposedRequirement] = []
        for idx, item in enumerate(raw_reqs):
            if not isinstance(item, Mapping):
                raise ReviewSchemaError(
                    f"requirement at index {idx} must be mapping, got {type(item).__name__}"
                )
            for forbidden in FORBIDDEN_P0606_FIELDS:
                if forbidden in item:
                    raise ReviewSchemaError(
                        f"Forbidden P-06.06 digest field '{forbidden}' in requirement {idx}"
                    )
            try:
                # If a stale requirement_id is present, it is intentionally not accepted
                # into ProposedRequirement authority; ProposedRequirement only takes statement,
                # citation, citation_start, citation_end, rationale.
                req = ProposedRequirement.from_dict(item)
                requirements.append(req)
            except Exception as e:
                raise ReviewSchemaError(f"Failed to parse requirement at index {idx}: {e}") from e

        return cls(
            task=task,
            semantics=semantics,
            requirements=tuple(requirements),
        )

    @classmethod
    def from_json(cls, json_str: str) -> ReviewBundle:
        """Construct from JSON string with strict schema validation."""
        if not isinstance(json_str, str):
            raise TypeError(f"json_str must be str, got {type(json_str).__name__}")
        try:
            data = json.loads(json_str)
        except json.JSONDecodeError as e:
            raise ReviewSchemaError(f"Invalid JSON for ReviewBundle: {e}") from e
        return cls.from_dict(data)


@dataclass(frozen=True, slots=True)
class ReviewResult:
    """Deterministic result of human contract review.

    Records the human decision, the deterministically validated contract
    (if approved), and optional reviewer note.

    ABSOLUTE P-06.06 INVARIANT:
    Zero final contract digest! This class does NOT compute or carry
    contract_digest, validation_digest, frozen_digest, builder_digest,
    or evidence_root_digest.
    """

    decision: ReviewDecision
    status: ReviewStatus
    task_digest: str
    contract: ValidatedContract | None
    reviewer_note: str = ""
    audit_trail: tuple[str, ...] = ()

    def __post_init__(self) -> None:
        if not isinstance(self.decision, ReviewDecision):
            raise TypeError(f"decision must be ReviewDecision, got {type(self.decision).__name__}")
        if not isinstance(self.status, ReviewStatus):
            raise TypeError(f"status must be ReviewStatus, got {type(self.status).__name__}")
        if not isinstance(self.task_digest, str) or not self.task_digest:
            raise ValueError("task_digest must be a non-empty string")
        if not isinstance(self.reviewer_note, str):
            raise TypeError(f"reviewer_note must be str, got {type(self.reviewer_note).__name__}")
        if not isinstance(self.audit_trail, tuple):
            if isinstance(self.audit_trail, Sequence) and not isinstance(
                self.audit_trail, (str, bytes)
            ):
                object.__setattr__(self, "audit_trail", tuple(self.audit_trail))
            else:
                raise TypeError(
                    f"audit_trail must be tuple of str, got {type(self.audit_trail).__name__}"
                )
        for item in self.audit_trail:
            if not isinstance(item, str):
                raise TypeError(f"audit_trail items must be str, got {type(item).__name__}")

        if self.decision == ReviewDecision.APPROVED:
            if self.status != ReviewStatus.READY_FOR_FREEZE:
                raise ValueError(
                    f"status must be READY_FOR_FREEZE when decision is APPROVED, got {self.status}"
                )
            if self.contract is None:
                raise ValueError("contract must not be None when decision is APPROVED")
            if not isinstance(self.contract, ValidatedContract):
                raise TypeError(
                    f"contract must be ValidatedContract, got {type(self.contract).__name__}"
                )
            if self.contract.task_digest != self.task_digest:
                raise ValueError(
                    f"contract.task_digest ({self.contract.task_digest}) does not match "
                    f"task_digest ({self.task_digest})"
                )

        elif self.decision == ReviewDecision.REJECTED:
            if self.status != ReviewStatus.REJECTED:
                raise ValueError(
                    f"status must be REJECTED when decision is REJECTED, got {self.status}"
                )
            if self.contract is not None:
                raise ValueError("contract must be None when decision is REJECTED")

    @property
    def is_ready_for_freeze(self) -> bool:
        """Returns True if the contract was approved and is ready for P-06.06 freezing."""
        return (
            self.decision == ReviewDecision.APPROVED
            and self.status == ReviewStatus.READY_FOR_FREEZE
            and self.contract is not None
        )

    def to_dict(self) -> dict[str, Any]:
        """Deterministic dictionary serialization with sorted keys."""
        return {
            "audit_trail": list(self.audit_trail),
            "contract": self.contract.to_dict() if self.contract is not None else None,
            "decision": self.decision.value,
            "reviewer_note": self.reviewer_note,
            "status": self.status.value,
            "task_digest": self.task_digest,
        }

    def to_json(self) -> str:
        """Deterministic JSON string serialization with 2-space indentation."""
        return json.dumps(self.to_dict(), indent=2, sort_keys=True)

    @classmethod
    def from_dict(cls, data: Mapping[str, Any]) -> ReviewResult:
        """Construct from dictionary with strict schema validation."""
        if not isinstance(data, Mapping):
            raise ReviewSchemaError(f"Expected mapping for ReviewResult, got {type(data).__name__}")

        # Strict schema: reject forbidden P-06.06 fields
        for forbidden in FORBIDDEN_P0606_FIELDS:
            if forbidden in data:
                raise ReviewSchemaError(
                    f"Forbidden P-06.06 digest field '{forbidden}' "
                    "must not be present in ReviewResult"
                )

        required_keys = {"decision", "status", "task_digest", "contract"}
        missing = required_keys - set(data.keys())
        if missing:
            raise ReviewSchemaError(f"Missing required fields for ReviewResult: {sorted(missing)}")

        unknown = set(data.keys()) - (required_keys | {"reviewer_note", "audit_trail"})
        if unknown:
            raise ReviewSchemaError(f"Unknown fields in ReviewResult: {sorted(unknown)}")

        raw_decision = data["decision"]
        if not isinstance(raw_decision, str):
            raise ReviewSchemaError(f"decision must be str, got {type(raw_decision).__name__}")
        try:
            decision = ReviewDecision(raw_decision)
        except ValueError:
            raise ReviewSchemaError(f"Invalid ReviewDecision: {raw_decision!r}") from None

        raw_status = data["status"]
        if not isinstance(raw_status, str):
            raise ReviewSchemaError(f"status must be str, got {type(raw_status).__name__}")
        try:
            status = ReviewStatus(raw_status)
        except ValueError:
            raise ReviewSchemaError(f"Invalid ReviewStatus: {raw_status!r}") from None

        raw_td = data["task_digest"]
        if not isinstance(raw_td, str):
            raise ReviewSchemaError(f"task_digest must be str, got {type(raw_td).__name__}")

        raw_contract = data["contract"]
        contract: ValidatedContract | None = None
        if raw_contract is not None:
            if not isinstance(raw_contract, Mapping):
                raise ReviewSchemaError(
                    f"contract must be mapping or None, got {type(raw_contract).__name__}"
                )
            try:
                contract = ValidatedContract.from_dict(raw_contract)
            except Exception as e:
                raise ReviewSchemaError(f"Failed to parse contract: {e}") from e

        raw_note = data.get("reviewer_note", "")
        if not isinstance(raw_note, str):
            raise ReviewSchemaError(f"reviewer_note must be str, got {type(raw_note).__name__}")

        raw_audit = data.get("audit_trail", ())
        if not isinstance(raw_audit, (list, tuple)):
            raise ReviewSchemaError(
                f"audit_trail must be list or tuple, got {type(raw_audit).__name__}"
            )
        audit_trail: list[str] = []
        for item in raw_audit:
            if not isinstance(item, str):
                raise ReviewSchemaError(f"audit_trail item must be str, got {type(item).__name__}")
            audit_trail.append(item)

        return cls(
            decision=decision,
            status=status,
            task_digest=raw_td,
            contract=contract,
            reviewer_note=raw_note,
            audit_trail=tuple(audit_trail),
        )

    @classmethod
    def from_json(cls, json_str: str) -> ReviewResult:
        """Construct from JSON string with strict schema validation."""
        if not isinstance(json_str, str):
            raise TypeError(f"json_str must be str, got {type(json_str).__name__}")
        try:
            data = json.loads(json_str)
        except json.JSONDecodeError as e:
            raise ReviewSchemaError(f"Invalid JSON for ReviewResult: {e}") from e
        return cls.from_dict(data)


class ReviewSession:
    """Deterministic review session managing local edits and P-06.04 revalidation.

    Preserves immutable task identity and canonical change semantics.
    Enforces deterministic requirement ID derivation upon any edit.
    """

    def __init__(
        self,
        bundle: ReviewBundle,
        audit_trail: Sequence[str] = (),
    ) -> None:
        if not isinstance(bundle, ReviewBundle):
            raise TypeError(f"bundle must be ReviewBundle, got {type(bundle).__name__}")

        self._task: NormalizedTask = bundle.task
        self._semantics: ChangeSemanticsClassification = bundle.semantics
        self._requirements: list[ProposedRequirement] = list(bundle.requirements)
        self._audit_trail: list[str] = list(audit_trail)

    @property
    def task(self) -> NormalizedTask:
        """Immutable normalized task."""
        return self._task

    @property
    def semantics(self) -> ChangeSemanticsClassification:
        """Immutable canonical change semantics."""
        return self._semantics

    @property
    def requirements(self) -> tuple[ProposedRequirement, ...]:
        """Current requirement proposals."""
        return tuple(self._requirements)

    @property
    def audit_trail(self) -> tuple[str, ...]:
        """Audit trail of edits performed in this session."""
        return tuple(self._audit_trail)

    def to_bundle(self) -> ReviewBundle:
        """Export current session state back to a ReviewBundle."""
        return ReviewBundle(
            task=self._task,
            semantics=self._semantics,
            requirements=tuple(self._requirements),
        )

    def inspect_summary(self) -> dict[str, Any]:
        """Return a structured summary of the current session state."""
        return {
            "task_digest": self._task.task_digest,
            "raw_digest": self._task.raw_digest,
            "character_count": self._task.character_count,
            "line_count": self._task.line_count,
            "byte_length": self._task.byte_length,
            "safe_summary": self._task.safe_summary(),
            "change_class": (
                self._semantics.change_class.value
                if self._semantics.change_class is not None
                else None
            ),
            "certainty": self._semantics.certainty.value,
            "confidence": self._semantics.confidence,
            "semantics_rationale": redact_log_text(self._semantics.rationale),
            "requirements_count": len(self._requirements),
        }

    def get_requirements_display(self) -> list[dict[str, Any]]:
        """Return human-inspectable list of requirements with derived IDs.

        Deterministic ordering is derived from the content-addressed requirement IDs.
        """
        display_items: list[dict[str, Any]] = []
        for idx, req in enumerate(self._requirements):
            derived_id = derive_requirement_id(
                req.statement, req.citation, req.citation_start, req.citation_end
            )
            display_items.append(
                {
                    "index": idx,
                    "requirement_id": derived_id,
                    "statement": redact_log_text(req.statement),
                    "citation": redact_log_text(req.citation),
                    "citation_start": req.citation_start,
                    "citation_end": req.citation_end,
                    "rationale": redact_log_text(req.rationale),
                }
            )
        return display_items

    def _check_index(self, index: int) -> None:
        """Verify that index is a valid non-negative integer within bounds."""
        if isinstance(index, bool) or not isinstance(index, int):
            raise ReviewOperationError(f"index must be int (not bool), got {type(index).__name__}")
        if index < 0 or index >= len(self._requirements):
            raise ReviewOperationError(
                f"Requirement index {index} out of range (0..{max(0, len(self._requirements) - 1)})"
            )

    def edit_statement(self, index: int, new_statement: str) -> None:
        """Edit the statement of requirement at index."""
        self._check_index(index)
        if not isinstance(new_statement, str):
            raise ReviewOperationError(
                f"new_statement must be str, got {type(new_statement).__name__}"
            )
        stmt = new_statement.strip()
        if not stmt:
            raise ReviewOperationError("statement must not be empty or whitespace-only")

        cur = self._requirements[index]
        self._requirements[index] = ProposedRequirement(
            statement=stmt,
            citation=cur.citation,
            citation_start=cur.citation_start,
            citation_end=cur.citation_end,
            rationale=cur.rationale,
        )
        self._audit_trail.append(f"edit_statement(index={index})")

    def edit_rationale(self, index: int, new_rationale: str) -> None:
        """Edit the rationale of requirement at index."""
        self._check_index(index)
        if not isinstance(new_rationale, str):
            raise ReviewOperationError(
                f"new_rationale must be str, got {type(new_rationale).__name__}"
            )

        cur = self._requirements[index]
        self._requirements[index] = ProposedRequirement(
            statement=cur.statement,
            citation=cur.citation,
            citation_start=cur.citation_start,
            citation_end=cur.citation_end,
            rationale=new_rationale.strip(),
        )
        self._audit_trail.append(f"edit_rationale(index={index})")

    def edit_citation(
        self,
        index: int,
        new_citation: str,
        citation_start: int,
        citation_end: int,
    ) -> None:
        """Edit citation and its exact span offsets together.

        Citation text and its start/end offsets must be edited together to maintain
        invariant source binding.
        """
        self._check_index(index)
        if not isinstance(new_citation, str):
            raise ReviewOperationError(
                f"new_citation must be str, got {type(new_citation).__name__}"
            )
        if isinstance(citation_start, bool) or not isinstance(citation_start, int):
            raise ReviewOperationError(
                f"citation_start must be int (not bool), got {type(citation_start).__name__}"
            )
        if isinstance(citation_end, bool) or not isinstance(citation_end, int):
            raise ReviewOperationError(
                f"citation_end must be int (not bool), got {type(citation_end).__name__}"
            )
        if citation_start < 0 or citation_end < citation_start:
            raise ReviewOperationError(f"Invalid citation span: [{citation_start}:{citation_end}]")

        cit = new_citation.strip()
        if not cit:
            raise ReviewOperationError("citation must not be empty or whitespace-only")

        cur = self._requirements[index]
        self._requirements[index] = ProposedRequirement(
            statement=cur.statement,
            citation=cit,
            citation_start=citation_start,
            citation_end=citation_end,
            rationale=cur.rationale,
        )
        self._audit_trail.append(
            f"edit_citation(index={index}, span=[{citation_start}:{citation_end}])"
        )

    def edit_requirement(
        self,
        index: int,
        *,
        statement: str | None = None,
        rationale: str | None = None,
        citation: str | None = None,
        citation_start: int | None = None,
        citation_end: int | None = None,
    ) -> None:
        """Edit one or more fields of a requirement at index.

        If citation is edited, citation_start and citation_end MUST both be provided.
        """
        self._check_index(index)
        cur = self._requirements[index]

        new_stmt = statement if statement is not None else cur.statement
        new_rat = rationale if rationale is not None else cur.rationale

        if citation is not None:
            if citation_start is None or citation_end is None:
                raise ReviewOperationError(
                    "When editing citation, citation_start and citation_end must both be provided"
                )
            new_cit = citation
            new_start = citation_start
            new_end = citation_end
        else:
            if citation_start is not None or citation_end is not None:
                raise ReviewOperationError(
                    "citation_start and citation_end cannot be edited without providing citation"
                )
            new_cit = cur.citation
            new_start = cur.citation_start
            new_end = cur.citation_end

        if not isinstance(new_stmt, str) or not new_stmt.strip():
            raise ReviewOperationError("statement must not be empty or whitespace-only")
        if not isinstance(new_cit, str) or not new_cit.strip():
            raise ReviewOperationError("citation must not be empty or whitespace-only")
        if isinstance(new_start, bool) or not isinstance(new_start, int):
            raise ReviewOperationError("citation_start must be int")
        if isinstance(new_end, bool) or not isinstance(new_end, int):
            raise ReviewOperationError("citation_end must be int")
        if new_start < 0 or new_end < new_start:
            raise ReviewOperationError(f"Invalid citation span: [{new_start}:{new_end}]")

        self._requirements[index] = ProposedRequirement(
            statement=new_stmt.strip(),
            citation=new_cit.strip(),
            citation_start=new_start,
            citation_end=new_end,
            rationale=new_rat.strip() if isinstance(new_rat, str) else "",
        )
        self._audit_trail.append(f"edit_requirement(index={index})")

    def add_requirement(
        self,
        statement: str,
        citation: str,
        citation_start: int,
        citation_end: int,
        rationale: str = "",
    ) -> None:
        """Add a new proposed requirement to the review draft."""
        if not isinstance(statement, str):
            raise ReviewOperationError(f"statement must be str, got {type(statement).__name__}")
        stmt = statement.strip()
        if not stmt:
            raise ReviewOperationError("statement must not be empty or whitespace-only")

        if not isinstance(citation, str):
            raise ReviewOperationError(f"citation must be str, got {type(citation).__name__}")
        cit = citation.strip()
        if not cit:
            raise ReviewOperationError("citation must not be empty or whitespace-only")

        if isinstance(citation_start, bool) or not isinstance(citation_start, int):
            raise ReviewOperationError(
                f"citation_start must be int, got {type(citation_start).__name__}"
            )
        if isinstance(citation_end, bool) or not isinstance(citation_end, int):
            raise ReviewOperationError(
                f"citation_end must be int, got {type(citation_end).__name__}"
            )
        if citation_start < 0 or citation_end < citation_start:
            raise ReviewOperationError(f"Invalid citation span: [{citation_start}:{citation_end}]")

        if not isinstance(rationale, str):
            raise ReviewOperationError(f"rationale must be str, got {type(rationale).__name__}")

        req = ProposedRequirement(
            statement=stmt,
            citation=cit,
            citation_start=citation_start,
            citation_end=citation_end,
            rationale=rationale.strip(),
        )
        self._requirements.append(req)
        self._audit_trail.append(f"add_requirement(index={len(self._requirements) - 1})")

    def remove_requirement(self, index: int) -> None:
        """Remove requirement at index."""
        self._check_index(index)
        removed = self._requirements.pop(index)
        derived_id = derive_requirement_id(
            removed.statement, removed.citation, removed.citation_start, removed.citation_end
        )
        self._audit_trail.append(f"remove_requirement(index={index}, id={derived_id})")

    def revalidate(
        self,
        manifest: ProtectedSurfaceManifest | None = None,
    ) -> ValidatedContract:
        """Revalidate current draft requirements against P-06.04 authority.

        CRITICAL: Converts all current requirements to ProposedRequirement representation
        so that P-06.04 deterministically re-derives all requirement IDs and validates
        scope, protected surfaces, forbidden actions, and contradictions.

        Raises:
            ContractValidationError: if validation fails.
            UnresolvedChangeClassError: if semantics certainty is AMBIGUOUS or UNKNOWN.
        """
        active_manifest = (
            manifest if manifest is not None else get_canonical_basebreak_protected_manifest()
        )
        return validate_contract(
            task=self._task,
            requirements=tuple(self._requirements),
            change_class=self._semantics,
            allow_derivation=True,
            manifest=active_manifest,
        )

    def approve(
        self,
        reviewer_note: str = "",
        manifest: ProtectedSurfaceManifest | None = None,
    ) -> ReviewResult:
        """Deterministically validate and approve reviewed contract draft.

        Approval is ONLY permitted if P-06.04 validate_contract succeeds completely.
        Produces ReviewResult with READY_FOR_FREEZE status for P-06.06.

        Raises:
            ReviewApprovalError: if revalidation fails.
            UnresolvedChangeClassError: if change semantics are AMBIGUOUS or UNKNOWN.
        """
        if not isinstance(reviewer_note, str):
            raise TypeError(f"reviewer_note must be str, got {type(reviewer_note).__name__}")

        # Fail closed on unresolved change semantics
        if self._semantics.certainty in (CertaintyLevel.AMBIGUOUS, CertaintyLevel.UNKNOWN):
            raise UnresolvedChangeClassError(
                "Cannot approve contract: change semantics certainty is "
                f"{self._semantics.certainty.value!r}"
            )
        if self._semantics.change_class is None:
            raise UnresolvedChangeClassError(
                "Cannot approve contract: authoritative change_class is None"
            )

        try:
            validated_contract = self.revalidate(manifest=manifest)
        except (ContractValidationError, ValueError, TypeError) as e:
            safe_detail = redact_log_text(str(e))
            raise ReviewApprovalError(
                f"Approval rejected: revalidation failed: {safe_detail}"
            ) from e

        return ReviewResult(
            decision=ReviewDecision.APPROVED,
            status=ReviewStatus.READY_FOR_FREEZE,
            task_digest=self._task.task_digest,
            contract=validated_contract,
            reviewer_note=reviewer_note,
            audit_trail=tuple(self._audit_trail),
        )

    def reject(self, reviewer_note: str = "") -> ReviewResult:
        """Reject the contract draft.

        Produces ReviewResult with REJECTED status and None contract.
        Cannot be used as ready for freeze.
        """
        if not isinstance(reviewer_note, str):
            raise TypeError(f"reviewer_note must be str, got {type(reviewer_note).__name__}")

        return ReviewResult(
            decision=ReviewDecision.REJECTED,
            status=ReviewStatus.REJECTED,
            task_digest=self._task.task_digest,
            contract=None,
            reviewer_note=reviewer_note,
            audit_trail=tuple(self._audit_trail),
        )


def create_review_bundle(
    task: NormalizedTask,
    semantics: ChangeSemanticsClassification,
    requirements: Sequence[ProposedRequirement | ValidatedRequirement | Mapping[str, Any]],
) -> ReviewBundle:
    """Create a ReviewBundle from task, semantics, and requirement proposals."""
    if not isinstance(task, NormalizedTask):
        raise TypeError(f"task must be NormalizedTask, got {type(task).__name__}")
    if not isinstance(semantics, ChangeSemanticsClassification):
        raise TypeError(
            f"semantics must be ChangeSemanticsClassification, got {type(semantics).__name__}"
        )
    if not isinstance(requirements, Sequence) or isinstance(requirements, (str, bytes)):
        raise TypeError(f"requirements must be a sequence, got {type(requirements).__name__}")

    proposals: list[ProposedRequirement] = []
    for idx, item in enumerate(requirements):
        if isinstance(item, ProposedRequirement):
            proposals.append(item)
        elif isinstance(item, ValidatedRequirement):
            proposals.append(
                ProposedRequirement(
                    statement=item.statement,
                    citation=item.citation,
                    citation_start=item.citation_start,
                    citation_end=item.citation_end,
                    rationale=item.rationale,
                )
            )
        elif isinstance(item, Mapping):
            proposals.append(ProposedRequirement.from_dict(item))
        else:
            raise TypeError(
                f"requirement at index {idx} must be ProposedRequirement, "
                f"ValidatedRequirement, or Mapping, got {type(item).__name__}"
            )

    return ReviewBundle(
        task=task,
        semantics=semantics,
        requirements=tuple(proposals),
    )


def create_review_bundle_from_contract(
    task: NormalizedTask,
    semantics: ChangeSemanticsClassification,
    contract: ValidatedContract,
) -> ReviewBundle:
    """Create a ReviewBundle from an existing ValidatedContract alongside authoritative sources."""
    if not isinstance(contract, ValidatedContract):
        raise TypeError(f"contract must be ValidatedContract, got {type(contract).__name__}")
    if contract.task_digest != task.task_digest:
        raise ValueError(
            f"contract.task_digest ({contract.task_digest}) does not match "
            f"task.task_digest ({task.task_digest})"
        )
    return create_review_bundle(task, semantics, contract.requirements)
