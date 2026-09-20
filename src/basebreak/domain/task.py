"""Engineering task and acceptance requirement domain contracts.

Carries deterministic engineering intent sufficient for contract compilation
without embedding model output or unstructured dictionaries as authority.
"""

from __future__ import annotations

from collections.abc import Sequence
from dataclasses import dataclass


@dataclass(frozen=True, slots=True)
class AcceptanceRequirement:
    """Deterministic acceptance requirement for an engineering task.

    Carries an immutable requirement identifier and precise requirement statement.
    """

    requirement_id: str
    statement: str

    def __post_init__(self) -> None:
        if not isinstance(self.requirement_id, str):
            tname = type(self.requirement_id).__name__
            raise TypeError(f"requirement_id must be a string, got {tname}")
        req_id = self.requirement_id.strip()
        if not req_id:
            raise ValueError("requirement_id must not be empty")
        if req_id != self.requirement_id:
            raise ValueError("requirement_id must not contain leading or trailing whitespace")

        if not isinstance(self.statement, str):
            tname = type(self.statement).__name__
            raise TypeError(f"statement must be a string, got {tname}")
        stmt = self.statement.strip()
        if not stmt:
            raise ValueError("statement must not be empty")
        if stmt != self.statement:
            raise ValueError("statement must not contain leading or trailing whitespace")


@dataclass(frozen=True, slots=True)
class EngineeringTask:
    """Deterministic engineering task contract with immutable acceptance requirements.

    Represents verified engineering intent prior to Builder execution.
    Order of requirements is deterministically preserved. Duplicate requirement IDs
    are strictly rejected.
    """

    task_id: str
    title: str
    requirements: tuple[AcceptanceRequirement, ...]
    description: str = ""

    def __post_init__(self) -> None:
        if not isinstance(self.task_id, str):
            tname = type(self.task_id).__name__
            raise TypeError(f"task_id must be a string, got {tname}")
        tid = self.task_id.strip()
        if not tid:
            raise ValueError("task_id must not be empty")
        if tid != self.task_id:
            raise ValueError("task_id must not contain leading or trailing whitespace")

        if not isinstance(self.title, str):
            tname = type(self.title).__name__
            raise TypeError(f"title must be a string, got {tname}")
        t = self.title.strip()
        if not t:
            raise ValueError("title must not be empty")
        if t != self.title:
            raise ValueError("title must not contain leading or trailing whitespace")

        if not isinstance(self.description, str):
            tname = type(self.description).__name__
            raise TypeError(f"description must be a string, got {tname}")

        # Ensure requirements is an immutable tuple
        if not isinstance(self.requirements, tuple):
            if isinstance(self.requirements, Sequence):
                object.__setattr__(self, "requirements", tuple(self.requirements))
            else:
                tname = type(self.requirements).__name__
                raise TypeError(f"requirements must be a sequence, got {tname}")

        seen_ids: set[str] = set()
        for idx, req in enumerate(self.requirements):
            if not isinstance(req, AcceptanceRequirement):
                tname = type(req).__name__
                raise TypeError(
                    f"requirement at index {idx} must be AcceptanceRequirement, got {tname}"
                )
            if req.requirement_id in seen_ids:
                raise ValueError(
                    f"Duplicate requirement_id detected in task: {req.requirement_id!r}"
                )
            seen_ids.add(req.requirement_id)

    @property
    def requirement_ids(self) -> tuple[str, ...]:
        """Ordered tuple of requirement IDs."""
        return tuple(req.requirement_id for req in self.requirements)

    def get_requirement(self, requirement_id: str) -> AcceptanceRequirement | None:
        """Lookup an acceptance requirement by its identifier."""
        for req in self.requirements:
            if req.requirement_id == requirement_id:
                return req
        return None
