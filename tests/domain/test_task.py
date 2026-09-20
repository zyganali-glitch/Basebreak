"""Focused tests for engineering task and acceptance-requirement contracts."""

from dataclasses import FrozenInstanceError

import pytest

from basebreak.domain.task import AcceptanceRequirement, EngineeringTask


class TestAcceptanceRequirement:
    """Tests for AcceptanceRequirement contract."""

    def test_valid_requirement(self) -> None:
        req = AcceptanceRequirement(
            requirement_id="REQ-001",
            statement="System must reject negative balance transfers.",
        )
        assert req.requirement_id == "REQ-001"
        assert req.statement == "System must reject negative balance transfers."

    @pytest.mark.parametrize("invalid_id", ["", "   ", " REQ-001", "REQ-001 "])
    def test_invalid_requirement_id_rejected(self, invalid_id: str) -> None:
        with pytest.raises(ValueError):
            AcceptanceRequirement(
                requirement_id=invalid_id,
                statement="Valid statement",
            )

    @pytest.mark.parametrize("invalid_stmt", ["", "   ", " statement ", "  "])
    def test_invalid_statement_rejected(self, invalid_stmt: str) -> None:
        with pytest.raises(ValueError):
            AcceptanceRequirement(
                requirement_id="REQ-001",
                statement=invalid_stmt,
            )

    def test_non_string_types_rejected(self) -> None:
        with pytest.raises(TypeError):
            AcceptanceRequirement(requirement_id=123, statement="valid")  # type: ignore[arg-type]
        with pytest.raises(TypeError):
            AcceptanceRequirement(requirement_id="REQ-001", statement=None)  # type: ignore[arg-type]

    def test_frozen_immutability(self) -> None:
        req = AcceptanceRequirement(requirement_id="REQ-001", statement="Initial")
        with pytest.raises(FrozenInstanceError):
            req.statement = "Modified"  # type: ignore[misc]


class TestEngineeringTask:
    """Tests for EngineeringTask contract."""

    def test_valid_task_construction(self) -> None:
        req1 = AcceptanceRequirement("REQ-1", "Base returns 400 on invalid token.")
        req2 = AcceptanceRequirement("REQ-2", "Candidate returns 200 on valid token.")
        task = EngineeringTask(
            task_id="TASK-42",
            title="Token validation bug fix",
            requirements=(req1, req2),
            description="Fix regression introduced in token authentication.",
        )
        assert task.task_id == "TASK-42"
        assert task.title == "Token validation bug fix"
        assert task.requirements == (req1, req2)
        assert task.description == "Fix regression introduced in token authentication."
        assert task.requirement_ids == ("REQ-1", "REQ-2")
        assert task.get_requirement("REQ-1") == req1
        assert task.get_requirement("REQ-2") == req2
        assert task.get_requirement("REQ-99") is None

    def test_multiple_ordered_requirements_preserved(self) -> None:
        reqs = tuple(AcceptanceRequirement(f"REQ-{i:03d}", f"Statement {i}") for i in range(10))
        task = EngineeringTask(
            task_id="TASK-ORDER",
            title="Preserve requirement ordering",
            requirements=reqs,
        )
        assert len(task.requirements) == 10
        for i in range(10):
            assert task.requirements[i].requirement_id == f"REQ-{i:03d}"
            assert task.requirements[i].statement == f"Statement {i}"
        assert task.requirement_ids == tuple(f"REQ-{i:03d}" for i in range(10))

    def test_duplicate_requirement_id_rejected(self) -> None:
        req1 = AcceptanceRequirement("REQ-DUPLICATE", "First statement.")
        req2 = AcceptanceRequirement("REQ-DUPLICATE", "Second statement with same ID.")
        with pytest.raises(ValueError, match="Duplicate requirement_id detected"):
            EngineeringTask(
                task_id="TASK-DUP",
                title="Duplicate test",
                requirements=(req1, req2),
            )

    @pytest.mark.parametrize("invalid_task_id", ["", "   ", " TASK-1", "TASK-1 "])
    def test_invalid_task_id_rejected(self, invalid_task_id: str) -> None:
        req = AcceptanceRequirement("REQ-1", "Valid")
        with pytest.raises(ValueError):
            EngineeringTask(
                task_id=invalid_task_id,
                title="Valid title",
                requirements=(req,),
            )

    @pytest.mark.parametrize("invalid_title", ["", "   ", " Title ", "  "])
    def test_invalid_title_rejected(self, invalid_title: str) -> None:
        req = AcceptanceRequirement("REQ-1", "Valid")
        with pytest.raises(ValueError):
            EngineeringTask(
                task_id="TASK-1",
                title=invalid_title,
                requirements=(req,),
            )

    def test_sequence_converted_to_immutable_tuple(self) -> None:
        req1 = AcceptanceRequirement("REQ-1", "Statement 1")
        req2 = AcceptanceRequirement("REQ-2", "Statement 2")
        mutable_list = [req1, req2]
        task = EngineeringTask(
            task_id="TASK-SEQ",
            title="List conversion test",
            requirements=mutable_list,  # type: ignore[arg-type]
        )
        assert isinstance(task.requirements, tuple)
        assert task.requirements == (req1, req2)
        # Mutating original list does not mutate task
        mutable_list.append(AcceptanceRequirement("REQ-3", "Statement 3"))
        assert len(task.requirements) == 2

    def test_invalid_requirement_items_rejected(self) -> None:
        with pytest.raises(TypeError, match="AcceptanceRequirement"):
            EngineeringTask(
                task_id="TASK-INVALID",
                title="Invalid req items",
                requirements=("not-a-req",),  # type: ignore[arg-type]
            )

    def test_frozen_immutability(self) -> None:
        req = AcceptanceRequirement("REQ-1", "Statement")
        task = EngineeringTask(
            task_id="TASK-1",
            title="Title",
            requirements=(req,),
        )
        with pytest.raises(FrozenInstanceError):
            task.title = "New title"  # type: ignore[misc]
        with pytest.raises(FrozenInstanceError):
            task.task_id = "TASK-2"  # type: ignore[misc]
        with pytest.raises(FrozenInstanceError):
            task.requirements = ()  # type: ignore[misc]
