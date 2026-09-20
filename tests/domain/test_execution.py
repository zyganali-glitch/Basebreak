"""Focused tests for execution command, result, and sandbox identity contracts."""

from dataclasses import FrozenInstanceError

import pytest

from basebreak.domain.execution import (
    ExecutionCommand,
    ExecutionResult,
    SandboxIdentity,
    TerminationStatus,
)


class TestExecutionCommand:
    """Tests for ExecutionCommand contract."""

    def test_argv_order_preserved(self) -> None:
        cmd = ExecutionCommand(argv=("python", "-m", "pytest", "-k", "test_core", "-v"))
        assert cmd.argv == ("python", "-m", "pytest", "-k", "test_core", "-v")
        assert cmd.executable == "python"

    def test_sequence_coerced_to_immutable_tuple(self) -> None:
        raw_list = ["pytest", "tests/unit"]
        cmd = ExecutionCommand(argv=raw_list)  # type: ignore[arg-type]
        assert isinstance(cmd.argv, tuple)
        assert cmd.argv == ("pytest", "tests/unit")
        raw_list.append("--cov")
        assert len(cmd.argv) == 2

    def test_empty_command_rejected(self) -> None:
        with pytest.raises(ValueError, match="empty"):
            ExecutionCommand(argv=())

    @pytest.mark.parametrize("invalid_exec", ["", "   ", " \t "])
    def test_empty_executable_rejected(self, invalid_exec: str) -> None:
        with pytest.raises(ValueError, match="Executable"):
            ExecutionCommand(argv=(invalid_exec, "arg1"))

    def test_non_string_argv_item_rejected(self) -> None:
        with pytest.raises(TypeError, match="string"):
            ExecutionCommand(argv=("python", 123))  # type: ignore[arg-type]

    def test_valid_repository_relative_cwd(self) -> None:
        cmd = ExecutionCommand(argv=("pytest",), cwd="packages/core")
        assert cmd.cwd == "packages/core"

    @pytest.mark.parametrize(
        "invalid_cwd",
        [
            "",
            "   ",
            "/absolute/path",
            "\\windows\\path",
            "C:\\project",
            "D:/project",
            "../outside",
            "..\\outside",
            "packages/../../escape",
            "packages/../..",
            "~/.config",
        ],
    )
    def test_invalid_cwd_rejected(self, invalid_cwd: str) -> None:
        with pytest.raises(ValueError):
            ExecutionCommand(argv=("pytest",), cwd=invalid_cwd)

    def test_env_mapping_and_pairs(self) -> None:
        cmd1 = ExecutionCommand(argv=("pytest",), env=(("KEY1", "VAL1"), ("KEY2", "VAL2")))
        assert cmd1.env == (("KEY1", "VAL1"), ("KEY2", "VAL2"))

        cmd2 = ExecutionCommand(argv=("pytest",), env={"FOO": "BAR"})  # type: ignore[arg-type]
        assert cmd2.env == (("FOO", "BAR"),)

    def test_empty_env_key_rejected(self) -> None:
        with pytest.raises(ValueError, match="empty"):
            ExecutionCommand(argv=("pytest",), env=(("", "val"),))

    def test_frozen_immutability(self) -> None:
        cmd = ExecutionCommand(argv=("python", "run.py"))
        with pytest.raises(FrozenInstanceError):
            cmd.argv = ("other",)  # type: ignore[misc]
        with pytest.raises(FrozenInstanceError):
            cmd.cwd = "subdir"  # type: ignore[misc]


class TestExecutionResult:
    """Tests for ExecutionResult contract."""

    def test_completed_execution_result(self) -> None:
        res = ExecutionResult(
            status=TerminationStatus.COMPLETED,
            exit_code=0,
            duration_seconds=1.234,
        )
        assert res.status == TerminationStatus.COMPLETED
        assert res.exit_code == 0
        assert res.duration_seconds == 1.234
        assert res.is_completed is True
        assert res.is_timed_out is False
        assert res.is_cancelled is False

    def test_completed_with_non_zero_exit_code(self) -> None:
        res = ExecutionResult(
            status=TerminationStatus.COMPLETED,
            exit_code=1,
            duration_seconds=0.5,
        )
        assert res.exit_code == 1
        assert res.is_completed is True

    def test_completed_requires_exit_code(self) -> None:
        with pytest.raises(ValueError, match="exit_code must be provided"):
            ExecutionResult(status=TerminationStatus.COMPLETED, exit_code=None)

    def test_timed_out_result(self) -> None:
        res = ExecutionResult(
            status=TerminationStatus.TIMED_OUT,
            exit_code=None,
            duration_seconds=30.0,
        )
        assert res.is_completed is False
        assert res.is_timed_out is True
        assert res.is_cancelled is False

    def test_cancelled_result(self) -> None:
        res = ExecutionResult(
            status=TerminationStatus.CANCELLED,
            exit_code=None,
        )
        assert res.is_completed is False
        assert res.is_timed_out is False
        assert res.is_cancelled is True

    def test_negative_duration_rejected(self) -> None:
        with pytest.raises(ValueError, match="negative"):
            ExecutionResult(
                status=TerminationStatus.COMPLETED,
                exit_code=0,
                duration_seconds=-0.1,
            )

    def test_frozen_immutability(self) -> None:
        res = ExecutionResult(status=TerminationStatus.COMPLETED, exit_code=0)
        with pytest.raises(FrozenInstanceError):
            res.exit_code = 1  # type: ignore[misc]


class TestSandboxIdentity:
    """Tests for SandboxIdentity abstract contract."""

    def test_valid_sandbox_identity(self) -> None:
        sb = SandboxIdentity(sandbox_id="sbx-clean-run-001", description="Clean baseline sandbox")
        assert sb.sandbox_id == "sbx-clean-run-001"
        assert sb.description == "Clean baseline sandbox"
        assert str(sb) == "sbx-clean-run-001"

    def test_two_sandbox_ids_are_distinct(self) -> None:
        sb1 = SandboxIdentity(sandbox_id="sbx-env-a")
        sb2 = SandboxIdentity(sandbox_id="sbx-env-b")
        assert sb1 != sb2
        assert hash(sb1) != hash(sb2)

    @pytest.mark.parametrize("invalid_id", ["", "   ", " sbx-1", "sbx-1 "])
    def test_invalid_sandbox_id_rejected(self, invalid_id: str) -> None:
        with pytest.raises(ValueError):
            SandboxIdentity(sandbox_id=invalid_id)

    def test_frozen_immutability(self) -> None:
        sb = SandboxIdentity(sandbox_id="sbx-1")
        with pytest.raises(FrozenInstanceError):
            sb.sandbox_id = "sbx-2"  # type: ignore[misc]

    def test_no_provider_specific_fields(self) -> None:
        """Verify SandboxIdentity exposes only abstract domain fields."""
        sb = SandboxIdentity(sandbox_id="sbx-test")
        fields = sb.__slots__
        assert fields == ("sandbox_id", "description")
        # Ensure no cloud/provider-specific fields are present
        forbidden = {"region", "nebius", "contree", "checkpoint", "clone", "branch", "cloud"}
        assert not any(f in forbidden for f in fields)
