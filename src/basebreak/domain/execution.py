"""Execution command, result, and sandbox identity domain contracts.

Defines provider-neutral immutable abstractions for command specification,
deterministic execution facts, and abstract sandbox identity.
"""

from __future__ import annotations

import math
import re
from collections.abc import Mapping, Sequence
from dataclasses import dataclass
from enum import Enum

_WINDOWS_DRIVE_PATTERN = re.compile(r"^[a-zA-Z]:[\\/]")


class TerminationStatus(str, Enum):
    """Normalized termination status of a command execution."""

    COMPLETED = "COMPLETED"
    TIMED_OUT = "TIMED_OUT"
    CANCELLED = "CANCELLED"
    FAILED_TO_START = "FAILED_TO_START"


def _validate_relative_cwd(cwd: str | None) -> None:
    """Validate repository-relative working directory."""
    if cwd is None:
        return
    if not isinstance(cwd, str):
        tname = type(cwd).__name__
        raise TypeError(f"cwd must be a string or None, got {tname}")
    if not cwd.strip():
        raise ValueError("cwd must not be empty if specified")
    if cwd.strip() != cwd:
        raise ValueError("cwd must not contain leading or trailing whitespace")
    if cwd.startswith(("/", "\\", "./", ".\\", "../", "..\\", "~")):
        raise ValueError(
            f"cwd must be repository-relative and not start with slash or relative prefix: {cwd!r}"
        )
    if _WINDOWS_DRIVE_PATTERN.match(cwd):
        raise ValueError(f"cwd must not be an absolute drive path: {cwd!r}")
    if "/../" in cwd or "\\..\\" in cwd or cwd.endswith(("/..", "\\..")):
        raise ValueError(f"cwd must not contain path traversal: {cwd!r}")


@dataclass(frozen=True, slots=True)
class ExecutionCommand:
    """Deterministic command specification without implicit shell invocation.

    Argv arguments are strictly preserved in order. Repository-relative working
    directory is validated against directory traversal escapes. Environment
    variables are strictly validated and normalized into canonical key-sorted tuples.
    """

    argv: tuple[str, ...]
    cwd: str | None = None
    env: tuple[tuple[str, str], ...] = ()

    def __post_init__(self) -> None:
        # Coerce sequence to tuple for immutability if needed
        if not isinstance(self.argv, tuple):
            if isinstance(self.argv, Sequence) and not isinstance(self.argv, (str, bytes)):
                object.__setattr__(self, "argv", tuple(self.argv))
            else:
                tname = type(self.argv).__name__
                raise TypeError(f"argv must be a sequence of strings, got {tname}")

        if len(self.argv) == 0:
            raise ValueError("argv must not be empty")

        for idx, arg in enumerate(self.argv):
            if not isinstance(arg, str):
                tname = type(arg).__name__
                raise TypeError(f"argv argument at index {idx} must be a string, got {tname}")

        executable = self.argv[0].strip()
        if not executable:
            raise ValueError("Executable (argv[0]) must not be empty or whitespace")

        _validate_relative_cwd(self.cwd)

        # Handle and canonicalize env parameter
        pairs: list[tuple[str, str]] = []
        seen_keys: set[str] = set()

        if isinstance(self.env, Mapping):
            for k, v in self.env.items():
                if not isinstance(k, str) or not isinstance(v, str):
                    raise TypeError("env keys and values must be strings")
                if not k.strip():
                    raise ValueError("env key must not be empty")
                if k in seen_keys:
                    raise ValueError(f"Duplicate environment key detected: {k!r}")
                seen_keys.add(k)
                pairs.append((k, v))
        elif isinstance(self.env, Sequence) and not isinstance(self.env, (str, bytes)):
            for idx, item in enumerate(self.env):
                if not isinstance(item, (tuple, list)) or len(item) != 2:
                    raise TypeError(f"env element at index {idx} must be a (key, value) pair")
                k, v = item
                if not isinstance(k, str) or not isinstance(v, str):
                    raise TypeError("env keys and values must be strings")
                if not k.strip():
                    raise ValueError("env key must not be empty")
                if k in seen_keys:
                    raise ValueError(f"Duplicate environment key detected: {k!r}")
                seen_keys.add(k)
                pairs.append((k, v))
        else:
            tname = type(self.env).__name__
            raise TypeError(f"env must be a mapping or sequence of pairs, got {tname}")

        # Canonicalize ordering deterministically by key
        canonical_env = tuple(sorted(pairs, key=lambda pair: pair[0]))
        object.__setattr__(self, "env", canonical_env)

    @property
    def executable(self) -> str:
        """The command executable (argv[0])."""
        return self.argv[0]


@dataclass(frozen=True, slots=True)
class ExecutionResult:
    """Deterministic result facts from a command execution.

    Records raw exit/termination state and duration without premature interpretation
    as PASS or FAIL. Verdict layers own interpretation against witnesses.
    """

    status: TerminationStatus
    exit_code: int | None = None
    duration_seconds: float | None = None

    def __post_init__(self) -> None:
        if not isinstance(self.status, TerminationStatus):
            tname = type(self.status).__name__
            raise TypeError(f"status must be an instance of TerminationStatus, got {tname}")

        if self.status == TerminationStatus.COMPLETED:
            if self.exit_code is None:
                raise ValueError("exit_code must be provided when status is COMPLETED")
            if not isinstance(self.exit_code, int):
                tname = type(self.exit_code).__name__
                raise TypeError(f"exit_code must be an integer, got {tname}")

        if self.duration_seconds is not None:
            if isinstance(self.duration_seconds, bool) or not isinstance(
                self.duration_seconds, (int, float)
            ):
                tname = type(self.duration_seconds).__name__
                raise TypeError(f"duration_seconds must be a finite number or None, got {tname}")
            if not math.isfinite(self.duration_seconds):
                raise ValueError(
                    f"duration_seconds must be a finite number, got {self.duration_seconds!r}"
                )
            if self.duration_seconds < 0.0:
                raise ValueError("duration_seconds must not be negative")

    @property
    def is_completed(self) -> bool:
        """True if execution ran to process completion."""
        return self.status == TerminationStatus.COMPLETED

    @property
    def is_timed_out(self) -> bool:
        """True if execution terminated due to timeout."""
        return self.status == TerminationStatus.TIMED_OUT

    @property
    def is_cancelled(self) -> bool:
        """True if execution was cancelled before completion."""
        return self.status == TerminationStatus.CANCELLED


@dataclass(frozen=True, slots=True)
class SandboxIdentity:
    """Abstract immutable identity to distinguish execution environments.

    Carries an opaque identifier without embedding provider-specific assumptions
    such as cloud names, regions, checkpoint semantics, or branching mechanisms.
    """

    sandbox_id: str
    description: str = ""

    def __post_init__(self) -> None:
        if not isinstance(self.sandbox_id, str):
            tname = type(self.sandbox_id).__name__
            raise TypeError(f"sandbox_id must be a string, got {tname}")
        sid = self.sandbox_id.strip()
        if not sid:
            raise ValueError("sandbox_id must not be empty")
        if sid != self.sandbox_id:
            raise ValueError("sandbox_id must not contain leading or trailing whitespace")

        if not isinstance(self.description, str):
            tname = type(self.description).__name__
            raise TypeError(f"description must be a string, got {tname}")

    def __str__(self) -> str:
        return self.sandbox_id
