"""Candidate workspace file editing and command execution.

P-07.03: Converts validated P-07.02 Builder proposals into controlled,
deterministic mutations and command executions inside a disposable candidate sandbox.

Core Invariants:
1. Bounded mutation primitives: CREATE, MODIFY, DELETE with strict path normalization.
2. Rejection of traversal, root escape, absolute paths, and duplicate/conflicting actions.
3. Strict command bounding: finite count, explicit timeouts, length ceiling, no recursion.
4. Zero host execution fallback: untrusted commands execute strictly inside disposable sandbox.
5. Zero credentials in guest workspace: secrets rejected before sandbox dispatch.
6. Deterministic fact capture: exit codes, output digests, durations, and sandbox identity.
7. Builder proposal and execution results possess ZERO self-verification authority:
   is_authoritative is strictly False across all records.
8. Provider neutrality: zero adapter imports, zero provider-specific identifiers.
"""

from __future__ import annotations

import base64
import json
import re
import shlex
import time
from collections.abc import Mapping, Sequence
from dataclasses import dataclass
from typing import Any

from basebreak.builder.context import BuilderContextEnvelope
from basebreak.builder.loop import (
    BuilderProposal,
    FileActionType,
    ProposedCommand,
    ProposedFileAction,
)
from basebreak.domain.execution import (
    SandboxIdentity,
    TerminationStatus,
)
from basebreak.domain.source import CommitRevision, SourceIdentity
from basebreak.domain.verdict import EvidenceProvenance
from basebreak.evidence.artifact import compute_bytes_digest
from basebreak.security.protected_surfaces import (
    InvalidPathError,
    PathSecurityError,
    PathTraversalError,
    normalize_repo_path,
)
from basebreak.security.sandbox_policy import (
    MAX_SANDBOX_TIMEOUT_SECONDS,
    MIN_SANDBOX_TIMEOUT_SECONDS,
)
from basebreak.security.secret_policy import (
    contains_secret,
    validate_no_secrets,
)

# --- Operational Constants ---

DEFAULT_MAX_FILE_ACTIONS: int = 50
DEFAULT_MAX_FILE_BYTES: int = 1_000_000  # 1 MB
DEFAULT_MAX_COMMANDS: int = 10
DEFAULT_PER_COMMAND_TIMEOUT_SECONDS: int = 120
DEFAULT_MAX_COMMAND_LENGTH_BYTES: int = 16384  # 16 KB
DEFAULT_WORKSPACE_PATH: str = "/workspace/candidate"
DEFAULT_SANDBOX_IMAGE: str = "tag:astral/uv:python3.11-alpine"

# Maximum base64 chunk size for multi-command streaming (must be multiple of 4)
_B64_CHUNK_SIZE: int = 7680

# Forbidden shell recursion and fork-bomb patterns
_FORK_BOMB_PATTERN = re.compile(
    r"(\:\(\)\s*\{|\(\)\s*\{[\s\S]*\|[\s\S]*\&|forkbomb)", re.IGNORECASE
)
_RECURSIVE_SHELL_PATTERN = re.compile(
    r"(\$0\s+.*\$0|\bexec\s+\$0|\bsh\s+\$0|\bbash\s+\$0|\bsource\s+\$0|\b\.\s+\$0)",
    re.IGNORECASE,
)
_PERSISTENT_DAEMON_PATTERN = re.compile(
    r"(\bnohup\b|\bdisown\b|\btmux\b|\bscreen\b|\bdaemon\b)",
    re.IGNORECASE,
)


# --- Exceptions ---


class CandidateExecutionError(Exception):
    """Base exception for all candidate execution failures."""


class CandidateExecutionConfigError(CandidateExecutionError):
    """Raised when CandidateExecutionConfig is invalid."""


class InvalidProposedMutationError(CandidateExecutionError):
    """Raised when a proposed file mutation violates path, action, or size bounds."""


class DuplicateActionError(InvalidProposedMutationError):
    """Raised when multiple proposed file actions target the same path."""


class MissingTargetError(CandidateExecutionError):
    """Raised when a MODIFY or DELETE action targets a non-existent file."""


class TargetAlreadyExistsError(CandidateExecutionError):
    """Raised when a CREATE action targets a file that already exists."""


class CommandBoundingError(CandidateExecutionError):
    """Raised when proposed commands exceed count, size, or structural limits."""


class ForbiddenCommandError(CandidateExecutionError):
    """Raised when a command contains fork bombs, shell recursion, or daemons."""


class CandidateExecutionTimeoutError(CandidateExecutionError):
    """Raised when candidate execution or command times out."""


class HostExecutionFallbackError(CandidateExecutionError):
    """Raised when execution attempts to fall back to the host machine."""


class CredentialLeakageError(CandidateExecutionError):
    """Raised when secret-shaped values are detected in content or commands."""


class WorkspaceExecutionError(CandidateExecutionError):
    """Raised when a sandbox execution fails, exits non-zero, or errors."""


# --- Data Records ---


@dataclass(frozen=True, slots=True)
class FileMutationRecord:
    """Deterministic record of a file mutation applied in the candidate workspace.

    Possesses zero verification authority: is_authoritative is strictly False.
    """

    path: str
    action: FileActionType
    exit_code: int
    stdout_digest: str
    stderr_digest: str
    duration_seconds: float
    content_digest: str
    is_success: bool
    sandbox_identity: SandboxIdentity
    is_authoritative: bool = False

    def __post_init__(self) -> None:
        if not isinstance(self.path, str) or not self.path.strip():
            raise ValueError("path must be a non-empty string")
        if not isinstance(self.action, FileActionType):
            raise TypeError(f"action must be FileActionType, got {type(self.action).__name__}")
        if not isinstance(self.exit_code, int) or isinstance(self.exit_code, bool):
            raise TypeError("exit_code must be an integer")
        if not isinstance(self.stdout_digest, str) or len(self.stdout_digest) != 64:
            raise ValueError("stdout_digest must be a 64-char hex string")
        if not isinstance(self.stderr_digest, str) or len(self.stderr_digest) != 64:
            raise ValueError("stderr_digest must be a 64-char hex string")
        if not isinstance(self.duration_seconds, (int, float)) or isinstance(
            self.duration_seconds, bool
        ):
            raise TypeError("duration_seconds must be a float")
        if not isinstance(self.content_digest, str):
            raise TypeError("content_digest must be a str")
        if self.action != FileActionType.DELETE and len(self.content_digest) != 64:
            raise ValueError("content_digest must be a 64-char hex string for CREATE/MODIFY")
        if not isinstance(self.is_success, bool):
            raise TypeError("is_success must be a bool")
        if not isinstance(self.sandbox_identity, SandboxIdentity):
            sid_type = type(self.sandbox_identity).__name__
            raise TypeError(f"sandbox_identity must be SandboxIdentity, got {sid_type}")
        if self.is_authoritative is not False:
            raise ValueError("FileMutationRecord is_authoritative must be strictly False")

    def to_dict(self) -> dict[str, Any]:
        """Serialize record to dictionary."""
        return {
            "action": self.action.value,
            "content_digest": self.content_digest,
            "duration_seconds": self.duration_seconds,
            "exit_code": self.exit_code,
            "is_authoritative": self.is_authoritative,
            "is_success": self.is_success,
            "path": self.path,
            "sandbox_id": self.sandbox_identity.sandbox_id,
            "stderr_digest": self.stderr_digest,
            "stdout_digest": self.stdout_digest,
        }

    @classmethod
    def from_dict(cls, data: Mapping[str, Any]) -> FileMutationRecord:
        """Deserialize record from dictionary."""
        if not isinstance(data, Mapping):
            raise TypeError(f"Expected mapping, got {type(data).__name__}")
        raw_action = data.get("action")
        if not isinstance(raw_action, str):
            raise ValueError(f"Invalid action: {raw_action!r}")
        action = FileActionType(raw_action.upper())

        return cls(
            path=str(data.get("path", "")),
            action=action,
            exit_code=int(data.get("exit_code", 0)),
            stdout_digest=str(data.get("stdout_digest", "")),
            stderr_digest=str(data.get("stderr_digest", "")),
            duration_seconds=float(data.get("duration_seconds", 0.0)),
            content_digest=str(data.get("content_digest", "")),
            is_success=bool(data.get("is_success", False)),
            sandbox_identity=SandboxIdentity(sandbox_id=str(data.get("sandbox_id", ""))),
            is_authoritative=False,
        )


@dataclass(frozen=True, slots=True)
class CommandExecutionRecord:
    """Deterministic record of a command executed in the candidate workspace.

    Possesses zero verification authority: is_authoritative is strictly False.
    """

    command: str
    exit_code: int | None
    stdout_digest: str
    stderr_digest: str
    duration_seconds: float | None
    status: TerminationStatus
    sandbox_identity: SandboxIdentity
    is_authoritative: bool = False

    def __post_init__(self) -> None:
        if not isinstance(self.command, str) or not self.command.strip():
            raise ValueError("command must be a non-empty string")
        if self.exit_code is not None:
            if not isinstance(self.exit_code, int) or isinstance(self.exit_code, bool):
                raise TypeError("exit_code must be an integer or None")
        if not isinstance(self.stdout_digest, str) or len(self.stdout_digest) != 64:
            raise ValueError("stdout_digest must be a 64-char hex string")
        if not isinstance(self.stderr_digest, str) or len(self.stderr_digest) != 64:
            raise ValueError("stderr_digest must be a 64-char hex string")
        if self.duration_seconds is not None:
            if not isinstance(self.duration_seconds, (int, float)) or isinstance(
                self.duration_seconds, bool
            ):
                raise TypeError("duration_seconds must be a float or None")
        if not isinstance(self.status, TerminationStatus):
            raise TypeError(f"status must be TerminationStatus, got {type(self.status).__name__}")
        if not isinstance(self.sandbox_identity, SandboxIdentity):
            sid_type = type(self.sandbox_identity).__name__
            raise TypeError(f"sandbox_identity must be SandboxIdentity, got {sid_type}")
        if self.is_authoritative is not False:
            raise ValueError("CommandExecutionRecord is_authoritative must be strictly False")

    def to_dict(self) -> dict[str, Any]:
        """Serialize record to dictionary."""
        return {
            "command": self.command,
            "duration_seconds": self.duration_seconds,
            "exit_code": self.exit_code,
            "is_authoritative": self.is_authoritative,
            "sandbox_id": self.sandbox_identity.sandbox_id,
            "status": self.status.value,
            "stderr_digest": self.stderr_digest,
            "stdout_digest": self.stdout_digest,
        }

    @classmethod
    def from_dict(cls, data: Mapping[str, Any]) -> CommandExecutionRecord:
        """Deserialize record from dictionary."""
        if not isinstance(data, Mapping):
            raise TypeError(f"Expected mapping, got {type(data).__name__}")
        raw_status = data.get("status")
        if not isinstance(raw_status, str):
            raise ValueError(f"Invalid status: {raw_status!r}")
        status = TerminationStatus(raw_status)

        exit_code_raw = data.get("exit_code")
        exit_code = int(exit_code_raw) if exit_code_raw is not None else None

        dur_raw = data.get("duration_seconds")
        duration = float(dur_raw) if dur_raw is not None else None

        return cls(
            command=str(data.get("command", "")),
            exit_code=exit_code,
            stdout_digest=str(data.get("stdout_digest", "")),
            stderr_digest=str(data.get("stderr_digest", "")),
            duration_seconds=duration,
            status=status,
            sandbox_identity=SandboxIdentity(sandbox_id=str(data.get("sandbox_id", ""))),
            is_authoritative=False,
        )


@dataclass(frozen=True, slots=True)
class CandidateExecutionConfig:
    """Bounded configuration for candidate workspace file mutation and execution."""

    max_file_actions: int = DEFAULT_MAX_FILE_ACTIONS
    max_file_bytes: int = DEFAULT_MAX_FILE_BYTES
    max_commands: int = DEFAULT_MAX_COMMANDS
    per_command_timeout_seconds: int = DEFAULT_PER_COMMAND_TIMEOUT_SECONDS
    max_command_length_bytes: int = DEFAULT_MAX_COMMAND_LENGTH_BYTES
    workspace_path: str = DEFAULT_WORKSPACE_PATH
    sandbox_image: str = DEFAULT_SANDBOX_IMAGE
    fail_fast: bool = True
    teardown_on_failure: bool = True
    teardown_on_completion: bool = False

    def __post_init__(self) -> None:
        if self.max_file_actions < 1 or self.max_file_actions > 200:
            raise CandidateExecutionConfigError(
                f"max_file_actions must be between 1 and 200, got {self.max_file_actions}"
            )
        if self.max_file_bytes < 1 or self.max_file_bytes > 10_000_000:
            raise CandidateExecutionConfigError(
                f"max_file_bytes must be between 1 and 10MB, got {self.max_file_bytes}"
            )
        if self.max_commands < 1 or self.max_commands > 20:
            raise CandidateExecutionConfigError(
                f"max_commands must be between 1 and 20, got {self.max_commands}"
            )
        if not (
            MIN_SANDBOX_TIMEOUT_SECONDS
            <= self.per_command_timeout_seconds
            <= MAX_SANDBOX_TIMEOUT_SECONDS
        ):
            raise CandidateExecutionConfigError(
                f"per_command_timeout_seconds must be between {MIN_SANDBOX_TIMEOUT_SECONDS} "
                f"and {MAX_SANDBOX_TIMEOUT_SECONDS}, got {self.per_command_timeout_seconds}"
            )
        if self.max_command_length_bytes < 256 or self.max_command_length_bytes > 65536:
            raise CandidateExecutionConfigError(
                f"max_command_length_bytes must be between 256 and 65536, "
                f"got {self.max_command_length_bytes}"
            )
        if not self.workspace_path or not self.workspace_path.strip():
            raise CandidateExecutionConfigError("workspace_path must not be empty")
        if not self.sandbox_image or not self.sandbox_image.strip():
            raise CandidateExecutionConfigError("sandbox_image must not be empty")


@dataclass(frozen=True, slots=True)
class CandidateExecutionResult:
    """Deterministic result of candidate workspace mutation and command execution.

    Cryptographically and mechanically binds:
    - frozen_contract_digest (64 hex chars)
    - context_digest (64 hex chars)
    - source_identity (SourceIdentity)
    - proposal_digest (64 hex chars)
    - proposal_plan_summary (str)
    - file_mutations (tuple of FileMutationRecord)
    - command_executions (tuple of CommandExecutionRecord)
    - sandbox_identity (SandboxIdentity)
    - total_duration_seconds (float)
    - provenance (EvidenceProvenance)
    - is_authoritative (strictly False)
    """

    frozen_contract_digest: str
    context_digest: str
    source_identity: SourceIdentity
    proposal_digest: str
    proposal_plan_summary: str
    file_mutations: tuple[FileMutationRecord, ...]
    command_executions: tuple[CommandExecutionRecord, ...]
    sandbox_identity: SandboxIdentity
    total_duration_seconds: float
    provenance: EvidenceProvenance = EvidenceProvenance.LOCAL_EXECUTION
    is_authoritative: bool = False

    def __post_init__(self) -> None:
        if (
            not isinstance(self.frozen_contract_digest, str)
            or len(self.frozen_contract_digest) != 64
        ):
            raise ValueError(
                f"frozen_contract_digest must be 64 hex chars, got {self.frozen_contract_digest!r}"
            )
        if not isinstance(self.context_digest, str) or len(self.context_digest) != 64:
            raise ValueError(f"context_digest must be 64 hex chars, got {self.context_digest!r}")
        if not isinstance(self.source_identity, SourceIdentity):
            raise TypeError(
                f"source_identity must be SourceIdentity, got {type(self.source_identity).__name__}"
            )
        if not isinstance(self.proposal_digest, str) or len(self.proposal_digest) != 64:
            raise ValueError(f"proposal_digest must be 64 hex chars, got {self.proposal_digest!r}")
        if (
            not isinstance(self.proposal_plan_summary, str)
            or not self.proposal_plan_summary.strip()
        ):
            raise ValueError("proposal_plan_summary must be a non-empty string")
        if not isinstance(self.file_mutations, tuple):
            if isinstance(self.file_mutations, Sequence):
                object.__setattr__(self, "file_mutations", tuple(self.file_mutations))
            else:
                raise TypeError("file_mutations must be a sequence of FileMutationRecord")
        for m in self.file_mutations:
            if not isinstance(m, FileMutationRecord):
                raise TypeError(
                    f"file_mutations item must be FileMutationRecord, got {type(m).__name__}"
                )
        if not isinstance(self.command_executions, tuple):
            if isinstance(self.command_executions, Sequence):
                object.__setattr__(self, "command_executions", tuple(self.command_executions))
            else:
                raise TypeError("command_executions must be a sequence of CommandExecutionRecord")
        for c in self.command_executions:
            if not isinstance(c, CommandExecutionRecord):
                c_type = type(c).__name__
                raise TypeError(
                    f"command_executions item must be CommandExecutionRecord, got {c_type}"
                )
        if not isinstance(self.sandbox_identity, SandboxIdentity):
            sid_type = type(self.sandbox_identity).__name__
            raise TypeError(f"sandbox_identity must be SandboxIdentity, got {sid_type}")
        if not isinstance(self.total_duration_seconds, (int, float)) or isinstance(
            self.total_duration_seconds, bool
        ):
            raise TypeError("total_duration_seconds must be a float")
        if self.total_duration_seconds < 0.0:
            raise ValueError("total_duration_seconds must not be negative")
        if not isinstance(self.provenance, EvidenceProvenance):
            raise TypeError(
                f"provenance must be EvidenceProvenance, got {type(self.provenance).__name__}"
            )
        if self.is_authoritative is not False:
            raise ValueError("CandidateExecutionResult is_authoritative must be strictly False")

    def to_dict(self) -> dict[str, Any]:
        """Serialize candidate execution result to dictionary."""
        return {
            "command_executions": [c.to_dict() for c in self.command_executions],
            "context_digest": self.context_digest,
            "file_mutations": [m.to_dict() for m in self.file_mutations],
            "frozen_contract_digest": self.frozen_contract_digest,
            "is_authoritative": self.is_authoritative,
            "proposal_digest": self.proposal_digest,
            "proposal_plan_summary": self.proposal_plan_summary,
            "provenance": self.provenance.value,
            "sandbox_id": self.sandbox_identity.sandbox_id,
            "source_commit_id": self.source_identity.resolved_commit_id,
            "source_locator": self.source_identity.locator,
            "source_subpath": self.source_identity.subpath,
            "total_duration_seconds": self.total_duration_seconds,
        }

    @classmethod
    def from_dict(cls, data: Mapping[str, Any]) -> CandidateExecutionResult:
        """Deserialize candidate execution result from dictionary."""
        if not isinstance(data, Mapping):
            raise TypeError(f"Expected mapping, got {type(data).__name__}")
        raw_mutations = data.get("file_mutations", [])
        if not isinstance(raw_mutations, (list, tuple)):
            raise TypeError("file_mutations must be a list")
        mutations = tuple(FileMutationRecord.from_dict(m) for m in raw_mutations)

        raw_cmds = data.get("command_executions", [])
        if not isinstance(raw_cmds, (list, tuple)):
            raise TypeError("command_executions must be a list")
        commands = tuple(CommandExecutionRecord.from_dict(c) for c in raw_cmds)

        raw_prov = data.get("provenance", "LOCAL_EXECUTION")
        prov = EvidenceProvenance(raw_prov)

        src_id = SourceIdentity(
            locator=str(data.get("source_locator", "")),
            revision=CommitRevision(str(data.get("source_commit_id", ""))),
            subpath=data.get("source_subpath"),
        )

        return cls(
            frozen_contract_digest=str(data.get("frozen_contract_digest", "")),
            context_digest=str(data.get("context_digest", "")),
            source_identity=src_id,
            proposal_digest=str(data.get("proposal_digest", "")),
            proposal_plan_summary=str(data.get("proposal_plan_summary", "")),
            file_mutations=mutations,
            command_executions=commands,
            sandbox_identity=SandboxIdentity(sandbox_id=str(data.get("sandbox_id", ""))),
            total_duration_seconds=float(data.get("total_duration_seconds", 0.0)),
            provenance=prov,
            is_authoritative=False,
        )


# --- Helper Functions ---


def validate_workspace_path(workspace_path: str) -> str:
    """Validate repository workspace directory inside sandbox container VM.

    Provider-neutral path validator ensuring:
    - Non-empty string without whitespace padding.
    - No null bytes or control characters.
    - Absolute path starting with '/'.
    - No '.' or '..' traversal segments.
    - Does not resolve to bare root '/'.
    """
    if not isinstance(workspace_path, str) or not workspace_path.strip():
        raise InvalidPathError("workspace_path must be a non-empty string")
    clean = workspace_path.strip()
    if "\x00" in clean or "\r" in clean or "\n" in clean:
        raise InvalidPathError("workspace_path contains forbidden control characters")
    if not clean.startswith("/"):
        raise InvalidPathError(
            f"workspace_path must be an absolute path starting with '/', got {clean!r}"
        )
    parts = [p for p in clean.split("/") if p]
    if not parts:
        raise InvalidPathError("workspace_path cannot be root directory '/'")
    if any(p == ".." or p == "." for p in parts):
        raise PathTraversalError("workspace_path cannot contain '.' or '..' segments")
    return "/" + "/".join(parts)


def compute_proposal_digest(proposal: BuilderProposal) -> str:
    """Compute deterministic SHA-256 digest of BuilderProposal."""
    canonical_bytes = json.dumps(
        proposal.to_dict(),
        sort_keys=True,
        separators=(",", ":"),
        ensure_ascii=False,
    ).encode("utf-8")
    return compute_bytes_digest(canonical_bytes).value


def validate_candidate_proposal(
    proposal: BuilderProposal,
    config: CandidateExecutionConfig,
) -> tuple[dict[str, ProposedFileAction], tuple[str, ...]]:
    """Validate Builder proposal against structural, bounding, and security invariants.

    Returns:
        Tuple of (mapping of normalized_path -> ProposedFileAction,
        tuple of validated command strings).

    Fails closed if:
    - proposal is not BuilderProposal or is_authoritative is True;
    - file action count exceeds max_file_actions;
    - path traversal, root escape, drive letters, or malformed paths detected;
    - duplicate/conflicting actions for the same normalized path detected;
    - file content exceeds max_file_bytes;
    - secret detected in any file content, rationale, or command;
    - command count exceeds max_commands;
    - command exceeds max_command_length_bytes or contains null bytes;
    - forbidden shell recursion, fork bomb, or daemon pattern detected.
    """
    if not isinstance(proposal, BuilderProposal):
        raise TypeError(f"proposal must be BuilderProposal, got {type(proposal).__name__}")
    if proposal.is_authoritative is not False:
        raise InvalidProposedMutationError(
            "BuilderProposal is_authoritative must be strictly False"
        )

    # 1. Validate File Actions
    if len(proposal.proposed_file_actions) > config.max_file_actions:
        raise InvalidProposedMutationError(
            f"Proposed file actions count ({len(proposal.proposed_file_actions)}) "
            f"exceeds limit ({config.max_file_actions})"
        )

    normalized_actions: dict[str, ProposedFileAction] = {}
    for idx, action in enumerate(proposal.proposed_file_actions):
        if not isinstance(action, ProposedFileAction):
            raise TypeError(
                f"proposed_file_actions item at {idx} must be ProposedFileAction, "
                f"got {type(action).__name__}"
            )
        if action.is_authoritative is not False:
            raise InvalidProposedMutationError(
                f"action at index {idx} is_authoritative must be strictly False"
            )

        # Normalize path and check for traversal / root escape
        try:
            norm_path = normalize_repo_path(action.path)
        except (PathTraversalError, InvalidPathError, PathSecurityError) as exc:
            raise InvalidProposedMutationError(
                f"Invalid or unsafe path in action at index {idx} ({action.path!r}): {exc}"
            ) from exc

        # Check for duplicate/conflicting mutations targeting the same path
        if norm_path in normalized_actions:
            prior = normalized_actions[norm_path]
            raise DuplicateActionError(
                f"Duplicate or conflicting file action for normalized path {norm_path!r}: "
                f"action {action.action.value} conflicts with prior {prior.action.value}"
            )

        # Check content size bounds
        content_bytes = action.content.encode("utf-8")
        if len(content_bytes) > config.max_file_bytes:
            raise InvalidProposedMutationError(
                f"File action for {norm_path!r} exceeds size limit: "
                f"{len(content_bytes)} bytes (max {config.max_file_bytes})"
            )

        # Check for credential leakage in content and rationale
        if contains_secret(action.content):
            raise CredentialLeakageError(
                f"Secret-shaped value detected in proposed file action content for {norm_path!r}"
            )
        validate_no_secrets(action.content, path=f"file_action[{norm_path}].content")

        if contains_secret(action.rationale):
            raise CredentialLeakageError(
                f"Secret-shaped value detected in proposed file action rationale for {norm_path!r}"
            )
        validate_no_secrets(action.rationale, path=f"file_action[{norm_path}].rationale")

        normalized_actions[norm_path] = action

    # 2. Validate Commands
    if len(proposal.proposed_commands) > config.max_commands:
        raise CommandBoundingError(
            f"Proposed commands count ({len(proposal.proposed_commands)}) "
            f"exceeds limit ({config.max_commands})"
        )

    validated_commands: list[str] = []
    for idx, cmd in enumerate(proposal.proposed_commands):
        if not isinstance(cmd, ProposedCommand):
            raise TypeError(
                f"proposed_commands item at {idx} must be ProposedCommand, got {type(cmd).__name__}"
            )
        if cmd.is_authoritative is not False:
            raise CommandBoundingError(
                f"command at index {idx} is_authoritative must be strictly False"
            )

        cmd_str = cmd.command.strip()
        if not cmd_str:
            raise CommandBoundingError(f"Command at index {idx} must not be empty or whitespace")
        if "\x00" in cmd_str:
            raise CommandBoundingError(f"Command at index {idx} contains forbidden null byte")

        cmd_bytes = cmd_str.encode("utf-8")
        if len(cmd_bytes) > config.max_command_length_bytes:
            raise CommandBoundingError(
                f"Command at index {idx} exceeds length limit: {len(cmd_bytes)} bytes "
                f"(max {config.max_command_length_bytes})"
            )

        # Check for forbidden recursion, fork bombs, and persistent daemons
        if _FORK_BOMB_PATTERN.search(cmd_str):
            raise ForbiddenCommandError(
                f"Forbidden fork bomb pattern detected in command at index {idx}"
            )
        if _RECURSIVE_SHELL_PATTERN.search(cmd_str):
            raise ForbiddenCommandError(
                f"Forbidden recursive shell invocation detected in command at index {idx}"
            )
        if _PERSISTENT_DAEMON_PATTERN.search(cmd_str):
            raise ForbiddenCommandError(
                f"Forbidden daemon or background manager detected in command at index {idx}"
            )

        # Check for credential leakage in command string and rationale
        if contains_secret(cmd_str):
            raise CredentialLeakageError(f"Secret-shaped value detected in command at index {idx}")
        validate_no_secrets(cmd_str, path=f"command[{idx}]")

        if contains_secret(cmd.rationale):
            raise CredentialLeakageError(
                f"Secret-shaped value detected in command rationale at index {idx}"
            )
        validate_no_secrets(cmd.rationale, path=f"command[{idx}].rationale")

        validated_commands.append(cmd_str)

    return normalized_actions, tuple(validated_commands)


def build_file_mutation_scripts(
    norm_path: str,
    action: ProposedFileAction,
    clean_workspace: str,
) -> tuple[str, ...]:
    """Build deterministic POSIX shell script(s) to apply a file action inside sandbox VM.

    Enforces:
    - Precondition validation (CREATE fails if target exists, MODIFY/DELETE fail if target missing).
    - Writes only through POSIX shell base64 decoding.
    - Chunking into commands < MAX_COMMAND_LENGTH_BYTES for large content.
    - Explicit exit codes:
      - 101: CREATE target already exists
      - 102: MODIFY target not found
      - 103: DELETE target not found
      - 104: CREATE target file creation unverified
      - 105: DELETE target file removal unverified
    """
    target_abs = f"{clean_workspace}/{norm_path}"
    target_dir = "/".join(target_abs.split("/")[:-1])
    quoted_target = shlex.quote(target_abs)
    quoted_dir = shlex.quote(target_dir)

    if action.action == FileActionType.DELETE:
        script = (
            "set -e\n"
            f"if [ ! -e {quoted_target} ] && [ ! -L {quoted_target} ]; then\n"
            f'    echo "BASEBREAK_MUTATION_ERROR: DELETE target not found: {norm_path}" >&2\n'
            "    exit 103\n"
            "fi\n"
            f"rm -rf {quoted_target}\n"
            f"if [ -e {quoted_target} ] || [ -L {quoted_target} ]; then\n"
            f'    echo "BASEBREAK_MUTATION_ERROR: '
            f'DELETE target removal unverified: {norm_path}" >&2\n'
            "    exit 105\n"
            "fi\n"
        )
        return (script,)

    # CREATE or MODIFY
    b64_content = base64.b64encode(action.content.encode("utf-8")).decode("ascii")

    # If small enough, execute as single bounded script
    if len(b64_content) <= 8000:
        lines: list[str] = ["set -e"]
        if action.action == FileActionType.CREATE:
            lines.append(
                f"if [ -e {quoted_target} ] || [ -L {quoted_target} ]; then\n"
                f'    echo "BASEBREAK_MUTATION_ERROR: '
                f'CREATE target already exists: {norm_path}" >&2\n'
                "    exit 101\n"
                "fi"
            )
        else:  # MODIFY
            lines.append(
                f"if [ ! -f {quoted_target} ]; then\n"
                f'    echo "BASEBREAK_MUTATION_ERROR: MODIFY target not found: {norm_path}" >&2\n'
                "    exit 102\n"
                "fi"
            )

        lines.append(f"mkdir -p {quoted_dir}")
        if b64_content:
            lines.append(f'printf "%s" {shlex.quote(b64_content)} | base64 -d > {quoted_target}')
        else:
            lines.append(f": > {quoted_target}")

        lines.append(
            f"if [ ! -f {quoted_target} ]; then\n"
            f'    echo "BASEBREAK_MUTATION_ERROR: '
            f'Target file creation unverified: {norm_path}" >&2\n'
            "    exit 104\n"
            "fi"
        )
        return ("\n".join(lines),)

    # For larger files (>8000 base64 chars), chunk into bounded commands
    scripts: list[str] = []

    # Command 1: Precondition check and truncate/init target
    init_lines = ["set -e"]
    if action.action == FileActionType.CREATE:
        init_lines.append(
            f"if [ -e {quoted_target} ] || [ -L {quoted_target} ]; then\n"
            f'    echo "BASEBREAK_MUTATION_ERROR: CREATE target already exists: {norm_path}" >&2\n'
            "    exit 101\n"
            "fi"
        )
    else:
        init_lines.append(
            f"if [ ! -f {quoted_target} ]; then\n"
            f'    echo "BASEBREAK_MUTATION_ERROR: MODIFY target not found: {norm_path}" >&2\n'
            "    exit 102\n"
            "fi"
        )
    init_lines.append(f"mkdir -p {quoted_dir}")
    init_lines.append(f": > {quoted_target}")
    scripts.append("\n".join(init_lines))

    # Commands 2..N: Stream base64 chunks (in multiples of 4)
    for offset in range(0, len(b64_content), _B64_CHUNK_SIZE):
        chunk = b64_content[offset : offset + _B64_CHUNK_SIZE]
        scripts.append(f'printf "%s" {shlex.quote(chunk)} | base64 -d >> {quoted_target}')

    # Final Command: Verify file exists
    verify_script = (
        "set -e\n"
        f"if [ ! -f {quoted_target} ]; then\n"
        f'    echo "BASEBREAK_MUTATION_ERROR: Target file creation unverified: {norm_path}" >&2\n'
        "    exit 104\n"
        "fi\n"
    )
    scripts.append(verify_script)

    return tuple(scripts)


# --- Candidate Workspace Executor ---


class CandidateWorkspaceExecutor:
    """Bounded production execution layer for candidate workspace mutations and commands.

    Enforces:
    - Rejection of host execution fallback: sandbox_adapter is mandatory.
    - Validation of BuilderProposal and authoritative context bindings.
    - Application of proposed mutations (CREATE, MODIFY, DELETE) through POSIX shell primitives.
    - Bounded execution of proposed commands inside disposable candidate sandbox.
    - Fail-closed recording of all deterministic execution facts.
    - Zero self-certification: is_authoritative is strictly False across all output.
    """

    def __init__(
        self,
        sandbox_adapter: Any,
        *,
        config: CandidateExecutionConfig | None = None,
    ) -> None:
        if sandbox_adapter is None:
            raise HostExecutionFallbackError(
                "sandbox_adapter is required; host execution fallback is strictly prohibited"
            )
        self.sandbox_adapter = sandbox_adapter
        self.config = config or CandidateExecutionConfig()

    def execute(
        self,
        proposal: BuilderProposal,
        *,
        envelope: BuilderContextEnvelope | None = None,
        frozen_contract_digest: str | None = None,
        context_digest: str | None = None,
        source_identity: SourceIdentity | None = None,
        sandbox_handle: Any | None = None,
        provenance: EvidenceProvenance = EvidenceProvenance.LOCAL_EXECUTION,
    ) -> CandidateExecutionResult:
        """Execute validated Builder proposal inside candidate sandbox.

        Steps:
        1. Resolve and validate authoritative context bindings.
        2. Validate proposal actions and commands against bounds and security invariants.
        3. Acquire sandbox handle (use provided or create disposable).
        4. Execute file mutations inside the candidate workspace.
        5. Execute proposed commands inside the candidate workspace.
        6. Clean up sandbox if configured.
        7. Return deterministic CandidateExecutionResult.
        """
        # Step 1: Authoritative Context Binding Resolution
        resolved_contract_digest: str
        resolved_context_digest: str
        resolved_source_id: SourceIdentity

        if envelope is not None:
            if not isinstance(envelope, BuilderContextEnvelope):
                raise TypeError(
                    f"envelope must be BuilderContextEnvelope, got {type(envelope).__name__}"
                )
            resolved_contract_digest = envelope.frozen_contract.contract_digest
            resolved_context_digest = envelope.context_digest
            resolved_source_id = envelope.source_identity
        else:
            if not frozen_contract_digest or not isinstance(frozen_contract_digest, str):
                raise ValueError("frozen_contract_digest is required when envelope is omitted")
            if not context_digest or not isinstance(context_digest, str):
                raise ValueError("context_digest is required when envelope is omitted")
            if source_identity is None or not isinstance(source_identity, SourceIdentity):
                raise TypeError("source_identity is required when envelope is omitted")
            resolved_contract_digest = frozen_contract_digest
            resolved_context_digest = context_digest
            resolved_source_id = source_identity

        # Step 2: Validate Proposal & Commands
        normalized_actions, validated_commands = validate_candidate_proposal(proposal, self.config)
        proposal_digest = compute_proposal_digest(proposal)
        clean_workspace = validate_workspace_path(self.config.workspace_path)

        start_time = time.perf_counter()

        # Step 3: Acquire Sandbox Handle
        created_handle = False
        handle: Any
        if sandbox_handle is not None:
            handle = sandbox_handle
        else:
            try:
                handle = self.sandbox_adapter.create_sandbox(
                    image=self.config.sandbox_image,
                    disposable=True,
                )
                created_handle = True
            except Exception as exc:
                raise WorkspaceExecutionError(
                    f"Failed to create disposable candidate sandbox: {exc}"
                ) from exc

        # Extract sandbox identity
        sbx_identity = getattr(
            handle, "sandbox_identity", SandboxIdentity(sandbox_id="sbx-unidentified")
        )

        mutation_records: list[FileMutationRecord] = []
        command_records: list[CommandExecutionRecord] = []

        try:
            # Step 4: Execute File Mutations
            for norm_path, action in normalized_actions.items():
                scripts = build_file_mutation_scripts(norm_path, action, clean_workspace)
                last_result: Any = None
                action_duration = 0.0

                for script in scripts:
                    try:
                        res = self.sandbox_adapter.execute_command(
                            handle,
                            script,
                            working_dir=clean_workspace,
                            timeout_seconds=self.config.per_command_timeout_seconds,
                        )
                    except Exception as exc:
                        # Normalize timeout vs general adapter error
                        if (
                            "timeout" in type(exc).__name__.lower()
                            or "timed out" in str(exc).lower()
                        ):
                            raise CandidateExecutionTimeoutError(
                                f"Timeout applying file mutation for {norm_path!r}: {exc}"
                            ) from exc
                        raise WorkspaceExecutionError(
                            f"Sandbox failure applying file mutation for {norm_path!r}: {exc}"
                        ) from exc

                    last_result = res
                    dur = getattr(res, "duration_seconds", 0.0) or 0.0
                    action_duration += float(dur)

                    exit_code = getattr(res, "exit_code", None)
                    if exit_code != 0:
                        break

                exit_code = getattr(last_result, "exit_code", -1) if last_result else -1
                raw_stdout = getattr(last_result, "stdout", "")
                raw_stderr = getattr(last_result, "stderr", "")

                stdout_digest = getattr(last_result, "stdout_digest", None)
                if not stdout_digest:
                    stdout_digest = compute_bytes_digest(raw_stdout.encode("utf-8")).value

                stderr_digest = getattr(last_result, "stderr_digest", None)
                if not stderr_digest:
                    stderr_digest = compute_bytes_digest(raw_stderr.encode("utf-8")).value

                content_digest = (
                    compute_bytes_digest(action.content.encode("utf-8")).value
                    if action.action != FileActionType.DELETE
                    else ""
                )

                rec = FileMutationRecord(
                    path=norm_path,
                    action=action.action,
                    exit_code=exit_code if exit_code is not None else -1,
                    stdout_digest=stdout_digest,
                    stderr_digest=stderr_digest,
                    duration_seconds=action_duration,
                    content_digest=content_digest,
                    is_success=(exit_code == 0),
                    sandbox_identity=sbx_identity,
                    is_authoritative=False,
                )
                mutation_records.append(rec)

                # Check fail-closed exit codes
                if exit_code != 0:
                    err_msg = (
                        f"Mutation failed for {norm_path!r} ({action.action.value}) "
                        f"with exit code {exit_code}: {raw_stderr}"
                    )
                    if exit_code == 101:
                        raise TargetAlreadyExistsError(err_msg)
                    if exit_code in (102, 103):
                        raise MissingTargetError(err_msg)
                    raise WorkspaceExecutionError(err_msg)

            # Step 5: Execute Proposed Commands
            for cmd_str in validated_commands:
                try:
                    cmd_res = self.sandbox_adapter.execute_command(
                        handle,
                        cmd_str,
                        working_dir=clean_workspace,
                        timeout_seconds=self.config.per_command_timeout_seconds,
                    )
                except Exception as exc:
                    if "timeout" in type(exc).__name__.lower() or "timed out" in str(exc).lower():
                        raise CandidateExecutionTimeoutError(
                            f"Timeout executing command {cmd_str!r}: {exc}"
                        ) from exc
                    raise WorkspaceExecutionError(
                        f"Sandbox failure executing command {cmd_str!r}: {exc}"
                    ) from exc

                is_to = getattr(cmd_res, "is_timeout", False)
                if is_to:
                    raise CandidateExecutionTimeoutError(
                        f"Command {cmd_str!r} timed out inside candidate sandbox"
                    )

                cmd_exit = getattr(cmd_res, "exit_code", None)
                cmd_dur = getattr(cmd_res, "duration_seconds", None)
                cmd_stdout = getattr(cmd_res, "stdout", "")
                cmd_stderr = getattr(cmd_res, "stderr", "")

                cmd_so_digest = getattr(cmd_res, "stdout_digest", None)
                if not cmd_so_digest:
                    cmd_so_digest = compute_bytes_digest(cmd_stdout.encode("utf-8")).value

                cmd_se_digest = getattr(cmd_res, "stderr_digest", None)
                if not cmd_se_digest:
                    cmd_se_digest = compute_bytes_digest(cmd_stderr.encode("utf-8")).value

                status: TerminationStatus
                if getattr(cmd_res, "is_cancelled", False):
                    status = TerminationStatus.CANCELLED
                elif cmd_exit is not None:
                    status = TerminationStatus.COMPLETED
                else:
                    status = TerminationStatus.FAILED_TO_START

                cmd_rec = CommandExecutionRecord(
                    command=cmd_str,
                    exit_code=cmd_exit,
                    stdout_digest=cmd_so_digest,
                    stderr_digest=cmd_se_digest,
                    duration_seconds=float(cmd_dur) if cmd_dur is not None else None,
                    status=status,
                    sandbox_identity=sbx_identity,
                    is_authoritative=False,
                )
                command_records.append(cmd_rec)

        except Exception:
            # Teardown on failure if handle was created by this executor
            if created_handle and self.config.teardown_on_failure:
                try:
                    self.sandbox_adapter.teardown_sandbox(handle)
                except Exception:
                    pass
            raise

        # Step 6: Teardown on completion if configured
        if created_handle and self.config.teardown_on_completion:
            try:
                self.sandbox_adapter.teardown_sandbox(handle)
            except Exception:
                pass

        total_duration = time.perf_counter() - start_time

        # Step 7: Return CandidateExecutionResult
        return CandidateExecutionResult(
            frozen_contract_digest=resolved_contract_digest,
            context_digest=resolved_context_digest,
            source_identity=resolved_source_id,
            proposal_digest=proposal_digest,
            proposal_plan_summary=proposal.plan.summary,
            file_mutations=tuple(mutation_records),
            command_executions=tuple(command_records),
            sandbox_identity=sbx_identity,
            total_duration_seconds=total_duration,
            provenance=provenance,
            is_authoritative=False,
        )
