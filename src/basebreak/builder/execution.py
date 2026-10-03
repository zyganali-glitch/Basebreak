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
from typing import Any, Protocol, runtime_checkable

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
    FileChange,
    FileChangeKind,
    InvalidPathError,
    PathSecurityError,
    PathTraversalError,
    ProtectedSurfaceManifest,
    ProtectedSurfaceViolation,
    check_change,
    get_canonical_basebreak_protected_manifest,
    validate_path,
)
from basebreak.security.sandbox_policy import (
    MAX_SANDBOX_TIMEOUT_SECONDS,
    MIN_SANDBOX_TIMEOUT_SECONDS,
    ProcessPolicyError,
    validate_command_string,
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


class MaterializedSourceVerificationError(CandidateExecutionError):
    """Base exception for materialized source workspace verification failures."""


class MissingAuthoritativeEnvelopeError(CandidateExecutionError):
    """Raised when execution is attempted without an authoritative BuilderContextEnvelope."""


class UnmaterializedWorkspaceError(MaterializedSourceVerificationError):
    """Raised when workspace has not been materialized from authoritative source."""


class MaterializedSourceMismatchError(MaterializedSourceVerificationError):
    """Base exception when materialized workspace does not match authoritative envelope."""


class SourceCommitMismatchError(MaterializedSourceMismatchError):
    """Raised when materialized source commit does not match authoritative envelope commit."""


class SandboxIdentityMismatchError(MaterializedSourceMismatchError):
    """Raised when materialized workspace sandbox identity does not match execution sandbox."""


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


@runtime_checkable
class MaterializedSourceBinding(Protocol):
    """Protocol for verified repository source materialization in a sandbox workspace.

    Satisfied by canonical MaterializedSourceRecord from P-05.
    """

    @property
    def source_identity(self) -> SourceIdentity: ...

    @property
    def resolved_commit_sha(self) -> str: ...

    @property
    def workspace_path(self) -> str: ...

    @property
    def sandbox_identity(self) -> SandboxIdentity: ...

    @property
    def is_verified(self) -> bool: ...


@runtime_checkable
class SourceMaterializerProtocol(Protocol):
    """Protocol for repository source materializer.

    Satisfied by canonical NebiusSourceMaterializer from P-05.
    """

    def materialize_repository(
        self,
        source_identity: SourceIdentity,
        *,
        sandbox: Any = None,
        workspace_path: str = "/workspace/repo",
        timeout_seconds: int = 120,
        **kwargs: Any,
    ) -> Any: ...


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
    enforce_protected_surfaces: bool = True
    protected_manifest: ProtectedSurfaceManifest | None = None
    bundled_execution: bool = False
    clean_base_record: Any | None = None

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
        if not self.enforce_protected_surfaces:
            raise CandidateExecutionConfigError(
                "enforce_protected_surfaces cannot be disabled; "
                "canonical P-04 protected-surface policy is mandatory and non-downgradable"
            )
        if self.protected_manifest is not None:
            raise CandidateExecutionConfigError(
                "Caller cannot override protected_manifest in CandidateExecutionConfig; "
                "canonical P-04 protected-surface policy is mandatory and non-downgradable"
            )


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
    workspace_path: str = DEFAULT_WORKSPACE_PATH
    provenance: EvidenceProvenance = EvidenceProvenance.LOCAL_EXECUTION
    is_authoritative: bool = False
    bundled_snapshot: Any | None = None

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
        if not isinstance(self.workspace_path, str) or not self.workspace_path.strip():
            raise ValueError("workspace_path must be a non-empty string")
        try:
            clean_ws = validate_workspace_path(self.workspace_path)
            object.__setattr__(self, "workspace_path", clean_ws)
        except Exception as exc:
            raise ValueError(f"Invalid workspace_path {self.workspace_path!r}: {exc}") from exc
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
            "workspace_path": self.workspace_path,
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

        raw_ws = data.get("workspace_path", DEFAULT_WORKSPACE_PATH)
        if not isinstance(raw_ws, str) or not raw_ws.strip():
            raise TypeError("workspace_path must be a non-empty string")

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
            workspace_path=raw_ws,
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


def validate_materialized_workspace(
    materialization_record: Any,
    envelope: BuilderContextEnvelope,
    expected_workspace_path: str,
    expected_sandbox_identity: SandboxIdentity,
) -> None:
    """Validate that candidate workspace is deterministically materialized from envelope source.

    Proves:
    1. Materialization verification succeeded (is_verified is True);
    2. Materialized commit matches envelope.source_identity.resolved_commit_id;
    3. Materialized source locator matches envelope.source_identity.locator;
    4. Materialized source subpath matches envelope.source_identity.subpath;
    5. Materialized workspace path matches expected candidate workspace path;
    6. Materialized sandbox identity matches expected sandbox identity.

    Fails closed if any invariant is violated or if materialization_record is malformed.
    """
    if materialization_record is None:
        raise UnmaterializedWorkspaceError(
            "Candidate workspace has not been materialized from authoritative source"
        )

    # 1. Verification status
    is_verified = getattr(materialization_record, "is_verified", None)
    if is_verified is not True:
        raise MaterializedSourceVerificationError(
            f"Materialized workspace verification did not succeed (is_verified={is_verified!r})"
        )

    # 2. Resolved commit match
    actual_commit = getattr(materialization_record, "resolved_commit_sha", None)
    if not isinstance(actual_commit, str) or not actual_commit.strip():
        raise MaterializedSourceVerificationError(
            "Materialized source record missing resolved_commit_sha"
        )
    expected_commit = envelope.source_identity.resolved_commit_id
    if actual_commit.strip().lower() != expected_commit.strip().lower():
        raise SourceCommitMismatchError(
            f"Materialized workspace source commit {actual_commit!r} does not match "
            f"authoritative envelope commit {expected_commit!r}"
        )

    # 3. Source locator match
    mat_source_id = getattr(materialization_record, "source_identity", None)
    mat_locator = (
        getattr(mat_source_id, "locator", None)
        if mat_source_id is not None
        else getattr(materialization_record, "source_locator", None)
    )
    if not isinstance(mat_locator, str) or not mat_locator.strip():
        raise MaterializedSourceVerificationError(
            "Materialized source record missing valid source_identity or locator"
        )
    expected_locator = envelope.source_identity.locator
    if mat_locator.strip() != expected_locator.strip():
        raise MaterializedSourceMismatchError(
            f"Materialized workspace source locator {mat_locator!r} does not match "
            f"authoritative envelope locator {expected_locator!r}"
        )

    # 4. Source subpath semantics match (where applicable)
    expected_subpath = envelope.source_identity.subpath
    actual_subpath = (
        getattr(mat_source_id, "subpath", None)
        if mat_source_id is not None
        else getattr(materialization_record, "subpath", None)
    )
    if expected_subpath != actual_subpath:
        raise MaterializedSourceMismatchError(
            f"Materialized workspace source subpath {actual_subpath!r} does not match "
            f"authoritative envelope subpath {expected_subpath!r}"
        )

    # 5. Workspace path match
    actual_ws = getattr(materialization_record, "workspace_path", None)
    if not isinstance(actual_ws, str) or not actual_ws.strip():
        raise MaterializedSourceVerificationError(
            "Materialized source record missing valid workspace_path"
        )
    if actual_ws.strip().rstrip("/") != expected_workspace_path.strip().rstrip("/"):
        raise MaterializedSourceMismatchError(
            f"Materialized workspace path {actual_ws!r} does not match "
            f"candidate execution workspace path {expected_workspace_path!r}"
        )

    # 6. Sandbox identity match
    actual_sbx_id = getattr(materialization_record, "sandbox_identity", None)
    if actual_sbx_id is None or not isinstance(actual_sbx_id, SandboxIdentity):
        raise MaterializedSourceVerificationError(
            "Materialized source record missing valid SandboxIdentity"
        )
    if not actual_sbx_id.sandbox_id or not actual_sbx_id.sandbox_id.strip():
        raise MaterializedSourceVerificationError(
            "Materialized source record contains empty or whitespace sandbox_id"
        )
    if actual_sbx_id != expected_sandbox_identity:
        raise SandboxIdentityMismatchError(
            f"Materialized workspace sandbox identity {actual_sbx_id!r} does not match "
            f"candidate execution sandbox identity {expected_sandbox_identity!r}"
        )


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
    protected_manifest: ProtectedSurfaceManifest | None = None,
) -> tuple[dict[str, ProposedFileAction], tuple[str, ...]]:
    """Validate Builder proposal against structural, bounding, and security invariants.

    Returns:
        Tuple of (mapping of normalized_path -> ProposedFileAction,
        tuple of validated command strings).

    Fails closed if:
    - proposal is not BuilderProposal or is_authoritative is True;
    - file action count exceeds max_file_actions;
    - path touches or targets a canonical protected surface;
    - path traversal, root escape, drive letters, or malformed paths detected;
    - duplicate/conflicting actions for the same normalized path detected;
    - file content exceeds max_file_bytes;
    - secret detected in any file content, rationale, or command;
    - command count exceeds max_commands;
    - command exceeds max_command_length_bytes or contains null bytes;
    - forbidden shell recursion, fork bomb, or daemon pattern detected;
    - command violates canonical sandbox process policy.
    """
    if not isinstance(proposal, BuilderProposal):
        raise TypeError(f"proposal must be BuilderProposal, got {type(proposal).__name__}")
    if proposal.is_authoritative is not False:
        raise InvalidProposedMutationError(
            "BuilderProposal is_authoritative must be strictly False"
        )
    if protected_manifest is not None:
        raise InvalidProposedMutationError(
            "Caller cannot supply protected_manifest to validate_candidate_proposal; "
            "canonical P-04 protected-surface policy is mandatory and non-downgradable"
        )
    if not getattr(config, "enforce_protected_surfaces", True):
        raise CandidateExecutionConfigError(
            "enforce_protected_surfaces cannot be disabled; "
            "canonical P-04 protected-surface policy is mandatory and non-downgradable"
        )
    if getattr(config, "protected_manifest", None) is not None:
        raise CandidateExecutionConfigError(
            "Caller cannot supply protected_manifest in CandidateExecutionConfig; "
            "canonical P-04 protected-surface policy is mandatory and non-downgradable"
        )

    manifest = get_canonical_basebreak_protected_manifest()

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

        # Map action type to canonical FileChangeKind
        kind: FileChangeKind
        if action.action == FileActionType.CREATE:
            kind = FileChangeKind.ADD
        elif action.action == FileActionType.MODIFY:
            kind = FileChangeKind.MODIFY
        elif action.action == FileActionType.DELETE:
            kind = FileChangeKind.DELETE
        else:
            raise InvalidProposedMutationError(f"Unsupported action type: {action.action}")

        # Normalize path and check for traversal / root escape / protected surfaces
        try:
            norm_path = validate_path(action.path, manifest)
        except ProtectedSurfaceViolation:
            raise
        except (PathTraversalError, InvalidPathError, PathSecurityError) as exc:
            raise InvalidProposedMutationError(
                f"Invalid or unsafe path in action at index {idx} ({action.path!r}): {exc}"
            ) from exc

        # Validate FileChange representation against manifest
        change = FileChange(path=norm_path, kind=kind)
        findings = check_change(change, manifest)
        if findings:
            first = findings[0]
            raise ProtectedSurfaceViolation(
                f"Proposed file action targets protected surface: {first.message}",
                findings=tuple(findings),
            )

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

        # Canonical P-04 sandbox policy validation (null byte, length, secret-shaped values)
        try:
            validate_command_string(cmd_str)
        except ProcessPolicyError as exc:
            if "secret-shaped" in str(exc).lower():
                raise CredentialLeakageError(
                    f"Secret-shaped value detected in command at index {idx}: {exc}"
                ) from exc
            raise CommandBoundingError(
                f"Command at index {idx} violates sandbox process policy: {exc}"
            ) from exc

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
    - Authoritative context binding: requires genuine BuilderContextEnvelope.
    - Bare contract/context/source digest authority paths are strictly forbidden.
    - Caller-supplied materialized_source authority paths are strictly forbidden.
    - Authoritative source materializer invocation: repository is materialized in candidate sandbox
      strictly by invoking a trusted source materializer before any mutations or commands execute.
    - Verified source materialization: proves workspace matches envelope source before mutation.
    - Deterministic sandbox identity: fails closed on missing/unidentified sandboxes.
    - Application of proposed mutations (CREATE, MODIFY, DELETE) through POSIX shell primitives.
    - Bounded execution of proposed commands inside disposable candidate sandbox.
    - Fail-closed recording of all deterministic execution facts.
    - Zero self-certification: is_authoritative is strictly False across all output.
    """

    def __init__(
        self,
        sandbox_adapter: Any,
        *,
        source_materializer: Any | None = None,
        config: CandidateExecutionConfig | None = None,
    ) -> None:
        if sandbox_adapter is None:
            raise HostExecutionFallbackError(
                "sandbox_adapter is required; host execution fallback is strictly prohibited"
            )
        resolved_config = config or CandidateExecutionConfig()
        if not getattr(resolved_config, "enforce_protected_surfaces", True):
            raise CandidateExecutionConfigError(
                "enforce_protected_surfaces cannot be disabled; "
                "canonical P-04 protected-surface policy is mandatory and non-downgradable"
            )
        if getattr(resolved_config, "protected_manifest", None) is not None:
            raise CandidateExecutionConfigError(
                "Caller cannot override protected_manifest in config; "
                "canonical P-04 protected-surface policy is mandatory and non-downgradable"
            )
        self.sandbox_adapter = sandbox_adapter
        self.source_materializer = source_materializer
        self.config = resolved_config

    def execute(
        self,
        proposal: BuilderProposal,
        *,
        envelope: BuilderContextEnvelope | None = None,
        source_materializer: Any | None = None,
        sandbox_handle: Any | None = None,
        provenance: EvidenceProvenance = EvidenceProvenance.LOCAL_EXECUTION,
        **kwargs: Any,
    ) -> CandidateExecutionResult:
        """Execute validated Builder proposal inside candidate sandbox.

        Steps:
        1. Reject caller-supplied materialized_source and bare digest inputs; enforce envelope.
        2. Resolve active source materializer (fail closed if not provided).
        3. Validate proposal actions and commands against bounds and security invariants.
        4. Acquire sandbox handle (use provided or create disposable).
        5. Validate deterministic SandboxIdentity on handle (fail closed if missing/empty).
        6. Materialize repository inside sandbox VM using authoritative source identity.
        7. Validate that returned materialization record matches envelope, workspace, and sandbox.
        8. Execute file mutations inside the candidate workspace.
        9. Execute proposed commands inside the candidate workspace.
        10. Clean up sandbox if configured.
        11. Return deterministic CandidateExecutionResult.
        """
        # Step 1: Reject caller-supplied materialized_source and bare digest inputs
        if kwargs:
            if "materialized_source" in kwargs:
                raise MaterializedSourceVerificationError(
                    "Caller-supplied materialized_source is strictly forbidden; "
                    "candidate execution requires an authoritative source materializer invocation"
                )
            forbidden_keys = {"frozen_contract_digest", "context_digest", "source_identity"}
            intersect = set(kwargs.keys()) & forbidden_keys
            if intersect:
                raise MissingAuthoritativeEnvelopeError(
                    f"Bare digest inputs {sorted(intersect)} are strictly forbidden; "
                    "execution requires an authoritative BuilderContextEnvelope"
                )
            raise TypeError(f"Unexpected keyword arguments: {sorted(kwargs.keys())}")

        if envelope is None or not isinstance(envelope, BuilderContextEnvelope):
            raise MissingAuthoritativeEnvelopeError(
                "envelope must be an authoritative BuilderContextEnvelope; "
                "execution cannot proceed without authoritative context"
            )

        resolved_contract_digest = envelope.frozen_contract.contract_digest
        resolved_context_digest = envelope.context_digest
        resolved_source_id = envelope.source_identity

        # Step 2: Resolve active source materializer (fail closed if absent)
        active_materializer = source_materializer or self.source_materializer
        if active_materializer is None:
            raise UnmaterializedWorkspaceError(
                "Cannot execute candidate in unmaterialized workspace: "
                "source_materializer dependency is required"
            )

        # Step 3: Validate Proposal & Commands
        normalized_actions, validated_commands = validate_candidate_proposal(proposal, self.config)
        proposal_digest = compute_proposal_digest(proposal)
        clean_workspace = validate_workspace_path(self.config.workspace_path)

        start_time = time.perf_counter()

        # Step 4: Acquire Sandbox Handle
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

        try:
            # Step 5: Extract and Validate Sandbox Identity - FAIL CLOSED if missing or invalid
            sbx_identity = getattr(handle, "sandbox_identity", None)
            if sbx_identity is None or not isinstance(sbx_identity, SandboxIdentity):
                raise WorkspaceExecutionError(
                    "Sandbox handle lacks a deterministic SandboxIdentity; "
                    "unidentified sandboxes are strictly prohibited"
                )
            if not sbx_identity.sandbox_id or not sbx_identity.sandbox_id.strip():
                raise WorkspaceExecutionError(
                    "Sandbox handle contains an empty or whitespace sandbox_id; "
                    "unidentified sandboxes are strictly prohibited"
                )

            # Step 6: Materialize Authoritative Source Repository inside Sandbox VM
            if self.config.clean_base_record is not None:
                cbr = self.config.clean_base_record
                if getattr(cbr, "is_verified", None) is not True:
                    raise MaterializedSourceVerificationError("clean_base_record is not verified")
                actual_commit = str(getattr(cbr, "resolved_commit_sha", ""))
                if (
                    actual_commit.strip().lower()
                    != resolved_source_id.resolved_commit_id.strip().lower()
                ):
                    raise SourceCommitMismatchError(
                        f"clean_base_record commit {actual_commit!r} does not match "
                        f"authoritative envelope commit {resolved_source_id.resolved_commit_id!r}"
                    )
                actual_ws = str(getattr(cbr, "workspace_path", ""))
                if actual_ws.strip().rstrip("/") != clean_workspace.strip().rstrip("/"):
                    raise MaterializedSourceMismatchError(
                        f"clean_base_record workspace path {actual_ws!r} "
                        f"does not match {clean_workspace!r}"
                    )
                mat_source = getattr(cbr, "source_identity", None)
                if (
                    mat_source is not None
                    and getattr(mat_source, "locator", "") != resolved_source_id.locator
                ):
                    raise MaterializedSourceMismatchError(
                        f"clean_base_record locator does not match {resolved_source_id.locator!r}"
                    )
                if not getattr(cbr, "result_image_uuid", None):
                    raise MaterializedSourceVerificationError(
                        "clean_base_record missing result_image_uuid"
                    )
                materialization_record = cbr
            else:
                try:
                    materialization_record = active_materializer.materialize_repository(
                        resolved_source_id,
                        sandbox=handle,
                        workspace_path=clean_workspace,
                        disposable=True,
                        timeout_seconds=self.config.per_command_timeout_seconds,
                    )
                except Exception as exc:
                    raise WorkspaceExecutionError(
                        f"Failed to materialize authoritative repository in sandbox: {exc}"
                    ) from exc

                # Step 7: Validate Materialized Source Workspace
                validate_materialized_workspace(
                    materialization_record,
                    envelope=envelope,
                    expected_workspace_path=clean_workspace,
                    expected_sandbox_identity=sbx_identity,
                )

            # Check if bundled execution mode is requested
            if self.config.bundled_execution:
                return self._execute_bundled(
                    handle=handle,
                    clean_workspace=clean_workspace,
                    normalized_actions=normalized_actions,
                    validated_commands=validated_commands,
                    sbx_identity=sbx_identity,
                    resolved_contract_digest=resolved_contract_digest,
                    resolved_context_digest=resolved_context_digest,
                    resolved_source_id=resolved_source_id,
                    proposal_digest=proposal_digest,
                    proposal=proposal,
                    start_time=start_time,
                    provenance=provenance,
                    created_handle=created_handle,
                )

            # Step 8: Execute File Mutations
            mutation_records: list[FileMutationRecord] = []
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

            # Step 7: Execute Proposed Commands
            command_records: list[CommandExecutionRecord] = []
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
            workspace_path=clean_workspace,
            provenance=provenance,
            is_authoritative=False,
        )

    def _execute_bundled(
        self,
        *,
        handle: Any,
        clean_workspace: str,
        normalized_actions: dict[str, ProposedFileAction],
        validated_commands: tuple[str, ...],
        sbx_identity: SandboxIdentity,
        resolved_contract_digest: str,
        resolved_context_digest: str,
        resolved_source_id: SourceIdentity,
        proposal_digest: str,
        proposal: BuilderProposal,
        start_time: float,
        provenance: EvidenceProvenance,
        created_handle: bool,
    ) -> CandidateExecutionResult:
        """Execute file actions, commands, and git capture in a single bundled script."""
        lines: list[str] = ["set -e", f"cd {shlex.quote(clean_workspace)}"]

        # Apply mutations
        for norm_path, action in normalized_actions.items():
            target_abs = f"{clean_workspace}/{norm_path}"
            target_dir = "/".join(target_abs.split("/")[:-1])
            q_target = shlex.quote(target_abs)
            q_dir = shlex.quote(target_dir)

            if action.action == FileActionType.DELETE:
                lines.append(
                    f"if [ ! -e {q_target} ] && [ ! -L {q_target} ]; then\n"
                    f'    echo "BASEBREAK_MUTATION_ERROR: '
                    f'DELETE target not found: {norm_path}" >&2\n'
                    f"    exit 103\n"
                    f"fi\n"
                    f"rm -rf {q_target}\n"
                    f"if [ -e {q_target} ] || [ -L {q_target} ]; then\n"
                    f'    echo "BASEBREAK_MUTATION_ERROR: '
                    f'DELETE target removal unverified: {norm_path}" >&2\n'
                    f"    exit 105\n"
                    f"fi"
                )
            else:
                b64_content = base64.b64encode(action.content.encode("utf-8")).decode("ascii")
                if action.action == FileActionType.CREATE:
                    lines.append(
                        f"if [ -e {q_target} ] || [ -L {q_target} ]; then\n"
                        f'    echo "BASEBREAK_MUTATION_ERROR: '
                        f'CREATE target already exists: {norm_path}" >&2\n'
                        f"    exit 101\n"
                        f"fi"
                    )
                else:  # MODIFY
                    lines.append(
                        f"if [ ! -f {q_target} ]; then\n"
                        f'    echo "BASEBREAK_MUTATION_ERROR: '
                        f'MODIFY target not found: {norm_path}" >&2\n'
                        f"    exit 102\n"
                        f"fi"
                    )
                lines.append(f"mkdir -p {q_dir}")
                if b64_content:
                    lines.append(f'printf "%s" {shlex.quote(b64_content)} | base64 -d > {q_target}')
                else:
                    lines.append(f": > {q_target}")
                lines.append(
                    f"if [ ! -f {q_target} ]; then\n"
                    f'    echo "BASEBREAK_MUTATION_ERROR: '
                    f'Target file creation unverified: {norm_path}" >&2\n'
                    f"    exit 104\n"
                    f"fi"
                )

        # Run commands
        for idx, cmd_str in enumerate(validated_commands):
            cmd_out_path = f"/tmp/basebreak_cmd_out_{idx}.log"
            cmd_err_path = f"/tmp/basebreak_cmd_err_{idx}.log"
            q_out = shlex.quote(cmd_out_path)
            q_err = shlex.quote(cmd_err_path)
            b64_out = f"$(base64 -w 0 {q_out} 2>/dev/null || base64 {q_out} | tr -d '\\n')"
            b64_err = f"$(base64 -w 0 {q_err} 2>/dev/null || base64 {q_err} | tr -d '\\n')"
            lines.append(
                f"set +e\n"
                f"{cmd_str} > {q_out} 2> {q_err}\n"
                f"CMD_EXIT_{idx}=$?\n"
                f"set -e\n"
                f'echo "BASEBREAK_CMD_EXIT_{idx}=$CMD_EXIT_{idx}"\n'
                f'echo "BASEBREAK_CMD_OUT_B64_{idx}={b64_out}"\n'
                f'echo "BASEBREAK_CMD_ERR_B64_{idx}={b64_err}"\n'
                f"rm -f {q_out} {q_err}"
            )

        # Git capture
        diff_path = "/tmp/basebreak_diff.patch"
        status_path = "/tmp/basebreak_status.txt"
        q_stat = shlex.quote(status_path)
        q_diff = shlex.quote(diff_path)
        b64_stat = f"$(base64 -w 0 {q_stat} 2>/dev/null || base64 {q_stat} | tr -d '\\n')"
        b64_diff = f"$(base64 -w 0 {q_diff} 2>/dev/null || base64 {q_diff} | tr -d '\\n')"
        lines.append(
            'echo "BASEBREAK_TOPLEVEL=$(git rev-parse --show-toplevel)"\n'
            'echo "BASEBREAK_HEAD=$(git rev-parse HEAD)"\n'
            "git add -A\n"
            'echo "BASEBREAK_CANDIDATE_TREE=$(git write-tree)"\n'
            f"git diff --name-status --no-renames --cached HEAD > {q_stat}\n"
            f'echo "BASEBREAK_STATUS_B64={b64_stat}"\n'
            f"rm -f {q_stat}\n"
            f"git diff --binary --full-index --cached HEAD > {q_diff}\n"
            f'echo "BASEBREAK_DIFF_B64={b64_diff}"\n'
            f"rm -f {q_diff}"
        )

        bundle_script = "\n".join(lines)

        try:
            res = self.sandbox_adapter.execute_command(
                handle,
                bundle_script,
                working_dir=clean_workspace,
                timeout_seconds=self.config.per_command_timeout_seconds,
            )
        except Exception as exc:
            if "timeout" in type(exc).__name__.lower() or "timed out" in str(exc).lower():
                raise CandidateExecutionTimeoutError(
                    f"Timeout executing bundled candidate script: {exc}"
                ) from exc
            raise WorkspaceExecutionError(
                f"Sandbox failure executing bundled candidate script: {exc}"
            ) from exc

        if getattr(res, "is_timeout", False):
            raise CandidateExecutionTimeoutError(
                "Bundled candidate script timed out inside candidate sandbox"
            )

        exit_code = getattr(res, "exit_code", -1)
        raw_stdout = getattr(res, "stdout", "")
        raw_stderr = getattr(res, "stderr", "")

        if exit_code != 0:
            err_msg = f"Bundled candidate execution failed with exit code {exit_code}: {raw_stderr}"
            if exit_code == 101:
                raise TargetAlreadyExistsError(err_msg)
            if exit_code in (102, 103):
                raise MissingTargetError(err_msg)
            raise WorkspaceExecutionError(err_msg)

        # Toplevel check
        toplevel_match = re.search(r"BASEBREAK_TOPLEVEL=([^\r\n]+)", raw_stdout)
        if not toplevel_match or toplevel_match.group(1).strip().rstrip(
            "/"
        ) != clean_workspace.rstrip("/"):
            raise WorkspaceExecutionError(
                "Candidate top-level workspace check failed in bundled execution"
            )

        # Head commit check
        head_match = re.search(r"BASEBREAK_HEAD=([0-9a-fA-F]{40,64})", raw_stdout)
        if (
            not head_match
            or head_match.group(1).strip().lower()
            != resolved_source_id.resolved_commit_id.strip().lower()
        ):
            raise WorkspaceExecutionError("Candidate HEAD commit check failed in bundled execution")

        # Candidate tree
        tree_match = re.search(r"BASEBREAK_CANDIDATE_TREE=([0-9a-fA-F]{40,64})", raw_stdout)
        if not tree_match:
            raise WorkspaceExecutionError(
                "Could not parse BASEBREAK_CANDIDATE_TREE from bundled execution output"
            )
        candidate_tree_sha = tree_match.group(1).strip().lower()

        from basebreak.builder.capture import (
            BinaryDiffUnsupportedError,
            CandidateSnapshot,
            identify_builder_authored_tests,
            parse_git_name_status,
        )

        # Status output
        status_match = re.search(r"BASEBREAK_STATUS_B64=([A-Za-z0-9+/=]*)", raw_stdout)
        status_b64 = status_match.group(1) if status_match else ""
        status_text = (
            base64.b64decode(status_b64.encode("ascii")).decode("utf-8") if status_b64 else ""
        )
        files_added, files_modified, files_deleted = parse_git_name_status(status_text)

        # Diff output
        diff_match = re.search(r"BASEBREAK_DIFF_B64=([A-Za-z0-9+/=]*)", raw_stdout)
        diff_b64 = diff_match.group(1) if diff_match else ""
        diff_bytes = base64.b64decode(diff_b64.encode("ascii")) if diff_b64 else b""
        if b"Binary files" in diff_bytes and b"differ" in diff_bytes:
            raise BinaryDiffUnsupportedError(
                "Non-reproducible binary diff detected: git reported binary files differ "
                "without reproducible binary patch"
            )
        diff_text = diff_bytes.decode("utf-8", errors="replace")
        patch_digest = compute_bytes_digest(diff_bytes).value

        mutation_records: list[FileMutationRecord] = []
        for norm_path, action in normalized_actions.items():
            content_digest = (
                compute_bytes_digest(action.content.encode("utf-8")).value
                if action.action != FileActionType.DELETE
                else ""
            )
            rec = FileMutationRecord(
                path=norm_path,
                action=action.action,
                exit_code=0,
                stdout_digest=compute_bytes_digest(b"").value,
                stderr_digest=compute_bytes_digest(b"").value,
                duration_seconds=0.0,
                content_digest=content_digest,
                is_success=True,
                sandbox_identity=sbx_identity,
                is_authoritative=False,
            )
            mutation_records.append(rec)

        command_records: list[CommandExecutionRecord] = []
        for idx, cmd_str in enumerate(validated_commands):
            cmd_exit_m = re.search(rf"BASEBREAK_CMD_EXIT_{idx}=(\d+)", raw_stdout)
            c_exit = int(cmd_exit_m.group(1)) if cmd_exit_m else None

            cmd_out_m = re.search(rf"BASEBREAK_CMD_OUT_B64_{idx}=([A-Za-z0-9+/=]*)", raw_stdout)
            cmd_out_b64 = cmd_out_m.group(1) if cmd_out_m else ""
            cmd_out_bytes = base64.b64decode(cmd_out_b64.encode("ascii")) if cmd_out_b64 else b""
            cmd_so_digest = compute_bytes_digest(cmd_out_bytes).value

            cmd_err_m = re.search(rf"BASEBREAK_CMD_ERR_B64_{idx}=([A-Za-z0-9+/=]*)", raw_stdout)
            cmd_err_b64 = cmd_err_m.group(1) if cmd_err_m else ""
            cmd_err_bytes = base64.b64decode(cmd_err_b64.encode("ascii")) if cmd_err_b64 else b""
            cmd_se_digest = compute_bytes_digest(cmd_err_bytes).value

            cmd_rec = CommandExecutionRecord(
                command=cmd_str,
                exit_code=c_exit,
                stdout_digest=cmd_so_digest,
                stderr_digest=cmd_se_digest,
                duration_seconds=None,
                status=TerminationStatus.COMPLETED
                if c_exit is not None
                else TerminationStatus.FAILED_TO_START,
                sandbox_identity=sbx_identity,
                is_authoritative=False,
            )
            command_records.append(cmd_rec)

        if created_handle and self.config.teardown_on_completion:
            try:
                self.sandbox_adapter.teardown_sandbox(handle)
            except Exception:
                pass

        total_duration = time.perf_counter() - start_time

        exec_result = CandidateExecutionResult(
            frozen_contract_digest=resolved_contract_digest,
            context_digest=resolved_context_digest,
            source_identity=resolved_source_id,
            proposal_digest=proposal_digest,
            proposal_plan_summary=proposal.plan.summary,
            file_mutations=tuple(mutation_records),
            command_executions=tuple(command_records),
            sandbox_identity=sbx_identity,
            total_duration_seconds=total_duration,
            workspace_path=clean_workspace,
            provenance=provenance,
            is_authoritative=False,
        )

        builder_tests = identify_builder_authored_tests(exec_result)
        cid = f"cand-{patch_digest[:16]}"
        snapshot = CandidateSnapshot(
            candidate_id=cid,
            source_identity=resolved_source_id,
            candidate_tree_digest=candidate_tree_sha,
            patch_digest=patch_digest,
            patch_text=diff_text,
            files_added=files_added,
            files_modified=files_modified,
            files_deleted=files_deleted,
            builder_authored_tests=builder_tests,
            frozen_contract_digest=resolved_contract_digest,
            context_digest=resolved_context_digest,
            sandbox_identity=sbx_identity,
            duration_seconds=total_duration,
            provenance=provenance,
            is_authoritative=False,
        )
        object.__setattr__(exec_result, "bundled_snapshot", snapshot)
        return exec_result
