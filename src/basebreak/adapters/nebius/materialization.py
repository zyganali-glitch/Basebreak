"""Repository materialization and deterministic source-hash verification adapter.

Authority:
- Proven in P-01.04 (docs/P01_04_LIVE_REPO_MATERIALIZATION.md) and P-01.05
- Domain contracts in src/basebreak/domain/source.py (SourceIdentity, CommitRevision)
- Sandbox adapter in src/basebreak/adapters/nebius/sandbox.py (NebiusSandboxAdapter)
- Binds materialized repository state to the exact requested immutable revision.
- Rejects mutable branch labels alone, builder summaries, or provider prose.
- Deterministic verification: actual git commit and tree hashes must match requested truth.
- Clean workspace guarantee: verifies absence of target workspace prior to materialization.
"""

from __future__ import annotations

import re
import shlex
from dataclasses import dataclass

from basebreak.domain.execution import SandboxIdentity
from basebreak.domain.source import SourceIdentity
from basebreak.security.secret_policy import redact_log_text

from .sandbox import (
    NebiusSandboxAdapter,
    NebiusSandboxExecutionResult,
    NebiusSandboxHandle,
    SandboxAdapterError,
)
from .sandbox_constants import (
    DEFAULT_SANDBOX_IMAGE,
    DEFAULT_SANDBOX_TIMEOUT_SECONDS,
)

_HEX_CHARS = frozenset("0123456789abcdef")
_COMMIT_RE = re.compile(r"BASEBREAK_RESOLVED_COMMIT=([0-9a-fA-F]{40,64})")
_TREE_RE = re.compile(r"BASEBREAK_RESOLVED_TREE=([0-9a-fA-F]{40,64})")
# Compatibility with P-01 discovery scripts
_ALT_COMMIT_RE = re.compile(r"RESOLVED_BASE_SHA=([0-9a-fA-F]{40,64})")
_ALT_TREE_RE = re.compile(r"TREE_SHA=([0-9a-fA-F]{40,64})")

_FORBIDDEN_ROOT_DIRS: frozenset[str] = frozenset(
    {"bin", "boot", "dev", "etc", "lib", "proc", "root", "sys", "usr", "tmp", "var"}
)

PRE_EXISTING_WORKSPACE_EXIT_CODE: int = 42
PRE_EXISTING_WORKSPACE_MARKER: str = "BASEBREAK_PRE_EXISTING_WORKSPACE"


# --- Exceptions ---


class SourceMaterializationError(SandboxAdapterError):
    """Base exception for repository materialization failures."""


class MalformedSourceIdentityError(SourceMaterializationError):
    """Raised when the requested source identity or commit revision is malformed."""


class MalformedWorkspacePathError(SourceMaterializationError):
    """Raised when workspace_path is invalid, relative, unsafe, or malformed."""


class PreExistingWorkspaceError(SourceMaterializationError):
    """Raised when target workspace path already exists in sandbox context."""


class MaterializationExecutionError(SourceMaterializationError):
    """Raised when the materialization command inside the sandbox fails or times out."""


class SourceVerificationError(SourceMaterializationError):
    """Raised when deterministic source identity verification fails."""


class SourceCommitMismatchError(SourceVerificationError):
    """Raised when the resolved commit hash inside the sandbox does not match requested commit."""

    def __init__(self, requested: str, actual: str) -> None:
        self.requested_commit_sha = requested
        self.actual_commit_sha = actual
        super().__init__(
            f"Source commit mismatch: requested '{requested}', "
            f"but materialized sandbox resolved '{actual}'"
        )

    def __repr__(self) -> str:
        return (
            f"SourceCommitMismatchError(requested={self.requested_commit_sha!r}, "
            f"actual={self.actual_commit_sha!r})"
        )


class SourceTreeMismatchError(SourceVerificationError):
    """Raised when the resolved git tree hash inside the sandbox does not match expected tree."""

    def __init__(self, expected: str, actual: str) -> None:
        self.expected_tree_sha = expected
        self.actual_tree_sha = actual
        super().__init__(
            f"Source tree mismatch: expected '{expected}', "
            f"but materialized sandbox resolved '{actual}'"
        )

    def __repr__(self) -> str:
        return (
            f"SourceTreeMismatchError(expected={self.expected_tree_sha!r}, "
            f"actual={self.actual_tree_sha!r})"
        )


# --- Workspace Path Validation ---


def validate_workspace_path(workspace_path: str) -> str:
    """Validate and normalize target workspace path inside container VM.

    Rejects:
    - Non-string, empty, or whitespace paths;
    - Paths with null bytes or control characters;
    - Non-absolute paths (must start with '/');
    - Path traversal segments ('..');
    - Dot segments ('.');
    - Root directory ('/');
    - Critical top-level system directories.
    """
    if not isinstance(workspace_path, str) or not workspace_path.strip():
        raise MalformedWorkspacePathError("workspace_path must be a non-empty string")

    clean = workspace_path.strip()
    if "\x00" in clean or "\r" in clean or "\n" in clean:
        raise MalformedWorkspacePathError(
            "workspace_path contains forbidden null or control characters"
        )

    if not clean.startswith("/"):
        raise MalformedWorkspacePathError(
            f"workspace_path must be absolute (start with '/'), got: {clean!r}"
        )

    parts = [p for p in clean.split("/") if p]
    if not parts:
        raise MalformedWorkspacePathError("workspace_path cannot be the root directory '/'")

    if any(p == ".." for p in parts):
        raise MalformedWorkspacePathError(
            "workspace_path cannot contain path traversal ('..') segments"
        )

    if any(p == "." for p in parts):
        raise MalformedWorkspacePathError("workspace_path cannot contain '.' segments")

    if len(parts) == 1 and parts[0] in _FORBIDDEN_ROOT_DIRS:
        raise MalformedWorkspacePathError(
            f"workspace_path cannot be a critical top-level system directory: '/{parts[0]}'"
        )

    return "/" + "/".join(parts)


# --- Data Records ---


@dataclass(frozen=True, slots=True)
class MaterializedSourceRecord:
    """Deterministic, immutable record of materialized repository source in a sandbox.

    Records the verified commit SHA and tree SHA resolved directly from the
    materialized git workspace inside the container VM.

    Guarantees:
    - Target workspace was absent prior to materialization (is_clean_workspace=True);
    - Resolved commit SHA and tree SHA are deterministically verified;
    - Sandbox freshness is distinguished: is_fresh_sandbox is True only when
      spawned in an unshared sandbox context (sandbox is None or image string),
      and False when executed in an existing NebiusSandboxHandle.
    """

    source_identity: SourceIdentity
    resolved_commit_sha: str
    resolved_tree_sha: str
    workspace_path: str
    sandbox_identity: SandboxIdentity
    operation_id: str
    duration_seconds: float | None
    result_image_uuid: str | None = None
    is_verified: bool = True
    is_clean_workspace: bool = True
    is_fresh_sandbox: bool = False

    def __repr__(self) -> str:
        return (
            f"MaterializedSourceRecord(commit={self.resolved_commit_sha[:12]!r}, "
            f"tree={self.resolved_tree_sha[:12]!r}, "
            f"workspace={self.workspace_path!r}, "
            f"sandbox_id={self.sandbox_identity.sandbox_id!r}, "
            f"is_verified={self.is_verified}, "
            f"is_clean_workspace={self.is_clean_workspace}, "
            f"is_fresh_sandbox={self.is_fresh_sandbox})"
        )


# --- Materialization Script Builder ---


def build_materialization_script(
    source_identity: SourceIdentity,
    workspace_path: str = "/workspace/repo",
) -> str:
    """Build a deterministic, bounded shell command to clone and checkout exact commit.

    Validates workspace_path and asserts that the target workspace does not already
    exist prior to clone.
    """
    clean_workspace = validate_workspace_path(workspace_path)
    parent_dir = "/".join(clean_workspace.split("/")[:-1]) or "/"

    locator = source_identity.locator
    commit_sha = source_identity.resolved_commit_id

    git_check_cmd = (
        "(which git >/dev/null 2>&1 || "
        "apk add --no-cache git >/dev/null 2>&1 || "
        "(apt-get update -qq && apt-get install -y -qq git >/dev/null 2>&1))"
    )
    lines = [
        "set -e",
        f"if [ -e {shlex.quote(clean_workspace)} ] || [ -L {shlex.quote(clean_workspace)} ]; then",
        f'    echo "{PRE_EXISTING_WORKSPACE_MARKER}: target workspace already exists: '
        f'{clean_workspace}" >&2',
        f"    exit {PRE_EXISTING_WORKSPACE_EXIT_CODE}",
        "fi",
        git_check_cmd,
        f"mkdir -p {shlex.quote(parent_dir)}",
        f"git clone --quiet {shlex.quote(locator)} {shlex.quote(clean_workspace)}",
        f"cd {shlex.quote(clean_workspace)}",
        f"git checkout --quiet {shlex.quote(commit_sha)}",
        'echo "BASEBREAK_RESOLVED_COMMIT=$(git rev-parse HEAD)"',
        'echo "BASEBREAK_RESOLVED_TREE=$(git write-tree)"',
    ]
    return "\n".join(lines)


# --- NebiusSourceMaterializer ---


class NebiusSourceMaterializer:
    """Adapter for bounded repository materialization and deterministic source verification.

    Binds source materialization into an isolated sandbox to an immutable CommitRevision.
    Verification asserts exact match of commit SHA and optionally tree SHA.
    """

    def __init__(self, adapter: NebiusSandboxAdapter) -> None:
        self._adapter = adapter

    @property
    def adapter(self) -> NebiusSandboxAdapter:
        return self._adapter

    def materialize_repository(
        self,
        source_identity: SourceIdentity,
        *,
        sandbox: NebiusSandboxHandle | str | None = None,
        workspace_path: str = "/workspace/repo",
        expected_tree_sha: str | None = None,
        disposable: bool = True,
        timeout_seconds: int = DEFAULT_SANDBOX_TIMEOUT_SECONDS,
    ) -> MaterializedSourceRecord:
        """Materialize repository into a clean sandbox and verify its source identity.

        Args:
            source_identity: Authoritative SourceIdentity with resolved CommitRevision.
            sandbox: Optional existing handle or image name (defaults to DEFAULT_SANDBOX_IMAGE).
            workspace_path: Container-relative path where repo will be cloned.
            expected_tree_sha: Optional expected git tree SHA (40 or 64 hex characters).
            disposable: True for disposable VM, False for checkpoint creation.
            timeout_seconds: Operational timeout budget for clone and verification.

        Returns:
            MaterializedSourceRecord with verified commit and tree hashes.

        Raises:
            MalformedSourceIdentityError: If source identity or hashes are invalid.
            MalformedWorkspacePathError: If workspace_path is invalid or unsafe.
            PreExistingWorkspaceError: If workspace_path already exists in sandbox.
            MaterializationExecutionError: If command execution inside sandbox fails.
            SourceCommitMismatchError: If resolved commit != requested commit.
            SourceTreeMismatchError: If expected_tree_sha is given and does not match.
            SourceVerificationError: If hashes cannot be extracted from output.
        """
        # Validate source identity
        if not isinstance(source_identity, SourceIdentity):
            raise MalformedSourceIdentityError(
                f"source_identity must be an instance of SourceIdentity, "
                f"got {type(source_identity).__name__}"
            )

        # Validate workspace path early
        clean_workspace = validate_workspace_path(workspace_path)

        if expected_tree_sha is not None:
            clean_tree = expected_tree_sha.strip().lower()
            if len(clean_tree) not in (40, 64) or not set(clean_tree).issubset(_HEX_CHARS):
                raise MalformedSourceIdentityError(
                    f"expected_tree_sha must be 40 or 64 hex characters, got {expected_tree_sha!r}"
                )
            expected_tree_sha = clean_tree

        # Distinguish sandbox freshness from workspace cleanliness
        is_fresh_sandbox = (sandbox is None) or isinstance(sandbox, str)

        target_sandbox = sandbox or DEFAULT_SANDBOX_IMAGE
        cmd_script = build_materialization_script(source_identity, clean_workspace)

        # Execute materialization script inside sandbox
        exec_result: NebiusSandboxExecutionResult = self._adapter.execute_command(
            target_sandbox,
            cmd_script,
            timeout_seconds=timeout_seconds,
            disposable=disposable,
            networking_enabled=True,  # Clone requires outbound HTTPS egress
        )

        # Check execution outcome
        if exec_result.is_timeout:
            raise MaterializationExecutionError(
                f"Repository materialization timed out after {timeout_seconds}s "
                f"for source {source_identity.locator!r}"
            )

        if exec_result.exit_code != 0:
            err_output = redact_log_text(exec_result.stderr or exec_result.stdout or "")
            code = exec_result.exit_code
            if (
                code == PRE_EXISTING_WORKSPACE_EXIT_CODE
                or PRE_EXISTING_WORKSPACE_MARKER in err_output
            ):
                raise PreExistingWorkspaceError(
                    f"Target workspace already exists before materialization: '{clean_workspace}' "
                    f"(refusing to inherit mutable or non-clean state)"
                )
            msg = (
                f"Repository materialization command failed with exit code {code}: "
                f"{err_output.strip()}"
            )
            raise MaterializationExecutionError(msg)

        # Parse output for resolved commit SHA
        stdout = exec_result.stdout
        commit_match = _COMMIT_RE.search(stdout) or _ALT_COMMIT_RE.search(stdout)
        if not commit_match:
            raise SourceVerificationError(
                "Materialization succeeded with exit code 0 but failed to output "
                "resolved commit SHA. Output was missing BASEBREAK_RESOLVED_COMMIT "
                "or RESOLVED_BASE_SHA."
            )
        resolved_commit = commit_match.group(1).lower()

        # Parse output for resolved tree SHA
        tree_match = _TREE_RE.search(stdout) or _ALT_TREE_RE.search(stdout)
        if not tree_match:
            raise SourceVerificationError(
                "Materialization succeeded with exit code 0 but failed to output "
                "resolved tree SHA. Output was missing BASEBREAK_RESOLVED_TREE "
                "or TREE_SHA."
            )
        resolved_tree = tree_match.group(1).lower()

        # Deterministic Verification 1: Commit SHA match
        requested_commit = source_identity.resolved_commit_id.lower()
        if resolved_commit != requested_commit:
            raise SourceCommitMismatchError(
                requested=requested_commit,
                actual=resolved_commit,
            )

        # Deterministic Verification 2: Tree SHA match (if expected)
        if expected_tree_sha is not None and resolved_tree != expected_tree_sha:
            raise SourceTreeMismatchError(
                expected=expected_tree_sha,
                actual=resolved_tree,
            )

        return MaterializedSourceRecord(
            source_identity=source_identity,
            resolved_commit_sha=resolved_commit,
            resolved_tree_sha=resolved_tree,
            workspace_path=clean_workspace,
            sandbox_identity=exec_result.sandbox_identity,
            operation_id=exec_result.operation_id,
            duration_seconds=exec_result.duration_seconds,
            result_image_uuid=exec_result.result_image_uuid,
            is_verified=True,
            is_clean_workspace=True,
            is_fresh_sandbox=is_fresh_sandbox,
        )
