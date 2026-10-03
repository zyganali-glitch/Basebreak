"""Candidate security policy and protected surface enforcement.

P-07.05: Enforces Basebreak security policy across Builder-controlled candidate
execution, binding pre-execution file actions, pre-dispatch command policy, and
actual post-execution candidate diff validation against canonical P-04 protected
surfaces.

Core Invariants:
1. Canonical security authority: Reuses canonical P-04 protected-surface manifest
   (AGENTS.md, plans/BASEBREAK_MASTER_EXECUTION_PLAN.md, docs/SECURITY_BOUNDARY.md,
   src/basebreak/domain, src/basebreak/evidence, src/basebreak/security).
2. Layer 1 (Pre-execution file actions): Converts proposed file actions to
   canonical FileChange representation (CREATE->ADD, MODIFY->MODIFY, DELETE->DELETE)
   and rejects exact files, directory descendants, case-folded variants, and
   traversals BEFORE any mutation or sandbox command is dispatched (zero mutations).
3. Layer 2 (Pre-dispatch command policy): Enforces finite command bounds, length limits,
   null-byte checks, secret detection, and sandbox process safety before dispatch.
4. Layer 3 (Actual post-execution diff): Captures actual candidate state from the SAME
   sandbox handle using P-07.04 capture path and validates resulting git diff through
   canonical P-04 diff validator. Detects commands mutating protected files, renames
   into/out of protected surfaces, and symlink bypasses.
5. Same-sandbox orchestration: Coordinates authoritative context -> materialization ->
   preflight policy -> execution -> capture -> postcondition in the SAME sandbox VM.
6. Fail-closed & teardown law: Any policy violation fails closed, destroys any disposable
   sandbox owned by the orchestrator, and returns ZERO accepted candidate.
7. Policy result authority: Security compliance != causal verification.
   Enforcement result is strictly non-authoritative (is_authoritative=False,
   is_causally_verified=False, grants_pass=False).
8. Provider neutrality: Zero adapter imports, zero provider-specific identifiers.
"""

from __future__ import annotations

import re
from collections.abc import Mapping, Sequence
from dataclasses import dataclass
from typing import Any

from basebreak.builder.capture import (
    CandidateSnapshot,
    capture_candidate_from_sandbox,
)
from basebreak.builder.context import BuilderContextEnvelope
from basebreak.builder.execution import (
    CandidateExecutionConfig,
    CandidateExecutionResult,
    CandidateWorkspaceExecutor,
    CommandBoundingError,
    CredentialLeakageError,
    DuplicateActionError,
    ForbiddenCommandError,
    HostExecutionFallbackError,
    InvalidProposedMutationError,
    MissingAuthoritativeEnvelopeError,
    UnmaterializedWorkspaceError,
    WorkspaceExecutionError,
)
from basebreak.builder.loop import (
    BuilderProposal,
    FileActionType,
    ProposedCommand,
    ProposedFileAction,
)
from basebreak.domain.execution import SandboxIdentity
from basebreak.domain.source import CommitRevision, SourceIdentity
from basebreak.domain.verdict import EvidenceProvenance
from basebreak.security.protected_surfaces import (
    FileChange,
    FileChangeKind,
    InvalidPathError,
    PathSecurityError,
    PathTraversalError,
    ProtectedSurfaceManifest,
    ProtectedSurfaceReport,
    ProtectedSurfaceViolation,
    check_change,
    get_canonical_basebreak_protected_manifest,
    validate_diff,
    validate_path,
)
from basebreak.security.sandbox_policy import (
    ProcessPolicyError,
    SandboxExecutionPolicy,
    validate_command_string,
)
from basebreak.security.secret_policy import (
    contains_secret,
    validate_no_secrets,
)

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


class CandidateEnforcementError(Exception):
    """Base exception for all candidate security enforcement failures."""


class PreflightSecurityViolation(CandidateEnforcementError):
    """Raised when pre-execution proposal violates file action or command security policy."""


class PostExecutionSecurityViolation(CandidateEnforcementError):
    """Raised when post-execution candidate diff touches a protected surface."""


# --- Data Records ---


@dataclass(frozen=True, slots=True)
class CandidateSecurityEnforcementResult:
    """Deterministic result of candidate security policy and protected surface enforcement.

    Proves security policy compliance, but possesses ZERO verification authority:
    - is_authoritative is strictly False
    - is_causally_verified is strictly False
    - grants_pass is strictly False
    """

    candidate_snapshot: CandidateSnapshot
    execution_result: CandidateExecutionResult
    protected_manifest: ProtectedSurfaceManifest
    sandbox_identity: SandboxIdentity
    source_identity: SourceIdentity
    candidate_tree_digest: str
    patch_digest: str
    is_policy_compliant: bool = True
    preflight_file_actions_checked: int = 0
    preflight_commands_checked: int = 0
    actual_diff_checked: bool = True
    is_authoritative: bool = False
    is_causally_verified: bool = False
    grants_pass: bool = False
    provenance: EvidenceProvenance = EvidenceProvenance.LOCAL_EXECUTION

    def __post_init__(self) -> None:
        if self.is_authoritative is not False:
            raise ValueError(
                "CandidateSecurityEnforcementResult is_authoritative must be strictly False"
            )
        if self.is_causally_verified is not False:
            raise ValueError(
                "CandidateSecurityEnforcementResult is_causally_verified must be strictly False; "
                "security compliance does NOT grant causal verification"
            )
        if self.grants_pass is not False:
            raise ValueError(
                "CandidateSecurityEnforcementResult grants_pass must be strictly False"
            )
        if self.is_policy_compliant is not True:
            raise ValueError(
                "CandidateSecurityEnforcementResult is_policy_compliant "
                "must be True for an accepted candidate"
            )
        if not isinstance(self.candidate_snapshot, CandidateSnapshot):
            raise TypeError("candidate_snapshot must be CandidateSnapshot")
        if not isinstance(self.execution_result, CandidateExecutionResult):
            raise TypeError("execution_result must be CandidateExecutionResult")
        if not isinstance(self.protected_manifest, ProtectedSurfaceManifest):
            raise TypeError("protected_manifest must be ProtectedSurfaceManifest")
        canonical_manifest = get_canonical_basebreak_protected_manifest()
        for exact_file in canonical_manifest.exact_files:
            if exact_file not in self.protected_manifest.exact_files:
                raise ValueError(
                    f"CandidateSecurityEnforcementResult protected_manifest is "
                    f"missing canonical exact file: {exact_file}"
                )
        for prefix in canonical_manifest.directory_prefixes:
            if prefix not in self.protected_manifest.directory_prefixes:
                raise ValueError(
                    f"CandidateSecurityEnforcementResult protected_manifest is "
                    f"missing canonical directory prefix: {prefix}"
                )
        if not isinstance(self.sandbox_identity, SandboxIdentity):
            raise TypeError("sandbox_identity must be SandboxIdentity")
        if not isinstance(self.source_identity, SourceIdentity):
            raise TypeError("source_identity must be SourceIdentity")

        # Identity consistency checks across components
        if self.execution_result.sandbox_identity != self.sandbox_identity:
            raise ValueError(
                "Execution result sandbox identity does not match enforcer sandbox identity"
            )
        if self.candidate_snapshot.sandbox_identity != self.sandbox_identity:
            raise ValueError(
                "Candidate snapshot sandbox identity does not match enforcer sandbox identity"
            )
        if self.execution_result.source_identity != self.source_identity:
            raise ValueError(
                "Execution result source identity does not match enforcer source identity"
            )
        if self.candidate_snapshot.source_identity != self.source_identity:
            raise ValueError(
                "Candidate snapshot source identity does not match enforcer source identity"
            )
        if self.candidate_snapshot.candidate_tree_digest != self.candidate_tree_digest:
            raise ValueError(
                "Candidate snapshot tree digest does not match result candidate_tree_digest"
            )
        if self.candidate_snapshot.patch_digest != self.patch_digest:
            raise ValueError("Candidate snapshot patch digest does not match result patch_digest")

    def to_dict(self) -> dict[str, Any]:
        """Serialize enforcement result to dictionary."""
        return {
            "actual_diff_checked": self.actual_diff_checked,
            "candidate_snapshot": self.candidate_snapshot.to_dict(),
            "candidate_tree_digest": self.candidate_tree_digest,
            "execution_result": self.execution_result.to_dict(),
            "grants_pass": self.grants_pass,
            "is_authoritative": self.is_authoritative,
            "is_causally_verified": self.is_causally_verified,
            "is_policy_compliant": self.is_policy_compliant,
            "patch_digest": self.patch_digest,
            "preflight_commands_checked": self.preflight_commands_checked,
            "preflight_file_actions_checked": self.preflight_file_actions_checked,
            "protected_manifest": self.protected_manifest.to_dict(),
            "provenance": self.provenance.value,
            "sandbox_id": self.sandbox_identity.sandbox_id,
            "source_commit_id": self.source_identity.resolved_commit_id,
            "source_locator": self.source_identity.locator,
            "source_subpath": self.source_identity.subpath,
        }

    @classmethod
    def from_dict(cls, data: Mapping[str, Any]) -> CandidateSecurityEnforcementResult:
        """Deserialize enforcement result from dictionary with strict validation."""
        if not isinstance(data, Mapping):
            raise TypeError(f"Expected mapping, got {type(data).__name__}")
        snap_data = data.get("candidate_snapshot")
        if not isinstance(snap_data, Mapping):
            raise TypeError("candidate_snapshot must be a mapping")
        snapshot = CandidateSnapshot.from_dict(snap_data)

        exec_data = data.get("execution_result")
        if not isinstance(exec_data, Mapping):
            raise TypeError("execution_result must be a mapping")
        exec_res = CandidateExecutionResult.from_dict(exec_data)

        manifest_data = data.get("protected_manifest")
        if not isinstance(manifest_data, Mapping):
            raise TypeError("protected_manifest must be a mapping")
        manifest = ProtectedSurfaceManifest.from_dict(dict(manifest_data))

        raw_prov = data.get("provenance", "LOCAL_EXECUTION")
        prov = EvidenceProvenance(str(raw_prov))
        sbx_id = SandboxIdentity(sandbox_id=str(data.get("sandbox_id", "")))
        src_id = SourceIdentity(
            locator=str(data.get("source_locator", "")),
            revision=CommitRevision(str(data.get("source_commit_id", ""))),
            subpath=data.get("source_subpath"),
        )

        return cls(
            candidate_snapshot=snapshot,
            execution_result=exec_res,
            protected_manifest=manifest,
            sandbox_identity=sbx_id,
            source_identity=src_id,
            candidate_tree_digest=str(data.get("candidate_tree_digest", "")),
            patch_digest=str(data.get("patch_digest", "")),
            is_policy_compliant=bool(data.get("is_policy_compliant", True)),
            preflight_file_actions_checked=int(data.get("preflight_file_actions_checked", 0)),
            preflight_commands_checked=int(data.get("preflight_commands_checked", 0)),
            actual_diff_checked=bool(data.get("actual_diff_checked", True)),
            is_authoritative=False,
            is_causally_verified=False,
            grants_pass=False,
            provenance=prov,
        )


# --- Security Enforcer ---


class CandidateSecurityEnforcer:
    """Orchestrates candidate execution with fail-closed security and protected surface enforcement.

    Coordinates:
    authoritative Builder context
    → source materialization
    → preflight policy (file actions + commands)
    → P-07.03 bounded execution (same sandbox)
    → P-07.04 actual-state capture (same sandbox)
    → protected-surface postcondition (actual diff)
    → deterministic policy result
    """

    def __init__(
        self,
        sandbox_adapter: Any,
        source_materializer: Any,
        *,
        config: CandidateExecutionConfig | None = None,
        sandbox_policy: SandboxExecutionPolicy | None = None,
        protected_manifest: ProtectedSurfaceManifest | None = None,
    ) -> None:
        if sandbox_adapter is None:
            raise HostExecutionFallbackError(
                "sandbox_adapter is required; host execution fallback is strictly prohibited"
            )
        if source_materializer is None:
            raise UnmaterializedWorkspaceError(
                "source_materializer is required for candidate workspace materialization"
            )
        if protected_manifest is not None:
            raise CandidateEnforcementError(
                "Caller cannot override protected_manifest; "
                "canonical P-04 protected surfaces are mandatory and non-downgradable"
            )

        resolved_config = config or CandidateExecutionConfig()
        if not getattr(resolved_config, "enforce_protected_surfaces", True):
            raise CandidateEnforcementError(
                "enforce_protected_surfaces cannot be False; "
                "canonical P-04 protected surface enforcement is mandatory"
            )
        if getattr(resolved_config, "protected_manifest", None) is not None:
            raise CandidateEnforcementError(
                "Caller cannot override protected_manifest in config; "
                "canonical P-04 protected surfaces are mandatory and non-downgradable"
            )

        self.sandbox_adapter = sandbox_adapter
        self.source_materializer = source_materializer
        self.config = resolved_config
        self.sandbox_policy = sandbox_policy or SandboxExecutionPolicy()

    @property
    def protected_manifest(self) -> ProtectedSurfaceManifest:
        """Canonical P-04 protected surface manifest. Non-downgradable."""
        return get_canonical_basebreak_protected_manifest()

    def validate_preflight_file_actions(
        self,
        actions: Sequence[ProposedFileAction],
    ) -> list[FileChange]:
        """Convert and validate proposed Builder file actions against canonical protected surfaces.

        Fails closed before ANY mutation command is dispatched.
        """
        if len(actions) > self.config.max_file_actions:
            raise InvalidProposedMutationError(
                f"Proposed file actions count ({len(actions)}) "
                f"exceeds limit ({self.config.max_file_actions})"
            )

        changes: list[FileChange] = []
        normalized_paths: set[str] = set()

        for idx, action in enumerate(actions):
            if not isinstance(action, ProposedFileAction):
                raise TypeError(
                    f"Action at {idx} must be ProposedFileAction, got {type(action).__name__}"
                )
            if action.is_authoritative is not False:
                raise InvalidProposedMutationError(
                    f"Action at {idx} is_authoritative must be strictly False"
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
                norm_path = validate_path(action.path, self.protected_manifest)
            except ProtectedSurfaceViolation:
                raise
            except (PathTraversalError, InvalidPathError, PathSecurityError) as exc:
                raise InvalidProposedMutationError(
                    f"Invalid or unsafe path in action at index {idx} ({action.path!r}): {exc}"
                ) from exc

            # Validate against protected surfaces via FileChange representation
            change = FileChange(path=norm_path, kind=kind)
            findings = check_change(change, self.protected_manifest)
            if findings:
                first = findings[0]
                raise ProtectedSurfaceViolation(
                    f"Proposed file action targets protected surface: {first.message}",
                    findings=tuple(findings),
                )

            # Duplicate check
            if norm_path in normalized_paths:
                raise DuplicateActionError(
                    f"Duplicate file action targeting normalized path {norm_path!r}"
                )
            normalized_paths.add(norm_path)

            # Content size bounds
            content_bytes = action.content.encode("utf-8")
            if len(content_bytes) > self.config.max_file_bytes:
                raise InvalidProposedMutationError(
                    f"File action for {norm_path!r} exceeds size limit: "
                    f"{len(content_bytes)} bytes (max {self.config.max_file_bytes})"
                )

            # Secret check
            if contains_secret(action.content):
                raise CredentialLeakageError(
                    f"Secret-shaped value in proposed file action content for {norm_path!r}"
                )
            validate_no_secrets(action.content, path=f"file_action[{norm_path}].content")

            if contains_secret(action.rationale):
                raise CredentialLeakageError(
                    f"Secret-shaped value in proposed file action rationale for {norm_path!r}"
                )
            validate_no_secrets(action.rationale, path=f"file_action[{norm_path}].rationale")

            changes.append(change)

        return changes

    def validate_preflight_commands(
        self,
        commands: Sequence[ProposedCommand],
    ) -> list[str]:
        """Validate proposed Builder commands against bounding, process policy, and secrets.

        Fails closed before ANY command is dispatched.
        """
        if len(commands) > self.config.max_commands:
            raise CommandBoundingError(
                f"Proposed commands count ({len(commands)}) "
                f"exceeds limit ({self.config.max_commands})"
            )

        validated: list[str] = []
        for idx, cmd in enumerate(commands):
            if not isinstance(cmd, ProposedCommand):
                raise TypeError(
                    f"Command at {idx} must be ProposedCommand, got {type(cmd).__name__}"
                )
            if cmd.is_authoritative is not False:
                raise CommandBoundingError(
                    f"Command at index {idx} is_authoritative must be strictly False"
                )

            cmd_str = cmd.command.strip()
            if not cmd_str:
                raise CommandBoundingError(
                    f"Command at index {idx} must not be empty or whitespace"
                )

            # Check bounded command length
            cmd_bytes = cmd_str.encode("utf-8")
            if len(cmd_bytes) > self.config.max_command_length_bytes:
                raise CommandBoundingError(
                    f"Command at index {idx} exceeds length limit: {len(cmd_bytes)} bytes "
                    f"(max {self.config.max_command_length_bytes})"
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

            # Fork-bomb, recursion, daemon pattern checks
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

            # Check credentials in rationale
            if contains_secret(cmd.rationale):
                raise CredentialLeakageError(
                    f"Secret-shaped value detected in command rationale at index {idx}"
                )
            validate_no_secrets(cmd.rationale, path=f"command[{idx}].rationale")

            validated.append(cmd_str)

        return validated

    def validate_post_execution_diff(self, patch_text: str) -> ProtectedSurfaceReport:
        """Validate candidate patch text against canonical protected surfaces.

        Fails closed with ProtectedSurfaceViolation if ANY protected surface
        was mutated, added, deleted, renamed, or linked.
        """
        return validate_diff(patch_text, self.protected_manifest)

    def execute_and_enforce(
        self,
        *,
        envelope: BuilderContextEnvelope,
        proposal: BuilderProposal,
        sandbox_handle: Any = None,
        candidate_id: str | None = None,
        timeout_seconds: int | None = None,
    ) -> CandidateSecurityEnforcementResult:
        """Execute candidate workspace mutations with full deterministic security enforcement.

        Coordinates:
        authoritative Builder context
        → preflight policy (file actions + commands)
        → source materialization & P-07.03 bounded execution (same sandbox)
        → P-07.04 actual-state capture (same sandbox)
        → protected-surface postcondition (actual diff)
        → deterministic policy result
        """
        # 1. Authority validation of input envelope and proposal
        if not isinstance(envelope, BuilderContextEnvelope):
            raise MissingAuthoritativeEnvelopeError(
                "envelope must be an authoritative BuilderContextEnvelope"
            )
        if not isinstance(proposal, BuilderProposal):
            raise TypeError(f"proposal must be BuilderProposal, got {type(proposal).__name__}")
        if proposal.is_authoritative is not False:
            raise InvalidProposedMutationError(
                "BuilderProposal is_authoritative must be strictly False"
            )

        # 2. Layer 1 — Pre-execution file-action enforcement
        # Must reject before mutation: exact protected files, directory descendants,
        # case-fold bypasses, path traversal, malformed paths.
        # ZERO candidate mutation commands dispatched on violation!
        self.validate_preflight_file_actions(proposal.proposed_file_actions)

        # 3. Layer 2 — Command policy pre-dispatch
        # Finite count, length ceiling, null-bytes, secrets, fork-bomb, recursive shell, daemon
        self.validate_preflight_commands(proposal.proposed_commands)

        # 4. Acquire / validate Sandbox Handle
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
            # Validate sandbox identity on handle
            sbx_id = getattr(handle, "sandbox_identity", None)
            if sbx_id is None or not isinstance(sbx_id, SandboxIdentity):
                raise WorkspaceExecutionError(
                    "Sandbox handle lacks a deterministic SandboxIdentity"
                )
            if not sbx_id.sandbox_id or not sbx_id.sandbox_id.strip():
                raise WorkspaceExecutionError(
                    "Sandbox handle contains empty or whitespace sandbox_id"
                )

            # 5. P-07.03 Bounded Workspace Execution inside SAME sandbox
            executor = CandidateWorkspaceExecutor(
                sandbox_adapter=self.sandbox_adapter,
                source_materializer=self.source_materializer,
                config=self.config,
            )
            execution_result = executor.execute(
                envelope=envelope,
                proposal=proposal,
                sandbox_handle=handle,
            )

            # 6. P-07.04 Capture Candidate State from SAME sandbox
            snapshot: CandidateSnapshot
            if execution_result.bundled_snapshot is not None:
                if not isinstance(execution_result.bundled_snapshot, CandidateSnapshot):
                    raise WorkspaceExecutionError("bundled_snapshot must be CandidateSnapshot")
                snapshot = execution_result.bundled_snapshot
            else:
                effective_timeout = (
                    timeout_seconds
                    if timeout_seconds is not None
                    else self.config.per_command_timeout_seconds
                )
                snapshot = capture_candidate_from_sandbox(
                    sandbox_adapter=self.sandbox_adapter,
                    sandbox_handle=handle,
                    execution_result=execution_result,
                    workspace_path=execution_result.workspace_path,
                    candidate_id=candidate_id,
                    timeout_seconds=effective_timeout,
                )

            # 7. Layer 3 — Actual post-execution protected-surface check
            # Validate actual resulting diff against canonical protected surfaces
            try:
                self.validate_post_execution_diff(snapshot.patch_text)
            except ProtectedSurfaceViolation:
                # Post-execution protected surface violation detected!
                # Teardown sandbox immediately to contain violation
                try:
                    self.sandbox_adapter.teardown_sandbox(handle)
                except Exception:
                    pass
                raise

        except Exception:
            # Teardown on failure/violation if handle was created here
            if created_handle and self.config.teardown_on_failure:
                try:
                    self.sandbox_adapter.teardown_sandbox(handle)
                except Exception:
                    pass
            raise

        # Teardown on completion if configured
        if created_handle and self.config.teardown_on_completion:
            try:
                self.sandbox_adapter.teardown_sandbox(handle)
            except Exception:
                pass

        # 8. Return deterministic policy result (ZERO causal/verification authority)
        return CandidateSecurityEnforcementResult(
            candidate_snapshot=snapshot,
            execution_result=execution_result,
            protected_manifest=self.protected_manifest,
            sandbox_identity=sbx_id,
            source_identity=envelope.source_identity,
            candidate_tree_digest=snapshot.candidate_tree_digest,
            patch_digest=snapshot.patch_digest,
            is_policy_compliant=True,
            preflight_file_actions_checked=len(proposal.proposed_file_actions),
            preflight_commands_checked=len(proposal.proposed_commands),
            actual_diff_checked=True,
            is_authoritative=False,
            is_causally_verified=False,
            grants_pass=False,
            provenance=execution_result.provenance,
        )


__all__ = [
    "CandidateEnforcementError",
    "CandidateSecurityEnforcementResult",
    "CandidateSecurityEnforcer",
    "PostExecutionSecurityViolation",
    "PreflightSecurityViolation",
]
