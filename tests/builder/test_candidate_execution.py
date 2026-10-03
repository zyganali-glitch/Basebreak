"""Acceptance test suite for P-07.03: Bounded candidate workspace execution.

Validates the core invariants:
1. CREATE, MODIFY, DELETE file mutations applied through bounded POSIX primitives.
2. Missing target and target already exists behavior.
3. Path traversal, root escape, drive letters, and malformed paths rejected.
4. Duplicate/conflicting mutations for the same normalized path rejected.
5. Finite command count, length ceiling, and per-command timeout bounding.
6. Forbidden shell recursion, fork bombs, and persistent daemons rejected.
7. Sandbox failure and timeout handling with zero silent fallback.
8. Teardown on failure and clean lifecycle management.
9. Zero host execution fallback (host execution strictly forbidden).
10. Zero credentials in guest workspace (secrets rejected before dispatch).
11. Proposal and execution result remain strictly non-authoritative.
12. Deterministic execution fact capture and unbroken binding.
"""

from __future__ import annotations

import ast
import inspect
from collections.abc import Sequence
from dataclasses import dataclass
from typing import Any

import pytest

from basebreak.builder.context import BuilderContextAllowlist, assemble_builder_context
from basebreak.builder.execution import (
    CandidateExecutionConfig,
    CandidateExecutionResult,
    CandidateExecutionTimeoutError,
    CandidateWorkspaceExecutor,
    CommandBoundingError,
    CredentialLeakageError,
    DuplicateActionError,
    ForbiddenCommandError,
    HostExecutionFallbackError,
    InvalidProposedMutationError,
    MaterializedSourceBinding,
    MaterializedSourceMismatchError,
    MaterializedSourceVerificationError,
    MissingAuthoritativeEnvelopeError,
    MissingTargetError,
    SandboxIdentityMismatchError,
    SourceCommitMismatchError,
    SourceMaterializerProtocol,
    TargetAlreadyExistsError,
    UnmaterializedWorkspaceError,
    WorkspaceExecutionError,
    build_file_mutation_scripts,
    compute_proposal_digest,
    validate_candidate_proposal,
    validate_materialized_workspace,
    validate_workspace_path,
)
from basebreak.builder.loop import (
    BuilderPlan,
    BuilderProposal,
    FileActionType,
    ProposedCommand,
    ProposedFileAction,
)
from basebreak.compiler.freeze import FrozenContract, freeze_review_result
from basebreak.compiler.ingestion import ingest_task
from basebreak.compiler.requirements import ProposedRequirement
from basebreak.compiler.review import ReviewBundle, ReviewSession
from basebreak.compiler.semantics import (
    CertaintyLevel,
    ChangeSemanticsClassification,
    DeterministicClassificationFact,
)
from basebreak.domain.execution import SandboxIdentity, TerminationStatus
from basebreak.domain.semantics import ChangeClass
from basebreak.domain.source import CommitRevision, SourceIdentity
from basebreak.security.protected_surfaces import InvalidPathError, PathTraversalError

# --- Mock Sandbox Adapter for Deterministic P-07.03 Testing ---


@dataclass
class MockSandboxHandle:
    sandbox_identity: SandboxIdentity
    image: str
    disposable: bool
    is_torn_down: bool = False


@dataclass
class MockExecutionCommandResult:
    exit_code: int = 0
    stdout: str = ""
    stderr: str = ""
    duration_seconds: float = 0.1
    stdout_digest: str | None = None
    stderr_digest: str | None = None
    is_timeout: bool = False
    is_cancelled: bool = False


class MockSandboxAdapter:
    """Mock sandbox adapter for candidate execution testing.

    Simulates sandbox VM execution, tracks commands and file mutations,
    and supports programmed responses, timeouts, and failures.
    """

    def __init__(
        self,
        *,
        default_exit_code: int = 0,
        fail_command_pattern: str | None = None,
        exit_code_map: dict[str, int] | None = None,
        should_timeout: bool = False,
        should_fail: bool = False,
        error_message: str = "Sandbox provider error",
    ) -> None:
        self.default_exit_code = default_exit_code
        self.fail_command_pattern = fail_command_pattern
        self.exit_code_map = exit_code_map or {}
        self.should_timeout = should_timeout
        self.should_fail = should_fail
        self.error_message = error_message
        self.created_handles: list[MockSandboxHandle] = []
        self.executed_commands: list[tuple[MockSandboxHandle, str, str | None]] = []
        self.torn_down_handles: list[MockSandboxHandle] = []

    def create_sandbox(self, image: str, disposable: bool = True) -> MockSandboxHandle:
        handle = MockSandboxHandle(
            sandbox_identity=SandboxIdentity(
                sandbox_id=f"sbx-mock-{len(self.created_handles):04d}"
            ),
            image=image,
            disposable=disposable,
        )
        self.created_handles.append(handle)
        return handle

    def execute_command(
        self,
        sandbox: MockSandboxHandle,
        command: str,
        *,
        working_dir: str | None = None,
        timeout_seconds: int | None = None,
    ) -> MockExecutionCommandResult:
        self.executed_commands.append((sandbox, command, working_dir))

        if self.should_fail:
            raise RuntimeError(self.error_message)

        if self.should_timeout:
            raise TimeoutError("Sandbox execution timed out after timeout_seconds")

        # Check programmed exit code map
        for pattern, code in self.exit_code_map.items():
            if pattern in command:
                stderr_msg = f"Programmed failure for pattern {pattern!r}" if code != 0 else ""
                return MockExecutionCommandResult(
                    exit_code=code,
                    stdout="",
                    stderr=stderr_msg,
                    duration_seconds=0.05,
                )

        if self.fail_command_pattern and self.fail_command_pattern in command:
            return MockExecutionCommandResult(
                exit_code=1,
                stdout="",
                stderr="Simulated command failure",
                duration_seconds=0.05,
            )

        return MockExecutionCommandResult(
            exit_code=self.default_exit_code,
            stdout="OK",
            stderr="",
            duration_seconds=0.05,
        )

    def teardown_sandbox(self, handle: MockSandboxHandle) -> None:
        handle.is_torn_down = True
        self.torn_down_handles.append(handle)


@dataclass(frozen=True, slots=True)
class _MockMaterializedSourceRecord:
    """Private test fixture record for mock materialization results."""

    source_identity: SourceIdentity
    resolved_commit_sha: str
    workspace_path: str
    sandbox_identity: SandboxIdentity
    is_verified: bool = True


class MockSourceMaterializer:
    """Mock repository source materializer for testing candidate execution.

    Satisfies SourceMaterializerProtocol and produces _MockMaterializedSourceRecord records.
    """

    def __init__(
        self,
        *,
        should_fail: bool = False,
        should_produce_commit_mismatch: bool = False,
        should_produce_locator_mismatch: bool = False,
        should_produce_subpath_mismatch: bool = False,
        should_produce_workspace_mismatch: bool = False,
        should_produce_sandbox_mismatch: bool = False,
        should_produce_unverified: bool = False,
        should_produce_malformed: bool = False,
        error_message: str = "Materialization failed in sandbox",
    ) -> None:
        self.should_fail = should_fail
        self.should_produce_commit_mismatch = should_produce_commit_mismatch
        self.should_produce_locator_mismatch = should_produce_locator_mismatch
        self.should_produce_subpath_mismatch = should_produce_subpath_mismatch
        self.should_produce_workspace_mismatch = should_produce_workspace_mismatch
        self.should_produce_sandbox_mismatch = should_produce_sandbox_mismatch
        self.should_produce_unverified = should_produce_unverified
        self.should_produce_malformed = should_produce_malformed
        self.error_message = error_message
        self.materialized_calls: list[dict[str, Any]] = []

    def materialize_repository(
        self,
        source_identity: SourceIdentity,
        *,
        sandbox: Any = None,
        workspace_path: str = "/workspace/repo",
        timeout_seconds: int = 120,
        **kwargs: Any,
    ) -> Any:
        self.materialized_calls.append(
            {
                "source_identity": source_identity,
                "sandbox": sandbox,
                "workspace_path": workspace_path,
                "timeout_seconds": timeout_seconds,
            }
        )
        if self.should_fail:
            raise RuntimeError(self.error_message)

        if self.should_produce_malformed:
            return "not-a-record"

        src_id = source_identity
        if self.should_produce_locator_mismatch:
            src_id = SourceIdentity(
                locator="https://github.com/mismatched/repo.git",
                revision=source_identity.revision,
                subpath=source_identity.subpath,
            )
        elif self.should_produce_subpath_mismatch:
            src_id = SourceIdentity(
                locator=source_identity.locator,
                revision=source_identity.revision,
                subpath="mismatched/subpath",
            )

        commit = (
            "ffffffffffffffffffffffffffffffffffffffff"
            if self.should_produce_commit_mismatch
            else source_identity.resolved_commit_id
        )

        ws_path = (
            "/workspace/wrong_path" if self.should_produce_workspace_mismatch else workspace_path
        )

        sbx_id = (
            SandboxIdentity(sandbox_id="sbx-mismatched-foreign")
            if self.should_produce_sandbox_mismatch
            else getattr(
                sandbox, "sandbox_identity", SandboxIdentity(sandbox_id="sbx-mock-default")
            )
        )

        return _MockMaterializedSourceRecord(
            source_identity=src_id,
            resolved_commit_sha=commit,
            workspace_path=ws_path,
            sandbox_identity=sbx_id,
            is_verified=not self.should_produce_unverified,
        )


# --- Helper Fixtures ---


def _create_test_source_identity() -> SourceIdentity:
    return SourceIdentity(
        locator="https://github.com/zyganali-glitch/Basebreak.git",
        revision=CommitRevision("1111111111111111111111111111111111111111"),
        subpath=None,
    )


def _create_test_frozen_contract() -> FrozenContract:
    norm_task = ingest_task(
        "Task: Fix connection pool leak by closing idle handles.\n"
        "Requirements:\n"
        "1. Close idle handles when pool is drained."
    )
    fact = DeterministicClassificationFact(
        inferred_class=ChangeClass.BUG_FIX,
        certainty=CertaintyLevel.CONFIDENT,
        confidence=0.95,
        alternative_classes=(),
        rationale="Fix connection leak defect",
        evidence_citations=("Fix connection pool leak",),
        matched_signals=("fix", "leak"),
    )
    semantics = ChangeSemanticsClassification(
        task_digest=norm_task.task_digest,
        change_class=ChangeClass.BUG_FIX,
        certainty=CertaintyLevel.CONFIDENT,
        confidence=0.95,
        alternative_classes=(),
        rationale="Fix connection leak defect",
        evidence_citations=("Fix connection pool leak",),
        deterministic_facts=fact,
    )
    cit = "Close idle handles when pool is drained."
    start = norm_task.normalized_text.index(cit)
    end = start + len(cit)

    req = ProposedRequirement(
        statement="Close idle handles when pool is drained",
        citation=cit,
        citation_start=start,
        citation_end=end,
        rationale="Prevents leaking socket descriptors.",
    )
    bundle = ReviewBundle(task=norm_task, semantics=semantics, requirements=(req,))
    session = ReviewSession(bundle)
    review_result = session.approve(reviewer_note="Approved for freeze")
    return freeze_review_result(review_result)


def _create_test_envelope(
    contract: FrozenContract,
    source_id: SourceIdentity,
) -> Any:
    allowlist = BuilderContextAllowlist.from_paths(["src/pool.py", "tests/test_pool.py"])
    return assemble_builder_context(
        frozen_contract=contract,
        source_identity=source_id,
        allowlist=allowlist,
        repository_files={
            "src/pool.py": "class Pool:\n    pass\n",
            "tests/test_pool.py": "def test_pool(): pass\n",
        },
    )


def _create_sample_proposal(
    actions: Sequence[ProposedFileAction] | None = None,
    commands: Sequence[ProposedCommand] | None = None,
) -> BuilderProposal:
    plan = BuilderPlan(
        summary="Implement connection pool cleanup",
        reasoning="Closes idle connections on timeout",
        steps=("Step 1: add cleanup", "Step 2: run tests"),
        is_authoritative=False,
    )
    default_actions = (
        ProposedFileAction(
            path="src/pool.py",
            action=FileActionType.MODIFY,
            content="class Pool:\n    def close_idle(self): pass\n",
            rationale="Add close_idle method",
            is_authoritative=False,
        ),
    )
    default_commands = (
        ProposedCommand(
            command="pytest tests/test_pool.py",
            rationale="Verify pool behavior",
            is_authoritative=False,
        ),
    )
    return BuilderProposal(
        plan=plan,
        proposed_file_actions=tuple(actions if actions is not None else default_actions),
        proposed_commands=tuple(commands if commands is not None else default_commands),
        raw_response='{"mock": "response"}',
        is_authoritative=False,
    )


# --- Acceptance Tests ---


class TestCandidateExecutionFileMutations:
    """Test CREATE, MODIFY, DELETE file mutations in candidate workspace."""

    def test_create_file_success(self) -> None:
        source_id = _create_test_source_identity()
        contract = _create_test_frozen_contract()
        envelope = _create_test_envelope(contract, source_id)
        adapter = MockSandboxAdapter()

        proposal = _create_sample_proposal(
            actions=[
                ProposedFileAction(
                    path="src/new_module.py",
                    action=FileActionType.CREATE,
                    content="def new_func(): return 42\n",
                    rationale="Add new module",
                )
            ],
            commands=[],
        )

        executor = CandidateWorkspaceExecutor(adapter, source_materializer=MockSourceMaterializer())
        result = executor.execute(proposal, envelope=envelope)

        assert isinstance(result, CandidateExecutionResult)
        assert len(result.file_mutations) == 1
        mutation = result.file_mutations[0]
        assert mutation.path == "src/new_module.py"
        assert mutation.action == FileActionType.CREATE
        assert mutation.exit_code == 0
        assert mutation.is_success is True
        assert len(mutation.stdout_digest) == 64
        assert len(mutation.stderr_digest) == 64
        assert len(mutation.content_digest) == 64
        assert mutation.is_authoritative is False

        # Verify command executed in sandbox
        assert len(adapter.executed_commands) == 1
        _, cmd_str, cwd = adapter.executed_commands[0]
        assert "CREATE target already exists" in cmd_str
        assert "src/new_module.py" in cmd_str
        assert cwd == "/workspace/candidate"

    def test_modify_file_success(self) -> None:
        source_id = _create_test_source_identity()
        contract = _create_test_frozen_contract()
        envelope = _create_test_envelope(contract, source_id)
        adapter = MockSandboxAdapter()

        proposal = _create_sample_proposal(
            actions=[
                ProposedFileAction(
                    path="src/pool.py",
                    action=FileActionType.MODIFY,
                    content="class Pool:\n    def drain(self): pass\n",
                    rationale="Add drain method",
                )
            ],
            commands=[],
        )

        executor = CandidateWorkspaceExecutor(adapter, source_materializer=MockSourceMaterializer())
        result = executor.execute(proposal, envelope=envelope)

        assert len(result.file_mutations) == 1
        mutation = result.file_mutations[0]
        assert mutation.path == "src/pool.py"
        assert mutation.action == FileActionType.MODIFY
        assert mutation.exit_code == 0
        assert mutation.is_success is True

        assert len(adapter.executed_commands) == 1
        _, cmd_str, _ = adapter.executed_commands[0]
        assert "MODIFY target not found" in cmd_str
        assert "src/pool.py" in cmd_str

    def test_delete_file_success(self) -> None:
        source_id = _create_test_source_identity()
        contract = _create_test_frozen_contract()
        envelope = _create_test_envelope(contract, source_id)
        adapter = MockSandboxAdapter()

        proposal = _create_sample_proposal(
            actions=[
                ProposedFileAction(
                    path="src/obsolete.py",
                    action=FileActionType.DELETE,
                    content="",
                    rationale="Remove obsolete file",
                )
            ],
            commands=[],
        )

        executor = CandidateWorkspaceExecutor(adapter, source_materializer=MockSourceMaterializer())
        result = executor.execute(proposal, envelope=envelope)

        assert len(result.file_mutations) == 1
        mutation = result.file_mutations[0]
        assert mutation.path == "src/obsolete.py"
        assert mutation.action == FileActionType.DELETE
        assert mutation.exit_code == 0
        assert mutation.is_success is True
        assert mutation.content_digest == ""  # Empty content digest for DELETE

        assert len(adapter.executed_commands) == 1
        _, cmd_str, _ = adapter.executed_commands[0]
        assert "DELETE target not found" in cmd_str
        assert "rm -rf" in cmd_str


class TestCandidateExecutionMissingTarget:
    """Test missing target and target already exists behavior."""

    def test_missing_target_modify(self) -> None:
        source_id = _create_test_source_identity()
        contract = _create_test_frozen_contract()
        envelope = _create_test_envelope(contract, source_id)

        # Program sandbox to return exit code 102 (MODIFY target not found)
        adapter = MockSandboxAdapter(exit_code_map={"MODIFY target not found": 102})

        proposal = _create_sample_proposal(
            actions=[
                ProposedFileAction(
                    path="src/non_existent.py",
                    action=FileActionType.MODIFY,
                    content="def foo(): pass",
                )
            ]
        )

        executor = CandidateWorkspaceExecutor(adapter, source_materializer=MockSourceMaterializer())
        with pytest.raises(MissingTargetError) as exc_info:
            executor.execute(proposal, envelope=envelope)

        assert "MODIFY target not found" in str(exc_info.value)
        assert "src/non_existent.py" in str(exc_info.value)

    def test_missing_target_delete(self) -> None:
        source_id = _create_test_source_identity()
        contract = _create_test_frozen_contract()
        envelope = _create_test_envelope(contract, source_id)

        # Program sandbox to return exit code 103 (DELETE target not found)
        adapter = MockSandboxAdapter(exit_code_map={"DELETE target not found": 103})

        proposal = _create_sample_proposal(
            actions=[
                ProposedFileAction(
                    path="src/ghost_file.py",
                    action=FileActionType.DELETE,
                    content="",
                )
            ]
        )

        executor = CandidateWorkspaceExecutor(adapter, source_materializer=MockSourceMaterializer())
        with pytest.raises(MissingTargetError) as exc_info:
            executor.execute(proposal, envelope=envelope)

        assert "DELETE target not found" in str(exc_info.value)

    def test_target_already_exists_create(self) -> None:
        source_id = _create_test_source_identity()
        contract = _create_test_frozen_contract()
        envelope = _create_test_envelope(contract, source_id)

        # Program sandbox to return exit code 101 (CREATE target already exists)
        adapter = MockSandboxAdapter(exit_code_map={"CREATE target already exists": 101})

        proposal = _create_sample_proposal(
            actions=[
                ProposedFileAction(
                    path="src/existing.py",
                    action=FileActionType.CREATE,
                    content="def bar(): pass",
                )
            ]
        )

        executor = CandidateWorkspaceExecutor(adapter, source_materializer=MockSourceMaterializer())
        with pytest.raises(TargetAlreadyExistsError) as exc_info:
            executor.execute(proposal, envelope=envelope)

        assert "CREATE target already exists" in str(exc_info.value)


class TestCandidateExecutionPathSecurity:
    """Test path traversal, root escape, and path security rejection."""

    def test_path_traversal_rejected(self) -> None:
        config = CandidateExecutionConfig()
        # Direct traversal ..
        proposal = _create_sample_proposal(
            actions=[
                ProposedFileAction(
                    path="../escape.py",
                    action=FileActionType.CREATE,
                    content="x = 1",
                )
            ]
        )
        with pytest.raises(InvalidProposedMutationError) as exc_info:
            validate_candidate_proposal(proposal, config)
        assert "travers" in str(exc_info.value).lower()

    def test_root_escape_absolute_path_rejected(self) -> None:
        config = CandidateExecutionConfig()
        proposal = _create_sample_proposal(
            actions=[
                ProposedFileAction(
                    path="/etc/passwd",
                    action=FileActionType.MODIFY,
                    content="evil",
                )
            ]
        )
        with pytest.raises(InvalidProposedMutationError) as exc_info:
            validate_candidate_proposal(proposal, config)
        assert "absolute path" in str(exc_info.value).lower()

    def test_windows_drive_letter_rejected(self) -> None:
        config = CandidateExecutionConfig()
        proposal = _create_sample_proposal(
            actions=[
                ProposedFileAction(
                    path="C:/Windows/System32/cmd.exe",
                    action=FileActionType.MODIFY,
                    content="evil",
                )
            ]
        )
        with pytest.raises(InvalidProposedMutationError) as exc_info:
            validate_candidate_proposal(proposal, config)
        assert "drive letter" in str(exc_info.value).lower()

    def test_duplicate_mutations_rejected(self) -> None:
        config = CandidateExecutionConfig()
        proposal = _create_sample_proposal(
            actions=[
                ProposedFileAction(
                    path="src/pool.py",
                    action=FileActionType.CREATE,
                    content="code1",
                ),
                ProposedFileAction(
                    path="./src/pool.py",
                    action=FileActionType.MODIFY,
                    content="code2",
                ),
            ]
        )
        with pytest.raises(DuplicateActionError) as exc_info:
            validate_candidate_proposal(proposal, config)
        assert "duplicate or conflicting" in str(exc_info.value).lower()
        assert "src/pool.py" in str(exc_info.value)

    def test_invalid_workspace_path_rejected(self) -> None:
        with pytest.raises(InvalidPathError):
            validate_workspace_path("")
        with pytest.raises(InvalidPathError):
            validate_workspace_path("relative/path")
        with pytest.raises(PathTraversalError):
            validate_workspace_path("/workspace/../etc")
        with pytest.raises(InvalidPathError):
            validate_workspace_path("/")


class TestCandidateExecutionCommandBounding:
    """Test command count bounds, timeouts, length ceilings, and recursion patterns."""

    def test_command_count_bound_exceeded(self) -> None:
        config = CandidateExecutionConfig(max_commands=3)
        cmds = [ProposedCommand(command=f"pytest test_{i}.py") for i in range(4)]
        proposal = _create_sample_proposal(commands=cmds)
        with pytest.raises(CommandBoundingError) as exc_info:
            validate_candidate_proposal(proposal, config)
        assert "exceeds limit" in str(exc_info.value)

    def test_command_length_bound_exceeded(self) -> None:
        config = CandidateExecutionConfig(max_command_length_bytes=300)
        long_cmd = "echo " + "a" * 500
        proposal = _create_sample_proposal(commands=[ProposedCommand(command=long_cmd)])
        with pytest.raises(CommandBoundingError) as exc_info:
            validate_candidate_proposal(proposal, config)
        assert "exceeds length limit" in str(exc_info.value)

    def test_forbidden_fork_bomb_rejected(self) -> None:
        config = CandidateExecutionConfig()
        fork_bomb = ":(){ :|:& };:"
        proposal = _create_sample_proposal(commands=[ProposedCommand(command=fork_bomb)])
        with pytest.raises(ForbiddenCommandError) as exc_info:
            validate_candidate_proposal(proposal, config)
        assert "fork bomb" in str(exc_info.value).lower()

    def test_forbidden_recursive_shell_rejected(self) -> None:
        config = CandidateExecutionConfig()
        rec_cmd = "sh $0 $0"
        proposal = _create_sample_proposal(commands=[ProposedCommand(command=rec_cmd)])
        with pytest.raises(ForbiddenCommandError) as exc_info:
            validate_candidate_proposal(proposal, config)
        assert "recursive shell" in str(exc_info.value).lower()

    def test_forbidden_persistent_daemon_rejected(self) -> None:
        config = CandidateExecutionConfig()
        daemon_cmd = "nohup python server.py &"
        proposal = _create_sample_proposal(commands=[ProposedCommand(command=daemon_cmd)])
        with pytest.raises(ForbiddenCommandError) as exc_info:
            validate_candidate_proposal(proposal, config)
        assert "daemon" in str(exc_info.value).lower()

    def test_command_timeout(self) -> None:
        source_id = _create_test_source_identity()
        contract = _create_test_frozen_contract()
        envelope = _create_test_envelope(contract, source_id)
        adapter = MockSandboxAdapter(should_timeout=True)

        proposal = _create_sample_proposal(actions=[])
        executor = CandidateWorkspaceExecutor(adapter, source_materializer=MockSourceMaterializer())

        with pytest.raises(CandidateExecutionTimeoutError) as exc_info:
            executor.execute(proposal, envelope=envelope)
        assert "timeout" in str(exc_info.value).lower()

    def test_command_non_zero_exit_recorded_without_crash(self) -> None:
        source_id = _create_test_source_identity()
        contract = _create_test_frozen_contract()
        envelope = _create_test_envelope(contract, source_id)
        # Program command to exit with 1 (e.g. pytest failure)
        adapter = MockSandboxAdapter(fail_command_pattern="pytest")

        proposal = _create_sample_proposal(actions=[])
        executor = CandidateWorkspaceExecutor(adapter, source_materializer=MockSourceMaterializer())
        result = executor.execute(proposal, envelope=envelope)

        assert len(result.command_executions) == 1
        cmd_rec = result.command_executions[0]
        assert cmd_rec.command == "pytest tests/test_pool.py"
        assert cmd_rec.exit_code == 1
        assert cmd_rec.status == TerminationStatus.COMPLETED
        assert cmd_rec.is_authoritative is False


class TestCandidateExecutionSafetyAndLifecycle:
    """Test host fallback prevention, secret safety, and lifecycle teardown."""

    def test_zero_host_execution_fallback(self) -> None:
        with pytest.raises(HostExecutionFallbackError) as exc_info:
            CandidateWorkspaceExecutor(None)
        assert "host execution fallback is strictly prohibited" in str(exc_info.value)

    def test_zero_credentials_in_file_content(self) -> None:
        config = CandidateExecutionConfig()
        secret_content = "API_KEY = 'AKIA1234567890123456'"
        proposal = _create_sample_proposal(
            actions=[
                ProposedFileAction(
                    path="src/config.py",
                    action=FileActionType.CREATE,
                    content=secret_content,
                )
            ]
        )
        with pytest.raises(CredentialLeakageError) as exc_info:
            validate_candidate_proposal(proposal, config)
        assert "secret-shaped value detected" in str(exc_info.value).lower()

    def test_zero_credentials_in_command(self) -> None:
        config = CandidateExecutionConfig()
        secret_cmd = "curl -H 'Authorization: Bearer nbs_sk_12345678901234567890' https://api.com"
        proposal = _create_sample_proposal(commands=[ProposedCommand(command=secret_cmd)])
        with pytest.raises(CredentialLeakageError) as exc_info:
            validate_candidate_proposal(proposal, config)
        assert "secret-shaped value detected" in str(exc_info.value).lower()

    def test_teardown_on_failure(self) -> None:
        source_id = _create_test_source_identity()
        contract = _create_test_frozen_contract()
        envelope = _create_test_envelope(contract, source_id)
        adapter = MockSandboxAdapter(should_fail=True)

        proposal = _create_sample_proposal()
        executor = CandidateWorkspaceExecutor(adapter, source_materializer=MockSourceMaterializer())

        with pytest.raises(WorkspaceExecutionError):
            executor.execute(proposal, envelope=envelope)

        # Verify created sandbox was torn down upon failure
        assert len(adapter.created_handles) == 1
        assert len(adapter.torn_down_handles) == 1
        assert adapter.created_handles[0].is_torn_down is True

    def test_proposal_and_result_strictly_non_authoritative(self) -> None:
        source_id = _create_test_source_identity()
        contract = _create_test_frozen_contract()
        envelope = _create_test_envelope(contract, source_id)
        adapter = MockSandboxAdapter()

        proposal = _create_sample_proposal()
        executor = CandidateWorkspaceExecutor(adapter, source_materializer=MockSourceMaterializer())
        result = executor.execute(proposal, envelope=envelope)

        assert result.is_authoritative is False
        for m in result.file_mutations:
            assert m.is_authoritative is False
        for c in result.command_executions:
            assert c.is_authoritative is False

        # Direct initialization with True fails
        with pytest.raises(ValueError):
            CandidateExecutionResult(
                frozen_contract_digest=result.frozen_contract_digest,
                context_digest=result.context_digest,
                source_identity=result.source_identity,
                proposal_digest=result.proposal_digest,
                proposal_plan_summary=result.proposal_plan_summary,
                file_mutations=result.file_mutations,
                command_executions=result.command_executions,
                sandbox_identity=result.sandbox_identity,
                total_duration_seconds=result.total_duration_seconds,
                is_authoritative=True,
            )

    def test_deterministic_result_capture_and_roundtrip(self) -> None:
        source_id = _create_test_source_identity()
        contract = _create_test_frozen_contract()
        envelope = _create_test_envelope(contract, source_id)
        adapter = MockSandboxAdapter()

        proposal = _create_sample_proposal()
        executor = CandidateWorkspaceExecutor(adapter, source_materializer=MockSourceMaterializer())
        result = executor.execute(proposal, envelope=envelope)

        # Check cryptographic bindings
        assert result.frozen_contract_digest == contract.contract_digest
        assert result.context_digest == envelope.context_digest
        assert result.source_identity == source_id
        assert len(result.proposal_digest) == 64
        assert result.proposal_digest == compute_proposal_digest(proposal)
        assert result.proposal_plan_summary == proposal.plan.summary

        # Serialization roundtrip test
        result_dict = result.to_dict()
        assert isinstance(result_dict, dict)
        restored = CandidateExecutionResult.from_dict(result_dict)
        assert restored == result
        assert restored.frozen_contract_digest == result.frozen_contract_digest
        assert restored.proposal_digest == result.proposal_digest
        assert len(restored.file_mutations) == len(result.file_mutations)
        assert len(restored.command_executions) == len(result.command_executions)

    def test_large_file_chunking(self) -> None:
        # Create a 20KB file content that exceeds 8000 base64 chars
        large_content = "def test_chunking():\n" + "    x = 1\n" * 1500
        action = ProposedFileAction(
            path="src/large_file.py",
            action=FileActionType.CREATE,
            content=large_content,
        )
        scripts = build_file_mutation_scripts("src/large_file.py", action, "/workspace/candidate")
        assert len(scripts) > 1  # Verify chunked into multiple commands
        for script in scripts:
            assert len(script.encode("utf-8")) < 16384  # All scripts under 16KB budget


class TestCandidateExecutionProviderPurity:
    """Verify CandidateWorkspaceExecutor is strictly provider-neutral."""

    def test_execution_has_zero_provider_imports(self) -> None:
        from basebreak.builder import execution

        src = inspect.getsource(execution)
        parsed = ast.parse(src)

        imported_modules: set[str] = set()
        for node in ast.walk(parsed):
            if isinstance(node, ast.Import):
                for alias in node.names:
                    imported_modules.add(alias.name)
            elif isinstance(node, ast.ImportFrom) and node.module:
                imported_modules.add(node.module)

        forbidden_prefixes = (
            "basebreak.adapters",
            "openai",
            "nebius",
            "tavily",
            "anthropic",
            "requests",
            "urllib3",
            "aiohttp",
            "httpx",
        )
        for mod in imported_modules:
            for forbidden in forbidden_prefixes:
                assert not (mod == forbidden or mod.startswith(forbidden + ".")), (
                    f"Forbidden provider or adapter import found in builder/execution.py: {mod}"
                )


class TestCandidateExecutionMaterializedSourceAuthority:
    """Test fail-closed authoritative context and verified materialized workspace enforcement."""

    def test_execution_without_envelope_fails_closed(self) -> None:
        adapter = MockSandboxAdapter()
        executor = CandidateWorkspaceExecutor(adapter)
        proposal = _create_sample_proposal()

        with pytest.raises(MissingAuthoritativeEnvelopeError) as exc_info:
            executor.execute(proposal, envelope=None)
        assert "authoritative BuilderContextEnvelope" in str(exc_info.value)

    def test_bare_digest_inputs_cannot_authorize_execution(self) -> None:
        source_id = _create_test_source_identity()
        adapter = MockSandboxAdapter()
        executor = CandidateWorkspaceExecutor(adapter)
        proposal = _create_sample_proposal()

        fake_contract_digest = "a" * 64
        fake_context_digest = "b" * 64

        # Attempting bare kwargs fails closed immediately
        with pytest.raises(MissingAuthoritativeEnvelopeError) as exc_info:
            executor.execute(
                proposal,
                frozen_contract_digest=fake_contract_digest,
                context_digest=fake_context_digest,
                source_identity=source_id,
            )
        assert "Bare digest inputs" in str(exc_info.value)
        assert "strictly forbidden" in str(exc_info.value)

    def test_unmaterialized_sandbox_fails_closed(self) -> None:
        source_id = _create_test_source_identity()
        contract = _create_test_frozen_contract()
        envelope = _create_test_envelope(contract, source_id)
        adapter = MockSandboxAdapter()

        # Executor without materializer in constructor and none passed at execution
        executor = CandidateWorkspaceExecutor(adapter)
        proposal = _create_sample_proposal()

        with pytest.raises(UnmaterializedWorkspaceError) as exc_info:
            executor.execute(proposal, envelope=envelope)
        assert "Cannot execute candidate in unmaterialized workspace" in str(exc_info.value)
        assert "source_materializer dependency is required" in str(exc_info.value)
        assert adapter.executed_commands == []

    def test_caller_cannot_supply_materialized_source_record(self) -> None:
        source_id = _create_test_source_identity()
        contract = _create_test_frozen_contract()
        envelope = _create_test_envelope(contract, source_id)
        adapter = MockSandboxAdapter()
        handle = adapter.create_sandbox("test-image")
        materializer = MockSourceMaterializer()

        fake_record = _MockMaterializedSourceRecord(
            source_identity=source_id,
            resolved_commit_sha=source_id.resolved_commit_id,
            workspace_path="/workspace/candidate",
            sandbox_identity=handle.sandbox_identity,
            is_verified=True,
        )

        executor = CandidateWorkspaceExecutor(adapter, source_materializer=materializer)
        proposal = _create_sample_proposal()

        with pytest.raises(MaterializedSourceVerificationError) as exc_info:
            executor.execute(
                proposal,
                envelope=envelope,
                materialized_source=fake_record,
                sandbox_handle=handle,
            )
        assert "Caller-supplied materialized_source is strictly forbidden" in str(exc_info.value)
        assert len(materializer.materialized_calls) == 0
        assert adapter.executed_commands == []

    def test_synthetic_verified_record_cannot_bypass_materializer_execution(self) -> None:
        source_id = _create_test_source_identity()
        contract = _create_test_frozen_contract()
        envelope = _create_test_envelope(contract, source_id)
        adapter = MockSandboxAdapter()
        handle = adapter.create_sandbox("test-image")
        materializer = MockSourceMaterializer()

        # Perfectly matching synthetic record
        synthetic = _MockMaterializedSourceRecord(
            source_identity=envelope.source_identity,
            resolved_commit_sha=envelope.source_identity.resolved_commit_id,
            workspace_path="/workspace/candidate",
            sandbox_identity=handle.sandbox_identity,
            is_verified=True,
        )

        executor = CandidateWorkspaceExecutor(adapter, source_materializer=materializer)
        proposal = _create_sample_proposal()

        with pytest.raises(MaterializedSourceVerificationError) as exc_info:
            executor.execute(
                proposal,
                envelope=envelope,
                materialized_source=synthetic,
                sandbox_handle=handle,
            )
        assert "materialized_source is strictly forbidden" in str(exc_info.value)
        assert len(materializer.materialized_calls) == 0
        assert adapter.executed_commands == []

    def test_materializer_invoked_exactly_once_before_first_candidate_mutation(self) -> None:
        source_id = _create_test_source_identity()
        contract = _create_test_frozen_contract()
        envelope = _create_test_envelope(contract, source_id)
        adapter = MockSandboxAdapter()
        materializer = MockSourceMaterializer()

        executor = CandidateWorkspaceExecutor(adapter, source_materializer=materializer)
        proposal = _create_sample_proposal(
            actions=[
                ProposedFileAction(
                    path="src/pool.py",
                    action=FileActionType.MODIFY,
                    content="class Pool:\n    pass\n",
                    rationale="Update pool",
                )
            ],
            commands=[
                ProposedCommand(command="python -m pytest", rationale="run tests"),
            ],
        )

        result = executor.execute(proposal, envelope=envelope)

        assert isinstance(result, CandidateExecutionResult)
        assert len(materializer.materialized_calls) == 1
        # All mutation commands in adapter occurred strictly after materialization
        assert len(adapter.executed_commands) == 2  # 1 file mutation + 1 proposed command

    def test_materializer_receives_authoritative_envelope_source_identity(self) -> None:
        source_id = _create_test_source_identity()
        contract = _create_test_frozen_contract()
        envelope = _create_test_envelope(contract, source_id)
        adapter = MockSandboxAdapter()
        materializer = MockSourceMaterializer()

        executor = CandidateWorkspaceExecutor(adapter, source_materializer=materializer)
        proposal = _create_sample_proposal()

        executor.execute(proposal, envelope=envelope)

        assert len(materializer.materialized_calls) == 1
        call = materializer.materialized_calls[0]
        assert call["source_identity"] == envelope.source_identity
        assert (
            call["source_identity"].resolved_commit_id
            == envelope.source_identity.resolved_commit_id
        )
        assert call["source_identity"].locator == envelope.source_identity.locator
        assert call["source_identity"].subpath == envelope.source_identity.subpath

    def test_materializer_receives_exact_same_sandbox_handle(self) -> None:
        source_id = _create_test_source_identity()
        contract = _create_test_frozen_contract()
        envelope = _create_test_envelope(contract, source_id)
        adapter = MockSandboxAdapter()
        handle = adapter.create_sandbox("test-image")
        materializer = MockSourceMaterializer()

        executor = CandidateWorkspaceExecutor(adapter, source_materializer=materializer)
        proposal = _create_sample_proposal()

        executor.execute(proposal, envelope=envelope, sandbox_handle=handle)

        assert len(materializer.materialized_calls) == 1
        call = materializer.materialized_calls[0]
        assert call["sandbox"] is handle
        for cmd_sbx, _, _ in adapter.executed_commands:
            assert cmd_sbx is handle

    def test_materializer_receives_exact_same_workspace_path(self) -> None:
        source_id = _create_test_source_identity()
        contract = _create_test_frozen_contract()
        envelope = _create_test_envelope(contract, source_id)
        adapter = MockSandboxAdapter()
        materializer = MockSourceMaterializer()

        executor = CandidateWorkspaceExecutor(adapter, source_materializer=materializer)
        proposal = _create_sample_proposal()

        executor.execute(proposal, envelope=envelope)

        assert len(materializer.materialized_calls) == 1
        call = materializer.materialized_calls[0]
        assert call["workspace_path"] == "/workspace/candidate"
        for _, _, cwd in adapter.executed_commands:
            assert cwd == "/workspace/candidate"

    def test_materializer_failure_prevents_all_candidate_mutations_and_commands(self) -> None:
        source_id = _create_test_source_identity()
        contract = _create_test_frozen_contract()
        envelope = _create_test_envelope(contract, source_id)
        adapter = MockSandboxAdapter()
        materializer = MockSourceMaterializer(
            should_fail=True,
            error_message="Git clone failed: host unreachable",
        )

        executor = CandidateWorkspaceExecutor(adapter, source_materializer=materializer)
        proposal = _create_sample_proposal()

        with pytest.raises(WorkspaceExecutionError) as exc_info:
            executor.execute(proposal, envelope=envelope)
        assert "Failed to materialize authoritative repository in sandbox" in str(exc_info.value)
        assert "Git clone failed: host unreachable" in str(exc_info.value)
        # Sandbox must be torn down
        assert len(adapter.created_handles) == 1
        assert adapter.created_handles[0].is_torn_down is True
        # Explicit assertion: zero candidate mutation or execution commands dispatched
        assert adapter.executed_commands == []

    def test_materializer_commit_mismatch_prevents_mutation(self) -> None:
        source_id = _create_test_source_identity()
        contract = _create_test_frozen_contract()
        envelope = _create_test_envelope(contract, source_id)
        adapter = MockSandboxAdapter()
        materializer = MockSourceMaterializer(should_produce_commit_mismatch=True)

        executor = CandidateWorkspaceExecutor(adapter, source_materializer=materializer)
        proposal = _create_sample_proposal()

        with pytest.raises(SourceCommitMismatchError) as exc_info:
            executor.execute(proposal, envelope=envelope)
        assert "does not match authoritative envelope commit" in str(exc_info.value)
        assert adapter.executed_commands == []

    def test_materializer_locator_mismatch_prevents_mutation(self) -> None:
        source_id = _create_test_source_identity()
        contract = _create_test_frozen_contract()
        envelope = _create_test_envelope(contract, source_id)
        adapter = MockSandboxAdapter()
        materializer = MockSourceMaterializer(should_produce_locator_mismatch=True)

        executor = CandidateWorkspaceExecutor(adapter, source_materializer=materializer)
        proposal = _create_sample_proposal()

        with pytest.raises(MaterializedSourceMismatchError) as exc_info:
            executor.execute(proposal, envelope=envelope)
        assert "does not match authoritative envelope locator" in str(exc_info.value)
        assert adapter.executed_commands == []

    def test_materializer_subpath_mismatch_prevents_mutation(self) -> None:
        source_id = _create_test_source_identity()
        contract = _create_test_frozen_contract()
        envelope = _create_test_envelope(contract, source_id)
        adapter = MockSandboxAdapter()
        materializer = MockSourceMaterializer(should_produce_subpath_mismatch=True)

        executor = CandidateWorkspaceExecutor(adapter, source_materializer=materializer)
        proposal = _create_sample_proposal()

        with pytest.raises(MaterializedSourceMismatchError) as exc_info:
            executor.execute(proposal, envelope=envelope)
        assert "subpath" in str(exc_info.value).lower()
        assert adapter.executed_commands == []

    def test_materializer_workspace_path_mismatch_prevents_mutation(self) -> None:
        source_id = _create_test_source_identity()
        contract = _create_test_frozen_contract()
        envelope = _create_test_envelope(contract, source_id)
        adapter = MockSandboxAdapter()
        materializer = MockSourceMaterializer(should_produce_workspace_mismatch=True)

        executor = CandidateWorkspaceExecutor(adapter, source_materializer=materializer)
        proposal = _create_sample_proposal()

        with pytest.raises(MaterializedSourceMismatchError) as exc_info:
            executor.execute(proposal, envelope=envelope)
        assert "does not match candidate execution workspace path" in str(exc_info.value)
        assert adapter.executed_commands == []

    def test_materializer_sandbox_identity_mismatch_prevents_mutation(self) -> None:
        source_id = _create_test_source_identity()
        contract = _create_test_frozen_contract()
        envelope = _create_test_envelope(contract, source_id)
        adapter = MockSandboxAdapter()
        materializer = MockSourceMaterializer(should_produce_sandbox_mismatch=True)

        executor = CandidateWorkspaceExecutor(adapter, source_materializer=materializer)
        proposal = _create_sample_proposal()

        with pytest.raises(SandboxIdentityMismatchError) as exc_info:
            executor.execute(proposal, envelope=envelope)
        assert "does not match candidate execution sandbox identity" in str(exc_info.value)
        assert adapter.executed_commands == []

    def test_missing_sandbox_identity_fails_closed_no_unidentified(self) -> None:
        source_id = _create_test_source_identity()
        contract = _create_test_frozen_contract()
        envelope = _create_test_envelope(contract, source_id)
        adapter = MockSandboxAdapter()

        # Handle without sandbox_identity
        @dataclass
        class BadSandboxHandle:
            sandbox_identity: Any = None
            is_torn_down: bool = False

        bad_handle = BadSandboxHandle()
        executor = CandidateWorkspaceExecutor(adapter, source_materializer=MockSourceMaterializer())
        proposal = _create_sample_proposal()

        with pytest.raises(WorkspaceExecutionError) as exc_info:
            executor.execute(proposal, envelope=envelope, sandbox_handle=bad_handle)
        assert "lacks a deterministic SandboxIdentity" in str(exc_info.value)
        assert "unidentified sandboxes are strictly prohibited" in str(exc_info.value)
        assert adapter.executed_commands == []

    def test_empty_sandbox_id_fails_closed_no_unidentified(self) -> None:
        source_id = _create_test_source_identity()
        contract = _create_test_frozen_contract()
        envelope = _create_test_envelope(contract, source_id)
        adapter = MockSandboxAdapter()

        empty_sid = object.__new__(SandboxIdentity)
        object.__setattr__(empty_sid, "sandbox_id", "   ")
        object.__setattr__(empty_sid, "description", "")

        @dataclass
        class EmptyIdSandboxHandle:
            sandbox_identity: Any = empty_sid
            is_torn_down: bool = False

        empty_handle = EmptyIdSandboxHandle()
        executor = CandidateWorkspaceExecutor(adapter, source_materializer=MockSourceMaterializer())
        proposal = _create_sample_proposal()

        with pytest.raises(WorkspaceExecutionError) as exc_info:
            executor.execute(proposal, envelope=envelope, sandbox_handle=empty_handle)
        assert "empty or whitespace sandbox_id" in str(exc_info.value)
        assert "unidentified sandboxes are strictly prohibited" in str(exc_info.value)
        assert adapter.executed_commands == []

    def test_unverified_materialization_record_prevents_mutation(self) -> None:
        source_id = _create_test_source_identity()
        contract = _create_test_frozen_contract()
        envelope = _create_test_envelope(contract, source_id)
        adapter = MockSandboxAdapter()
        materializer = MockSourceMaterializer(should_produce_unverified=True)

        executor = CandidateWorkspaceExecutor(adapter, source_materializer=materializer)
        proposal = _create_sample_proposal()

        with pytest.raises(MaterializedSourceVerificationError) as exc_info:
            executor.execute(proposal, envelope=envelope)
        assert "verification did not succeed" in str(exc_info.value)
        assert adapter.executed_commands == []

    def test_malformed_materialization_record_prevents_mutation(self) -> None:
        source_id = _create_test_source_identity()
        contract = _create_test_frozen_contract()
        envelope = _create_test_envelope(contract, source_id)
        adapter = MockSandboxAdapter()
        materializer = MockSourceMaterializer(should_produce_malformed=True)

        executor = CandidateWorkspaceExecutor(adapter, source_materializer=materializer)
        proposal = _create_sample_proposal()

        with pytest.raises(MaterializedSourceVerificationError):
            executor.execute(proposal, envelope=envelope)
        assert adapter.executed_commands == []

    def test_successful_verified_materializer_result_allows_normal_bounded_execution(
        self,
    ) -> None:
        source_id = _create_test_source_identity()
        contract = _create_test_frozen_contract()
        envelope = _create_test_envelope(contract, source_id)
        adapter = MockSandboxAdapter()
        handle = adapter.create_sandbox("test-image")
        materializer = MockSourceMaterializer()

        executor = CandidateWorkspaceExecutor(adapter, source_materializer=materializer)
        proposal = _create_sample_proposal(
            actions=[
                ProposedFileAction(
                    path="src/repaired.py",
                    action=FileActionType.CREATE,
                    content="def repair(): pass\n",
                    rationale="Add repair",
                )
            ],
            commands=[
                ProposedCommand(command="python -m pytest", rationale="run tests"),
            ],
        )

        result = executor.execute(
            proposal,
            envelope=envelope,
            sandbox_handle=handle,
        )

        assert isinstance(result, CandidateExecutionResult)
        assert result.source_identity == source_id
        assert result.frozen_contract_digest == contract.contract_digest
        assert result.context_digest == envelope.context_digest
        assert result.sandbox_identity == handle.sandbox_identity
        assert len(result.file_mutations) == 1
        assert len(result.command_executions) == 1
        assert len(materializer.materialized_calls) == 1

    def test_runtime_injected_source_materializer_allows_execution(self) -> None:
        source_id = _create_test_source_identity()
        contract = _create_test_frozen_contract()
        envelope = _create_test_envelope(contract, source_id)
        adapter = MockSandboxAdapter()
        materializer = MockSourceMaterializer()

        # Constructor receives None, materializer injected at execute()
        executor = CandidateWorkspaceExecutor(adapter, source_materializer=None)
        proposal = _create_sample_proposal()

        result = executor.execute(proposal, envelope=envelope, source_materializer=materializer)

        assert isinstance(result, CandidateExecutionResult)
        assert len(materializer.materialized_calls) == 1
        call = materializer.materialized_calls[0]
        assert call["source_identity"] == source_id
        assert call["workspace_path"] == "/workspace/candidate"

    def test_result_identity_comes_only_from_authoritative_envelope(self) -> None:
        source_id = _create_test_source_identity()
        contract = _create_test_frozen_contract()
        envelope = _create_test_envelope(contract, source_id)
        adapter = MockSandboxAdapter()
        executor = CandidateWorkspaceExecutor(adapter, source_materializer=MockSourceMaterializer())
        proposal = _create_sample_proposal()

        result = executor.execute(proposal, envelope=envelope)

        assert result.frozen_contract_digest == envelope.frozen_contract.contract_digest
        assert result.context_digest == envelope.context_digest
        assert result.source_identity == envelope.source_identity
        expected_commit = "1111111111111111111111111111111111111111"
        assert result.source_identity.resolved_commit_id == expected_commit

    def test_validate_materialized_workspace_helper_direct(self) -> None:
        source_id = _create_test_source_identity()
        contract = _create_test_frozen_contract()
        envelope = _create_test_envelope(contract, source_id)
        sbx_id = SandboxIdentity(sandbox_id="sbx-direct")
        record = _MockMaterializedSourceRecord(
            source_identity=source_id,
            resolved_commit_sha=source_id.resolved_commit_id,
            workspace_path="/workspace/candidate",
            sandbox_identity=sbx_id,
            is_verified=True,
        )
        validate_materialized_workspace(
            record,
            envelope=envelope,
            expected_workspace_path="/workspace/candidate",
            expected_sandbox_identity=sbx_id,
        )

    def test_protocols_satisfied_by_materialized_records(self) -> None:
        from basebreak.adapters.nebius.materialization import MaterializedSourceRecord

        source_id = _create_test_source_identity()
        mock_record = _MockMaterializedSourceRecord(
            source_identity=source_id,
            resolved_commit_sha=source_id.resolved_commit_id,
            workspace_path="/workspace/repo",
            sandbox_identity=SandboxIdentity(sandbox_id="sbx-test"),
            is_verified=True,
        )
        assert isinstance(mock_record, MaterializedSourceBinding)

        canonical_record = MaterializedSourceRecord(
            source_identity=source_id,
            resolved_commit_sha=source_id.resolved_commit_id,
            resolved_tree_sha="2222222222222222222222222222222222222222",
            workspace_path="/workspace/repo",
            sandbox_identity=SandboxIdentity(sandbox_id="sbx-canon"),
            operation_id="op-1234",
            duration_seconds=1.5,
            is_verified=True,
        )
        assert isinstance(canonical_record, MaterializedSourceBinding)
        assert isinstance(MockSourceMaterializer(), SourceMaterializerProtocol)

    def test_no_p07_05_authority_accidentally_introduced(self) -> None:
        source_id = _create_test_source_identity()
        contract = _create_test_frozen_contract()
        envelope = _create_test_envelope(contract, source_id)
        adapter = MockSandboxAdapter()
        executor = CandidateWorkspaceExecutor(adapter, source_materializer=MockSourceMaterializer())
        proposal = _create_sample_proposal()

        result = executor.execute(proposal, envelope=envelope)

        # Self-certification forbidden
        assert result.is_authoritative is False
        for m in result.file_mutations:
            assert m.is_authoritative is False
        for c in result.command_executions:
            assert c.is_authoritative is False

        # Verify no P-07.05 policy authority attributes exist on result
        assert not hasattr(result, "is_verified_candidate")
        assert not hasattr(result, "protected_surface_verdict")
        assert not hasattr(result, "forbidden_surface_mutations")

    def test_candidate_execution_creates_disposable_sandbox(self) -> None:
        """Blocker 2: Candidate workspace executor must create disposable=True sandbox."""
        source_id = _create_test_source_identity()
        contract = _create_test_frozen_contract()
        envelope = _create_test_envelope(contract, source_id)
        adapter = MockSandboxAdapter()
        executor = CandidateWorkspaceExecutor(adapter, source_materializer=MockSourceMaterializer())
        proposal = _create_sample_proposal()

        executor.execute(proposal, envelope=envelope)
        assert len(adapter.created_handles) == 1
        assert adapter.created_handles[0].disposable is True, (
            "Candidate sandbox must be disposable=True"
        )

    def test_candidate_execution_materializer_type_error_fails_closed_no_retry(self) -> None:
        """Blocker 2: Materializer TypeError must fail closed and NOT be silently retried."""
        source_id = _create_test_source_identity()
        contract = _create_test_frozen_contract()
        envelope = _create_test_envelope(contract, source_id)
        adapter = MockSandboxAdapter()

        call_count = 0

        class FailingMaterializer:
            def materialize_repository(self, *args: Any, **kwargs: Any) -> Any:
                nonlocal call_count
                call_count += 1
                raise TypeError("Simulated materializer TypeError bug")

        executor = CandidateWorkspaceExecutor(adapter, source_materializer=FailingMaterializer())
        proposal = _create_sample_proposal()

        with pytest.raises(WorkspaceExecutionError, match="Simulated materializer TypeError bug"):
            executor.execute(proposal, envelope=envelope)

        assert call_count == 1, (
            f"Materializer must be called exactly once, called {call_count} times"
        )

    def test_candidate_execution_bundled_with_clean_base_record(self) -> None:
        """Blocker 2: Candidate execution with clean_base_record uses clean checkpoint image
        and bundled disposable execution.
        """
        import base64
        from types import SimpleNamespace

        source_id = _create_test_source_identity()
        contract = _create_test_frozen_contract()
        envelope = _create_test_envelope(contract, source_id)

        clean_base_record = SimpleNamespace(
            source_identity=source_id,
            resolved_commit_sha=source_id.resolved_commit_id,
            workspace_path="/workspace/candidate",
            result_image_uuid="img-clean-base-checkpoint-uuid",
            is_verified=True,
        )

        class MockBundledAdapter:
            def __init__(self) -> None:
                self.created_handles: list[Any] = []
                self.executed_commands: list[str] = []

            def create_sandbox(self, image: str, disposable: bool = True) -> Any:
                h = MockSandboxHandle(
                    sandbox_identity=SandboxIdentity("sbx-candidate-bundled"),
                    image=image,
                    disposable=disposable,
                )
                self.created_handles.append(h)
                return h

            def execute_command(self, sandbox: Any, command: str, **kwargs: Any) -> Any:
                self.executed_commands.append(command)
                status_b64 = base64.b64encode(b"A\tsrc/foo.py\n").decode("ascii")
                raw_diff = (
                    b"diff --git a/src/foo.py b/src/foo.py\n"
                    b"new file mode 100644\n--- /dev/null\n+++ b/src/foo.py\n"
                    b"@@ -0,0 +1 @@\n+def foo(): pass\n"
                )
                diff_b64 = base64.b64encode(raw_diff).decode("ascii")
                stdout = (
                    "BASEBREAK_TOPLEVEL=/workspace/candidate\n"
                    f"BASEBREAK_HEAD={source_id.resolved_commit_id}\n"
                    "BASEBREAK_CANDIDATE_TREE=1234567890abcdef1234567890abcdef12345678\n"
                    f"BASEBREAK_STATUS_B64={status_b64}\n"
                    f"BASEBREAK_DIFF_B64={diff_b64}\n"
                )
                return SimpleNamespace(exit_code=0, stdout=stdout, stderr="")

            def teardown_sandbox(self, sandbox: Any) -> None:
                pass

        adapter = MockBundledAdapter()
        config = CandidateExecutionConfig(
            bundled_execution=True,
            clean_base_record=clean_base_record,
            sandbox_image=clean_base_record.result_image_uuid,
            workspace_path="/workspace/candidate",
        )
        executor = CandidateWorkspaceExecutor(
            adapter, source_materializer=MockSourceMaterializer(), config=config
        )
        proposal = _create_sample_proposal(
            actions=[
                ProposedFileAction(
                    path="src/foo.py",
                    action=FileActionType.CREATE,
                    content="def foo(): pass",
                )
            ]
        )

        res = executor.execute(proposal, envelope=envelope)
        assert res.sandbox_identity.sandbox_id == "sbx-candidate-bundled"
        assert adapter.created_handles[0].disposable is True
        assert adapter.created_handles[0].image == "img-clean-base-checkpoint-uuid"
        assert len(adapter.executed_commands) == 1
        assert res.bundled_snapshot is not None
        assert (
            res.bundled_snapshot.candidate_tree_digest == "1234567890abcdef1234567890abcdef12345678"
        )
        assert "src/foo.py" in res.bundled_snapshot.files_added
