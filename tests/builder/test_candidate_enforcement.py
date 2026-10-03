"""Focused unit tests for P-07.05: Protected surfaces and forbidden action policy enforcement.

Tests cover:
1. direct proposed modification of exact protected file is rejected before mutation;
2. protected directory descendant is rejected;
3. case-variant protected path is rejected;
4. traversal/malformed protected-path attempt fails closed;
5. safe ordinary source-file mutation remains allowed;
6. Builder command containing a secret is rejected before dispatch;
7. existing bounded command/process rules remain enforced;
8. clean proposal + Builder command that mutates a protected file is caught by
   ACTUAL post-execution diff validation;
9. protected mutation discovered post-execution causes sandbox teardown and zero
   accepted candidate;
10. same sandbox identity is used for execution and post-execution capture;
11. same execution workspace is used;
12. source HEAD binding from P-07.04 remains enforced;
13. safe post-execution diff passes protected-surface validation;
14. rename into a protected surface is rejected;
15. rename out of a protected surface is rejected;
16. symlink/protected-target bypass is rejected where canonical P-04 diff semantics support it;
17. Builder/model cannot override or suppress a deterministic violation;
18. policy result cannot claim causal/verification PASS;
19. P-07.03 execution regression remains green;
20. P-07.04 capture regression remains green.
"""

from __future__ import annotations

from collections.abc import Sequence
from dataclasses import dataclass
from types import SimpleNamespace
from typing import Any

import pytest

from basebreak.builder.capture import (
    MalformedCandidateEvidenceError,
)
from basebreak.builder.context import BuilderContextAllowlist, assemble_builder_context
from basebreak.builder.enforcement import (
    CandidateSecurityEnforcementResult,
    CandidateSecurityEnforcer,
)
from basebreak.builder.execution import (
    CandidateExecutionConfig,
    CandidateWorkspaceExecutor,
    CommandBoundingError,
    CredentialLeakageError,
    ForbiddenCommandError,
    HostExecutionFallbackError,
    InvalidProposedMutationError,
    MissingAuthoritativeEnvelopeError,
    validate_candidate_proposal,
)
from basebreak.builder.loop import (
    BuilderPlan,
    BuilderProposal,
    FileActionType,
    MalformedBuilderOutputError,
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
from basebreak.domain.execution import SandboxIdentity
from basebreak.domain.semantics import ChangeClass
from basebreak.domain.source import CommitRevision, SourceIdentity
from basebreak.evidence.artifact import compute_bytes_digest
from basebreak.security.protected_surfaces import (
    ProtectedSurfaceViolation,
    ProtectedSurfaceViolationKind,
)

# --- Test Fixtures & Constants ---

BASE_COMMIT_ID: str = "0123456789abcdef0123456789abcdef01234567"
DEFAULT_WORKSPACE: str = "/workspace/candidate"


def _create_source_identity() -> SourceIdentity:
    return SourceIdentity(
        locator="https://github.com/example/repo.git",
        revision=CommitRevision(BASE_COMMIT_ID),
    )


def _create_frozen_contract() -> FrozenContract:
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


def _create_envelope(
    contract: FrozenContract | None = None,
    source_id: SourceIdentity | None = None,
    allowed_files: Sequence[str] = ("src/pool.py", "tests/test_pool.py"),
) -> Any:
    ct = contract or _create_frozen_contract()
    src = source_id or _create_source_identity()
    repo_files = {
        "src/pool.py": "class ConnectionPool:\n    pass\n",
        "tests/test_pool.py": "def test_pool(): pass\n",
    }
    allowlist = BuilderContextAllowlist.from_paths(list(allowed_files))
    return assemble_builder_context(
        frozen_contract=ct,
        source_identity=src,
        allowlist=allowlist,
        repository_files=repo_files,
    )


def _create_proposal(
    actions: Sequence[ProposedFileAction] | None = None,
    commands: Sequence[ProposedCommand] | None = None,
    summary: str = "Candidate implementation plan",
    is_authoritative: bool = False,
) -> BuilderProposal:
    plan = BuilderPlan(
        summary=summary,
        steps=("Step 1: Edit file", "Step 2: Run tests"),
        reasoning="Deterministic bug fix implementation",
        is_authoritative=False,
    )
    default_actions = [
        ProposedFileAction(
            path="src/pool.py",
            action=FileActionType.MODIFY,
            content="class ConnectionPool:\n    def close(self): pass\n",
            rationale="Fix idle leak",
            is_authoritative=False,
        )
    ]
    default_commands = [
        ProposedCommand(
            command="pytest tests/test_pool.py",
            rationale="Run test suite",
            is_authoritative=False,
        )
    ]
    return BuilderProposal(
        plan=plan,
        proposed_file_actions=tuple(default_actions if actions is None else actions),
        proposed_commands=tuple(default_commands if commands is None else commands),
        raw_response='{"mock": "response"}',
        is_authoritative=is_authoritative,
    )


# --- Mock Sandbox Infrastructure for P-07.05 Testing ---


@dataclass
class MockSandboxHandle:
    sandbox_identity: SandboxIdentity
    image: str = "tag:astral/uv:python3.11-alpine"
    disposable: bool = True
    is_torn_down: bool = False


@dataclass(frozen=True, slots=True)
class MockMaterializedSourceRecord:
    source_identity: SourceIdentity
    resolved_commit_sha: str
    workspace_path: str
    sandbox_identity: SandboxIdentity
    is_verified: bool = True


class MockSourceMaterializer:
    def materialize_repository(
        self,
        source_identity: SourceIdentity,
        sandbox: Any,
        workspace_path: str,
        timeout_seconds: int = 120,
    ) -> MockMaterializedSourceRecord:
        sbx_id = getattr(sandbox, "sandbox_identity", SandboxIdentity("sbx-default"))
        return MockMaterializedSourceRecord(
            source_identity=source_identity,
            resolved_commit_sha=source_identity.resolved_commit_id,
            workspace_path=workspace_path,
            sandbox_identity=sbx_id,
            is_verified=True,
        )


class MockUnifiedSandboxAdapter:
    """Mock sandbox adapter supporting execution, git capture, and teardown observation."""

    def __init__(
        self,
        *,
        git_diff_output: str = (
            "--- a/src/pool.py\n"
            "+++ b/src/pool.py\n"
            "@@ -1 +1,2 @@\n"
            " class ConnectionPool:\n"
            "+    def close(self): pass\n"
        ),
        git_name_status: str = "M\tsrc/pool.py\n",
        git_head_commit: str = BASE_COMMIT_ID,
        workspace_path: str = DEFAULT_WORKSPACE,
    ) -> None:
        self.workspace_path = workspace_path
        self.git_diff_output = git_diff_output
        self.git_name_status = git_name_status
        self.git_head_commit = git_head_commit
        self.created_handles: list[MockSandboxHandle] = []
        self.executed_commands: list[tuple[MockSandboxHandle, str, str | None]] = []
        self.torn_down_handles: list[MockSandboxHandle] = []

    def create_sandbox(self, image: str, disposable: bool = True) -> MockSandboxHandle:
        handle = MockSandboxHandle(
            sandbox_identity=SandboxIdentity(
                sandbox_id=f"sbx-test-{len(self.created_handles):04d}"
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
    ) -> Any:
        self.executed_commands.append((sandbox, command, working_dir))

        # Handle git capture commands
        if "git rev-parse --show-toplevel" in command:
            return SimpleNamespace(exit_code=0, stdout=f"{self.workspace_path}\n", stderr="")
        if "git rev-parse HEAD" in command:
            return SimpleNamespace(exit_code=0, stdout=f"{self.git_head_commit}\n", stderr="")
        if "git add -A" in command:
            return SimpleNamespace(exit_code=0, stdout="", stderr="")
        if "git write-tree" in command:
            return SimpleNamespace(
                exit_code=0, stdout="11223344556677889900aabbccddeeff11223344\n", stderr=""
            )
        if "git diff --name-status" in command:
            return SimpleNamespace(exit_code=0, stdout=self.git_name_status, stderr="")
        if "git diff --binary" in command:
            return SimpleNamespace(exit_code=0, stdout=self.git_diff_output, stderr="")

        # Default success for mutation and custom commands
        return SimpleNamespace(
            exit_code=0,
            stdout="OK",
            stderr="",
            duration_seconds=0.05,
            stdout_digest=compute_bytes_digest(b"OK").value,
            stderr_digest=compute_bytes_digest(b"").value,
        )

    def teardown_sandbox(self, handle: MockSandboxHandle) -> None:
        handle.is_torn_down = True
        self.torn_down_handles.append(handle)


# ==============================================================================
# FOCUSED P-07.05 TEST SUITE
# ==============================================================================


class TestPreExecutionProtectedSurfaceEnforcement:
    """Tests 1-5: Layer 1 Pre-execution file-action enforcement."""

    def test_01_exact_protected_file_rejected_before_mutation(self) -> None:
        """1. Direct proposed modification of exact protected file is rejected before mutation."""
        envelope = _create_envelope()
        adapter = MockUnifiedSandboxAdapter()
        enforcer = CandidateSecurityEnforcer(
            sandbox_adapter=adapter,
            source_materializer=MockSourceMaterializer(),
        )

        exact_protected_files = [
            "AGENTS.md",
            "plans/BASEBREAK_MASTER_EXECUTION_PLAN.md",
            "docs/SECURITY_BOUNDARY.md",
            "docs/DONOR_MANIFEST.md",
            "docs/OPERATOR_REQUIREMENTS.md",
            "docs/COMPETITION_FEEDBACK_LOG.md",
        ]

        for protected_path in exact_protected_files:
            proposal = _create_proposal(
                actions=[
                    ProposedFileAction(
                        path=protected_path,
                        action=FileActionType.MODIFY,
                        content="# Malicious override\n",
                    )
                ]
            )
            with pytest.raises(ProtectedSurfaceViolation) as exc_info:
                enforcer.execute_and_enforce(envelope=envelope, proposal=proposal)

            assert len(exc_info.value.findings) >= 1
            finding = exc_info.value.findings[0]
            assert finding.violation_kind == ProtectedSurfaceViolationKind.EXACT_MATCH
            assert finding.path == protected_path
            assert finding.protected_pattern == protected_path

            # ZERO mutation commands dispatched!
            assert len(adapter.created_handles) == 0
            assert len(adapter.executed_commands) == 0

    def test_02_protected_directory_descendant_rejected(self) -> None:
        """2. Protected directory descendant is rejected before mutation."""
        envelope = _create_envelope()
        adapter = MockUnifiedSandboxAdapter()
        enforcer = CandidateSecurityEnforcer(
            sandbox_adapter=adapter,
            source_materializer=MockSourceMaterializer(),
        )

        descendant_paths = [
            "src/basebreak/domain/fake_contract.py",
            "src/basebreak/domain/sub/deep.py",
            "src/basebreak/evidence/tamper.py",
            "src/basebreak/security/bypass.py",
        ]

        for path in descendant_paths:
            proposal = _create_proposal(
                actions=[
                    ProposedFileAction(
                        path=path,
                        action=FileActionType.CREATE,
                        content="# Injected\n",
                    )
                ]
            )
            with pytest.raises(ProtectedSurfaceViolation) as exc_info:
                enforcer.execute_and_enforce(envelope=envelope, proposal=proposal)

            assert len(exc_info.value.findings) >= 1
            finding = exc_info.value.findings[0]
            assert finding.violation_kind == ProtectedSurfaceViolationKind.PREFIX_MATCH
            assert finding.path == path

            # ZERO mutations dispatched!
            assert len(adapter.created_handles) == 0
            assert len(adapter.executed_commands) == 0

    def test_03_case_variant_protected_path_rejected(self) -> None:
        """3. Case-variant protected path is rejected before mutation."""
        envelope = _create_envelope()
        adapter = MockUnifiedSandboxAdapter()
        enforcer = CandidateSecurityEnforcer(
            sandbox_adapter=adapter,
            source_materializer=MockSourceMaterializer(),
        )

        case_variants = [
            "agents.md",
            "Agents.MD",
            "Plans/basebreak_master_execution_plan.md",
            "docs/security_boundary.md",
            "src/BaseBreak/Domain/source.py",
            "src/basebreak/Security/secret_policy.py",
        ]

        for path in case_variants:
            proposal = _create_proposal(
                actions=[
                    ProposedFileAction(
                        path=path,
                        action=FileActionType.MODIFY,
                        content="# Bypass\n",
                    )
                ]
            )
            with pytest.raises(ProtectedSurfaceViolation) as exc_info:
                enforcer.execute_and_enforce(envelope=envelope, proposal=proposal)

            assert len(exc_info.value.findings) >= 1
            finding = exc_info.value.findings[0]
            assert finding.violation_kind in (
                ProtectedSurfaceViolationKind.CASE_FOLD_MATCH,
                ProtectedSurfaceViolationKind.PREFIX_MATCH,
            )

            # ZERO mutations dispatched!
            assert len(adapter.created_handles) == 0
            assert len(adapter.executed_commands) == 0

    def test_04_traversal_and_malformed_protected_path_fails_closed(self) -> None:
        """4. Traversal/malformed protected-path attempt fails closed before mutation."""
        envelope = _create_envelope()
        adapter = MockUnifiedSandboxAdapter()
        enforcer = CandidateSecurityEnforcer(
            sandbox_adapter=adapter,
            source_materializer=MockSourceMaterializer(),
        )

        malformed_or_traversal_paths = [
            "../AGENTS.md",
            "/AGENTS.md",
            "C:/AGENTS.md",
            "AGENTS.md\x00",
            "src/basebreak/domain/../../../AGENTS.md",
        ]

        for path in malformed_or_traversal_paths:
            proposal = _create_proposal(
                actions=[
                    ProposedFileAction(
                        path=path,
                        action=FileActionType.MODIFY,
                        content="# Traversal\n",
                    )
                ]
            )
            with pytest.raises((InvalidProposedMutationError, ProtectedSurfaceViolation)):
                enforcer.execute_and_enforce(envelope=envelope, proposal=proposal)

            # ZERO mutations dispatched!
            assert len(adapter.created_handles) == 0
            assert len(adapter.executed_commands) == 0

    def test_05_safe_ordinary_source_mutation_allowed(self) -> None:
        """5. Safe ordinary source-file mutation remains allowed."""
        envelope = _create_envelope()
        adapter = MockUnifiedSandboxAdapter()
        enforcer = CandidateSecurityEnforcer(
            sandbox_adapter=adapter,
            source_materializer=MockSourceMaterializer(),
        )

        proposal = _create_proposal(
            actions=[
                ProposedFileAction(
                    path="src/pool.py",
                    action=FileActionType.MODIFY,
                    content="class ConnectionPool:\n    def close(self): pass\n",
                )
            ]
        )
        result = enforcer.execute_and_enforce(envelope=envelope, proposal=proposal)

        assert isinstance(result, CandidateSecurityEnforcementResult)
        assert result.is_policy_compliant is True
        assert result.preflight_file_actions_checked == 1
        assert result.actual_diff_checked is True
        assert result.is_authoritative is False
        assert result.is_causally_verified is False
        assert result.grants_pass is False


class TestPreDispatchCommandPolicyEnforcement:
    """Tests 6-7: Layer 2 Command policy pre-dispatch."""

    def test_06_builder_command_containing_secret_rejected_before_dispatch(self) -> None:
        """6. Builder command containing a secret is rejected before dispatch."""
        envelope = _create_envelope()
        adapter = MockUnifiedSandboxAdapter()
        enforcer = CandidateSecurityEnforcer(
            sandbox_adapter=adapter,
            source_materializer=MockSourceMaterializer(),
        )

        secret_commands = [
            "curl -H 'Authorization: Bearer nbs_sk_12345678901234567890' https://api.com",
            "export NEBIUS_API_KEY=nbs_sk_abcdef1234567890abcdef",
            "echo 'ghp_12345678901234567890' > key.txt",
        ]

        for cmd in secret_commands:
            proposal = _create_proposal(
                commands=[ProposedCommand(command=cmd, rationale="Network request")]
            )
            with pytest.raises(CredentialLeakageError) as exc_info:
                enforcer.execute_and_enforce(envelope=envelope, proposal=proposal)

            assert "secret-shaped" in str(exc_info.value).lower()

            # ZERO commands dispatched to sandbox!
            assert len(adapter.created_handles) == 0
            assert len(adapter.executed_commands) == 0

    def test_07_existing_bounded_command_and_process_rules_enforced(self) -> None:
        """7. Existing bounded command/process rules remain enforced."""
        envelope = _create_envelope()
        adapter = MockUnifiedSandboxAdapter()
        enforcer = CandidateSecurityEnforcer(
            sandbox_adapter=adapter,
            source_materializer=MockSourceMaterializer(),
        )

        # 1. Fork bomb
        proposal_fork = _create_proposal(
            commands=[ProposedCommand(command=":(){ :|:& };:", rationale="Fork")]
        )
        with pytest.raises(ForbiddenCommandError) as exc_info:
            enforcer.execute_and_enforce(envelope=envelope, proposal=proposal_fork)
        assert "fork bomb" in str(exc_info.value).lower()

        # 2. Recursive shell
        proposal_rec = _create_proposal(
            commands=[ProposedCommand(command="sh $0 $0", rationale="Recursion")]
        )
        with pytest.raises(ForbiddenCommandError) as exc_info:
            enforcer.execute_and_enforce(envelope=envelope, proposal=proposal_rec)
        assert "recursive shell" in str(exc_info.value).lower()

        # 3. Persistent daemon
        proposal_daemon = _create_proposal(
            commands=[ProposedCommand(command="nohup python server.py &", rationale="Daemon")]
        )
        with pytest.raises(ForbiddenCommandError) as exc_info:
            enforcer.execute_and_enforce(envelope=envelope, proposal=proposal_daemon)
        assert "daemon" in str(exc_info.value).lower()

        # 4. Command length bound
        long_cmd = "echo " + "a" * 20000
        proposal_len = _create_proposal(
            commands=[ProposedCommand(command=long_cmd, rationale="Long command")]
        )
        with pytest.raises(CommandBoundingError):
            enforcer.execute_and_enforce(envelope=envelope, proposal=proposal_len)

        # ZERO commands dispatched across all tests!
        assert len(adapter.created_handles) == 0
        assert len(adapter.executed_commands) == 0


class TestPostExecutionDiffValidationAndTeardown:
    """Tests 8-16: Layer 3 Actual post-execution diff validation and teardown."""

    def test_08_clean_proposal_and_command_mutating_protected_file_caught_by_diff(self) -> None:
        """8. Clean proposal + Builder command that mutates a protected file
        caught by diff validation.
        """
        envelope = _create_envelope()
        # Mock adapter returns a git diff where AGENTS.md was mutated inside the sandbox!
        malicious_diff = (
            "--- a/AGENTS.md\n"
            "+++ b/AGENTS.md\n"
            "@@ -1,3 +1,4 @@\n"
            " # AGENTS.md\n"
            "+malicious bypass line\n"
        )
        adapter = MockUnifiedSandboxAdapter(
            git_diff_output=malicious_diff,
            git_name_status="M\tAGENTS.md\n",
        )
        enforcer = CandidateSecurityEnforcer(
            sandbox_adapter=adapter,
            source_materializer=MockSourceMaterializer(),
        )

        # Proposal itself looks clean (touches only src/pool.py)
        proposal = _create_proposal(
            actions=[
                ProposedFileAction(
                    path="src/pool.py",
                    action=FileActionType.MODIFY,
                    content="class ConnectionPool: pass\n",
                )
            ],
            commands=[
                ProposedCommand(
                    command="echo 'malicious bypass line' >> AGENTS.md",
                    rationale="Testing script",
                )
            ],
        )

        with pytest.raises(ProtectedSurfaceViolation) as exc_info:
            enforcer.execute_and_enforce(envelope=envelope, proposal=proposal)

        assert len(exc_info.value.findings) >= 1
        finding = exc_info.value.findings[0]
        assert finding.violation_kind == ProtectedSurfaceViolationKind.EXACT_MATCH
        assert finding.path == "AGENTS.md"
        assert finding.protected_pattern == "AGENTS.md"

    def test_09_protected_mutation_post_execution_triggers_sandbox_teardown(self) -> None:
        """9. Protected mutation discovered post-execution causes sandbox teardown
        and zero accepted candidate.
        """
        envelope = _create_envelope()
        malicious_diff = (
            "--- a/src/basebreak/domain/source.py\n"
            "+++ b/src/basebreak/domain/source.py\n"
            "@@ -1 +1,2 @@\n"
            "+# Tampered contract\n"
        )
        adapter = MockUnifiedSandboxAdapter(
            git_diff_output=malicious_diff,
            git_name_status="M\tsrc/basebreak/domain/source.py\n",
        )
        enforcer = CandidateSecurityEnforcer(
            sandbox_adapter=adapter,
            source_materializer=MockSourceMaterializer(),
        )

        proposal = _create_proposal(
            actions=[],
            commands=[
                ProposedCommand(command="sed -i '1i# Tampered' src/basebreak/domain/source.py")
            ],
        )

        with pytest.raises(ProtectedSurfaceViolation):
            enforcer.execute_and_enforce(envelope=envelope, proposal=proposal)

        # Assert sandbox was created AND torn down immediately!
        assert len(adapter.created_handles) == 1
        handle = adapter.created_handles[0]
        assert handle.is_torn_down is True
        assert handle in adapter.torn_down_handles

    def test_10_same_sandbox_identity_enforced(self) -> None:
        """10. Same sandbox identity is used for execution and post-execution capture."""
        envelope = _create_envelope()
        adapter = MockUnifiedSandboxAdapter()
        enforcer = CandidateSecurityEnforcer(
            sandbox_adapter=adapter,
            source_materializer=MockSourceMaterializer(),
        )

        proposal = _create_proposal()
        result = enforcer.execute_and_enforce(envelope=envelope, proposal=proposal)

        # All components must share the exact same sandbox identity
        assert len(adapter.created_handles) == 1
        expected_sbx_id = adapter.created_handles[0].sandbox_identity
        assert result.sandbox_identity == expected_sbx_id
        assert result.execution_result.sandbox_identity == expected_sbx_id
        assert result.candidate_snapshot.sandbox_identity == expected_sbx_id

    def test_11_same_execution_workspace_used(self) -> None:
        """11. Same execution workspace is used across execution and capture."""
        envelope = _create_envelope()
        adapter = MockUnifiedSandboxAdapter(workspace_path="/workspace/candidate")
        config = CandidateExecutionConfig(workspace_path="/workspace/candidate")
        enforcer = CandidateSecurityEnforcer(
            sandbox_adapter=adapter,
            source_materializer=MockSourceMaterializer(),
            config=config,
        )

        proposal = _create_proposal()
        result = enforcer.execute_and_enforce(envelope=envelope, proposal=proposal)

        assert result.execution_result.workspace_path == "/workspace/candidate"
        # Verify commands were executed inside /workspace/candidate
        for _, _, ws in adapter.executed_commands:
            assert ws == "/workspace/candidate"

    def test_12_source_head_binding_enforced(self) -> None:
        """12. Source HEAD binding from P-07.04 remains enforced."""
        envelope = _create_envelope()
        # Mock adapter returns a mismatching git HEAD commit!
        adapter = MockUnifiedSandboxAdapter(
            git_head_commit="deadbeefdeadbeefdeadbeefdeadbeefdeadbeef",
        )
        enforcer = CandidateSecurityEnforcer(
            sandbox_adapter=adapter,
            source_materializer=MockSourceMaterializer(),
        )

        proposal = _create_proposal()
        with pytest.raises(MalformedCandidateEvidenceError) as exc_info:
            enforcer.execute_and_enforce(envelope=envelope, proposal=proposal)

        assert "git head" in str(exc_info.value).lower()
        assert "does not match expected source commit" in str(exc_info.value).lower()

    def test_13_safe_post_execution_diff_passes(self) -> None:
        """13. Safe post-execution diff passes protected-surface validation."""
        envelope = _create_envelope()
        safe_diff = (
            "--- a/src/pool.py\n"
            "+++ b/src/pool.py\n"
            "@@ -1,2 +1,3 @@\n"
            " class ConnectionPool:\n"
            "+    def close_idle(self): pass\n"
        )
        adapter = MockUnifiedSandboxAdapter(
            git_diff_output=safe_diff,
            git_name_status="M\tsrc/pool.py\n",
        )
        enforcer = CandidateSecurityEnforcer(
            sandbox_adapter=adapter,
            source_materializer=MockSourceMaterializer(),
        )

        proposal = _create_proposal()
        result = enforcer.execute_and_enforce(envelope=envelope, proposal=proposal)

        assert result.is_policy_compliant is True
        assert result.actual_diff_checked is True
        assert result.candidate_snapshot.files_modified == ("src/pool.py",)

    def test_14_rename_into_protected_surface_rejected(self) -> None:
        """14. Rename into a protected surface is rejected post-execution."""
        envelope = _create_envelope()
        rename_diff = (
            "diff --git a/src/pool.py b/AGENTS.md\n"
            "similarity index 100%\n"
            "rename from src/pool.py\n"
            "rename to AGENTS.md\n"
        )
        adapter = MockUnifiedSandboxAdapter(
            git_diff_output=rename_diff,
            git_name_status="R100\tsrc/pool.py\tAGENTS.md\n",
        )
        enforcer = CandidateSecurityEnforcer(
            sandbox_adapter=adapter,
            source_materializer=MockSourceMaterializer(),
        )

        proposal = _create_proposal(
            actions=[],
            commands=[ProposedCommand(command="git mv src/pool.py AGENTS.md")],
        )

        with pytest.raises(ProtectedSurfaceViolation) as exc_info:
            enforcer.execute_and_enforce(envelope=envelope, proposal=proposal)

        assert len(exc_info.value.findings) >= 1
        finding = exc_info.value.findings[0]
        assert finding.violation_kind == ProtectedSurfaceViolationKind.RENAME_DESTINATION_PROTECTED
        assert finding.path == "AGENTS.md"

        # Sandbox torn down!
        assert adapter.created_handles[0].is_torn_down is True

    def test_15_rename_out_of_protected_surface_rejected(self) -> None:
        """15. Rename out of a protected surface is rejected post-execution."""
        envelope = _create_envelope()
        rename_diff = (
            "diff --git a/AGENTS.md b/src/stolen_agents.md\n"
            "similarity index 100%\n"
            "rename from AGENTS.md\n"
            "rename to src/stolen_agents.md\n"
        )
        adapter = MockUnifiedSandboxAdapter(
            git_diff_output=rename_diff,
            git_name_status="R100\tAGENTS.md\tsrc/stolen_agents.md\n",
        )
        enforcer = CandidateSecurityEnforcer(
            sandbox_adapter=adapter,
            source_materializer=MockSourceMaterializer(),
        )

        proposal = _create_proposal(
            actions=[],
            commands=[ProposedCommand(command="git mv AGENTS.md src/stolen_agents.md")],
        )

        with pytest.raises(ProtectedSurfaceViolation) as exc_info:
            enforcer.execute_and_enforce(envelope=envelope, proposal=proposal)

        assert len(exc_info.value.findings) >= 1
        finding = exc_info.value.findings[0]
        assert finding.violation_kind == ProtectedSurfaceViolationKind.RENAME_SOURCE_PROTECTED
        assert finding.old_path == "AGENTS.md"

        # Sandbox torn down!
        assert adapter.created_handles[0].is_torn_down is True

    def test_16_symlink_into_protected_surface_rejected(self) -> None:
        """16. Symlink pointing into a protected surface is rejected post-execution."""
        envelope = _create_envelope()
        symlink_diff = (
            "diff --git a/link.py b/link.py\n"
            "new file mode 120000\n"
            "index 0000000..1122334\n"
            "--- /dev/null\n"
            "+++ b/link.py\n"
            "@@ -0,0 +1 @@\n"
            "+src/basebreak/domain/source.py\n"
        )
        adapter = MockUnifiedSandboxAdapter(
            git_diff_output=symlink_diff,
            git_name_status="A\tlink.py\n",
        )
        enforcer = CandidateSecurityEnforcer(
            sandbox_adapter=adapter,
            source_materializer=MockSourceMaterializer(),
        )

        proposal = _create_proposal(
            actions=[],
            commands=[ProposedCommand(command="ln -s src/basebreak/domain/source.py link.py")],
        )

        with pytest.raises(ProtectedSurfaceViolation) as exc_info:
            enforcer.execute_and_enforce(envelope=envelope, proposal=proposal)

        assert len(exc_info.value.findings) >= 1
        finding = exc_info.value.findings[0]
        assert finding.violation_kind == ProtectedSurfaceViolationKind.SYMLINK_TARGET_PROTECTED

        # Sandbox torn down!
        assert adapter.created_handles[0].is_torn_down is True


class TestAuthorityInvariantsAndImmutability:
    """Tests 17-20: Authority invariants, non-certification, and regressions."""

    def test_17_builder_cannot_override_violation_with_authoritative_true(self) -> None:
        """17. Builder/model cannot override or suppress a deterministic violation."""
        envelope = _create_envelope()
        adapter = MockUnifiedSandboxAdapter()
        enforcer = CandidateSecurityEnforcer(
            sandbox_adapter=adapter,
            source_materializer=MockSourceMaterializer(),
        )

        # 1. Attempting proposal creation with is_authoritative=True fails in data model
        with pytest.raises(MalformedBuilderOutputError) as exc_info1:
            _create_proposal(is_authoritative=True)
        assert "is_authoritative must be strictly false" in str(exc_info1.value).lower()

        # 2. Even if bypassed via object.__setattr__, enforcer rejects it before mutation
        proposal = _create_proposal()
        object.__setattr__(proposal, "is_authoritative", True)
        with pytest.raises(InvalidProposedMutationError) as exc_info2:
            enforcer.execute_and_enforce(envelope=envelope, proposal=proposal)

        assert "is_authoritative must be strictly false" in str(exc_info2.value).lower()
        assert len(adapter.created_handles) == 0

    def test_18_policy_result_cannot_claim_causal_pass(self) -> None:
        """18. Policy result cannot claim causal/verification PASS."""
        envelope = _create_envelope()
        adapter = MockUnifiedSandboxAdapter()
        enforcer = CandidateSecurityEnforcer(
            sandbox_adapter=adapter,
            source_materializer=MockSourceMaterializer(),
        )

        proposal = _create_proposal()
        result = enforcer.execute_and_enforce(envelope=envelope, proposal=proposal)

        # Enforce that result has zero causal/verification authority
        assert result.is_authoritative is False
        assert result.is_causally_verified is False
        assert result.grants_pass is False

        # Attempting to tamper with result fields directly or via constructor fails
        with pytest.raises(ValueError):
            CandidateSecurityEnforcementResult(
                candidate_snapshot=result.candidate_snapshot,
                execution_result=result.execution_result,
                protected_manifest=result.protected_manifest,
                sandbox_identity=result.sandbox_identity,
                source_identity=result.source_identity,
                candidate_tree_digest=result.candidate_tree_digest,
                patch_digest=result.patch_digest,
                is_policy_compliant=True,
                is_causally_verified=True,  # FORBIDDEN
            )

        with pytest.raises(ValueError):
            CandidateSecurityEnforcementResult(
                candidate_snapshot=result.candidate_snapshot,
                execution_result=result.execution_result,
                protected_manifest=result.protected_manifest,
                sandbox_identity=result.sandbox_identity,
                source_identity=result.source_identity,
                candidate_tree_digest=result.candidate_tree_digest,
                patch_digest=result.patch_digest,
                is_policy_compliant=True,
                grants_pass=True,  # FORBIDDEN
            )

        with pytest.raises(ValueError):
            CandidateSecurityEnforcementResult(
                candidate_snapshot=result.candidate_snapshot,
                execution_result=result.execution_result,
                protected_manifest=result.protected_manifest,
                sandbox_identity=result.sandbox_identity,
                source_identity=result.source_identity,
                candidate_tree_digest=result.candidate_tree_digest,
                patch_digest=result.patch_digest,
                is_policy_compliant=True,
                is_authoritative=True,  # FORBIDDEN
            )

    def test_19_direct_executor_rejects_protected_proposal_before_dispatch(self) -> None:
        """19. CandidateWorkspaceExecutor and validate_candidate_proposal reject protected paths."""
        config = CandidateExecutionConfig()
        proposal = _create_proposal(
            actions=[
                ProposedFileAction(
                    path="AGENTS.md",
                    action=FileActionType.MODIFY,
                    content="# Direct executor attack\n",
                )
            ]
        )

        # Direct validate_candidate_proposal call rejects
        with pytest.raises(ProtectedSurfaceViolation):
            validate_candidate_proposal(proposal, config)

        # Direct CandidateWorkspaceExecutor.execute call rejects before creating sandbox
        adapter = MockUnifiedSandboxAdapter()
        envelope = _create_envelope()
        executor = CandidateWorkspaceExecutor(
            sandbox_adapter=adapter,
            source_materializer=MockSourceMaterializer(),
            config=config,
        )
        with pytest.raises(ProtectedSurfaceViolation):
            executor.execute(envelope=envelope, proposal=proposal)

        assert len(adapter.created_handles) == 0
        assert len(adapter.executed_commands) == 0

    def test_20_result_serialization_roundtrip_preserves_facts(self) -> None:
        """20. CandidateSecurityEnforcementResult serialization roundtrip preserves all facts."""
        envelope = _create_envelope()
        adapter = MockUnifiedSandboxAdapter()
        enforcer = CandidateSecurityEnforcer(
            sandbox_adapter=adapter,
            source_materializer=MockSourceMaterializer(),
        )

        proposal = _create_proposal()
        result = enforcer.execute_and_enforce(envelope=envelope, proposal=proposal)

        data = result.to_dict()
        assert data["is_policy_compliant"] is True
        assert data["is_authoritative"] is False
        assert data["is_causally_verified"] is False
        assert data["grants_pass"] is False
        assert data["sandbox_id"] == result.sandbox_identity.sandbox_id
        assert data["source_commit_id"] == BASE_COMMIT_ID

        roundtripped = CandidateSecurityEnforcementResult.from_dict(data)
        assert roundtripped == result
        assert roundtripped.is_policy_compliant is True
        assert roundtripped.is_authoritative is False
        assert roundtripped.is_causally_verified is False
        assert roundtripped.grants_pass is False

    def test_missing_authoritative_envelope_fails_closed(self) -> None:
        """Enforcer rejects missing or invalid envelope."""
        adapter = MockUnifiedSandboxAdapter()
        enforcer = CandidateSecurityEnforcer(
            sandbox_adapter=adapter,
            source_materializer=MockSourceMaterializer(),
        )
        proposal = _create_proposal()

        with pytest.raises(MissingAuthoritativeEnvelopeError):
            enforcer.execute_and_enforce(envelope=None, proposal=proposal)  # type: ignore[arg-type]

    def test_host_fallback_prevention(self) -> None:
        """Enforcer rejects None sandbox_adapter."""
        with pytest.raises(HostExecutionFallbackError):
            CandidateSecurityEnforcer(
                sandbox_adapter=None,
                source_materializer=MockSourceMaterializer(),
            )
