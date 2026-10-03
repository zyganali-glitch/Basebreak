"""Focused unit tests for P-07.04 candidate diff/tree hash and builder-authored test capture.

Tests cover:
- no-change candidate (empty diff, base tree digest, is_no_change=True)
- single modification
- create (file added)
- delete (file removed)
- multiple changes with deterministic ordering
- same candidate state -> same digest (reproducibility)
- changed content -> changed digest
- changed base identity -> distinct binding
- Builder-authored test identification (from mutations and command execution)
- Builder-authored test law: passing test (exit_code=0) possesses zero authority
  (grants_pass=False, is_authoritative=False)
- generic pytest with zero Builder-modified test files does NOT create BuilderAuthoredTest
- candidate tree/diff identity survives serialization/roundtrip
- patch_text tamper rejection
- patch_digest tamper rejection
- proposal cannot substitute for actual post-execution candidate state
- changed-file lists reject duplicate/noncanonical/overlapping/unsorted paths
- malformed candidate evidence fails closed
- binary/unrepresentable changes fail cleanly (BinaryDiffUnsupportedError)
- null bytes in file content fail cleanly
- sandbox identity, workspace, and HEAD commit binding during sandbox capture
- sandbox capture via mock adapter (git write-tree, status, diff parsing)
- binary diff handling in sandbox capture (reproducible binary patch vs unrepresentable fail-close)
- provider purity: zero adapter or provider imports in basebreak.builder.capture
"""

from __future__ import annotations

import inspect
from dataclasses import dataclass
from types import SimpleNamespace
from typing import Any

import pytest

from basebreak.builder.capture import (
    BinaryDiffUnsupportedError,
    BuilderAuthoredTest,
    CandidateCaptureError,
    CandidateSnapshot,
    MalformedCandidateEvidenceError,
    capture_candidate_from_execution,
    capture_candidate_from_files,
    capture_candidate_from_sandbox,
    compute_tree_digest,
    generate_unified_diff,
    identify_builder_authored_tests,
)
from basebreak.builder.execution import (
    DEFAULT_WORKSPACE_PATH,
    CandidateExecutionResult,
    CommandExecutionRecord,
    FileMutationRecord,
)
from basebreak.builder.loop import (
    BuilderPlan,
    BuilderProposal,
    FileActionType,
    ProposedFileAction,
)
from basebreak.domain.execution import SandboxIdentity, TerminationStatus
from basebreak.domain.source import CommitRevision, SourceIdentity
from basebreak.domain.verdict import EvidenceProvenance
from basebreak.evidence.artifact import compute_bytes_digest

# --- Fixtures ---

BASE_COMMIT_ID = "0123456789abcdef0123456789abcdef01234567"
ALT_COMMIT_ID = "fedcba9876543210fedcba9876543210fedcba98"
FROZEN_CONTRACT_DIGEST = "a" * 64
ALT_FROZEN_CONTRACT_DIGEST = "b" * 64
CONTEXT_DIGEST = "c" * 64
EMPTY_PATCH_DIGEST = compute_bytes_digest(b"").value


def make_source_identity(commit_id: str = BASE_COMMIT_ID) -> SourceIdentity:
    return SourceIdentity(
        locator="https://github.com/example/repo.git",
        revision=CommitRevision(commit_id),
    )


def make_sandbox_id(sid: str = "sbx-test-12345") -> SandboxIdentity:
    return SandboxIdentity(sandbox_id=sid)


@dataclass
class MockSandboxHandle:
    sandbox_identity: SandboxIdentity | None


class MockSandboxAdapter:
    def __init__(self, stdout: str, exit_code: int = 0) -> None:
        self.stdout = stdout
        self.exit_code = exit_code
        self.recorded_commands: list[str] = []

    def execute_command(
        self,
        handle: Any,
        command: str,
        working_dir: str | None = None,
        timeout_seconds: int = 60,
    ) -> Any:
        self.recorded_commands.append(command)
        return SimpleNamespace(
            exit_code=self.exit_code,
            stdout=self.stdout,
            stderr="",
        )


def make_sandbox_stdout(
    *,
    workspace: str = DEFAULT_WORKSPACE_PATH,
    head_commit: str = BASE_COMMIT_ID,
    tree_sha: str = "0123456789abcdef0123456789abcdef01234567",
    status_lines: str = " M src/app.py\n?? tests/test_app.py\n D src/legacy.py",
    diff_text: str = "--- a/src/app.py\n+++ b/src/app.py\n@@ -1 +1 @@\n-old\n+new\n",
) -> str:
    return (
        f"BASEBREAK_REPO_TOPLEVEL={workspace}\n"
        f"BASEBREAK_HEAD={head_commit}\n"
        f"BASEBREAK_TREE={tree_sha}\n"
        "BASEBREAK_STATUS_START\n"
        f"{status_lines}\n"
        "BASEBREAK_STATUS_END\n"
        "BASEBREAK_DIFF_START\n"
        f"{diff_text}"
        "BASEBREAK_DIFF_END\n"
    )


# --- Diff & Tree Digest Tests ---


def test_no_change_diff_and_snapshot() -> None:
    base_files = {
        "src/main.py": "print('hello')\n",
        "README.md": "# Readme\n",
    }
    src_id = make_source_identity()
    snap = capture_candidate_from_files(
        base_files=base_files,
        candidate_files=base_files,
        source_identity=src_id,
        frozen_contract_digest=FROZEN_CONTRACT_DIGEST,
        context_digest=CONTEXT_DIGEST,
    )
    assert snap.is_no_change is True
    assert snap.total_changed_files_count == 0
    assert snap.files_added == ()
    assert snap.files_modified == ()
    assert snap.files_deleted == ()
    assert snap.patch_text == ""
    assert len(snap.patch_digest) == 64
    assert snap.patch_digest == EMPTY_PATCH_DIGEST
    assert len(snap.candidate_tree_digest) == 64
    assert snap.is_authoritative is False


def test_single_modification() -> None:
    base_files = {"src/app.py": "def run():\n    return 1\n"}
    cand_files = {"src/app.py": "def run():\n    return 2\n"}
    src_id = make_source_identity()

    snap = capture_candidate_from_files(
        base_files=base_files,
        candidate_files=cand_files,
        source_identity=src_id,
        frozen_contract_digest=FROZEN_CONTRACT_DIGEST,
        context_digest=CONTEXT_DIGEST,
    )
    assert snap.is_no_change is False
    assert snap.total_changed_files_count == 1
    assert snap.files_modified == ("src/app.py",)
    assert snap.files_added == ()
    assert snap.files_deleted == ()
    assert "--- a/src/app.py" in snap.patch_text
    assert "+++ b/src/app.py" in snap.patch_text
    assert "-    return 1" in snap.patch_text
    assert "+    return 2" in snap.patch_text


def test_create_file() -> None:
    base_files = {"README.md": "# Readme\n"}
    cand_files = {
        "README.md": "# Readme\n",
        "src/new_module.py": "print('new')\n",
    }
    src_id = make_source_identity()

    snap = capture_candidate_from_files(
        base_files=base_files,
        candidate_files=cand_files,
        source_identity=src_id,
        frozen_contract_digest=FROZEN_CONTRACT_DIGEST,
        context_digest=CONTEXT_DIGEST,
    )
    assert snap.files_added == ("src/new_module.py",)
    assert snap.files_modified == ()
    assert snap.files_deleted == ()
    assert "--- /dev/null" in snap.patch_text
    assert "+++ b/src/new_module.py" in snap.patch_text


def test_delete_file() -> None:
    base_files = {
        "src/app.py": "print('app')\n",
        "src/deprecated.py": "print('old')\n",
    }
    cand_files = {"src/app.py": "print('app')\n"}
    src_id = make_source_identity()

    snap = capture_candidate_from_files(
        base_files=base_files,
        candidate_files=cand_files,
        source_identity=src_id,
        frozen_contract_digest=FROZEN_CONTRACT_DIGEST,
        context_digest=CONTEXT_DIGEST,
    )
    assert snap.files_deleted == ("src/deprecated.py",)
    assert snap.files_added == ()
    assert snap.files_modified == ()
    assert "--- a/src/deprecated.py" in snap.patch_text
    assert "+++ /dev/null" in snap.patch_text


def test_multiple_changes_deterministic_ordering() -> None:
    base_files = {
        "z_file.py": "z = 1\n",
        "a_file.py": "a = 1\n",
        "m_file.py": "m = 1\n",
    }
    cand_files = {
        "z_file.py": "z = 1\n",
        "a_file.py": "a = 2\n",
        "y_file.py": "y = 1\n",
        "b_file.py": "b = 1\n",
    }
    src_id = make_source_identity()

    snap1 = capture_candidate_from_files(
        base_files=base_files,
        candidate_files=cand_files,
        source_identity=src_id,
        frozen_contract_digest=FROZEN_CONTRACT_DIGEST,
        context_digest=CONTEXT_DIGEST,
    )
    assert snap1.files_added == ("b_file.py", "y_file.py")
    assert snap1.files_modified == ("a_file.py",)
    assert snap1.files_deleted == ("m_file.py",)

    pos_a = snap1.patch_text.find("a_file.py")
    pos_b = snap1.patch_text.find("b_file.py")
    pos_m = snap1.patch_text.find("m_file.py")
    pos_y = snap1.patch_text.find("y_file.py")
    assert pos_a < pos_b < pos_m < pos_y


def test_same_candidate_state_produces_identical_digest() -> None:
    files_a = {
        "src/util.py": "def f(): pass\n",
        "tests/test_util.py": "def test(): pass\n",
    }
    files_b = {
        "tests/test_util.py": "def test(): pass\n",
        "src/util.py": "def f(): pass\n",
    }
    assert compute_tree_digest(files_a) == compute_tree_digest(files_b)


def test_changed_content_produces_distinct_digest() -> None:
    files_1 = {"src/app.py": "VERSION = 1\n"}
    files_2 = {"src/app.py": "VERSION = 2\n"}
    assert compute_tree_digest(files_1) != compute_tree_digest(files_2)


def test_changed_base_identity_produces_distinct_binding() -> None:
    base_files = {"src/app.py": "x = 1\n"}
    cand_files = {"src/app.py": "x = 2\n"}

    snap1 = capture_candidate_from_files(
        base_files=base_files,
        candidate_files=cand_files,
        source_identity=make_source_identity(BASE_COMMIT_ID),
        frozen_contract_digest=FROZEN_CONTRACT_DIGEST,
        context_digest=CONTEXT_DIGEST,
    )
    snap2 = capture_candidate_from_files(
        base_files=base_files,
        candidate_files=cand_files,
        source_identity=make_source_identity(ALT_COMMIT_ID),
        frozen_contract_digest=FROZEN_CONTRACT_DIGEST,
        context_digest=CONTEXT_DIGEST,
    )
    assert snap1.source_identity != snap2.source_identity
    assert snap1.source_identity.resolved_commit_id != snap2.source_identity.resolved_commit_id


# --- Builder-Authored Test Law Tests ---


def test_builder_authored_test_law_invariants() -> None:
    bat = BuilderAuthoredTest(
        path="tests/test_builder.py",
        command="pytest tests/test_builder.py",
        exit_code=0,
        stdout_digest="d" * 64,
        stderr_digest="e" * 64,
        duration_seconds=0.5,
        status=TerminationStatus.COMPLETED,
    )
    assert bat.is_builder_authored is True
    assert bat.is_authoritative is False
    assert bat.grants_pass is False

    with pytest.raises(ValueError, match="is_authoritative must be strictly False"):
        BuilderAuthoredTest(
            path="tests/test_builder.py",
            command="pytest tests/test_builder.py",
            exit_code=0,
            stdout_digest="d" * 64,
            stderr_digest="e" * 64,
            duration_seconds=0.5,
            status=TerminationStatus.COMPLETED,
            is_authoritative=True,
        )

    with pytest.raises(ValueError, match="grants_pass must be strictly False"):
        BuilderAuthoredTest(
            path="tests/test_builder.py",
            command="pytest tests/test_builder.py",
            exit_code=0,
            stdout_digest="d" * 64,
            stderr_digest="e" * 64,
            duration_seconds=0.5,
            status=TerminationStatus.COMPLETED,
            grants_pass=True,
        )

    with pytest.raises(ValueError, match="is_builder_authored must be strictly True"):
        BuilderAuthoredTest(
            path="tests/test_builder.py",
            command="pytest tests/test_builder.py",
            exit_code=0,
            stdout_digest="d" * 64,
            stderr_digest="e" * 64,
            duration_seconds=0.5,
            status=TerminationStatus.COMPLETED,
            is_builder_authored=False,
        )


def test_identify_builder_authored_tests() -> None:
    sbx_id = make_sandbox_id()
    src_id = make_source_identity()

    muts = (
        FileMutationRecord(
            path="tests/test_patch.py",
            action=FileActionType.CREATE,
            exit_code=0,
            stdout_digest="0" * 64,
            stderr_digest="0" * 64,
            duration_seconds=0.1,
            content_digest="1" * 64,
            is_success=True,
            sandbox_identity=sbx_id,
        ),
        FileMutationRecord(
            path="src/logic.py",
            action=FileActionType.MODIFY,
            exit_code=0,
            stdout_digest="0" * 64,
            stderr_digest="0" * 64,
            duration_seconds=0.1,
            content_digest="2" * 64,
            is_success=True,
            sandbox_identity=sbx_id,
        ),
    )
    cmds = (
        CommandExecutionRecord(
            command="pytest tests/test_patch.py",
            exit_code=0,
            stdout_digest="3" * 64,
            stderr_digest="4" * 64,
            duration_seconds=0.8,
            status=TerminationStatus.COMPLETED,
            sandbox_identity=sbx_id,
        ),
        CommandExecutionRecord(
            command="python -m flake8 src/",
            exit_code=0,
            stdout_digest="5" * 64,
            stderr_digest="6" * 64,
            duration_seconds=0.3,
            status=TerminationStatus.COMPLETED,
            sandbox_identity=sbx_id,
        ),
    )
    exec_res = CandidateExecutionResult(
        source_identity=src_id,
        frozen_contract_digest=FROZEN_CONTRACT_DIGEST,
        context_digest=CONTEXT_DIGEST,
        proposal_digest="7" * 64,
        proposal_plan_summary="Plan summary",
        sandbox_identity=sbx_id,
        file_mutations=muts,
        command_executions=cmds,
        total_duration_seconds=1.2,
        provenance=EvidenceProvenance.LOCAL_EXECUTION,
    )

    tests = identify_builder_authored_tests(exec_res)
    assert len(tests) == 1
    t = tests[0]
    assert t.path == "tests/test_patch.py"
    assert t.command == "pytest tests/test_patch.py"
    assert t.exit_code == 0
    assert t.is_builder_authored is True
    assert t.is_authoritative is False
    assert t.grants_pass is False


def test_generic_pytest_with_zero_builder_test_files_does_not_create_builder_authored_test() -> (
    None
):
    """Proves: broad test command creates 0 BuilderAuthoredTest when no test files mutated."""
    sbx_id = make_sandbox_id()
    src_id = make_source_identity()

    # Builder only changed source files, zero test files created or modified
    muts = (
        FileMutationRecord(
            path="src/app.py",
            action=FileActionType.MODIFY,
            exit_code=0,
            stdout_digest="0" * 64,
            stderr_digest="0" * 64,
            duration_seconds=0.1,
            content_digest="1" * 64,
            is_success=True,
            sandbox_identity=sbx_id,
        ),
    )
    # Builder ran generic pytest against trusted repo test suite
    cmds = (
        CommandExecutionRecord(
            command="pytest",
            exit_code=0,
            stdout_digest="3" * 64,
            stderr_digest="4" * 64,
            duration_seconds=1.5,
            status=TerminationStatus.COMPLETED,
            sandbox_identity=sbx_id,
        ),
        CommandExecutionRecord(
            command="pytest tests/existing_test.py",
            exit_code=0,
            stdout_digest="5" * 64,
            stderr_digest="6" * 64,
            duration_seconds=0.7,
            status=TerminationStatus.COMPLETED,
            sandbox_identity=sbx_id,
        ),
    )
    exec_res = CandidateExecutionResult(
        source_identity=src_id,
        frozen_contract_digest=FROZEN_CONTRACT_DIGEST,
        context_digest=CONTEXT_DIGEST,
        proposal_digest="7" * 64,
        proposal_plan_summary="Plan summary",
        sandbox_identity=sbx_id,
        file_mutations=muts,
        command_executions=cmds,
        total_duration_seconds=2.3,
        provenance=EvidenceProvenance.LOCAL_EXECUTION,
    )

    tests = identify_builder_authored_tests(exec_res)
    # Zero Builder-authored test files -> strictly 0 BuilderAuthoredTest records
    assert tests == ()


# --- Capture From Execution Tests ---


def test_capture_candidate_from_execution_with_actual_files() -> None:
    sbx_id = make_sandbox_id()
    src_id = make_source_identity()
    base_files = {
        "src/app.py": "def f(): return 1\n",
    }
    actual_candidate_files = {
        "src/app.py": "def f(): return 2\n",
        "tests/test_app.py": "def test_f(): pass\n",
    }
    muts = (
        FileMutationRecord(
            path="src/app.py",
            action=FileActionType.MODIFY,
            exit_code=0,
            stdout_digest="0" * 64,
            stderr_digest="0" * 64,
            duration_seconds=0.1,
            content_digest="1" * 64,
            is_success=True,
            sandbox_identity=sbx_id,
        ),
        FileMutationRecord(
            path="tests/test_app.py",
            action=FileActionType.CREATE,
            exit_code=0,
            stdout_digest="0" * 64,
            stderr_digest="0" * 64,
            duration_seconds=0.1,
            content_digest="2" * 64,
            is_success=True,
            sandbox_identity=sbx_id,
        ),
    )
    cmds = (
        CommandExecutionRecord(
            command="pytest tests/test_app.py",
            exit_code=0,
            stdout_digest="3" * 64,
            stderr_digest="4" * 64,
            duration_seconds=0.5,
            status=TerminationStatus.COMPLETED,
            sandbox_identity=sbx_id,
        ),
    )
    exec_res = CandidateExecutionResult(
        source_identity=src_id,
        frozen_contract_digest=FROZEN_CONTRACT_DIGEST,
        context_digest=CONTEXT_DIGEST,
        proposal_digest="5" * 64,
        proposal_plan_summary="Update app return value",
        sandbox_identity=sbx_id,
        file_mutations=muts,
        command_executions=cmds,
        total_duration_seconds=0.7,
        provenance=EvidenceProvenance.LOCAL_EXECUTION,
    )

    snap = capture_candidate_from_execution(
        execution_result=exec_res,
        base_files=base_files,
        candidate_files=actual_candidate_files,
    )
    assert snap.files_modified == ("src/app.py",)
    assert snap.files_added == ("tests/test_app.py",)
    assert len(snap.builder_authored_tests) == 1
    assert snap.builder_authored_tests[0].path == "tests/test_app.py"
    assert snap.builder_authored_tests[0].grants_pass is False


def test_proposal_cannot_substitute_for_actual_candidate_state() -> None:
    """Proves: BuilderProposal cannot be used to reconstruct candidate state (fails closed)."""
    sbx_id = make_sandbox_id()
    src_id = make_source_identity()
    base_files = {"src/app.py": "def f(): return 1\n"}

    proposal = BuilderProposal(
        plan=BuilderPlan(summary="Proposal plan"),
        proposed_file_actions=(
            ProposedFileAction(
                action=FileActionType.MODIFY,
                path="src/app.py",
                content="def f(): return 999\n",
            ),
        ),
        proposed_commands=(),
        raw_response="...",
    )
    muts = (
        FileMutationRecord(
            path="src/app.py",
            action=FileActionType.MODIFY,
            exit_code=0,
            stdout_digest="0" * 64,
            stderr_digest="0" * 64,
            duration_seconds=0.1,
            content_digest="1" * 64,
            is_success=True,
            sandbox_identity=sbx_id,
        ),
    )
    exec_res = CandidateExecutionResult(
        source_identity=src_id,
        frozen_contract_digest=FROZEN_CONTRACT_DIGEST,
        context_digest=CONTEXT_DIGEST,
        proposal_digest="5" * 64,
        proposal_plan_summary="Plan summary",
        sandbox_identity=sbx_id,
        file_mutations=muts,
        command_executions=(),
        total_duration_seconds=0.1,
        provenance=EvidenceProvenance.LOCAL_EXECUTION,
    )

    # Passing proposal must fail closed with MalformedCandidateEvidenceError
    with pytest.raises(MalformedCandidateEvidenceError, match="strictly forbidden"):
        capture_candidate_from_execution(
            execution_result=exec_res,
            base_files=base_files,
            proposal=proposal,
        )

    # Calling without candidate_files when mutations exist must fail closed
    with pytest.raises(MalformedCandidateEvidenceError, match="candidate_files must be provided"):
        capture_candidate_from_execution(
            execution_result=exec_res,
            base_files=base_files,
        )

    # Actual candidate files (e.g. return 2) must govern candidate identity,
    # not proposal (return 999)
    actual_candidate_files = {"src/app.py": "def f(): return 2\n"}
    snap = capture_candidate_from_execution(
        execution_result=exec_res,
        base_files=base_files,
        candidate_files=actual_candidate_files,
    )
    assert "+def f(): return 2" in snap.patch_text
    assert "999" not in snap.patch_text


# --- Serialization & Tamper Rejection Tests ---


def test_serialization_roundtrip() -> None:
    base_files = {"src/app.py": "x = 1\n"}
    cand_files = {
        "src/app.py": "x = 2\n",
        "tests/test_app.py": "assert True\n",
    }
    src_id = make_source_identity()
    test_record = BuilderAuthoredTest(
        path="tests/test_app.py",
        command="pytest tests/test_app.py",
        exit_code=0,
        stdout_digest="1" * 64,
        stderr_digest="2" * 64,
        duration_seconds=0.4,
        status=TerminationStatus.COMPLETED,
    )
    snap = capture_candidate_from_files(
        base_files=base_files,
        candidate_files=cand_files,
        source_identity=src_id,
        frozen_contract_digest=FROZEN_CONTRACT_DIGEST,
        context_digest=CONTEXT_DIGEST,
        builder_authored_tests=[test_record],
        sandbox_identity=make_sandbox_id(),
        duration_seconds=1.5,
    )

    data = snap.to_dict()
    restored = CandidateSnapshot.from_dict(data)

    assert restored.candidate_id == snap.candidate_id
    assert restored.source_identity == snap.source_identity
    assert restored.candidate_tree_digest == snap.candidate_tree_digest
    assert restored.patch_digest == snap.patch_digest
    assert restored.patch_text == snap.patch_text
    assert restored.files_added == snap.files_added
    assert restored.files_modified == snap.files_modified
    assert restored.files_deleted == snap.files_deleted
    assert restored.frozen_contract_digest == snap.frozen_contract_digest
    assert restored.context_digest == snap.context_digest
    assert restored.sandbox_identity == snap.sandbox_identity
    assert restored.duration_seconds == snap.duration_seconds
    assert restored.is_authoritative is False
    assert len(restored.builder_authored_tests) == 1
    assert restored.builder_authored_tests[0].grants_pass is False


def test_patch_text_tamper_rejected() -> None:
    """Proves: mutating patch_text causes deserialization to fail closed."""
    base_files = {"src/app.py": "x = 1\n"}
    cand_files = {"src/app.py": "x = 2\n"}
    src_id = make_source_identity()

    snap = capture_candidate_from_files(
        base_files=base_files,
        candidate_files=cand_files,
        source_identity=src_id,
        frozen_contract_digest=FROZEN_CONTRACT_DIGEST,
        context_digest=CONTEXT_DIGEST,
    )
    data = snap.to_dict()
    # Mutate patch_text only
    data["patch_text"] = data["patch_text"] + "\n# attacker injected change\n"

    with pytest.raises(MalformedCandidateEvidenceError, match="does not match computed SHA-256"):
        CandidateSnapshot.from_dict(data)


def test_patch_digest_tamper_rejected() -> None:
    """Proves: mutating patch_digest causes deserialization to fail closed."""
    base_files = {"src/app.py": "x = 1\n"}
    cand_files = {"src/app.py": "x = 2\n"}
    src_id = make_source_identity()

    snap = capture_candidate_from_files(
        base_files=base_files,
        candidate_files=cand_files,
        source_identity=src_id,
        frozen_contract_digest=FROZEN_CONTRACT_DIGEST,
        context_digest=CONTEXT_DIGEST,
    )
    data = snap.to_dict()
    # Mutate patch_digest only
    data["patch_digest"] = "f" * 64

    with pytest.raises(MalformedCandidateEvidenceError, match="does not match computed SHA-256"):
        CandidateSnapshot.from_dict(data)


# --- Changed Files Canonicality & Disjointness Tests ---


def test_changed_files_rejects_duplicate_paths() -> None:
    src_id = make_source_identity()
    with pytest.raises(MalformedCandidateEvidenceError, match="Duplicate path detected"):
        CandidateSnapshot(
            candidate_id="cand-1",
            source_identity=src_id,
            candidate_tree_digest="a" * 64,
            patch_digest=EMPTY_PATCH_DIGEST,
            patch_text="",
            files_added=("src/a.py", "src/a.py"),
            files_modified=(),
            files_deleted=(),
            builder_authored_tests=(),
            frozen_contract_digest=FROZEN_CONTRACT_DIGEST,
            context_digest=CONTEXT_DIGEST,
        )


def test_changed_files_rejects_noncanonical_paths() -> None:
    src_id = make_source_identity()
    with pytest.raises(MalformedCandidateEvidenceError, match="not normalized"):
        CandidateSnapshot(
            candidate_id="cand-1",
            source_identity=src_id,
            candidate_tree_digest="a" * 64,
            patch_digest=EMPTY_PATCH_DIGEST,
            patch_text="",
            files_added=("./src/a.py",),
            files_modified=(),
            files_deleted=(),
            builder_authored_tests=(),
            frozen_contract_digest=FROZEN_CONTRACT_DIGEST,
            context_digest=CONTEXT_DIGEST,
        )


def test_changed_files_rejects_unsorted_paths() -> None:
    src_id = make_source_identity()
    with pytest.raises(MalformedCandidateEvidenceError, match="deterministic sorted order"):
        CandidateSnapshot(
            candidate_id="cand-1",
            source_identity=src_id,
            candidate_tree_digest="a" * 64,
            patch_digest=EMPTY_PATCH_DIGEST,
            patch_text="",
            files_added=("src/z.py", "src/a.py"),
            files_modified=(),
            files_deleted=(),
            builder_authored_tests=(),
            frozen_contract_digest=FROZEN_CONTRACT_DIGEST,
            context_digest=CONTEXT_DIGEST,
        )


def test_changed_files_rejects_overlapping_sets() -> None:
    src_id = make_source_identity()

    # Overlap added and modified
    with pytest.raises(
        MalformedCandidateEvidenceError, match="files_added and files_modified overlap"
    ):
        CandidateSnapshot(
            candidate_id="cand-1",
            source_identity=src_id,
            candidate_tree_digest="a" * 64,
            patch_digest=EMPTY_PATCH_DIGEST,
            patch_text="",
            files_added=("src/a.py",),
            files_modified=("src/a.py",),
            files_deleted=(),
            builder_authored_tests=(),
            frozen_contract_digest=FROZEN_CONTRACT_DIGEST,
            context_digest=CONTEXT_DIGEST,
        )

    # Overlap added and deleted
    with pytest.raises(
        MalformedCandidateEvidenceError, match="files_added and files_deleted overlap"
    ):
        CandidateSnapshot(
            candidate_id="cand-1",
            source_identity=src_id,
            candidate_tree_digest="a" * 64,
            patch_digest=EMPTY_PATCH_DIGEST,
            patch_text="",
            files_added=("src/a.py",),
            files_modified=(),
            files_deleted=("src/a.py",),
            builder_authored_tests=(),
            frozen_contract_digest=FROZEN_CONTRACT_DIGEST,
            context_digest=CONTEXT_DIGEST,
        )

    # Overlap modified and deleted
    with pytest.raises(
        MalformedCandidateEvidenceError, match="files_modified and files_deleted overlap"
    ):
        CandidateSnapshot(
            candidate_id="cand-1",
            source_identity=src_id,
            candidate_tree_digest="a" * 64,
            patch_digest=EMPTY_PATCH_DIGEST,
            patch_text="",
            files_added=(),
            files_modified=("src/a.py",),
            files_deleted=("src/a.py",),
            builder_authored_tests=(),
            frozen_contract_digest=FROZEN_CONTRACT_DIGEST,
            context_digest=CONTEXT_DIGEST,
        )


# --- Fail-Closed Malformed Evidence Tests ---


def test_malformed_candidate_snapshot_fails_closed() -> None:
    src_id = make_source_identity()
    # Invalid candidate_tree_digest (not hex)
    with pytest.raises(MalformedCandidateEvidenceError, match="candidate_tree_digest"):
        CandidateSnapshot(
            candidate_id="cand-1",
            source_identity=src_id,
            candidate_tree_digest="not-a-valid-hex-digest",
            patch_digest=EMPTY_PATCH_DIGEST,
            patch_text="",
            files_added=(),
            files_modified=(),
            files_deleted=(),
            builder_authored_tests=(),
            frozen_contract_digest=FROZEN_CONTRACT_DIGEST,
            context_digest=CONTEXT_DIGEST,
        )

    # Invalid patch_digest format
    with pytest.raises(MalformedCandidateEvidenceError, match="64 hex char string"):
        CandidateSnapshot(
            candidate_id="cand-1",
            source_identity=src_id,
            candidate_tree_digest="a" * 64,
            patch_digest="invalid",
            patch_text="",
            files_added=(),
            files_modified=(),
            files_deleted=(),
            builder_authored_tests=(),
            frozen_contract_digest=FROZEN_CONTRACT_DIGEST,
            context_digest=CONTEXT_DIGEST,
        )

    # Attempting is_authoritative=True
    with pytest.raises(ValueError, match="is_authoritative must be strictly False"):
        CandidateSnapshot(
            candidate_id="cand-1",
            source_identity=src_id,
            candidate_tree_digest="a" * 64,
            patch_digest=EMPTY_PATCH_DIGEST,
            patch_text="",
            files_added=(),
            files_modified=(),
            files_deleted=(),
            builder_authored_tests=(),
            frozen_contract_digest=FROZEN_CONTRACT_DIGEST,
            context_digest=CONTEXT_DIGEST,
            is_authoritative=True,
        )


def test_from_dict_malformed_fails_closed() -> None:
    with pytest.raises(MalformedCandidateEvidenceError):
        CandidateSnapshot.from_dict({"candidate_id": ""})

    with pytest.raises(MalformedCandidateEvidenceError):
        BuilderAuthoredTest.from_dict({"status": "invalid_status"})


# --- Binary & Null Byte Rejection Tests ---


def test_binary_diff_unsupported_rejection() -> None:
    base_files = {"image.png": b"\x89PNG\r\n\x1a\n\x00\x00\x00\rIHDR"}
    cand_files = {"image.png": b"\x89PNG\r\n\x1a\n\x00\x00\x00\rIHDR_MODIFIED"}
    with pytest.raises(BinaryDiffUnsupportedError):
        generate_unified_diff(base_files, cand_files)


def test_null_bytes_in_text_file_rejected() -> None:
    base_files = {"data.txt": "normal\n"}
    cand_files = {"data.txt": "binary\x00null\n"}
    with pytest.raises(BinaryDiffUnsupportedError):
        generate_unified_diff(base_files, cand_files)


# --- Sandbox Capture Simulation & Security Binding Tests ---


def test_capture_candidate_from_sandbox_success() -> None:
    """Proves: same-sandbox, same-workspace, same-base capture succeeds deterministically."""
    mock_tree = "0123456789abcdef0123456789abcdef01234567"
    sbx_id = make_sandbox_id()
    src_id = make_source_identity()
    handle = MockSandboxHandle(sandbox_identity=sbx_id)

    mock_stdout = make_sandbox_stdout(
        workspace="/workspace/candidate",
        head_commit=src_id.resolved_commit_id,
        tree_sha=mock_tree,
    )
    adapter = MockSandboxAdapter(stdout=mock_stdout)

    exec_res = CandidateExecutionResult(
        source_identity=src_id,
        frozen_contract_digest=FROZEN_CONTRACT_DIGEST,
        context_digest=CONTEXT_DIGEST,
        proposal_digest="1" * 64,
        proposal_plan_summary="Plan summary",
        sandbox_identity=sbx_id,
        file_mutations=(),
        command_executions=(),
        total_duration_seconds=0.5,
        workspace_path="/workspace/candidate",
        provenance=EvidenceProvenance.LIVE_NEBIUS,
    )

    snap = capture_candidate_from_sandbox(
        sandbox_adapter=adapter,
        sandbox_handle=handle,
        execution_result=exec_res,
    )

    assert snap.candidate_tree_digest == mock_tree
    assert snap.files_modified == ("src/app.py",)
    assert snap.files_added == ("tests/test_app.py",)
    assert snap.files_deleted == ("src/legacy.py",)
    assert "--- a/src/app.py" in snap.patch_text
    assert snap.is_authoritative is False


def test_capture_candidate_from_sandbox_identity_mismatch_rejected() -> None:
    """Proves: mismatched sandbox identity fails closed."""
    sbx_id = make_sandbox_id("sbx-expected")
    foreign_sbx_id = make_sandbox_id("sbx-foreign")
    src_id = make_source_identity()

    handle = MockSandboxHandle(sandbox_identity=foreign_sbx_id)
    adapter = MockSandboxAdapter(stdout="")

    exec_res = CandidateExecutionResult(
        source_identity=src_id,
        frozen_contract_digest=FROZEN_CONTRACT_DIGEST,
        context_digest=CONTEXT_DIGEST,
        proposal_digest="1" * 64,
        proposal_plan_summary="Plan summary",
        sandbox_identity=sbx_id,
        file_mutations=(),
        command_executions=(),
        total_duration_seconds=0.5,
        provenance=EvidenceProvenance.LIVE_NEBIUS,
    )

    with pytest.raises(MalformedCandidateEvidenceError, match="Sandbox identity mismatch"):
        capture_candidate_from_sandbox(
            sandbox_adapter=adapter,
            sandbox_handle=handle,
            execution_result=exec_res,
        )


def test_capture_candidate_from_sandbox_missing_or_empty_identity_rejected() -> None:
    """Proves: missing or empty sandbox identity fails closed."""
    sbx_id = make_sandbox_id()
    src_id = make_source_identity()
    adapter = MockSandboxAdapter(stdout="")

    exec_res = CandidateExecutionResult(
        source_identity=src_id,
        frozen_contract_digest=FROZEN_CONTRACT_DIGEST,
        context_digest=CONTEXT_DIGEST,
        proposal_digest="1" * 64,
        proposal_plan_summary="Plan summary",
        sandbox_identity=sbx_id,
        file_mutations=(),
        command_executions=(),
        total_duration_seconds=0.5,
        provenance=EvidenceProvenance.LIVE_NEBIUS,
    )

    handle_none = MockSandboxHandle(sandbox_identity=None)
    with pytest.raises(
        MalformedCandidateEvidenceError, match="lacks a valid deterministic SandboxIdentity"
    ):
        capture_candidate_from_sandbox(
            sandbox_adapter=adapter,
            sandbox_handle=handle_none,
            execution_result=exec_res,
        )

    bypassed_empty_id = SandboxIdentity(sandbox_id="temp")
    object.__setattr__(bypassed_empty_id, "sandbox_id", "   ")
    handle_empty = MockSandboxHandle(sandbox_identity=bypassed_empty_id)
    with pytest.raises(MalformedCandidateEvidenceError, match="empty or whitespace sandbox_id"):
        capture_candidate_from_sandbox(
            sandbox_adapter=adapter,
            sandbox_handle=handle_empty,
            execution_result=exec_res,
        )


def test_capture_candidate_from_sandbox_workspace_mismatch_rejected() -> None:
    """Proves: mismatched workspace path fails closed."""
    sbx_id = make_sandbox_id()
    src_id = make_source_identity()
    handle = MockSandboxHandle(sandbox_identity=sbx_id)
    adapter = MockSandboxAdapter(stdout="")

    exec_res = CandidateExecutionResult(
        source_identity=src_id,
        frozen_contract_digest=FROZEN_CONTRACT_DIGEST,
        context_digest=CONTEXT_DIGEST,
        proposal_digest="1" * 64,
        proposal_plan_summary="Plan summary",
        sandbox_identity=sbx_id,
        file_mutations=(),
        command_executions=(),
        total_duration_seconds=0.5,
        workspace_path="/workspace/candidate",
        provenance=EvidenceProvenance.LIVE_NEBIUS,
    )

    # 1. Caller supplies mismatched workspace argument
    with pytest.raises(MalformedCandidateEvidenceError, match="Workspace path mismatch"):
        capture_candidate_from_sandbox(
            sandbox_adapter=adapter,
            sandbox_handle=handle,
            execution_result=exec_res,
            workspace_path="/workspace/wrong_path",
        )

    # 2. Inside sandbox, git repo top-level reports different directory
    mock_stdout_wrong_ws = make_sandbox_stdout(workspace="/workspace/rogue_repo")
    adapter_wrong_ws = MockSandboxAdapter(stdout=mock_stdout_wrong_ws)
    with pytest.raises(
        MalformedCandidateEvidenceError, match="does not match expected candidate workspace"
    ):
        capture_candidate_from_sandbox(
            sandbox_adapter=adapter_wrong_ws,
            sandbox_handle=handle,
            execution_result=exec_res,
        )


def test_capture_candidate_from_sandbox_head_commit_mismatch_rejected() -> None:
    """Proves: sandbox git HEAD differing from execution source commit fails closed."""
    sbx_id = make_sandbox_id()
    src_id = make_source_identity(BASE_COMMIT_ID)
    handle = MockSandboxHandle(sandbox_identity=sbx_id)

    # Inside sandbox, git HEAD resolved to ALT_COMMIT_ID
    mock_stdout_wrong_head = make_sandbox_stdout(head_commit=ALT_COMMIT_ID)
    adapter = MockSandboxAdapter(stdout=mock_stdout_wrong_head)

    exec_res = CandidateExecutionResult(
        source_identity=src_id,
        frozen_contract_digest=FROZEN_CONTRACT_DIGEST,
        context_digest=CONTEXT_DIGEST,
        proposal_digest="1" * 64,
        proposal_plan_summary="Plan summary",
        sandbox_identity=sbx_id,
        file_mutations=(),
        command_executions=(),
        total_duration_seconds=0.5,
        provenance=EvidenceProvenance.LIVE_NEBIUS,
    )

    with pytest.raises(
        MalformedCandidateEvidenceError, match="does not match expected source commit"
    ):
        capture_candidate_from_sandbox(
            sandbox_adapter=adapter,
            sandbox_handle=handle,
            execution_result=exec_res,
        )


def test_capture_candidate_from_sandbox_binary_files_differ_fails_closed() -> None:
    """Proves: non-reproducible binary diff fails closed with BinaryDiffUnsupportedError."""
    sbx_id = make_sandbox_id()
    src_id = make_source_identity()
    handle = MockSandboxHandle(sandbox_identity=sbx_id)

    non_reproducible_diff = (
        "diff --git a/bin/artifact.dat b/bin/artifact.dat\n"
        "Binary files a/bin/artifact.dat and b/bin/artifact.dat differ\n"
    )
    mock_stdout = make_sandbox_stdout(
        workspace="/workspace/candidate",
        head_commit=src_id.resolved_commit_id,
        diff_text=non_reproducible_diff,
    )
    adapter = MockSandboxAdapter(stdout=mock_stdout)

    exec_res = CandidateExecutionResult(
        source_identity=src_id,
        frozen_contract_digest=FROZEN_CONTRACT_DIGEST,
        context_digest=CONTEXT_DIGEST,
        proposal_digest="1" * 64,
        proposal_plan_summary="Plan summary",
        sandbox_identity=sbx_id,
        file_mutations=(),
        command_executions=(),
        total_duration_seconds=0.5,
        provenance=EvidenceProvenance.LIVE_NEBIUS,
    )

    with pytest.raises(BinaryDiffUnsupportedError, match="Non-reproducible binary diff detected"):
        capture_candidate_from_sandbox(
            sandbox_adapter=adapter,
            sandbox_handle=handle,
            execution_result=exec_res,
        )


def test_capture_candidate_from_sandbox_reproducible_git_binary_patch_succeeds() -> None:
    """Proves: reproducible GIT binary patch representation succeeds."""
    sbx_id = make_sandbox_id()
    src_id = make_source_identity()
    handle = MockSandboxHandle(sandbox_identity=sbx_id)

    reproducible_binary_patch = (
        "diff --git a/bin/blob.bin b/bin/blob.bin\n"
        "new file mode 100644\n"
        "index 0000000000000000000000000000000000000000..f3b0...1234\n"
        "GIT binary patch\n"
        "literal 5\n"
        "Mc${n00001\n\n"
    )
    mock_stdout = make_sandbox_stdout(
        workspace="/workspace/candidate",
        head_commit=src_id.resolved_commit_id,
        diff_text=reproducible_binary_patch,
    )
    adapter = MockSandboxAdapter(stdout=mock_stdout)

    exec_res = CandidateExecutionResult(
        source_identity=src_id,
        frozen_contract_digest=FROZEN_CONTRACT_DIGEST,
        context_digest=CONTEXT_DIGEST,
        proposal_digest="1" * 64,
        proposal_plan_summary="Plan summary",
        sandbox_identity=sbx_id,
        file_mutations=(),
        command_executions=(),
        total_duration_seconds=0.5,
        provenance=EvidenceProvenance.LIVE_NEBIUS,
    )

    snap = capture_candidate_from_sandbox(
        sandbox_adapter=adapter,
        sandbox_handle=handle,
        execution_result=exec_res,
    )
    assert "GIT binary patch" in snap.patch_text
    expected_patch_digest = compute_bytes_digest(reproducible_binary_patch.encode("utf-8")).value
    assert snap.patch_digest == expected_patch_digest


def test_capture_candidate_from_sandbox_handles_script_failure() -> None:
    adapter = MockSandboxAdapter(stdout="error", exit_code=1)
    sbx_id = make_sandbox_id()
    handle = MockSandboxHandle(sandbox_identity=sbx_id)
    src_id = make_source_identity()

    exec_res = CandidateExecutionResult(
        source_identity=src_id,
        frozen_contract_digest=FROZEN_CONTRACT_DIGEST,
        context_digest=CONTEXT_DIGEST,
        proposal_digest="1" * 64,
        proposal_plan_summary="Plan summary",
        sandbox_identity=sbx_id,
        file_mutations=(),
        command_executions=(),
        total_duration_seconds=0.5,
        provenance=EvidenceProvenance.LIVE_NEBIUS,
    )

    with pytest.raises(CandidateCaptureError, match="failed inside sandbox with exit 1"):
        capture_candidate_from_sandbox(
            sandbox_adapter=adapter,
            sandbox_handle=handle,
            execution_result=exec_res,
        )


# --- Provider Purity Tests ---


def test_provider_purity_in_capture_module() -> None:
    import basebreak.builder.capture as capture_mod

    source = inspect.getsource(capture_mod)
    forbidden = ["openai", "nebius", "anthropic", "basebreak.adapters"]
    for f in forbidden:
        assert f not in source, f"Forbidden provider import/reference '{f}' found in capture.py"
