"""Deterministic unit tests for repository materialization and source verification.

Provenance: FIXTURE / LOCAL_EXECUTION.
Validates all requirements of P-05.03 without requiring live network credentials.
"""

from __future__ import annotations

import json
import urllib.request
from typing import Any

import pytest

from basebreak.adapters.nebius import (
    PRE_EXISTING_WORKSPACE_EXIT_CODE,
    PRE_EXISTING_WORKSPACE_MARKER,
    MalformedSourceIdentityError,
    MalformedWorkspacePathError,
    MaterializationExecutionError,
    MaterializedSourceRecord,
    NebiusSandboxAdapter,
    NebiusSandboxHandle,
    NebiusSourceMaterializer,
    PreExistingWorkspaceError,
    SandboxClientConfig,
    SandboxLifecycleState,
    SourceCommitMismatchError,
    SourceTreeMismatchError,
    SourceVerificationError,
    TransportResponse,
    build_materialization_script,
    validate_workspace_path,
)
from basebreak.domain.execution import SandboxIdentity
from basebreak.domain.source import CommitRevision, RequestedRef, SourceIdentity

TEST_LOCATOR = "https://github.com/zyganali-glitch/Basebreak.git"
TEST_COMMIT = "d74d8103c7048bdb1c73221bb690575cba43818f"
TEST_TREE = "aa54850bf7ddcd222539d3e0b6fe5059cb1d693d"
WRONG_COMMIT = "0123456789abcdef0123456789abcdef01234567"
WRONG_TREE = "fedcba9876543210fedcba9876543210fedcba98"


def _make_transport_response(
    status_code: int = 200,
    body: bytes | dict[str, Any] | str = b"",
    headers: dict[str, str] | None = None,
) -> TransportResponse:
    if isinstance(body, dict):
        raw_body = json.dumps(body).encode("utf-8")
    elif isinstance(body, str):
        raw_body = body.encode("utf-8")
    else:
        raw_body = body
    return TransportResponse(
        status_code=status_code,
        body=raw_body,
        headers=headers or {},
    )


class TestNebiusSourceMaterializer:
    """Test suite covering P-05.03 repository materialization adapter."""

    # 1. Script builder validation
    def test_build_materialization_script_structure(self) -> None:
        source_id = SourceIdentity(
            locator=TEST_LOCATOR,
            revision=CommitRevision(commit_id=TEST_COMMIT),
            requested_ref=RequestedRef(name="main"),
        )
        script = build_materialization_script(source_id, "/workspace/repo")
        assert f"git clone --quiet {TEST_LOCATOR} /workspace/repo" in script
        assert f"git checkout --quiet {TEST_COMMIT}" in script
        assert 'echo "BASEBREAK_RESOLVED_COMMIT=$(git rev-parse HEAD)"' in script
        assert 'echo "BASEBREAK_RESOLVED_TREE=$(git write-tree)"' in script

    # 2. Exact source match
    def test_materialize_exact_source_match(self) -> None:
        def fake_transport(req: urllib.request.Request, timeout: float) -> TransportResponse:
            if "/instances" in req.full_url:
                return _make_transport_response(
                    status_code=201,
                    headers={"Location": "/sandboxes/v1/operations/op-mat-ok"},
                )
            return _make_transport_response(
                status_code=200,
                body={
                    "id": "op-mat-ok",
                    "status": "SUCCESS",
                    "result": {
                        "exit_code": 0,
                        "duration": 4.5,
                        "stdout": (
                            f"BASEBREAK_RESOLVED_COMMIT={TEST_COMMIT}\n"
                            f"BASEBREAK_RESOLVED_TREE={TEST_TREE}\n"
                        ),
                        "stderr": "",
                        "result_image_uuid": None,
                    },
                },
            )

        adapter = NebiusSandboxAdapter(
            config=SandboxClientConfig(
                api_key="key", project_id="proj", poll_interval_seconds=0.01
            ),
            transport=fake_transport,
        )
        materializer = NebiusSourceMaterializer(adapter)

        source_id = SourceIdentity(
            locator=TEST_LOCATOR,
            revision=CommitRevision(commit_id=TEST_COMMIT),
        )

        record = materializer.materialize_repository(
            source_id,
            expected_tree_sha=TEST_TREE,
        )

        assert isinstance(record, MaterializedSourceRecord)
        assert record.resolved_commit_sha == TEST_COMMIT
        assert record.resolved_tree_sha == TEST_TREE
        assert record.is_verified is True
        assert record.operation_id == "op-mat-ok"
        assert record.workspace_path == "/workspace/repo"

    # 3. Source commit mismatch fails closed
    def test_materialize_source_commit_mismatch_fails_closed(self) -> None:
        def fake_transport(req: urllib.request.Request, timeout: float) -> TransportResponse:
            if "/instances" in req.full_url:
                return _make_transport_response(
                    status_code=201,
                    headers={"Location": "/sandboxes/v1/operations/op-mismatch"},
                )
            return _make_transport_response(
                status_code=200,
                body={
                    "id": "op-mismatch",
                    "status": "SUCCESS",
                    "result": {
                        "exit_code": 0,
                        "duration": 3.0,
                        "stdout": (
                            f"BASEBREAK_RESOLVED_COMMIT={WRONG_COMMIT}\n"
                            f"BASEBREAK_RESOLVED_TREE={TEST_TREE}\n"
                        ),
                        "stderr": "",
                    },
                },
            )

        adapter = NebiusSandboxAdapter(
            config=SandboxClientConfig(
                api_key="key", project_id="proj", poll_interval_seconds=0.01
            ),
            transport=fake_transport,
        )
        materializer = NebiusSourceMaterializer(adapter)

        source_id = SourceIdentity(
            locator=TEST_LOCATOR,
            revision=CommitRevision(commit_id=TEST_COMMIT),
        )

        with pytest.raises(SourceCommitMismatchError) as exc_info:
            materializer.materialize_repository(source_id)

        assert exc_info.value.requested_commit_sha == TEST_COMMIT
        assert exc_info.value.actual_commit_sha == WRONG_COMMIT

    # 4. Source tree mismatch fails closed
    def test_materialize_source_tree_mismatch_fails_closed(self) -> None:
        def fake_transport(req: urllib.request.Request, timeout: float) -> TransportResponse:
            if "/instances" in req.full_url:
                return _make_transport_response(
                    status_code=201,
                    headers={"Location": "/sandboxes/v1/operations/op-tree-mismatch"},
                )
            return _make_transport_response(
                status_code=200,
                body={
                    "id": "op-tree-mismatch",
                    "status": "SUCCESS",
                    "result": {
                        "exit_code": 0,
                        "duration": 3.0,
                        "stdout": (
                            f"BASEBREAK_RESOLVED_COMMIT={TEST_COMMIT}\n"
                            f"BASEBREAK_RESOLVED_TREE={WRONG_TREE}\n"
                        ),
                        "stderr": "",
                    },
                },
            )

        adapter = NebiusSandboxAdapter(
            config=SandboxClientConfig(
                api_key="key", project_id="proj", poll_interval_seconds=0.01
            ),
            transport=fake_transport,
        )
        materializer = NebiusSourceMaterializer(adapter)

        source_id = SourceIdentity(
            locator=TEST_LOCATOR,
            revision=CommitRevision(commit_id=TEST_COMMIT),
        )

        with pytest.raises(SourceTreeMismatchError) as exc_info:
            materializer.materialize_repository(source_id, expected_tree_sha=TEST_TREE)

        assert exc_info.value.expected_tree_sha == TEST_TREE
        assert exc_info.value.actual_tree_sha == WRONG_TREE

    # 5. Malformed source identity input
    def test_materialize_rejects_non_source_identity(self) -> None:
        adapter = NebiusSandboxAdapter(config=SandboxClientConfig(api_key="k", project_id="p"))
        materializer = NebiusSourceMaterializer(adapter)

        with pytest.raises(MalformedSourceIdentityError, match="instance of SourceIdentity"):
            materializer.materialize_repository("not-a-source-identity")  # type: ignore[arg-type]

    def test_materialize_rejects_invalid_expected_tree_sha(self) -> None:
        adapter = NebiusSandboxAdapter(config=SandboxClientConfig(api_key="k", project_id="p"))
        materializer = NebiusSourceMaterializer(adapter)
        source_id = SourceIdentity(
            locator=TEST_LOCATOR,
            revision=CommitRevision(commit_id=TEST_COMMIT),
        )

        with pytest.raises(MalformedSourceIdentityError, match="40 or 64 hex characters"):
            materializer.materialize_repository(source_id, expected_tree_sha="not-valid-sha")

    # 6. Materialization command failure inside sandbox
    def test_materialize_command_exit_code_failure_fails_closed(self) -> None:
        def fake_transport(req: urllib.request.Request, timeout: float) -> TransportResponse:
            if "/instances" in req.full_url:
                return _make_transport_response(
                    status_code=201,
                    headers={"Location": "/sandboxes/v1/operations/op-fail"},
                )
            return _make_transport_response(
                status_code=200,
                body={
                    "id": "op-fail",
                    "status": "FAILED",
                    "result": {
                        "exit_code": 128,
                        "duration": 1.2,
                        "stdout": "",
                        "stderr": "fatal: repository not found",
                    },
                },
            )

        adapter = NebiusSandboxAdapter(
            config=SandboxClientConfig(
                api_key="key", project_id="proj", poll_interval_seconds=0.01
            ),
            transport=fake_transport,
        )
        materializer = NebiusSourceMaterializer(adapter)

        source_id = SourceIdentity(
            locator="https://github.com/zyganali-glitch/NonExistent.git",
            revision=CommitRevision(commit_id=TEST_COMMIT),
        )

        with pytest.raises(MaterializationExecutionError, match="exit code 128"):
            materializer.materialize_repository(source_id)

    # 7. Missing verification hashes in stdout
    def test_materialize_missing_hashes_in_stdout_fails_closed(self) -> None:
        def fake_transport(req: urllib.request.Request, timeout: float) -> TransportResponse:
            if "/instances" in req.full_url:
                return _make_transport_response(
                    status_code=201,
                    headers={"Location": "/sandboxes/v1/operations/op-nohash"},
                )
            return _make_transport_response(
                status_code=200,
                body={
                    "id": "op-nohash",
                    "status": "SUCCESS",
                    "result": {
                        "exit_code": 0,
                        "duration": 2.0,
                        "stdout": "Cloning into '/workspace/repo'...\ndone.\n",
                        "stderr": "",
                    },
                },
            )

        adapter = NebiusSandboxAdapter(
            config=SandboxClientConfig(
                api_key="key", project_id="proj", poll_interval_seconds=0.01
            ),
            transport=fake_transport,
        )
        materializer = NebiusSourceMaterializer(adapter)

        source_id = SourceIdentity(
            locator=TEST_LOCATOR,
            revision=CommitRevision(commit_id=TEST_COMMIT),
        )

        with pytest.raises(SourceVerificationError, match="failed to output resolved commit SHA"):
            materializer.materialize_repository(source_id)

    # 8. Secret safety: synthetic secrets in failure messages are redacted
    def test_materialize_redacts_synthetic_secrets_in_error(self) -> None:
        synthetic_secret = "ghp_SECRETACCESSTOKEN1234567890abcdefghij"

        def fake_transport(req: urllib.request.Request, timeout: float) -> TransportResponse:
            if "/instances" in req.full_url:
                return _make_transport_response(
                    status_code=201,
                    headers={"Location": "/sandboxes/v1/operations/op-secret-fail"},
                )
            return _make_transport_response(
                status_code=200,
                body={
                    "id": "op-secret-fail",
                    "status": "FAILED",
                    "result": {
                        "exit_code": 1,
                        "stdout": "",
                        "stderr": f"Error authenticating with {synthetic_secret}",
                    },
                },
            )

        adapter = NebiusSandboxAdapter(
            config=SandboxClientConfig(
                api_key="key", project_id="proj", poll_interval_seconds=0.01
            ),
            transport=fake_transport,
        )
        materializer = NebiusSourceMaterializer(adapter)

        source_id = SourceIdentity(
            locator=TEST_LOCATOR,
            revision=CommitRevision(commit_id=TEST_COMMIT),
        )

        with pytest.raises(MaterializationExecutionError) as exc_info:
            materializer.materialize_repository(source_id)

        err_text = str(exc_info.value)
        assert synthetic_secret not in err_text
        assert "[REDACTED" in err_text

    # 9. Workspace path validation: valid paths normalize properly
    def test_validate_workspace_path_valid(self) -> None:
        assert validate_workspace_path("/workspace/repo") == "/workspace/repo"
        assert validate_workspace_path("/opt/project/my-repo/") == "/opt/project/my-repo"
        assert validate_workspace_path("  /custom/path/repo  ") == "/custom/path/repo"

    # 10. Workspace path validation: malformed and unsafe paths fail closed
    @pytest.mark.parametrize(
        "bad_path",
        [
            "",
            "   ",
            "workspace/repo",
            "relative/path",
            "/workspace/../etc",
            "/workspace/./repo",
            "/",
            "///",
            "/bin",
            "/etc",
            "/usr",
            "/proc",
            "/sys",
            "/dev",
            "/tmp",
            "/workspace/\x00repo",
            "/workspace/\nrepo",
            "/workspace/\rrepo",
        ],
    )
    def test_validate_workspace_path_malformed_rejects(self, bad_path: str) -> None:
        with pytest.raises(MalformedWorkspacePathError):
            validate_workspace_path(bad_path)

    # 11. Pre-existing target workspace fails closed with PreExistingWorkspaceError
    def test_materialize_pre_existing_workspace_fails_closed(self) -> None:
        def fake_transport(req: urllib.request.Request, timeout: float) -> TransportResponse:
            if "/instances" in req.full_url:
                return _make_transport_response(
                    status_code=201,
                    headers={"Location": "/sandboxes/v1/operations/op-pre-exist"},
                )
            return _make_transport_response(
                status_code=200,
                body={
                    "id": "op-pre-exist",
                    "status": "FAILED",
                    "result": {
                        "exit_code": PRE_EXISTING_WORKSPACE_EXIT_CODE,
                        "duration": 0.5,
                        "stdout": "",
                        "stderr": (
                            f"{PRE_EXISTING_WORKSPACE_MARKER}: target workspace already exists: "
                            "/workspace/repo"
                        ),
                    },
                },
            )

        adapter = NebiusSandboxAdapter(
            config=SandboxClientConfig(
                api_key="key", project_id="proj", poll_interval_seconds=0.01
            ),
            transport=fake_transport,
        )
        materializer = NebiusSourceMaterializer(adapter)
        source_id = SourceIdentity(
            locator=TEST_LOCATOR,
            revision=CommitRevision(commit_id=TEST_COMMIT),
        )

        with pytest.raises(PreExistingWorkspaceError, match="Target workspace already exists"):
            materializer.materialize_repository(source_id, workspace_path="/workspace/repo")

    # 12. Existing sandbox handle does not bypass clean workspace check; distinguishes freshness
    def test_materialize_existing_sandbox_handle_clean_vs_pre_existing(self) -> None:
        handle = NebiusSandboxHandle(
            sandbox_identity=SandboxIdentity(sandbox_id="sb-reused"),
            image="ubuntu:22.04",
            disposable=False,
            lifecycle_state=SandboxLifecycleState.CREATED,
        )

        # 12a: Pre-existing workspace inside reused handle still fails closed
        def fake_transport_dirty(req: urllib.request.Request, timeout: float) -> TransportResponse:
            if "/instances" in req.full_url:
                return _make_transport_response(
                    status_code=201,
                    headers={"Location": "/sandboxes/v1/operations/op-dirty-handle"},
                )
            return _make_transport_response(
                status_code=200,
                body={
                    "id": "op-dirty-handle",
                    "status": "FAILED",
                    "result": {
                        "exit_code": PRE_EXISTING_WORKSPACE_EXIT_CODE,
                        "stdout": "",
                        "stderr": (
                            f"{PRE_EXISTING_WORKSPACE_MARKER}: target workspace already exists"
                        ),
                    },
                },
            )

        adapter_dirty = NebiusSandboxAdapter(
            config=SandboxClientConfig(
                api_key="key", project_id="proj", poll_interval_seconds=0.01
            ),
            transport=fake_transport_dirty,
        )
        mat_dirty = NebiusSourceMaterializer(adapter_dirty)
        source_id = SourceIdentity(
            locator=TEST_LOCATOR,
            revision=CommitRevision(commit_id=TEST_COMMIT),
        )

        with pytest.raises(PreExistingWorkspaceError):
            mat_dirty.materialize_repository(source_id, sandbox=handle)

        # 12b: Clean workspace inside reused handle succeeds and marks is_fresh_sandbox=False
        def fake_transport_clean(req: urllib.request.Request, timeout: float) -> TransportResponse:
            if "/instances" in req.full_url:
                return _make_transport_response(
                    status_code=201,
                    headers={"Location": "/sandboxes/v1/operations/op-clean-handle"},
                )
            return _make_transport_response(
                status_code=200,
                body={
                    "id": "op-clean-handle",
                    "status": "SUCCESS",
                    "result": {
                        "exit_code": 0,
                        "duration": 2.1,
                        "stdout": (
                            f"BASEBREAK_RESOLVED_COMMIT={TEST_COMMIT}\n"
                            f"BASEBREAK_RESOLVED_TREE={TEST_TREE}\n"
                        ),
                        "stderr": "",
                    },
                },
            )

        adapter_clean = NebiusSandboxAdapter(
            config=SandboxClientConfig(
                api_key="key", project_id="proj", poll_interval_seconds=0.01
            ),
            transport=fake_transport_clean,
        )
        mat_clean = NebiusSourceMaterializer(adapter_clean)
        record = mat_clean.materialize_repository(source_id, sandbox=handle)

        assert record.is_clean_workspace is True
        assert record.is_fresh_sandbox is False

    # 13. Fresh sandbox flag is True when sandbox is None or image string
    def test_materialize_fresh_sandbox_flag(self) -> None:
        def fake_transport(req: urllib.request.Request, timeout: float) -> TransportResponse:
            if "/instances" in req.full_url:
                return _make_transport_response(
                    status_code=201,
                    headers={"Location": "/sandboxes/v1/operations/op-fresh"},
                )
            return _make_transport_response(
                status_code=200,
                body={
                    "id": "op-fresh",
                    "status": "SUCCESS",
                    "result": {
                        "exit_code": 0,
                        "duration": 3.0,
                        "stdout": (
                            f"BASEBREAK_RESOLVED_COMMIT={TEST_COMMIT}\n"
                            f"BASEBREAK_RESOLVED_TREE={TEST_TREE}\n"
                        ),
                        "stderr": "",
                    },
                },
            )

        adapter = NebiusSandboxAdapter(
            config=SandboxClientConfig(
                api_key="key", project_id="proj", poll_interval_seconds=0.01
            ),
            transport=fake_transport,
        )
        materializer = NebiusSourceMaterializer(adapter)
        source_id = SourceIdentity(
            locator=TEST_LOCATOR,
            revision=CommitRevision(commit_id=TEST_COMMIT),
        )

        record_default = materializer.materialize_repository(source_id)
        assert record_default.is_fresh_sandbox is True
        assert record_default.is_clean_workspace is True

        record_image = materializer.materialize_repository(source_id, sandbox="custom-image:latest")
        assert record_image.is_fresh_sandbox is True
        assert record_image.is_clean_workspace is True

    # 14. No automatic retries on materialization failure
    def test_materialize_no_automatic_retry(self) -> None:
        call_count = 0

        def fake_transport(req: urllib.request.Request, timeout: float) -> TransportResponse:
            nonlocal call_count
            call_count += 1
            if "/instances" in req.full_url:
                return _make_transport_response(
                    status_code=201,
                    headers={"Location": "/sandboxes/v1/operations/op-noretry"},
                )
            return _make_transport_response(
                status_code=200,
                body={
                    "id": "op-noretry",
                    "status": "FAILED",
                    "result": {
                        "exit_code": 1,
                        "stdout": "",
                        "stderr": "git error",
                    },
                },
            )

        adapter = NebiusSandboxAdapter(
            config=SandboxClientConfig(
                api_key="key", project_id="proj", poll_interval_seconds=0.01
            ),
            transport=fake_transport,
        )
        materializer = NebiusSourceMaterializer(adapter)
        source_id = SourceIdentity(
            locator=TEST_LOCATOR,
            revision=CommitRevision(commit_id=TEST_COMMIT),
        )

        with pytest.raises(MaterializationExecutionError):
            materializer.materialize_repository(source_id)

        # Exactly 2 calls: 1 POST to create instance, 1 GET to poll operation; no retries
        assert call_count == 2
