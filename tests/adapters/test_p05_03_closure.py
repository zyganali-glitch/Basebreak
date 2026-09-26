"""Acceptance gate and closure verification suite for P-05.03.

Master Plan Task:
P-05.03 — Implement repository materialization and source-hash verification adapter

Acceptance Criteria:
- exact source match
- source mismatch
- malformed source identity
- materialization command failure
- secret safety
- clean-state assumptions encoded honestly
- provider purity
- no P-05.04+ leakage before this task commits
"""

from __future__ import annotations

import json
import urllib.request
from pathlib import Path
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
    TransportResponse,
    build_materialization_script,
    validate_workspace_path,
)
from basebreak.domain.execution import SandboxIdentity
from basebreak.domain.source import CommitRevision, SourceIdentity

TEST_LOCATOR = "https://github.com/zyganali-glitch/Basebreak.git"
TEST_COMMIT = "d74d8103c7048bdb1c73221bb690575cba43818f"
TEST_TREE = "aa54850bf7ddcd222539d3e0b6fe5059cb1d693d"
WRONG_COMMIT = "1111111111111111111111111111111111111111"


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


class TestP0503ClosureGate:
    """Acceptance gate test suite for P-05.03 closure."""

    # Gate 1: Exact source match
    def test_gate_exact_source_match(self) -> None:
        def transport(req: urllib.request.Request, timeout: float) -> TransportResponse:
            if "/instances" in req.full_url:
                return _make_transport_response(
                    status_code=201,
                    headers={"Location": "/sandboxes/v1/operations/gate-mat-1"},
                )
            return _make_transport_response(
                status_code=200,
                body={
                    "id": "gate-mat-1",
                    "status": "SUCCESS",
                    "result": {
                        "exit_code": 0,
                        "duration": 5.0,
                        "stdout": (
                            f"BASEBREAK_RESOLVED_COMMIT={TEST_COMMIT}\n"
                            f"BASEBREAK_RESOLVED_TREE={TEST_TREE}\n"
                        ),
                        "stderr": "",
                    },
                },
            )

        adapter = NebiusSandboxAdapter(
            config=SandboxClientConfig(api_key="k", project_id="p", poll_interval_seconds=0.01),
            transport=transport,
        )
        materializer = NebiusSourceMaterializer(adapter)
        source_id = SourceIdentity(
            locator=TEST_LOCATOR, revision=CommitRevision(commit_id=TEST_COMMIT)
        )

        record = materializer.materialize_repository(source_id, expected_tree_sha=TEST_TREE)
        assert isinstance(record, MaterializedSourceRecord)
        assert record.resolved_commit_sha == TEST_COMMIT
        assert record.resolved_tree_sha == TEST_TREE
        assert record.is_verified is True

    # Gate 2: Source mismatch fails closed
    def test_gate_source_mismatch_fails_closed(self) -> None:
        def transport(req: urllib.request.Request, timeout: float) -> TransportResponse:
            if "/instances" in req.full_url:
                return _make_transport_response(
                    status_code=201,
                    headers={"Location": "/sandboxes/v1/operations/gate-mat-mismatch"},
                )
            return _make_transport_response(
                status_code=200,
                body={
                    "id": "gate-mat-mismatch",
                    "status": "SUCCESS",
                    "result": {
                        "exit_code": 0,
                        "stdout": (
                            f"BASEBREAK_RESOLVED_COMMIT={WRONG_COMMIT}\n"
                            f"BASEBREAK_RESOLVED_TREE={TEST_TREE}\n"
                        ),
                        "stderr": "",
                    },
                },
            )

        adapter = NebiusSandboxAdapter(
            config=SandboxClientConfig(api_key="k", project_id="p", poll_interval_seconds=0.01),
            transport=transport,
        )
        materializer = NebiusSourceMaterializer(adapter)
        source_id = SourceIdentity(
            locator=TEST_LOCATOR, revision=CommitRevision(commit_id=TEST_COMMIT)
        )

        with pytest.raises(SourceCommitMismatchError):
            materializer.materialize_repository(source_id)

    # Gate 3: Malformed source identity
    def test_gate_malformed_source_identity(self) -> None:
        adapter = NebiusSandboxAdapter(config=SandboxClientConfig(api_key="k", project_id="p"))
        materializer = NebiusSourceMaterializer(adapter)

        with pytest.raises(MalformedSourceIdentityError):
            materializer.materialize_repository(None)  # type: ignore[arg-type]

        source_id = SourceIdentity(
            locator=TEST_LOCATOR, revision=CommitRevision(commit_id=TEST_COMMIT)
        )
        with pytest.raises(MalformedSourceIdentityError):
            materializer.materialize_repository(source_id, expected_tree_sha="invalid-tree")

    # Gate 4: Materialization command failure
    def test_gate_materialization_command_failure(self) -> None:
        def transport(req: urllib.request.Request, timeout: float) -> TransportResponse:
            if "/instances" in req.full_url:
                return _make_transport_response(
                    status_code=201,
                    headers={"Location": "/sandboxes/v1/operations/gate-fail"},
                )
            return _make_transport_response(
                status_code=200,
                body={
                    "id": "gate-fail",
                    "status": "FAILED",
                    "result": {
                        "exit_code": 1,
                        "stdout": "",
                        "stderr": "fatal: Remote branch not found",
                    },
                },
            )

        adapter = NebiusSandboxAdapter(
            config=SandboxClientConfig(api_key="k", project_id="p", poll_interval_seconds=0.01),
            transport=transport,
        )
        materializer = NebiusSourceMaterializer(adapter)
        source_id = SourceIdentity(
            locator=TEST_LOCATOR, revision=CommitRevision(commit_id=TEST_COMMIT)
        )

        with pytest.raises(MaterializationExecutionError, match="exit code 1"):
            materializer.materialize_repository(source_id)

    # Gate 5: Secret safety
    def test_gate_secret_safety_in_errors(self) -> None:
        raw_secret = "ghp_SECRETTOKENFORTESTING1234567890abcde"

        def transport(req: urllib.request.Request, timeout: float) -> TransportResponse:
            if "/instances" in req.full_url:
                return _make_transport_response(
                    status_code=201,
                    headers={"Location": "/sandboxes/v1/operations/gate-sec"},
                )
            return _make_transport_response(
                status_code=200,
                body={
                    "id": "gate-sec",
                    "status": "FAILED",
                    "result": {
                        "exit_code": 128,
                        "stdout": "",
                        "stderr": f"Authentication failed with token: {raw_secret}",
                    },
                },
            )

        adapter = NebiusSandboxAdapter(
            config=SandboxClientConfig(api_key="k", project_id="p", poll_interval_seconds=0.01),
            transport=transport,
        )
        materializer = NebiusSourceMaterializer(adapter)
        source_id = SourceIdentity(
            locator=TEST_LOCATOR, revision=CommitRevision(commit_id=TEST_COMMIT)
        )

        with pytest.raises(MaterializationExecutionError) as exc_info:
            materializer.materialize_repository(source_id)

        assert raw_secret not in str(exc_info.value)
        assert "[REDACTED" in str(exc_info.value)

    # Gate 6: Clean state assumptions encoded honestly
    def test_gate_clean_state_assumptions(self) -> None:
        source_id = SourceIdentity(
            locator=TEST_LOCATOR, revision=CommitRevision(commit_id=TEST_COMMIT)
        )

        # 6a: Materialization script encodes pre-existence check and fail-closed exit
        script = build_materialization_script(source_id, "/workspace/clean_repo")
        assert "git clone" in script
        assert "/workspace/clean_repo" in script
        assert f"exit {PRE_EXISTING_WORKSPACE_EXIT_CODE}" in script
        assert PRE_EXISTING_WORKSPACE_MARKER in script

        # 6b: Malformed / traversal workspace path fails closed early
        with pytest.raises(MalformedWorkspacePathError):
            validate_workspace_path("/workspace/../etc")
        with pytest.raises(MalformedWorkspacePathError):
            validate_workspace_path("relative/path")

        # 6c: Pre-existing workspace fails closed with PreExistingWorkspaceError
        def transport_pre_exist(req: urllib.request.Request, timeout: float) -> TransportResponse:
            if "/instances" in req.full_url:
                return _make_transport_response(
                    status_code=201,
                    headers={"Location": "/sandboxes/v1/operations/gate-pre-exist"},
                )
            return _make_transport_response(
                status_code=200,
                body={
                    "id": "gate-pre-exist",
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

        adapter_pe = NebiusSandboxAdapter(
            config=SandboxClientConfig(api_key="k", project_id="p", poll_interval_seconds=0.01),
            transport=transport_pre_exist,
        )
        mat_pe = NebiusSourceMaterializer(adapter_pe)
        with pytest.raises(PreExistingWorkspaceError):
            mat_pe.materialize_repository(source_id)

        # 6d: Reused handle marks is_fresh_sandbox=False, while fresh sandbox marks True
        handle = NebiusSandboxHandle(
            sandbox_identity=SandboxIdentity(sandbox_id="sb-gate-reuse"),
            image="ubuntu:22.04",
            disposable=False,
            lifecycle_state=SandboxLifecycleState.CREATED,
        )

        def transport_ok(req: urllib.request.Request, timeout: float) -> TransportResponse:
            if "/instances" in req.full_url:
                return _make_transport_response(
                    status_code=201,
                    headers={"Location": "/sandboxes/v1/operations/gate-reuse-ok"},
                )
            return _make_transport_response(
                status_code=200,
                body={
                    "id": "gate-reuse-ok",
                    "status": "SUCCESS",
                    "result": {
                        "exit_code": 0,
                        "duration": 1.0,
                        "stdout": (
                            f"BASEBREAK_RESOLVED_COMMIT={TEST_COMMIT}\n"
                            f"BASEBREAK_RESOLVED_TREE={TEST_TREE}\n"
                        ),
                        "stderr": "",
                    },
                },
            )

        adapter_ok = NebiusSandboxAdapter(
            config=SandboxClientConfig(api_key="k", project_id="p", poll_interval_seconds=0.01),
            transport=transport_ok,
        )
        mat_ok = NebiusSourceMaterializer(adapter_ok)

        record_reused = mat_ok.materialize_repository(source_id, sandbox=handle)
        assert record_reused.is_clean_workspace is True
        assert record_reused.is_fresh_sandbox is False

        record_fresh = mat_ok.materialize_repository(source_id, sandbox=None)
        assert record_fresh.is_clean_workspace is True
        assert record_fresh.is_fresh_sandbox is True

    # Gate 7: Provider purity
    def test_gate_provider_purity(self) -> None:
        src_root = Path(__file__).resolve().parent.parent.parent / "src" / "basebreak"
        for pkg in ("domain", "evidence", "security"):
            for py_file in (src_root / pkg).glob("**/*.py"):
                text = py_file.read_text(encoding="utf-8")
                assert "basebreak.adapters" not in text
                assert "from .adapters" not in text

    # Gate 8: No P-05.04+ leakage
    def test_gate_no_p05_04_plus_leakage(self) -> None:
        mat_file = (
            Path(__file__).resolve().parent.parent.parent
            / "src"
            / "basebreak"
            / "adapters"
            / "nebius"
            / "materialization.py"
        )
        text = mat_file.read_text(encoding="utf-8")
        assert "TelemetryNormalizer" not in text
        assert "ExponentialBackoff" not in text
        assert "RetryPolicy" not in text
