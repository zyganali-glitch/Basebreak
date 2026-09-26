"""Acceptance gate and closure verification suite for P-05.02.

Master Plan Task:
P-05.02 — Implement sandbox create/exec/inspect/teardown adapter

Acceptance Criteria:
- create request semantics
- exec request semantics
- inspect semantics
- teardown semantics
- timeout/error handling
- malformed response behavior
- secret redaction
- deterministic execution fact preservation
- exactly-once transport behavior at this layer
- no retry leakage
- provider purity
- no P-05.03+ implementation leakage before this task commits
"""

from __future__ import annotations

import json
import urllib.request
from pathlib import Path
from typing import Any

import pytest

from basebreak.adapters.nebius import (
    DEFAULT_SANDBOX_IMAGE,
    MissingSandboxCredentialError,
    NebiusSandboxAdapter,
    SandboxAdapterError,
    SandboxClientConfig,
    SandboxConfigError,
    SandboxLifecycleError,
    SandboxLifecycleState,
    SandboxProviderError,
    SandboxResponseFormatError,
    SandboxTransportError,
    TransportResponse,
)
from basebreak.security.normalization import NormalizedExecutionOutcome


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


class TestP0502ClosureGate:
    """Acceptance gate test suite for P-05.02 closure."""

    # Gate 1: Create request semantics
    def test_gate_create_request_semantics(self) -> None:
        adapter = NebiusSandboxAdapter(config=SandboxClientConfig(api_key="k", project_id="p"))
        handle = adapter.create_sandbox(
            image=DEFAULT_SANDBOX_IMAGE,
            disposable=True,
            description="Gate verification handle",
        )
        assert handle.lifecycle_state == SandboxLifecycleState.CREATED
        assert handle.image == DEFAULT_SANDBOX_IMAGE
        assert handle.disposable is True
        assert handle.sandbox_identity.sandbox_id.startswith("sbx-")

    # Gate 2: Exec request semantics
    def test_gate_exec_request_semantics(self) -> None:
        requests = []

        def transport(req: urllib.request.Request, timeout: float) -> TransportResponse:
            requests.append(req)
            if "/instances" in req.full_url:
                return _make_transport_response(
                    status_code=201,
                    headers={"Location": "/sandboxes/v1/operations/gate-op-1"},
                )
            return _make_transport_response(
                status_code=200,
                body={
                    "id": "gate-op-1",
                    "status": "SUCCESS",
                    "result": {
                        "exit_code": 0,
                        "duration": 0.88,
                        "stdout": "GATE_EXEC_OK\n",
                        "stderr": "",
                        "result_image_uuid": None,
                    },
                },
            )

        adapter = NebiusSandboxAdapter(
            config=SandboxClientConfig(api_key="k", project_id="p", poll_interval_seconds=0.01),
            transport=transport,
        )
        result = adapter.execute_command(DEFAULT_SANDBOX_IMAGE, "echo GATE_EXEC_OK")

        assert result.exit_code == 0
        assert result.stdout == "GATE_EXEC_OK\n"
        assert result.duration_seconds == 0.88
        assert result.is_completed is True
        assert len(requests) == 2
        assert requests[0].method == "POST"
        assert requests[0].full_url.endswith("/instances")

    # Gate 3: Inspect semantics
    def test_gate_inspect_semantics(self) -> None:
        def transport(req: urllib.request.Request, timeout: float) -> TransportResponse:
            assert req.method == "GET"
            assert req.full_url.endswith("/operations/inspect-gate-1")
            return _make_transport_response(
                status_code=200,
                body={
                    "id": "inspect-gate-1",
                    "status": "SUCCESS",
                    "result": {"exit_code": 0, "stdout": "OUT", "stderr": "ERR"},
                },
            )

        adapter = NebiusSandboxAdapter(
            config=SandboxClientConfig(api_key="k", project_id="p"),
            transport=transport,
        )
        status = adapter.inspect_operation("inspect-gate-1")
        assert status.operation_id == "inspect-gate-1"
        assert status.status == "SUCCESS"
        assert status.exit_code == 0
        assert status.stdout == "OUT"
        assert status.stderr == "ERR"

    def test_gate_live_schema_inspect_semantics(self) -> None:
        live_fixture = {
            "uuid": "01a0d8ca-gate-live",
            "kind": "instance",
            "status": "SUCCESS",
            "duration": 0.369,
            "metadata": {
                "command": "echo HELLO_SANDBOX",
                "result": {
                    "state": {
                        "exit_code": 0,
                        "pid": 8,
                        "signal": -1,
                        "timed_out": False,
                    },
                    "stdout": {
                        "value": "HELLO_SANDBOX\n",
                        "encoding": "ascii",
                        "truncated": False,
                    },
                    "stderr": {
                        "value": "",
                        "encoding": "ascii",
                        "truncated": False,
                    },
                },
            },
        }

        def transport(req: urllib.request.Request, timeout: float) -> TransportResponse:
            return _make_transport_response(status_code=200, body=live_fixture)

        adapter = NebiusSandboxAdapter(
            config=SandboxClientConfig(api_key="k", project_id="p"),
            transport=transport,
        )
        status = adapter.inspect_operation("01a0d8ca-gate-live")
        assert status.status == "SUCCESS"
        assert status.exit_code == 0
        assert isinstance(status.exit_code, int)
        assert status.stdout == "HELLO_SANDBOX\n"
        assert status.stderr == ""
        assert status.duration_seconds == 0.369

    def test_gate_conflicting_exit_code_fails_closed(self) -> None:
        fixture = {
            "uuid": "gate-conflict-exit",
            "status": "SUCCESS",
            "metadata": {
                "result": {
                    "exit_code": 0,
                    "state": {"exit_code": 1},
                    "stdout": {"value": "OUT"},
                    "stderr": {"value": ""},
                }
            },
        }

        def transport(req: urllib.request.Request, timeout: float) -> TransportResponse:
            return _make_transport_response(status_code=200, body=fixture)

        adapter = NebiusSandboxAdapter(
            config=SandboxClientConfig(api_key="k", project_id="p"),
            transport=transport,
        )
        with pytest.raises(SandboxResponseFormatError, match="Conflicting exit code fields"):
            adapter.inspect_operation("gate-conflict-exit")

    def test_gate_conflicting_stream_fields_fail_closed(self) -> None:
        adapter = NebiusSandboxAdapter(config=SandboxClientConfig(api_key="k", project_id="p"))
        with pytest.raises(SandboxResponseFormatError, match="Conflicting stream fields"):
            adapter._parse_stream_output({"value": "V1", "data": "V2"})

    def test_gate_malformed_stream_dictionary_fails_closed(self) -> None:
        adapter = NebiusSandboxAdapter(config=SandboxClientConfig(api_key="k", project_id="p"))
        with pytest.raises(SandboxResponseFormatError, match="missing both 'value' and 'data'"):
            adapter._parse_stream_output({"encoding": "ascii", "truncated": False})

    def test_gate_strict_exit_code_types_fail_closed(self) -> None:
        bad_codes: tuple[Any, ...] = ("0", 0.0, 1.7, True, False, [], {})
        for bad_code in bad_codes:

            def transport(req: urllib.request.Request, timeout: float) -> TransportResponse:
                return _make_transport_response(
                    status_code=200,
                    body={
                        "uuid": "gate-bad-exit",
                        "status": "SUCCESS",
                        "metadata": {"result": {"state": {"exit_code": bad_code}}},
                    },
                )

            adapter_inst = NebiusSandboxAdapter(
                config=SandboxClientConfig(api_key="k", project_id="p"),
                transport=transport,
            )
            with pytest.raises(SandboxResponseFormatError, match="must be a strict integer"):
                adapter_inst.inspect_operation("gate-bad-exit")

    def test_gate_strict_stream_content_types_fail_closed(self) -> None:
        adapter = NebiusSandboxAdapter(config=SandboxClientConfig(api_key="k", project_id="p"))
        bad_contents: tuple[Any, ...] = (123, 0.0, True, False, None, ["a"], {"x": 1})
        for bad_content in bad_contents:
            with pytest.raises(SandboxResponseFormatError):
                adapter._parse_stream_output({"value": bad_content})
            with pytest.raises(SandboxResponseFormatError):
                adapter._parse_stream_output({"data": bad_content})
        with pytest.raises(SandboxResponseFormatError):
            adapter._parse_stream_output(456)

    # Gate 4: Teardown semantics
    def test_gate_teardown_semantics(self) -> None:
        cancel_called = []

        def transport(req: urllib.request.Request, timeout: float) -> TransportResponse:
            if "/cancel" in req.full_url:
                cancel_called.append(True)
                return _make_transport_response(status_code=200)
            return _make_transport_response(status_code=200)

        adapter = NebiusSandboxAdapter(
            config=SandboxClientConfig(api_key="k", project_id="p"),
            transport=transport,
        )
        handle = adapter.create_sandbox()
        handle.lifecycle_state = SandboxLifecycleState.RUNNING
        handle.last_operation_id = "op-gate-cancel"

        adapter.teardown_sandbox(handle)
        assert handle.lifecycle_state == SandboxLifecycleState.DISPOSED
        assert len(cancel_called) == 1

        # Execution on disposed handle fails closed
        with pytest.raises(SandboxLifecycleError):
            adapter.execute_command(handle, "echo impossible")

        # Cancellation failure fails closed without marking DISPOSED
        def failing_transport(req: urllib.request.Request, timeout: float) -> TransportResponse:
            return _make_transport_response(status_code=500, body={"error": "Cancel failed"})

        fail_adapter = NebiusSandboxAdapter(
            config=SandboxClientConfig(api_key="k", project_id="p"),
            transport=failing_transport,
        )
        fail_handle = fail_adapter.create_sandbox()
        fail_handle.lifecycle_state = SandboxLifecycleState.RUNNING
        fail_handle.last_operation_id = "op-fail-cancel"

        with pytest.raises(SandboxProviderError):
            fail_adapter.teardown_sandbox(fail_handle)

        assert fail_handle.lifecycle_state == SandboxLifecycleState.RUNNING

        # Verification failure with verify_whoami fails closed without marking DISPOSED
        def whoami_nonzero_transport(
            req: urllib.request.Request, timeout: float
        ) -> TransportResponse:
            return _make_transport_response(
                status_code=200,
                body={"operations_stat": {"running_instances": 1}},
            )

        whoami_adapter = NebiusSandboxAdapter(
            config=SandboxClientConfig(api_key="k", project_id="p"),
            transport=whoami_nonzero_transport,
        )
        whoami_handle = whoami_adapter.create_sandbox()
        with pytest.raises(SandboxAdapterError, match="whoami reports 1 active running instance"):
            whoami_adapter.teardown_sandbox(whoami_handle, verify_whoami=True)

        assert whoami_handle.lifecycle_state != SandboxLifecycleState.DISPOSED

    # Gate 5: Timeout/error handling
    def test_gate_timeout_and_error_handling(self) -> None:
        adapter = NebiusSandboxAdapter(config=SandboxClientConfig(api_key="k", project_id="p"))
        with pytest.raises(SandboxConfigError, match="timeout_seconds"):
            adapter.execute_command(DEFAULT_SANDBOX_IMAGE, "echo hi", timeout_seconds=999)

        # Missing credential fails closed
        adapter_no_cred = NebiusSandboxAdapter(
            config=SandboxClientConfig(api_key=None, project_id=None)
        )
        with pytest.raises(MissingSandboxCredentialError):
            adapter_no_cred.inspect_whoami()

    # Gate 6: Malformed response behavior
    def test_gate_malformed_response_behavior(self) -> None:
        def transport(req: urllib.request.Request, timeout: float) -> TransportResponse:
            return _make_transport_response(status_code=200, body=b"CORRUPT")

        adapter = NebiusSandboxAdapter(
            config=SandboxClientConfig(api_key="k", project_id="p"),
            transport=transport,
        )
        with pytest.raises(SandboxResponseFormatError):
            adapter.inspect_operation("op-corrupt")

    # Gate 7: Secret redaction
    def test_gate_secret_redaction(self) -> None:
        fake_secret = "ghp_FAKEGITHUBSECRET1234567890abcdefghij"

        def transport(req: urllib.request.Request, timeout: float) -> TransportResponse:
            return _make_transport_response(
                status_code=400,
                body={"error": f"Bad token: {fake_secret}"},
            )

        adapter = NebiusSandboxAdapter(
            config=SandboxClientConfig(api_key="k", project_id="p"),
            transport=transport,
        )
        with pytest.raises(SandboxProviderError) as exc_info:
            adapter.inspect_whoami()

        err_text = str(exc_info.value)
        assert fake_secret not in err_text
        assert "[REDACTED" in err_text

    # Gate 8: Deterministic execution fact preservation
    def test_gate_deterministic_execution_fact_preservation(self) -> None:
        def transport(req: urllib.request.Request, timeout: float) -> TransportResponse:
            if "/instances" in req.full_url:
                return _make_transport_response(
                    status_code=201,
                    headers={"Location": "/sandboxes/v1/operations/fact-op"},
                )
            return _make_transport_response(
                status_code=200,
                body={
                    "id": "fact-op",
                    "status": "FAILED",  # Provider says FAILED
                    "error": "Task process exited with code 1",
                    "result": {
                        "exit_code": 1,
                        "duration": 0.5,
                        "stdout": "",
                        "stderr": "FAILED",
                    },
                },
            )

        adapter = NebiusSandboxAdapter(
            config=SandboxClientConfig(api_key="k", project_id="p", poll_interval_seconds=0.01),
            transport=transport,
        )
        result = adapter.execute_command(DEFAULT_SANDBOX_IMAGE, "run-tests")
        normalized = result.to_normalized_record()

        # Deterministic exit code 1 takes precedence over provider status "FAILED"
        assert normalized.outcome == NormalizedExecutionOutcome.NONZERO_EXIT
        assert normalized.exit_code == 1

    # Gate 9: Exactly-once transport behavior & no retry leakage
    def test_gate_exactly_once_transport_behavior(self) -> None:
        call_count = [0]

        def failing_transport(req: urllib.request.Request, timeout: float) -> TransportResponse:
            call_count[0] += 1
            raise urllib.error.URLError("Network unreachable")

        adapter = NebiusSandboxAdapter(
            config=SandboxClientConfig(api_key="k", project_id="p"),
            transport=failing_transport,
        )
        with pytest.raises(SandboxTransportError):
            adapter.inspect_whoami()

        assert call_count[0] == 1, "Exactly one attempt must be made; no retry loops"

    # Gate 10: Provider purity check
    def test_gate_provider_purity(self) -> None:
        src_root = Path(__file__).resolve().parent.parent.parent / "src" / "basebreak"
        for pkg in ("domain", "evidence", "security"):
            for py_file in (src_root / pkg).glob("**/*.py"):
                text = py_file.read_text(encoding="utf-8")
                assert "basebreak.adapters" not in text
                assert "from .adapters" not in text

    # Gate 11: No P-05.03+ implementation leakage
    def test_gate_no_p05_03_plus_leakage(self) -> None:
        sandbox_file = (
            Path(__file__).resolve().parent.parent.parent
            / "src"
            / "basebreak"
            / "adapters"
            / "nebius"
            / "sandbox.py"
        )
        text = sandbox_file.read_text(encoding="utf-8")
        # Ensure no repository cloning, git tree hash verification, or retry policy backoff
        assert "git clone" not in text
        assert "write-tree" not in text
        assert "CommitRevision" not in text
        assert "ExponentialBackoff" not in text
        assert "TelemetryNormalizer" not in text
