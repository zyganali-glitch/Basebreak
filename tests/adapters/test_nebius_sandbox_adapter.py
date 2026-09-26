"""Deterministic unit tests for Nebius Token Factory bounded sandbox adapter.

Provenance: FIXTURE / LOCAL_EXECUTION.
Validates all requirements of P-05.02 without requiring live network credentials.
"""

from __future__ import annotations

import json
import urllib.error
import urllib.request
from typing import Any

import pytest

from basebreak.adapters.nebius import (
    DEFAULT_SANDBOX_API_BASE_URL,
    DEFAULT_SANDBOX_IMAGE,
    NebiusOperationStatus,
    NebiusSandboxAdapter,
    NebiusSandboxExecutionResult,
    NebiusSandboxHandle,
    SandboxAdapterError,
    SandboxClientConfig,
    SandboxConfigError,
    SandboxLifecycleError,
    SandboxLifecycleState,
    SandboxProviderError,
    SandboxResponseFormatError,
    SandboxTimeoutError,
    SandboxTransportError,
    TransportResponse,
)
from basebreak.domain.execution import ExecutionCommand
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


class TestNebiusSandboxAdapter:
    """Test suite covering all P-05.02 bounded sandbox adapter requirements."""

    # 1. Create request and handle semantics
    def test_create_sandbox_handle_initialization(self) -> None:
        adapter = NebiusSandboxAdapter(
            config=SandboxClientConfig(api_key="test-key", project_id="proj-123")
        )
        handle = adapter.create_sandbox(
            image="tag:astral/uv:python3.11-alpine",
            disposable=True,
            description="Test run",
        )
        assert isinstance(handle, NebiusSandboxHandle)
        assert handle.image == "tag:astral/uv:python3.11-alpine"
        assert handle.disposable is True
        assert handle.lifecycle_state == SandboxLifecycleState.CREATED
        assert handle.sandbox_identity.sandbox_id.startswith("sbx-")
        assert handle.sandbox_identity.description == "Test run"
        assert handle.last_operation_id is None
        assert handle.result_image_uuid is None

    def test_create_sandbox_uses_default_image_if_omitted(self) -> None:
        adapter = NebiusSandboxAdapter(
            config=SandboxClientConfig(api_key="test-key", project_id="proj-123")
        )
        handle = adapter.create_sandbox()
        assert handle.image == DEFAULT_SANDBOX_IMAGE

    def test_create_sandbox_rejects_empty_image(self) -> None:
        adapter = NebiusSandboxAdapter(
            config=SandboxClientConfig(api_key="test-key", project_id="proj-123")
        )
        with pytest.raises(SandboxConfigError, match="image must not be empty"):
            adapter.create_sandbox(image="   ")

    # 2. Exec request semantics
    def test_exec_request_semantics_and_headers(self) -> None:
        captured_requests: list[urllib.request.Request] = []

        def fake_transport(req: urllib.request.Request, timeout: float) -> TransportResponse:
            captured_requests.append(req)
            if req.method == "POST" and "/instances" in req.full_url:
                return _make_transport_response(
                    status_code=201,
                    body={"id": "op-001", "status": "PENDING"},
                    headers={"Location": "/sandboxes/v1/operations/op-001"},
                )
            if req.method == "GET" and "/operations/op-001" in req.full_url:
                return _make_transport_response(
                    status_code=200,
                    body={
                        "id": "op-001",
                        "status": "SUCCESS",
                        "metadata": {
                            "result": {
                                "exit_code": 0,
                                "duration": 1.25,
                                "stdout": "HELLO_BASEBREAK\n",
                                "stderr": "",
                                "result_image_uuid": None,
                            }
                        },
                    },
                )
            raise AssertionError(f"Unexpected request: {req.method} {req.full_url}")

        adapter = NebiusSandboxAdapter(
            config=SandboxClientConfig(
                api_key="secret-api-key",
                project_id="proj-abc",
                poll_interval_seconds=0.01,
            ),
            transport=fake_transport,
        )

        handle = adapter.create_sandbox()
        result = adapter.execute_command(
            handle,
            "echo HELLO_BASEBREAK",
            timeout_seconds=60,
        )

        assert isinstance(result, NebiusSandboxExecutionResult)
        assert result.exit_code == 0
        assert result.stdout == "HELLO_BASEBREAK\n"
        assert result.stderr == ""
        assert result.duration_seconds == 1.25
        assert result.is_completed is True
        assert result.is_timeout is False
        assert result.is_cancelled is False
        assert handle.lifecycle_state == SandboxLifecycleState.COMPLETED
        assert handle.last_operation_id == "op-001"

        # Verify spawn request headers and payload
        assert len(captured_requests) >= 2
        spawn_req = captured_requests[0]
        assert spawn_req.method == "POST"
        assert spawn_req.full_url == f"{DEFAULT_SANDBOX_API_BASE_URL}/instances"
        assert spawn_req.headers["Authorization"] == "Bearer secret-api-key"
        assert spawn_req.headers["Project"] == "proj-abc"
        assert spawn_req.headers["Content-type"] == "application/json"

        assert isinstance(spawn_req.data, bytes)
        body = json.loads(spawn_req.data.decode("utf-8"))
        assert body["image"] == DEFAULT_SANDBOX_IMAGE
        assert body["command"] == "echo HELLO_BASEBREAK"
        assert body["shell"] is True
        assert body["disposable"] is True
        assert body["timeout"] == 60
        assert body["networking"] == {"enabled": True}

    def test_exec_with_execution_command_object(self) -> None:
        captured_requests: list[urllib.request.Request] = []

        def fake_transport(req: urllib.request.Request, timeout: float) -> TransportResponse:
            captured_requests.append(req)
            if "/instances" in req.full_url:
                return _make_transport_response(
                    status_code=201,
                    headers={"Location": "/sandboxes/v1/operations/op-ec"},
                )
            return _make_transport_response(
                status_code=200,
                body={
                    "id": "op-ec",
                    "status": "SUCCESS",
                    "result": {"exit_code": 0, "stdout": "OK", "stderr": ""},
                },
            )

        adapter = NebiusSandboxAdapter(
            config=SandboxClientConfig(
                api_key="key", project_id="proj", poll_interval_seconds=0.01
            ),
            transport=fake_transport,
        )

        cmd = ExecutionCommand(
            argv=("python3", "-m", "pytest", "tests/"),
            cwd="workspace/repo",
            env=(("CI", "true"),),
        )
        res = adapter.execute_command(DEFAULT_SANDBOX_IMAGE, cmd)

        assert res.exit_code == 0
        spawn_req = captured_requests[0]
        assert isinstance(spawn_req.data, bytes)
        body = json.loads(spawn_req.data.decode("utf-8"))
        assert "cd workspace/repo && python3 -m pytest tests/" in body["command"]
        assert body["working_dir"] == "workspace/repo"
        assert body["env"] == {"CI": "true"}

    def test_exec_checkpoint_mode_records_result_image_uuid(self) -> None:
        def fake_transport(req: urllib.request.Request, timeout: float) -> TransportResponse:
            if "/instances" in req.full_url:
                return _make_transport_response(
                    status_code=201,
                    headers={"Location": "/sandboxes/v1/operations/op-cp"},
                )
            return _make_transport_response(
                status_code=200,
                body={
                    "id": "op-cp",
                    "status": "SUCCESS",
                    "result": {
                        "exit_code": 0,
                        "duration": 2.0,
                        "stdout": "CHECKPOINT_OK",
                        "stderr": "",
                        "result_image_uuid": "img-uuid-9999",
                    },
                },
            )

        adapter = NebiusSandboxAdapter(
            config=SandboxClientConfig(
                api_key="key", project_id="proj", poll_interval_seconds=0.01
            ),
            transport=fake_transport,
        )

        handle = adapter.create_sandbox(disposable=False)
        result = adapter.execute_command(handle, "echo CHECKPOINT")

        assert result.result_image_uuid == "img-uuid-9999"
        assert handle.result_image_uuid == "img-uuid-9999"
        assert handle.lifecycle_state == SandboxLifecycleState.COMPLETED

    # 3. Inspect semantics
    def test_inspect_operation_parses_contree_output_formats(self) -> None:
        # Test ConTree dictionary stdout format: {"data": "output text", "encoding": "ascii"}
        def fake_transport(req: urllib.request.Request, timeout: float) -> TransportResponse:
            return _make_transport_response(
                status_code=200,
                body={
                    "id": "op-inspect",
                    "status": "SUCCESS",
                    "metadata": {
                        "result": {
                            "exit_code": 0,
                            "duration": 0.5,
                            "stdout": {
                                "data": "CAPTURED_STDOUT\n",
                                "encoding": "ascii",
                                "truncated": False,
                            },
                            "stderr": {"data": "CAPTURED_STDERR\n", "encoding": "ascii"},
                            "result_image_uuid": "img-1234",
                        }
                    },
                },
            )

        adapter = NebiusSandboxAdapter(
            config=SandboxClientConfig(api_key="key", project_id="proj"),
            transport=fake_transport,
        )

        status = adapter.inspect_operation("op-inspect")
        assert isinstance(status, NebiusOperationStatus)
        assert status.operation_id == "op-inspect"
        assert status.status == "SUCCESS"
        assert status.is_terminal is True
        assert status.exit_code == 0
        assert status.duration_seconds == 0.5
        assert status.stdout == "CAPTURED_STDOUT\n"
        assert status.stderr == "CAPTURED_STDERR\n"
        assert status.result_image_uuid == "img-1234"

    def test_inspect_operation_pending_and_running(self) -> None:
        def fake_transport(req: urllib.request.Request, timeout: float) -> TransportResponse:
            return _make_transport_response(
                status_code=200,
                body={"id": "op-run", "status": "RUNNING"},
            )

        adapter = NebiusSandboxAdapter(
            config=SandboxClientConfig(api_key="key", project_id="proj"),
            transport=fake_transport,
        )
        status = adapter.inspect_operation("op-run")
        assert status.status == "RUNNING"
        assert status.is_terminal is False

    # 3b. Live schema repair regression tests (P-05.02 surgical repair)
    def test_inspect_operation_parses_live_schema_exact_facts(self) -> None:
        # Proves A, B, C: nested state.exit_code=0 is int 0, stdout.value parses exact,
        # stderr.value="" remains empty string
        live_fixture = {
            "uuid": "01a0d8ca-28fd-777e-9d32-0907c4cb6f28",
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

        def fake_transport(req: urllib.request.Request, timeout: float) -> TransportResponse:
            return _make_transport_response(status_code=200, body=live_fixture)

        adapter = NebiusSandboxAdapter(
            config=SandboxClientConfig(api_key="key", project_id="proj"),
            transport=fake_transport,
        )

        status = adapter.inspect_operation("01a0d8ca-28fd-777e-9d32-0907c4cb6f28")
        assert isinstance(status, NebiusOperationStatus)
        assert status.status == "SUCCESS"
        assert status.is_terminal is True
        # A: nested state.exit_code = 0 parses exactly as integer 0
        assert isinstance(status.exit_code, int)
        assert status.exit_code == 0
        # B: stdout.value parses exact stdout
        assert status.stdout == "HELLO_SANDBOX\n"
        # C: stderr.value="" remains exact empty string
        assert status.stderr == ""
        # Duration parsed from payload level
        assert status.duration_seconds == 0.369

    def test_inspect_operation_nested_nonzero_exit_code(self) -> None:
        # Proves D: terminal SUCCESS + nested nonzero exit code preserves the nonzero code
        fixture = {
            "uuid": "op-nonzero-nested",
            "status": "SUCCESS",
            "metadata": {
                "result": {
                    "state": {
                        "exit_code": 42,
                        "pid": 12,
                        "signal": -1,
                        "timed_out": False,
                    },
                    "stdout": {"value": ""},
                    "stderr": {"value": "error details\n"},
                }
            },
        }

        def fake_transport(req: urllib.request.Request, timeout: float) -> TransportResponse:
            return _make_transport_response(status_code=200, body=fixture)

        adapter = NebiusSandboxAdapter(
            config=SandboxClientConfig(api_key="key", project_id="proj"),
            transport=fake_transport,
        )
        status = adapter.inspect_operation("op-nonzero-nested")
        assert status.status == "SUCCESS"
        assert status.exit_code == 42
        assert status.stderr == "error details\n"

    def test_inspect_operation_direct_legacy_exit_code_preserved(self) -> None:
        # Proves E: direct legacy exit_code still parses if retained
        fixture = {
            "uuid": "op-legacy-direct",
            "status": "SUCCESS",
            "metadata": {
                "result": {
                    "exit_code": 0,
                    "stdout": "direct-stdout\n",
                    "stderr": "",
                }
            },
        }

        def fake_transport(req: urllib.request.Request, timeout: float) -> TransportResponse:
            return _make_transport_response(status_code=200, body=fixture)

        adapter = NebiusSandboxAdapter(
            config=SandboxClientConfig(api_key="key", project_id="proj"),
            transport=fake_transport,
        )
        status = adapter.inspect_operation("op-legacy-direct")
        assert status.exit_code == 0
        assert status.stdout == "direct-stdout\n"

    # Focused tests proving strict fail-closed exit-code and stream semantics (A through O)
    def test_a_nested_exit_code_int_0_parses_as_0(self) -> None:
        # A: nested exit_code int 0 parses as 0
        fixture = {
            "uuid": "op-a",
            "status": "SUCCESS",
            "metadata": {
                "result": {
                    "state": {"exit_code": 0},
                    "stdout": {"value": "ok\n"},
                    "stderr": {"value": ""},
                }
            },
        }

        def fake_transport(req: urllib.request.Request, timeout: float) -> TransportResponse:
            return _make_transport_response(status_code=200, body=fixture)

        adapter = NebiusSandboxAdapter(
            config=SandboxClientConfig(api_key="k", project_id="p"),
            transport=fake_transport,
        )
        status = adapter.inspect_operation("op-a")
        assert status.exit_code == 0
        assert type(status.exit_code) is int

    def test_b_nested_exit_code_string_fails_closed(self) -> None:
        # B: nested exit_code string "0" fails closed
        fixture = {
            "uuid": "op-b",
            "status": "SUCCESS",
            "metadata": {
                "result": {
                    "state": {"exit_code": "0"},
                    "stdout": {"value": "ok\n"},
                    "stderr": {"value": ""},
                }
            },
        }

        def fake_transport(req: urllib.request.Request, timeout: float) -> TransportResponse:
            return _make_transport_response(status_code=200, body=fixture)

        adapter = NebiusSandboxAdapter(
            config=SandboxClientConfig(api_key="k", project_id="p"),
            transport=fake_transport,
        )
        with pytest.raises(SandboxResponseFormatError, match="must be a strict integer"):
            adapter.inspect_operation("op-b")

    def test_c_nested_exit_code_float_fails_closed(self) -> None:
        # C: nested exit_code float 0.0 fails closed
        fixture = {
            "uuid": "op-c",
            "status": "SUCCESS",
            "metadata": {
                "result": {
                    "state": {"exit_code": 0.0},
                    "stdout": {"value": "ok\n"},
                    "stderr": {"value": ""},
                }
            },
        }

        def fake_transport(req: urllib.request.Request, timeout: float) -> TransportResponse:
            return _make_transport_response(status_code=200, body=fixture)

        adapter = NebiusSandboxAdapter(
            config=SandboxClientConfig(api_key="k", project_id="p"),
            transport=fake_transport,
        )
        with pytest.raises(SandboxResponseFormatError, match="must be a strict integer"):
            adapter.inspect_operation("op-c")

    def test_d_nested_exit_code_bool_fails_closed(self) -> None:
        # D: nested exit_code bool False and True fail closed
        for b_val in (False, True):
            fixture = {
                "uuid": "op-d",
                "status": "SUCCESS",
                "metadata": {
                    "result": {
                        "state": {"exit_code": b_val},
                        "stdout": {"value": "ok\n"},
                        "stderr": {"value": ""},
                    }
                },
            }

            def fake_transport(req: urllib.request.Request, timeout: float) -> TransportResponse:
                return _make_transport_response(status_code=200, body=fixture)

            adapter = NebiusSandboxAdapter(
                config=SandboxClientConfig(api_key="k", project_id="p"),
                transport=fake_transport,
            )
            with pytest.raises(SandboxResponseFormatError, match="must be a strict integer"):
                adapter.inspect_operation("op-d")

    def test_e_direct_exit_code_string_fails_closed(self) -> None:
        # E: direct exit_code string "1" fails closed
        bad_values: tuple[Any, ...] = ("1", 0.0, False, [], {})
        for malformed in bad_values:
            fixture = {
                "uuid": "op-e",
                "status": "SUCCESS",
                "metadata": {
                    "result": {
                        "exit_code": malformed,
                        "stdout": {"value": "ok\n"},
                        "stderr": {"value": ""},
                    }
                },
            }

            def fake_transport(req: urllib.request.Request, timeout: float) -> TransportResponse:
                return _make_transport_response(status_code=200, body=fixture)

            adapter = NebiusSandboxAdapter(
                config=SandboxClientConfig(api_key="k", project_id="p"),
                transport=fake_transport,
            )
            with pytest.raises(SandboxResponseFormatError, match="must be a strict integer"):
                adapter.inspect_operation("op-e")

    def test_f_direct_and_nested_equal_real_ints_accepted(self) -> None:
        # F: direct + nested equal real ints accepted
        fixture = {
            "uuid": "op-equal-exit",
            "status": "SUCCESS",
            "metadata": {
                "result": {
                    "exit_code": 0,
                    "state": {"exit_code": 0},
                    "stdout": {"value": "OK"},
                    "stderr": {"value": ""},
                }
            },
        }

        def fake_transport(req: urllib.request.Request, timeout: float) -> TransportResponse:
            return _make_transport_response(status_code=200, body=fixture)

        adapter = NebiusSandboxAdapter(
            config=SandboxClientConfig(api_key="key", project_id="proj"),
            transport=fake_transport,
        )
        status = adapter.inspect_operation("op-equal-exit")
        assert status.exit_code == 0
        assert type(status.exit_code) is int

    def test_g_direct_valid_int_nested_malformed_string_fails_closed(self) -> None:
        # G: direct valid int + nested malformed string fails closed
        fixture = {
            "uuid": "op-conflict-exit",
            "status": "SUCCESS",
            "metadata": {
                "result": {
                    "exit_code": 0,
                    "state": {"exit_code": "0"},
                    "stdout": {"value": "CONFLICT"},
                    "stderr": {"value": ""},
                }
            },
        }

        def fake_transport(req: urllib.request.Request, timeout: float) -> TransportResponse:
            return _make_transport_response(status_code=200, body=fixture)

        adapter = NebiusSandboxAdapter(
            config=SandboxClientConfig(api_key="key", project_id="proj"),
            transport=fake_transport,
        )
        with pytest.raises(SandboxResponseFormatError, match="must be a strict integer"):
            adapter.inspect_operation("op-conflict-exit")

    def test_direct_and_nested_unequal_real_ints_fails_closed(self) -> None:
        fixture = {
            "uuid": "op-unequal-exit",
            "status": "SUCCESS",
            "metadata": {
                "result": {
                    "exit_code": 0,
                    "state": {"exit_code": 1},
                    "stdout": {"value": "CONFLICT"},
                    "stderr": {"value": ""},
                }
            },
        }

        def fake_transport(req: urllib.request.Request, timeout: float) -> TransportResponse:
            return _make_transport_response(status_code=200, body=fixture)

        adapter = NebiusSandboxAdapter(
            config=SandboxClientConfig(api_key="key", project_id="proj"),
            transport=fake_transport,
        )
        with pytest.raises(SandboxResponseFormatError, match="Conflicting exit code fields"):
            adapter.inspect_operation("op-unequal-exit")

    def test_h_stdout_value_empty_string_remains_exact_empty_string(self) -> None:
        # H: stdout.value="" remains exact empty string
        adapter = NebiusSandboxAdapter(config=SandboxClientConfig(api_key="k", project_id="p"))
        assert adapter._parse_stream_output({"value": ""}) == ""

    def test_i_stdout_value_none_fails_closed(self) -> None:
        # I: stdout.value=None fails closed
        adapter = NebiusSandboxAdapter(config=SandboxClientConfig(api_key="k", project_id="p"))
        with pytest.raises(SandboxResponseFormatError, match="'value' field must be a string"):
            adapter._parse_stream_output({"value": None})

    def test_j_stdout_value_int_fails_closed(self) -> None:
        # J: stdout.value=123 fails closed
        adapter = NebiusSandboxAdapter(config=SandboxClientConfig(api_key="k", project_id="p"))
        with pytest.raises(SandboxResponseFormatError, match="'value' field must be a string"):
            adapter._parse_stream_output({"value": 123})

    def test_k_stdout_value_dict_fails_closed(self) -> None:
        # K: stdout.value={"x": 1} fails closed
        adapter = NebiusSandboxAdapter(config=SandboxClientConfig(api_key="k", project_id="p"))
        with pytest.raises(SandboxResponseFormatError, match="'value' field must be a string"):
            adapter._parse_stream_output({"value": {"x": 1}})

    def test_l_legacy_data_field_strict_string(self) -> None:
        # L: legacy data field must also be strict string
        adapter = NebiusSandboxAdapter(config=SandboxClientConfig(api_key="k", project_id="p"))
        assert adapter._parse_stream_output({"data": "LEGACY_OK\n"}) == "LEGACY_OK\n"
        with pytest.raises(SandboxResponseFormatError, match="'data' field must be a string"):
            adapter._parse_stream_output({"data": 123})
        with pytest.raises(SandboxResponseFormatError, match="'data' field must be a string"):
            adapter._parse_stream_output({"data": None})
        with pytest.raises(SandboxResponseFormatError, match="'data' field must be a string"):
            adapter._parse_stream_output({"data": ["a", "b"]})

    def test_m_value_data_identical_strings_accepted(self) -> None:
        # M: value/data identical strings accepted
        adapter = NebiusSandboxAdapter(config=SandboxClientConfig(api_key="k", project_id="p"))
        parsed = adapter._parse_stream_output({"value": "MATCH\n", "data": "MATCH\n"})
        assert parsed == "MATCH\n"

    def test_n_value_data_where_either_side_is_non_string_fails_closed(self) -> None:
        # N: value/data where either side is non-string fails closed
        adapter = NebiusSandboxAdapter(config=SandboxClientConfig(api_key="k", project_id="p"))
        with pytest.raises(SandboxResponseFormatError, match="'data' field must be a string"):
            adapter._parse_stream_output({"value": "VALID", "data": 123})
        with pytest.raises(SandboxResponseFormatError, match="'value' field must be a string"):
            adapter._parse_stream_output({"value": 123, "data": "VALID"})
        with pytest.raises(SandboxResponseFormatError, match="'value' field must be a string"):
            adapter._parse_stream_output({"value": None, "data": "VALID"})
        with pytest.raises(SandboxResponseFormatError, match="'data' field must be a string"):
            adapter._parse_stream_output({"value": "VALID", "data": None})

    def test_o_value_data_conflicting_strings_fail_closed(self) -> None:
        # O: value/data conflicting strings fail closed
        adapter = NebiusSandboxAdapter(config=SandboxClientConfig(api_key="k", project_id="p"))
        with pytest.raises(SandboxResponseFormatError, match="Conflicting stream fields"):
            adapter._parse_stream_output({"value": "VAL_1", "data": "VAL_2"})

    def test_stream_output_malformed_mapping_fails_closed(self) -> None:
        adapter = NebiusSandboxAdapter(config=SandboxClientConfig(api_key="k", project_id="p"))
        with pytest.raises(SandboxResponseFormatError, match="missing both 'value' and 'data'"):
            adapter._parse_stream_output({"encoding": "ascii", "truncated": False})

        with pytest.raises(SandboxResponseFormatError, match="Unsupported stream output type"):
            adapter._parse_stream_output(12345)

    def test_execute_command_with_live_schema_fixture(self) -> None:
        # Proves K: execute_command() over fixture matching current live schema produces exact facts
        live_fixture = {
            "uuid": "01a0d8ca-exec-live",
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

        def fake_transport(req: urllib.request.Request, timeout: float) -> TransportResponse:
            if "/instances" in req.full_url:
                return _make_transport_response(
                    status_code=201,
                    headers={"Location": "/sandboxes/v1/operations/01a0d8ca-exec-live"},
                )
            return _make_transport_response(status_code=200, body=live_fixture)

        adapter = NebiusSandboxAdapter(
            config=SandboxClientConfig(
                api_key="key", project_id="proj", poll_interval_seconds=0.01
            ),
            transport=fake_transport,
        )
        result = adapter.execute_command(DEFAULT_SANDBOX_IMAGE, "echo HELLO_SANDBOX")
        assert isinstance(result, NebiusSandboxExecutionResult)
        assert result.exit_code == 0
        assert result.stdout == "HELLO_SANDBOX\n"
        assert result.stderr == ""
        assert result.duration_seconds == 0.369
        assert result.provider_status == "SUCCESS"
        assert result.is_completed is True
        assert result.is_timeout is False
        assert result.is_cancelled is False

    def test_materialization_with_live_schema_fixture_succeeds(self) -> None:
        # Proves L: materialization no longer interprets a live-shaped exit_code=0 result
        # as exit_code=None
        from basebreak.adapters.nebius.materialization import NebiusSourceMaterializer
        from basebreak.domain.source import CommitRevision, SourceIdentity

        target_commit = "68b825802f345a7d4fe6402748fbff447fdf187c"
        target_tree = "27e8537391a96af3233d11ffc351afae1c430810"
        stdout_payload = (
            f"CLONE_START\n"
            f"BASEBREAK_RESOLVED_COMMIT={target_commit}\n"
            f"BASEBREAK_RESOLVED_TREE={target_tree}\n"
            f"CLONE_SUCCESS\n"
        )
        live_materialization_fixture = {
            "uuid": "01a0d8ca-mat-live",
            "kind": "instance",
            "status": "SUCCESS",
            "duration": 1.2,
            "metadata": {
                "command": "git clone ...",
                "result": {
                    "state": {
                        "exit_code": 0,
                        "pid": 10,
                        "signal": -1,
                        "timed_out": False,
                    },
                    "stdout": {
                        "value": stdout_payload,
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

        def fake_transport(req: urllib.request.Request, timeout: float) -> TransportResponse:
            if "/instances" in req.full_url:
                return _make_transport_response(
                    status_code=201,
                    headers={"Location": "/sandboxes/v1/operations/01a0d8ca-mat-live"},
                )
            return _make_transport_response(status_code=200, body=live_materialization_fixture)

        adapter = NebiusSandboxAdapter(
            config=SandboxClientConfig(
                api_key="key", project_id="proj", poll_interval_seconds=0.01
            ),
            transport=fake_transport,
        )
        materializer = NebiusSourceMaterializer(adapter)
        source = SourceIdentity(
            locator="https://github.com/zyganali-glitch/Basebreak.git",
            revision=CommitRevision(commit_id=target_commit),
        )
        record = materializer.materialize_repository(source)
        assert record.resolved_commit_sha == target_commit
        assert record.resolved_tree_sha == target_tree
        assert record.source_identity == source

    def test_live_schema_execution_no_automatic_retry(self) -> None:
        # Proves M: no automatic retry is introduced
        call_counts: dict[str, int] = {"spawn": 0, "inspect": 0}

        def fake_transport(req: urllib.request.Request, timeout: float) -> TransportResponse:
            if "/instances" in req.full_url:
                call_counts["spawn"] += 1
                return _make_transport_response(
                    status_code=201,
                    headers={"Location": "/sandboxes/v1/operations/op-live-no-retry"},
                )
            if "/operations/" in req.full_url:
                call_counts["inspect"] += 1
                return _make_transport_response(
                    status_code=200,
                    body={
                        "uuid": "op-live-no-retry",
                        "status": "SUCCESS",
                        "metadata": {
                            "result": {
                                "state": {"exit_code": 0},
                                "stdout": {"value": "OK"},
                                "stderr": {"value": ""},
                            }
                        },
                    },
                )
            raise AssertionError(f"Unexpected: {req.full_url}")

        adapter = NebiusSandboxAdapter(
            config=SandboxClientConfig(
                api_key="key", project_id="proj", poll_interval_seconds=0.01
            ),
            transport=fake_transport,
        )
        result = adapter.execute_command(DEFAULT_SANDBOX_IMAGE, "echo hi")
        assert result.exit_code == 0
        assert call_counts["spawn"] == 1
        assert call_counts["inspect"] == 1

    # 4. Teardown semantics
    def test_teardown_cancels_running_operation_and_disposes(self) -> None:
        cancel_called = []

        def fake_transport(req: urllib.request.Request, timeout: float) -> TransportResponse:
            if "/cancel" in req.full_url:
                cancel_called.append(req.full_url)
                return _make_transport_response(status_code=200)
            return _make_transport_response(status_code=200)

        adapter = NebiusSandboxAdapter(
            config=SandboxClientConfig(api_key="key", project_id="proj"),
            transport=fake_transport,
        )

        handle = adapter.create_sandbox()
        handle.lifecycle_state = SandboxLifecycleState.RUNNING
        handle.last_operation_id = "op-inflight"

        adapter.teardown_sandbox(handle)
        assert handle.lifecycle_state == SandboxLifecycleState.DISPOSED
        assert len(cancel_called) == 1
        assert "op-inflight/cancel" in cancel_called[0]

        # Executing on disposed handle fails closed
        with pytest.raises(SandboxLifecycleError, match="Cannot execute command on disposed"):
            adapter.execute_command(handle, "echo should_fail")

    def test_teardown_is_idempotent(self) -> None:
        adapter = NebiusSandboxAdapter(config=SandboxClientConfig(api_key="key", project_id="proj"))
        handle = adapter.create_sandbox()
        handle.lifecycle_state = SandboxLifecycleState.DISPOSED
        # Must not raise
        adapter.teardown_sandbox(handle)
        assert handle.lifecycle_state == SandboxLifecycleState.DISPOSED

    def test_teardown_cancellation_transport_failure_does_not_dispose(self) -> None:
        def fake_transport(req: urllib.request.Request, timeout: float) -> TransportResponse:
            raise urllib.error.URLError("Connection refused")

        adapter = NebiusSandboxAdapter(
            config=SandboxClientConfig(api_key="key", project_id="proj"),
            transport=fake_transport,
        )
        handle = adapter.create_sandbox()
        handle.lifecycle_state = SandboxLifecycleState.RUNNING
        handle.last_operation_id = "op-fail-transport"

        with pytest.raises(SandboxTransportError):
            adapter.teardown_sandbox(handle)

        assert handle.lifecycle_state == SandboxLifecycleState.RUNNING

    def test_teardown_cancellation_timeout_does_not_dispose(self) -> None:
        def fake_transport(req: urllib.request.Request, timeout: float) -> TransportResponse:
            raise TimeoutError("Cancellation timed out")

        adapter = NebiusSandboxAdapter(
            config=SandboxClientConfig(api_key="key", project_id="proj"),
            transport=fake_transport,
        )
        handle = adapter.create_sandbox()
        handle.lifecycle_state = SandboxLifecycleState.RUNNING
        handle.last_operation_id = "op-fail-timeout"

        with pytest.raises(SandboxTimeoutError):
            adapter.teardown_sandbox(handle)

        assert handle.lifecycle_state == SandboxLifecycleState.RUNNING

    def test_teardown_cancellation_provider_error_does_not_dispose(self) -> None:
        def fake_transport(req: urllib.request.Request, timeout: float) -> TransportResponse:
            return _make_transport_response(
                status_code=500,
                body={"error": "Internal Server Error"},
            )

        adapter = NebiusSandboxAdapter(
            config=SandboxClientConfig(api_key="key", project_id="proj"),
            transport=fake_transport,
        )
        handle = adapter.create_sandbox()
        handle.lifecycle_state = SandboxLifecycleState.RUNNING
        handle.last_operation_id = "op-fail-provider"

        with pytest.raises(SandboxProviderError) as exc_info:
            adapter.teardown_sandbox(handle)

        assert exc_info.value.status_code == 500
        assert handle.lifecycle_state == SandboxLifecycleState.RUNNING

    def test_teardown_cancellation_unconfirmed_status_does_not_dispose(self) -> None:
        def fake_transport(req: urllib.request.Request, timeout: float) -> TransportResponse:
            # 206 is non-standard for cancel confirmation
            return _make_transport_response(status_code=206)

        adapter = NebiusSandboxAdapter(
            config=SandboxClientConfig(api_key="key", project_id="proj"),
            transport=fake_transport,
        )
        handle = adapter.create_sandbox()
        handle.lifecycle_state = SandboxLifecycleState.RUNNING
        handle.last_operation_id = "op-unconfirmed"

        with pytest.raises(SandboxAdapterError, match="returned unconfirmed status"):
            adapter.teardown_sandbox(handle)

        assert handle.lifecycle_state == SandboxLifecycleState.RUNNING

    def test_teardown_running_without_operation_id_fails_closed(self) -> None:
        adapter = NebiusSandboxAdapter(config=SandboxClientConfig(api_key="key", project_id="proj"))
        handle = adapter.create_sandbox()
        handle.lifecycle_state = SandboxLifecycleState.RUNNING
        handle.last_operation_id = None

        with pytest.raises(SandboxLifecycleError, match="missing operation ID"):
            adapter.teardown_sandbox(handle)

        assert handle.lifecycle_state == SandboxLifecycleState.RUNNING

    def test_teardown_verify_whoami_success(self) -> None:
        def fake_transport(req: urllib.request.Request, timeout: float) -> TransportResponse:
            return _make_transport_response(
                status_code=200,
                body={"operations_stat": {"running_instances": 0}},
            )

        adapter = NebiusSandboxAdapter(
            config=SandboxClientConfig(api_key="key", project_id="proj"),
            transport=fake_transport,
        )
        handle = adapter.create_sandbox()
        adapter.teardown_sandbox(handle, verify_whoami=True)
        assert handle.lifecycle_state == SandboxLifecycleState.DISPOSED

    def test_teardown_verify_whoami_nonzero_running_fails_closed(self) -> None:
        def fake_transport(req: urllib.request.Request, timeout: float) -> TransportResponse:
            return _make_transport_response(
                status_code=200,
                body={"operations_stat": {"running_instances": 2}},
            )

        adapter = NebiusSandboxAdapter(
            config=SandboxClientConfig(api_key="key", project_id="proj"),
            transport=fake_transport,
        )
        handle = adapter.create_sandbox()

        with pytest.raises(SandboxAdapterError, match="whoami reports 2 active running instance"):
            adapter.teardown_sandbox(handle, verify_whoami=True)

        assert handle.lifecycle_state != SandboxLifecycleState.DISPOSED

    def test_teardown_verify_whoami_malformed_fails_closed(self) -> None:
        def fake_transport(req: urllib.request.Request, timeout: float) -> TransportResponse:
            return _make_transport_response(
                status_code=200,
                body={"user": "test"},  # Missing operations_stat
            )

        adapter = NebiusSandboxAdapter(
            config=SandboxClientConfig(api_key="key", project_id="proj"),
            transport=fake_transport,
        )
        handle = adapter.create_sandbox()

        with pytest.raises(
            SandboxResponseFormatError, match="missing or invalid 'operations_stat'"
        ):
            adapter.teardown_sandbox(handle, verify_whoami=True)

        assert handle.lifecycle_state != SandboxLifecycleState.DISPOSED

    def test_teardown_verify_whoami_transport_failure_does_not_dispose(self) -> None:
        def fake_transport(req: urllib.request.Request, timeout: float) -> TransportResponse:
            return _make_transport_response(
                status_code=503,
                body={"error": "Whoami temporarily down"},
            )

        adapter = NebiusSandboxAdapter(
            config=SandboxClientConfig(api_key="key", project_id="proj"),
            transport=fake_transport,
        )
        handle = adapter.create_sandbox()

        with pytest.raises(SandboxProviderError):
            adapter.teardown_sandbox(handle, verify_whoami=True)

        assert handle.lifecycle_state != SandboxLifecycleState.DISPOSED

    def test_teardown_no_automatic_retry(self) -> None:
        calls: list[str] = []

        def fake_transport(req: urllib.request.Request, timeout: float) -> TransportResponse:
            calls.append(req.full_url)
            return _make_transport_response(status_code=500, body={"error": "Server error"})

        adapter = NebiusSandboxAdapter(
            config=SandboxClientConfig(api_key="key", project_id="proj"),
            transport=fake_transport,
        )
        handle = adapter.create_sandbox()
        handle.lifecycle_state = SandboxLifecycleState.RUNNING
        handle.last_operation_id = "op-no-retry"

        with pytest.raises(SandboxProviderError):
            adapter.teardown_sandbox(handle)

        assert len(calls) == 1

    def test_teardown_secret_safety_in_cancellation_error(self) -> None:
        secret = "sk-nebius-secret-key-abcdef987654321"

        def fake_transport(req: urllib.request.Request, timeout: float) -> TransportResponse:
            return _make_transport_response(
                status_code=500,
                body={"error": f"Failed with auth key: {secret}"},
            )

        adapter = NebiusSandboxAdapter(
            config=SandboxClientConfig(api_key="key", project_id="proj"),
            transport=fake_transport,
        )
        handle = adapter.create_sandbox()
        handle.lifecycle_state = SandboxLifecycleState.RUNNING
        handle.last_operation_id = "op-secret"

        with pytest.raises(SandboxProviderError) as exc_info:
            adapter.teardown_sandbox(handle)

        assert secret not in str(exc_info.value)
        assert "[REDACTED" in str(exc_info.value)

    # 5. Timeout & error handling
    def test_timeout_bounds_enforced(self) -> None:
        adapter = NebiusSandboxAdapter(config=SandboxClientConfig(api_key="key", project_id="proj"))
        handle = adapter.create_sandbox()

        with pytest.raises(SandboxConfigError, match="timeout_seconds must be between"):
            adapter.execute_command(handle, "echo hi", timeout_seconds=0)

        with pytest.raises(SandboxConfigError, match="timeout_seconds must be between"):
            adapter.execute_command(handle, "echo hi", timeout_seconds=601)

    def test_command_length_budget_enforced(self) -> None:
        adapter = NebiusSandboxAdapter(config=SandboxClientConfig(api_key="key", project_id="proj"))
        huge_cmd = "a" * 16385
        with pytest.raises(SandboxConfigError, match="Command exceeds length budget"):
            adapter.execute_command(DEFAULT_SANDBOX_IMAGE, huge_cmd)

    def test_command_rejects_null_bytes(self) -> None:
        adapter = NebiusSandboxAdapter(config=SandboxClientConfig(api_key="key", project_id="proj"))
        with pytest.raises(SandboxConfigError, match="Command must not contain null bytes"):
            adapter.execute_command(DEFAULT_SANDBOX_IMAGE, "echo hello\x00world")

    def test_client_side_polling_timeout_raises_and_cancels(self) -> None:
        cancelled = []

        def fake_transport(req: urllib.request.Request, timeout: float) -> TransportResponse:
            if "/instances" in req.full_url:
                return _make_transport_response(
                    status_code=201,
                    headers={"Location": "/sandboxes/v1/operations/op-slow"},
                )
            if "/cancel" in req.full_url:
                cancelled.append(True)
                return _make_transport_response(status_code=200)
            # Never completes
            return _make_transport_response(
                status_code=200,
                body={"id": "op-slow", "status": "RUNNING"},
            )

        adapter = NebiusSandboxAdapter(
            config=SandboxClientConfig(
                api_key="key",
                project_id="proj",
                default_timeout_seconds=1,  # 1 second timeout
                poll_interval_seconds=0.01,
            ),
            transport=fake_transport,
        )

        handle = adapter.create_sandbox()
        with pytest.raises(SandboxTimeoutError, match="timed out after"):
            adapter.execute_command(handle, "sleep 100", timeout_seconds=1)

        assert len(cancelled) == 1
        assert handle.lifecycle_state == SandboxLifecycleState.FAILED

    # 6. Malformed response behavior
    def test_spawn_missing_location_header_and_body_id_fails_closed(self) -> None:
        def fake_transport(req: urllib.request.Request, timeout: float) -> TransportResponse:
            return _make_transport_response(status_code=201, body=b"")

        adapter = NebiusSandboxAdapter(
            config=SandboxClientConfig(api_key="key", project_id="proj"),
            transport=fake_transport,
        )
        with pytest.raises(SandboxResponseFormatError, match="Could not extract operation ID"):
            adapter.execute_command(DEFAULT_SANDBOX_IMAGE, "echo hi")

    def test_inspect_invalid_json_fails_closed(self) -> None:
        def fake_transport(req: urllib.request.Request, timeout: float) -> TransportResponse:
            return _make_transport_response(status_code=200, body=b"NOT_JSON{")

        adapter = NebiusSandboxAdapter(
            config=SandboxClientConfig(api_key="key", project_id="proj"),
            transport=fake_transport,
        )
        with pytest.raises(SandboxResponseFormatError, match="not valid JSON"):
            adapter.inspect_operation("op-123")

    def test_inspect_missing_status_fails_closed(self) -> None:
        def fake_transport(req: urllib.request.Request, timeout: float) -> TransportResponse:
            return _make_transport_response(status_code=200, body={"id": "op-123"})

        adapter = NebiusSandboxAdapter(
            config=SandboxClientConfig(api_key="key", project_id="proj"),
            transport=fake_transport,
        )
        with pytest.raises(SandboxResponseFormatError, match="missing 'status' field"):
            adapter.inspect_operation("op-123")

    # 7. Secret safety & redaction
    def test_sensitive_env_keys_rejected_before_spawn(self) -> None:
        call_count = [0]

        def fake_transport(req: urllib.request.Request, timeout: float) -> TransportResponse:
            call_count[0] += 1
            return _make_transport_response(status_code=200)

        adapter = NebiusSandboxAdapter(
            config=SandboxClientConfig(api_key="key", project_id="proj"),
            transport=fake_transport,
        )

        with pytest.raises(SandboxConfigError, match="Secret-shaped or sensitive key forbidden"):
            adapter.execute_command(
                DEFAULT_SANDBOX_IMAGE,
                "echo hi",
                env={"NEBIUS_API_KEY": "sk-synthetic-secret-12345"},
            )

        assert call_count[0] == 0, "No network request must be made when secrets are present"

    def test_provider_error_message_redacted(self) -> None:
        synthetic_secret = "ghp_1234567890abcdefghijklmnopqrstuvwxyz"

        def fake_transport(req: urllib.request.Request, timeout: float) -> TransportResponse:
            return _make_transport_response(
                status_code=403,
                body=f"Failed due to token {synthetic_secret}",
            )

        adapter = NebiusSandboxAdapter(
            config=SandboxClientConfig(api_key="key", project_id="proj"),
            transport=fake_transport,
        )

        with pytest.raises(SandboxProviderError) as exc_info:
            adapter.inspect_whoami()

        err_str = str(exc_info.value)
        assert synthetic_secret not in err_str
        assert "[REDACTED" in err_str

    def test_repr_never_leaks_api_key(self) -> None:
        cfg = SandboxClientConfig(api_key="real-sensitive-key-999", project_id="proj-1")
        cfg_repr = repr(cfg)
        assert "real-sensitive-key-999" not in cfg_repr
        assert "***" in cfg_repr

    # 8. Deterministic execution fact preservation & normalization
    def test_deterministic_execution_facts_preserved_over_provider_prose(self) -> None:
        def fake_transport(req: urllib.request.Request, timeout: float) -> TransportResponse:
            if "/instances" in req.full_url:
                return _make_transport_response(
                    status_code=201,
                    headers={"Location": "/sandboxes/v1/operations/op-nonzero"},
                )
            return _make_transport_response(
                status_code=200,
                body={
                    "id": "op-nonzero",
                    "status": "FAILED",  # Provider says FAILED
                    "error": "Command exited with status 1",
                    "result": {
                        "exit_code": 1,  # Deterministic fact: exit code 1
                        "duration": 0.45,
                        "stdout": "",
                        "stderr": "AssertionError: test failed",
                    },
                },
            )

        adapter = NebiusSandboxAdapter(
            config=SandboxClientConfig(
                api_key="key", project_id="proj", poll_interval_seconds=0.01
            ),
            transport=fake_transport,
        )

        result = adapter.execute_command(DEFAULT_SANDBOX_IMAGE, "pytest")
        assert result.exit_code == 1
        assert result.duration_seconds == 0.45
        assert result.stderr == "AssertionError: test failed"
        assert result.provider_status == "FAILED"

        # Authority boundary: normalize_execution_result must classify as NONZERO_EXIT,
        # NOT as FAILED_TO_START or UNKNOWN_PROVIDER_FAILURE!
        normalized = result.to_normalized_record()
        assert normalized.outcome == NormalizedExecutionOutcome.NONZERO_EXIT
        assert normalized.exit_code == 1

    def test_platform_failed_to_start_normalized(self) -> None:
        def fake_transport(req: urllib.request.Request, timeout: float) -> TransportResponse:
            if "/instances" in req.full_url:
                return _make_transport_response(
                    status_code=201,
                    headers={"Location": "/sandboxes/v1/operations/op-nostart"},
                )
            return _make_transport_response(
                status_code=200,
                body={
                    "id": "op-nostart",
                    "status": "FAILED",
                    "error": "Failed to pull image: not found",
                    "result": None,
                },
            )

        adapter = NebiusSandboxAdapter(
            config=SandboxClientConfig(
                api_key="key", project_id="proj", poll_interval_seconds=0.01
            ),
            transport=fake_transport,
        )

        result = adapter.execute_command(DEFAULT_SANDBOX_IMAGE, "echo hi")
        assert result.exit_code is None
        assert result.provider_status == "FAILED"

        normalized = result.to_normalized_record()
        assert normalized.outcome == NormalizedExecutionOutcome.FAILED_TO_START

    # 9. Exactly-once transport behavior (no silent retry loops)
    def test_exactly_once_transport_call_per_action(self) -> None:
        call_counts: dict[str, int] = {"whoami": 0, "inspect": 0, "cancel": 0}

        def fake_transport(req: urllib.request.Request, timeout: float) -> TransportResponse:
            if "/whoami" in req.full_url:
                call_counts["whoami"] += 1
                return _make_transport_response(status_code=200, body={"operations_stat": {}})
            if "/cancel" in req.full_url:
                call_counts["cancel"] += 1
                return _make_transport_response(status_code=200)
            if "/operations/" in req.full_url:
                call_counts["inspect"] += 1
                return _make_transport_response(
                    status_code=200,
                    body={"id": "op-1", "status": "SUCCESS", "result": {"exit_code": 0}},
                )
            raise AssertionError(f"Unexpected: {req.full_url}")

        adapter = NebiusSandboxAdapter(
            config=SandboxClientConfig(api_key="key", project_id="proj"),
            transport=fake_transport,
        )

        adapter.inspect_whoami()
        assert call_counts["whoami"] == 1

        adapter.inspect_operation("op-1")
        assert call_counts["inspect"] == 1

        adapter.cancel_operation("op-1")
        assert call_counts["cancel"] == 1

    def test_transport_error_does_not_retry_at_this_layer(self) -> None:
        call_count = [0]

        def failing_transport(req: urllib.request.Request, timeout: float) -> TransportResponse:
            call_count[0] += 1
            raise urllib.error.URLError("Connection refused")

        adapter = NebiusSandboxAdapter(
            config=SandboxClientConfig(api_key="key", project_id="proj"),
            transport=failing_transport,
        )

        with pytest.raises(SandboxTransportError):
            adapter.inspect_whoami()

        assert call_count[0] == 1, "Must make exactly 1 attempt with no automatic retry"
