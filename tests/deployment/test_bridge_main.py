"""Focused tests for the localhost trusted-bridge runner (P-27.06)."""

from __future__ import annotations

import json
import time
import urllib.error
import urllib.request
from typing import Any

import pytest

from basebreak.deployment.bridge_main import (
    DEFAULT_BRIDGE_PORT,
    LOOPBACK_HOST,
    BridgeRunnerError,
    _ensure_loopback,
    bridge_server,
    collect_readiness,
    main,
    validate_port,
)
from basebreak.deployment.live_bridge import (
    BRIDGE_REQUEST_SCHEMA_VERSION,
    LIVE_BRIDGE_ROUTE,
    TrustedBridgeConfig,
    TrustedVerifierBridge,
    _load_canonical_live_bridge_scenario,
    create_trusted_verifier_bridge_from_env,
    sign_bridge_request,
)

_SECRET_ENV_NAMES = (
    "BASEBREAK_VERIFIER_SIGNING_KEY",
    "NEBIUS_API_KEY",
    "NEBIUS_PROJECT_ID",
    "TRUSTED_VERIFIER_BRIDGE_SHARED_SECRET",
    "BASEBREAK_LIVE_EXECUTION_ENABLED",
    "TRUSTED_VERIFIER_BRIDGE_STATE_DIR",
    "EXPECTED_SOURCE_COMMIT",
    "BASEBREAK_BUILD_COMMIT_SHA",
)
_TEST_SECRET = "unit-test-secret"
_TEST_AUDIENCE = "cloudflare-worker"
_TEST_SOURCE = "a" * 40


def _clear_env(monkeypatch: pytest.MonkeyPatch) -> None:
    for name in _SECRET_ENV_NAMES:
        monkeypatch.delenv(name, raising=False)


def _make_bridge(
    *,
    shared_secret: str | None = _TEST_SECRET,
    live_execution_enabled: bool = False,
    expected_source_commit: str = _TEST_SOURCE,
) -> TrustedVerifierBridge:
    return TrustedVerifierBridge(
        config=TrustedBridgeConfig(
            shared_secret=shared_secret,
            expected_source_commit=expected_source_commit,
            live_execution_enabled=live_execution_enabled,
        )
    )


def _signed_headers(secret: str, body: dict[str, Any]) -> dict[str, str]:
    timestamp = str(int(time.time() * 1000))
    signature = sign_bridge_request(
        shared_secret=secret,
        method="POST",
        path=LIVE_BRIDGE_ROUTE,
        timestamp=timestamp,
        audience=_TEST_AUDIENCE,
        body=body,
    )
    return {
        "Content-Type": "application/json",
        "X-Basebreak-Bridge-Timestamp": timestamp,
        "X-Basebreak-Bridge-Audience": _TEST_AUDIENCE,
        "X-Basebreak-Bridge-Signature": signature,
    }


def _parse(body: bytes) -> dict[str, Any]:
    try:
        parsed = json.loads(body.decode("utf-8"))
    except (UnicodeDecodeError, json.JSONDecodeError):
        return {"raw": body.decode("utf-8", errors="replace")}
    return parsed if isinstance(parsed, dict) else {"raw": parsed}


def _request(
    url: str,
    *,
    method: str = "POST",
    body: bytes | None = None,
    headers: dict[str, str] | None = None,
) -> tuple[int, dict[str, Any]]:
    request = urllib.request.Request(url, data=body, method=method, headers=headers or {})
    try:
        with urllib.request.urlopen(request, timeout=5) as response:
            return int(response.status), _parse(response.read())
    except urllib.error.HTTPError as exc:
        return int(exc.code), _parse(exc.read())


# --- Pure helpers -----------------------------------------------------------------


def test_default_bridge_port_is_8787() -> None:
    assert DEFAULT_BRIDGE_PORT == 8787
    assert LOOPBACK_HOST == "127.0.0.1"


def test_validate_port_accepts_valid_range() -> None:
    assert validate_port("8787") == 8787
    assert validate_port(1) == 1
    assert validate_port(65535) == 65535


@pytest.mark.parametrize("bad", [0, -1, 65536, "abc", None, 3.5])
def test_validate_port_rejects_invalid(bad: Any) -> None:
    with pytest.raises(ValueError):
        validate_port(bad)


def test_ensure_loopback_rejects_external_interface() -> None:
    _ensure_loopback("127.0.0.1")
    for bad in ("0.0.0.0", "::", "192.168.1.10", "localhost"):
        with pytest.raises(BridgeRunnerError):
            _ensure_loopback(bad)


# --- CLI surface ------------------------------------------------------------------


def test_cli_help_exits_zero() -> None:
    with pytest.raises(SystemExit) as excinfo:
        main(["--help"])
    assert excinfo.value.code == 0


@pytest.mark.parametrize("bad", ["0", "70000", "-1", "abc"])
def test_cli_rejects_invalid_port(bad: str) -> None:
    with pytest.raises(SystemExit) as excinfo:
        main(["--port", bad])
    assert excinfo.value.code == 2


# --- Offline self-check mode ------------------------------------------------------


def test_self_check_reports_fail_closed_without_secrets(
    monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    _clear_env(monkeypatch)
    rc = main(["--check"])
    assert rc == 0
    data = json.loads(capsys.readouterr().out)
    assert data["bind_host"] == "127.0.0.1"
    assert data["route"] == LIVE_BRIDGE_ROUTE
    assert data["live_execution_enabled"] is False
    assert data["shared_secret_configured"] is False
    assert data["provider_credentials_present"] is False
    assert data["signing_authority_compatible"] is False
    assert data["durable_idempotency_available"] is False
    assert data["ready_for_live"] is False


def test_self_check_never_prints_secret_values(
    monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    _clear_env(monkeypatch)
    monkeypatch.setenv("TRUSTED_VERIFIER_BRIDGE_SHARED_SECRET", "top-secret-value-marker")
    rc = main(["--check"])
    assert rc == 0
    out = capsys.readouterr().out
    assert "top-secret-value-marker" not in out
    assert json.loads(out)["shared_secret_configured"] is True


def test_factory_creates_no_ephemeral_idempotency_storage(monkeypatch: pytest.MonkeyPatch) -> None:
    _clear_env(monkeypatch)
    bridge = create_trusted_verifier_bridge_from_env()
    assert bridge.idempotency_store is None
    assert bridge.idempotency_store_error is not None
    assert collect_readiness(bridge)["durable_idempotency_available"] is False


# --- Server lifecycle -------------------------------------------------------------


def test_localhost_binding_and_graceful_shutdown() -> None:
    bridge = _make_bridge()
    with bridge_server(bridge, 0) as server:
        assert server.base_url.startswith("http://127.0.0.1:")
    # After exit the server is stopped and no longer resolvable.
    with pytest.raises(RuntimeError):
        _ = server.base_url


# --- HTTP fail-closed behavior (assert exact existing responses) ------------------


def test_http_unauthorized_missing_headers() -> None:
    bridge = _make_bridge()
    with bridge_server(bridge, 0) as server:
        status, body = _request(f"{server.base_url}{LIVE_BRIDGE_ROUTE}", body=b"{}")
    assert status == 401
    assert body["status"] == "UNAUTHORIZED"


def test_http_unauthorized_wrong_signature() -> None:
    bridge = _make_bridge()
    headers = {
        "Content-Type": "application/json",
        "X-Basebreak-Bridge-Timestamp": str(int(time.time() * 1000)),
        "X-Basebreak-Bridge-Audience": _TEST_AUDIENCE,
        "X-Basebreak-Bridge-Signature": "deadbeef",
    }
    with bridge_server(bridge, 0) as server:
        status, body = _request(
            f"{server.base_url}{LIVE_BRIDGE_ROUTE}", body=b"{}", headers=headers
        )
    assert status == 401
    assert body["status"] == "UNAUTHORIZED"


def test_http_malformed_body_after_auth_checks() -> None:
    bridge = _make_bridge()
    headers = {
        "Content-Type": "application/json",
        "X-Basebreak-Bridge-Timestamp": str(int(time.time() * 1000)),
        "X-Basebreak-Bridge-Audience": _TEST_AUDIENCE,
        "X-Basebreak-Bridge-Signature": "deadbeef",
    }
    with bridge_server(bridge, 0) as server:
        status, body = _request(
            f"{server.base_url}{LIVE_BRIDGE_ROUTE}", body=b"not-json", headers=headers
        )
    assert status == 401
    assert body["status"] == "UNAUTHORIZED"


def test_http_method_not_allowed_over_http_is_stdlib_501() -> None:
    # The stdlib handler only dispatches do_POST; a non-POST request is rejected
    # by BaseHTTPRequestHandler with 501 before our routing logic runs.
    bridge = _make_bridge()
    with bridge_server(bridge, 0) as server:
        status, _body = _request(f"{server.base_url}{LIVE_BRIDGE_ROUTE}", method="GET")
    assert status == 501


def test_bridge_routing_method_not_allowed_is_405() -> None:
    # Directly exercise the existing routing contract: non-POST is 405.
    bridge = _make_bridge()
    status_code, body = bridge.handle_http_request(
        method="GET", path=LIVE_BRIDGE_ROUTE, headers={}, raw_body=b""
    )
    assert status_code == 405
    assert body["status"] == "METHOD_NOT_ALLOWED"


def test_http_unknown_route() -> None:
    bridge = _make_bridge()
    with bridge_server(bridge, 0) as server:
        status, body = _request(f"{server.base_url}/not-the-bridge-route", body=b"{}")
    assert status == 404
    assert body["status"] == "NOT_FOUND"


def test_http_not_ready_when_shared_secret_absent() -> None:
    bridge = _make_bridge(shared_secret=None)
    with bridge_server(bridge, 0) as server:
        status, body = _request(f"{server.base_url}{LIVE_BRIDGE_ROUTE}", body=b"{}")
    assert status == 503
    assert body["status"] == "NOT_READY_FOR_DEPLOYMENT"


def test_http_invalid_input_with_valid_auth() -> None:
    bridge = _make_bridge()
    payload = {"schema_version": BRIDGE_REQUEST_SCHEMA_VERSION}
    body_bytes = json.dumps(payload).encode("utf-8")
    with bridge_server(bridge, 0) as server:
        status, body = _request(
            f"{server.base_url}{LIVE_BRIDGE_ROUTE}",
            body=body_bytes,
            headers=_signed_headers(_TEST_SECRET, payload),
        )
    assert status == 400
    assert body["status"] == "INVALID_INPUT"


def test_http_live_disabled_fails_closed() -> None:
    bridge = _make_bridge(live_execution_enabled=False)
    scenario = _load_canonical_live_bridge_scenario()
    now_ms = int(time.time() * 1000)
    payload: dict[str, Any] = {
        "schema_version": BRIDGE_REQUEST_SCHEMA_VERSION,
        "request_id": "run-bridge-main-live-disabled",
        "issued_at_ms": now_ms,
        "deadline_ms": now_ms + 60_000,
        "receipt_audience": _TEST_AUDIENCE,
        "task_id": scenario.task_id,
        "change_class": scenario.change_class,
        "target": scenario.target,
        "source_commit_id": _TEST_SOURCE,
        "frozen_contract_digest": scenario.frozen_contract_digest,
        "max_estimated_cost_usd": 0.25,
    }
    body_bytes = json.dumps(payload).encode("utf-8")
    with bridge_server(bridge, 0) as server:
        status, body = _request(
            f"{server.base_url}{LIVE_BRIDGE_ROUTE}",
            body=body_bytes,
            headers=_signed_headers(_TEST_SECRET, payload),
        )
    assert status == 503
    assert body["status"] == "BLOCKED_LIVE_DISABLED"
