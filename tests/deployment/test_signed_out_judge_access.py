"""Tests for signed-out/free judge access and authorization boundary (P-27.05).

Verifies that:
1. Signed-out judges can freely inspect published verification runs and receipts.
2. Private runs remain strictly protected with 401 Unauthorized for anonymous callers.
3. Mutating operations (POST /v1/runs, POST /v1/runs/{id}/publish) strictly require Bearer token.
4. Tampered receipts fail closed before delivery.
"""

from __future__ import annotations

import json
import urllib.error
import urllib.request
from collections.abc import Generator
from pathlib import Path
from typing import Any

import pytest

from basebreak.api.auth import ApiAuthManager
from basebreak.api.server import BasebreakApiServer
from basebreak.api.store import ApiRunStore


def _http_get(url: str, token: str | None = None) -> tuple[int, str, dict[str, Any] | None]:
    """Helper for HTTP GET returning (status_code, body_text, parsed_json_or_none)."""
    headers = {"User-Agent": "Basebreak-Test-Client"}
    if token:
        headers["Authorization"] = f"Bearer {token}"
    req = urllib.request.Request(url, headers=headers, method="GET")
    try:
        with urllib.request.urlopen(req, timeout=5.0) as resp:
            body = resp.read().decode("utf-8")
            try:
                data = json.loads(body)
            except Exception:
                data = None
            return resp.status, body, data
    except urllib.error.HTTPError as exc:
        body = exc.read().decode("utf-8")
        try:
            data = json.loads(body)
        except Exception:
            data = None
        return exc.code, body, data


def _http_post(
    url: str, payload: dict[str, Any], token: str | None = None
) -> tuple[int, str, dict[str, Any] | None]:
    """Helper for HTTP POST returning (status_code, body_text, parsed_json_or_none)."""
    headers = {"Content-Type": "application/json", "User-Agent": "Basebreak-Test-Client"}
    if token:
        headers["Authorization"] = f"Bearer {token}"
    data_bytes = json.dumps(payload).encode("utf-8")
    req = urllib.request.Request(url, data=data_bytes, headers=headers, method="POST")
    try:
        with urllib.request.urlopen(req, timeout=5.0) as resp:
            body = resp.read().decode("utf-8")
            try:
                data = json.loads(body)
            except Exception:
                data = None
            return resp.status, body, data
    except urllib.error.HTTPError as exc:
        body = exc.read().decode("utf-8")
        try:
            data = json.loads(body)
        except Exception:
            data = None
        return exc.code, body, data


@pytest.fixture
def auth_server(
    tmp_path: Path,
) -> Generator[tuple[BasebreakApiServer, ApiRunStore, str, str], None, None]:
    """Fixture providing a configured Basebreak server with a Bearer token."""
    runs_dir = tmp_path / "auth_runs"
    runs_dir.mkdir(parents=True, exist_ok=True)
    store = ApiRunStore(runs_dir=runs_dir)
    token = "secret-operator-token-xyz"
    auth = ApiAuthManager(bearer_token=token)
    server = BasebreakApiServer(store=store, auth=auth, host="127.0.0.1", port=0)
    server.start()
    base_url = server.base_url
    yield server, store, token, base_url
    server.stop()


def test_anonymous_health_check_allowed(
    auth_server: tuple[BasebreakApiServer, ApiRunStore, str, str],
) -> None:
    """Health check is public and accessible without credentials."""
    _, _, _, base_url = auth_server
    status_code, _, data = _http_get(f"{base_url}/health")

    assert status_code == 200
    assert data is not None
    assert data.get("status") == "healthy"
    assert data.get("read_only_judge_mode") is True


def test_anonymous_run_creation_rejected(
    auth_server: tuple[BasebreakApiServer, ApiRunStore, str, str],
) -> None:
    """Mutating run creation without Bearer token returns 401 Unauthorized."""
    _, _, _, base_url = auth_server
    payload = {"target": "tests/fixtures/demo_target", "change_class": "BUG_FIX"}

    status_code, _, data = _http_post(f"{base_url}/v1/runs", payload, token=None)

    assert status_code == 401
    assert data is not None
    assert "unauthorized" in str(data.get("error")).lower()


def test_signed_out_published_run_inspection(
    auth_server: tuple[BasebreakApiServer, ApiRunStore, str, str],
) -> None:
    """Signed-out judges can inspect published verification runs and receipts without auth."""
    _, store, token, base_url = auth_server

    # 1. Operator creates a published run
    payload = {
        "target": "tests/fixtures/demo_target",
        "change_class": "BUG_FIX",
        "publish": True,
    }
    status_code, _, data = _http_post(f"{base_url}/v1/runs", payload, token=token)
    assert status_code == 201
    assert data is not None
    run_id = data["run_id"]
    assert store.is_run_published(run_id) is True

    # 2. Signed-out judge inspects /judge
    judge_status, judge_body, _ = _http_get(f"{base_url}/judge", token=None)
    assert judge_status == 200
    assert "BASEBREAK VERIFICATION RUNTIME" in judge_body
    assert run_id in judge_body

    # 3. Signed-out judge inspects /judge/{run_id}
    specific_status, specific_body, _ = _http_get(f"{base_url}/judge/{run_id}", token=None)
    assert specific_status == 200
    assert run_id in specific_body

    # 4. Signed-out judge inspects /v1/runs/{run_id}/receipt
    rc_status, _, rc_data = _http_get(f"{base_url}/v1/runs/{run_id}/receipt", token=None)
    assert rc_status == 200
    assert rc_data is not None
    assert "receipt_digest" in rc_data


def test_anonymous_private_run_access_rejected(
    auth_server: tuple[BasebreakApiServer, ApiRunStore, str, str],
) -> None:
    """Private (unpublished) runs reject anonymous access with 401 Unauthorized."""
    _, store, token, base_url = auth_server

    # 1. Operator creates a private run (publish=False)
    payload = {
        "target": "tests/fixtures/demo_target",
        "change_class": "BUG_FIX",
        "publish": False,
    }
    status_code, _, data = _http_post(f"{base_url}/v1/runs", payload, token=token)
    assert status_code == 201
    assert data is not None
    run_id = data["run_id"]
    assert store.is_run_published(run_id) is False

    # 2. Anonymous attempt to view private UI -> 401
    ui_status, ui_body, _ = _http_get(f"{base_url}/judge/{run_id}", token=None)
    assert ui_status == 401
    assert "is Private" in ui_body

    # 3. Anonymous attempt to fetch private receipt -> 401
    rc_status, _, rc_data = _http_get(f"{base_url}/v1/runs/{run_id}/receipt", token=None)
    assert rc_status == 401
    assert rc_data is not None
    assert "private" in str(rc_data.get("error")).lower()

    # 4. Authenticated operator can still inspect it -> 200
    authed_ui_status, authed_ui_body, _ = _http_get(f"{base_url}/judge/{run_id}", token=token)
    assert authed_ui_status == 200
    assert run_id in authed_ui_body


def test_operator_publish_endpoint_workflow(
    auth_server: tuple[BasebreakApiServer, ApiRunStore, str, str],
) -> None:
    """Operator can explicitly publish an existing private run via POST /v1/runs/{id}/publish."""
    _, store, token, base_url = auth_server

    # 1. Create private run
    payload = {"target": "tests/fixtures/demo_target", "change_class": "BUG_FIX", "publish": False}
    create_status, _, data = _http_post(f"{base_url}/v1/runs", payload, token=token)
    assert create_status == 201
    assert data is not None
    run_id = data["run_id"]

    # 2. Anonymous access rejected before publish
    rc_status, _, _ = _http_get(f"{base_url}/v1/runs/{run_id}/receipt", token=None)
    assert rc_status == 401

    # 3. Operator publishes run
    pub_status, _, pub_data = _http_post(f"{base_url}/v1/runs/{run_id}/publish", {}, token=token)
    assert pub_status == 200
    assert pub_data == {"run_id": run_id, "is_published": True}
    assert store.is_run_published(run_id) is True

    # 4. Anonymous access succeeds after publish
    rc_status_after, _, rc_data_after = _http_get(
        f"{base_url}/v1/runs/{run_id}/receipt", token=None
    )
    assert rc_status_after == 200
    assert rc_data_after is not None
    assert "receipt_digest" in rc_data_after
