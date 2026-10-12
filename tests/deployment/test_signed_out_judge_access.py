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
        with urllib.request.urlopen(req, timeout=30.0) as resp:
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
        with urllib.request.urlopen(req, timeout=30.0) as resp:
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


def test_unconfigured_server_fails_closed_and_protects_private_runs(
    tmp_path: Path,
) -> None:
    """Server without Bearer token configured fails closed for mutations and private access."""
    runs_dir = tmp_path / "unconf_runs"
    runs_dir.mkdir(parents=True, exist_ok=True)
    store = ApiRunStore(runs_dir=runs_dir)
    auth = ApiAuthManager(bearer_token=None)  # No token configured
    server = BasebreakApiServer(store=store, auth=auth, host="127.0.0.1", port=0)
    server.start()
    base_url = server.base_url

    try:
        # 1. Health probe works unauthenticated
        h_code, _, h_data = _http_get(f"{base_url}/health")
        assert h_code == 200
        assert h_data is not None
        assert h_data.get("status") == "healthy"

        # 2. Mutation attempt without server token fails closed (401)
        post_code, _, _ = _http_post(
            f"{base_url}/v1/runs",
            {"target": "tests/fixtures/demo_target", "change_class": "BUG_FIX"},
        )
        assert post_code == 401

        # 3. Publish attempt fails closed (401)
        pub_code, _, _ = _http_post(f"{base_url}/v1/runs/any-run/publish", {})
        assert pub_code == 401

        # 4. Create an unpublished run directly on disk
        from basebreak.cli.config import BasebreakConfig
        from basebreak.cli.runner import execute_verification_pipeline

        cfg = BasebreakConfig(runs_dir=str(runs_dir))
        res = execute_verification_pipeline(
            target="tests/fixtures/demo_target", change_class_name="BUG_FIX", config=cfg
        )
        store.persistence.save_run(
            res.run_id,
            res.metadata,
            evidence=res.evidence,
            receipt=res.receipt.to_dict() if res.receipt else None,
        )

        # Anonymous cannot access private UI or receipt or metadata
        ui_code, _, _ = _http_get(f"{base_url}/judge/{res.run_id}")
        assert ui_code == 401
        rc_code, _, _ = _http_get(f"{base_url}/v1/runs/{res.run_id}/receipt")
        assert rc_code == 401
        meta_code, _, _ = _http_get(f"{base_url}/v1/runs/{res.run_id}")
        assert meta_code == 401

        # 5. When explicitly published in store, anonymous can inspect UI and receipt
        store.publish_run(res.run_id)
        ui_pub_code, ui_pub_body, _ = _http_get(f"{base_url}/judge/{res.run_id}")
        assert ui_pub_code == 200
        assert res.run_id in ui_pub_body
        rc_pub_code, _, rc_pub_data = _http_get(f"{base_url}/v1/runs/{res.run_id}/receipt")
        assert rc_pub_code == 200
        assert rc_pub_data is not None
        assert "receipt_digest" in rc_pub_data

        # But raw metadata still requires operator (returns 401 since no operator can exist)
        meta_pub_code, _, _ = _http_get(f"{base_url}/v1/runs/{res.run_id}")
        assert meta_pub_code == 401
    finally:
        server.stop()


def test_auth_header_negative_cases(
    auth_server: tuple[BasebreakApiServer, ApiRunStore, str, str],
) -> None:
    """Invalid tokens, absent tokens, and malformed auth headers are all rejected with 401."""
    _, _, _, base_url = auth_server
    payload = {"target": "tests/fixtures/demo_target", "change_class": "BUG_FIX"}

    # No token
    c1, _, _ = _http_post(f"{base_url}/v1/runs", payload, token=None)
    assert c1 == 401

    # Wrong token
    c2, _, _ = _http_post(f"{base_url}/v1/runs", payload, token="wrong-operator-token")
    assert c2 == 401

    # Malformed non-Bearer header
    headers = {"Authorization": "Basic dXNlcjpwYXNz", "Content-Type": "application/json"}
    req = urllib.request.Request(
        f"{base_url}/v1/runs",
        data=json.dumps(payload).encode("utf-8"),
        headers=headers,
        method="POST",
    )
    with pytest.raises(urllib.error.HTTPError) as exc_info:
        urllib.request.urlopen(req)
    assert exc_info.value.code == 401


def test_published_run_does_not_leak_raw_internals_to_anonymous(
    auth_server: tuple[BasebreakApiServer, ApiRunStore, str, str],
) -> None:
    """Anonymous callers cannot access raw internal evidence, events, or run metadata."""
    _, store, token, base_url = auth_server

    payload = {
        "target": "tests/fixtures/demo_target",
        "change_class": "BUG_FIX",
        "publish": True,
    }
    status, _, data = _http_post(f"{base_url}/v1/runs", payload, token=token)
    assert status == 201
    assert data is not None
    run_id = data["run_id"]
    assert store.is_run_published(run_id) is True

    # Anonymous access to public surfaces succeeds
    rc_code, _, _ = _http_get(f"{base_url}/v1/runs/{run_id}/receipt", token=None)
    assert rc_code == 200
    ui_code, _, _ = _http_get(f"{base_url}/judge/{run_id}", token=None)
    assert ui_code == 200

    # Anonymous access to internal surfaces is strictly rejected with 401
    meta_code, _, _ = _http_get(f"{base_url}/v1/runs/{run_id}", token=None)
    assert meta_code == 401
    evid_code, _, _ = _http_get(f"{base_url}/v1/runs/{run_id}/evidence", token=None)
    assert evid_code == 401
    ev_code, _, _ = _http_get(f"{base_url}/v1/runs/{run_id}/events", token=None)
    assert ev_code == 401

    # Authenticated operator can access raw internal surfaces
    op_meta_code, _, op_meta = _http_get(f"{base_url}/v1/runs/{run_id}", token=token)
    assert op_meta_code == 200
    assert op_meta is not None
    assert op_meta.get("run_id") == run_id

    op_evid_code, _, op_evid = _http_get(f"{base_url}/v1/runs/{run_id}/evidence", token=token)
    assert op_evid_code == 200
    assert op_evid is not None
    assert "evidence" in op_evid


def test_unpublishable_run_rejections(
    auth_server: tuple[BasebreakApiServer, ApiRunStore, str, str],
) -> None:
    """Runs with missing receipts, tampered receipts, or raw secrets cannot be published."""
    _, store, token, base_url = auth_server

    # 1. Run without receipt cannot be published
    from basebreak.cli.config import BasebreakConfig
    from basebreak.cli.runner import execute_verification_pipeline

    cfg = BasebreakConfig(runs_dir=str(store.runs_dir))

    # A run with invalid patch fails before generating a receipt
    res_no_rc = execute_verification_pipeline(
        target="tests/fixtures/demo_target",
        patch="invalid non-diff garbage",
        change_class_name="BUG_FIX",
        config=cfg,
    )
    store.persistence.save_run(
        res_no_rc.run_id,
        res_no_rc.metadata,
        evidence=res_no_rc.evidence,
        receipt=None,
    )
    pub_code, _, pub_err = _http_post(
        f"{base_url}/v1/runs/{res_no_rc.run_id}/publish", {}, token=token
    )
    assert pub_code == 422
    assert "missing public verification receipt" in str(pub_err)

    # 2. Run with valid receipt but tampered hash cannot be published
    res_valid = execute_verification_pipeline(
        target="tests/fixtures/demo_target",
        change_class_name="BUG_FIX",
        config=cfg,
    )
    assert res_valid.receipt is not None
    tampered_dict = res_valid.receipt.to_dict()
    tampered_dict["task_id"] = "tampered-task-id"  # Mutate field to invalidate digest
    store.persistence.save_run(
        res_valid.run_id,
        res_valid.metadata,
        evidence=res_valid.evidence,
        receipt=tampered_dict,
    )
    pub_code2, _, pub_err2 = _http_post(
        f"{base_url}/v1/runs/{res_valid.run_id}/publish", {}, token=token
    )
    assert pub_code2 == 422
    assert "receipt integrity verification failed" in str(pub_err2)

    # 3. Run with secret in receipt cannot be published
    secret_dict = res_valid.receipt.to_dict()
    secret_dict["repo_locator"] = "token=ghp_fakeabcdefghijklmnopqrstuvwxyz123456"
    store.persistence.save_run(
        "secret-run-id",
        {"run_id": "secret-run-id", "status": "VERIFIED"},
        evidence=[],
        receipt=secret_dict,
    )
    pub_code3, _, pub_err3 = _http_post(
        f"{base_url}/v1/runs/secret-run-id/publish", {}, token=token
    )
    assert pub_code3 == 422
    assert "receipt contains raw recognized secrets" in str(pub_err3)


def test_tampered_receipt_rejected_before_rendering_judge_ui(
    auth_server: tuple[BasebreakApiServer, ApiRunStore, str, str],
) -> None:
    """Tampered published receipts on disk reject GET /judge/{id} with 400 Bad Request."""
    _, store, token, base_url = auth_server

    payload = {"target": "tests/fixtures/demo_target", "change_class": "BUG_FIX", "publish": True}
    status, _, data = _http_post(f"{base_url}/v1/runs", payload, token=token)
    assert status == 201
    assert data is not None
    run_id = data["run_id"]

    # Tamper with receipt file on disk
    rc_file = store.persistence.get_run_dir(run_id) / "receipt.json"
    with rc_file.open("r", encoding="utf-8") as f:
        rc_json = json.load(f)
    rc_json["task_id"] = "tampered-after-publish"
    with rc_file.open("w", encoding="utf-8") as f:
        json.dump(rc_json, f, indent=2)

    # GET /judge/{run_id} rejects before rendering UI
    ui_status, ui_body, _ = _http_get(f"{base_url}/judge/{run_id}", token=None)
    assert ui_status == 400
    assert "Receipt Integrity Verification Failed" in ui_body


def test_restart_and_recovery_of_publication_state(tmp_path: Path) -> None:
    """Published runs recover safely across restart; tampered receipts are discarded."""
    runs_dir = tmp_path / "persist_runs"
    runs_dir.mkdir(parents=True, exist_ok=True)
    token = "persisted-operator-token"

    # Phase 1: create server and published run
    store1 = ApiRunStore(runs_dir=runs_dir)
    auth1 = ApiAuthManager(bearer_token=token)
    server1 = BasebreakApiServer(store=store1, auth=auth1, host="127.0.0.1", port=0)
    server1.start()
    try:
        payload = {
            "target": "tests/fixtures/demo_target",
            "change_class": "BUG_FIX",
            "publish": True,
        }
        code, _, data = _http_post(f"{server1.base_url}/v1/runs", payload, token=token)
        assert code == 201
        assert data is not None
        run_id = data["run_id"]
        assert store1.is_run_published(run_id) is True
    finally:
        server1.stop()

    # Phase 2: restart server and verify publication state is recovered
    store2 = ApiRunStore(runs_dir=runs_dir)
    assert store2.is_run_published(run_id) is True
    assert run_id in store2.list_published_runs()

    # Phase 3: tamper with receipt file on disk and re-initialize store
    rc_file = store2.persistence.get_run_dir(run_id) / "receipt.json"
    with rc_file.open("r", encoding="utf-8") as f:
        rc_json = json.load(f)
    rc_json["task_id"] = "corrupted-for-recovery-test"
    with rc_file.open("w", encoding="utf-8") as f:
        json.dump(rc_json, f, indent=2)

    store3 = ApiRunStore(runs_dir=runs_dir)
    # Recovery must reject the tampered receipt and discard the run from published list
    assert store3.is_run_published(run_id) is False
    assert run_id not in store3.list_published_runs()
