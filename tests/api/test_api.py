"""Integration tests for Phase P-21: API & Orchestrator Surface.

P-21.01: Run API contracts from domain types
P-21.02: Create, status, evidence, receipt endpoints
P-21.03: Server-Sent Events (SSE) live event stream
P-21.04: Authorization enforcement and secret-safe serialization
P-21.05: Idempotency replay, conflict detection, and restart recovery
"""

from __future__ import annotations

import json
import urllib.error
import urllib.request
from collections.abc import Generator
from pathlib import Path

import pytest

from basebreak.api.auth import ApiAuthManager
from basebreak.api.server import BasebreakApiServer
from basebreak.api.store import ApiRunStore


@pytest.fixture
def running_server(tmp_path: Path) -> Generator[tuple[BasebreakApiServer, str], None, None]:
    """Start an ephemeral Basebreak API server."""
    runs_dir = tmp_path / "runs"
    store = ApiRunStore(runs_dir=runs_dir)
    server = BasebreakApiServer(store=store, host="127.0.0.1", port=0)
    server.start()
    try:
        yield server, server.base_url
    finally:
        server.stop()


class TestApiEndpoints:
    """Tests for P-21.01, P-21.02, P-21.03: Endpoints and SSE streaming."""

    def test_create_and_get_run_lifecycle(
        self, running_server: tuple[BasebreakApiServer, str]
    ) -> None:
        _, base_url = running_server

        # 1. POST /v1/runs
        payload = {
            "target": "sample_repo",
            "base_sha": "1" * 40,
            "candidate_sha": "2" * 40,
            "change_class": "BUG_FIX",
        }
        req = urllib.request.Request(
            f"{base_url}/v1/runs",
            data=json.dumps(payload).encode("utf-8"),
            headers={"Content-Type": "application/json"},
            method="POST",
        )
        with urllib.request.urlopen(req) as resp:
            assert resp.status == 201
            body = json.loads(resp.read().decode("utf-8"))
            run_id = body["run_id"]
            assert body["status"] == "VERIFIED"
            assert body["exit_code"] == 0

        # 2. GET /v1/runs/{run_id}
        with urllib.request.urlopen(f"{base_url}/v1/runs/{run_id}") as resp:
            assert resp.status == 200
            meta = json.loads(resp.read().decode("utf-8"))
            assert meta["run_id"] == run_id
            assert meta["status"] == "VERIFIED"

        # 3. GET /v1/runs/{run_id}/evidence
        with urllib.request.urlopen(f"{base_url}/v1/runs/{run_id}/evidence") as resp:
            assert resp.status == 200
            ev_body = json.loads(resp.read().decode("utf-8"))
            evidence = ev_body["evidence"]
            assert len(evidence) == 3
            worlds = {e["world"] for e in evidence}
            assert worlds == {"BASE", "CANDIDATE", "COUNTERFACTUAL"}

        # 4. GET /v1/runs/{run_id}/receipt
        with urllib.request.urlopen(f"{base_url}/v1/runs/{run_id}/receipt") as resp:
            assert resp.status == 200
            rc = json.loads(resp.read().decode("utf-8"))
            assert "receipt_digest" in rc
            assert rc["overall_verdict"] == "VERIFIED"

        # 5. GET /v1/runs/{run_id}/events (SSE)
        with urllib.request.urlopen(f"{base_url}/v1/runs/{run_id}/events") as resp:
            assert resp.status == 200
            assert resp.headers.get("Content-Type") == "text/event-stream"
            stream_text = resp.read().decode("utf-8")
            assert "event: run.created" in stream_text
            assert "event: contract.frozen" in stream_text
            assert "event: witness.sealed" in stream_text
            assert "event: base.executing" in stream_text
            assert "event: candidate.executing" in stream_text
            assert "event: counterfactual.executing" in stream_text
            assert "event: reconciliation.completed" in stream_text
            assert "event: receipt.generated" in stream_text
            assert "event: run.completed" in stream_text

    def test_get_nonexistent_run_returns_404(
        self, running_server: tuple[BasebreakApiServer, str]
    ) -> None:
        _, base_url = running_server
        with pytest.raises(urllib.error.HTTPError) as exc:
            urllib.request.urlopen(f"{base_url}/v1/runs/missing_run_id")
        assert exc.value.code == 404


class TestApiIdempotencyAndRecovery:
    """Tests for P-21.05: Idempotency replay, conflict, and disk recovery."""

    def test_idempotency_replay_same_key(
        self, running_server: tuple[BasebreakApiServer, str]
    ) -> None:
        _, base_url = running_server
        payload = {
            "target": "idemp_repo",
            "base_sha": "1" * 40,
            "idempotency_key": "idemp_test_key_001",
        }
        req_data = json.dumps(payload).encode("utf-8")

        # First request: 201 Created
        req1 = urllib.request.Request(
            f"{base_url}/v1/runs",
            data=req_data,
            headers={"Content-Type": "application/json"},
            method="POST",
        )
        with urllib.request.urlopen(req1) as resp:
            assert resp.status == 201
            body1 = json.loads(resp.read().decode("utf-8"))
            run_id_1 = body1["run_id"]

        # Second request with same idempotency key and same payload: 200 OK (replay)
        req2 = urllib.request.Request(
            f"{base_url}/v1/runs",
            data=req_data,
            headers={"Content-Type": "application/json"},
            method="POST",
        )
        with urllib.request.urlopen(req2) as resp:
            assert resp.status == 200
            body2 = json.loads(resp.read().decode("utf-8"))
            assert body2["run_id"] == run_id_1

    def test_idempotency_conflict_different_payload(
        self, running_server: tuple[BasebreakApiServer, str]
    ) -> None:
        _, base_url = running_server
        key = "idemp_conflict_key_999"

        payload1 = {"target": "repo_alpha", "idempotency_key": key}
        req1 = urllib.request.Request(
            f"{base_url}/v1/runs",
            data=json.dumps(payload1).encode("utf-8"),
            headers={"Content-Type": "application/json"},
            method="POST",
        )
        with urllib.request.urlopen(req1) as resp:
            assert resp.status == 201

        # Second request with same key but different target -> 409 Conflict
        payload2 = {"target": "repo_beta", "idempotency_key": key}
        req2 = urllib.request.Request(
            f"{base_url}/v1/runs",
            data=json.dumps(payload2).encode("utf-8"),
            headers={"Content-Type": "application/json"},
            method="POST",
        )
        with pytest.raises(urllib.error.HTTPError) as exc:
            urllib.request.urlopen(req2)
        assert exc.value.code == 409

    def test_restart_recovery_from_disk(self, tmp_path: Path) -> None:
        runs_dir = tmp_path / "runs"
        store1 = ApiRunStore(runs_dir=runs_dir)
        server1 = BasebreakApiServer(store=store1, port=0)
        server1.start()
        url1 = server1.base_url

        try:
            req_data = json.dumps({"target": "persisted_repo"}).encode("utf-8")
            req = urllib.request.Request(
                f"{url1}/v1/runs",
                data=req_data,
                headers={"Content-Type": "application/json"},
                method="POST",
            )
            with urllib.request.urlopen(req) as resp:
                created = json.loads(resp.read().decode("utf-8"))
                run_id = created["run_id"]
        finally:
            server1.stop()

        # Start a brand new server pointing to same runs_dir
        store2 = ApiRunStore(runs_dir=runs_dir)
        server2 = BasebreakApiServer(store=store2, port=0)
        server2.start()
        url2 = server2.base_url
        try:
            with urllib.request.urlopen(f"{url2}/v1/runs/{run_id}") as resp:
                assert resp.status == 200
                recovered = json.loads(resp.read().decode("utf-8"))
                assert recovered["run_id"] == run_id
                assert recovered["status"] == "VERIFIED"
        finally:
            server2.stop()


class TestApiAuthAndSecretSafety:
    """Tests for P-21.04: Bearer auth and secret-safe responses."""

    def test_bearer_token_enforcement(self, tmp_path: Path) -> None:
        runs_dir = tmp_path / "runs"
        store = ApiRunStore(runs_dir=runs_dir)
        auth = ApiAuthManager(bearer_token="super_secret_auth_token_456")
        server = BasebreakApiServer(store=store, auth=auth, port=0)
        server.start()
        base_url = server.base_url

        try:
            # Missing header -> 401
            req_no_auth = urllib.request.Request(
                f"{base_url}/v1/runs",
                data=json.dumps({"target": "target"}).encode("utf-8"),
                headers={"Content-Type": "application/json"},
                method="POST",
            )
            with pytest.raises(urllib.error.HTTPError) as exc1:
                urllib.request.urlopen(req_no_auth)
            assert exc1.value.code == 401

            # Wrong token -> 401
            req_wrong_auth = urllib.request.Request(
                f"{base_url}/v1/runs",
                data=json.dumps({"target": "target"}).encode("utf-8"),
                headers={
                    "Content-Type": "application/json",
                    "Authorization": "Bearer wrong_token",
                },
                method="POST",
            )
            with pytest.raises(urllib.error.HTTPError) as exc2:
                urllib.request.urlopen(req_wrong_auth)
            assert exc2.value.code == 401

            # Correct token -> 201
            req_good_auth = urllib.request.Request(
                f"{base_url}/v1/runs",
                data=json.dumps({"target": "target"}).encode("utf-8"),
                headers={
                    "Content-Type": "application/json",
                    "Authorization": "Bearer super_secret_auth_token_456",
                },
                method="POST",
            )
            with urllib.request.urlopen(req_good_auth) as resp:
                assert resp.status == 201
        finally:
            server.stop()

    def test_secret_redaction_in_api_response(
        self, running_server: tuple[BasebreakApiServer, str]
    ) -> None:
        _, base_url = running_server
        secret_token = "ghp_123456789012345678901234567890123456"
        secret_target = f"repo_with_token/{secret_token}"

        req = urllib.request.Request(
            f"{base_url}/v1/runs",
            data=json.dumps({"target": secret_target}).encode("utf-8"),
            headers={"Content-Type": "application/json"},
            method="POST",
        )
        with urllib.request.urlopen(req) as resp:
            body_text = resp.read().decode("utf-8")
            assert secret_token not in body_text
            assert "[REDACTED]" in body_text
