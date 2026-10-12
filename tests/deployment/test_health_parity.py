"""Tests for health readiness and source SHA parity verification (P-27.04).

Validates that the /health endpoint and verify_health_parity function
confirm healthy status and exact source SHA parity.
"""

from __future__ import annotations

from collections.abc import Generator
from pathlib import Path

import pytest

from basebreak.api.auth import ApiAuthManager
from basebreak.api.server import BasebreakApiServer
from basebreak.api.store import ApiRunStore
from basebreak.deployment.health import get_build_commit_sha
from basebreak.deployment.parity import verify_health_parity


@pytest.fixture
def running_test_server(tmp_path: Path) -> Generator[tuple[BasebreakApiServer, str], None, None]:
    """Launch a local test BasebreakApiServer on ephemeral port."""
    runs_dir = tmp_path / "runs"
    runs_dir.mkdir(parents=True, exist_ok=True)
    store = ApiRunStore(runs_dir=runs_dir)
    auth = ApiAuthManager(bearer_token="test-secret-bearer-token")
    server = BasebreakApiServer(store=store, auth=auth, host="127.0.0.1", port=0)
    server.start()
    base_url = server.base_url
    yield server, base_url
    server.stop()


def test_health_endpoint_live_parity(running_test_server: tuple[BasebreakApiServer, str]) -> None:
    """verify_health_parity succeeds when expected commit SHA matches server report."""
    _, base_url = running_test_server
    expected_sha = get_build_commit_sha()

    res = verify_health_parity(expected_sha=expected_sha, base_url=base_url)

    assert res.status_code == 200
    assert res.service_status == "healthy"
    assert res.reported_sha == expected_sha
    assert res.is_sha_matched is True
    assert res.success is True
    assert "in parity" in res.message


def test_health_parity_sha_mismatch(running_test_server: tuple[BasebreakApiServer, str]) -> None:
    """verify_health_parity fails closed when expected SHA does not match reported SHA."""
    _, base_url = running_test_server
    wrong_sha = "0000000000000000000000000000000000000000"

    res = verify_health_parity(expected_sha=wrong_sha, base_url=base_url)

    assert res.status_code == 200
    assert res.service_status == "healthy"
    assert res.is_sha_matched is False
    assert res.success is False
    assert "mismatch" in res.message.lower()


def test_health_parity_connection_failure() -> None:
    """verify_health_parity handles unreachable hosts gracefully with fail-closed result."""
    dead_url = "http://127.0.0.1:59999"
    dummy_sha = "1111111111111111111111111111111111111111"

    res = verify_health_parity(expected_sha=dummy_sha, base_url=dead_url, timeout_seconds=1.0)

    assert res.success is False
    assert res.status_code == 0
    assert res.is_sha_matched is False
    assert "failed to connect" in res.message.lower()
