"""Focused regressions for the production ResetVault frozen-contract authority (P-27.06).

Proves that the production trusted bridge no longer imports the P-23 pytest test
module, that the canonical frozen-contract digest is preserved, and that a
correctly HMAC-signed request with the live gate disabled returns
``503 BLOCKED_LIVE_DISABLED`` instead of raising an unhandled exception.
"""

from __future__ import annotations

import importlib
import json
import os
import subprocess
import sys
import time
from pathlib import Path

from basebreak.deployment.live_bridge import (
    BRIDGE_REQUEST_SCHEMA_VERSION,
    DEFAULT_BRIDGE_AUDIENCE,
    LIVE_BRIDGE_ROUTE,
    TrustedBridgeConfig,
    TrustedVerifierBridge,
    _load_canonical_live_bridge_scenario,
    sign_bridge_request,
)
from basebreak.deployment.reset_vault_contract import create_reset_vault_frozen_contract

CANONICAL_RESET_VAULT_CONTRACT_DIGEST = (
    "93eeeb2cc7eb02a988da3c8a8543ad40b4816608c1452d048ff62ee93702f812"
)
_SECRET = "unit-test-verifier-bridge-secret"
_SOURCE = "a" * 40
_REPO_ROOT = Path(__file__).resolve().parents[2]


def _bridge(*, live_execution_enabled: bool = False) -> TrustedVerifierBridge:
    return TrustedVerifierBridge(
        config=TrustedBridgeConfig(
            shared_secret=_SECRET,
            expected_source_commit=_SOURCE,
            live_execution_enabled=live_execution_enabled,
        )
    )


def _signed_request(
    *, digest: str | None = None, source: str | None = None
) -> tuple[dict[str, str], bytes]:
    scenario = _load_canonical_live_bridge_scenario()
    now = int(time.time() * 1000)
    payload = {
        "schema_version": BRIDGE_REQUEST_SCHEMA_VERSION,
        "request_id": "run-reset-vault-contract-authority",
        "issued_at_ms": now,
        "deadline_ms": now + 60_000,
        "receipt_audience": DEFAULT_BRIDGE_AUDIENCE,
        "task_id": scenario.task_id,
        "change_class": scenario.change_class,
        "target": scenario.target,
        "source_commit_id": _SOURCE if source is None else source,
        "frozen_contract_digest": (scenario.frozen_contract_digest if digest is None else digest),
        "max_estimated_cost_usd": 0.25,
    }
    body = json.dumps(payload).encode("utf-8")
    timestamp = str(now)
    signature = sign_bridge_request(
        shared_secret=_SECRET,
        method="POST",
        path=LIVE_BRIDGE_ROUTE,
        timestamp=timestamp,
        audience=DEFAULT_BRIDGE_AUDIENCE,
        body=payload,
    )
    headers = {
        "Content-Type": "application/json",
        "X-Basebreak-Bridge-Timestamp": timestamp,
        "X-Basebreak-Bridge-Audience": DEFAULT_BRIDGE_AUDIENCE,
        "X-Basebreak-Bridge-Signature": signature,
    }
    return headers, body


def _post(headers: dict[str, str], body: bytes) -> tuple[int, dict[str, object]]:
    return _bridge().handle_http_request(
        method="POST", path=LIVE_BRIDGE_ROUTE, headers=headers, raw_body=body
    )


# --- Contract authority -------------------------------------------------------------


def test_production_factory_preserves_canonical_contract_digest() -> None:
    contract = create_reset_vault_frozen_contract()
    assert contract.contract_digest == CANONICAL_RESET_VAULT_CONTRACT_DIGEST
    assert contract.change_class.value == "BUG_FIX"
    assert contract.requirements[0].requirement_id == "REQ-RESET-001"


def test_p23_test_consumes_single_production_authority() -> None:
    if str(_REPO_ROOT) not in sys.path:
        sys.path.insert(0, str(_REPO_ROOT))
    p23 = importlib.import_module("tests.demo.test_p23_killer_demo")
    assert (
        getattr(p23, "create_reset_vault_frozen_contract", None)
        is create_reset_vault_frozen_contract
    )


def test_live_bridge_scenario_digest_matches_canonical_pin() -> None:
    scenario = _load_canonical_live_bridge_scenario()
    assert scenario.frozen_contract_digest == CANONICAL_RESET_VAULT_CONTRACT_DIGEST


def test_live_bridge_scenario_builds_without_pytest_or_p23_import() -> None:
    """Fresh process that blocks ``pytest`` and any ``tests.*`` import must still build."""
    script = (
        "import sys\n"
        "class _Blocker:\n"
        "    def find_spec(self, name, path=None, target=None):\n"
        "        if name == 'pytest' or name == 'tests' or name.startswith('tests.'):\n"
        "            raise ImportError('blocked test import: ' + name)\n"
        "        return None\n"
        "sys.meta_path.insert(0, _Blocker())\n"
        "from basebreak.deployment.live_bridge import _load_canonical_live_bridge_scenario\n"
        "s = _load_canonical_live_bridge_scenario()\n"
        "assert len(s.frozen_contract_digest) == 64\n"
        "assert 'pytest' not in sys.modules\n"
        "assert 'tests.demo.test_p23_killer_demo' not in sys.modules\n"
        "print('OK')\n"
    )
    env = dict(os.environ)
    env["PYTHONPATH"] = str(_REPO_ROOT / "src")
    proc = subprocess.run(
        [sys.executable, "-c", script],
        capture_output=True,
        text=True,
        env=env,
        cwd=str(_REPO_ROOT),
        check=False,
    )
    assert proc.returncode == 0, proc.stderr
    assert "OK" in proc.stdout


# --- Signed request behaviour -------------------------------------------------------


def test_signed_request_with_live_disabled_returns_blocked_live_disabled() -> None:
    headers, body = _signed_request()
    status, resp = _post(headers, body)
    assert status == 503
    assert resp["status"] == "BLOCKED_LIVE_DISABLED"
    assert resp["provider_dispatched"] is False


def test_missing_hmac_returns_401() -> None:
    body = json.dumps({"schema_version": BRIDGE_REQUEST_SCHEMA_VERSION}).encode("utf-8")
    status, resp = _post({}, body)
    assert status == 401
    assert resp["status"] == "UNAUTHORIZED"
    assert resp["provider_dispatched"] is False


def test_invalid_hmac_returns_401() -> None:
    headers, body = _signed_request()
    headers = dict(headers)
    headers["X-Basebreak-Bridge-Signature"] = "deadbeef"
    status, resp = _post(headers, body)
    assert status == 401
    assert resp["status"] == "UNAUTHORIZED"
    assert resp["provider_dispatched"] is False


def test_source_substitution_fails_closed() -> None:
    headers, body = _signed_request(source="b" * 40)
    status, resp = _post(headers, body)
    assert status == 400
    assert resp["status"] == "INVALID_SOURCE"


def test_contract_substitution_fails_closed() -> None:
    headers, body = _signed_request(digest="0" * 64)
    status, resp = _post(headers, body)
    assert status == 400
    assert resp["status"] == "INVALID_CONTRACT"
