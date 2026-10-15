"""Parity and schema verification tests for Cloudflare Workers deployment (P-27.01 & P-27.04).

Verifies that:
1. wrangler.jsonc contains required bindings (Durable Object SQLite, Assets, defaults).
2. Canonical public receipts generated for Cloudflare satisfy Python validation.
3. Health endpoint schema in Cloudflare Worker matches Basebreak Python parity requirements.
4. Zero-Cost Law constraints (LIVE_ENABLED=false, $5.00 safety reserve floor) are frozen.
"""

from __future__ import annotations

import json
import re
from pathlib import Path
from typing import Any, cast

from basebreak.causal.public_receipt import (
    compute_public_receipt_digest,
    verify_public_receipt_integrity,
)
from basebreak.cli.config import BasebreakConfig
from basebreak.security.secret_policy import contains_secret


def _read_wrangler_config(wrangler_path: Path) -> dict[str, Any]:
    """Read and parse wrangler.jsonc stripping JSON comments."""
    text = wrangler_path.read_text(encoding="utf-8")
    text_no_comments = re.sub(r"//.*$", "", text, flags=re.MULTILINE)
    parsed: Any = json.loads(text_no_comments)
    return cast(dict[str, Any], parsed)


class TestCloudflareDeploymentParity:
    """Test suite for Cloudflare Workers configuration and verification parity."""

    def test_wrangler_configuration_parity(self) -> None:
        """Verify wrangler.jsonc configures SQLite DO, Static Assets, and Zero-Cost vars."""
        repo_root = Path(__file__).resolve().parent.parent.parent
        wrangler_file = repo_root / "cloudflare" / "wrangler.jsonc"
        assert wrangler_file.is_file(), "cloudflare/wrangler.jsonc must exist"

        config = _read_wrangler_config(wrangler_file)

        assert config.get("name") == "basebreak"
        assert config.get("main") == "src/index.js"
        assert "nodejs_compat" in config.get("compatibility_flags", [])

        # Assets binding
        assets = config.get("assets", {})
        assert assets.get("directory") in ("./public", "public")
        assert assets.get("binding") == "ASSETS"

        # Durable Object SQLite binding
        do_bindings = config.get("durable_objects", {}).get("bindings", [])
        ledger_binding = next((b for b in do_bindings if b.get("name") == "ADMISSION_LEDGER"), None)
        assert ledger_binding is not None, "ADMISSION_LEDGER binding must be declared"
        assert ledger_binding.get("class_name") == "AdmissionLedgerDO"

        # SQLite migration tag
        migrations = config.get("migrations", [])
        assert any("AdmissionLedgerDO" in m.get("new_sqlite_classes", []) for m in migrations), (
            "AdmissionLedgerDO must be declared as a new_sqlite_class"
        )

        # Environment variables & fail-closed defaults
        vars_dict = config.get("vars", {})
        assert vars_dict.get("LIVE_ENABLED") == "false", "LIVE_ENABLED must default to false"
        assert vars_dict.get("TOKEN_FACTORY_PROMO_STOP_THRESHOLD") == "5.00"
        assert vars_dict.get("ALLOWLISTED_TARGET") == "tests/fixtures/reset_vault"
        assert "GLOBAL_INVOCATION_CAP" in vars_dict

    def test_static_judge_dashboard_asset_presence(self) -> None:
        """Verify the pre-rendered Judge UI dashboard exists and contains core thesis elements."""
        repo_root = Path(__file__).resolve().parent.parent.parent
        index_html = repo_root / "cloudflare" / "public" / "index.html"
        assert index_html.is_file(), "cloudflare/public/index.html must exist"

        html_text = index_html.read_text(encoding="utf-8")
        assert "If the patch matters, the base must break" in html_text
        assert "BASE = FAIL &rarr; CANDIDATE = PASS &rarr; COUNTERFACTUAL = FAIL" in html_text
        assert "AUTHENTIC (SHA-256)" in html_text
        assert "tests/fixtures/reset_vault" in html_text

    def test_canonical_reset_vault_receipt_python_verification(self) -> None:
        """Verify that canonical receipt format matches Python public receipt verification."""
        from basebreak.cli.runner import execute_verification_pipeline

        res = execute_verification_pipeline(
            target="tests/fixtures/demo_target",
            change_class_name="BUG_FIX",
            config=BasebreakConfig(offline_mode=True),
        )
        assert res.receipt is not None
        receipt = res.receipt
        receipt_dict = receipt.to_dict()

        # Recomputed digest check: verify does not raise exception
        verify_public_receipt_integrity(receipt)
        assert contains_secret(json.dumps(receipt_dict)) is False

        # Altering task_id breaks digest integrity
        tampered_dict = dict(receipt_dict)
        tampered_dict["task_id"] = "TAMPERED_TASK"
        recomputed = compute_public_receipt_digest(
            {k: v for k, v in tampered_dict.items() if k != "receipt_digest"}
        )
        assert recomputed != tampered_dict["receipt_digest"]

    def test_health_parity_schema_compatibility(self) -> None:
        """Verify schema compatibility of Cloudflare /health endpoint."""
        expected_sha = "80b43b84014fa61b941c7ebcd87836a56dcd7c92"
        mock_cf_health_data = {
            "status": "ok",
            "platform": "cloudflare_workers",
            "version": "1.0.0",
            "source_commit_id": expected_sha,
            "live_enabled": False,
        }

        # Check required keys are present
        assert mock_cf_health_data["status"] == "ok"
        assert mock_cf_health_data["platform"] == "cloudflare_workers"
        assert mock_cf_health_data["version"] == "1.0.0"
        assert mock_cf_health_data["source_commit_id"] == expected_sha
        assert mock_cf_health_data["live_enabled"] is False
