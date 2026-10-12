"""Health and source SHA parity verification (P-27.04).

Verifies that a running Basebreak instance reports healthy readiness
and exact commit SHA parity against expected target revision.
"""

from __future__ import annotations

import json
import urllib.error
import urllib.request
from dataclasses import dataclass
from typing import Any


@dataclass(frozen=True)
class HealthParityResult:
    """Outcome of health and source SHA parity verification."""

    success: bool
    status_code: int
    reported_sha: str
    expected_sha: str
    is_sha_matched: bool
    service_status: str
    uptime_seconds: float
    raw_payload: dict[str, Any]
    message: str


def verify_health_parity(
    expected_sha: str,
    base_url: str,
    timeout_seconds: float = 5.0,
) -> HealthParityResult:
    """Verify health readiness and exact source SHA parity of a target server.

    Connects to '<base_url>/health' and checks that:
    - HTTP response code is 200;
    - status field is 'healthy';
    - commit_sha matches expected_sha (case-insensitive hex comparison).
    """
    clean_base = base_url.rstrip("/")
    health_url = f"{clean_base}/health"

    req = urllib.request.Request(
        health_url,
        headers={"User-Agent": "Basebreak-Health-Verifier/0.1.0"},
        method="GET",
    )

    try:
        with urllib.request.urlopen(req, timeout=timeout_seconds) as resp:
            status_code = resp.status
            body_bytes = resp.read()
            payload = json.loads(body_bytes.decode("utf-8"))
    except urllib.error.HTTPError as exc:
        return HealthParityResult(
            success=False,
            status_code=exc.code,
            reported_sha="N/A",
            expected_sha=expected_sha,
            is_sha_matched=False,
            service_status="http_error",
            uptime_seconds=0.0,
            raw_payload={"error": str(exc)},
            message=f"Health probe returned HTTP {exc.code}: {exc.reason}",
        )
    except Exception as exc:
        return HealthParityResult(
            success=False,
            status_code=0,
            reported_sha="N/A",
            expected_sha=expected_sha,
            is_sha_matched=False,
            service_status="connection_failed",
            uptime_seconds=0.0,
            raw_payload={"error": str(exc)},
            message=f"Failed to connect to health endpoint: {exc}",
        )

    reported_sha = str(payload.get("commit_sha", "")).strip()
    service_status = str(payload.get("status", "")).strip()
    uptime = float(payload.get("uptime_seconds", 0.0))

    clean_expected = expected_sha.strip().lower()
    clean_reported = reported_sha.lower()

    is_matched = (
        clean_expected == clean_reported
        and len(clean_expected) == 40
        and clean_reported not in ("unknown_build_sha", "unknown", "")
    )
    is_healthy = service_status.lower() in ("healthy", "ok")

    success = is_healthy and is_matched

    if clean_reported in ("unknown_build_sha", "unknown", "") or len(clean_reported) != 40:
        msg = (
            f"Reported commit SHA '{reported_sha}' is not a valid 40-character git SHA "
            f"(build SHA unknown); production parity cannot pass."
        )
    elif not is_healthy:
        msg = f"Service reported unhealthy status: '{service_status}'"
    elif not is_matched:
        msg = (
            f"Source SHA mismatch: expected {clean_expected[:12]}..., "
            f"reported {clean_reported[:12]}..."
        )
    else:
        msg = f"Health and source SHA verified in parity with commit {clean_reported[:12]}."

    return HealthParityResult(
        success=success,
        status_code=status_code,
        reported_sha=reported_sha,
        expected_sha=expected_sha,
        is_sha_matched=is_matched,
        service_status=service_status,
        uptime_seconds=uptime,
        raw_payload=payload,
        message=msg,
    )
