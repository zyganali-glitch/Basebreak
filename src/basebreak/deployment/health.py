"""Health readiness and runtime metadata for Basebreak deployment (P-27.02 & P-27.04).

Provides source SHA visibility, uptime tracking, and service status
for container health probes and judge verification.
"""

from __future__ import annotations

import os
import subprocess
import time
from typing import Any

BASEBREAK_VERSION: str = "0.1.0"
SERVICE_NAME: str = "basebreak-verification-runtime"


def get_build_commit_sha() -> str:
    """Resolve build commit SHA from environment or git repository.

    Priority:
    1. BASEBREAK_BUILD_COMMIT_SHA environment variable (injected at build/deploy time).
    2. Local git repository 'git rev-parse HEAD' if git is available.
    3. Fallback to 'UNKNOWN_BUILD_SHA'.
    """
    env_sha = os.environ.get("BASEBREAK_BUILD_COMMIT_SHA")
    if env_sha and env_sha.strip():
        return env_sha.strip()

    try:
        proc = subprocess.run(
            ["git", "rev-parse", "HEAD"],
            capture_output=True,
            text=True,
            timeout=2.0,
            check=False,
        )
        if proc.returncode == 0 and proc.stdout.strip():
            return proc.stdout.strip()
    except Exception:
        pass

    return "UNKNOWN_BUILD_SHA"


def get_health_status(
    server_start_time: float | None = None,
    published_runs_count: int = 0,
) -> dict[str, Any]:
    """Generate structured health and identity status dictionary."""
    uptime = round(time.time() - server_start_time, 2) if server_start_time is not None else 0.0
    return {
        "status": "healthy",
        "service": SERVICE_NAME,
        "version": BASEBREAK_VERSION,
        "commit_sha": get_build_commit_sha(),
        "uptime_seconds": uptime,
        "published_runs_count": published_runs_count,
        "read_only_judge_mode": True,
    }
