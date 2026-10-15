"""Integration test executing the real Miniflare/workerd runtime preflight.

P-27.03 Closure Obligation:
Executes the real Miniflare/workerd preflight on GitHub Actions Linux runner
and local environments, asserting exit code 0 and all 6 runtime checks passing.

Note on Vitest vs Miniflare/workerd:
The upstream `@cloudflare/vitest-plugin` runner currently aborts before test collection
with `Error: File path must be a file: URL` (`npm run test:workers`). That broken harness
is explicitly distinguished from this independent Miniflare/workerd preflight
(`npm run test:workerd-preflight`), which exercises the real bundled Worker entrypoint,
static assets, health parity, authenticated admin endpoints, atomic admission contention,
SQLite Durable Object transactional rollbacks, recovery across re-instantiation, and
fail-closed provider dispatch.

Evidence Provenance: LOCAL_EXECUTION.
No credentials, no Cloudflare deployment, and no Nebius calls.
"""

from __future__ import annotations

import os
import re
import shutil
import subprocess
from pathlib import Path

EXPECTED_CHECK_NAMES = (
    "serves static judge asset and truthful health",
    "uses Durable Object SQLite transaction rollback",
    "enforces atomic admission, contention, and idempotency",
    "requires admin auth, sanitizes public data, and blocks provider dispatch",
    "recovers durable state across object re-instantiation",
    "rejects forged live receipts and preserves kill switch",
)


def test_workerd_miniflare_preflight_real_runtime() -> None:
    """Execute real Miniflare/workerd preflight and assert all 6 checks pass."""
    repo_root = Path(__file__).resolve().parent.parent.parent
    cloudflare_dir = repo_root / "cloudflare"
    package_lock = cloudflare_dir / "package-lock.json"
    package_json = cloudflare_dir / "package.json"

    assert cloudflare_dir.is_dir(), f"cloudflare directory not found at {cloudflare_dir}"
    assert package_json.is_file(), "cloudflare/package.json must exist"
    assert package_lock.is_file(), "cloudflare/package-lock.json must exist"

    # 1. Require Node and npm tooling (must fail CI if unavailable)
    npm_bin = shutil.which("npm")
    assert npm_bin is not None, "npm executable not found on PATH; Node.js/npm tooling is required"
    node_bin = shutil.which("node")
    assert node_bin is not None, (
        "node executable not found on PATH; Node.js/npm tooling is required"
    )

    # 2. Reproducibly install dependencies from package-lock.json if miniflare is not installed
    # or if running under CI
    node_modules_miniflare = cloudflare_dir / "node_modules" / "miniflare"
    is_ci = "CI" in os.environ or "GITHUB_ACTIONS" in os.environ
    if is_ci or not node_modules_miniflare.is_dir():
        install_proc = subprocess.run(
            [npm_bin, "ci"],
            cwd=cloudflare_dir,
            capture_output=True,
            text=True,
            timeout=180,
        )
        assert install_proc.returncode == 0, (
            f"npm ci failed with code {install_proc.returncode}:\n"
            f"stdout: {install_proc.stdout}\n"
            f"stderr: {install_proc.stderr}"
        )

    # 3. Execute real npm run test:workerd-preflight command
    preflight_proc = subprocess.run(
        [npm_bin, "run", "test:workerd-preflight"],
        cwd=cloudflare_dir,
        capture_output=True,
        text=True,
        timeout=120,
    )

    # 4. Assert zero exit code
    assert preflight_proc.returncode == 0, (
        f"npm run test:workerd-preflight failed with return code {preflight_proc.returncode}:\n"
        f"STDOUT:\n{preflight_proc.stdout}\n"
        f"STDERR:\n{preflight_proc.stderr}"
    )

    # 5. Assert all six genuine runtime checks passing
    # In non-TTY environments (such as CI), Node.js node:test TAP reporter routes
    # test console output to stderr to prevent corrupting stdout TAP stream.
    combined_output = f"{preflight_proc.stdout}\n{preflight_proc.stderr}"
    for name in EXPECTED_CHECK_NAMES:
        pattern = rf"{re.escape(name)}\s*\.\.\.\s*(?:#\s*)?PASS"
        assert re.search(pattern, combined_output) is not None, (
            f"Missing required preflight check passing marker for {name!r}:\n"
            f"STDOUT:\n{preflight_proc.stdout}\n"
            f"STDERR:\n{preflight_proc.stderr}"
        )

    assert "Miniflare workerd preflight summary: 6/6 checks passed." in combined_output, (
        f"Summary marker not found in preflight output:\n"
        f"STDOUT:\n{preflight_proc.stdout}\n"
        f"STDERR:\n{preflight_proc.stderr}"
    )
    assert "Miniflare workerd preflight passed." in combined_output, (
        f"Completion marker not found in preflight output:\n"
        f"STDOUT:\n{preflight_proc.stdout}\n"
        f"STDERR:\n{preflight_proc.stderr}"
    )
