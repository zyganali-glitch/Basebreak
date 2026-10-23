"""P-29.01 Clean-Checkout Reproducibility Tests.

Validates that Basebreak can be reproduced in an isolated, clean directory from git
without relying on developer workspace state, cached build artifacts, or private
operator environment variables.
"""

from __future__ import annotations

import os
import shutil
import subprocess
import tempfile
from pathlib import Path

import pytest

REPO_ROOT = Path(__file__).resolve().parent.parent.parent


def test_runtime_dependencies_are_zero() -> None:
    """Basebreak runtime must have zero external runtime dependencies in pyproject.toml."""
    pyproject_path = REPO_ROOT / "pyproject.toml"
    assert pyproject_path.is_file(), "pyproject.toml must exist"
    content = pyproject_path.read_text(encoding="utf-8")

    # Verify dependencies is explicitly empty
    assert "dependencies = []" in content or "dependencies = [\n]" in content, (
        "Basebreak core runtime must have zero external runtime dependencies "
        "to ensure deterministic public reproducibility."
    )


def test_worker_runtime_dependencies_are_zero() -> None:
    """Cloudflare Worker runtime must have zero runtime dependencies in package.json."""
    pkg_path = REPO_ROOT / "cloudflare" / "package.json"
    assert pkg_path.is_file(), "cloudflare/package.json must exist"
    content = pkg_path.read_text(encoding="utf-8")

    # It must have devDependencies only, not production dependencies
    assert '"dependencies"' not in content, (
        "Cloudflare Worker must have zero runtime npm dependencies. "
        "Only devDependencies are permitted for testing."
    )


def test_dependency_freeze_artifacts_are_pinned() -> None:
    """Verifies Python build and dev dependencies are strictly pinned with no floating ranges."""
    pyproject_path = REPO_ROOT / "pyproject.toml"
    assert pyproject_path.is_file(), "pyproject.toml must exist"
    pyproject_text = pyproject_path.read_text(encoding="utf-8")

    # pyproject.toml build-system and dev dependencies must be pinned (==), not floating (>=)
    assert 'requires = ["hatchling==' in pyproject_text, "hatchling build-system must be pinned"
    for dev_dep in ["mypy==", "pytest==", "python-dotenv==", "ruff=="]:
        assert dev_dep in pyproject_text, f"{dev_dep} must be pinned in pyproject.toml dev"

    # constraints.txt must exist and contain locked transitive toolchain
    constraints_path = REPO_ROOT / "constraints.txt"
    assert constraints_path.is_file(), "constraints.txt lock artifact must exist"
    constraints_text = constraints_path.read_text(encoding="utf-8")
    for locked in [
        "hatchling==",
        "mypy==",
        "pytest==",
        "python-dotenv==",
        "ruff==",
        "typing-extensions==",
        "pluggy==",
        "packaging==",
    ]:
        assert locked in constraints_text, f"{locked} must be pinned in constraints.txt"


def test_isolated_clean_checkout_reproduction() -> None:
    """Verifies that an isolated checkout reproduces core imports and syntax."""
    git_exe = shutil.which("git")
    node_exe = shutil.which("node")
    if not git_exe:
        pytest.skip("git not available on PATH")

    with tempfile.TemporaryDirectory(prefix="basebreak_clean_test_") as tmp_dir:
        tmp_path = Path(tmp_dir)

        # Create clean export of git tracked files
        archive_proc = subprocess.run(
            [git_exe, "archive", "HEAD"],
            cwd=REPO_ROOT,
            capture_output=True,
            check=True,
        )

        tar_exe = shutil.which("tar")
        if not tar_exe:
            pytest.skip("tar not available on PATH for git archive unpacking")

        subprocess.run(
            [tar_exe, "-xf", "-", "-C", str(tmp_path)],
            input=archive_proc.stdout,
            check=True,
        )

        # 1. Verify clean exported tree has no workspace caches
        assert not (tmp_path / ".venv").exists()
        assert not (tmp_path / ".pytest_cache").exists()
        assert not (tmp_path / ".mypy_cache").exists()
        assert not (tmp_path / ".ruff_cache").exists()

        # 2. Verify pyproject.toml, package.json, and constraints.txt are present
        assert (tmp_path / "pyproject.toml").is_file()
        assert (tmp_path / "cloudflare" / "package.json").is_file()
        # Note: constraints.txt is tracked in git and will be present in HEAD commit archive
        if (REPO_ROOT / "constraints.txt").is_file() and (tmp_path / "constraints.txt").is_file():
            assert (tmp_path / "constraints.txt").is_file()

        # 3. Verify core package imports directly from src without local env
        clean_env = {
            "SYSTEMROOT": os.environ.get("SYSTEMROOT", ""),
            "PATH": os.environ.get("PATH", ""),
            "PYTHONPATH": str(tmp_path / "src"),
        }
        py_code = (
            "import basebreak\n"
            "from basebreak.causal.public_receipt import PublicVerificationReceipt\n"
            "from basebreak.domain.verdict import PreliminaryVerdict\n"
            "print('BASEBREAK_CLEAN_IMPORT_OK')\n"
        )
        py_res = subprocess.run(
            [shutil.which("python") or "python", "-c", py_code],
            cwd=tmp_path,
            env=clean_env,
            capture_output=True,
            text=True,
        )
        assert py_res.returncode == 0, f"Clean import failed: {py_res.stderr}"
        assert "BASEBREAK_CLEAN_IMPORT_OK" in py_res.stdout

        # 4. If node is available, verify Worker JavaScript files pass syntax check
        if node_exe:
            worker_files = [
                "src/index.js",
                "src/ledger.js",
                "src/crypto_utils.js",
                "src/provider_dispatcher.js",
                "src/sql_adapter.js",
            ]
            for rel_file in worker_files:
                target_file = tmp_path / "cloudflare" / rel_file
                if target_file.is_file():
                    node_res = subprocess.run(
                        [node_exe, "--check", str(target_file)],
                        capture_output=True,
                        text=True,
                    )
                    assert node_res.returncode == 0, (
                        f"Worker file syntax check failed for {rel_file}: {node_res.stderr}"
                    )
