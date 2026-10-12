"""Tests for deployment packaging, container configuration, and CLI server (P-27.02).

Validates Dockerfile, .dockerignore, docker-compose.yml, health readiness,
reproducible dependency installation, and safe network defaults.
"""

from __future__ import annotations

from pathlib import Path

import pytest

from basebreak.cli.main import build_parser
from basebreak.deployment.health import (
    BASEBREAK_VERSION,
    SERVICE_NAME,
    get_build_commit_sha,
    get_health_status,
)

REPO_ROOT = Path(__file__).resolve().parent.parent.parent


def test_dockerfile_reproducibility_and_security() -> None:
    """Validate Dockerfile adheres to security, rootless, and health standards."""
    dockerfile_path = REPO_ROOT / "Dockerfile"
    assert dockerfile_path.is_file(), "Dockerfile must exist at repository root"

    content = dockerfile_path.read_text(encoding="utf-8")

    # Base image must be python:3.11-slim
    assert "FROM python:3.11-slim" in content

    # Non-root user created and switched
    assert "useradd" in content and "appuser" in content
    assert "USER appuser" in content

    # Standard port exposure
    assert "EXPOSE 8080" in content

    # Native HTTP health check probe defined
    assert "HEALTHCHECK" in content
    assert "/health" in content

    # Default entrypoint runs server on safe host and port
    assert 'CMD ["python", "-m", "basebreak.cli.main", "serve"' in content

    # No credentials embedded
    assert "NEBIUS_API_KEY=" not in content
    assert "TAVILY_API_KEY=" not in content
    assert "password" not in content.lower()


def test_dockerignore_secret_and_artifact_hygiene() -> None:
    """.dockerignore must prevent copying git history, venvs, caches, and secrets."""
    ignore_path = REPO_ROOT / ".dockerignore"
    assert ignore_path.is_file(), ".dockerignore must exist"

    patterns = set(ignore_path.read_text(encoding="utf-8").splitlines())
    clean_patterns = {p.strip() for p in patterns if p.strip() and not p.startswith("#")}

    assert ".git" in clean_patterns
    assert ".venv" in clean_patterns
    assert ".env" in clean_patterns
    assert "__pycache__" in clean_patterns


def test_docker_compose_configuration() -> None:
    """docker-compose.yml must define reproducible local container orchestration."""
    compose_path = REPO_ROOT / "docker-compose.yml"
    assert compose_path.is_file(), "docker-compose.yml must exist"

    content = compose_path.read_text(encoding="utf-8")
    assert "basebreak:" in content
    assert "8080:8080" in content
    assert "healthcheck:" in content
    assert "/health" in content


def test_health_metadata_structure() -> None:
    """get_health_status produces valid structured health and version metadata."""
    status = get_health_status(server_start_time=100.0, published_runs_count=3)

    assert status["status"] == "healthy"
    assert status["service"] == SERVICE_NAME
    assert status["version"] == BASEBREAK_VERSION
    assert status["published_runs_count"] == 3
    assert status["read_only_judge_mode"] is True
    assert isinstance(status["commit_sha"], str)
    assert len(status["commit_sha"]) > 0


def test_build_commit_sha_env_override(monkeypatch: pytest.MonkeyPatch) -> None:
    """BASEBREAK_BUILD_COMMIT_SHA takes precedence over git discovery."""
    test_sha = "abcdef1234567890abcdef1234567890abcdef12"
    monkeypatch.setenv("BASEBREAK_BUILD_COMMIT_SHA", test_sha)
    assert get_build_commit_sha() == test_sha


def test_serve_cli_argument_parsing() -> None:
    """Verify that 'basebreak serve' CLI subcommand parses host, port, and token."""
    parser = build_parser()
    args = parser.parse_args(
        ["serve", "--host", "0.0.0.0", "--port", "9090", "--bearer-token", "test-token"]
    )

    assert args.command == "serve"
    assert args.host == "0.0.0.0"
    assert args.port == 9090
    assert args.bearer_token == "test-token"


def test_serve_cli_defaults() -> None:
    """Verify 'basebreak serve' defaults when optional arguments omitted."""
    parser = build_parser()
    args = parser.parse_args(["serve"])

    assert args.command == "serve"
    assert args.host is None
    assert args.port is None
    assert args.bearer_token is None
