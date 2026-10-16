"""Global pytest safeguards for the Basebreak test suite.

INCIDENT SAFEGUARD (P-27.06): a previous offline validation run executed
``@pytest.mark.live`` tests because provider credentials were present in the
environment while live-marked tests were not excluded. Live-marked tests make
real, chargeable Nebius/NVIDIA provider calls and may rewrite historical proof
documents, so they must NEVER run by default.

This module enforces the smallest focused opt-in: unless the operator explicitly
sets ``BASEBREAK_ALLOW_LIVE_TESTS=1``, every ``live``-marked test is skipped at
collection time, regardless of which credentials happen to be present. Ordinary
offline validation therefore cannot inherit live credentials and accidentally
issue provider calls or mutate historical evidence.
"""

from __future__ import annotations

import os

import pytest

LIVE_MARKER_NAME = "live"
ALLOW_LIVE_ENV_VAR = "BASEBREAK_ALLOW_LIVE_TESTS"


def pytest_collection_modifyitems(config: pytest.Config, items: list[pytest.Item]) -> None:
    """Skip live-marked tests unless the operator explicitly opts in."""
    if os.environ.get(ALLOW_LIVE_ENV_VAR, "").strip() == "1":
        return

    skip_live = pytest.mark.skip(
        reason=(
            "live-marked tests require explicit opt-in via "
            f"{ALLOW_LIVE_ENV_VAR}=1 (offline default)."
        )
    )
    for item in items:
        if LIVE_MARKER_NAME in item.keywords:
            item.add_marker(skip_live)
