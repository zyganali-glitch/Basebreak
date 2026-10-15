"""Immutable comparison checks for historical LIVE_NEBIUS proof documents."""

from __future__ import annotations

import subprocess
from pathlib import Path

PREDECESSOR_SHA = "32235bce2ab31550406ca948f3111892765245df"
HISTORICAL_DOCS = [
    "docs/P05_06_LIVE_ADAPTER_INTEGRATION.md",
    "docs/P09_LIVE_WITNESS_PLAN.md",
    "docs/P10_LIVE_CLOSURE_PROOF.md",
    "docs/P11_LIVE_CLOSURE_PROOF.md",
    "docs/P13_LIVE_CLOSURE_PROOF.md",
]


def _git_diff(repo_root: Path, paths: list[str]) -> subprocess.CompletedProcess[str]:
    proc = subprocess.run(
        ["git", "--no-pager", "diff", "--exit-code", PREDECESSOR_SHA, "--", *paths],
        cwd=repo_root,
        capture_output=True,
        text=True,
    )
    return proc


def test_historical_live_docs_match_predecessor_exactly() -> None:
    """Historical live proof files must match the predecessor commit exactly."""
    repo_root = Path(__file__).resolve().parent.parent.parent
    diff_proc = _git_diff(repo_root, HISTORICAL_DOCS)
    assert diff_proc.returncode == 0, diff_proc.stdout
