"""Immutable comparison checks for historical LIVE_NEBIUS proof documents."""

from __future__ import annotations

import subprocess
from pathlib import Path

PREDECESSOR_SHA = "32235bce2ab31550406ca948f3111892765245df"
HISTORICAL_DOC_BLOB_HASHES = {
    "docs/P05_06_LIVE_ADAPTER_INTEGRATION.md": "dc61d338e0e49184d15b9a7671c0fe2464e50f37",
    "docs/P09_LIVE_WITNESS_PLAN.md": "9d22d785a0c29a8cf4648aeada0fd271a193aa51",
    "docs/P10_LIVE_CLOSURE_PROOF.md": "1c03ea729fa2f867312623b8b6fc6c88fc1d73bc",
    "docs/P11_LIVE_CLOSURE_PROOF.md": "23232d1b43809a4a14a5a64898f32357627f102a",
    "docs/P13_LIVE_CLOSURE_PROOF.md": "e914f917afd1c3dfa39cd3e7be6b70a2a1559753",
}


def _git_hash_object(repo_root: Path, relative_path: str) -> str:
    proc = subprocess.run(
        ["git", "hash-object", relative_path],
        cwd=repo_root,
        check=True,
        capture_output=True,
        text=True,
    )
    return proc.stdout.strip()


def test_historical_live_docs_match_predecessor_exactly() -> None:
    """Historical live proof files must match the predecessor commit exactly."""
    repo_root = Path(__file__).resolve().parent.parent.parent

    for relative_path, expected_blob_hash in HISTORICAL_DOC_BLOB_HASHES.items():
        actual_blob_hash = _git_hash_object(repo_root, relative_path)
        assert actual_blob_hash == expected_blob_hash, (
            f"{relative_path} drifted from predecessor {PREDECESSOR_SHA}: "
            f"{actual_blob_hash} != {expected_blob_hash}"
        )
