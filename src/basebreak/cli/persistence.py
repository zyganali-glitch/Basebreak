"""Persistence manager for CLI verification runs.

Persists and loads run metadata, evidence records, and public receipts
under `.basebreak/runs/<run_id>/`.
"""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any

from basebreak.cli.config import DEFAULT_RUNS_DIR


class RunNotFoundError(Exception):
    """Raised when a requested run_id cannot be found in the runs store."""


class RunCorruptError(Exception):
    """Raised when run files on disk are invalid or corrupted."""


class RunPersistenceManager:
    """Manages disk persistence of verification runs."""

    def __init__(self, runs_dir: str | Path = DEFAULT_RUNS_DIR) -> None:
        self.runs_dir = Path(runs_dir)

    def get_run_dir(self, run_id: str) -> Path:
        """Get directory path for a specific run ID."""
        return self.runs_dir / run_id

    def run_exists(self, run_id: str) -> bool:
        """Check if run exists."""
        return (self.get_run_dir(run_id) / "metadata.json").is_file()

    def save_run(
        self,
        run_id: str,
        metadata: dict[str, Any],
        evidence: list[dict[str, Any]] | None = None,
        receipt: dict[str, Any] | None = None,
        events: list[dict[str, Any]] | None = None,
    ) -> Path:
        """Save run state to disk."""
        run_dir = self.get_run_dir(run_id)
        run_dir.mkdir(parents=True, exist_ok=True)

        meta_file = run_dir / "metadata.json"
        with meta_file.open("w", encoding="utf-8") as f:
            json.dump(metadata, f, indent=2, sort_keys=True)

        ev_file = run_dir / "evidence.json"
        with ev_file.open("w", encoding="utf-8") as f:
            json.dump(evidence if evidence is not None else [], f, indent=2, sort_keys=True)

        if receipt is not None:
            rc_file = run_dir / "receipt.json"
            with rc_file.open("w", encoding="utf-8") as f:
                json.dump(receipt, f, indent=2, sort_keys=True)

        if events is not None:
            events_file = run_dir / "events.json"
            with events_file.open("w", encoding="utf-8") as f:
                json.dump(events, f, indent=2, sort_keys=True)

        return run_dir

    def load_metadata(self, run_id: str) -> dict[str, Any]:
        """Load metadata for a run."""
        meta_file = self.get_run_dir(run_id) / "metadata.json"
        if not meta_file.is_file():
            raise RunNotFoundError(f"Run '{run_id}' not found at {meta_file}")
        try:
            with meta_file.open("r", encoding="utf-8") as f:
                data = json.load(f)
            if not isinstance(data, dict):
                raise RunCorruptError(f"metadata.json must contain a JSON object in {run_id}")
            return data
        except json.JSONDecodeError as exc:
            raise RunCorruptError(f"Malformed metadata.json in {run_id}: {exc}") from exc

    def load_evidence(self, run_id: str) -> list[dict[str, Any]]:
        """Load evidence records for a run."""
        ev_file = self.get_run_dir(run_id) / "evidence.json"
        if not ev_file.is_file():
            if not self.run_exists(run_id):
                raise RunNotFoundError(f"Run '{run_id}' not found")
            return []
        try:
            with ev_file.open("r", encoding="utf-8") as f:
                data = json.load(f)
            if not isinstance(data, list):
                raise RunCorruptError(f"evidence.json must contain a JSON list in {run_id}")
            return data
        except json.JSONDecodeError as exc:
            raise RunCorruptError(f"Malformed evidence.json in {run_id}: {exc}") from exc

    def load_receipt(self, run_id: str) -> dict[str, Any] | None:
        """Load public receipt for a run if available."""
        rc_file = self.get_run_dir(run_id) / "receipt.json"
        if not rc_file.is_file():
            if not self.run_exists(run_id):
                raise RunNotFoundError(f"Run '{run_id}' not found")
            return None
        try:
            with rc_file.open("r", encoding="utf-8") as f:
                data = json.load(f)
            if not isinstance(data, dict):
                raise RunCorruptError(f"receipt.json must contain a JSON object in {run_id}")
            return data
        except json.JSONDecodeError as exc:
            raise RunCorruptError(f"Malformed receipt.json in {run_id}: {exc}") from exc

    def load_events(self, run_id: str) -> list[dict[str, Any]]:
        """Load events records for a run if available."""
        events_file = self.get_run_dir(run_id) / "events.json"
        if not events_file.is_file():
            if not self.run_exists(run_id):
                raise RunNotFoundError(f"Run '{run_id}' not found")
            return []
        try:
            with events_file.open("r", encoding="utf-8") as f:
                data = json.load(f)
            if not isinstance(data, list):
                raise RunCorruptError(f"events.json must contain a JSON list in {run_id}")
            return data
        except json.JSONDecodeError as exc:
            raise RunCorruptError(f"Malformed events.json in {run_id}: {exc}") from exc

    def list_runs(self) -> list[str]:
        """List all run IDs in the store."""
        if not self.runs_dir.is_dir():
            return []
        runs = []
        for p in self.runs_dir.iterdir():
            if p.is_dir() and (p / "metadata.json").is_file():
                runs.append(p.name)
        return sorted(runs, reverse=True)
