"""Durable run state management independent of mutable workspace.

P-25.01: Persist recoverable run state without trusting mutable workspace.
State is stored in a designated durable path using atomic file writes (temp + rename)
so that mid-pipeline crashes do not result in partial or corrupted records.
"""

from __future__ import annotations

import json
import os
from dataclasses import asdict, dataclass, field
from datetime import datetime, timezone
from enum import Enum
from pathlib import Path
from typing import Any


class RunStep(str, Enum):
    """Execution step sequence for a verification pipeline."""

    INITIALIZED = "INITIALIZED"
    CONTRACT_FROZEN = "CONTRACT_FROZEN"
    BASE_EXECUTED = "BASE_EXECUTED"
    CANDIDATE_EXECUTED = "CANDIDATE_EXECUTED"
    COUNTERFACTUAL_EXECUTED = "COUNTERFACTUAL_EXECUTED"
    RECONCILED = "RECONCILED"
    RECEIPT_GENERATED = "RECEIPT_GENERATED"
    COMPLETED = "COMPLETED"
    FAILED = "FAILED"


@dataclass(frozen=True, slots=True)
class DurableRunState:
    """Immutable snapshot of pipeline progress and provenance bindings."""

    run_id: str
    step: RunStep
    source_repo: str
    base_sha: str
    candidate_sha: str | None = None
    created_at: str = field(default_factory=lambda: datetime.now(timezone.utc).isoformat())
    updated_at: str = field(default_factory=lambda: datetime.now(timezone.utc).isoformat())
    metadata: dict[str, Any] = field(default_factory=dict)
    evidence_digests: tuple[str, ...] = field(default_factory=tuple)
    error_reason: str | None = None
    receipt_digest: str | None = None

    def to_dict(self) -> dict[str, Any]:
        """Convert state to a JSON-serializable dictionary."""
        d = asdict(self)
        d["step"] = self.step.value
        d["evidence_digests"] = list(self.evidence_digests)
        return d

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> DurableRunState:
        """Construct state from dictionary."""
        return cls(
            run_id=data["run_id"],
            step=RunStep(data["step"]),
            source_repo=data["source_repo"],
            base_sha=data["base_sha"],
            candidate_sha=data.get("candidate_sha"),
            created_at=data["created_at"],
            updated_at=data["updated_at"],
            metadata=dict(data.get("metadata", {})),
            evidence_digests=tuple(data.get("evidence_digests", [])),
            error_reason=data.get("error_reason"),
            receipt_digest=data.get("receipt_digest"),
        )


class DurableStateManager:
    """Manages atomic durable state persistence outside the workspace."""

    def __init__(self, storage_dir: str | Path) -> None:
        self.storage_dir = Path(storage_dir)
        self.storage_dir.mkdir(parents=True, exist_ok=True)

    def _get_run_path(self, run_id: str) -> Path:
        """Return canonical path to state file for run_id."""
        return self.storage_dir / f"{run_id}.state.json"

    def save_state(self, state: DurableRunState) -> Path:
        """Persist state atomically using write-to-temp and rename."""
        target_path = self._get_run_path(state.run_id)
        temp_path = self.storage_dir / f"{state.run_id}.state.json.tmp.{os.getpid()}"

        payload = state.to_dict()
        with temp_path.open("w", encoding="utf-8") as f:
            json.dump(payload, f, indent=2, sort_keys=True)
            f.flush()
            os.fsync(f.fileno())

        os.replace(temp_path, target_path)
        return target_path

    def load_state(self, run_id: str) -> DurableRunState | None:
        """Load state from disk, returning None if not found."""
        target_path = self._get_run_path(run_id)
        if not target_path.is_file():
            return None
        with target_path.open("r", encoding="utf-8") as f:
            data = json.load(f)
        return DurableRunState.from_dict(data)

    def transition(
        self,
        current_state: DurableRunState,
        next_step: RunStep,
        *,
        error_reason: str | None = None,
        receipt_digest: str | None = None,
        additional_evidence: tuple[str, ...] = (),
        extra_metadata: dict[str, Any] | None = None,
    ) -> DurableRunState:
        """Create and atomically persist a step transition."""
        meta = dict(current_state.metadata)
        if extra_metadata:
            meta.update(extra_metadata)

        ev_digests = tuple(list(current_state.evidence_digests) + list(additional_evidence))

        new_state = DurableRunState(
            run_id=current_state.run_id,
            step=next_step,
            source_repo=current_state.source_repo,
            base_sha=current_state.base_sha,
            candidate_sha=current_state.candidate_sha,
            created_at=current_state.created_at,
            updated_at=datetime.now(timezone.utc).isoformat(),
            metadata=meta,
            evidence_digests=ev_digests,
            error_reason=error_reason or current_state.error_reason,
            receipt_digest=receipt_digest or current_state.receipt_digest,
        )
        self.save_state(new_state)
        return new_state

    def list_run_ids(self) -> list[str]:
        """List all run IDs found in the storage directory."""
        run_ids: list[str] = []
        for p in self.storage_dir.glob("*.state.json"):
            name = p.name
            if name.endswith(".state.json"):
                run_ids.append(name[: -len(".state.json")])
        return sorted(run_ids)
