"""In-memory and persistent run store with idempotency and restart recovery.

P-21.05: Idempotency and recovery for run creation.
Binds idempotency key to request fingerprint, detects conflicts, and recovers
from persistent disk store on server startup.
"""

from __future__ import annotations

import hashlib
import json
from pathlib import Path
from typing import Any

from basebreak.api.models import ApiEvent, RunCreateRequest
from basebreak.cli.config import BasebreakConfig
from basebreak.cli.persistence import RunPersistenceManager
from basebreak.cli.runner import execute_verification_pipeline


class IdempotencyConflictError(Exception):
    """Raised when an idempotency key is reused with a different request payload."""


class ApiRunStore:
    """Manages runs, idempotency mapping, and live event streams."""

    def __init__(self, runs_dir: str | Path = ".basebreak/runs") -> None:
        self.runs_dir = Path(runs_dir)
        self.persistence = RunPersistenceManager(self.runs_dir)
        self._runs: dict[str, dict[str, Any]] = {}
        self._idempotency_records: dict[str, dict[str, str]] = {}
        self._events: dict[str, list[ApiEvent]] = {}
        self.recover_from_disk()

    @staticmethod
    def _compute_fingerprint(data: dict[str, Any]) -> str:
        """Compute canonical SHA-256 fingerprint of request parameters."""
        # Exclude the idempotency_key itself from the fingerprint
        cleaned = {k: v for k, v in data.items() if k != "idempotency_key"}
        raw_bytes = json.dumps(cleaned, sort_keys=True, separators=(",", ":")).encode("utf-8")
        return hashlib.sha256(raw_bytes).hexdigest()

    def recover_from_disk(self) -> int:
        """Recover existing runs from disk into the store on startup."""
        recovered_count = 0
        run_ids = self.persistence.list_runs()
        for run_id in run_ids:
            try:
                meta = self.persistence.load_metadata(run_id)
                self._runs[run_id] = meta
                # If there are no recorded events in memory, generate recovered completion event
                if run_id not in self._events:
                    self._events[run_id] = [
                        ApiEvent.create("run.recovered", run_id, {"status": meta.get("status")})
                    ]
                recovered_count += 1
            except Exception:
                continue
        return recovered_count

    def get_run(self, run_id: str) -> dict[str, Any] | None:
        """Get run metadata by ID."""
        if run_id in self._runs:
            return self._runs[run_id]
        if self.persistence.run_exists(run_id):
            meta = self.persistence.load_metadata(run_id)
            self._runs[run_id] = meta
            return meta
        return None

    def get_evidence(self, run_id: str) -> list[dict[str, Any]]:
        """Get evidence records for a run."""
        return self.persistence.load_evidence(run_id)

    def get_receipt(self, run_id: str) -> dict[str, Any] | None:
        """Get public receipt for a run if present."""
        return self.persistence.load_receipt(run_id)

    def get_events(self, run_id: str) -> list[ApiEvent]:
        """Get event stream for a run."""
        return self._events.get(run_id, [])

    def create_or_get_run(
        self,
        request: RunCreateRequest,
        config: BasebreakConfig | None = None,
    ) -> tuple[dict[str, Any], bool]:
        """Create a new verification run or return existing run via idempotency.

        Returns:
            tuple of (run_metadata_dict, is_new_run: bool)

        Raises:
            IdempotencyConflictError: If idempotency_key is reused with different request payload.
        """
        req_dict = request.to_dict()
        fingerprint = self._compute_fingerprint(req_dict)
        idemp_key = request.idempotency_key

        # Check idempotency record
        if idemp_key:
            if idemp_key in self._idempotency_records:
                record = self._idempotency_records[idemp_key]
                if record["fingerprint"] != fingerprint:
                    raise IdempotencyConflictError(
                        f"Idempotency-Key '{idemp_key}' has already been used "
                        "with different request parameters."
                    )
                existing_run_id = record["run_id"]
                existing_meta = self.get_run(existing_run_id)
                if existing_meta is not None:
                    return existing_meta, False  # Replay existing run

        active_config = config or BasebreakConfig(runs_dir=str(self.runs_dir))

        # Execute verification pipeline
        res = execute_verification_pipeline(
            target=request.target,
            patch=request.patch,
            base_sha=request.base_sha,
            candidate_sha=request.candidate_sha,
            change_class_name=request.change_class,
            allow_live=request.allow_live,
            config=active_config,
        )

        run_id = res.run_id
        self._runs[run_id] = res.metadata

        # Record structured event stream
        events = [
            ApiEvent.create("run.created", run_id, {"target": request.target}),
            ApiEvent.create("contract.frozen", run_id, {"change_class": request.change_class}),
            ApiEvent.create("witness.sealed", run_id, {"witness_id": "wit_001"}),
            ApiEvent.create("base.executing", run_id, {"world": "BASE"}),
            ApiEvent.create(
                "base.completed",
                run_id,
                {"outcome": res.world_states.get("BASE", {}).get("outcome")},
            ),
            ApiEvent.create("candidate.executing", run_id, {"world": "CANDIDATE"}),
            ApiEvent.create(
                "candidate.completed",
                run_id,
                {"outcome": res.world_states.get("CANDIDATE", {}).get("outcome")},
            ),
            ApiEvent.create("counterfactual.executing", run_id, {"world": "COUNTERFACTUAL"}),
            ApiEvent.create(
                "counterfactual.completed",
                run_id,
                {"outcome": res.world_states.get("COUNTERFACTUAL", {}).get("outcome")},
            ),
            ApiEvent.create(
                "reconciliation.completed",
                run_id,
                {"transition": res.causal_transition, "verdict": res.metadata.get("verdict")},
            ),
        ]
        if res.receipt is not None:
            events.append(
                ApiEvent.create(
                    "receipt.generated",
                    run_id,
                    {"receipt_digest": res.receipt.receipt_digest},
                )
            )
        events.append(
            ApiEvent.create(
                "run.completed",
                run_id,
                {"status": res.status, "exit_code": res.exit_code},
            )
        )
        self._events[run_id] = events

        # Store idempotency binding
        if idemp_key:
            self._idempotency_records[idemp_key] = {
                "fingerprint": fingerprint,
                "run_id": run_id,
            }

        return res.metadata, True
