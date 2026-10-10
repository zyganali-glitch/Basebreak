"""In-memory and persistent run store with idempotency and restart recovery.

P-21.05: Idempotency and recovery for run creation.
Binds idempotency key to request fingerprint, detects conflicts, and recovers
from persistent disk store on server startup.
"""

from __future__ import annotations

import hashlib
import json
import threading
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
        self._lock = threading.Lock()
        self._runs: dict[str, dict[str, Any]] = {}
        self._idempotency_records: dict[str, dict[str, str]] = {}
        self._events: dict[str, list[ApiEvent]] = {}
        self._idempotency_file = self.runs_dir / "idempotency.json"
        self.recover_from_disk()

    @staticmethod
    def _compute_fingerprint(data: dict[str, Any]) -> str:
        """Compute canonical SHA-256 fingerprint of request parameters."""
        # Exclude the idempotency_key itself from the fingerprint
        cleaned = {k: v for k, v in data.items() if k != "idempotency_key"}
        raw_bytes = json.dumps(cleaned, sort_keys=True, separators=(",", ":")).encode("utf-8")
        return hashlib.sha256(raw_bytes).hexdigest()

    def recover_from_disk(self) -> int:
        """Recover existing runs and durable idempotency mapping from disk on startup."""
        recovered_count = 0
        run_ids = self.persistence.list_runs()
        for run_id in run_ids:
            try:
                meta = self.persistence.load_metadata(run_id)
                self._runs[run_id] = meta

                # Recover actual persisted events if available
                persisted_raw_events = self.persistence.load_events(run_id)
                if persisted_raw_events:
                    self._events[run_id] = [ApiEvent.from_dict(raw) for raw in persisted_raw_events]
                elif run_id not in self._events:
                    self._events[run_id] = [
                        ApiEvent.create("run.recovered", run_id, {"status": meta.get("status")})
                    ]
                recovered_count += 1
            except Exception:
                continue

        # Load durable idempotency records
        if self._idempotency_file.is_file():
            try:
                with self._idempotency_file.open("r", encoding="utf-8") as f:
                    self._idempotency_records = json.load(f)
            except Exception:
                pass

        return recovered_count

    def _persist_idempotency_records(self) -> None:
        """Durable persistence of idempotency bindings."""
        self.runs_dir.mkdir(parents=True, exist_ok=True)
        with self._idempotency_file.open("w", encoding="utf-8") as f:
            json.dump(self._idempotency_records, f, indent=2, sort_keys=True)

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

        with self._lock:
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

            # Record factual event stream — NEVER fabricate execution milestones!
            events = [
                ApiEvent.create(
                    "run.created",
                    run_id,
                    {"target": request.target, "change_class": request.change_class},
                )
            ]

            if res.status == "BLOCKED":
                events.append(
                    ApiEvent.create(
                        "run.blocked",
                        run_id,
                        {"message": res.message, "exit_code": res.exit_code},
                    )
                )
            elif res.status == "INVALID_INPUT":
                events.append(
                    ApiEvent.create(
                        "run.invalid_input",
                        run_id,
                        {"message": res.message, "exit_code": res.exit_code},
                    )
                )
            else:
                # Factual world completions
                for world in ("BASE", "CANDIDATE", "COUNTERFACTUAL"):
                    if world in res.world_states:
                        w_state = res.world_states[world]
                        events.append(
                            ApiEvent.create(
                                f"{world.lower()}.completed",
                                run_id,
                                {
                                    "world": world,
                                    "outcome": w_state.get("outcome"),
                                    "exit_code": w_state.get("exit_code"),
                                    "sandbox_id": w_state.get("sandbox_id"),
                                },
                            )
                        )

                if res.causal_transition:
                    events.append(
                        ApiEvent.create(
                            "reconciliation.completed",
                            run_id,
                            {
                                "transition": res.causal_transition,
                                "verdict": res.metadata.get("verdict"),
                            },
                        )
                    )

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

            # Persist run state and events to disk
            self.persistence.save_run(
                run_id=run_id,
                metadata=res.metadata,
                evidence=res.evidence,
                receipt=res.receipt.to_dict() if res.receipt else None,
                events=[e.to_dict() for e in events],
            )

            # Store durable idempotency binding
            if idemp_key:
                self._idempotency_records[idemp_key] = {
                    "fingerprint": fingerprint,
                    "run_id": run_id,
                }
                self._persist_idempotency_records()

            return res.metadata, True
