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


class UnpublishableRunError(Exception):
    """Raised when a run cannot be published due to missing, invalid, or secret-bearing receipt."""


class ApiRunStore:
    """Manages runs, idempotency mapping, and live event streams."""

    def __init__(self, runs_dir: str | Path = ".basebreak/runs") -> None:
        self.runs_dir = Path(runs_dir)
        self.persistence = RunPersistenceManager(self.runs_dir)
        self._lock = threading.RLock()
        self._runs: dict[str, dict[str, Any]] = {}
        self._idempotency_records: dict[str, dict[str, str]] = {}
        self._events: dict[str, list[ApiEvent]] = {}
        self._published_runs: set[str] = set()
        self._idempotency_file = self.runs_dir / "idempotency.json"
        self._published_file = self.runs_dir / "published_runs.json"
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
                if meta.get("is_published") is True:
                    if self.is_run_published(run_id):
                        self._published_runs.add(run_id)
                    else:
                        meta["is_published"] = False
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

        # Load durable published run records
        if self._published_file.is_file():
            try:
                with self._published_file.open("r", encoding="utf-8") as f:
                    pub_list = json.load(f)
                    if isinstance(pub_list, list):
                        for pub_id in pub_list:
                            if self.is_run_published(pub_id):
                                self._published_runs.add(pub_id)
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

    def list_runs(self) -> list[str]:
        """List all stored run IDs."""
        return self.persistence.list_runs()

    def has_published_status(self, run_id: str) -> bool:
        """Check whether a run was recorded as published by the operator."""
        if run_id in self._published_runs:
            return True
        meta = self.get_run(run_id)
        return bool(meta and meta.get("is_published") is True)

    def is_run_published(self, run_id: str) -> bool:
        """Check whether a run is explicitly published for signed-out judge access.

        Requires that the run is recorded as published AND has an integrity-validated,
        secret-safe public verification receipt.
        """
        if not self.has_published_status(run_id):
            return False

        # Validate that the published run actually has a valid, untampered receipt
        receipt_dict = self.get_receipt(run_id)
        if receipt_dict is None:
            self._published_runs.discard(run_id)
            return False

        from basebreak.causal.public_receipt import (
            PublicVerificationReceipt,
            verify_public_receipt_integrity,
        )
        from basebreak.security.secret_policy import contains_secret

        try:
            rc_obj = PublicVerificationReceipt.from_dict(receipt_dict)
            verify_public_receipt_integrity(rc_obj)
            if contains_secret(json.dumps(receipt_dict)):
                self._published_runs.discard(run_id)
                return False
        except Exception:
            self._published_runs.discard(run_id)
            return False

        self._published_runs.add(run_id)
        return True

    def publish_run(self, run_id: str) -> bool:
        """Explicitly publish a verified run for signed-out judge access.

        Requires:
        1. Run must exist.
        2. A public receipt must exist.
        3. The public receipt must pass cryptographic integrity verification.
        4. The public receipt must not contain raw recognized secrets.

        Preserves legitimate CONTRADICTED/INCONCLUSIVE/BLOCKED runs with valid receipts;
        does not require a fabricated VERIFIED verdict.

        Raises:
            KeyError: If run does not exist.
            UnpublishableRunError: If receipt is missing, tampered, or contains secrets.
        """
        meta = self.get_run(run_id)
        if meta is None:
            raise KeyError(f"Run '{run_id}' not found.")

        receipt_dict = self.get_receipt(run_id)
        if receipt_dict is None:
            raise UnpublishableRunError(
                f"Run '{run_id}' cannot be published: missing public verification receipt."
            )

        from basebreak.causal.public_receipt import (
            PublicVerificationReceipt,
            verify_public_receipt_integrity,
        )
        from basebreak.security.secret_policy import contains_secret

        if contains_secret(json.dumps(receipt_dict)):
            raise UnpublishableRunError(
                f"Run '{run_id}' cannot be published: receipt contains raw recognized secrets."
            )

        try:
            rc_obj = PublicVerificationReceipt.from_dict(receipt_dict)
            verify_public_receipt_integrity(rc_obj)
        except Exception as exc:
            raise UnpublishableRunError(
                f"Run '{run_id}' cannot be published: receipt integrity verification failed: {exc}"
            ) from exc

        with self._lock:
            meta["is_published"] = True
            self._published_runs.add(run_id)
            run_dir = self.persistence.get_run_dir(run_id)
            meta_file = run_dir / "metadata.json"
            if meta_file.is_file():
                try:
                    with meta_file.open("w", encoding="utf-8") as f:
                        json.dump(meta, f, indent=2, sort_keys=True)
                except Exception:
                    pass
            self._persist_published_records()
            return True

    def list_published_runs(self) -> list[str]:
        """List all published run IDs available for signed-out judge inspection."""
        valid_published: list[str] = []
        for r in sorted(list(self._published_runs)):
            if self.is_run_published(r):
                valid_published.append(r)
        return valid_published

    def _persist_published_records(self) -> None:
        """Durable persistence of published run IDs."""
        self.runs_dir.mkdir(parents=True, exist_ok=True)
        with self._published_file.open("w", encoding="utf-8") as f:
            json.dump(sorted(list(self._published_runs)), f, indent=2, sort_keys=True)

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
                        if request.publish and not existing_meta.get("is_published"):
                            self.publish_run(existing_run_id)
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

            # Persist run state and events to disk first
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

            # If publication requested, explicitly validate and publish
            if request.publish:
                self.publish_run(run_id)

            return res.metadata, True
