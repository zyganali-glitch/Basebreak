"""API data contracts and models derived from domain types.

P-21.01: Defines run API contracts from domain types.
"""

from __future__ import annotations

import datetime
import json
from dataclasses import asdict, dataclass
from typing import Any


@dataclass(slots=True)
class RunCreateRequest:
    """Request payload to create a new verification run."""

    target: str
    patch: str | None = None
    base_sha: str | None = None
    candidate_sha: str | None = None
    change_class: str = "BUG_FIX"
    idempotency_key: str | None = None
    allow_live: bool = False

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> RunCreateRequest:
        if not isinstance(data, dict):
            raise TypeError(f"Payload must be a dictionary, got {type(data).__name__}")
        target = data.get("target")
        if not target or not isinstance(target, str):
            raise ValueError("Field 'target' is required and must be a non-empty string.")

        return cls(
            target=target.strip(),
            patch=data.get("patch"),
            base_sha=data.get("base_sha"),
            candidate_sha=data.get("candidate_sha"),
            change_class=data.get("change_class", "BUG_FIX"),
            idempotency_key=data.get("idempotency_key"),
            allow_live=bool(data.get("allow_live", False)),
        )

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


@dataclass(slots=True)
class RunStatusResponse:
    """Status response representing a verification run."""

    run_id: str
    status: str
    exit_code: int
    verdict: str
    causal_transition: str | None
    created_at: str
    error_message: str | None = None

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


@dataclass(frozen=True, slots=True)
class ApiEvent:
    """Individual event emitted during build and verification."""

    event_type: str
    run_id: str
    timestamp_utc: str
    data: dict[str, Any]

    def to_sse(self) -> str:
        """Format as Server-Sent Event (SSE) block."""
        payload = json.dumps(
            {
                "event": self.event_type,
                "run_id": self.run_id,
                "timestamp_utc": self.timestamp_utc,
                "data": self.data,
            },
            sort_keys=True,
        )
        return f"event: {self.event_type}\ndata: {payload}\n\n"

    @classmethod
    def create(cls, event_type: str, run_id: str, data: dict[str, Any] | None = None) -> ApiEvent:
        now_utc = datetime.datetime.now(datetime.timezone.utc).isoformat()
        return cls(
            event_type=event_type,
            run_id=run_id,
            timestamp_utc=now_utc,
            data=data or {},
        )
