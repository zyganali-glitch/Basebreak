"""Real-world open-source bug-fix replay package (P-23.08).

Reproduces immutable real-world upstream bug fixes with explicit commit SHAs,
upstream license provenance, and independent behavioral witness verification.
"""

from __future__ import annotations

from basebreak.replays.real_world import (
    CANONICAL_CLICK_REPLAY,
    FabricatedReplayError,
    RealWorldReplayOutcome,
    RealWorldReplayRecord,
    execute_real_world_replay,
    verify_replay_outcome_integrity,
)

__all__ = [
    "CANONICAL_CLICK_REPLAY",
    "FabricatedReplayError",
    "RealWorldReplayOutcome",
    "RealWorldReplayRecord",
    "execute_real_world_replay",
    "verify_replay_outcome_integrity",
]
