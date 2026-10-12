"""Real-world open-source bug-fix replay package (P-23.08).

Reproduces immutable real-world upstream bug fixes with explicit commit SHAs,
upstream license provenance, and independent behavioral witness verification.
"""

from __future__ import annotations

from basebreak.replays.real_world import (
    CANONICAL_CLICK_REPLAY,
    DEFAULT_REPLAY_TIMEOUT_SECONDS,
    FabricatedReplayError,
    RealWorldReplayOutcome,
    RealWorldReplayRecord,
    SourceAttestationError,
    SourceAttestationStatus,
    build_isolated_subprocess_env,
    classify_witness_outcome,
    execute_real_world_replay,
    is_safe_execution_boundary_available,
    verify_replay_outcome_integrity,
    verify_source_directory_attestation,
)

__all__ = [
    "CANONICAL_CLICK_REPLAY",
    "DEFAULT_REPLAY_TIMEOUT_SECONDS",
    "FabricatedReplayError",
    "RealWorldReplayOutcome",
    "RealWorldReplayRecord",
    "SourceAttestationError",
    "SourceAttestationStatus",
    "build_isolated_subprocess_env",
    "classify_witness_outcome",
    "execute_real_world_replay",
    "is_safe_execution_boundary_available",
    "verify_replay_outcome_integrity",
    "verify_source_directory_attestation",
]
