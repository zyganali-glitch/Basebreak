"""Real-world open-source bug-fix replay with immutable SHA & license provenance (P-23.08).

Demonstrates that Basebreak's causal verification engine can independently verify
historical, real-world open-source changes without claiming authorship.
"""

from __future__ import annotations

import hashlib
import os
import subprocess
import sys
from dataclasses import dataclass
from pathlib import Path

from basebreak.causal.reconciliation import CausalTransition
from basebreak.domain.verdict import EvidenceProvenance, PreliminaryVerdict
from basebreak.verifier.witness_result import WitnessOutcome


class FabricatedReplayError(ValueError):
    """Raised when a historical replay violates evidence integrity or fabricates execution."""


@dataclass(frozen=True, slots=True)
class RealWorldReplayRecord:
    """Provenance metadata for an immutable upstream open-source bug-fix replay."""

    repo_name: str
    upstream_url: str
    upstream_license: str
    base_commit_sha: str
    fixed_commit_sha: str
    issue_reference: str
    bug_description: str
    is_verified_upstream: bool = False
    author_disclaimer: str = (
        "Basebreak did NOT author this historical upstream fix. "
        "Basebreak independently executes a causal behavioral witness across "
        "the two immutable upstream revisions to verify that the patch caused "
        "the claimed behavioral transition (BASE=FAIL, CANDIDATE=PASS)."
    )

    def compute_provenance_digest(self) -> str:
        """Compute canonical SHA-256 digest of upstream replay facts."""
        payload = (
            f"{self.repo_name}:{self.upstream_url}:{self.upstream_license}:"
            f"{self.base_commit_sha}:{self.fixed_commit_sha}:{self.issue_reference}:"
            f"{self.is_verified_upstream}"
        )
        return hashlib.sha256(payload.encode("utf-8")).hexdigest()


@dataclass(frozen=True, slots=True)
class RealWorldReplayOutcome:
    """Execution outcome of running independent witness on base and candidate revisions."""

    replay_record: RealWorldReplayRecord
    provenance_digest: str
    provenance: EvidenceProvenance
    verdict: PreliminaryVerdict
    transition: CausalTransition
    base_outcome: WitnessOutcome | None
    base_exit_code: int | None
    base_command: list[str] | None
    candidate_outcome: WitnessOutcome | None
    candidate_exit_code: int | None
    candidate_command: list[str] | None
    base_source_digest: str | None
    candidate_source_digest: str | None
    witness_detail: str


# Canonical P-23.08 reference pin:
# Upstream repository: pallets/click
# Upstream License: BSD-3-Clause
# Note: The previously referenced commit SHAs are not verified in upstream pallets/click history.
# is_verified_upstream is explicitly False to indicate unverified upstream commits.
CANONICAL_CLICK_REPLAY = RealWorldReplayRecord(
    repo_name="pallets/click",
    upstream_url="https://github.com/pallets/click",
    upstream_license="BSD-3-Clause",
    base_commit_sha="4e38c4b14d2325c3453b6fa0c42289417042be6a",
    fixed_commit_sha="8a213945de21b476f5f3e911c4709ecdfa693175",
    issue_reference="Issue #2123 / PR #2124 (unverified upstream reference)",
    bug_description=(
        "Historical report regarding option parsing default value vs "
        "environment variable precedence."
    ),
    is_verified_upstream=False,
)


def _compute_dir_or_file_digest(path: Path) -> str:
    """Compute deterministic SHA-256 digest of a file or directory tree."""
    if path.is_file():
        return hashlib.sha256(path.read_bytes()).hexdigest()
    h = hashlib.sha256()
    for p in sorted(path.rglob("*")):
        if p.is_file() and not p.name.endswith(".pyc") and "__pycache__" not in p.parts:
            h.update(p.relative_to(path).as_posix().encode("utf-8"))
            h.update(p.read_bytes())
    return h.hexdigest()


def verify_replay_outcome_integrity(outcome: RealWorldReplayOutcome) -> None:
    """Validate that a replay outcome does not contain fabricated facts or forbidden provenance."""
    if outcome.provenance in (EvidenceProvenance.RECORDED_LIVE, EvidenceProvenance.LIVE_NEBIUS):
        raise FabricatedReplayError(
            f"Historical replay cannot claim {outcome.provenance.value} provenance. "
            "Replays must be LOCAL_EXECUTION or FIXTURE."
        )

    if outcome.verdict == PreliminaryVerdict.VERIFIED:
        if outcome.base_exit_code is None or outcome.candidate_exit_code is None:
            raise FabricatedReplayError(
                "VERIFIED outcome cannot have null exit codes. Real execution is mandatory."
            )
        if outcome.base_command is None or outcome.candidate_command is None:
            raise FabricatedReplayError("VERIFIED outcome cannot lack executed commands.")
        if (
            outcome.base_outcome != WitnessOutcome.FAIL
            or outcome.candidate_outcome != WitnessOutcome.PASS
        ):
            raise FabricatedReplayError("VERIFIED outcome mandates BASE=FAIL and CANDIDATE=PASS.")


def execute_real_world_replay(
    replay_record: RealWorldReplayRecord = CANONICAL_CLICK_REPLAY,
    *,
    base_source_path: Path | str | None = None,
    candidate_source_path: Path | str | None = None,
    witness_command: list[str] | None = None,
    is_local_reconstruction: bool = False,
    asserted_provenance: EvidenceProvenance | None = None,
) -> RealWorldReplayOutcome:
    """Execute independent witness on real base and candidate source material.

    If actual source directories are not materialized locally, or if historical source
    cannot be safely fetched without pulling untrusted code into the host, this function
    fails closed by returning PreliminaryVerdict.BLOCKED rather than fabricating
    stand-in execution or exit codes.
    """
    if asserted_provenance in (EvidenceProvenance.RECORDED_LIVE, EvidenceProvenance.LIVE_NEBIUS):
        raise FabricatedReplayError(
            f"Historical replay cannot claim {asserted_provenance.value} provenance. "
            "A local reconstruction is FIXTURE; actual local execution of upstream source "
            "is LOCAL_EXECUTION."
        )

    provenance = (
        EvidenceProvenance.FIXTURE
        if is_local_reconstruction
        else EvidenceProvenance.LOCAL_EXECUTION
    )

    # If source paths are not provided, return honest BLOCKED status without fabricating exit codes
    if base_source_path is None or candidate_source_path is None:
        outcome = RealWorldReplayOutcome(
            replay_record=replay_record,
            provenance_digest=replay_record.compute_provenance_digest(),
            provenance=provenance,
            verdict=PreliminaryVerdict.BLOCKED,
            transition=CausalTransition.UNVERIFIED_DEFECT_PERSISTS,
            base_outcome=None,
            base_exit_code=None,
            base_command=None,
            candidate_outcome=None,
            candidate_exit_code=None,
            candidate_command=None,
            base_source_digest=None,
            candidate_source_digest=None,
            witness_detail=(
                f"Upstream source material for {replay_record.repo_name} at base "
                f"{replay_record.base_commit_sha} and fixed {replay_record.fixed_commit_sha} "
                "is not materialized locally. Cannot safely execute without verified immutable "
                "source checkouts. Returning BLOCKED under evidence integrity rules."
            ),
        )
        verify_replay_outcome_integrity(outcome)
        return outcome

    base_path = Path(base_source_path)
    cand_path = Path(candidate_source_path)

    if not base_path.exists():
        raise FileNotFoundError(f"Base source path does not exist: {base_path}")
    if not cand_path.exists():
        raise FileNotFoundError(f"Candidate source path does not exist: {cand_path}")

    base_digest = _compute_dir_or_file_digest(base_path)
    cand_digest = _compute_dir_or_file_digest(cand_path)

    cmd = witness_command or [sys.executable, "-m", "pytest", "-q"]

    # Execute BASE world
    base_env = os.environ.copy()
    base_src = base_path / "src" if (base_path / "src").is_dir() else base_path
    base_env["PYTHONPATH"] = str(base_src.resolve())
    proc_base = subprocess.run(
        cmd,
        cwd=str(base_path),
        capture_output=True,
        text=True,
        env=base_env,
    )
    base_exit = proc_base.returncode
    base_outcome = WitnessOutcome.PASS if base_exit == 0 else WitnessOutcome.FAIL

    # Execute CANDIDATE world
    cand_env = os.environ.copy()
    cand_src = cand_path / "src" if (cand_path / "src").is_dir() else cand_path
    cand_env["PYTHONPATH"] = str(cand_src.resolve())
    proc_cand = subprocess.run(
        cmd,
        cwd=str(cand_path),
        capture_output=True,
        text=True,
        env=cand_env,
    )
    cand_exit = proc_cand.returncode
    cand_outcome = WitnessOutcome.PASS if cand_exit == 0 else WitnessOutcome.FAIL

    if base_outcome == WitnessOutcome.FAIL and cand_outcome == WitnessOutcome.PASS:
        transition = CausalTransition.CAUSAL_BUG_FIX_VERIFIED
        verdict = PreliminaryVerdict.VERIFIED
        detail = (
            f"Witness failed on base revision (exit {base_exit}) "
            f"and passed on fixed revision (exit {cand_exit})."
        )
    else:
        transition = CausalTransition.UNVERIFIED_DEFECT_PERSISTS
        verdict = PreliminaryVerdict.CONTRADICTED
        detail = (
            f"Behavioral transition did not reproduce expected BUG_FIX: "
            f"base={base_outcome.value} (exit {base_exit}), "
            f"candidate={cand_outcome.value} (exit {cand_exit})."
        )

    outcome = RealWorldReplayOutcome(
        replay_record=replay_record,
        provenance_digest=replay_record.compute_provenance_digest(),
        provenance=provenance,
        verdict=verdict,
        transition=transition,
        base_outcome=base_outcome,
        base_exit_code=base_exit,
        base_command=cmd,
        candidate_outcome=cand_outcome,
        candidate_exit_code=cand_exit,
        candidate_command=cmd,
        base_source_digest=base_digest,
        candidate_source_digest=cand_digest,
        witness_detail=detail,
    )
    verify_replay_outcome_integrity(outcome)
    return outcome
