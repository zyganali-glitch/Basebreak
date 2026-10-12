"""Real-world open-source bug-fix replay with immutable SHA & license provenance (P-23.08).

Demonstrates that Basebreak's causal verification engine can independently verify
historical, real-world open-source changes without claiming authorship.
Enforces deterministic source authority, bounded untrusted execution safety,
credential boundary isolation, and robust witness outcome normalization.
"""

from __future__ import annotations

import hashlib
import json
import os
import shutil
import subprocess
import sys
from dataclasses import dataclass
from enum import Enum
from pathlib import Path

from basebreak.causal.reconciliation import CausalTransition
from basebreak.domain.verdict import EvidenceProvenance, PreliminaryVerdict
from basebreak.evidence.capture import DEFAULT_MAX_CAPTURE_BYTES, StreamType, capture_stream
from basebreak.security.secret_policy import (
    find_secret_findings,
    is_sensitive_key,
    validate_no_secrets,
)
from basebreak.verifier.witness_result import WitnessOutcome

DEFAULT_REPLAY_TIMEOUT_SECONDS: float = 30.0


class FabricatedReplayError(ValueError):
    """Raised when a historical replay violates evidence integrity or fabricates execution."""


class SourceAttestationError(ValueError):
    """Raised when source material lacks verifiable attestation or commit mismatch occurs."""


class SourceAttestationStatus(str, Enum):
    """Classification of source-tree attestation against declared upstream commit."""

    VERIFIED_GIT_HEAD = "VERIFIED_GIT_HEAD"
    VERIFIED_MANIFEST = "VERIFIED_MANIFEST"
    UNVERIFIED_DIRECTORY = "UNVERIFIED_DIRECTORY"
    COMMIT_MISMATCH = "COMMIT_MISMATCH"
    MISSING_SOURCE = "MISSING_SOURCE"


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
    is_source_attested: bool = False
    source_attestation_status: SourceAttestationStatus = (
        SourceAttestationStatus.UNVERIFIED_DIRECTORY
    )


# Canonical P-23.08 reference pin:
# Upstream repository: pallets/click
# Upstream License: BSD-3-Clause
# Verified against upstream GitHub API:
# Base commit: d036881798e34289a49b18a5c550c7cf687e5a7a
# Fixed commit: 70689853e39c30e36eb0d83d586cc914a74db9d3
# PR #3865: "Fix short help abbreviation"
CANONICAL_CLICK_REPLAY = RealWorldReplayRecord(
    repo_name="pallets/click",
    upstream_url="https://github.com/pallets/click",
    upstream_license="BSD-3-Clause",
    base_commit_sha="d036881798e34289a49b18a5c550c7cf687e5a7a",
    fixed_commit_sha="70689853e39c30e36eb0d83d586cc914a74db9d3",
    issue_reference="PR #3865 (Fix short help abbreviation)",
    bug_description=(
        "A command's short help stopped at an abbreviation such as 'vs.' or 'e.g.' "
        "inside the first sentence. Fix ensures a period ends a sentence only when it "
        "closes the text or the subsequent word does not start in lowercase."
    ),
    is_verified_upstream=True,
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


def verify_source_directory_attestation(
    source_path: Path | None,
    expected_commit_sha: str,
    repo_name: str,
) -> tuple[SourceAttestationStatus, str]:
    """Verify that a source directory corresponds to declared commit."""
    if source_path is None:
        return SourceAttestationStatus.MISSING_SOURCE, "Source path is None"
    path = Path(source_path)
    if not path.exists():
        return SourceAttestationStatus.MISSING_SOURCE, f"Source path does not exist: {path}"

    # 1. Check git repository attestation
    git_dir = path / ".git"
    if git_dir.exists():
        head_file = git_dir / "HEAD"
        actual_sha = None
        if head_file.is_file():
            head_content = head_file.read_text(encoding="utf-8").strip()
            if len(head_content) == 40 and all(c in "0123456789abcdefABCDEF" for c in head_content):
                actual_sha = head_content.lower()
            elif head_content.startswith("ref: "):
                ref_path = git_dir / head_content[5:].strip()
                if ref_path.is_file():
                    actual_sha = ref_path.read_text(encoding="utf-8").strip().lower()

        if actual_sha is None:
            try:
                res = subprocess.run(
                    ["git", "rev-parse", "HEAD"],
                    cwd=str(path),
                    capture_output=True,
                    text=True,
                    timeout=5,
                )
                if res.returncode == 0:
                    actual_sha = res.stdout.strip().lower()
            except Exception:
                actual_sha = None

        if actual_sha:
            if actual_sha == expected_commit_sha.lower():
                return (
                    SourceAttestationStatus.VERIFIED_GIT_HEAD,
                    f"Git commit HEAD matches expected commit {expected_commit_sha}",
                )
            return (
                SourceAttestationStatus.COMMIT_MISMATCH,
                f"Git HEAD {actual_sha} does not match expected {expected_commit_sha}",
            )

    # 2. Check cryptographic manifest attestation
    manifest_path = path / ".basebreak_attestation.json"
    if manifest_path.is_file():
        try:
            data = json.loads(manifest_path.read_text(encoding="utf-8"))
            if (
                data.get("repo_name") == repo_name
                and data.get("commit_sha", "").lower() == expected_commit_sha.lower()
            ):
                return (
                    SourceAttestationStatus.VERIFIED_MANIFEST,
                    f"Attestation manifest verified for {expected_commit_sha}",
                )
            return (
                SourceAttestationStatus.COMMIT_MISMATCH,
                "Attestation manifest does not match declared repository or commit",
            )
        except Exception:
            return SourceAttestationStatus.UNVERIFIED_DIRECTORY, "Corrupted attestation manifest"

    return SourceAttestationStatus.UNVERIFIED_DIRECTORY, (
        f"Directory lacks git commit or attestation matching {repo_name}@{expected_commit_sha}"
    )


def is_safe_execution_boundary_available() -> bool:
    """Determine if a verified isolated sandbox boundary is available for untrusted execution."""
    docker_bin = shutil.which("docker")
    if docker_bin:
        try:
            res = subprocess.run([docker_bin, "info"], capture_output=True, timeout=3)
            if res.returncode == 0:
                return True
        except Exception:
            pass
    # Live Token Factory Sandboxes are held at operator credit gate (NOT_RUN)
    return False


def build_isolated_subprocess_env(
    *,
    base_dir: Path,
    extra_pythonpath: Path | None = None,
) -> dict[str, str]:
    """Construct minimal, secret-free environment for isolated subprocess execution.

    Strips all inherited host credentials, secret tokens, and sensitive keys.
    Enforces secret detection validation before returning.
    """
    safe_keys = {
        "SYSTEMROOT",
        "SYSTEMDRIVE",
        "WINDIR",
        "PATH",
        "PATHEXT",
        "COMSPEC",
        "TEMP",
        "TMP",
        "LANG",
        "LC_ALL",
    }
    isolated_env: dict[str, str] = {}
    for key, val in os.environ.items():
        if key.upper() in safe_keys:
            if not is_sensitive_key(key) and not find_secret_findings(val):
                isolated_env[key] = val

    isolated_env["PYTHONUNBUFFERED"] = "1"
    isolated_env["PYTHONDONTWRITEBYTECODE"] = "1"

    paths: list[str] = []
    if extra_pythonpath:
        paths.append(str(extra_pythonpath.resolve()))
    src_dir = base_dir / "src" if (base_dir / "src").is_dir() else base_dir
    paths.append(str(src_dir.resolve()))
    isolated_env["PYTHONPATH"] = os.pathsep.join(paths)

    validate_no_secrets(isolated_env, path="isolated_subprocess_env")
    return isolated_env


def classify_witness_outcome(
    exit_code: int | None,
    stdout: str,
    stderr: str,
    timed_out: bool = False,
) -> tuple[WitnessOutcome, str]:
    """Deterministically classify subprocess execution outcome for behavioral witness.

    Guarantees:
    - Never collapses timeout, import error, syntax error, crash, or execution denial into FAIL.
    - Requires genuine assertion failure for FAIL.
    - Requires clean test execution with >0 tests for PASS.
    """
    if timed_out:
        return WitnessOutcome.TIMEOUT, "Execution timed out"
    if exit_code is None:
        return WitnessOutcome.ERROR, "Process terminated without exit code"

    combined_output = (stdout + "\n" + stderr).lower()

    if exit_code == 0:
        if (
            "collected 0 items" in combined_output
            or "no tests ran" in combined_output
            or "0 passed" in combined_output
        ):
            return WitnessOutcome.INVALID_PRECONDITION, "Witness collected 0 items or no tests ran"
        return WitnessOutcome.PASS, "Witness executed and passed all assertions"

    # Non-zero exit code analysis
    if exit_code in (124, 137):
        return WitnessOutcome.TIMEOUT, f"Process timed out or killed (exit {exit_code})"
    if (
        exit_code in (126, 127)
        or "not recognized as an internal or external command" in combined_output
        or "command not found" in combined_output
        or "permission denied" in combined_output
    ):
        return WitnessOutcome.ERROR, f"Execution denied or command not found (exit {exit_code})"
    if exit_code < 0 or exit_code > 128:
        return WitnessOutcome.ERROR, f"Process crashed or terminated by signal (exit {exit_code})"
    if exit_code in (2, 3, 4):
        return WitnessOutcome.ERROR, f"Pytest invocation error (exit {exit_code})"
    if exit_code == 5:
        return WitnessOutcome.INVALID_PRECONDITION, "Pytest collected 0 items"

    # Check for collection / import errors
    if (
        "modulenotfounderror" in combined_output
        or "importerror" in combined_output
        or "no module named" in combined_output
        or "error collecting" in combined_output
        or "errors during collection" in combined_output
    ):
        return (
            WitnessOutcome.INVALID_PRECONDITION,
            "Import or dependency error during test collection",
        )

    # Check for syntax errors
    if "syntaxerror" in combined_output:
        return WitnessOutcome.ERROR, "Syntax error during witness execution"

    # Check for unhandled exceptions outside test assertions
    if any(
        err in combined_output
        for err in (
            "runtimeerror:",
            "typeerror:",
            "valueerror:",
            "zerodivisionerror:",
            "nameerror:",
            "attributeerror:",
            "filenotfounderror:",
            "indexerror:",
            "keyerror:",
        )
    ):
        if "assertionerror" not in combined_output and " failed" not in combined_output:
            return WitnessOutcome.ERROR, "Unhandled runtime exception outside test assertion"

    # Genuine behavioral assertion failure
    if (
        "assertionerror" in combined_output
        or "failed" in combined_output
        or "replay vulnerability detected" in combined_output
    ):
        return WitnessOutcome.FAIL, "Behavioral witness assertion failed as expected"

    return WitnessOutcome.ERROR, f"Execution failed with unclassified error (exit {exit_code})"


def _run_bounded_subproc(
    *,
    cmd: list[str],
    cwd: Path,
    env: dict[str, str],
    timeout_seconds: float,
) -> tuple[int | None, str, str, bool]:
    """Execute command in isolated subprocess with timeout and bounded stream capture."""
    try:
        proc = subprocess.run(
            cmd,
            cwd=str(cwd),
            capture_output=True,
            text=True,
            env=env,
            timeout=timeout_seconds,
        )
        c_stdout = capture_stream(
            proc.stdout, StreamType.STDOUT, max_bytes=DEFAULT_MAX_CAPTURE_BYTES
        )
        c_stderr = capture_stream(
            proc.stderr, StreamType.STDERR, max_bytes=DEFAULT_MAX_CAPTURE_BYTES
        )
        return proc.returncode, c_stdout.sanitized_text, c_stderr.sanitized_text, False
    except subprocess.TimeoutExpired as exc:
        raw_stdout = (
            exc.stdout.decode("utf-8", errors="replace")
            if isinstance(exc.stdout, bytes)
            else (exc.stdout or "")
        )
        raw_stderr = (
            exc.stderr.decode("utf-8", errors="replace")
            if isinstance(exc.stderr, bytes)
            else (exc.stderr or "")
        )
        c_stdout = capture_stream(
            raw_stdout, StreamType.STDOUT, max_bytes=DEFAULT_MAX_CAPTURE_BYTES
        )
        c_stderr = capture_stream(
            raw_stderr, StreamType.STDERR, max_bytes=DEFAULT_MAX_CAPTURE_BYTES
        )
        return 124, c_stdout.sanitized_text, c_stderr.sanitized_text, True
    except FileNotFoundError:
        return 127, "", "Executable not found", False
    except PermissionError:
        return 126, "", "Permission denied", False
    except Exception as e:
        return -1, "", f"Execution error: {type(e).__name__}: {e}", False


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
        if not outcome.is_source_attested:
            raise FabricatedReplayError(
                "VERIFIED outcome mandates verified upstream source attestation. "
                "Arbitrary directory substitution or unverified commit cannot produce VERIFIED."
            )
        if outcome.provenance == EvidenceProvenance.FIXTURE:
            raise FabricatedReplayError(
                "Synthetic reconstruction (FIXTURE) cannot claim VERIFIED upstream verification."
            )


def execute_real_world_replay(
    replay_record: RealWorldReplayRecord = CANONICAL_CLICK_REPLAY,
    *,
    base_source_path: Path | str | None = None,
    candidate_source_path: Path | str | None = None,
    witness_command: list[str] | None = None,
    is_local_reconstruction: bool = False,
    asserted_provenance: EvidenceProvenance | None = None,
    timeout_seconds: float = DEFAULT_REPLAY_TIMEOUT_SECONDS,
) -> RealWorldReplayOutcome:
    """Execute independent witness on real base and candidate source material.

    Enforces:
    1. Provenance boundary: only LOCAL_EXECUTION or FIXTURE allowed.
    2. Honest BLOCKED status when unmaterialized or when safe boundary is unavailable.
    3. Deterministic source attestation: arbitrary directories cannot manufacture VERIFIED.
    4. Credential isolation: host secrets are stripped before execution.
    5. Witness outcome normalization: crashes and collection errors cannot fake BASE=FAIL.
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

    # If source paths are not provided: return honest BLOCKED
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
            is_source_attested=False,
            source_attestation_status=SourceAttestationStatus.MISSING_SOURCE,
        )
        verify_replay_outcome_integrity(outcome)
        return outcome

    base_path = Path(base_source_path)
    cand_path = Path(candidate_source_path)

    if not base_path.exists():
        raise FileNotFoundError(f"Base source path does not exist: {base_path}")
    if not cand_path.exists():
        raise FileNotFoundError(f"Candidate source path does not exist: {cand_path}")

    # Check source attestation
    base_att_status, base_att_detail = verify_source_directory_attestation(
        base_path, replay_record.base_commit_sha, replay_record.repo_name
    )
    cand_att_status, cand_att_detail = verify_source_directory_attestation(
        cand_path, replay_record.fixed_commit_sha, replay_record.repo_name
    )

    is_attested = base_att_status in (
        SourceAttestationStatus.VERIFIED_GIT_HEAD,
        SourceAttestationStatus.VERIFIED_MANIFEST,
    ) and cand_att_status in (
        SourceAttestationStatus.VERIFIED_GIT_HEAD,
        SourceAttestationStatus.VERIFIED_MANIFEST,
    )

    # If untrusted upstream execution is attempted without a verified safe sandbox boundary:
    if not is_local_reconstruction:
        if not is_safe_execution_boundary_available():
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
                base_source_digest=_compute_dir_or_file_digest(base_path),
                candidate_source_digest=_compute_dir_or_file_digest(cand_path),
                witness_detail=(
                    f"Untrusted code execution for upstream repo {replay_record.repo_name} "
                    "requires an isolated sandbox boundary. No container runtime on host "
                    "and live sandboxes held at operator authorization gate. "
                    "Failing closed as BLOCKED under Untrusted Subprocess Execution safety."
                ),
                is_source_attested=is_attested,
                source_attestation_status=(
                    base_att_status
                    if not is_attested
                    else SourceAttestationStatus.VERIFIED_GIT_HEAD
                ),
            )
            verify_replay_outcome_integrity(outcome)
            return outcome

    # If source is NOT attested (arbitrary directory substitution or mismatched commits):
    if not is_attested and not is_local_reconstruction:
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
            base_source_digest=_compute_dir_or_file_digest(base_path),
            candidate_source_digest=_compute_dir_or_file_digest(cand_path),
            witness_detail=(
                f"Source attestation failed for {replay_record.repo_name}: "
                f"base={base_att_detail}, candidate={cand_att_detail}. "
                "Arbitrary directory substitution rejected."
            ),
            is_source_attested=False,
            source_attestation_status=base_att_status,
        )
        verify_replay_outcome_integrity(outcome)
        return outcome

    # Execute isolated subprocesses (e.g. for synthetic fixture reconstructions or verified source)
    base_digest = _compute_dir_or_file_digest(base_path)
    cand_digest = _compute_dir_or_file_digest(cand_path)

    cmd = witness_command or [sys.executable, "-m", "pytest", "-q"]

    # 1. BASE execution with credential boundary & timeout
    base_env = build_isolated_subprocess_env(base_dir=base_path)
    base_exit, base_stdout, base_stderr, base_timed_out = _run_bounded_subproc(
        cmd=cmd, cwd=base_path, env=base_env, timeout_seconds=timeout_seconds
    )
    base_outcome, base_detail = classify_witness_outcome(
        exit_code=base_exit, stdout=base_stdout, stderr=base_stderr, timed_out=base_timed_out
    )

    # 2. CANDIDATE execution with credential boundary & timeout
    cand_env = build_isolated_subprocess_env(base_dir=cand_path)
    cand_exit, cand_stdout, cand_stderr, cand_timed_out = _run_bounded_subproc(
        cmd=cmd, cwd=cand_path, env=cand_env, timeout_seconds=timeout_seconds
    )
    cand_outcome, cand_detail = classify_witness_outcome(
        exit_code=cand_exit, stdout=cand_stdout, stderr=cand_stderr, timed_out=cand_timed_out
    )

    # Verdict evaluation: synthetic reconstruction (FIXTURE) cannot claim upstream VERIFIED
    if is_local_reconstruction:
        verdict = PreliminaryVerdict.BLOCKED
        transition = (
            CausalTransition.CAUSAL_BUG_FIX_VERIFIED
            if (base_outcome == WitnessOutcome.FAIL and cand_outcome == WitnessOutcome.PASS)
            else CausalTransition.UNVERIFIED_DEFECT_PERSISTS
        )
        detail = (
            f"Synthetic reconstruction under FIXTURE provenance (base={base_outcome.value}, "
            f"candidate={cand_outcome.value}). Upstream historical verification is BLOCKED "
            "because synthetic reconstruction cannot certify immutable upstream commits."
        )
    elif (
        base_outcome == WitnessOutcome.FAIL and cand_outcome == WitnessOutcome.PASS and is_attested
    ):
        transition = CausalTransition.CAUSAL_BUG_FIX_VERIFIED
        verdict = PreliminaryVerdict.VERIFIED
        detail = (
            f"Witness failed on base revision (exit {base_exit}: {base_detail}) "
            f"and passed on fixed revision (exit {cand_exit}: {cand_detail})."
        )
    else:
        transition = CausalTransition.UNVERIFIED_DEFECT_PERSISTS
        verdict = PreliminaryVerdict.CONTRADICTED
        detail = (
            f"Behavioral transition did not reproduce expected BUG_FIX: "
            f"base={base_outcome.value} (exit {base_exit}: {base_detail}), "
            f"candidate={cand_outcome.value} (exit {cand_exit}: {cand_detail})."
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
        is_source_attested=is_attested,
        source_attestation_status=(
            base_att_status if is_attested else SourceAttestationStatus.UNVERIFIED_DIRECTORY
        ),
    )
    verify_replay_outcome_integrity(outcome)
    return outcome
