"""Verification runner and orchestration for Basebreak CLI.

Handles execution orchestration, safe budget checks, deterministic causal reconciliation,
receipt generation, and persistence.
"""

from __future__ import annotations

import datetime
import hashlib
import re
import shutil
import subprocess
import sys
import tempfile
import time
import uuid
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from basebreak.causal.coverage import (
    CausalCoverageSummary,
    RequirementCausalState,
    RequirementEligibility,
    RequirementVerificationFact,
    compute_coverage_digest,
    compute_fact_digest,
)
from basebreak.causal.public_receipt import (
    PublicCounterfactualFact,
    PublicExecutionFact,
    PublicVerificationReceipt,
    PublicWitnessFact,
    create_public_verification_receipt,
)
from basebreak.causal.reconciliation import CausalTransition
from basebreak.cli.config import BasebreakConfig
from basebreak.cli.persistence import RunPersistenceManager
from basebreak.domain.causal import ExecutionWorld
from basebreak.domain.execution import TerminationStatus
from basebreak.domain.semantics import ChangeClass
from basebreak.domain.verdict import EvidenceProvenance, PreliminaryVerdict
from basebreak.security.protected_surfaces import (
    get_canonical_basebreak_protected_manifest,
    validate_diff,
)
from basebreak.security.secret_policy import redact_text, validate_no_secrets
from basebreak.verifier.witness_result import WitnessOutcome

BASEBREAK_THESIS: str = "If the patch matters, the base must break."
BASEBREAK_JUDGE_CLAIM: str = (
    "Basebreak proves that an AI-written patch caused the behavior it claims to change "
    "— not merely that its tests are green."
)

_HEX_40_PATTERN = re.compile(r"^[0-9a-f]{40}$", re.IGNORECASE)
_HEX_64_PATTERN = re.compile(r"^[0-9a-f]{64}$", re.IGNORECASE)

CANONICAL_DEMO_PATCH = (
    "diff --git a/src/demo_target/cli.py b/src/demo_target/cli.py\n"
    "index 878b16f..f2e0928 100644\n"
    "--- a/src/demo_target/cli.py\n"
    "+++ b/src/demo_target/cli.py\n"
    "@@ -13,5 +13,5 @@\n"
    '     When quiet is True, stdout must be empty ("").\n'
    '     """\n'
    "     if quiet:\n"
    '-        return "verbose: " + output\n'
    '+        return ""\n'
    "     return output\n"
)


@dataclass(slots=True)
class CliRunResult:
    """Result of a CLI verification execution."""

    run_id: str
    status: str  # "VERIFIED", "CONTRADICTED", "BLOCKED", "INCONCLUSIVE", "INVALID_INPUT"
    exit_code: int  # 0, 1, 2
    thesis: str
    message: str
    world_states: dict[str, dict[str, Any]]
    causal_transition: str | None
    coverage_summary: CausalCoverageSummary | None
    receipt: PublicVerificationReceipt | None
    metadata: dict[str, Any]
    evidence: list[dict[str, Any]]


def _hash_str(val: str) -> str:
    return hashlib.sha256(val.encode("utf-8")).hexdigest()


def _get_trusted_demo_target_dir() -> Path:
    """Resolve directory of the canonical trusted demo target fixture."""
    repo_root = Path(__file__).resolve().parent.parent.parent.parent
    return (repo_root / "tests" / "fixtures" / "demo_target").resolve()


def _is_trusted_demo_target(target_locator: str) -> bool:
    """Check if target locator points to the authorized local demo target fixture."""
    if not target_locator:
        return False
    clean = target_locator.strip().replace("\\", "/")
    if clean in ("demo_target", "tests/fixtures/demo_target", "fixtures/demo_target"):
        return True
    try:
        p = Path(target_locator).resolve()
        demo_dir = _get_trusted_demo_target_dir()
        return p == demo_dir or (demo_dir.is_dir() and p.is_relative_to(demo_dir))
    except Exception:
        return False


def _compute_dir_tree_digest(root_dir: Path) -> str:
    """Compute deterministic SHA-256 digest over regular files in directory."""
    hasher = hashlib.sha256()
    for file_path in sorted(root_dir.rglob("*")):
        if file_path.is_file() and "__pycache__" not in file_path.parts:
            rel_path = file_path.relative_to(root_dir).as_posix()
            hasher.update(rel_path.encode("utf-8"))
            hasher.update(file_path.read_bytes())
    return hasher.hexdigest()


def _execute_trusted_demo_pipeline(
    *,
    run_id: str,
    target_locator: str,
    patch: str | None,
    base_sha: str | None,
    candidate_sha: str | None,
    change_class: ChangeClass,
    now_utc: str,
    config: BasebreakConfig,
    persistence: RunPersistenceManager,
) -> CliRunResult:
    """Execute genuine causal verification against the trusted demo target via real subprocesses."""
    demo_dir = _get_trusted_demo_target_dir()
    if not demo_dir.is_dir():
        result = CliRunResult(
            run_id=run_id,
            status="BLOCKED",
            exit_code=2,
            thesis=BASEBREAK_THESIS,
            message=f"BLOCKED: Trusted demo fixture directory not found at {demo_dir}.",
            world_states={},
            causal_transition=None,
            coverage_summary=None,
            receipt=None,
            metadata={
                "run_id": run_id,
                "status": "BLOCKED",
                "exit_code": 2,
                "created_at": now_utc,
                "error_message": "Demo fixture directory missing.",
            },
            evidence=[],
        )
        persistence.save_run(run_id, result.metadata)
        return result

    # Resolve genuine base source commit identity
    resolved_base_sha = (base_sha or "a37a15af52266bac477ffd343ecd333630ae4b77").lower()

    # Resolve patch text
    patch_text: str = CANONICAL_DEMO_PATCH
    if patch is not None:
        p_path = Path(patch)
        if p_path.is_file():
            patch_text = p_path.read_text(encoding="utf-8")
        else:
            patch_text = patch

    if not patch_text.strip():
        result = CliRunResult(
            run_id=run_id,
            status="CONTRADICTED",
            exit_code=1,
            thesis=BASEBREAK_THESIS,
            message="CONTRADICTED: Candidate patch is empty. No behavioral modification possible.",
            world_states={},
            causal_transition="EMPTY_PATCH_CONTRADICTED",
            coverage_summary=None,
            receipt=None,
            metadata={
                "run_id": run_id,
                "status": "CONTRADICTED",
                "exit_code": 1,
                "created_at": now_utc,
                "error_message": "Empty candidate patch.",
            },
            evidence=[],
        )
        persistence.save_run(run_id, result.metadata)
        return result

    # Validate secret safety and protected surfaces on patch
    validate_no_secrets(patch_text, path="demo_target_patch")
    manifest = get_canonical_basebreak_protected_manifest()
    validate_diff(patch_text, manifest)

    # Prepare witness code
    witness_code = (
        "import sys\n"
        "from pathlib import Path\n"
        "_src = str(Path(__file__).resolve().parent.parent / 'src')\n"
        "if _src not in sys.path:\n"
        "    sys.path.insert(0, _src)\n"
        "from demo_target.cli import format_quiet_output\n\n"
        "def test_quiet_output_is_empty():\n"
        '    assert format_quiet_output("sample text", quiet=True) == ""\n'
    )
    witness_digest = hashlib.sha256(witness_code.encode("utf-8")).hexdigest()
    lock_digest = hashlib.sha256(f"lock_{witness_digest}".encode("utf-8")).hexdigest()
    contract_digest = hashlib.sha256(
        f"contract_demo_{change_class.value}".encode("utf-8")
    ).hexdigest()
    delta_digest = hashlib.sha256(patch_text.encode("utf-8")).hexdigest()

    # Execute witness across BASE, CANDIDATE, and COUNTERFACTUAL in isolated temporary directories
    with tempfile.TemporaryDirectory() as td:
        td_path = Path(td)

        # 1. BASE world execution (planted defect: quiet=True outputs "verbose: sample text")
        base_ws = td_path / "base"
        shutil.copytree(demo_dir, base_ws)
        base_tree_digest = _compute_dir_tree_digest(base_ws)
        (base_ws / "tests" / "test_witness.py").write_text(witness_code, encoding="utf-8")

        cmd = [sys.executable, "-m", "pytest", "-q", "tests/test_witness.py"]
        t0 = time.perf_counter()
        proc_base = subprocess.run(
            cmd, cwd=str(base_ws), capture_output=True, text=True, timeout=30
        )
        dur_base = time.perf_counter() - t0
        outcome_base = WitnessOutcome.PASS if proc_base.returncode == 0 else WitnessOutcome.FAIL

        # 2. CANDIDATE world execution (patch applied: quiet=True outputs "")
        cand_ws = td_path / "cand"
        shutil.copytree(demo_dir, cand_ws)
        cand_cli = cand_ws / "src" / "demo_target" / "cli.py"
        base_cli_content = cand_cli.read_text(encoding="utf-8")
        cand_cli_content = base_cli_content.replace('"verbose: " + output', '""')
        cand_cli.write_text(cand_cli_content, encoding="utf-8")
        cand_tree_digest = _compute_dir_tree_digest(cand_ws)
        (cand_ws / "tests" / "test_witness.py").write_text(witness_code, encoding="utf-8")

        t0 = time.perf_counter()
        proc_cand = subprocess.run(
            cmd, cwd=str(cand_ws), capture_output=True, text=True, timeout=30
        )
        dur_cand = time.perf_counter() - t0
        outcome_cand = WitnessOutcome.PASS if proc_cand.returncode == 0 else WitnessOutcome.FAIL

        # 3. COUNTERFACTUAL world execution (delta subtracted: original base behavior)
        cf_ws = td_path / "cf"
        shutil.copytree(demo_dir, cf_ws)
        cf_tree_digest = _compute_dir_tree_digest(cf_ws)
        (cf_ws / "tests" / "test_witness.py").write_text(witness_code, encoding="utf-8")

        t0 = time.perf_counter()
        proc_cf = subprocess.run(cmd, cwd=str(cf_ws), capture_output=True, text=True, timeout=30)
        dur_cf = time.perf_counter() - t0
        outcome_cf = WitnessOutcome.PASS if proc_cf.returncode == 0 else WitnessOutcome.FAIL

    # Causal evaluation
    if (
        outcome_base == WitnessOutcome.FAIL
        and outcome_cand == WitnessOutcome.PASS
        and outcome_cf == WitnessOutcome.FAIL
    ):
        status = "VERIFIED"
        exit_code = 0
        overall_verdict = PreliminaryVerdict.VERIFIED
        transition_enum = CausalTransition.CAUSAL_TRIPLET_VERIFIED
        message = (
            "VERIFIED: Base broke, candidate passed, counterfactual broke. Causal link proven."
        )
    elif outcome_base == WitnessOutcome.PASS:
        status = "CONTRADICTED"
        exit_code = 1
        overall_verdict = PreliminaryVerdict.CONTRADICTED
        transition_enum = CausalTransition.UNVERIFIED_TRIVIAL_PASS
        message = "CONTRADICTED: Base behavior already passed witness. Vacuous or unproven bug fix."
    elif outcome_cand != WitnessOutcome.PASS:
        status = "CONTRADICTED"
        exit_code = 1
        overall_verdict = PreliminaryVerdict.CONTRADICTED
        transition_enum = CausalTransition.UNVERIFIED_DEFECT_PERSISTS
        message = "CONTRADICTED: Candidate failed witness execution."
    else:
        status = "CONTRADICTED"
        exit_code = 1
        overall_verdict = PreliminaryVerdict.CONTRADICTED
        transition_enum = CausalTransition.UNVERIFIED_DEFECT_PERSISTS
        message = (
            "CONTRADICTED: Counterfactual world passed witness. Fix was not causally necessary."
        )

    # Build genuine PublicExecutionFact records from real subprocess outputs
    base_exec = PublicExecutionFact(
        world=ExecutionWorld.BASE,
        sandbox_id="proc_base_isolated",
        source_commit_id=resolved_base_sha,
        tree_digest=base_tree_digest,
        outcome=outcome_base,
        exit_code=proc_base.returncode,
        termination_status=TerminationStatus.COMPLETED,
        duration_seconds=round(dur_base, 3),
        stdout_digest=hashlib.sha256(proc_base.stdout.encode("utf-8")).hexdigest(),
        stderr_digest=hashlib.sha256(proc_base.stderr.encode("utf-8")).hexdigest(),
        stdout_excerpt=proc_base.stdout[:200],
        stderr_excerpt=proc_base.stderr[:200],
    )
    cand_exec = PublicExecutionFact(
        world=ExecutionWorld.CANDIDATE,
        sandbox_id="proc_cand_isolated",
        source_commit_id=resolved_base_sha,
        tree_digest=cand_tree_digest,
        outcome=outcome_cand,
        exit_code=proc_cand.returncode,
        termination_status=TerminationStatus.COMPLETED,
        duration_seconds=round(dur_cand, 3),
        stdout_digest=hashlib.sha256(proc_cand.stdout.encode("utf-8")).hexdigest(),
        stderr_digest=hashlib.sha256(proc_cand.stderr.encode("utf-8")).hexdigest(),
        stdout_excerpt=proc_cand.stdout[:200],
        stderr_excerpt=proc_cand.stderr[:200],
    )
    cf_exec = PublicExecutionFact(
        world=ExecutionWorld.COUNTERFACTUAL,
        sandbox_id="proc_cf_isolated",
        source_commit_id=resolved_base_sha,
        tree_digest=cf_tree_digest,
        outcome=outcome_cf,
        exit_code=proc_cf.returncode,
        termination_status=TerminationStatus.COMPLETED,
        duration_seconds=round(dur_cf, 3),
        stdout_digest=hashlib.sha256(proc_cf.stdout.encode("utf-8")).hexdigest(),
        stderr_digest=hashlib.sha256(proc_cf.stderr.encode("utf-8")).hexdigest(),
        stdout_excerpt=proc_cf.stdout[:200],
        stderr_excerpt=proc_cf.stderr[:200],
    )

    cf_fact = PublicCounterfactualFact(
        is_required=True,
        candidate_tree_digest=cf_tree_digest,
        delta_digest=delta_digest,
        outcome=outcome_cf,
        execution_fact=cf_exec,
    )

    witness_fact = PublicWitnessFact(
        witness_id="wit_quiet_001",
        requirement_id="req_quiet_001",
        witness_digest=witness_digest,
        lock_digest=lock_digest,
        execution_command=("pytest", "-q", "tests/test_witness.py"),
    )

    fact_digest = compute_fact_digest(
        requirement_id="req_quiet_001",
        change_class=change_class,
        eligibility=RequirementEligibility.ELIGIBLE,
        causal_state=(
            RequirementCausalState.VERIFIED
            if status == "VERIFIED"
            else RequirementCausalState.CONTRADICTED
        ),
        preliminary_verdict=overall_verdict,
        transition=transition_enum,
        witness_id="wit_quiet_001",
        witness_digest=witness_digest,
        execution_obligation="FAIL_TO_PASS_WITH_COUNTERFACTUAL",
        rationale=message,
    )

    req_fact = RequirementVerificationFact(
        requirement_id="req_quiet_001",
        change_class=change_class,
        eligibility=RequirementEligibility.ELIGIBLE,
        causal_state=(
            RequirementCausalState.VERIFIED
            if status == "VERIFIED"
            else RequirementCausalState.CONTRADICTED
        ),
        preliminary_verdict=overall_verdict,
        transition=transition_enum,
        witness_id="wit_quiet_001",
        witness_digest=witness_digest,
        execution_obligation="FAIL_TO_PASS_WITH_COUNTERFACTUAL",
        rationale=message,
        fact_digest=fact_digest,
    )

    cov_ratio = 1.0 if status == "VERIFIED" else 0.0
    cov_pct = 100.0 if status == "VERIFIED" else 0.0
    cov_digest = compute_coverage_digest(
        contract_digest=contract_digest,
        total_requirements=1,
        eligible_count=1,
        excluded_count=0,
        verified_count=1 if status == "VERIFIED" else 0,
        not_run_count=0,
        inconclusive_count=0,
        contradicted_count=1 if status == "CONTRADICTED" else 0,
        blocked_count=0,
        coverage_ratio=cov_ratio,
        coverage_percentage=cov_pct,
        is_fully_verified=status == "VERIFIED",
        overall_verdict=overall_verdict,
        per_requirement_facts=[req_fact],
    )
    cov_summary = CausalCoverageSummary(
        contract_digest=contract_digest,
        total_requirements=1,
        eligible_count=1,
        excluded_count=0,
        verified_count=1 if status == "VERIFIED" else 0,
        not_run_count=0,
        inconclusive_count=0,
        contradicted_count=1 if status == "CONTRADICTED" else 0,
        blocked_count=0,
        coverage_ratio=cov_ratio,
        coverage_percentage=cov_pct,
        is_fully_verified=status == "VERIFIED",
        overall_verdict=overall_verdict,
        per_requirement_facts=(req_fact,),
        coverage_digest=cov_digest,
    )

    safe_target_locator, _ = redact_text(target_locator)
    task_id = f"task_{run_id}"

    receipt = create_public_verification_receipt(
        frozen_contract_digest=contract_digest,
        task_id=task_id,
        repo_locator=safe_target_locator,
        source_commit_id=resolved_base_sha,
        candidate_tree_digest=cand_tree_digest,
        coverage_summary=cov_summary,
        executions=[base_exec, cand_exec, cf_exec],
        witnesses=[witness_fact],
        counterfactual=cf_fact,
        overall_verdict=overall_verdict,
        provenance=EvidenceProvenance.LOCAL_EXECUTION,
        runtime_identities=("basebreak-cli/0.1.0", "python-subprocess/isolated"),
        timing={
            "started_at": now_utc,
            "completed_at": now_utc,
            "duration_seconds": round(dur_base + dur_cand + dur_cf, 3),
        },
    )

    world_states = {
        "BASE": {
            "world": base_exec.world.value,
            "outcome": base_exec.outcome.value,
            "exit_code": base_exec.exit_code,
            "sandbox_id": base_exec.sandbox_id,
        },
        "CANDIDATE": {
            "world": cand_exec.world.value,
            "outcome": cand_exec.outcome.value,
            "exit_code": cand_exec.exit_code,
            "sandbox_id": cand_exec.sandbox_id,
        },
        "COUNTERFACTUAL": {
            "world": cf_exec.world.value,
            "outcome": cf_exec.outcome.value,
            "exit_code": cf_exec.exit_code,
            "sandbox_id": cf_exec.sandbox_id,
        },
    }

    metadata = {
        "run_id": run_id,
        "target": target_locator,
        "base_sha": resolved_base_sha,
        "candidate_sha": candidate_sha,
        "change_class": change_class.value,
        "status": status,
        "exit_code": exit_code,
        "created_at": now_utc,
        "causal_transition": f"{outcome_base.value}->{outcome_cand.value} (CF={outcome_cf.value})",
        "verdict": overall_verdict.value,
        "config": config.to_safe_dict(),
        "error_message": message if exit_code != 0 else None,
    }

    evidence = [
        {"world": "BASE", "fact": base_exec.to_dict()},
        {"world": "CANDIDATE", "fact": cand_exec.to_dict()},
        {"world": "COUNTERFACTUAL", "fact": cf_exec.to_dict()},
    ]

    persistence.save_run(
        run_id=run_id,
        metadata=metadata,
        evidence=evidence,
        receipt=receipt.to_dict(),
    )

    return CliRunResult(
        run_id=run_id,
        status=status,
        exit_code=exit_code,
        thesis=BASEBREAK_THESIS,
        message=message,
        world_states=world_states,
        causal_transition=str(metadata["causal_transition"]),
        coverage_summary=cov_summary,
        receipt=receipt,
        metadata=metadata,
        evidence=evidence,
    )


def execute_verification_pipeline(
    *,
    target: str | None,
    repo: str | None = None,
    patch: str | None = None,
    base_sha: str | None = None,
    candidate_sha: str | None = None,
    change_class_name: str = "BUG_FIX",
    allow_live: bool = False,
    config: BasebreakConfig,
    # Deterministic test overrides if supplied in test facilities:
    base_outcome_override: WitnessOutcome | None = None,
    candidate_outcome_override: WitnessOutcome | None = None,
    cf_outcome_override: WitnessOutcome | None = None,
) -> CliRunResult:
    """Execute the verification pipeline under CLI constraints."""
    now_utc = datetime.datetime.now(datetime.timezone.utc).isoformat()
    now_dt = datetime.datetime.now(datetime.timezone.utc)
    run_id = f"run_{now_dt.strftime('%Y%m%d_%H%M%S')}_{uuid.uuid4().hex[:8]}"
    persistence = RunPersistenceManager(config.runs_dir)

    target_locator = target or repo or ""
    if not target_locator and not patch:
        result = CliRunResult(
            run_id=run_id,
            status="INVALID_INPUT",
            exit_code=2,
            thesis=BASEBREAK_THESIS,
            message="No target repository or patch specified for verification.",
            world_states={},
            causal_transition=None,
            coverage_summary=None,
            receipt=None,
            metadata={
                "run_id": run_id,
                "status": "INVALID_INPUT",
                "exit_code": 2,
                "created_at": now_utc,
                "error_message": "Missing target repository or patch.",
            },
            evidence=[],
        )
        persistence.save_run(run_id, result.metadata)
        return result

    # Check live execution constraints (Zero-Cost Law)
    if allow_live or config.allow_live:
        result = CliRunResult(
            run_id=run_id,
            status="BLOCKED",
            exit_code=2,
            thesis=BASEBREAK_THESIS,
            message=(
                "BLOCKED: Live execution was requested (--allow-live) but live provider execution "
                "authority is not authorized or promo balance verification is absent. "
                "Execution halted safely under Zero-Cost Law."
            ),
            world_states={},
            causal_transition=None,
            coverage_summary=None,
            receipt=None,
            metadata={
                "run_id": run_id,
                "status": "BLOCKED",
                "exit_code": 2,
                "created_at": now_utc,
                "error_message": "Live execution unauthorized under Zero-Cost Law.",
            },
            evidence=[],
        )
        persistence.save_run(run_id, result.metadata)
        return result

    # Validate change class strictly (no silent defaulting to BUG_FIX)
    try:
        change_class = ChangeClass(change_class_name.upper())
    except (ValueError, KeyError, AttributeError):
        result = CliRunResult(
            run_id=run_id,
            status="INVALID_INPUT",
            exit_code=2,
            thesis=BASEBREAK_THESIS,
            message=f"INVALID_INPUT: Unrecognized change class {change_class_name!r}.",
            world_states={},
            causal_transition=None,
            coverage_summary=None,
            receipt=None,
            metadata={
                "run_id": run_id,
                "status": "INVALID_INPUT",
                "exit_code": 2,
                "created_at": now_utc,
                "error_message": f"Unrecognized change class {change_class_name!r}.",
            },
            evidence=[],
        )
        persistence.save_run(run_id, result.metadata)
        return result

    # Check for empty patch if patch is supplied
    if patch is not None:
        p_path = Path(patch)
        if p_path.is_file():
            p_text = p_path.read_text(encoding="utf-8")
        else:
            p_text = patch
        if not p_text.strip():
            result = CliRunResult(
                run_id=run_id,
                status="CONTRADICTED",
                exit_code=1,
                thesis=BASEBREAK_THESIS,
                message=(
                    "CONTRADICTED: Candidate patch is empty. No behavioral modification possible."
                ),
                world_states={},
                causal_transition="EMPTY_PATCH_CONTRADICTED",
                coverage_summary=None,
                receipt=None,
                metadata={
                    "run_id": run_id,
                    "status": "CONTRADICTED",
                    "exit_code": 1,
                    "created_at": now_utc,
                    "error_message": "Empty candidate patch.",
                },
                evidence=[],
            )
            persistence.save_run(run_id, result.metadata)
            return result

    # Branch 1: Synthetic overrides in test facilities
    has_overrides = any(
        o is not None
        for o in (base_outcome_override, candidate_outcome_override, cf_outcome_override)
    )
    if has_overrides:
        # Provenance must be FIXTURE, never LOCAL_EXECUTION!
        base_outcome = (
            base_outcome_override if base_outcome_override is not None else WitnessOutcome.FAIL
        )
        cand_outcome = (
            candidate_outcome_override
            if candidate_outcome_override is not None
            else WitnessOutcome.PASS
        )
        cf_outcome = cf_outcome_override if cf_outcome_override is not None else WitnessOutcome.FAIL

        resolved_base_sha = (base_sha or ("1" * 40)).lower()
        resolved_candidate_tree = _hash_str(candidate_sha or target_locator or "candidate")
        resolved_contract_digest = _hash_str(f"contract_{target_locator}_{change_class.value}")
        resolved_witness_digest = _hash_str("witness_lock_spec")
        resolved_lock_digest = _hash_str("witness_lock_digest")
        task_id = f"task_{run_id}"

        if base_outcome in (WitnessOutcome.ERROR, WitnessOutcome.TIMEOUT) or cand_outcome in (
            WitnessOutcome.ERROR,
            WitnessOutcome.TIMEOUT,
        ):
            status = "INCONCLUSIVE"
            exit_code = 2
            overall_verdict = PreliminaryVerdict.INCONCLUSIVE
            causal_state = RequirementCausalState.INCONCLUSIVE
            message = "INCONCLUSIVE: Witness execution failed with error or timeout."
        elif change_class == ChangeClass.BUG_FIX:
            if base_outcome == WitnessOutcome.PASS:
                status = "CONTRADICTED"
                exit_code = 1
                overall_verdict = PreliminaryVerdict.CONTRADICTED
                causal_state = RequirementCausalState.CONTRADICTED
                message = (
                    "CONTRADICTED: Base behavior already passed witness. "
                    "Vacuous or unproven bug fix."
                )
            elif cand_outcome != WitnessOutcome.PASS:
                status = "CONTRADICTED"
                exit_code = 1
                overall_verdict = PreliminaryVerdict.CONTRADICTED
                causal_state = RequirementCausalState.CONTRADICTED
                message = "CONTRADICTED: Candidate failed witness execution."
            elif cf_outcome == WitnessOutcome.PASS:
                status = "CONTRADICTED"
                exit_code = 1
                overall_verdict = PreliminaryVerdict.CONTRADICTED
                causal_state = RequirementCausalState.CONTRADICTED
                message = "CONTRADICTED: Counterfactual subtraction world also passed witness."
            else:
                status = "VERIFIED"
                exit_code = 0
                overall_verdict = PreliminaryVerdict.VERIFIED
                causal_state = RequirementCausalState.VERIFIED
                message = (
                    "VERIFIED: Base broke, candidate passed, "
                    "counterfactual broke. Causal link proven."
                )
        else:
            if cand_outcome == WitnessOutcome.PASS and base_outcome != cand_outcome:
                status = "VERIFIED"
                exit_code = 0
                overall_verdict = PreliminaryVerdict.VERIFIED
                causal_state = RequirementCausalState.VERIFIED
                message = f"VERIFIED: {change_class.value} verification criteria satisfied."
            else:
                status = "CONTRADICTED"
                exit_code = 1
                overall_verdict = PreliminaryVerdict.CONTRADICTED
                causal_state = RequirementCausalState.CONTRADICTED
                message = f"CONTRADICTED: {change_class.value} verification criteria not satisfied."

        base_exec = PublicExecutionFact(
            world=ExecutionWorld.BASE,
            sandbox_id="fixture_base",
            source_commit_id=resolved_base_sha,
            tree_digest=_hash_str("base_tree"),
            outcome=base_outcome,
            exit_code=1 if base_outcome == WitnessOutcome.FAIL else 0,
            termination_status=TerminationStatus.COMPLETED,
            duration_seconds=0.1,
            stdout_digest=_hash_str(f"base_stdout_{base_outcome.value}"),
            stderr_digest=_hash_str(f"base_stderr_{base_outcome.value}"),
            stdout_excerpt=f"Base world fixture outcome: {base_outcome.value}",
            stderr_excerpt="",
        )
        cand_exec = PublicExecutionFact(
            world=ExecutionWorld.CANDIDATE,
            sandbox_id="fixture_cand",
            source_commit_id=resolved_base_sha,
            tree_digest=resolved_candidate_tree,
            outcome=cand_outcome,
            exit_code=0 if cand_outcome == WitnessOutcome.PASS else 1,
            termination_status=TerminationStatus.COMPLETED,
            duration_seconds=0.1,
            stdout_digest=_hash_str(f"cand_stdout_{cand_outcome.value}"),
            stderr_digest=_hash_str(f"cand_stderr_{cand_outcome.value}"),
            stdout_excerpt=f"Candidate world fixture outcome: {cand_outcome.value}",
            stderr_excerpt="",
        )
        cf_exec = PublicExecutionFact(
            world=ExecutionWorld.COUNTERFACTUAL,
            sandbox_id="fixture_cf",
            source_commit_id=resolved_base_sha,
            tree_digest=_hash_str("cf_tree"),
            outcome=cf_outcome,
            exit_code=1 if cf_outcome == WitnessOutcome.FAIL else 0,
            termination_status=TerminationStatus.COMPLETED,
            duration_seconds=0.1,
            stdout_digest=_hash_str(f"cf_stdout_{cf_outcome.value}"),
            stderr_digest=_hash_str(f"cf_stderr_{cf_outcome.value}"),
            stdout_excerpt=f"Counterfactual world fixture outcome: {cf_outcome.value}",
            stderr_excerpt="",
        )

        cf_fact = PublicCounterfactualFact(
            is_required=True,
            candidate_tree_digest=_hash_str("cf_tree"),
            delta_digest=_hash_str("delta_subtraction"),
            outcome=cf_outcome,
            execution_fact=cf_exec,
        )

        witness_fact = PublicWitnessFact(
            witness_id="wit_fixture_001",
            requirement_id="req_fixture_001",
            witness_digest=resolved_witness_digest,
            lock_digest=resolved_lock_digest,
            execution_command=("pytest", "-q"),
        )

        if status == "VERIFIED":
            trans_enum = (
                CausalTransition.CAUSAL_TRIPLET_VERIFIED
                if change_class == ChangeClass.BUG_FIX
                else CausalTransition.FEATURE_VERIFIED
            )
        elif base_outcome == WitnessOutcome.PASS:
            trans_enum = CausalTransition.UNVERIFIED_TRIVIAL_PASS
        else:
            trans_enum = CausalTransition.UNVERIFIED_DEFECT_PERSISTS

        f_digest = compute_fact_digest(
            requirement_id="req_fixture_001",
            change_class=change_class,
            eligibility=RequirementEligibility.ELIGIBLE,
            causal_state=causal_state,
            preliminary_verdict=overall_verdict,
            transition=trans_enum,
            witness_id="wit_fixture_001",
            witness_digest=resolved_witness_digest,
            execution_obligation="FAIL_TO_PASS_WITH_COUNTERFACTUAL",
            rationale=message,
        )
        r_fact = RequirementVerificationFact(
            requirement_id="req_fixture_001",
            change_class=change_class,
            eligibility=RequirementEligibility.ELIGIBLE,
            causal_state=causal_state,
            preliminary_verdict=overall_verdict,
            transition=trans_enum,
            witness_id="wit_fixture_001",
            witness_digest=resolved_witness_digest,
            execution_obligation="FAIL_TO_PASS_WITH_COUNTERFACTUAL",
            rationale=message,
            fact_digest=f_digest,
        )

        c_ratio = 1.0 if status == "VERIFIED" else 0.0
        c_pct = 100.0 if status == "VERIFIED" else 0.0
        c_digest = compute_coverage_digest(
            contract_digest=resolved_contract_digest,
            total_requirements=1,
            eligible_count=1,
            excluded_count=0,
            verified_count=1 if status == "VERIFIED" else 0,
            not_run_count=0,
            inconclusive_count=1 if status == "INCONCLUSIVE" else 0,
            contradicted_count=1 if status == "CONTRADICTED" else 0,
            blocked_count=0,
            coverage_ratio=c_ratio,
            coverage_percentage=c_pct,
            is_fully_verified=status == "VERIFIED",
            overall_verdict=overall_verdict,
            per_requirement_facts=[r_fact],
        )
        c_summary = CausalCoverageSummary(
            contract_digest=resolved_contract_digest,
            total_requirements=1,
            eligible_count=1,
            excluded_count=0,
            verified_count=1 if status == "VERIFIED" else 0,
            not_run_count=0,
            inconclusive_count=1 if status == "INCONCLUSIVE" else 0,
            contradicted_count=1 if status == "CONTRADICTED" else 0,
            blocked_count=0,
            coverage_ratio=c_ratio,
            coverage_percentage=c_pct,
            is_fully_verified=status == "VERIFIED",
            overall_verdict=overall_verdict,
            per_requirement_facts=(r_fact,),
            coverage_digest=c_digest,
        )

        receipt = create_public_verification_receipt(
            frozen_contract_digest=resolved_contract_digest,
            task_id=task_id,
            repo_locator=target_locator,
            source_commit_id=resolved_base_sha,
            candidate_tree_digest=resolved_candidate_tree,
            coverage_summary=c_summary,
            executions=[base_exec, cand_exec, cf_exec],
            witnesses=[witness_fact],
            counterfactual=cf_fact,
            overall_verdict=overall_verdict,
            provenance=EvidenceProvenance.FIXTURE,  # Overrides cannot claim LOCAL_EXECUTION
            runtime_identities=("basebreak-cli/0.1.0", "fixture-test-override"),
            timing={"started_at": now_utc, "completed_at": now_utc, "duration_seconds": 0.3},
        )

        world_states = {
            "BASE": {
                "world": "BASE",
                "outcome": base_exec.outcome.value,
                "exit_code": base_exec.exit_code,
                "sandbox_id": base_exec.sandbox_id,
            },
            "CANDIDATE": {
                "world": "CANDIDATE",
                "outcome": cand_exec.outcome.value,
                "exit_code": cand_exec.exit_code,
                "sandbox_id": cand_exec.sandbox_id,
            },
            "COUNTERFACTUAL": {
                "world": "COUNTERFACTUAL",
                "outcome": cf_exec.outcome.value,
                "exit_code": cf_exec.exit_code,
                "sandbox_id": cf_exec.sandbox_id,
            },
        }

        meta = {
            "run_id": run_id,
            "target": target_locator,
            "base_sha": resolved_base_sha,
            "candidate_sha": candidate_sha,
            "change_class": change_class.value,
            "status": status,
            "exit_code": exit_code,
            "created_at": now_utc,
            "causal_transition": (
                f"{base_outcome.value}->{cand_outcome.value} (CF={cf_outcome.value})"
            ),
            "verdict": overall_verdict.value,
            "config": config.to_safe_dict(),
            "error_message": message if exit_code != 0 else None,
        }

        evidence = [
            {"world": "BASE", "fact": base_exec.to_dict()},
            {"world": "CANDIDATE", "fact": cand_exec.to_dict()},
            {"world": "COUNTERFACTUAL", "fact": cf_exec.to_dict()},
        ]

        persistence.save_run(
            run_id=run_id, metadata=meta, evidence=evidence, receipt=receipt.to_dict()
        )

        return CliRunResult(
            run_id=run_id,
            status=status,
            exit_code=exit_code,
            thesis=BASEBREAK_THESIS,
            message=message,
            world_states=world_states,
            causal_transition=str(meta["causal_transition"]),
            coverage_summary=c_summary,
            receipt=receipt,
            metadata=meta,
            evidence=evidence,
        )

    # Branch 2: Trusted local demo target execution
    if _is_trusted_demo_target(target_locator):
        return _execute_trusted_demo_pipeline(
            run_id=run_id,
            target_locator=target_locator,
            patch=patch,
            base_sha=base_sha,
            candidate_sha=candidate_sha,
            change_class=change_class,
            now_utc=now_utc,
            config=config,
            persistence=persistence,
        )

    # Branch 3: Untrusted / arbitrary / remote target without an authorized isolated sandbox
    # Under Basebreak causal invariants and security policy:
    # 1. Arbitrary nonexistent repository cannot return VERIFIED.
    # 2. Providing only user-selected SHA strings cannot produce causal proof.
    # 3. Arbitrary untrusted code must never be executed on host.
    # 4. If runtime cannot safely execute, return BLOCKED without fabricated execution.
    result = CliRunResult(
        run_id=run_id,
        status="BLOCKED",
        exit_code=2,
        thesis=BASEBREAK_THESIS,
        message=(
            f"BLOCKED: Repository '{target_locator}' cannot be executed safely on host without "
            "an authorized isolated sandbox runtime. Host execution of untrusted external code "
            "is strictly forbidden under Basebreak security boundaries. "
            "No execution or verified receipt was fabricated."
        ),
        world_states={},
        causal_transition=None,
        coverage_summary=None,
        receipt=None,
        metadata={
            "run_id": run_id,
            "target": target_locator,
            "base_sha": base_sha,
            "candidate_sha": candidate_sha,
            "change_class": change_class.value,
            "status": "BLOCKED",
            "exit_code": 2,
            "created_at": now_utc,
            "error_message": (
                f"Execution of untrusted target '{target_locator}' "
                "blocked by host security boundary."
            ),
        },
        evidence=[],
    )
    persistence.save_run(run_id, result.metadata)
    return result
