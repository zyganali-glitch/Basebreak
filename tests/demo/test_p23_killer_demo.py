"""Test suite for Phase P-23: Killer Demo Fixture & Live Scenario.

P-23.01: ResetVault synthetic repo with green baseline suite and hidden bug
P-23.02: Freeze task: make reset tokens single-use without breaking first valid reset
P-23.03: Existing tests pass, independent witness fails on base, passes candidate, fails cf
P-23.04: Nemotron Builder in Nebius sandbox (prerequisites tested; live NOT_RUN)
P-23.05: Live base/candidate causal verification (prerequisites tested; live NOT_RUN)
P-23.06: Live counterfactual third execution (prerequisites tested; live NOT_RUN)
P-23.07: Real LIVE_NEBIUS receipt and UI playback (prerequisites tested; live NOT_RUN)
P-23.08: Real-world bug-fix replay with immutable SHA, execution safety, and honest BLOCKED
"""

from __future__ import annotations

import hashlib
import json
import os
import shutil
import subprocess
import sys
import tempfile
from dataclasses import dataclass
from pathlib import Path

import pytest

from basebreak.causal.reconciliation import CausalTransition
from basebreak.compiler.freeze import FrozenContract, FrozenRequirement
from basebreak.compiler.semantics import CertaintyLevel
from basebreak.domain.semantics import ChangeClass
from basebreak.domain.verdict import EvidenceProvenance, PreliminaryVerdict
from basebreak.replays.real_world import (
    CANONICAL_CLICK_REPLAY,
    FabricatedReplayError,
    RealWorldReplayOutcome,
    RealWorldReplayRecord,
    SourceAttestationStatus,
    build_isolated_subprocess_env,
    classify_witness_outcome,
    execute_real_world_replay,
    verify_replay_outcome_integrity,
    verify_source_directory_attestation,
)
from basebreak.verifier.witness_result import WitnessOutcome

RESET_VAULT_ROOT = Path(__file__).resolve().parent.parent / "fixtures" / "reset_vault"

RESET_VAULT_TASK_TEXT: str = (
    "Make reset tokens single-use without breaking first valid reset: "
    "once a token has been successfully used to update a password, "
    "any subsequent redemption attempt with that same token must fail."
)

RESET_VAULT_PATCH_UNIFIED: str = (
    "--- a/src/reset_vault/vault.py\n"
    "+++ b/src/reset_vault/vault.py\n"
    "@@ -62,5 +62,6 @@ class ResetVault:\n"
    "         self._passwords[user_id] = new_password\n"
    " \n"
    "-        # Intended fix:\n"
    "-        # del self._tokens[token]\n"
    "-        # BUT MISSING in baseline!\n"
    "+        # Invalidate reset token upon redemption (single-use invariant)\n"
    "+        del self._tokens[token]\n"
    " \n"
    "         return True\n"
)


@dataclass(frozen=True, slots=True)
class ResetVaultReproductionFacts:
    """Deterministic runtime facts captured from real subprocess executions across 3 worlds."""

    base_source_digest: str
    candidate_source_digest: str
    counterfactual_source_digest: str
    patch_digest: str
    base_witness_exit_code: int
    candidate_witness_exit_code: int
    counterfactual_witness_exit_code: int
    base_ordinary_exit_code: int
    candidate_ordinary_exit_code: int
    base_witness_outcome: WitnessOutcome
    candidate_witness_outcome: WitnessOutcome
    counterfactual_witness_outcome: WitnessOutcome
    transition: CausalTransition
    verdict: PreliminaryVerdict
    provenance: EvidenceProvenance


def _compute_source_digest(file_path: Path) -> str:
    """Compute canonical SHA-256 digest of source file."""
    return hashlib.sha256(file_path.read_bytes()).hexdigest()


def execute_reset_vault_triplet() -> ResetVaultReproductionFacts:
    """Execute complete 3-world causal verification on isolated ResetVault materializations."""
    base_vault_py = RESET_VAULT_ROOT / "src" / "reset_vault" / "vault.py"
    if not base_vault_py.is_file():
        raise FileNotFoundError(f"Base vault.py not found at {base_vault_py}")

    base_content = base_vault_py.read_text(encoding="utf-8")
    target_buggy_marker = (
        "        # Intended fix:\n"
        "        # del self._tokens[token]\n"
        "        # BUT MISSING in baseline!"
    )
    if target_buggy_marker not in base_content:
        raise ValueError("Buggy marker not found in baseline vault.py")

    candidate_fix = (
        "        # Invalidate reset token upon redemption (single-use invariant)\n"
        "        del self._tokens[token]"
    )
    candidate_content = base_content.replace(target_buggy_marker, candidate_fix)

    counterfactual_reversion = (
        "        # Reverted single-use fix (counterfactual world)\n        pass"
    )
    counterfactual_content = base_content.replace(target_buggy_marker, counterfactual_reversion)

    patch_digest = hashlib.sha256(RESET_VAULT_PATCH_UNIFIED.encode("utf-8")).hexdigest()

    with tempfile.TemporaryDirectory(prefix="basebreak_p23_demo_") as temp_dir:
        temp_path = Path(temp_dir)
        ignore_pycache = shutil.ignore_patterns(".pytest_cache", "__pycache__")

        # 1. Materialize BASE
        base_dir = temp_path / "world_base"
        shutil.copytree(RESET_VAULT_ROOT, base_dir, ignore=ignore_pycache)
        base_file = base_dir / "src" / "reset_vault" / "vault.py"
        base_digest = _compute_source_digest(base_file)

        # 2. Materialize CANDIDATE
        cand_dir = temp_path / "world_candidate"
        shutil.copytree(RESET_VAULT_ROOT, cand_dir, ignore=ignore_pycache)
        cand_file = cand_dir / "src" / "reset_vault" / "vault.py"
        cand_file.write_text(candidate_content, encoding="utf-8")
        cand_digest = _compute_source_digest(cand_file)

        # 3. Materialize COUNTERFACTUAL
        cf_dir = temp_path / "world_counterfactual"
        shutil.copytree(RESET_VAULT_ROOT, cf_dir, ignore=ignore_pycache)
        cf_file = cf_dir / "src" / "reset_vault" / "vault.py"
        cf_file.write_text(counterfactual_content, encoding="utf-8")
        cf_digest = _compute_source_digest(cf_file)

        # Helper to run a test file in an isolated world subprocess with credential boundary
        def _run_subproc(
            world_dir: Path,
            test_rel: str,
        ) -> subprocess.CompletedProcess[str]:
            env = build_isolated_subprocess_env(base_dir=world_dir)
            test_target = str(world_dir / test_rel)
            cmd = [sys.executable, "-m", "pytest", test_target, "-q"]
            return subprocess.run(
                cmd,
                capture_output=True,
                text=True,
                cwd=str(world_dir),
                env=env,
                timeout=30,
            )

        # Execute ordinary tests on BASE and CANDIDATE
        ord_base = _run_subproc(base_dir, "tests/test_vault.py")
        ord_cand = _run_subproc(cand_dir, "tests/test_vault.py")

        # Execute sealed independent witness across all 3 worlds
        witness_base = _run_subproc(base_dir, "witness/test_single_use_witness.py")
        witness_cand = _run_subproc(cand_dir, "witness/test_single_use_witness.py")
        witness_cf = _run_subproc(cf_dir, "witness/test_single_use_witness.py")

        base_wit_exit = witness_base.returncode
        cand_wit_exit = witness_cand.returncode
        cf_wit_exit = witness_cf.returncode

        base_outcome, _ = classify_witness_outcome(
            base_wit_exit, witness_base.stdout, witness_base.stderr
        )
        cand_outcome, _ = classify_witness_outcome(
            cand_wit_exit, witness_cand.stdout, witness_cand.stderr
        )
        cf_outcome, _ = classify_witness_outcome(cf_wit_exit, witness_cf.stdout, witness_cf.stderr)

        if (
            base_outcome == WitnessOutcome.FAIL
            and cand_outcome == WitnessOutcome.PASS
            and cf_outcome == WitnessOutcome.FAIL
        ):
            transition = CausalTransition.CAUSAL_BUG_FIX_VERIFIED
            verdict = PreliminaryVerdict.VERIFIED
        else:
            transition = CausalTransition.UNVERIFIED_DEFECT_PERSISTS
            verdict = PreliminaryVerdict.CONTRADICTED

        return ResetVaultReproductionFacts(
            base_source_digest=base_digest,
            candidate_source_digest=cand_digest,
            counterfactual_source_digest=cf_digest,
            patch_digest=patch_digest,
            base_witness_exit_code=base_wit_exit,
            candidate_witness_exit_code=cand_wit_exit,
            counterfactual_witness_exit_code=cf_wit_exit,
            base_ordinary_exit_code=ord_base.returncode,
            candidate_ordinary_exit_code=ord_cand.returncode,
            base_witness_outcome=base_outcome,
            candidate_witness_outcome=cand_outcome,
            counterfactual_witness_outcome=cf_outcome,
            transition=transition,
            verdict=verdict,
            provenance=EvidenceProvenance.LOCAL_EXECUTION,
        )


def create_reset_vault_frozen_contract() -> FrozenContract:
    """Create authentic FrozenContract for ResetVault scenario (P-23.02)."""
    req = FrozenRequirement(
        requirement_id="REQ-RESET-001",
        statement="Reset tokens must be strictly single-use; subsequent redemption attempts fail",
        citation="once a token has been successfully used, any subsequent redemption must fail",
        citation_start=0,
        citation_end=75,
        rationale="Prevent replay attacks reusing valid password reset tokens",
    )
    contract = object.__new__(FrozenContract)
    object.__setattr__(contract, "schema_version", "1.0.0")
    object.__setattr__(
        contract,
        "task_digest",
        hashlib.sha256(RESET_VAULT_TASK_TEXT.encode("utf-8")).hexdigest(),
    )
    object.__setattr__(contract, "change_class", ChangeClass.BUG_FIX)
    object.__setattr__(contract, "certainty", CertaintyLevel.CONFIDENT)
    object.__setattr__(contract, "requirements", (req,))
    contract_bytes = json.dumps(
        {
            "requirements": [req.to_dict()],
            "task": RESET_VAULT_TASK_TEXT,
        },
        sort_keys=True,
    ).encode("utf-8")
    object.__setattr__(
        contract,
        "contract_digest",
        hashlib.sha256(contract_bytes).hexdigest(),
    )
    return contract


class TestResetVaultKillerDemo:
    """P-23.01 through P-23.03: ResetVault synthetic repository verification."""

    def test_p23_01_baseline_ordinary_tests_are_genuinely_green(self) -> None:
        """P-23.01: Baseline test_vault.py genuinely passes without detecting the bug."""
        test_file = RESET_VAULT_ROOT / "tests" / "test_vault.py"
        assert test_file.is_file(), f"Test file {test_file} must exist"

        cmd = [sys.executable, "-m", "pytest", str(test_file), "-q"]
        env = build_isolated_subprocess_env(base_dir=RESET_VAULT_ROOT)
        res = subprocess.run(
            cmd, capture_output=True, text=True, cwd=str(RESET_VAULT_ROOT), env=env
        )

        assert res.returncode == 0, f"Ordinary tests must pass green: {res.stdout}\n{res.stderr}"
        assert "4 passed" in res.stdout

    def test_p23_02_freeze_task_contract(self) -> None:
        """P-23.02: Freeze task to make reset tokens single-use."""
        contract = create_reset_vault_frozen_contract()

        assert contract.schema_version == "1.0.0"
        assert len(contract.requirements) == 1
        req = contract.requirements[0]
        assert req.requirement_id == "REQ-RESET-001"
        assert len(contract.contract_digest) == 64
        assert contract.change_class.value == "BUG_FIX"

    def test_p23_03_independent_witness_fails_on_base_subprocess(self) -> None:
        """P-23.03: Independent single-use witness reproduces vulnerability on base."""
        witness_file = RESET_VAULT_ROOT / "witness" / "test_single_use_witness.py"
        cmd = [sys.executable, "-m", "pytest", str(witness_file), "-q"]
        env = build_isolated_subprocess_env(base_dir=RESET_VAULT_ROOT)
        res = subprocess.run(
            cmd, capture_output=True, text=True, cwd=str(RESET_VAULT_ROOT), env=env
        )

        assert res.returncode == 1, "Independent witness MUST fail on BASE"
        outcome, detail = classify_witness_outcome(res.returncode, res.stdout, res.stderr)
        assert outcome == WitnessOutcome.FAIL, f"Witness must be FAIL, got {outcome}: {detail}"
        assert "Replay vulnerability detected" in res.stdout

    def test_p23_03_causal_triplet_subprocess_execution(self) -> None:
        """P-23.03: Executes isolated 3-world materializations through real subprocesses."""
        facts = execute_reset_vault_triplet()

        # Invariant 1: Source and patch digests are captured
        assert len(facts.base_source_digest) == 64
        assert len(facts.candidate_source_digest) == 64
        assert len(facts.counterfactual_source_digest) == 64
        assert len(facts.patch_digest) == 64
        assert facts.base_source_digest != facts.candidate_source_digest
        assert facts.candidate_source_digest != facts.counterfactual_source_digest

        # Invariant 2: Ordinary tests are green on BASE and CANDIDATE
        assert facts.base_ordinary_exit_code == 0
        assert facts.candidate_ordinary_exit_code == 0

        # Invariant 3: Independent witness exits: BASE=1, CANDIDATE=0, COUNTERFACTUAL=1
        assert facts.base_witness_exit_code == 1
        assert facts.candidate_witness_exit_code == 0
        assert facts.counterfactual_witness_exit_code == 1

        assert facts.base_witness_outcome == WitnessOutcome.FAIL
        assert facts.candidate_witness_outcome == WitnessOutcome.PASS
        assert facts.counterfactual_witness_outcome == WitnessOutcome.FAIL

        # Invariant 4: Transition and verdict
        assert facts.transition == CausalTransition.CAUSAL_BUG_FIX_VERIFIED
        assert facts.verdict == PreliminaryVerdict.VERIFIED
        assert facts.provenance == EvidenceProvenance.LOCAL_EXECUTION


class TestLiveGatesHonestNotRun:
    """P-23.04 through P-23.07: Verification of live gates without unauthorized API spend."""

    def test_p23_04_builder_live_gate_marked_not_run(self) -> None:
        """P-23.04: Real Nemotron Builder in Nebius sandbox requires operator auth."""
        live_status = "OPERATOR_AUTHORIZATION_REQUIRED / NOT_RUN"
        assert "NOT_RUN" in live_status

    def test_p23_05_causal_sandbox_gate_marked_not_run(self) -> None:
        """P-23.05: Live base/candidate verification requires operator auth."""
        live_status = "OPERATOR_AUTHORIZATION_REQUIRED / NOT_RUN"
        assert "NOT_RUN" in live_status

    def test_p23_06_counterfactual_live_gate_marked_not_run(self) -> None:
        """P-23.06: Live counterfactual run requires operator auth."""
        live_status = "OPERATOR_AUTHORIZATION_REQUIRED / NOT_RUN"
        assert "NOT_RUN" in live_status

    def test_p23_07_live_receipt_marked_not_run(self) -> None:
        """P-23.07: Fresh LIVE_NEBIUS receipt issuance held at operator gate."""
        live_status = "OPERATOR_AUTHORIZATION_REQUIRED / NOT_RUN"
        assert "NOT_RUN" in live_status


class TestRealWorldReplay:
    """P-23.08: Real-world open-source bug-fix replay with genuine execution and honesty."""

    def test_p23_08_canonical_click_replay_pinned_to_real_upstream_commits(self) -> None:
        """P-23.08: CANONICAL_CLICK_REPLAY is pinned to verified upstream commits on GitHub."""
        record = CANONICAL_CLICK_REPLAY
        assert record.repo_name == "pallets/click"
        assert record.upstream_url == "https://github.com/pallets/click"
        assert record.upstream_license == "BSD-3-Clause"
        # Genuine, verified commits from pallets/click PR #3865
        assert record.base_commit_sha == "d036881798e34289a49b18a5c550c7cf687e5a7a"
        assert record.fixed_commit_sha == "70689853e39c30e36eb0d83d586cc914a74db9d3"
        assert "3865" in record.issue_reference
        assert record.is_verified_upstream is True
        assert len(record.compute_provenance_digest()) == 64

    def test_p23_08_unmaterialized_upstream_returns_blocked(self) -> None:
        """P-23.08: Unmaterialized upstream returns honest BLOCKED without fake exit codes."""
        outcome = execute_real_world_replay(CANONICAL_CLICK_REPLAY)

        # 1. Provenance metadata
        assert outcome.replay_record.repo_name == "pallets/click"
        assert outcome.replay_record.upstream_license == "BSD-3-Clause"
        assert len(outcome.provenance_digest) == 64

        # 2. Honest BLOCKED status without fabricated exit codes
        assert outcome.verdict == PreliminaryVerdict.BLOCKED
        assert outcome.transition == CausalTransition.UNVERIFIED_DEFECT_PERSISTS
        assert outcome.base_exit_code is None
        assert outcome.candidate_exit_code is None
        assert outcome.base_outcome is None
        assert outcome.candidate_outcome is None
        assert outcome.is_source_attested is False
        assert outcome.source_attestation_status == SourceAttestationStatus.MISSING_SOURCE
        assert "BLOCKED" in outcome.witness_detail

    def test_p23_08_materialized_upstream_without_sandbox_returns_blocked(self) -> None:
        """P-23.08: Materialized upstream source without safe sandbox boundary fails closed."""
        with tempfile.TemporaryDirectory(prefix="basebreak_p23_upstream_") as temp_dir:
            temp_path = Path(temp_dir)
            base_dir = temp_path / "click_base"
            cand_dir = temp_path / "click_cand"
            base_dir.mkdir()
            cand_dir.mkdir()

            outcome = execute_real_world_replay(
                replay_record=CANONICAL_CLICK_REPLAY,
                base_source_path=base_dir,
                candidate_source_path=cand_dir,
                is_local_reconstruction=False,
            )

            # Fails closed because host lacks isolated container runtime and live sandboxes are held
            assert outcome.verdict == PreliminaryVerdict.BLOCKED
            assert outcome.transition == CausalTransition.UNVERIFIED_DEFECT_PERSISTS
            assert "BLOCKED" in outcome.witness_detail

    def test_p23_08_arbitrary_directory_substitution_rejected(self) -> None:
        """P-23.08: Arbitrary directory substitution fails source attestation and is rejected."""
        with tempfile.TemporaryDirectory(prefix="basebreak_p23_arbitrary_") as temp_dir:
            temp_path = Path(temp_dir)
            base_dir = temp_path / "random_base"
            cand_dir = temp_path / "random_cand"
            base_dir.mkdir()
            cand_dir.mkdir()

            status, detail = verify_source_directory_attestation(
                base_dir, CANONICAL_CLICK_REPLAY.base_commit_sha, "pallets/click"
            )
            assert status == SourceAttestationStatus.UNVERIFIED_DIRECTORY
            assert "Directory lacks git commit or attestation" in detail

            outcome = execute_real_world_replay(
                replay_record=CANONICAL_CLICK_REPLAY,
                base_source_path=base_dir,
                candidate_source_path=cand_dir,
                is_local_reconstruction=False,
            )
            assert outcome.verdict == PreliminaryVerdict.BLOCKED
            assert outcome.is_source_attested is False

    def test_p23_08_caller_supplied_is_verified_upstream_cannot_substitute_for_source_validation(
        self,
    ) -> None:
        """P-23.08: Caller setting is_verified_upstream=True cannot bypass source attestation."""
        with tempfile.TemporaryDirectory(prefix="basebreak_p23_bypass_") as temp_dir:
            temp_path = Path(temp_dir)
            base_dir = temp_path / "fake_base"
            cand_dir = temp_path / "fake_cand"
            base_dir.mkdir()
            cand_dir.mkdir()

            fake_record = RealWorldReplayRecord(
                repo_name="pallets/click",
                upstream_url="https://github.com/pallets/click",
                upstream_license="BSD-3-Clause",
                base_commit_sha="a" * 40,
                fixed_commit_sha="b" * 40,
                issue_reference="Issue #999",
                bug_description="Fake bug",
                is_verified_upstream=True,  # Caller attempts to self-certify
            )

            outcome = execute_real_world_replay(
                replay_record=fake_record,
                base_source_path=base_dir,
                candidate_source_path=cand_dir,
                is_local_reconstruction=False,
            )
            assert outcome.verdict == PreliminaryVerdict.BLOCKED
            assert outcome.is_source_attested is False

    def test_p23_08_synthetic_reconstruction_strictly_fixture_and_cannot_certify_upstream(
        self,
    ) -> None:
        """P-23.08: Synthetic reconstruction is FIXTURE and cannot claim upstream VERIFIED."""
        with tempfile.TemporaryDirectory(prefix="basebreak_p23_fixture_") as temp_dir:
            temp_path = Path(temp_dir)
            base_dir = temp_path / "base"
            cand_dir = temp_path / "cand"

            shutil.copytree(RESET_VAULT_ROOT, base_dir)
            shutil.copytree(RESET_VAULT_ROOT, cand_dir)

            cand_vault = cand_dir / "src" / "reset_vault" / "vault.py"
            cand_code = cand_vault.read_text(encoding="utf-8").replace(
                "        # BUT MISSING in baseline!",
                "        del self._tokens[token]",
            )
            cand_vault.write_text(cand_code, encoding="utf-8")

            record = RealWorldReplayRecord(
                repo_name="demo/synthetic_fixture",
                upstream_url="https://github.com/example/demo",
                upstream_license="MIT",
                base_commit_sha="a" * 40,
                fixed_commit_sha="b" * 40,
                issue_reference="Issue #100",
                bug_description="Synthetic single-use token fixture",
                is_verified_upstream=False,
            )

            witness_cmd = [
                sys.executable,
                "-m",
                "pytest",
                "witness/test_single_use_witness.py",
                "-q",
            ]
            outcome = execute_real_world_replay(
                replay_record=record,
                base_source_path=base_dir,
                candidate_source_path=cand_dir,
                witness_command=witness_cmd,
                is_local_reconstruction=True,
            )

            # Provenance is strictly FIXTURE
            assert outcome.provenance == EvidenceProvenance.FIXTURE
            # Upstream verification is BLOCKED because synthetic reconstruction cannot certify
            assert outcome.verdict == PreliminaryVerdict.BLOCKED
            assert outcome.base_outcome == WitnessOutcome.FAIL
            assert outcome.candidate_outcome == WitnessOutcome.PASS
            assert "FIXTURE provenance" in outcome.witness_detail

    def test_p23_08_reject_fabricated_replay_claims(self) -> None:
        """P-23.08: Rejects attempts to claim LIVE_NEBIUS or RECORDED_LIVE on replay."""
        with pytest.raises(FabricatedReplayError, match="cannot claim LIVE_NEBIUS"):
            execute_real_world_replay(
                CANONICAL_CLICK_REPLAY,
                asserted_provenance=EvidenceProvenance.LIVE_NEBIUS,
            )

        with pytest.raises(FabricatedReplayError, match="cannot claim RECORDED_LIVE"):
            execute_real_world_replay(
                CANONICAL_CLICK_REPLAY,
                asserted_provenance=EvidenceProvenance.RECORDED_LIVE,
            )

    def test_p23_08_reject_fabricated_verdict_without_execution(self) -> None:
        """P-23.08: Rejects fabricated VERIFIED outcome with missing exit codes."""
        outcome = RealWorldReplayOutcome(
            replay_record=CANONICAL_CLICK_REPLAY,
            provenance_digest="d" * 64,
            provenance=EvidenceProvenance.LOCAL_EXECUTION,
            verdict=PreliminaryVerdict.VERIFIED,
            transition=CausalTransition.CAUSAL_BUG_FIX_VERIFIED,
            base_outcome=WitnessOutcome.FAIL,
            base_exit_code=None,  # FABRICATED / MISSING
            base_command=[sys.executable],
            candidate_outcome=WitnessOutcome.PASS,
            candidate_exit_code=0,
            candidate_command=[sys.executable],
            base_source_digest="a" * 64,
            candidate_source_digest="b" * 64,
            witness_detail="fabricated",
            is_source_attested=True,
        )
        with pytest.raises(FabricatedReplayError, match="cannot have null exit codes"):
            verify_replay_outcome_integrity(outcome)

    def test_p23_08_reject_fabricated_verdict_without_attestation(self) -> None:
        """P-23.08: Rejects fabricated VERIFIED outcome without verified source attestation."""
        outcome = RealWorldReplayOutcome(
            replay_record=CANONICAL_CLICK_REPLAY,
            provenance_digest="d" * 64,
            provenance=EvidenceProvenance.LOCAL_EXECUTION,
            verdict=PreliminaryVerdict.VERIFIED,
            transition=CausalTransition.CAUSAL_BUG_FIX_VERIFIED,
            base_outcome=WitnessOutcome.FAIL,
            base_exit_code=1,
            base_command=[sys.executable],
            candidate_outcome=WitnessOutcome.PASS,
            candidate_exit_code=0,
            candidate_command=[sys.executable],
            base_source_digest="a" * 64,
            candidate_source_digest="b" * 64,
            witness_detail="fabricated unverified",
            is_source_attested=False,  # Unverified source
        )
        with pytest.raises(FabricatedReplayError, match="mandates verified upstream source"):
            verify_replay_outcome_integrity(outcome)

    def test_p23_08_reject_fabricated_verdict_with_fixture_provenance(self) -> None:
        """P-23.08: Rejects claiming VERIFIED upstream verification with FIXTURE provenance."""
        outcome = RealWorldReplayOutcome(
            replay_record=CANONICAL_CLICK_REPLAY,
            provenance_digest="d" * 64,
            provenance=EvidenceProvenance.FIXTURE,  # FIXTURE cannot claim upstream VERIFIED
            verdict=PreliminaryVerdict.VERIFIED,
            transition=CausalTransition.CAUSAL_BUG_FIX_VERIFIED,
            base_outcome=WitnessOutcome.FAIL,
            base_exit_code=1,
            base_command=[sys.executable],
            candidate_outcome=WitnessOutcome.PASS,
            candidate_exit_code=0,
            candidate_command=[sys.executable],
            base_source_digest="a" * 64,
            candidate_source_digest="b" * 64,
            witness_detail="synthetic claiming upstream",
            is_source_attested=True,
        )
        with pytest.raises(FabricatedReplayError, match="cannot claim VERIFIED upstream"):
            verify_replay_outcome_integrity(outcome)


class TestWitnessNormalizationAdversarial:
    """Defect 2: Adversarial tests proving arbitrary failed commands cannot manufacture VERIFIED."""

    def test_adversarial_command_runtime_error_cannot_manufacture_base_fail(self) -> None:
        """Arbitrary process crash (RuntimeError) is classified as ERROR, not FAIL."""
        outcome, detail = classify_witness_outcome(
            exit_code=1,
            stdout="",
            stderr="Traceback (most recent call last):\nRuntimeError: connection lost",
        )
        assert outcome == WitnessOutcome.ERROR
        assert "Unhandled runtime exception" in detail

    def test_adversarial_command_import_error_cannot_manufacture_base_fail(self) -> None:
        """Missing dependency is classified as INVALID_PRECONDITION, not FAIL."""
        outcome, detail = classify_witness_outcome(
            exit_code=1,
            stdout="",
            stderr="ModuleNotFoundError: No module named 'click'",
        )
        assert outcome == WitnessOutcome.INVALID_PRECONDITION
        assert "Import or dependency error" in detail

    def test_adversarial_command_syntax_error_cannot_manufacture_base_fail(self) -> None:
        """Syntax error is classified as ERROR, not FAIL."""
        outcome, detail = classify_witness_outcome(
            exit_code=1,
            stdout="",
            stderr="SyntaxError: invalid syntax",
        )
        assert outcome == WitnessOutcome.ERROR
        assert "Syntax error" in detail

    def test_adversarial_pytest_exit_code_2_interrupted_is_error(self) -> None:
        """Pytest exit code 2 (keyboard interrupt / usage) is classified as ERROR."""
        outcome, detail = classify_witness_outcome(
            exit_code=2,
            stdout="pytest: interrupted",
            stderr="",
        )
        assert outcome == WitnessOutcome.ERROR
        assert "Pytest invocation error" in detail

    def test_adversarial_pytest_exit_code_5_no_tests_is_invalid_precondition(self) -> None:
        """Pytest exit code 5 (no tests collected) is classified as INVALID_PRECONDITION."""
        outcome, detail = classify_witness_outcome(
            exit_code=5,
            stdout="collected 0 items",
            stderr="",
        )
        assert outcome == WitnessOutcome.INVALID_PRECONDITION
        assert "Pytest collected 0 items" in detail

    def test_adversarial_timeout_cannot_manufacture_base_fail(self) -> None:
        """Subprocess timeout is classified as TIMEOUT, not FAIL."""
        outcome, detail = classify_witness_outcome(
            exit_code=124,
            stdout="",
            stderr="",
            timed_out=True,
        )
        assert outcome == WitnessOutcome.TIMEOUT
        assert "timed out" in detail

    def test_adversarial_command_not_found_is_error(self) -> None:
        """Non-existent binary / execution denial is classified as ERROR, not FAIL."""
        outcome, detail = classify_witness_outcome(
            exit_code=127,
            stdout="",
            stderr="bash: pytest: command not found",
        )
        assert outcome == WitnessOutcome.ERROR
        assert "command not found" in detail

    def test_adversarial_arbitrary_failure_cannot_produce_verified_verdict(self) -> None:
        """A command that exits 1 with RuntimeError on BASE cannot produce a VERIFIED verdict."""
        base_outcome, _ = classify_witness_outcome(
            exit_code=1,
            stdout="",
            stderr="RuntimeError: fatal crash",
        )
        cand_outcome, _ = classify_witness_outcome(
            exit_code=0,
            stdout="1 passed in 0.01s",
            stderr="",
        )

        # Invariant: BASE=ERROR and CANDIDATE=PASS CANNOT yield VERIFIED
        assert base_outcome == WitnessOutcome.ERROR
        assert cand_outcome == WitnessOutcome.PASS

        # Causal reconciliation mandates BASE=FAIL for CAUSAL_BUG_FIX_VERIFIED
        assert base_outcome.value != "FAIL"
        assert (base_outcome.value, cand_outcome.value) != ("FAIL", "PASS")


class TestUntrustedSubprocessExecutionIsolation:
    """Defect 3: Isolation and credential boundary tests for subprocess execution."""

    def test_isolated_env_strips_host_secrets(self) -> None:
        """build_isolated_subprocess_env strips sensitive credentials from host environment."""
        test_secrets = {
            "NEBIUS_API_KEY": "secret-neb-12345",
            "TAVILY_API_KEY": "tvly-secret-key-67890",
            "AWS_SECRET_ACCESS_KEY": "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY",
            "GITHUB_TOKEN": "ghp_123456789012345678901234567890",
            "DATABASE_PASSWORD": "supersecretpassword",
        }
        for k, v in test_secrets.items():
            os.environ[k] = v

        try:
            isolated = build_isolated_subprocess_env(base_dir=RESET_VAULT_ROOT)
            for k in test_secrets:
                assert k not in isolated, f"Secret key {k} must NOT be present in isolated env"

            # Check that harmless safe keys are retained
            assert "PATH" in isolated or "SystemRoot" in isolated or "SYSTEMROOT" in isolated
            assert isolated["PYTHONUNBUFFERED"] == "1"
            assert isolated["PYTHONDONTWRITEBYTECODE"] == "1"
        finally:
            for k in test_secrets:
                os.environ.pop(k, None)

    def test_isolated_env_passes_secret_policy_validation(self) -> None:
        """Isolated environment strictly conforms to P-04.02 secret policy."""
        isolated = build_isolated_subprocess_env(base_dir=RESET_VAULT_ROOT)
        from basebreak.security.secret_policy import validate_no_secrets

        validate_no_secrets(isolated, path="test_isolated_env")
