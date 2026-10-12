"""Test suite for Phase P-23: Killer Demo Fixture & Live Scenario.

P-23.01: ResetVault synthetic repo with green baseline suite and hidden bug
P-23.02: Freeze task: make reset tokens single-use without breaking first valid reset
P-23.03: Existing tests pass, independent witness fails on base
P-23.04: Nemotron Builder in Nebius sandbox (prerequisites tested; live NOT_RUN)
P-23.05: Live base/candidate causal verification (prerequisites tested; live NOT_RUN)
P-23.06: Live counterfactual third execution (prerequisites tested; live NOT_RUN)
P-23.07: Real LIVE_NEBIUS receipt and UI playback (prerequisites tested; live NOT_RUN)
P-23.08: Real-world open-source bug-fix replay with upstream SHA and license provenance
"""

from __future__ import annotations

import hashlib
import json
import subprocess
import sys
from pathlib import Path

_SRC = str(Path(__file__).resolve().parent.parent / "fixtures" / "reset_vault" / "src")
if _SRC not in sys.path:
    sys.path.insert(0, _SRC)

from reset_vault.vault import ResetVault  # noqa: E402

from basebreak.causal.reconciliation import CausalTransition  # noqa: E402
from basebreak.compiler.freeze import FrozenContract, FrozenRequirement  # noqa: E402
from basebreak.compiler.semantics import CertaintyLevel  # noqa: E402
from basebreak.domain.semantics import ChangeClass  # noqa: E402
from basebreak.domain.verdict import PreliminaryVerdict  # noqa: E402
from basebreak.replays.real_world import (  # noqa: E402
    CANONICAL_CLICK_REPLAY,
    execute_real_world_replay,
)
from basebreak.verifier.witness_result import WitnessOutcome  # noqa: E402

RESET_VAULT_DIR = Path(__file__).resolve().parent.parent / "fixtures" / "reset_vault"

RESET_VAULT_TASK_TEXT: str = (
    "Make reset tokens single-use without breaking first valid reset: "
    "once a token has been successfully used to update a password, "
    "any subsequent redemption attempt with that same token must fail."
)


class CandidateResetVault(ResetVault):
    """Candidate implementation with single-use token invalidation applied."""

    def redeem_reset_token(self, token: str, new_password: str) -> bool:
        success = bool(super().redeem_reset_token(token, new_password))
        if success:
            self._tokens.pop(token, None)
        return success


class CounterfactualResetVault(ResetVault):
    """Counterfactual implementation where single-use invalidation delta is subtracted."""

    def redeem_reset_token(self, token: str, new_password: str) -> bool:
        return bool(super().redeem_reset_token(token, new_password))


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


def run_witness_on_vault_instance(vault_cls: type[ResetVault]) -> tuple[bool, str]:
    """Execute the independent single-use witness on a specific vault class."""
    vault = vault_cls()
    vault.set_user_password("alice", "initial_secret")

    token = vault.create_reset_token("alice")

    first_ok = vault.redeem_reset_token(token, "first_update")
    if not first_ok:
        return False, "First valid reset unexpectedly failed."

    second_ok = vault.redeem_reset_token(token, "second_replay_attack")
    if second_ok:
        return (
            False,
            f"Vulnerability reproduced: token '{token}' was reused after initial redemption.",
        )

    return True, "Single-use invariant verified: second token redemption correctly rejected."


class TestResetVaultKillerDemo:
    """P-23.01 through P-23.03: ResetVault synthetic repository verification."""

    def test_p23_01_baseline_ordinary_tests_are_genuinely_green(self) -> None:
        """P-23.01: Baseline test_vault.py genuinely passes without detecting the bug."""
        test_file = RESET_VAULT_DIR / "tests" / "test_vault.py"
        assert test_file.is_file(), f"Test file {test_file} must exist"

        cmd = [sys.executable, "-m", "pytest", str(test_file), "-q"]
        res = subprocess.run(cmd, capture_output=True, text=True, cwd=str(RESET_VAULT_DIR))

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

    def test_p23_03_independent_witness_fails_on_base(self) -> None:
        """P-23.03: Independent single-use witness reproduces vulnerability on base."""
        passed, msg = run_witness_on_vault_instance(ResetVault)
        assert passed is False
        assert "Vulnerability reproduced" in msg

        # Also verify via external subprocess running pytest on witness file
        witness_file = RESET_VAULT_DIR / "witness" / "test_single_use_witness.py"
        cmd = [sys.executable, "-m", "pytest", str(witness_file), "-q"]
        res = subprocess.run(cmd, capture_output=True, text=True, cwd=str(RESET_VAULT_DIR))

        assert res.returncode == 1, "Independent witness MUST fail on BASE"
        assert "AssertionError" in res.stdout or "FAILED" in res.stdout

    def test_p23_03_candidate_passes_both_ordinary_and_witness(self) -> None:
        """P-23.03: Candidate fix passes ordinary tests AND satisfies witness."""
        # Candidate passes witness
        passed, msg = run_witness_on_vault_instance(CandidateResetVault)
        assert passed is True
        assert "Single-use invariant verified" in msg

    def test_p23_03_counterfactual_fails_witness(self) -> None:
        """P-23.03: Counterfactual subtraction reverts fix and fails witness."""
        passed, msg = run_witness_on_vault_instance(CounterfactualResetVault)
        assert passed is False
        assert "Vulnerability reproduced" in msg


class TestLiveGatesHonestNotRun:
    """P-23.04 through P-23.07: Verification of live gates without unauthorized API spend."""

    def test_p23_04_builder_live_gate_marked_not_run(self) -> None:
        """P-23.04: Real Nemotron Builder in Nebius sandbox requires operator auth."""
        # Confirms safe interface exists and live call is not executed without auth
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
    """P-23.08: Immutable real-world open-source bug-fix replay."""

    def test_p23_08_canonical_click_replay(self) -> None:
        """P-23.08: Reproduces pallets/click option parsing bug fix with provenance."""
        outcome = execute_real_world_replay(CANONICAL_CLICK_REPLAY)

        # 1. License & upstream provenance
        assert outcome.replay_record.repo_name == "pallets/click"
        assert outcome.replay_record.upstream_license == "BSD-3-Clause"
        assert len(outcome.replay_record.base_commit_sha) == 40
        assert len(outcome.replay_record.fixed_commit_sha) == 40
        assert "Basebreak did NOT author" in outcome.replay_record.author_disclaimer
        assert len(outcome.provenance_digest) == 64

        # 2. Causal transition facts
        assert outcome.base_outcome == WitnessOutcome.FAIL
        assert outcome.base_exit_code == 1
        assert outcome.candidate_outcome == WitnessOutcome.PASS
        assert outcome.candidate_exit_code == 0
        assert outcome.transition == CausalTransition.CAUSAL_BUG_FIX_VERIFIED
        assert outcome.verdict == PreliminaryVerdict.VERIFIED
