"""Comprehensive tests for Phase P-25 Reliability, Recovery & Idempotency.

Exercises all 6 micro-tasks:
- P-25.01: Persist recoverable run state without trusting mutable workspace
- P-25.02: Implement crash/retry semantics for model calls
- P-25.03: Implement sandbox-loss recovery
- P-25.04: Implement duplicate-run/idempotency protection
- P-25.05: Implement evidence write deduplication and replay safety
- P-25.06: Fresh-process recovery E2E
"""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from basebreak.recovery.dedup import (
    ContentAddressedEvidenceStore,
    EvidenceTamperingError,
)
from basebreak.recovery.idempotency import (
    IdempotencyDecision,
    IdempotencyEngine,
    IdempotencyKeyConflictError,
)
from basebreak.recovery.retry import (
    BudgetFloorExceededError,
    NonRetryableModelError,
    RetryableModelError,
    RetryConfig,
    execute_with_retry,
)
from basebreak.recovery.sandbox_recovery import (
    SandboxFailureKind,
    SandboxLossRecoveryManager,
    classify_sandbox_failure,
)
from basebreak.recovery.state import (
    DurableRunState,
    DurableStateManager,
    RunStep,
)


class TestP25ReliabilityAndRecovery:
    """Rigorous tests covering the complete P-25 reliability matrix."""

    # -------------------------------------------------------------------------
    # P-25.01: Persist recoverable run state without trusting mutable workspace
    # -------------------------------------------------------------------------
    def test_p25_01_durable_state_manager_atomic(self, tmp_path: Path) -> None:
        """P-25.01: State is persisted atomically outside workspace with step progression."""
        storage_dir = tmp_path / "durable_states"
        manager = DurableStateManager(storage_dir)

        initial = DurableRunState(
            run_id="run-test-01",
            step=RunStep.INITIALIZED,
            source_repo="zyganali-glitch/Basebreak",
            base_sha="a" * 40,
            metadata={"priority": "high"},
        )

        manager.save_state(initial)

        # Verify state is loadable
        loaded = manager.load_state("run-test-01")
        assert loaded is not None
        assert loaded.run_id == "run-test-01"
        assert loaded.step == RunStep.INITIALIZED
        assert loaded.base_sha == "a" * 40
        assert loaded.metadata["priority"] == "high"

        # Transition to CONTRACT_FROZEN and verify update
        updated = manager.transition(
            loaded,
            RunStep.CONTRACT_FROZEN,
            additional_evidence=("ev-digest-1",),
            extra_metadata={"contract_id": "CNT-001"},
        )
        assert updated.step == RunStep.CONTRACT_FROZEN
        assert updated.evidence_digests == ("ev-digest-1",)
        assert updated.metadata["contract_id"] == "CNT-001"

        # Re-load from disk to verify atomic overwrite
        reloaded = manager.load_state("run-test-01")
        assert reloaded is not None
        assert reloaded.step == RunStep.CONTRACT_FROZEN

    # -------------------------------------------------------------------------
    # P-25.02: Implement crash/retry semantics for model calls
    # -------------------------------------------------------------------------
    def test_p25_02_model_call_retry_transient_and_budget_floor(self) -> None:
        """P-25.02: Model retries transient errors with backoff and stops at budget floor."""
        calls = 0

        def transient_failure() -> str:
            nonlocal calls
            calls += 1
            if calls < 3:
                raise RetryableModelError("HTTP 429 Rate Limit")
            return "SUCCESS"

        sleep_delays: list[float] = []
        cfg = RetryConfig(max_retries=3, initial_backoff_seconds=0.01, jitter=False)

        res = execute_with_retry(
            transient_failure,
            config=cfg,
            sleep_fn=lambda d: sleep_delays.append(d),
        )
        assert res == "SUCCESS"
        assert calls == 3
        assert len(sleep_delays) == 2

        # Invariant: Non-retryable error fails immediately without retry
        def deterministic_failure() -> str:
            raise NonRetryableModelError("HTTP 401 Unauthorized")

        with pytest.raises(NonRetryableModelError):
            execute_with_retry(deterministic_failure, config=cfg)

        # Invariant: Zero-Cost Law / Budget floor stops retries
        def budget_breaker() -> str:
            raise RetryableModelError("HTTP 500")

        with pytest.raises(BudgetFloorExceededError):
            execute_with_retry(
                budget_breaker,
                config=cfg,
                budget_check_fn=lambda: False,  # Floor reached
            )

    # -------------------------------------------------------------------------
    # P-25.03: Implement sandbox-loss recovery
    # -------------------------------------------------------------------------
    def test_p25_03_sandbox_loss_discrimination(self) -> None:
        """P-25.03: Distinguish sandbox crash/disconnect from test assertion failure."""
        # Case 1: Pytest assertion failure (exit code 1) -> TEST_FAILURE, NOT infra failure
        test_fail = classify_sandbox_failure(exit_code=1, stderr="AssertionError: 1 != 2")
        assert test_fail.kind == SandboxFailureKind.TEST_FAILURE
        assert test_fail.is_infra_failure is False
        assert test_fail.can_retry_in_fresh_sandbox is False

        # Case 2: Sandbox agent disconnect -> SANDBOX_DISCONNECT, infra failure, can retry
        disconnect = classify_sandbox_failure(
            exit_code=None,
            stderr="sandbox agent unreachable: Connection reset by peer",
        )
        assert disconnect.kind == SandboxFailureKind.SANDBOX_DISCONNECT
        assert disconnect.is_infra_failure is True
        assert disconnect.can_retry_in_fresh_sandbox is True

        # Case 3: OOM killed (SIGKILL 137) -> OOM_KILLED, infra failure, no fresh retry
        oom = classify_sandbox_failure(
            exit_code=137,
            stderr="Killed process 123 (python) total-vm: 4GB out of memory",
        )
        assert oom.kind == SandboxFailureKind.OOM_KILLED
        assert oom.can_retry_in_fresh_sandbox is False

        # Case 4: Timeout watchdog -> TIMEOUT, not infra
        timeout = classify_sandbox_failure(exit_code=None, is_timeout=True)
        assert timeout.kind == SandboxFailureKind.TIMEOUT
        assert timeout.can_retry_in_fresh_sandbox is False

        # Recovery manager policy
        rec_mgr = SandboxLossRecoveryManager(max_infra_retries=1)
        assert rec_mgr.evaluate_recovery(disconnect, current_infra_retries=0) is True
        assert rec_mgr.evaluate_recovery(disconnect, current_infra_retries=1) is False
        assert rec_mgr.evaluate_recovery(test_fail, current_infra_retries=0) is False

    # -------------------------------------------------------------------------
    # P-25.04: Implement duplicate-run / idempotency protection
    # -------------------------------------------------------------------------
    def test_p25_04_idempotency_engine_and_conflicts(self, tmp_path: Path) -> None:
        """P-25.04: Detects conflicting payload and replays identical requests."""
        journal_file = tmp_path / "idempotency_journal.json"
        engine = IdempotencyEngine(journal_file)

        payload_a = {"repo": "test/repo", "sha": "1" * 40}
        decision, rec = engine.evaluate_request("key-123", payload_a)
        assert decision == IdempotencyDecision.EXECUTE_NEW
        assert rec is None

        # Register completed run
        engine.register_completed_run(
            idempotency_key="key-123",
            payload=payload_a,
            run_id="run-abc",
            created_at="2026-10-12T00:00:00Z",
            result_summary={"verdict": "VERIFIED"},
        )

        # Same key with same payload -> RETURN_EXISTING
        decision_replay, rec_replay = engine.evaluate_request("key-123", payload_a)
        assert decision_replay == IdempotencyDecision.RETURN_EXISTING
        assert rec_replay is not None
        assert rec_replay.run_id == "run-abc"

        # Same key with altered payload -> CONFLICT ERROR
        payload_altered = {"repo": "test/repo", "sha": "2" * 40}
        with pytest.raises(IdempotencyKeyConflictError) as exc_info:
            engine.evaluate_request("key-123", payload_altered)

        assert "Idempotency key 'key-123' was previously registered" in str(exc_info.value)

    # -------------------------------------------------------------------------
    # P-25.05: Implement evidence write deduplication and replay safety
    # -------------------------------------------------------------------------
    def test_p25_05_evidence_write_dedup_and_tamper(self, tmp_path: Path) -> None:
        """P-25.05: Content-addressed evidence deduplication and tamper rejection."""
        store_dir = tmp_path / "cas_evidence"
        store = ContentAddressedEvidenceStore(store_dir)

        fact = {"witness": "w1", "outcome": "PASS", "run_id": "r-1"}

        digest1, written1 = store.store_evidence(fact)
        assert written1 is True
        assert len(digest1) == 64

        # Redundant write -> deduplicated, not written
        digest2, written2 = store.store_evidence(fact)
        assert digest2 == digest1
        assert written2 is False

        # Load and verify
        loaded = store.load_evidence(digest1)
        assert loaded["outcome"] == "PASS"
        assert store.verify_integrity(digest1) is True

        # Tamper attack: modify evidence file content
        ev_file = store_dir / f"{digest1}.json"
        with ev_file.open("w", encoding="utf-8") as f:
            json.dump({"witness": "w1", "outcome": "TAMPERED_PASS"}, f)

        with pytest.raises(EvidenceTamperingError) as exc_info:
            store.load_evidence(digest1)

        assert "Tampered evidence detected" in str(exc_info.value)
        assert store.verify_integrity(digest1) is False

    # -------------------------------------------------------------------------
    # P-25.06: Fresh-process recovery E2E
    # -------------------------------------------------------------------------
    def test_p25_06_fresh_process_recovery_e2e(self, tmp_path: Path) -> None:
        """P-25.06: Simulate process crash mid-pipeline and resume in clean process."""
        durable_dir = tmp_path / "proc_recovery"
        proc1_manager = DurableStateManager(durable_dir)

        # Process 1 starts a verification run
        run_state = DurableRunState(
            run_id="run-crash-test",
            step=RunStep.INITIALIZED,
            source_repo="zyganali-glitch/Basebreak",
            base_sha="0" * 40,
            candidate_sha="1" * 40,
        )
        proc1_manager.save_state(run_state)

        # Process 1 advances to BASE_EXECUTED
        run_state = proc1_manager.transition(
            run_state,
            RunStep.BASE_EXECUTED,
            additional_evidence=("digest-base-evidence",),
        )

        # --- SIMULATE PROCESS 1 CRASH / RESTART ---
        del proc1_manager
        del run_state

        # Process 2 (fresh instance) initializes and recovers run
        proc2_manager = DurableStateManager(durable_dir)
        recovered = proc2_manager.load_state("run-crash-test")

        assert recovered is not None
        assert recovered.run_id == "run-crash-test"
        assert recovered.step == RunStep.BASE_EXECUTED
        assert recovered.base_sha == "0" * 40
        assert recovered.candidate_sha == "1" * 40
        assert recovered.evidence_digests == ("digest-base-evidence",)

        # Process 2 resumes pipeline from BASE_EXECUTED to CANDIDATE_EXECUTED -> COMPLETED
        resumed = proc2_manager.transition(
            recovered,
            RunStep.CANDIDATE_EXECUTED,
            additional_evidence=("digest-candidate-evidence",),
        )
        completed = proc2_manager.transition(
            resumed,
            RunStep.COMPLETED,
            receipt_digest="receipt-sha256",
        )

        assert completed.step == RunStep.COMPLETED
        assert completed.receipt_digest == "receipt-sha256"
        assert len(completed.evidence_digests) == 2
