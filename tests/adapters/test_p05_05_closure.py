"""Acceptance gate and closure verification suite for P-05.05.

Master Plan Task:
P-05.05 — Implement retry/idempotency policy without duplicating external actions

Acceptance Criteria:
- Gate 1: Non-idempotent mutation failure makes strictly 1 attempt and fails closed.
- Gate 2: Read-only transient 503 succeeds on retry with bounded delay and audit trail.
- Gate 3: Read-only query permanent 403 failure makes exactly 1 attempt without retry.
- Gate 4: Exhausted attempts on persistent 503 raises MaxAttemptsExceededError.
- Gate 5: Idempotent mutations (e.g. cancel_operation) safely retry on transient failure.
- Gate 6: Deterministic bounded backoff progression respecting ceilings.
- Gate 7: Secret safety: credentials and tokens are redacted in all attempt surfaces.
- Gate 8: Operational ceilings enforced (1 <= max_attempts <= 5, bounded backoff).
- Gate 9: Provider purity: domain, evidence, security packages never import adapters.
- Gate 10: Zero-cost / offline invariant: P-05.06 remains NOT_RUN; no live tokens.
"""

from __future__ import annotations

from pathlib import Path

import pytest

from basebreak.adapters.nebius import (
    CEILING_MAX_ATTEMPTS,
    DEFAULT_MAX_ATTEMPTS,
    MIN_MAX_ATTEMPTS,
    MaxAttemptsExceededError,
    ModelProviderError,
    NebiusRetryExecutor,
    NonRetryableOperationError,
    OperationEffect,
    RetryAuditTrail,
    RetryPolicyConfig,
    RetryPolicyError,
    SandboxProviderError,
    compute_backoff_seconds,
)


class TestP0505ClosureGate:
    """Acceptance gate test suite for P-05.05 closure."""

    # Gate 1: Non-idempotent mutation failure makes strictly 1 attempt and fails closed
    def test_gate_1_non_idempotent_mutation_fails_closed(self) -> None:
        call_count = 0

        def mutate_action() -> None:
            nonlocal call_count
            call_count += 1
            raise SandboxProviderError(status_code=500, sanitized_message="Server error")

        executor = NebiusRetryExecutor(RetryPolicyConfig(max_attempts=3))

        with pytest.raises(NonRetryableOperationError) as exc_info:
            executor.execute(
                operation_name="create_instance",
                operation_effect=OperationEffect.NON_IDEMPOTENT_MUTATION,
                action=mutate_action,
            )

        assert call_count == 1
        assert exc_info.value.operation_name == "create_instance"
        assert exc_info.value.operation_effect == OperationEffect.NON_IDEMPOTENT_MUTATION
        assert (
            "retrying is forbidden to prevent duplicate external execution" in exc_info.value.reason
        )

    # Gate 2: Read-only query transient 503 succeeds on retry with bounded delay and audit trail
    def test_gate_2_read_only_transient_recovers_with_audit_trail(self) -> None:
        attempts = 0
        sleep_log: list[float] = []

        def read_action() -> dict[str, str]:
            nonlocal attempts
            attempts += 1
            if attempts == 1:
                raise ModelProviderError(
                    status_code=503, sanitized_message="503 Service Unavailable"
                )
            return {"status": "ACTIVE"}

        cfg = RetryPolicyConfig(
            max_attempts=3,
            initial_backoff_seconds=0.1,
            backoff_multiplier=2.0,
            sleep_callable=sleep_log.append,
        )
        executor = NebiusRetryExecutor(cfg)

        result, trail = executor.execute(
            operation_name="inspect_status",
            operation_effect=OperationEffect.READ_ONLY,
            action=read_action,
        )

        assert result == {"status": "ACTIVE"}
        assert attempts == 2
        assert len(sleep_log) == 1
        assert sleep_log[0] == 0.1
        assert isinstance(trail, RetryAuditTrail)
        assert trail.total_attempts == 2
        assert trail.is_terminal_success is True
        assert trail.attempts[0].status == "TRANSIENT_FAILURE"
        assert trail.attempts[0].status_code == 503
        assert trail.attempts[1].status == "SUCCESS"
        assert trail.attempts[1].status_code == 200

    # Gate 3: Read-only query permanent 403 failure makes exactly 1 attempt without retry
    def test_gate_3_permanent_failure_aborts_immediately(self) -> None:
        attempts = 0

        def forbidden_action() -> None:
            nonlocal attempts
            attempts += 1
            raise ModelProviderError(status_code=403, sanitized_message="Unauthorized")

        executor = NebiusRetryExecutor(RetryPolicyConfig(max_attempts=3))

        with pytest.raises(ModelProviderError) as exc_info:
            executor.execute(
                operation_name="inspect_protected_info",
                operation_effect=OperationEffect.READ_ONLY,
                action=forbidden_action,
            )

        assert exc_info.value.status_code == 403
        assert attempts == 1

    # Gate 4: Exhausted attempts on persistent 503 raises MaxAttemptsExceededError
    def test_gate_4_exhausted_attempts_raises_max_attempts_exceeded(self) -> None:
        attempts = 0
        sleep_log: list[float] = []

        def failing_action() -> None:
            nonlocal attempts
            attempts += 1
            raise SandboxProviderError(status_code=503, sanitized_message="Overloaded")

        cfg = RetryPolicyConfig(
            max_attempts=3,
            initial_backoff_seconds=0.05,
            backoff_multiplier=2.0,
            sleep_callable=sleep_log.append,
        )
        executor = NebiusRetryExecutor(cfg)

        with pytest.raises(MaxAttemptsExceededError) as exc_info:
            executor.execute(
                operation_name="inspect_operation",
                operation_effect=OperationEffect.READ_ONLY,
                action=failing_action,
            )

        err = exc_info.value
        assert err.operation_name == "inspect_operation"
        assert err.total_attempts == 3
        assert attempts == 3
        assert len(sleep_log) == 2
        assert err.audit_trail.total_attempts == 3
        assert err.audit_trail.is_terminal_success is False
        assert len(err.audit_trail.attempts) == 3

    # Gate 5: Idempotent mutations safely retry on transient failure
    def test_gate_5_idempotent_mutation_retries_transient(self) -> None:
        attempts = 0

        def cancel_action() -> str:
            nonlocal attempts
            attempts += 1
            if attempts == 1:
                raise SandboxProviderError(status_code=429, sanitized_message="Rate limit")
            return "CANCELLED"

        cfg = RetryPolicyConfig(
            max_attempts=2,
            initial_backoff_seconds=0.01,
            sleep_callable=lambda _: None,
        )
        executor = NebiusRetryExecutor(cfg)

        result, trail = executor.execute(
            operation_name="cancel_operation",
            operation_effect=OperationEffect.IDEMPOTENT_MUTATION,
            action=cancel_action,
        )

        assert result == "CANCELLED"
        assert attempts == 2
        assert trail.is_terminal_success is True

    # Gate 6: Deterministic bounded backoff progression respecting ceilings
    def test_gate_6_backoff_progression_and_ceilings(self) -> None:
        cfg = RetryPolicyConfig(
            initial_backoff_seconds=0.5,
            max_backoff_seconds=4.0,
            backoff_multiplier=2.0,
        )
        assert compute_backoff_seconds(1, cfg) == 0.5
        assert compute_backoff_seconds(2, cfg) == 1.0
        assert compute_backoff_seconds(3, cfg) == 2.0
        assert compute_backoff_seconds(4, cfg) == 4.0
        assert compute_backoff_seconds(5, cfg) == 4.0  # Capped at max_backoff_seconds

    # Gate 7: Secret safety: credentials/tokens redacted in attempt records, trails, errors
    def test_gate_7_secret_safety_in_all_surfaces(self) -> None:
        secret = "sk-nebius-secret-token-abcdef1234567890"

        def leaking_action() -> None:
            raise ModelProviderError(
                status_code=503, sanitized_message=f"Request failed with key: {secret}"
            )

        cfg = RetryPolicyConfig(
            max_attempts=2,
            initial_backoff_seconds=0.01,
            sleep_callable=lambda _: None,
        )
        executor = NebiusRetryExecutor(cfg)

        with pytest.raises(MaxAttemptsExceededError) as exc_info:
            executor.execute(
                operation_name="query_model",
                operation_effect=OperationEffect.READ_ONLY,
                action=leaking_action,
            )

        err_str = str(exc_info.value)
        assert secret not in err_str
        assert secret not in exc_info.value.last_error_message
        for record in exc_info.value.audit_trail.attempts:
            if record.error_message:
                assert secret not in record.error_message

    # Gate 8: Operational ceilings enforced
    def test_gate_8_operational_ceilings_enforced(self) -> None:
        assert MIN_MAX_ATTEMPTS == 1
        assert CEILING_MAX_ATTEMPTS == 5
        assert DEFAULT_MAX_ATTEMPTS == 3

        with pytest.raises(RetryPolicyError, match="max_attempts must be between"):
            RetryPolicyConfig(max_attempts=0)

        with pytest.raises(RetryPolicyError, match="max_attempts must be between"):
            RetryPolicyConfig(max_attempts=6)

        with pytest.raises(RetryPolicyError, match="initial_backoff_seconds must be positive"):
            RetryPolicyConfig(initial_backoff_seconds=-1.0)

        with pytest.raises(RetryPolicyError, match="max_backoff_seconds must be >= initial"):
            RetryPolicyConfig(initial_backoff_seconds=10.0, max_backoff_seconds=1.0)

        with pytest.raises(RetryPolicyError, match="backoff_multiplier must be >= 1.0"):
            RetryPolicyConfig(backoff_multiplier=0.5)

    # Gate 9: Provider purity
    def test_gate_9_provider_purity(self) -> None:
        src_root = Path(__file__).resolve().parent.parent.parent / "src" / "basebreak"
        for pkg in ("domain", "evidence", "security"):
            for py_file in (src_root / pkg).glob("**/*.py"):
                text = py_file.read_text(encoding="utf-8")
                assert "basebreak.adapters" not in text, f"Leakage found in {py_file}"
                assert "from .adapters" not in text, f"Leakage found in {py_file}"

    # Gate 10: Zero-cost / offline invariant: P-05.06 remains NOT_RUN; no live tokens
    def test_gate_10_zero_cost_offline_invariant(self) -> None:
        # P-05.06 must not be implemented or executed
        adapters_dir = (
            Path(__file__).resolve().parent.parent.parent
            / "src"
            / "basebreak"
            / "adapters"
            / "nebius"
        )
        assert not (adapters_dir / "integration.py").exists()
        assert not (adapters_dir / "live_suite.py").exists()
