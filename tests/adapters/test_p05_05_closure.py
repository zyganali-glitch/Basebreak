"""Acceptance gate and closure verification suite for P-05.05.

Master Plan Task:
P-05.05 — Implement retry/idempotency policy without duplicating external actions

Acceptance Criteria:
- Gate 1: Non-idempotent mutation failure makes strictly 1 attempt and fails closed.
- Gate 2: Read-only transient 503 succeeds on retry with bounded delay and audit trail.
- Gate 3: Read-only query permanent 403 failure makes exactly 1 attempt without retry.
- Gate 4: Exhausted attempts on persistent 503 raises MaxAttemptsExceededError.
- Gate 5: Mutating cancel_operation makes strictly 1 attempt and fails closed on 5xx.
- Gate 5b: Mutating cancel_operation fails closed on timeout after strictly 1 attempt.
- Gate 5c: Attempting unproven mutation as IDEMPOTENT_MUTATION raises RetryPolicyError.
- Gate 5d: Operation effect classification correctly maps mutating and read-only ops.
- Gate 5e: Canonical classification authority enforced (zero caller bypass).
- Gate 5f: Public retry decision helper enforces canonical classification authority.
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
    SandboxTimeoutError,
    classify_operation_effect,
    compute_backoff_seconds,
    is_operation_retryable,
    validate_operation_classification,
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
            operation_name="inspect_operation",
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
                operation_name="inspect_whoami",
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

    # Gate 5: cancel_operation makes strictly 1 attempt and fails closed on error
    def test_gate_5_cancel_operation_fails_closed_on_transient_failure(self) -> None:
        attempts = 0

        def cancel_action() -> str:
            nonlocal attempts
            attempts += 1
            raise SandboxProviderError(status_code=429, sanitized_message="Rate limit")

        cfg = RetryPolicyConfig(
            max_attempts=3,
            initial_backoff_seconds=0.01,
            sleep_callable=lambda _: None,
        )
        executor = NebiusRetryExecutor(cfg)

        with pytest.raises(NonRetryableOperationError) as exc_info:
            executor.execute(
                operation_name="cancel_operation",
                action=cancel_action,
            )

        err = exc_info.value
        assert err.operation_name == "cancel_operation"
        assert err.operation_effect == OperationEffect.NON_IDEMPOTENT_MUTATION
        assert "retrying is forbidden to prevent duplicate external execution" in err.reason
        assert attempts == 1

    # Gate 5b: Unproven mutating cancel_operation fails closed on timeout after strictly 1 attempt
    def test_gate_5b_cancel_operation_fails_closed_on_timeout(self) -> None:
        attempts = 0

        def cancel_action() -> str:
            nonlocal attempts
            attempts += 1
            raise SandboxTimeoutError("Timeout cancelling operation")

        executor = NebiusRetryExecutor(RetryPolicyConfig(max_attempts=3))

        with pytest.raises(NonRetryableOperationError) as exc_info:
            executor.execute(
                operation_name="cancel_operation",
                action=cancel_action,
            )

        err = exc_info.value
        assert err.operation_name == "cancel_operation"
        assert err.operation_effect == OperationEffect.NON_IDEMPOTENT_MUTATION
        assert attempts == 1

    # Gate 5c: Unproven mutation as IDEMPOTENT_MUTATION raises RetryPolicyError
    def test_gate_5c_unproven_mutation_claiming_idempotent_raises_policy_error(self) -> None:
        executor = NebiusRetryExecutor()

        with pytest.raises(RetryPolicyError, match="has no proven provider idempotency guarantee"):
            executor.execute(
                operation_name="cancel_operation",
                operation_effect=OperationEffect.IDEMPOTENT_MUTATION,
                action=lambda: None,
            )

    # Gate 5d: Operation effect classification correctly maps mutating and read-only operations
    def test_gate_5d_operation_effect_classification_contract(self) -> None:
        assert (
            classify_operation_effect("cancel_operation") == OperationEffect.NON_IDEMPOTENT_MUTATION
        )
        assert (
            classify_operation_effect("create_instance") == OperationEffect.NON_IDEMPOTENT_MUTATION
        )
        assert (
            classify_operation_effect("chat_completion") == OperationEffect.NON_IDEMPOTENT_MUTATION
        )
        assert classify_operation_effect("inspect_operation") == OperationEffect.READ_ONLY
        assert classify_operation_effect("whoami") == OperationEffect.READ_ONLY
        assert (
            classify_operation_effect("unknown_operation")
            == OperationEffect.NON_IDEMPOTENT_MUTATION
        )

    # Gate 5e: Canonical classification authority enforced: zero caller bypass
    def test_gate_5e_classification_authority_enforced(self) -> None:
        executor = NebiusRetryExecutor()
        call_count = 0

        def dummy_action() -> str:
            nonlocal call_count
            call_count += 1
            return "ok"

        # 1. Known mutation passed as READ_ONLY raises RetryPolicyError before action call
        with pytest.raises(
            RetryPolicyError, match="Operation classification mismatch for known operation"
        ):
            executor.execute(
                operation_name="create_instance",
                operation_effect=OperationEffect.READ_ONLY,
                action=dummy_action,
            )
        assert call_count == 0

        # 2. Known READ_ONLY passed as NON_IDEMPOTENT_MUTATION raises RetryPolicyError
        with pytest.raises(
            RetryPolicyError, match="Operation classification mismatch for known operation"
        ):
            executor.execute(
                operation_name="whoami",
                operation_effect=OperationEffect.NON_IDEMPOTENT_MUTATION,
                action=dummy_action,
            )
        assert call_count == 0

        # 3. Unknown operation passed as READ_ONLY raises RetryPolicyError before action call
        with pytest.raises(
            RetryPolicyError, match="Cannot assert READ_ONLY for unregistered operation"
        ):
            executor.execute(
                operation_name="unknown_custom_op",
                operation_effect=OperationEffect.READ_ONLY,
                action=dummy_action,
            )
        assert call_count == 0

        # 4. Unknown operation passed as IDEMPOTENT_MUTATION raises RetryPolicyError
        with pytest.raises(
            RetryPolicyError, match="Cannot assert IDEMPOTENT_MUTATION for unregistered operation"
        ):
            executor.execute(
                operation_name="unknown_custom_op",
                operation_effect=OperationEffect.IDEMPOTENT_MUTATION,
                action=dummy_action,
            )
        assert call_count == 0

        # 5. Unknown operation with explicit NON_IDEMPOTENT_MUTATION is accepted and executed once
        result, trail = executor.execute(
            operation_name="unknown_custom_op",
            operation_effect=OperationEffect.NON_IDEMPOTENT_MUTATION,
            action=dummy_action,
        )
        assert result == "ok"
        assert call_count == 1
        assert trail.operation_effect == OperationEffect.NON_IDEMPOTENT_MUTATION

    # Gate 5f: Public retry decision helper enforces canonical classification authority
    def test_gate_5f_public_helper_classification_authority_enforced(self) -> None:
        transient_exc = ModelProviderError(status_code=503, sanitized_message="Temp unavailable")
        perm_exc = ModelProviderError(status_code=403, sanitized_message="Access forbidden")

        # 1. Mandatory operation identity: calling without operation_name raises TypeError
        with pytest.raises(TypeError):
            is_operation_retryable(exc=transient_exc)  # type: ignore[call-arg]

        # 2. Passing OperationEffect enum as operation_name raises RetryPolicyError
        with pytest.raises(
            RetryPolicyError, match="operation_name must be a canonical operation name string"
        ):
            is_operation_retryable(
                OperationEffect.IDEMPOTENT_MUTATION,
                transient_exc,
            )

        # 3. Known READ_ONLY + transient 503 => retryable
        can_retry, rationale = is_operation_retryable("whoami", transient_exc)
        assert can_retry is True
        assert "Safe retryable failure" in rationale

        # 4. Known READ_ONLY + permanent failure => not retryable
        can_retry, rationale = is_operation_retryable("whoami", perm_exc)
        assert can_retry is False
        assert "Permanent failure" in rationale

        # 5. Known mutation + transient => not retryable (fails closed)
        can_retry, rationale = is_operation_retryable("create_instance", transient_exc)
        assert can_retry is False
        assert "no proven provider idempotency guarantee" in rationale

        # 6. Unknown operation + transient => not retryable (fails closed)
        can_retry, rationale = is_operation_retryable("unknown_operation_xyz", transient_exc)
        assert can_retry is False
        assert "no proven provider idempotency guarantee" in rationale

        # 7. Known mutation falsely asserted READ_ONLY raises RetryPolicyError (cannot upgrade)
        with pytest.raises(
            RetryPolicyError, match="Operation classification mismatch for known operation"
        ):
            is_operation_retryable(
                "create_instance", transient_exc, operation_effect=OperationEffect.READ_ONLY
            )

        # 8. Unknown operation falsely asserted READ_ONLY raises RetryPolicyError (cannot upgrade)
        with pytest.raises(
            RetryPolicyError, match="Cannot assert READ_ONLY for unregistered operation"
        ):
            is_operation_retryable(
                "unknown_operation_xyz",
                transient_exc,
                operation_effect=OperationEffect.READ_ONLY,
            )

        # 9. Unknown operation falsely asserted IDEMPOTENT_MUTATION raises RetryPolicyError
        with pytest.raises(
            RetryPolicyError, match="Cannot assert IDEMPOTENT_MUTATION for unregistered operation"
        ):
            is_operation_retryable(
                "unknown_operation_xyz",
                transient_exc,
                operation_effect=OperationEffect.IDEMPOTENT_MUTATION,
            )

        # 10. validate_operation_classification derives canonical effect and rejects mismatch
        assert validate_operation_classification("whoami") == OperationEffect.READ_ONLY
        assert (
            validate_operation_classification("create_instance")
            == OperationEffect.NON_IDEMPOTENT_MUTATION
        )
        with pytest.raises(RetryPolicyError):
            validate_operation_classification("create_instance", OperationEffect.READ_ONLY)

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
                operation_name="inspect_operation",
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
