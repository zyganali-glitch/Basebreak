"""Unit tests for Nebius retry and idempotency policy (P-05.05).

Authority:
- Section 4 / P-05.05: Owns retry/idempotency policy for Nebius Token Factory adapters.
- Core Invariant: A retry MUST NOT cause an externally visible operation to execute twice
  unless the provider contract supplies a proven idempotency mechanism that makes the repeat safe.
- Non-idempotent mutating actions fail closed immediately on failure to prevent duplicate execution.
- Read-only queries may retry on transient errors with bounded backoff.
- Credentials and bearer tokens are strictly redacted in attempt records and error messages.
"""

from __future__ import annotations

import pytest

from basebreak.adapters.nebius.client import (
    MissingCredentialError,
    ModelConfigError,
    ModelNetworkError,
    ModelProviderError,
)
from basebreak.adapters.nebius.materialization import (
    SourceCommitMismatchError,
)
from basebreak.adapters.nebius.retry import (
    CEILING_MAX_ATTEMPTS,
    DEFAULT_BACKOFF_MULTIPLIER,
    DEFAULT_INITIAL_BACKOFF_SECONDS,
    DEFAULT_MAX_ATTEMPTS,
    DEFAULT_MAX_BACKOFF_SECONDS,
    KNOWN_OPERATION_EFFECTS,
    MaxAttemptsExceededError,
    NebiusRetryExecutor,
    NonRetryableOperationError,
    OperationEffect,
    RetryPolicyConfig,
    RetryPolicyError,
    classify_operation_effect,
    compute_backoff_seconds,
    is_operation_retryable,
    is_permanent_failure,
    is_transient_failure,
)
from basebreak.adapters.nebius.sandbox import (
    MissingSandboxCredentialError,
    SandboxConfigError,
    SandboxProviderError,
    SandboxTimeoutError,
    SandboxTransportError,
)


class TestRetryPolicyConfig:
    """Tests for RetryPolicyConfig validation and boundaries."""

    def test_default_config(self) -> None:
        cfg = RetryPolicyConfig()
        assert cfg.max_attempts == DEFAULT_MAX_ATTEMPTS
        assert cfg.initial_backoff_seconds == DEFAULT_INITIAL_BACKOFF_SECONDS
        assert cfg.max_backoff_seconds == DEFAULT_MAX_BACKOFF_SECONDS
        assert cfg.backoff_multiplier == DEFAULT_BACKOFF_MULTIPLIER

    def test_custom_valid_config(self) -> None:
        cfg = RetryPolicyConfig(
            max_attempts=5,
            initial_backoff_seconds=1.0,
            max_backoff_seconds=5.0,
            backoff_multiplier=1.5,
        )
        assert cfg.max_attempts == 5
        assert cfg.initial_backoff_seconds == 1.0
        assert cfg.max_backoff_seconds == 5.0
        assert cfg.backoff_multiplier == 1.5

    def test_max_attempts_bounds(self) -> None:
        with pytest.raises(RetryPolicyError, match="max_attempts must be between"):
            RetryPolicyConfig(max_attempts=0)

        with pytest.raises(RetryPolicyError, match="max_attempts must be between"):
            RetryPolicyConfig(max_attempts=CEILING_MAX_ATTEMPTS + 1)

    def test_initial_backoff_positive(self) -> None:
        with pytest.raises(RetryPolicyError, match="initial_backoff_seconds must be positive"):
            RetryPolicyConfig(initial_backoff_seconds=0.0)

    def test_max_backoff_greater_or_equal_initial(self) -> None:
        with pytest.raises(RetryPolicyError, match="max_backoff_seconds must be >= initial"):
            RetryPolicyConfig(initial_backoff_seconds=5.0, max_backoff_seconds=2.0)

    def test_multiplier_greater_or_equal_one(self) -> None:
        with pytest.raises(RetryPolicyError, match="backoff_multiplier must be >= 1.0"):
            RetryPolicyConfig(backoff_multiplier=0.9)


class TestBackoffComputation:
    """Tests for compute_backoff_seconds."""

    def test_backoff_progression(self) -> None:
        cfg = RetryPolicyConfig(
            initial_backoff_seconds=1.0,
            max_backoff_seconds=10.0,
            backoff_multiplier=2.0,
        )
        assert compute_backoff_seconds(0, cfg) == 0.0
        assert compute_backoff_seconds(1, cfg) == 1.0
        assert compute_backoff_seconds(2, cfg) == 2.0
        assert compute_backoff_seconds(3, cfg) == 4.0
        assert compute_backoff_seconds(4, cfg) == 8.0
        # Capped at max_backoff_seconds
        assert compute_backoff_seconds(5, cfg) == 10.0
        assert compute_backoff_seconds(10, cfg) == 10.0


class TestErrorClassification:
    """Tests for error classification (permanent vs transient vs retryable)."""

    def test_permanent_exceptions(self) -> None:
        assert is_permanent_failure(MissingCredentialError("no key"))
        assert is_permanent_failure(MissingSandboxCredentialError("no key"))
        assert is_permanent_failure(ModelConfigError("bad temp"))
        assert is_permanent_failure(SandboxConfigError("bad timeout"))
        assert is_permanent_failure(SourceCommitMismatchError("exp", "act"))

    def test_permanent_http_statuses(self) -> None:
        exc400 = ModelProviderError(status_code=400, sanitized_message="bad request")
        exc401 = SandboxProviderError(status_code=401, sanitized_message="unauthorized")
        exc403 = ModelProviderError(status_code=403, sanitized_message="forbidden")
        exc404 = SandboxProviderError(status_code=404, sanitized_message="not found")
        assert is_permanent_failure(exc400)
        assert is_permanent_failure(exc401)
        assert is_permanent_failure(exc403)
        assert is_permanent_failure(exc404)
        assert not is_transient_failure(exc403)

    def test_transient_http_statuses(self) -> None:
        exc429 = ModelProviderError(status_code=429, sanitized_message="rate limit")
        exc502 = SandboxProviderError(status_code=502, sanitized_message="bad gateway")
        exc503 = ModelProviderError(status_code=503, sanitized_message="service unavailable")
        exc504 = SandboxProviderError(status_code=504, sanitized_message="gateway timeout")
        assert is_transient_failure(exc429)
        assert is_transient_failure(exc502)
        assert is_transient_failure(exc503)
        assert is_transient_failure(exc504)
        assert not is_permanent_failure(exc503)

    def test_transient_transport_errors(self) -> None:
        assert is_transient_failure(ModelNetworkError("Connection reset by peer"))
        assert is_transient_failure(SandboxTransportError("Transport error: timeout"))

    def test_operation_retryable_classification(self) -> None:
        transient_exc = ModelProviderError(status_code=503, sanitized_message="temp down")
        perm_exc = ModelProviderError(status_code=403, sanitized_message="forbidden")

        # READ_ONLY on transient -> retryable
        can_retry, _ = is_operation_retryable(OperationEffect.READ_ONLY, transient_exc)
        assert can_retry is True

        # IDEMPOTENT_MUTATION on transient -> retryable
        can_retry, _ = is_operation_retryable(OperationEffect.IDEMPOTENT_MUTATION, transient_exc)
        assert can_retry is True

        # NON_IDEMPOTENT_MUTATION on transient -> FORBIDDEN (cannot retry)
        can_retry, rationale = is_operation_retryable(
            OperationEffect.NON_IDEMPOTENT_MUTATION, transient_exc
        )
        assert can_retry is False
        assert "Non-idempotent operation risks duplicating" in rationale

        # cancel_operation specifically blocked by name regardless of asserted effect
        can_retry_cancel, rationale_cancel = is_operation_retryable(
            OperationEffect.IDEMPOTENT_MUTATION, transient_exc, operation_name="cancel_operation"
        )
        assert can_retry_cancel is False
        assert "no proven provider idempotency guarantee" in rationale_cancel

        # Any operation on permanent failure -> cannot retry
        can_retry, _ = is_operation_retryable(OperationEffect.READ_ONLY, perm_exc)
        assert can_retry is False
        can_retry, _ = is_operation_retryable(OperationEffect.IDEMPOTENT_MUTATION, perm_exc)
        assert can_retry is False


class TestOperationClassification:
    """Tests for classify_operation_effect and KNOWN_OPERATION_EFFECTS."""

    def test_read_only_operations(self) -> None:
        assert classify_operation_effect("whoami") == OperationEffect.READ_ONLY
        assert classify_operation_effect("inspect_whoami") == OperationEffect.READ_ONLY
        assert classify_operation_effect("inspect_operation") == OperationEffect.READ_ONLY
        assert classify_operation_effect("poll_operation") == OperationEffect.READ_ONLY
        assert classify_operation_effect("list_images") == OperationEffect.READ_ONLY
        assert classify_operation_effect("inspect_image") == OperationEffect.READ_ONLY

    def test_mutating_operations_are_non_idempotent(self) -> None:
        # cancel_operation is non-idempotent because no provider idempotency guarantee exists
        mutating_ops = (
            "cancel_operation",
            "cancel",
            "create_instance",
            "chat_completion",
            "spawn_disposable",
            "spawn_instance",
            "clone_repository",
            "materialize_source",
        )
        for op in mutating_ops:
            assert classify_operation_effect(op) == OperationEffect.NON_IDEMPOTENT_MUTATION

    def test_known_operation_effects_mapping(self) -> None:
        assert KNOWN_OPERATION_EFFECTS["cancel_operation"] == (
            OperationEffect.NON_IDEMPOTENT_MUTATION
        )
        assert KNOWN_OPERATION_EFFECTS["whoami"] == OperationEffect.READ_ONLY

    def test_unknown_operation_defaults_to_non_idempotent_mutation(self) -> None:
        assert (
            classify_operation_effect("unknown_action_xyz")
            == OperationEffect.NON_IDEMPOTENT_MUTATION
        )
        assert (
            classify_operation_effect("custom_post_call") == OperationEffect.NON_IDEMPOTENT_MUTATION
        )

    def test_case_and_whitespace_insensitivity(self) -> None:
        assert (
            classify_operation_effect("  CANCEL_OPERATION  ")
            == OperationEffect.NON_IDEMPOTENT_MUTATION
        )
        assert classify_operation_effect("  WhoAmI  ") == OperationEffect.READ_ONLY


class TestNebiusRetryExecutor:
    """Tests for NebiusRetryExecutor behavior across operations and errors."""

    def test_successful_execution_first_attempt(self) -> None:
        executor = NebiusRetryExecutor()
        result, trail = executor.execute(
            operation_name="inspect_whoami",
            operation_effect=OperationEffect.READ_ONLY,
            action=lambda: {"user": "test_user"},
        )
        assert result == {"user": "test_user"}
        assert trail.total_attempts == 1
        assert trail.is_terminal_success is True
        assert len(trail.attempts) == 1
        assert trail.attempts[0].attempt_number == 1
        assert trail.attempts[0].status == "SUCCESS"
        assert trail.attempts[0].status_code == 200

    def test_non_idempotent_mutation_fails_closed_without_retry(self) -> None:
        """Mutating operation (e.g. creating sandbox) must fail closed after exactly 1 attempt."""
        call_count = 0
        sleep_durations: list[float] = []

        def failing_action() -> None:
            nonlocal call_count
            call_count += 1
            raise SandboxProviderError(status_code=503, sanitized_message="Service Unavailable")

        config = RetryPolicyConfig(
            max_attempts=3,
            sleep_callable=sleep_durations.append,
        )
        executor = NebiusRetryExecutor(config)

        with pytest.raises(NonRetryableOperationError) as exc_info:
            executor.execute(
                operation_name="create_sandbox_instance",
                operation_effect=OperationEffect.NON_IDEMPOTENT_MUTATION,
                action=failing_action,
            )

        err = exc_info.value
        assert err.operation_name == "create_sandbox_instance"
        assert err.operation_effect == OperationEffect.NON_IDEMPOTENT_MUTATION
        assert "retrying is forbidden to prevent duplicate external execution" in err.reason
        assert call_count == 1
        assert len(sleep_durations) == 0  # No sleep, immediate fail-closed

    def test_read_only_recovers_on_transient_retry(self) -> None:
        """Read-only operation retries transient 503 and succeeds on attempt 2."""
        call_count = 0
        sleep_durations: list[float] = []

        def recovering_action() -> str:
            nonlocal call_count
            call_count += 1
            if call_count == 1:
                raise ModelProviderError(status_code=503, sanitized_message="High load")
            return "recovered_data"

        config = RetryPolicyConfig(
            max_attempts=3,
            initial_backoff_seconds=0.1,
            backoff_multiplier=2.0,
            sleep_callable=sleep_durations.append,
        )
        executor = NebiusRetryExecutor(config)

        result, trail = executor.execute(
            operation_name="inspect_operation",
            operation_effect=OperationEffect.READ_ONLY,
            action=recovering_action,
        )

        assert result == "recovered_data"
        assert call_count == 2
        assert len(sleep_durations) == 1
        assert sleep_durations[0] == 0.1
        assert trail.total_attempts == 2
        assert trail.is_terminal_success is True
        assert trail.attempts[0].status == "TRANSIENT_FAILURE"
        assert trail.attempts[0].is_retryable is True
        assert trail.attempts[1].status == "SUCCESS"

    def test_permanent_failure_re_raises_immediately(self) -> None:
        """Permanent 403 on read-only query aborts on attempt 1 without retry."""
        call_count = 0
        sleep_durations: list[float] = []

        def forbidden_action() -> None:
            nonlocal call_count
            call_count += 1
            raise ModelProviderError(status_code=403, sanitized_message="Access denied")

        config = RetryPolicyConfig(
            max_attempts=3,
            sleep_callable=sleep_durations.append,
        )
        executor = NebiusRetryExecutor(config)

        with pytest.raises(ModelProviderError) as exc_info:
            executor.execute(
                operation_name="inspect_whoami",
                operation_effect=OperationEffect.READ_ONLY,
                action=forbidden_action,
            )

        assert exc_info.value.status_code == 403
        assert call_count == 1
        assert len(sleep_durations) == 0

    def test_transient_failure_exhausts_max_attempts(self) -> None:
        """Continuous transient failures exhaust max_attempts and raise MaxAttemptsExceededError."""
        call_count = 0
        sleep_durations: list[float] = []

        def persistent_503() -> None:
            nonlocal call_count
            call_count += 1
            raise SandboxProviderError(
                status_code=503, sanitized_message="Service Temporarily Overloaded"
            )

        config = RetryPolicyConfig(
            max_attempts=3,
            initial_backoff_seconds=0.2,
            backoff_multiplier=2.0,
            sleep_callable=sleep_durations.append,
        )
        executor = NebiusRetryExecutor(config)

        with pytest.raises(MaxAttemptsExceededError) as exc_info:
            executor.execute(
                operation_name="inspect_operation",
                operation_effect=OperationEffect.READ_ONLY,
                action=persistent_503,
            )

        err = exc_info.value
        assert err.operation_name == "inspect_operation"
        assert err.total_attempts == 3
        assert "Service Temporarily Overloaded" in err.last_error_message
        assert call_count == 3
        assert sleep_durations == [0.2, 0.4]
        assert err.audit_trail.total_attempts == 3
        assert err.audit_trail.is_terminal_success is False
        assert len(err.audit_trail.attempts) == 3

    def test_cancel_operation_strictly_one_attempt_on_success(self) -> None:
        """Requirement A: cancel_operation makes strictly 1 attempt on success."""
        call_count = 0

        def cancel_action() -> bool:
            nonlocal call_count
            call_count += 1
            return True

        executor = NebiusRetryExecutor(RetryPolicyConfig(max_attempts=3))
        result, trail = executor.execute(
            operation_name="cancel_operation",
            action=cancel_action,
        )
        assert result is True
        assert call_count == 1
        assert trail.total_attempts == 1
        assert trail.is_terminal_success is True
        assert trail.operation_effect == OperationEffect.NON_IDEMPOTENT_MUTATION

    def test_cancel_operation_transient_5xx_fails_closed(self) -> None:
        """Requirement B: transient 5xx on cancel_operation fails closed, call count = 1."""
        call_count = 0
        sleep_durations: list[float] = []

        def cancel_503() -> None:
            nonlocal call_count
            call_count += 1
            raise SandboxProviderError(status_code=503, sanitized_message="Overloaded")

        executor = NebiusRetryExecutor(
            RetryPolicyConfig(max_attempts=3, sleep_callable=sleep_durations.append)
        )
        with pytest.raises(NonRetryableOperationError) as exc_info:
            executor.execute(
                operation_name="cancel_operation",
                action=cancel_503,
            )

        err = exc_info.value
        assert err.operation_name == "cancel_operation"
        assert err.operation_effect == OperationEffect.NON_IDEMPOTENT_MUTATION
        assert "retrying is forbidden to prevent duplicate external execution" in err.reason
        assert call_count == 1
        assert len(sleep_durations) == 0

    def test_cancel_operation_timeout_fails_closed(self) -> None:
        """Requirement C: timeout on cancel_operation fails closed, call count = 1."""
        call_count = 0
        sleep_durations: list[float] = []

        def cancel_timeout() -> None:
            nonlocal call_count
            call_count += 1
            raise SandboxTimeoutError("Operation cancel timeout")

        executor = NebiusRetryExecutor(
            RetryPolicyConfig(max_attempts=3, sleep_callable=sleep_durations.append)
        )
        with pytest.raises(NonRetryableOperationError) as exc_info:
            executor.execute(
                operation_name="cancel_operation",
                action=cancel_timeout,
            )

        err = exc_info.value
        assert err.operation_name == "cancel_operation"
        assert err.operation_effect == OperationEffect.NON_IDEMPOTENT_MUTATION
        assert call_count == 1
        assert len(sleep_durations) == 0

    def test_create_instance_remains_strictly_one_attempt(self) -> None:
        """Requirement D: create_instance fails closed after strictly 1 attempt."""
        call_count = 0

        def create_action() -> None:
            nonlocal call_count
            call_count += 1
            raise SandboxProviderError(status_code=500, sanitized_message="Internal Error")

        executor = NebiusRetryExecutor(RetryPolicyConfig(max_attempts=3))
        with pytest.raises(NonRetryableOperationError):
            executor.execute(
                operation_name="create_instance",
                action=create_action,
            )
        assert call_count == 1

    def test_chat_completion_remains_strictly_one_attempt(self) -> None:
        """Requirement E: chat_completion fails closed after strictly 1 attempt."""
        call_count = 0

        def chat_action() -> None:
            nonlocal call_count
            call_count += 1
            raise ModelProviderError(status_code=429, sanitized_message="Rate limit")

        executor = NebiusRetryExecutor(RetryPolicyConfig(max_attempts=3))
        with pytest.raises(NonRetryableOperationError):
            executor.execute(
                operation_name="chat_completion",
                action=chat_action,
            )
        assert call_count == 1

    def test_deterministic_audit_trail_structure(self) -> None:
        """Requirement H: deterministic AttemptRecord and RetryAuditTrail structure."""

        def action() -> str:
            return "ok"

        executor = NebiusRetryExecutor()
        result, trail = executor.execute("whoami", action=action)
        assert result == "ok"
        d = trail.to_dict()
        assert d["operation_name"] == "whoami"
        assert d["operation_effect"] == "READ_ONLY"
        assert d["total_attempts"] == 1
        assert d["is_terminal_success"] is True
        assert len(d["attempts"]) == 1
        assert d["attempts"][0]["status"] == "SUCCESS"
        assert d["attempts"][0]["status_code"] == 200

    def test_no_lower_adapter_duplicate_external_mutation(self) -> None:
        """Requirement J: lower adapter mutating action is called strictly once on error."""
        calls: list[str] = []

        class MockLowerAdapter:
            def cancel_op(self, op_id: str) -> None:
                calls.append(f"cancel:{op_id}")
                raise SandboxProviderError(status_code=503, sanitized_message="Busy")

        adapter = MockLowerAdapter()
        executor = NebiusRetryExecutor(RetryPolicyConfig(max_attempts=5))

        with pytest.raises(NonRetryableOperationError):
            executor.execute(
                operation_name="cancel_operation",
                action=lambda: adapter.cancel_op("op-12345"),
            )

        assert calls == ["cancel:op-12345"]
        assert len(calls) == 1

    def test_unproven_mutation_claiming_idempotent_raises_retry_policy_error(self) -> None:
        """Requirement K: unproven mutation claiming IDEMPOTENT_MUTATION raises error."""
        executor = NebiusRetryExecutor()

        for op_name in (
            "cancel_operation",
            "cancel",
            "create_instance",
            "chat_completion",
            "spawn_disposable",
        ):
            with pytest.raises(
                RetryPolicyError, match="has no proven provider idempotency guarantee"
            ):
                executor.execute(
                    operation_name=op_name,
                    operation_effect=OperationEffect.IDEMPOTENT_MUTATION,
                    action=lambda: None,
                )

    def test_secret_redaction_in_audit_trail_and_errors(self) -> None:
        """Synthetic secrets in error messages must be redacted in AttemptRecords and errors."""
        secret_raw = "Authorization: Bearer secret_nebius_api_key_xyz987654321 failed with 503"

        def leaky_error_action() -> None:
            raise ModelProviderError(status_code=503, sanitized_message=secret_raw)

        config = RetryPolicyConfig(
            max_attempts=2,
            initial_backoff_seconds=0.01,
            sleep_callable=lambda _: None,
        )
        executor = NebiusRetryExecutor(config)

        with pytest.raises(MaxAttemptsExceededError) as exc_info:
            executor.execute(
                operation_name="inspect_whoami",
                operation_effect=OperationEffect.READ_ONLY,
                action=leaky_error_action,
            )

        err = exc_info.value
        # Check that secret is redacted
        assert "secret_nebius_api_key_xyz987654321" not in str(err)
        assert "secret_nebius_api_key_xyz987654321" not in err.last_error_message
        assert "[REDACTED" in err.last_error_message

        # Check in audit trail
        trail = err.audit_trail
        assert "secret_nebius_api_key_xyz987654321" not in str(trail.to_dict())
        for attempt in trail.attempts:
            if attempt.error_message:
                assert "secret_nebius_api_key_xyz987654321" not in attempt.error_message
                assert "[REDACTED" in attempt.error_message


class TestClassificationAuthority:
    """Tests proving canonical operation classification is authoritative (P-05.05 repair)."""

    def test_requirement_a_known_mutation_explicit_read_only_raises_before_action(self) -> None:
        """Requirement A & J: known mutation + explicit READ_ONLY raises RetryPolicyError;
        action called 0 times.
        """
        executor = NebiusRetryExecutor()
        call_count = 0

        def action() -> None:
            nonlocal call_count
            call_count += 1

        for op_name in (
            "create_instance",
            "cancel_operation",
            "chat_completion",
            "materialize_source",
        ):
            with pytest.raises(
                RetryPolicyError, match="Operation classification mismatch for known operation"
            ):
                executor.execute(
                    operation_name=op_name,
                    operation_effect=OperationEffect.READ_ONLY,
                    action=action,
                )
            assert call_count == 0

    def test_requirement_b_known_mutation_explicit_idempotent_mutation_raises_before_action(
        self,
    ) -> None:
        """Requirement B & J: known mutation + explicit IDEMPOTENT_MUTATION raises
        RetryPolicyError; action called 0 times.
        """
        executor = NebiusRetryExecutor()
        call_count = 0

        def action() -> None:
            nonlocal call_count
            call_count += 1

        for op_name in (
            "create_instance",
            "cancel_operation",
            "chat_completion",
            "spawn_disposable",
        ):
            with pytest.raises(
                RetryPolicyError, match="has no proven provider idempotency guarantee"
            ):
                executor.execute(
                    operation_name=op_name,
                    operation_effect=OperationEffect.IDEMPOTENT_MUTATION,
                    action=action,
                )
            assert call_count == 0

    def test_requirement_c_known_read_only_conflicting_classification_raises_before_action(
        self,
    ) -> None:
        """Requirement C & J: known READ_ONLY + conflicting classification raises
        RetryPolicyError; action called 0 times.
        """
        executor = NebiusRetryExecutor()
        call_count = 0

        def action() -> None:
            nonlocal call_count
            call_count += 1

        for conflicting_effect in (
            OperationEffect.NON_IDEMPOTENT_MUTATION,
            OperationEffect.IDEMPOTENT_MUTATION,
        ):
            for op_name in ("whoami", "inspect_whoami", "inspect_operation", "poll_operation"):
                with pytest.raises(
                    RetryPolicyError, match="Operation classification mismatch for known operation"
                ):
                    executor.execute(
                        operation_name=op_name,
                        operation_effect=conflicting_effect,
                        action=action,
                    )
                assert call_count == 0

    def test_requirement_d_unknown_operation_explicit_read_only_raises_before_action(
        self,
    ) -> None:
        """Requirement D & J: unknown operation + explicit READ_ONLY raises RetryPolicyError;
        action called 0 times.
        """
        executor = NebiusRetryExecutor()
        call_count = 0

        def action() -> None:
            nonlocal call_count
            call_count += 1

        with pytest.raises(
            RetryPolicyError, match="Cannot assert READ_ONLY for unregistered operation"
        ):
            executor.execute(
                operation_name="unknown_action_xyz",
                operation_effect=OperationEffect.READ_ONLY,
                action=action,
            )
        assert call_count == 0

    def test_requirement_e_unknown_operation_explicit_idempotent_mutation_raises_before_action(
        self,
    ) -> None:
        """Requirement E & J: unknown operation + explicit IDEMPOTENT_MUTATION raises
        RetryPolicyError; action called 0 times.
        """
        executor = NebiusRetryExecutor()
        call_count = 0

        def action() -> None:
            nonlocal call_count
            call_count += 1

        with pytest.raises(
            RetryPolicyError, match="Cannot assert IDEMPOTENT_MUTATION for unregistered operation"
        ):
            executor.execute(
                operation_name="unknown_mutating_provider_call",
                operation_effect=OperationEffect.IDEMPOTENT_MUTATION,
                action=action,
            )
        assert call_count == 0

    def test_requirement_f_unknown_operation_no_explicit_effect_defaults_non_idempotent_mutation(
        self,
    ) -> None:
        """Requirement F: unknown operation with no explicit effect defaults to
        NON_IDEMPOTENT_MUTATION and gets exactly 1 attempt.
        """
        executor = NebiusRetryExecutor(RetryPolicyConfig(max_attempts=3))

        # Subcase 1: Success makes exactly 1 attempt and records NON_IDEMPOTENT_MUTATION
        call_count = 0

        def success_action() -> str:
            nonlocal call_count
            call_count += 1
            return "ok"

        res, trail = executor.execute("unknown_op_foo", action=success_action)
        assert res == "ok"
        assert call_count == 1
        assert trail.total_attempts == 1
        assert trail.operation_effect == OperationEffect.NON_IDEMPOTENT_MUTATION
        assert trail.attempts[0].operation_effect == OperationEffect.NON_IDEMPOTENT_MUTATION

        # Subcase 2: Transient failure makes strictly 1 attempt and fails closed
        # with NonRetryableOperationError
        fail_count = 0

        def failing_action() -> None:
            nonlocal fail_count
            fail_count += 1
            raise SandboxProviderError(status_code=503, sanitized_message="Service Unavailable")

        with pytest.raises(NonRetryableOperationError) as exc_info:
            executor.execute("unknown_op_foo", action=failing_action)

        assert fail_count == 1
        assert exc_info.value.operation_name == "unknown_op_foo"
        assert exc_info.value.operation_effect == OperationEffect.NON_IDEMPOTENT_MUTATION

    def test_requirement_g_unknown_operation_explicit_non_idempotent_mutation_behaves_identically(
        self,
    ) -> None:
        """Requirement G: unknown operation + explicit NON_IDEMPOTENT_MUTATION behaves
        identically to default.
        """
        executor = NebiusRetryExecutor(RetryPolicyConfig(max_attempts=3))

        call_count = 0

        def success_action() -> str:
            nonlocal call_count
            call_count += 1
            return "ok_explicit"

        res, trail = executor.execute(
            operation_name="unknown_op_bar",
            operation_effect=OperationEffect.NON_IDEMPOTENT_MUTATION,
            action=success_action,
        )
        assert res == "ok_explicit"
        assert call_count == 1
        assert trail.total_attempts == 1
        assert trail.operation_effect == OperationEffect.NON_IDEMPOTENT_MUTATION

        fail_count = 0

        def failing_action() -> None:
            nonlocal fail_count
            fail_count += 1
            raise SandboxProviderError(status_code=503, sanitized_message="Service Unavailable")

        with pytest.raises(NonRetryableOperationError) as exc_info:
            executor.execute(
                operation_name="unknown_op_bar",
                operation_effect=OperationEffect.NON_IDEMPOTENT_MUTATION,
                action=failing_action,
            )

        assert fail_count == 1
        assert exc_info.value.operation_name == "unknown_op_bar"
        assert exc_info.value.operation_effect == OperationEffect.NON_IDEMPOTENT_MUTATION

    def test_requirement_h_successful_known_mutation_trail_records_non_idempotent_mutation(
        self,
    ) -> None:
        """Requirement H: successful known mutation trail records NON_IDEMPOTENT_MUTATION
        regardless of caller attempts.
        """
        executor = NebiusRetryExecutor()

        # 1. Attempting to misclassify as READ_ONLY is rejected before action
        call_count = 0

        def mutate_action() -> dict[str, str]:
            nonlocal call_count
            call_count += 1
            return {"instance_id": "inst-1"}

        with pytest.raises(RetryPolicyError):
            executor.execute(
                operation_name="create_instance",
                operation_effect=OperationEffect.READ_ONLY,
                action=mutate_action,
            )
        assert call_count == 0

        # 2. Executing with default (no effect) records NON_IDEMPOTENT_MUTATION
        res, trail_default = executor.execute(
            operation_name="create_instance",
            action=mutate_action,
        )
        assert res == {"instance_id": "inst-1"}
        assert call_count == 1
        assert trail_default.operation_effect == OperationEffect.NON_IDEMPOTENT_MUTATION
        assert trail_default.attempts[0].operation_effect == OperationEffect.NON_IDEMPOTENT_MUTATION

        # 3. Executing with matching explicit assertion records NON_IDEMPOTENT_MUTATION
        res2, trail_explicit = executor.execute(
            operation_name="create_instance",
            operation_effect=OperationEffect.NON_IDEMPOTENT_MUTATION,
            action=mutate_action,
        )
        assert res2 == {"instance_id": "inst-1"}
        assert call_count == 2
        assert trail_explicit.operation_effect == OperationEffect.NON_IDEMPOTENT_MUTATION
        assert (
            trail_explicit.attempts[0].operation_effect == OperationEffect.NON_IDEMPOTENT_MUTATION
        )

    def test_requirement_i_canonical_read_only_retries_bounded_transient_failures(self) -> None:
        """Requirement I: canonical READ_ONLY operation still retries bounded transient failures."""
        call_count = 0

        def transient_action() -> str:
            nonlocal call_count
            call_count += 1
            if call_count < 3:
                raise ModelProviderError(status_code=503, sanitized_message="Service Unavailable")
            return "read_success"

        executor = NebiusRetryExecutor(
            RetryPolicyConfig(
                max_attempts=3,
                initial_backoff_seconds=0.01,
                sleep_callable=lambda _: None,
            )
        )
        res, trail = executor.execute("inspect_whoami", action=transient_action)
        assert res == "read_success"
        assert call_count == 3
        assert trail.total_attempts == 3
        assert trail.is_terminal_success is True
        assert trail.operation_effect == OperationEffect.READ_ONLY
        assert trail.attempts[0].status == "TRANSIENT_FAILURE"
        assert trail.attempts[1].status == "TRANSIENT_FAILURE"
        assert trail.attempts[2].status == "SUCCESS"

    def test_is_operation_retryable_rejects_unknown_operation_even_with_asserted_idempotent(
        self,
    ) -> None:
        """is_operation_retryable helper directly rejects unknown operations by name."""
        transient_exc = SandboxProviderError(status_code=503, sanitized_message="Busy")
        can_retry, rationale = is_operation_retryable(
            OperationEffect.IDEMPOTENT_MUTATION,
            transient_exc,
            operation_name="unknown_mutating_provider_call",
        )
        assert can_retry is False
        assert "no proven provider idempotency guarantee" in rationale
