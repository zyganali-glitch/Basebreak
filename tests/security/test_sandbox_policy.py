"""Tests for sandbox execution security policy (P-04.03)."""

from __future__ import annotations

import pytest

from basebreak.security.protected_surfaces import (
    ProtectedSurfaceViolation,
)
from basebreak.security.sandbox_policy import (
    CEILING_MAX_OUTPUT_BYTES,
    DEFAULT_MAX_LAYER_BYTES,
    DEFAULT_MAX_OUTPUT_BYTES,
    DEFAULT_SANDBOX_CONCURRENCY,
    DEFAULT_SANDBOX_TIMEOUT_SECONDS,
    MAX_COMMAND_LENGTH_BYTES,
    MAX_COMMANDS_PER_RUN,
    MAX_SANDBOX_CONCURRENCY,
    MAX_SANDBOX_TIMEOUT_SECONDS,
    MIN_SANDBOX_TIMEOUT_SECONDS,
    PLATFORM_CAPABILITIES,
    PROVIDER_MAX_LAYER_BYTES,
    CapabilityRecord,
    CapabilityStatus,
    FilesystemPolicyError,
    NetworkPolicyError,
    ProcessPolicyError,
    ResourceBudgetError,
    SandboxCapability,
    SandboxExecutionMode,
    SandboxExecutionPolicy,
    SandboxNetworkMode,
    SandboxResourceBudget,
    WorkspaceIsolationError,
    get_capability_record,
    is_capability_proven,
    validate_command_string,
    validate_image_identifier,
    validate_two_world_isolation,
)
from basebreak.security.secret_policy import SecretPersistenceError


class TestPlatformCapabilityMatrix:
    """Verify factual grounding and taxonomy of platform capabilities."""

    def test_proven_capabilities_are_marked_proven(self) -> None:
        proven = [
            SandboxCapability.DISPOSABLE_EXECUTION,
            SandboxCapability.CHECKPOINT_SNAPSHOT,
            SandboxCapability.FORK_FROM_IMAGE,
            SandboxCapability.TEARDOWN_OBSERVABILITY,
            SandboxCapability.OUTBOUND_HTTPS,
        ]
        for cap in proven:
            record = get_capability_record(cap)
            assert record.status == CapabilityStatus.PROVEN_SUPPORTED
            assert record.provenance == "RECORDED_LIVE"
            assert is_capability_proven(cap) is True

    def test_unproven_capabilities_are_explicitly_unproven(self) -> None:
        unproven = [
            SandboxCapability.INBOUND_NETWORK_ISOLATION,
            SandboxCapability.CPU_HARD_QUOTA,
            SandboxCapability.MEMORY_HARD_KILL,
            SandboxCapability.PID_PROCESS_LIMIT,
            SandboxCapability.SYSCALL_FILTERING,
            SandboxCapability.FILESYSTEM_MOUNT_RESTRICTIONS,
        ]
        for cap in unproven:
            record = get_capability_record(cap)
            assert record.status == CapabilityStatus.UNPROVEN
            assert record.provenance == "UNPROVEN"
            assert is_capability_proven(cap) is False

    def test_unsupported_capabilities_are_explicitly_unsupported(self) -> None:
        unsupported = [
            SandboxCapability.ARBITRARY_EGRESS_FILTERING,
            SandboxCapability.PROVIDER_SECRET_PROTECTION,
            SandboxCapability.SEALED_VERIFIER_ISOLATION,
        ]
        for cap in unsupported:
            record = get_capability_record(cap)
            assert record.status == CapabilityStatus.UNSUPPORTED
            assert is_capability_proven(cap) is False

    def test_all_enum_members_in_registry(self) -> None:
        for cap in SandboxCapability:
            assert cap in PLATFORM_CAPABILITIES
            record = PLATFORM_CAPABILITIES[cap]
            assert isinstance(record, CapabilityRecord)
            assert record.description
            assert record.notes


class TestResourceBudget:
    """Verify resource budget enforcement and operational ceilings."""

    def test_default_budget_is_valid(self) -> None:
        budget = SandboxResourceBudget()
        budget.validate()
        assert budget.timeout_seconds == DEFAULT_SANDBOX_TIMEOUT_SECONDS
        assert budget.max_concurrency == DEFAULT_SANDBOX_CONCURRENCY
        assert budget.max_output_bytes == DEFAULT_MAX_OUTPUT_BYTES
        assert budget.max_layer_bytes == DEFAULT_MAX_LAYER_BYTES
        assert budget.max_commands == MAX_COMMANDS_PER_RUN

    def test_budget_exceeding_operational_timeout_ceiling_rejected(self) -> None:
        # Provider limit is 3600s, but Basebreak operational ceiling is 600s
        budget = SandboxResourceBudget(timeout_seconds=601)
        with pytest.raises(ResourceBudgetError, match="exceeds Basebreak operational ceiling"):
            budget.validate()

    def test_budget_at_operational_ceiling_accepted(self) -> None:
        budget = SandboxResourceBudget(timeout_seconds=MAX_SANDBOX_TIMEOUT_SECONDS)
        budget.validate()

    def test_budget_below_min_timeout_rejected(self) -> None:
        budget = SandboxResourceBudget(timeout_seconds=0)
        with pytest.raises(ResourceBudgetError, match=f"must be >= {MIN_SANDBOX_TIMEOUT_SECONDS}"):
            budget.validate()

    def test_budget_concurrency_ceiling(self) -> None:
        budget = SandboxResourceBudget(max_concurrency=MAX_SANDBOX_CONCURRENCY + 1)
        with pytest.raises(ResourceBudgetError, match="exceeds Basebreak operational ceiling"):
            budget.validate()

    def test_budget_output_bytes_ceiling(self) -> None:
        budget = SandboxResourceBudget(max_output_bytes=CEILING_MAX_OUTPUT_BYTES + 1)
        with pytest.raises(ResourceBudgetError, match="exceeds Basebreak ceiling"):
            budget.validate()

    def test_budget_layer_bytes_ceiling(self) -> None:
        budget = SandboxResourceBudget(max_layer_bytes=PROVIDER_MAX_LAYER_BYTES + 1)
        with pytest.raises(ResourceBudgetError, match="exceeds provider limit"):
            budget.validate()

    def test_budget_commands_per_run_ceiling(self) -> None:
        budget = SandboxResourceBudget(max_commands=MAX_COMMANDS_PER_RUN + 1)
        with pytest.raises(ResourceBudgetError, match="exceeds Basebreak limit"):
            budget.validate()

    def test_budget_to_dict_deterministic(self) -> None:
        budget = SandboxResourceBudget(timeout_seconds=120, max_concurrency=3)
        d = budget.to_dict()
        assert d["timeout_seconds"] == 120
        assert d["max_concurrency"] == 3
        assert d["max_output_bytes"] == DEFAULT_MAX_OUTPUT_BYTES


class TestImageIdentifierValidation:
    """Verify validation of image tags and UUIDs."""

    def test_valid_image_tags(self) -> None:
        valid_tags = [
            "tag:busybox:latest",
            "tag:alpine:latest",
            "tag:astral/uv:python3.11-alpine",
            "tag:gcc:14",
        ]
        for tag in valid_tags:
            validate_image_identifier(tag)

    def test_valid_image_uuids(self) -> None:
        valid_uuids = [
            "28f5d6d6-f977-42a8-94b5-d8db23e62c8c",
            "95ba4f1b-a511-325b-af1c-a22b4f52f73b",
            "28f5d6d6f97742a894b5d8db23e62c8c",
        ]
        for uuid in valid_uuids:
            validate_image_identifier(uuid)

    def test_invalid_image_identifiers_rejected(self) -> None:
        invalid = [
            "",
            "   ",
            "busybox:latest",  # Missing tag: prefix
            "alpine",
            "../../etc/passwd",
            "tag:invalid space",
            "not-a-uuid",
        ]
        for inv in invalid:
            with pytest.raises(FilesystemPolicyError):
                validate_image_identifier(inv)


class TestCommandStringValidation:
    """Verify command string bounding and secret detection."""

    def test_valid_command_passes(self) -> None:
        validate_command_string("python -m pytest tests/test_task.py")

    def test_empty_command_rejected(self) -> None:
        with pytest.raises(ProcessPolicyError, match="must be a non-empty string"):
            validate_command_string("")
        with pytest.raises(ProcessPolicyError, match="must be a non-empty string"):
            validate_command_string("   ")

    def test_command_with_null_bytes_rejected(self) -> None:
        with pytest.raises(ProcessPolicyError, match="null bytes"):
            validate_command_string("echo hello\x00world")

    def test_command_exceeding_max_length_rejected(self) -> None:
        long_cmd = "a" * (MAX_COMMAND_LENGTH_BYTES + 1)
        with pytest.raises(ProcessPolicyError, match="exceeds maximum allowed length"):
            validate_command_string(long_cmd)

    def test_command_with_raw_secret_rejected(self) -> None:
        # Synthetic Bearer token
        secret_cmd = (
            "curl -H 'Authorization: Bearer nbs_sk_live_test1234567890abcdef' https://api.test"
        )
        with pytest.raises(ProcessPolicyError, match="contains forbidden secret-shaped value"):
            validate_command_string(secret_cmd)


class TestSandboxExecutionPolicy:
    """Verify comprehensive execution policy validation."""

    def test_valid_verification_request_passes(self) -> None:
        policy = SandboxExecutionPolicy()
        policy.validate_execution_request(
            command="python -m pytest tests/",
            image="tag:astral/uv:python3.11-alpine",
            execution_mode=SandboxExecutionMode.DISPOSABLE,
            network_mode=SandboxNetworkMode.DISABLED,
            is_verification_run=True,
        )

    def test_verification_run_rejects_checkpoint_mode(self) -> None:
        policy = SandboxExecutionPolicy()
        with pytest.raises(
            WorkspaceIsolationError, match="Verification run must use DISPOSABLE mode"
        ):
            policy.validate_execution_request(
                command="python -m pytest tests/",
                image="tag:astral/uv:python3.11-alpine",
                execution_mode=SandboxExecutionMode.CHECKPOINT,
                network_mode=SandboxNetworkMode.DISABLED,
                is_verification_run=True,
            )

    def test_checkpoint_mode_allowed_for_setup_run(self) -> None:
        policy = SandboxExecutionPolicy()
        policy.validate_execution_request(
            command="git clone https://github.com/example/repo.git",
            image="tag:astral/uv:python3.11-alpine",
            execution_mode=SandboxExecutionMode.CHECKPOINT,
            network_mode=SandboxNetworkMode.EGRESS_REQUIRED,
            is_verification_run=False,
        )

    def test_sensitive_environment_variable_rejected(self) -> None:
        policy = SandboxExecutionPolicy()
        with pytest.raises(SecretPersistenceError, match="FORBIDDEN_SENSITIVE_KEY"):
            policy.validate_execution_request(
                command="pytest",
                image="tag:astral/uv:python3.11-alpine",
                execution_mode=SandboxExecutionMode.DISPOSABLE,
                network_mode=SandboxNetworkMode.DISABLED,
                env={"NEBIUS_API_KEY": "dummy_key"},
            )

    def test_secret_shaped_value_in_env_rejected(self) -> None:
        policy = SandboxExecutionPolicy()
        with pytest.raises(SecretPersistenceError):
            policy.validate_execution_request(
                command="pytest",
                image="tag:astral/uv:python3.11-alpine",
                execution_mode=SandboxExecutionMode.DISPOSABLE,
                network_mode=SandboxNetworkMode.DISABLED,
                env={"CUSTOM_CONFIG": "Bearer eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.e30.signature"},
            )

    def test_network_egress_disabled_policy_rejection(self) -> None:
        policy = SandboxExecutionPolicy(allow_network_egress=False)
        with pytest.raises(NetworkPolicyError, match="Network egress is explicitly disabled"):
            policy.validate_execution_request(
                command="curl https://example.com",
                image="tag:astral/uv:python3.11-alpine",
                execution_mode=SandboxExecutionMode.DISPOSABLE,
                network_mode=SandboxNetworkMode.EGRESS_REQUIRED,
            )

    def test_protected_surface_diff_mutation_rejected(self) -> None:
        policy = SandboxExecutionPolicy()
        malicious_diff = """--- a/plans/BASEBREAK_MASTER_EXECUTION_PLAN.md
+++ b/plans/BASEBREAK_MASTER_EXECUTION_PLAN.md
@@ -1,3 +1,3 @@
-# BASEBREAK
+# COMPROMISED
"""
        with pytest.raises(ProtectedSurfaceViolation):
            policy.validate_execution_request(
                command="pytest",
                image="tag:astral/uv:python3.11-alpine",
                execution_mode=SandboxExecutionMode.DISPOSABLE,
                network_mode=SandboxNetworkMode.DISABLED,
                diff_content=malicious_diff,
            )

    def test_benign_diff_mutation_allowed(self) -> None:
        policy = SandboxExecutionPolicy()
        benign_diff = """--- a/src/my_app/calculator.py
+++ b/src/my_app/calculator.py
@@ -1,2 +1,2 @@
-def add(a, b): return a - b
+def add(a, b): return a + b
"""
        policy.validate_execution_request(
            command="pytest",
            image="tag:astral/uv:python3.11-alpine",
            execution_mode=SandboxExecutionMode.DISPOSABLE,
            network_mode=SandboxNetworkMode.DISABLED,
            diff_content=benign_diff,
        )


class TestTwoWorldIsolationValidator:
    """Verify two-clean-environment isolation checks."""

    def test_valid_isolation_passes(self) -> None:
        validate_two_world_isolation(
            base_execution_id="01a0d8ce-9ce0-7310-846b-8b556856ce48",
            candidate_execution_id="01a0d8ce-9f6c-7314-98c8-a30d7cef5af7",
            base_image="tag:astral/uv:python3.11-alpine",
            candidate_image="tag:astral/uv:python3.11-alpine",
            base_mode=SandboxExecutionMode.DISPOSABLE,
            candidate_mode=SandboxExecutionMode.DISPOSABLE,
        )

    def test_same_execution_identity_rejected(self) -> None:
        same_id = "01a0d8ce-9ce0-7310-846b-8b556856ce48"
        with pytest.raises(
            WorkspaceIsolationError, match="cannot share the same execution identity"
        ):
            validate_two_world_isolation(
                base_execution_id=same_id,
                candidate_execution_id=same_id,
                base_image="tag:astral/uv:python3.11-alpine",
                candidate_image="tag:astral/uv:python3.11-alpine",
                base_mode=SandboxExecutionMode.DISPOSABLE,
                candidate_mode=SandboxExecutionMode.DISPOSABLE,
            )

    def test_non_disposable_base_rejected(self) -> None:
        with pytest.raises(WorkspaceIsolationError, match="BASE execution must be DISPOSABLE"):
            validate_two_world_isolation(
                base_execution_id="id-1",
                candidate_execution_id="id-2",
                base_image="tag:astral/uv:python3.11-alpine",
                candidate_image="tag:astral/uv:python3.11-alpine",
                base_mode=SandboxExecutionMode.CHECKPOINT,
                candidate_mode=SandboxExecutionMode.DISPOSABLE,
            )

    def test_non_disposable_candidate_rejected(self) -> None:
        with pytest.raises(WorkspaceIsolationError, match="CANDIDATE execution must be DISPOSABLE"):
            validate_two_world_isolation(
                base_execution_id="id-1",
                candidate_execution_id="id-2",
                base_image="tag:astral/uv:python3.11-alpine",
                candidate_image="tag:astral/uv:python3.11-alpine",
                base_mode=SandboxExecutionMode.DISPOSABLE,
                candidate_mode=SandboxExecutionMode.CHECKPOINT,
            )
