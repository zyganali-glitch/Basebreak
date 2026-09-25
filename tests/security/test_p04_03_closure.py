"""Acceptance criteria and closure tests for task P-04.03.

P-04.03 — Define sandbox resource/network/process policy from proven platform capability.

Acceptance criteria:
1. Resource ceilings/policy derived from proven facts;
2. Network policy derived from proven facts;
3. Process policy derived from proven facts;
4. Unknown capabilities explicitly marked unknown/unavailable rather than guessed;
5. Policy integrates P-04.02 secrets and P-04.04 protected surfaces;
6. No provider capability overclaim;
7. No P-05 adapter implementation.
"""

from __future__ import annotations

import inspect

import pytest

import basebreak.security.sandbox_policy as sp
from basebreak.security.protected_surfaces import ProtectedSurfaceViolation
from basebreak.security.sandbox_policy import (
    CEILING_MAX_OUTPUT_BYTES,
    DEFAULT_MAX_OUTPUT_BYTES,
    DEFAULT_SANDBOX_CONCURRENCY,
    DEFAULT_SANDBOX_TIMEOUT_SECONDS,
    MAX_COMMAND_LENGTH_BYTES,
    MAX_COMMANDS_PER_RUN,
    MAX_SANDBOX_CONCURRENCY,
    MAX_SANDBOX_TIMEOUT_SECONDS,
    MIN_SANDBOX_TIMEOUT_SECONDS,
    PLATFORM_CAPABILITIES,
    PROVIDER_IMAGES_IMPORT_MAX_CONCURRENCY,
    PROVIDER_IMAGES_IMPORT_MAX_TIMEOUT,
    PROVIDER_MAX_CONCURRENCY,
    PROVIDER_MAX_LAYER_BYTES,
    PROVIDER_MAX_TIMEOUT_SECONDS,
    CapabilityStatus,
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
    validate_two_world_isolation,
)
from basebreak.security.secret_policy import SecretPersistenceError


class TestP0403Criterion1ResourceBudgets:
    """Criterion 1: Resource ceilings/policy derived from proven facts."""

    def test_provider_limits_grounded_in_live_whoami(self) -> None:
        assert PROVIDER_MAX_TIMEOUT_SECONDS == 3600
        assert PROVIDER_MAX_CONCURRENCY == 50
        assert PROVIDER_MAX_LAYER_BYTES == 12_884_901_888
        assert PROVIDER_IMAGES_IMPORT_MAX_CONCURRENCY == 8
        assert PROVIDER_IMAGES_IMPORT_MAX_TIMEOUT == 3600

    def test_basebreak_operational_ceilings_constrained(self) -> None:
        # Strict inequality: operational ceilings strictly smaller than provider max
        assert MAX_SANDBOX_TIMEOUT_SECONDS < PROVIDER_MAX_TIMEOUT_SECONDS
        assert MAX_SANDBOX_TIMEOUT_SECONDS == 600
        assert DEFAULT_SANDBOX_TIMEOUT_SECONDS == 180
        assert MIN_SANDBOX_TIMEOUT_SECONDS == 1

        assert MAX_SANDBOX_CONCURRENCY < PROVIDER_MAX_CONCURRENCY
        assert MAX_SANDBOX_CONCURRENCY == 4
        assert DEFAULT_SANDBOX_CONCURRENCY == 2

        assert DEFAULT_MAX_OUTPUT_BYTES == 65_536
        assert CEILING_MAX_OUTPUT_BYTES == 1_048_576

        assert MAX_COMMANDS_PER_RUN == 10
        assert MAX_COMMAND_LENGTH_BYTES == 16_384

    def test_budget_validation_enforces_operational_ceilings(self) -> None:
        valid_budget = SandboxResourceBudget()
        valid_budget.validate()

        with pytest.raises(ResourceBudgetError):
            SandboxResourceBudget(timeout_seconds=MAX_SANDBOX_TIMEOUT_SECONDS + 1).validate()

        with pytest.raises(ResourceBudgetError):
            SandboxResourceBudget(timeout_seconds=0).validate()

        with pytest.raises(ResourceBudgetError):
            SandboxResourceBudget(max_concurrency=MAX_SANDBOX_CONCURRENCY + 1).validate()

        with pytest.raises(ResourceBudgetError):
            SandboxResourceBudget(max_output_bytes=CEILING_MAX_OUTPUT_BYTES + 1).validate()


class TestP0403Criterion2NetworkPolicy:
    """Criterion 2: Network policy derived from proven facts."""

    def test_outbound_https_proven_but_egress_filtering_unsupported(self) -> None:
        rec_https = get_capability_record(SandboxCapability.OUTBOUND_HTTPS)
        assert rec_https.status == CapabilityStatus.PROVEN_SUPPORTED
        assert rec_https.provenance == "RECORDED_LIVE"

        rec_filtering = get_capability_record(SandboxCapability.ARBITRARY_EGRESS_FILTERING)
        assert rec_filtering.status == CapabilityStatus.UNSUPPORTED
        assert rec_filtering.provenance == "OFFICIAL_DOC"

    def test_network_modes_supported(self) -> None:
        assert SandboxNetworkMode.DISABLED.value == "DISABLED"
        assert SandboxNetworkMode.EGRESS_REQUIRED.value == "EGRESS_REQUIRED"

    def test_network_egress_disabled_fails_closed(self) -> None:
        policy = SandboxExecutionPolicy(allow_network_egress=False)
        with pytest.raises(NetworkPolicyError, match="Network egress is explicitly disabled"):
            policy.validate_execution_request(
                command="curl https://api.test",
                image="tag:astral/uv:python3.11-alpine",
                execution_mode=SandboxExecutionMode.DISPOSABLE,
                network_mode=SandboxNetworkMode.EGRESS_REQUIRED,
            )

    def test_network_egress_with_secret_fails_closed(self) -> None:
        # With secret policy bypass, network policy itself independently fails closed
        policy = SandboxExecutionPolicy(enforce_secret_policy=False)
        with pytest.raises(NetworkPolicyError, match="Network egress execution contains secret"):
            policy.validate_execution_request(
                command="curl https://api.test",
                image="tag:astral/uv:python3.11-alpine",
                execution_mode=SandboxExecutionMode.DISPOSABLE,
                network_mode=SandboxNetworkMode.EGRESS_REQUIRED,
                env={"MY_CONFIG": "Bearer test_token_1234567890abcdef_secret"},
            )


class TestP0403Criterion3ProcessPolicy:
    """Criterion 3: Process policy derived from proven facts."""

    def test_command_string_safety(self) -> None:
        validate_command_string("pytest -v")

        with pytest.raises(ProcessPolicyError, match="non-empty string"):
            validate_command_string("")

        with pytest.raises(ProcessPolicyError, match="null bytes"):
            validate_command_string("echo a\x00b")

        with pytest.raises(ProcessPolicyError, match="exceeds maximum allowed length"):
            validate_command_string("x" * (MAX_COMMAND_LENGTH_BYTES + 1))

    def test_process_fanout_policy_timeout_ceiling_rejection(self) -> None:
        policy = SandboxExecutionPolicy()
        with pytest.raises(ResourceBudgetError, match="exceeds Basebreak ceiling"):
            policy.validate_execution_request(
                command="pytest",
                image="tag:astral/uv:python3.11-alpine",
                execution_mode=SandboxExecutionMode.DISPOSABLE,
                network_mode=SandboxNetworkMode.DISABLED,
                timeout_seconds=MAX_SANDBOX_TIMEOUT_SECONDS + 1,
            )

    def test_pid_process_limit_capability_is_explicitly_unproven(self) -> None:
        rec = get_capability_record(SandboxCapability.PID_PROCESS_LIMIT)
        assert rec.status == CapabilityStatus.UNPROVEN
        assert "unproven" in rec.notes.lower()
        assert is_capability_proven(SandboxCapability.PID_PROCESS_LIMIT) is False


class TestP0403Criterion4UnknownCapabilitiesExplicit:
    """Criterion 4: Unknown capabilities explicitly marked unknown/unavailable.

    Never guess platform capabilities without runtime proof.
    """

    def test_unknown_capabilities_are_not_guessed(self) -> None:
        unproven_caps = [
            SandboxCapability.INBOUND_NETWORK_ISOLATION,
            SandboxCapability.CPU_HARD_QUOTA,
            SandboxCapability.MEMORY_HARD_KILL,
            SandboxCapability.PID_PROCESS_LIMIT,
            SandboxCapability.SYSCALL_FILTERING,
            SandboxCapability.FILESYSTEM_MOUNT_RESTRICTIONS,
        ]
        for cap in unproven_caps:
            rec = get_capability_record(cap)
            assert rec.status == CapabilityStatus.UNPROVEN, f"{cap} must be UNPROVEN"
            assert is_capability_proven(cap) is False

    def test_unsupported_capabilities_are_not_claimed(self) -> None:
        unsupported_caps = [
            SandboxCapability.ARBITRARY_EGRESS_FILTERING,
            SandboxCapability.PROVIDER_SECRET_PROTECTION,
            SandboxCapability.SEALED_VERIFIER_ISOLATION,
        ]
        for cap in unsupported_caps:
            rec = get_capability_record(cap)
            assert rec.status == CapabilityStatus.UNSUPPORTED, f"{cap} must be UNSUPPORTED"
            assert is_capability_proven(cap) is False


class TestP0403Criterion5IntegrationWithSecretsAndProtectedSurfaces:
    """Criterion 5: Policy integrates P-04.02 secrets and P-04.04 protected surfaces."""

    def test_sensitive_env_keys_fail_closed(self) -> None:
        policy = SandboxExecutionPolicy()
        with pytest.raises(SecretPersistenceError, match="FORBIDDEN_SENSITIVE_KEY"):
            policy.validate_execution_request(
                command="pytest",
                image="tag:astral/uv:python3.11-alpine",
                execution_mode=SandboxExecutionMode.DISPOSABLE,
                network_mode=SandboxNetworkMode.DISABLED,
                env={"API_KEY": "sk-123456789"},
            )

    def test_command_embedded_secrets_fail_closed(self) -> None:
        policy = SandboxExecutionPolicy()
        with pytest.raises(ProcessPolicyError, match="contains forbidden secret-shaped value"):
            policy.validate_execution_request(
                command="echo 'Bearer sk_live_test_canary_secret_1234567890'",
                image="tag:astral/uv:python3.11-alpine",
                execution_mode=SandboxExecutionMode.DISPOSABLE,
                network_mode=SandboxNetworkMode.DISABLED,
            )

    def test_protected_surface_diff_mutation_fails_closed(self) -> None:
        policy = SandboxExecutionPolicy()
        malicious_diff = """--- a/docs/SECURITY_BOUNDARY.md
+++ b/docs/SECURITY_BOUNDARY.md
@@ -1,3 +1,3 @@
-# Security Boundary
+# Tampered Boundary
"""
        with pytest.raises(ProtectedSurfaceViolation):
            policy.validate_execution_request(
                command="pytest",
                image="tag:astral/uv:python3.11-alpine",
                execution_mode=SandboxExecutionMode.DISPOSABLE,
                network_mode=SandboxNetworkMode.DISABLED,
                diff_content=malicious_diff,
            )

    def test_two_world_isolation_enforces_clean_workspace(self) -> None:
        # Same execution ID must fail
        with pytest.raises(
            WorkspaceIsolationError, match="cannot share the same execution identity"
        ):
            validate_two_world_isolation(
                base_execution_id="op-1",
                candidate_execution_id="op-1",
                base_image="tag:astral/uv:python3.11-alpine",
                candidate_image="tag:astral/uv:python3.11-alpine",
                base_mode=SandboxExecutionMode.DISPOSABLE,
                candidate_mode=SandboxExecutionMode.DISPOSABLE,
            )

        # Checkpoint mode for verification run must fail
        with pytest.raises(WorkspaceIsolationError, match="BASE execution must be DISPOSABLE"):
            validate_two_world_isolation(
                base_execution_id="op-1",
                candidate_execution_id="op-2",
                base_image="tag:astral/uv:python3.11-alpine",
                candidate_image="tag:astral/uv:python3.11-alpine",
                base_mode=SandboxExecutionMode.CHECKPOINT,
                candidate_mode=SandboxExecutionMode.DISPOSABLE,
            )


class TestP0403Criterion6NoCapabilityOverclaim:
    """Criterion 6: No provider capability overclaim."""

    def test_proven_capabilities_strictly_match_p01_evidence(self) -> None:
        proven_set = {
            cap
            for cap, rec in PLATFORM_CAPABILITIES.items()
            if rec.status == CapabilityStatus.PROVEN_SUPPORTED
        }
        expected_proven = {
            SandboxCapability.DISPOSABLE_EXECUTION,
            SandboxCapability.CHECKPOINT_SNAPSHOT,
            SandboxCapability.FORK_FROM_IMAGE,
            SandboxCapability.TEARDOWN_OBSERVABILITY,
            SandboxCapability.OUTBOUND_HTTPS,
        }
        assert proven_set == expected_proven


class TestP0403Criterion7NoP05AdapterImplementation:
    """Criterion 7: Pure security policy, zero P-05 adapter implementation."""

    def test_security_module_has_no_provider_network_or_sdk_imports(self) -> None:
        source = inspect.getsource(sp)
        forbidden_tokens = [
            "contree",
            "httpx",
            "aiohttp",
            "urllib.request",
            "requests",
            "OpenAI",
            "openai",
            "socket",
        ]
        for token in forbidden_tokens:
            assert token not in source, (
                f"Forbidden provider/network token '{token}' in sandbox_policy.py"
            )
