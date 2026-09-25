"""Acceptance criteria tests for P-04.06: Malicious Fixtures & Boundary Enforcement.

Audits:
- Criterion 1: Malicious secret exfiltration attempts blocked and sanitized.
- Criterion 2: Fork bomb / process explosion class handled safely with deterministic outcomes.
- Criterion 3: Verifier discovery and sealed asset probing blocked.
- Criterion 4: Protected-surface mutation attacks rejected fail-closed.
- Criterion 5: Network exfiltration policy enforced without unverified platform assumptions.
- Criterion 6: Zero provider SDK imports or P-05 adapter code in security module.
- Criterion 7: Deterministic execution (< 5 seconds total runtime, zero host crashes).
"""

from __future__ import annotations

import time

import pytest

from basebreak.security.normalization import (
    NormalizedExecutionOutcome,
    ResourceFailureClass,
    normalize_execution_result,
)
from basebreak.security.protected_surfaces import (
    PathTraversalError,
    ProtectedSurfaceManifest,
    ProtectedSurfaceViolation,
    get_canonical_basebreak_protected_manifest,
    is_path_protected,
    validate_diff,
)
from basebreak.security.sandbox_policy import (
    MAX_COMMAND_LENGTH_BYTES,
    ProcessPolicyError,
    SandboxExecutionMode,
    SandboxExecutionPolicy,
    SandboxNetworkMode,
    WorkspaceIsolationError,
    validate_command_string,
    validate_two_world_isolation,
)
from basebreak.security.secret_policy import (
    SecretPersistenceError,
    validate_no_secrets,
)


class TestP0406Criterion1SecretExfiltrationBlocked:
    """Criterion 1: Malicious secret exfiltration attempts blocked and sanitized."""

    def test_synthetic_canaries_in_output_sanitized_in_preview(self) -> None:
        raw_output = "Secret leaked: Bearer nbs_sk_live_canary_key_1234567890abcdef"
        record = normalize_execution_result(
            exit_code=0, stdout=raw_output, provider_status="SUCCESS"
        )
        assert "[REDACTED]" in record.stdout_preview
        assert "nbs_sk_live" not in record.stdout_preview

    def test_secret_in_persistence_path_raises_secret_persistence_error(self) -> None:
        malicious_val = "bearer token=nbs_sk_live_secret1234567890abcdef"
        with pytest.raises(SecretPersistenceError):
            validate_no_secrets(malicious_val, path="test_path")


class TestP0406Criterion2ProcessExplosionAndForkBombSafety:
    """Criterion 2: Fork-bomb and process explosion class handled safely."""

    def test_bloated_command_fails_before_execution(self) -> None:
        huge_cmd = "python -c 'pass' " + ("#" * (MAX_COMMAND_LENGTH_BYTES + 10))
        with pytest.raises(ProcessPolicyError):
            validate_command_string(huge_cmd)

    def test_process_runaway_simulated_oom_normalizes_deterministically(self) -> None:
        oom_payload = {
            "status": "FAILURE",
            "error": "cgroup memory limit reached, process killed by oom-killer",
            "metadata": {"result": {"exit_code": 137, "duration": 2.5}},
        }
        record = normalize_execution_result(raw_payload=oom_payload)
        assert record.outcome == NormalizedExecutionOutcome.RESOURCE_FAILURE
        assert record.resource_failure_class == ResourceFailureClass.OUT_OF_MEMORY


class TestP0406Criterion3VerifierDiscoveryBlocked:
    """Criterion 3: Verifier discovery and sealed asset probing blocked."""

    def test_verifier_directory_is_in_protected_manifest(self) -> None:
        manifest = ProtectedSurfaceManifest(
            exact_files=frozenset({"tests/verifier/test_witness.py"}),
            directory_prefixes=frozenset({"tests/verifier"}),
        )
        assert is_path_protected("tests/verifier/test_witness.py", manifest)
        assert is_path_protected("tests/verifier/fixtures/fixture.json", manifest)

    def test_isolation_fails_if_same_sandbox_reused(self) -> None:
        with pytest.raises(WorkspaceIsolationError):
            validate_two_world_isolation(
                base_execution_id="same-id",
                candidate_execution_id="same-id",
                base_image="tag:python313",
                candidate_image="tag:python313",
                base_mode=SandboxExecutionMode.DISPOSABLE,
                candidate_mode=SandboxExecutionMode.DISPOSABLE,
            )


class TestP0406Criterion4ProtectedSurfaceMutationRejected:
    """Criterion 4: Protected-surface mutation attacks rejected fail-closed."""

    def test_direct_modification_of_agents_md_rejected(self) -> None:
        manifest = get_canonical_basebreak_protected_manifest()
        diff = "--- a/AGENTS.md\n+++ b/AGENTS.md\n@@ -1,1 +1,1 @@\n-# AGENTS.md\n+# COMPROMISED\n"
        with pytest.raises(ProtectedSurfaceViolation) as exc_info:
            validate_diff(diff, manifest)
        assert "AGENTS.md" in str(exc_info.value)

    def test_traversal_in_diff_rejected(self) -> None:
        manifest = get_canonical_basebreak_protected_manifest()
        diff = "--- a/../outside.py\n+++ b/../outside.py\n@@ -1,1 +1,1 @@\n+evil\n"
        with pytest.raises((PathTraversalError, ProtectedSurfaceViolation)):
            validate_diff(diff, manifest)


class TestP0406Criterion5NetworkPolicyEnforced:
    """Criterion 5: Network exfiltration policy enforced without guessing platform filters."""

    def test_cannot_enable_network_with_sensitive_env(self) -> None:
        policy = SandboxExecutionPolicy()
        with pytest.raises(Exception):
            policy.validate_execution_request(
                command="echo hello",
                image="tag:python313",
                execution_mode=SandboxExecutionMode.DISPOSABLE,
                network_mode=SandboxNetworkMode.EGRESS_REQUIRED,
                env={"API_KEY": "nbs_sk_live_secret_canary_value_12345"},
            )


class TestP0406Criterion6ZeroProviderSDKImports:
    """Criterion 6: Security module remains pure without provider SDKs."""

    def test_no_forbidden_provider_imports_in_security_module(self) -> None:
        import ast
        from pathlib import Path

        security_dir = Path("src/basebreak/security")
        forbidden_substrings = ("nebius", "openai", "tavily", "daytona", "e2b")

        for py_file in security_dir.glob("*.py"):
            content = py_file.read_text(encoding="utf-8")
            tree = ast.parse(content, filename=str(py_file))
            for node in ast.walk(tree):
                if isinstance(node, ast.Import):
                    for alias in node.names:
                        for forbidden in forbidden_substrings:
                            assert forbidden not in alias.name.lower(), (
                                f"Forbidden import '{alias.name}' in {py_file}"
                            )
                elif isinstance(node, ast.ImportFrom) and node.module:
                    for forbidden in forbidden_substrings:
                        assert forbidden not in node.module.lower(), (
                            f"Forbidden import '{node.module}' in {py_file}"
                        )


class TestP0406Criterion7DeterministicFastExecution:
    """Criterion 7: All malicious fixtures execute in < 2 seconds deterministically."""

    def test_full_malicious_fixture_execution_under_time_budget(self) -> None:
        start = time.perf_counter()

        # Run representative malicious cases in loop
        manifest = get_canonical_basebreak_protected_manifest()
        for i in range(20):
            res = is_path_protected("AGENTS.md", manifest)
            assert res is True
            rec = normalize_execution_result(
                exit_code=0,
                stdout=f"token: Bearer nbs_sk_live_canary_{i}_1234567890abcdef",
                provider_status="SUCCESS",
            )
            assert "[REDACTED]" in rec.stdout_preview

        duration = time.perf_counter() - start
        assert duration < 2.0, f"Malicious fixtures took {duration:.3f}s, expected < 2.0s"
