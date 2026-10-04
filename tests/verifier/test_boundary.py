"""Tests for P-08.04: Mechanical boundary enforcement between Builder and Verifier.

Verifies:
1. Rejection of verifier / witness paths in Builder context.
2. Mechanical filtering of repository file enumeration for Builder.
3. Builder execution environment variable protection.
4. Sanitization of error output / tracebacks (no witness code leakage).
5. Protection of verifier surfaces against candidate patch mutation.
6. Detection and rejection of witness code leakage in public results.
7. Provider purity (zero adapter imports in boundary module).
"""

from __future__ import annotations

import ast
import inspect

import pytest

from basebreak.security.protected_surfaces import ProtectedSurfaceViolation
from basebreak.verifier.boundary import (
    REDACTED_VERIFIER_PATH,
    REDACTED_WITNESS_DIGEST,
    REDACTED_WITNESS_ID,
    REDACTED_WITNESS_TEXT,
    VerifierAssetExclusionError,
    VerifierBoundaryEnforcer,
    VerifierEnvironmentLeakageError,
    WitnessLeakageInResultError,
)
from basebreak.verifier.witness_store import (
    TrustedWitnessVault,
    WitnessArtifact,
)


@pytest.fixture
def sample_vault() -> TrustedWitnessVault:
    vault = TrustedWitnessVault()
    art = WitnessArtifact.from_text(
        path="tests/verifier/test_hidden_edge_case.py",
        content="def test_hidden_edge_case():\n    assert check_token_is_consumed()\n",
    )
    vault.seal_witness(
        witness_id="wit-secret-001",
        requirement_id="REQ-36E68AC0",
        frozen_contract_digest="a" * 64,
        source_commit_id="a" * 40,
        artifacts=[art],
    )
    return vault


def test_builder_context_path_exclusion(sample_vault: TrustedWitnessVault) -> None:
    """Builder cannot admit verifier paths or sealed witness paths."""
    enforcer = VerifierBoundaryEnforcer()

    # Generic verifier prefix
    with pytest.raises(VerifierAssetExclusionError):
        enforcer.validate_builder_context_path("tests/verifier/test_something.py")

    with pytest.raises(VerifierAssetExclusionError):
        enforcer.validate_builder_context_path("src/basebreak/verifier/sandbox.py")

    # Vault sealed witness path
    with pytest.raises(VerifierAssetExclusionError):
        enforcer.validate_builder_context_path(
            "tests/verifier/test_hidden_edge_case.py", vault=sample_vault
        )

    # Ordinary repository path passes
    enforcer.validate_builder_context_path("src/pool/core.py")
    enforcer.validate_builder_context_path("tests/test_pool.py")


def test_filter_repository_paths_for_builder(sample_vault: TrustedWitnessVault) -> None:
    """Repository enumeration mechanically strips verifier and witness paths."""
    enforcer = VerifierBoundaryEnforcer()
    raw_paths = [
        "src/pool/core.py",
        "tests/verifier/test_hidden_edge_case.py",
        "tests/test_pool.py",
        "src/basebreak/verifier/context.py",
        "README.md",
    ]

    filtered = enforcer.filter_repository_paths_for_builder(raw_paths, vault=sample_vault)

    assert filtered == ["README.md", "src/pool/core.py", "tests/test_pool.py"]
    assert "tests/verifier/test_hidden_edge_case.py" not in filtered
    assert "src/basebreak/verifier/context.py" not in filtered


def test_builder_env_validation() -> None:
    """Builder environment leaking verifier secrets or paths fails closed."""
    enforcer = VerifierBoundaryEnforcer()

    with pytest.raises(VerifierEnvironmentLeakageError, match="leaks verifier"):
        enforcer.validate_builder_env({"VERIFIER_TOKEN": "secret-token-123"})

    with pytest.raises(VerifierEnvironmentLeakageError, match="references verifier"):
        enforcer.validate_builder_env({"STORAGE_PATH": "/verifier_workspace/data"})

    # Clean environment passes
    enforcer.validate_builder_env({"APP_ENV": "development", "PORT": "8080"})


def test_error_output_sanitization(sample_vault: TrustedWitnessVault) -> None:
    """Verifier traceback containing witness code and digests is sanitized."""
    enforcer = VerifierBoundaryEnforcer()
    record = sample_vault.get_witness("wit-secret-001")

    raw_traceback = (
        f"AssertionError in {record.artifacts[0].path} line 2:\n"
        f"    assert check_token_is_consumed()\n"
        f"Witness ID: {record.witness_id}, Seal: {record.seal_digest}\n"
        f"Working dir: /verifier_workspace/repo\n"
    )

    sanitized = enforcer.sanitize_verifier_error_output(raw_traceback, vault=sample_vault)

    assert "assert check_token_is_consumed()" not in sanitized
    assert REDACTED_WITNESS_TEXT in sanitized
    assert record.witness_id not in sanitized
    assert REDACTED_WITNESS_ID in sanitized
    assert record.seal_digest not in sanitized
    assert REDACTED_WITNESS_DIGEST in sanitized
    assert "/verifier_workspace/repo" not in sanitized
    assert REDACTED_VERIFIER_PATH in sanitized


def test_candidate_patch_isolation_mutation_rejected(sample_vault: TrustedWitnessVault) -> None:
    """Candidate diff attempting to modify verifier files triggers ProtectedSurfaceViolation."""
    enforcer = VerifierBoundaryEnforcer()

    target = "tests/verifier/test_hidden_edge_case.py"
    patch_attack = (
        f"diff --git a/{target} b/{target}\n"
        f"--- a/{target}\n"
        f"+++ b/{target}\n"
        "@@ -1,2 +1,2 @@\n"
        "-def test_hidden_edge_case():\n"
        "+def test_hidden_edge_case(): return True\n"
    )

    with pytest.raises(ProtectedSurfaceViolation, match="touches protected surface"):
        enforcer.validate_candidate_patch_isolation(patch_attack, vault=sample_vault)


def test_public_result_leakage_detection(sample_vault: TrustedWitnessVault) -> None:
    """Result dictionaries containing unredacted witness code are caught."""
    enforcer = VerifierBoundaryEnforcer()

    leaking_result = {
        "status": "COMPLETED",
        "details": {
            "snippet": "assert check_token_is_consumed()",
        },
    }

    with pytest.raises(WitnessLeakageInResultError):
        enforcer.validate_public_result_isolation(leaking_result, vault=sample_vault)

    # Clean sanitized result passes
    clean_result = {
        "status": "COMPLETED",
        "details": {
            "snippet": "[REDACTED_WITNESS_CONTENT]",
        },
    }
    enforcer.validate_public_result_isolation(clean_result, vault=sample_vault)


def test_provider_purity_boundary() -> None:
    """Boundary module has zero imports from basebreak.adapters."""
    import basebreak.verifier.boundary as boundary

    tree = ast.parse(inspect.getsource(boundary))
    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            for name in node.names:
                assert not name.name.startswith("basebreak.adapters"), (
                    f"Forbidden adapter import: {name.name}"
                )
        elif isinstance(node, ast.ImportFrom):
            if node.module:
                assert not node.module.startswith("basebreak.adapters"), (
                    f"Forbidden adapter import from: {node.module}"
                )
