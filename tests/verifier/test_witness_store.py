"""Tests for P-08.03: Sealed witness storage and integrity contracts.

Verifies:
1. Deterministic witness identity and cryptographic seal digests.
2. Immutable fail-closed integrity validation.
3. Rejection of path traversal and root escapes in witness artifacts.
4. Rejection of protected surface collisions (e.g. AGENTS.md, src/basebreak/...).
5. Rejection of secrets / credentials in witness content.
6. Rejection of caller-created typed records claiming unverified authority.
7. Rejection of cross-vault forgery.
8. Rejection of artifact content or seal digest tampering.
9. Provider purity (zero adapter imports in witness store).
"""

from __future__ import annotations

import ast
import inspect

import pytest

from basebreak.verifier.witness_store import (
    SealedWitnessRecord,
    TrustedWitnessVault,
    UntrustedWitnessAuthorityError,
    WitnessArtifact,
    WitnessPathSecurityError,
    WitnessProtectedSurfaceCollisionError,
    WitnessSecretError,
    WitnessTamperingError,
)


def test_seal_witness_success() -> None:
    """Witness is sealed with deterministic identity and validated authentically."""
    vault = TrustedWitnessVault()
    artifact = WitnessArtifact.from_text(
        path="tests/verifier/test_idle_close.py",
        content="def test_idle_close():\n    assert True\n",
    )

    record = vault.seal_witness(
        witness_id="wit-req-001",
        requirement_id="REQ-36E68AC0",
        frozen_contract_digest="0" * 64,
        source_commit_id="0" * 40,
        artifacts=[artifact],
    )

    assert isinstance(record, SealedWitnessRecord)
    assert record.witness_id == "wit-req-001"
    assert record.requirement_id == "REQ-36E68AC0"
    assert len(record.seal_digest) == 64
    assert len(record.vault_signature) == 64
    assert record.is_sealed

    # Integrity verification passes
    assert vault.verify_witness_integrity(record) is True
    assert vault.get_witness("wit-req-001") == record
    assert "wit-req-001" in vault.list_sealed_witness_ids()


def test_reject_witness_path_traversal() -> None:
    """Artifact with path traversal fails closed with WitnessPathSecurityError."""
    with pytest.raises(WitnessPathSecurityError):
        WitnessArtifact.from_text(
            path="../escape.py",
            content="def test(): pass",
        )

    with pytest.raises(WitnessPathSecurityError):
        WitnessArtifact.from_text(
            path="/etc/passwd",
            content="def test(): pass",
        )

    with pytest.raises(WitnessPathSecurityError):
        WitnessArtifact.from_text(
            path="tests/../../escape.py",
            content="def test(): pass",
        )


def test_reject_witness_protected_surface_collision() -> None:
    """Artifact targeting canonical protected surfaces fails closed."""
    with pytest.raises(WitnessProtectedSurfaceCollisionError, match="collides with protected"):
        WitnessArtifact.from_text(
            path="AGENTS.md",
            content="# Overwritten",
        )

    with pytest.raises(WitnessProtectedSurfaceCollisionError, match="collides with protected"):
        WitnessArtifact.from_text(
            path="src/basebreak/domain/source.py",
            content="# Overwritten",
        )

    with pytest.raises(WitnessProtectedSurfaceCollisionError, match="collides with protected"):
        WitnessArtifact.from_text(
            path="plans/BASEBREAK_MASTER_EXECUTION_PLAN.md",
            content="# Overwritten",
        )


def test_reject_secret_in_witness_content() -> None:
    """Witness content with credentials fails closed with WitnessSecretError."""
    with pytest.raises(WitnessSecretError, match="contains credentials"):
        WitnessArtifact.from_text(
            path="tests/verifier/test_secret.py",
            content="API_KEY = 'AKIA1234567890123456'\n",
        )

    with pytest.raises(WitnessSecretError, match="contains credentials"):
        WitnessArtifact.from_text(
            path="tests/verifier/test_secret2.py",
            content=(
                "-----BEGIN RSA PRIVATE KEY-----\n"
                "MIIEowIBAAKCAQEA0...\n"
                "-----END RSA PRIVATE KEY-----"
            ),
        )


def test_reject_caller_created_unverified_record() -> None:
    """Caller instantiating SealedWitnessRecord with is_sealed=True possesses zero authority."""
    vault = TrustedWitnessVault()
    artifact = WitnessArtifact.from_text(
        path="tests/verifier/test_fake.py",
        content="def test_fake(): pass\n",
    )

    from basebreak.verifier.witness_store import (
        build_canonical_witness_identity_payload,
        compute_seal_digest,
    )

    # Compute genuine seal digest so SealedWitnessRecord passes internal validation,
    # but has a forged/foreign vault signature and was never registered in vault.
    payload = build_canonical_witness_identity_payload(
        witness_id="wit-forged",
        requirement_id="REQ-FORGED",
        frozen_contract_digest="f" * 64,
        source_commit_id="f" * 40,
        artifacts=(artifact,),
        created_at_utc="2026-10-04T00:00:00Z",
    )
    seal_digest = compute_seal_digest(payload)

    forged_record = SealedWitnessRecord(
        witness_id="wit-forged",
        requirement_id="REQ-FORGED",
        frozen_contract_digest="f" * 64,
        source_commit_id="f" * 40,
        artifacts=(artifact,),
        seal_digest=seal_digest,
        created_at_utc="2026-10-04T00:00:00Z",
        vault_signature="f" * 64,
        is_sealed=True,
    )

    with pytest.raises(UntrustedWitnessAuthorityError, match="not sealed by this trusted vault"):
        vault.verify_witness_integrity(forged_record)


def test_reject_cross_vault_authority() -> None:
    """Record sealed by Vault A is rejected when verified against Vault B."""
    vault_a = TrustedWitnessVault()
    vault_b = TrustedWitnessVault()

    artifact = WitnessArtifact.from_text(
        path="tests/verifier/test_cross.py",
        content="def test_cross(): pass\n",
    )
    record_a = vault_a.seal_witness(
        witness_id="wit-cross",
        requirement_id="REQ-001",
        frozen_contract_digest="0" * 64,
        source_commit_id="0" * 40,
        artifacts=[artifact],
    )

    with pytest.raises(UntrustedWitnessAuthorityError):
        vault_b.verify_witness_integrity(record_a)


def test_reject_artifact_content_tampering() -> None:
    """Mutating artifact content after sealing fails closed with WitnessTamperingError."""
    vault = TrustedWitnessVault()
    artifact = WitnessArtifact.from_text(
        path="tests/verifier/test_tamper.py",
        content="def test_original(): pass\n",
    )
    record = vault.seal_witness(
        witness_id="wit-tamper",
        requirement_id="REQ-001",
        frozen_contract_digest="0" * 64,
        source_commit_id="0" * 40,
        artifacts=[artifact],
    )

    # Mutate the artifact in place using object.__setattr__
    tampered_artifact = WitnessArtifact.from_text(
        path="tests/verifier/test_tamper.py",
        content="def test_tampered(): pass\n",
    )
    # Tampering artifact inside record
    object.__setattr__(record, "artifacts", (tampered_artifact,))

    with pytest.raises(WitnessTamperingError):
        vault.verify_witness_integrity(record)


def test_provider_purity_witness_store() -> None:
    """Witness store module has zero imports from basebreak.adapters."""
    import basebreak.verifier.witness_store as witness_store

    tree = ast.parse(inspect.getsource(witness_store))
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
