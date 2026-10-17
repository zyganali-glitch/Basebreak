"""Focused negative tests for the production verifier trust-anchor pin contract.

These tests guard the canonical public signing pin against inconsistent rotation
and verify that fail-closed behavior holds for incompatible private keys, tampered
proofs, and missing signing authority.

No private key material is present in this module: all keypairs used here are
ephemeral, generated in-process only for boundary testing.
"""

from __future__ import annotations

import hashlib
import re
from pathlib import Path

import pytest

from basebreak.deployment.bridge_main import collect_readiness
from basebreak.deployment.live_bridge import (
    _signer_holds_authority_private_key,
    _signer_matches_canonical_authority,
    create_trusted_verifier_bridge_from_env,
)
from basebreak.verifier.trust_bridge import (
    PINNED_VERIFIER_EXPONENT,
    PINNED_VERIFIER_MODULUS,
    PINNED_VERIFIER_MODULUS_HEX,
    VerifierAuthorityRoot,
    _PrivilegedVerifierSigner,
)

_REPO_ROOT = Path(__file__).resolve().parents[2]
_JS_PIN_SOURCE = _REPO_ROOT / "cloudflare" / "src" / "provider_dispatcher.js"


def _extract_js_modulus_hex() -> str:
    source = _JS_PIN_SOURCE.read_text(encoding="utf-8")
    match = re.search(r"const PINNED_VERIFIER_MODULUS_HEX\s*=\s*(.*?);", source, re.DOTALL)
    assert match is not None, "JS PINNED_VERIFIER_MODULUS_HEX definition not found"
    chunks = re.findall(r'"([0-9a-fA-F]+)"', match.group(1))
    return "".join(chunks).lower()


# --- Pin consistency & shape -------------------------------------------------------


def test_python_and_js_modulus_pins_are_identical() -> None:
    """The Worker (JS) and verifier (Python) MUST pin the same modulus."""
    assert _extract_js_modulus_hex() == PINNED_VERIFIER_MODULUS_HEX


def test_pinned_modulus_is_2048_bit_with_canonical_exponent() -> None:
    assert len(PINNED_VERIFIER_MODULUS_HEX) == 512
    assert PINNED_VERIFIER_MODULUS_HEX == PINNED_VERIFIER_MODULUS_HEX.lower()
    assert PINNED_VERIFIER_MODULUS.bit_length() == 2048
    assert PINNED_VERIFIER_EXPONENT == 65537
    assert int(PINNED_VERIFIER_MODULUS_HEX, 16) == PINNED_VERIFIER_MODULUS


# --- Incompatible keys are rejected ------------------------------------------------


def test_incompatible_ephemeral_key_is_rejected_by_pinned_authority() -> None:
    signer, _root = _PrivilegedVerifierSigner.create_ephemeral_pair()
    assert _signer_matches_canonical_authority(signer) is False
    # Control: the same signer is authoritative for its own ephemeral parameters.
    assert (
        _signer_holds_authority_private_key(
            signer, modulus=signer.modulus, exponent=signer.exponent
        )
        is True
    )


def test_correct_modulus_but_wrong_private_exponent_is_rejected() -> None:
    """Correct public modulus with an incompatible private exponent must fail closed."""
    wrong = _PrivilegedVerifierSigner(private_key_d=3)
    assert wrong.modulus == PINNED_VERIFIER_MODULUS
    assert _signer_matches_canonical_authority(wrong) is False


def test_incompatible_env_signing_key_never_becomes_authoritative(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setenv("BASEBREAK_VERIFIER_SIGNING_KEY", "3")
    signer = _PrivilegedVerifierSigner.from_environment()
    assert signer is not None
    assert _signer_matches_canonical_authority(signer) is False


# --- Tampered proofs are rejected --------------------------------------------------


def test_tampered_signature_fails_recovery_equation() -> None:
    """RSA recovery used by production verification rejects a tampered signature."""
    signer, _root = _PrivilegedVerifierSigner.create_ephemeral_pair()
    digest = "basebreak:trust-anchor-rotation:challenge"
    signature_hex = signer.sign_attestation_digest(digest)
    expected = int.from_bytes(hashlib.sha256(digest.encode("utf-8")).digest(), "big")
    modulus = signer.modulus

    assert pow(int(signature_hex, 16), PINNED_VERIFIER_EXPONENT, modulus) == expected

    last = signature_hex[-1]
    tampered = signature_hex[:-1] + ("0" if last != "0" else "1")
    assert pow(int(tampered, 16), PINNED_VERIFIER_EXPONENT, modulus) != expected


# --- Missing signing authority fails closed ----------------------------------------


def test_missing_signing_authority_fails_closed(monkeypatch: pytest.MonkeyPatch) -> None:
    for name in (
        "BASEBREAK_VERIFIER_SIGNING_KEY",
        "NEBIUS_API_KEY",
        "NEBIUS_PROJECT_ID",
        "TRUSTED_VERIFIER_BRIDGE_SHARED_SECRET",
        "BASEBREAK_LIVE_EXECUTION_ENABLED",
        "TRUSTED_VERIFIER_BRIDGE_STATE_DIR",
    ):
        monkeypatch.delenv(name, raising=False)

    assert _PrivilegedVerifierSigner.from_environment() is None

    bridge = create_trusted_verifier_bridge_from_env()
    readiness = collect_readiness(bridge)
    assert readiness["signing_authority_present"] is False
    assert readiness["signing_authority_compatible"] is False
    assert readiness["live_execution_enabled"] is False
    assert readiness["ready_for_live"] is False


def test_pinned_authority_root_is_the_canonical_anchor() -> None:
    root = VerifierAuthorityRoot()
    assert root.modulus == PINNED_VERIFIER_MODULUS
    assert root.exponent == PINNED_VERIFIER_EXPONENT
    assert root.is_canonical_anchor is True
