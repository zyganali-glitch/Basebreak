"""Ordinary unit tests for ResetVault.

These baseline unit tests pass genuinely on the unpatched base codebase.
They verify token creation, first valid redemption, invalid tokens, and expired tokens,
but they fail to test token reuse/replay, leaving the single-use vulnerability undetected.
"""

from __future__ import annotations

import sys
from pathlib import Path

# Add src to sys.path so tests can import reset_vault
_SRC = str(Path(__file__).resolve().parent.parent / "src")
if _SRC not in sys.path:
    sys.path.insert(0, _SRC)

from reset_vault.vault import ResetVault  # noqa: E402


def test_issue_reset_token() -> None:
    vault = ResetVault()
    token = vault.create_reset_token("alice")
    assert isinstance(token, str)
    assert len(token) == 32


def test_valid_token_redemption_updates_password() -> None:
    vault = ResetVault()
    vault.set_user_password("alice", "initial_pass")
    token = vault.create_reset_token("alice")

    result = vault.redeem_reset_token(token, "new_secure_pass")
    assert result is True
    assert vault.get_user_password("alice") == "new_secure_pass"


def test_unknown_token_rejected() -> None:
    vault = ResetVault()
    assert vault.redeem_reset_token("nonexistent_token_123", "password") is False


def test_expired_token_rejected() -> None:
    vault = ResetVault()
    token = vault.create_reset_token("bob", ttl_seconds=-10.0)
    assert vault.redeem_reset_token(token, "password") is False
