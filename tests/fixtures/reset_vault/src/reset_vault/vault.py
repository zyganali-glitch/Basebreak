"""Core token and credential management for ResetVault.

This baseline file contains an intentional subtle defect:
Reset tokens are validated and used to update passwords, but are NOT invalidated
upon redemption. This enables replay attacks where a single token can be reused.
Existing ordinary test suite only tests single valid redemption, leaving this defect hidden.
"""

from __future__ import annotations

import secrets
import time
from typing import Any


class TokenError(Exception):
    """Base exception for reset token failures."""


class ResetVault:
    """Manages password reset tokens and user credentials."""

    def __init__(self) -> None:
        self._tokens: dict[str, dict[str, Any]] = {}
        self._passwords: dict[str, str] = {}

    def set_user_password(self, user_id: str, password: str) -> None:
        """Initialize or update a user password."""
        self._passwords[user_id] = password

    def get_user_password(self, user_id: str) -> str | None:
        """Retrieve stored password for user."""
        return self._passwords.get(user_id)

    def create_reset_token(self, user_id: str, ttl_seconds: float = 3600.0) -> str:
        """Issue a new password reset token."""
        token = secrets.token_hex(16)
        self._tokens[token] = {
            "user_id": user_id,
            "expires_at": time.time() + ttl_seconds,
            "created_at": time.time(),
        }
        return token

    def redeem_reset_token(self, token: str, new_password: str) -> bool:
        """Redeem reset token and update password.

        Requirement REQ-RESET-001:
        Reset tokens MUST be strictly single-use. Once redeemed,
        subsequent redemption attempts MUST fail.

        DEFECT in baseline: Token is not invalidated upon successful redemption!
        """
        if token not in self._tokens:
            return False

        record = self._tokens[token]
        if time.time() > record["expires_at"]:
            return False

        user_id = record["user_id"]
        self._passwords[user_id] = new_password

        # Intended fix:
        # del self._tokens[token]
        # BUT MISSING in baseline!

        return True
