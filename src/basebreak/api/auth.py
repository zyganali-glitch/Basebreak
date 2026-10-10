"""Authorization enforcement and secret-safe serialization for API orchestrator.

P-21.04: Enforces Bearer token authorization and secret-safe JSON serialization.
"""

from __future__ import annotations

import hmac
import json
from typing import Any

from basebreak.security.secret_policy import redact_text


class ApiAuthError(Exception):
    """Raised when request authorization fails."""


class ApiAuthManager:
    """Manages Bearer token validation and secret-safe output serialization."""

    def __init__(self, bearer_token: str | None = None) -> None:
        self.bearer_token = bearer_token.strip() if bearer_token and bearer_token.strip() else None

    @property
    def is_auth_required(self) -> bool:
        """Return True if a Bearer token is configured and required."""
        return self.bearer_token is not None

    def validate_auth_header(self, auth_header: str | None) -> bool:
        """Validate an HTTP Authorization header.

        Returns:
            True if auth is valid (or if no auth is configured), False otherwise.
        """
        if not self.is_auth_required:
            return True

        if not auth_header or not auth_header.strip():
            return False

        parts = auth_header.strip().split()
        if len(parts) != 2 or parts[0].lower() != "bearer":
            return False

        token = parts[1]
        assert self.bearer_token is not None
        return hmac.compare_digest(token, self.bearer_token)

    @staticmethod
    def serialize_secret_safe(data: Any, indent: int | None = None) -> str:
        """Serialize data to JSON string guaranteed free of raw recognized secrets."""
        raw_json = json.dumps(data, indent=indent, sort_keys=True)
        redacted_json, _ = redact_text(raw_json)
        return redacted_json
