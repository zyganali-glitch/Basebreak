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
    def is_auth_configured(self) -> bool:
        """Return True if a Bearer token is configured."""
        return self.bearer_token is not None

    def is_authenticated_operator(self, auth_header: str | None) -> bool:
        """Validate whether the request presents a valid operator Bearer token.

        Fails closed:
        - If no Bearer token is configured on the server, returns False (no one is operator).
        - If auth_header is missing, empty, or not in 'Bearer <token>' format, returns False.
        - If the token does not match via constant-time comparison, returns False.
        """
        if not self.is_auth_configured:
            return False  # Fail-closed: no operator exists when auth is not configured

        if not auth_header or not auth_header.strip():
            return False

        parts = auth_header.strip().split()
        if len(parts) != 2 or parts[0].lower() != "bearer":
            return False

        token = parts[1]
        assert self.bearer_token is not None
        return hmac.compare_digest(token, self.bearer_token)

    def validate_execution_auth(self, auth_header: str | None) -> bool:
        """Validate authorization for execution-capable operations (fail-closed)."""
        return self.is_authenticated_operator(auth_header)

    def validate_auth_header(self, auth_header: str | None, *, is_execution: bool = False) -> bool:
        """Validate an HTTP Authorization header.

        Execution operations strictly require an authenticated operator.
        For non-execution queries, returns True ONLY if valid operator token is presented.
        Anonymous read-only access is governed by publication state, not by pretending
        anonymous callers are authenticated operators.
        """
        return self.is_authenticated_operator(auth_header)

    @staticmethod
    def serialize_secret_safe(data: Any, indent: int | None = None) -> str:
        """Serialize data to JSON string guaranteed free of raw recognized secrets."""
        raw_json = json.dumps(data, indent=indent, sort_keys=True)
        redacted_json, _ = redact_text(raw_json)
        return redacted_json
