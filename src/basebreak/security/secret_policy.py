"""Deterministic secret redaction engine and persistence boundary rules.

Provides provider-neutral deterministic secret-shaped value detection, redaction,
and forbidden persistence enforcement. Distinguishes non-authoritative log/display
redaction from authoritative evidence fail-closed persistence boundaries.
"""

from __future__ import annotations

import re
from dataclasses import dataclass
from enum import Enum
from typing import Any

REDACTION_MARKER: str = "[REDACTED]"

# --- Secret Categories & Rules ---


class SecretCategory(str, Enum):
    """Recognized category of secret-bearing material."""

    AUTH_BEARER = "AUTH_BEARER"
    AUTH_BASIC = "AUTH_BASIC"
    KEY_VALUE_ASSIGNMENT = "KEY_VALUE_ASSIGNMENT"
    TOKEN_PREFIX = "TOKEN_PREFIX"
    PEM_PRIVATE_KEY = "PEM_PRIVATE_KEY"
    URL_CREDENTIALS = "URL_CREDENTIALS"
    SENSITIVE_KEY = "SENSITIVE_KEY"


@dataclass(frozen=True, slots=True)
class SecretFinding:
    """Safe metadata describing a detected secret without containing raw secret text.

    Guarantees non-leakage by retaining only rule ID, category, and character indices.
    """

    rule_id: str
    category: SecretCategory
    start: int
    end: int


class SecretPersistenceError(Exception):
    """Raised when secret-bearing authoritative material violates persistence policy.

    Guarantees non-leakage: raw secret text, bytes, or snippets are NEVER stored
    on this exception or included in its string or representation.
    """

    def __init__(
        self,
        rule_id: str,
        path: str,
        category: str = "SECRET_PERSISTENCE_FORBIDDEN",
    ) -> None:
        self.rule_id = rule_id
        self.path = path
        self.category = category
        super().__init__(
            f"Secret persistence forbidden [{category}]: rule '{rule_id}' violated at '{path}'"
        )

    def __repr__(self) -> str:
        return (
            f"SecretPersistenceError(rule_id={self.rule_id!r}, "
            f"path={self.path!r}, category={self.category!r})"
        )


# --- Sensitive Keys (Key-Aware Policy) ---

SENSITIVE_KEY_NAMES: frozenset[str] = frozenset(
    {
        "api_key",
        "apikey",
        "api_secret",
        "token",
        "secret",
        "password",
        "passwd",
        "credential",
        "credentials",
        "authorization",
        "auth",
        "private_key",
        "access_key",
        "client_secret",
        "auth_token",
        "secret_key",
    }
)

SENSITIVE_KEY_SUFFIXES: tuple[str, ...] = (
    "_api_key",
    "_apikey",
    "_api_secret",
    "_token",
    "_secret",
    "_password",
    "_passwd",
    "_credential",
    "_credentials",
    "_private_key",
    "_access_key",
    "_client_secret",
    "_auth_token",
    "_secret_key",
)

SENSITIVE_KEY_PREFIXES: tuple[str, ...] = (
    "api_key_",
    "secret_",
    "password_",
    "private_key_",
)


def is_sensitive_key(key: str) -> bool:
    """Determine whether a key name denotes security-sensitive material.

    Case-insensitive, normalizes dashes to underscores. Does not match
    harmless keys like PATH, USER, AUTHOR, or TOKEN_BUDGET.
    """
    if not isinstance(key, str):
        return False
    norm = key.strip().lower().replace("-", "_")
    if not norm:
        return False
    if norm in SENSITIVE_KEY_NAMES:
        return True
    if norm.endswith(SENSITIVE_KEY_SUFFIXES):
        return True
    if norm.startswith(SENSITIVE_KEY_PREFIXES):
        return True
    return False


# --- Deterministic Compiled Regex Patterns ---

# 1. PEM private key blocks (multiline)
_PEM_PRIVATE_KEY_PATTERN = re.compile(
    r"-----BEGIN (?:[A-Za-z0-9_-]+ )?PRIVATE KEY-----"
    r"[\s\S]*?"
    r"-----END (?:[A-Za-z0-9_-]+ )?PRIVATE KEY-----"
)

# 2. URL credentials (user-info in URL schemes)
_URL_CREDENTIALS_PATTERN = re.compile(r"(?i)\b([a-z][a-z0-9+.-]*://)([^/\s@:]*:[^/\s@]+@)")

# 3. Bearer authorization tokens
_AUTH_BEARER_PATTERN = re.compile(r"(?i)\b(Bearer\s+)(?!\[REDACTED\])[A-Za-z0-9_\-\.+=/]{8,}\b")

# 4. Basic authorization credentials
_AUTH_BASIC_PATTERN = re.compile(r"(?i)\b(Basic\s+)(?!\[REDACTED\])[A-Za-z0-9+/=]{8,}\b")

# 5. Common token prefix forms
_TOKEN_PREFIX_PATTERNS: tuple[re.Pattern[str], ...] = (
    re.compile(r"\b(sk-[A-Za-z0-9_\-]{16,})\b"),
    re.compile(r"\b(ghp_[A-Za-z0-9]{16,})\b"),
    re.compile(r"\b(gho_[A-Za-z0-9]{16,})\b"),
    re.compile(r"\b(ghu_[A-Za-z0-9]{16,})\b"),
    re.compile(r"\b(ghs_[A-Za-z0-9]{16,})\b"),
    re.compile(r"\b(ghr_[A-Za-z0-9]{16,})\b"),
    re.compile(r"\b(glpat-[A-Za-z0-9_\-]{20,})\b"),
)

# 6. Key-value assignments in text:
# Key expression matches sensitive keys (optionally preceded by a prefix like NEBIUS_ or GITHUB_)
_KEY_EXPR = (
    r"(?i)(['\"]?)(\b(?:[A-Za-z0-9_]+[_-])?(?:api[_-]?key|token|secret|password|passwd|"
    r"credentials?|authorization|auth|private[_-]?key|access[_-]?key|client[_-]?secret|"
    r"auth[_-]?token|secret[_-]?key)\b)\1"
)

# 6a. Quoted assignment: key = "value" (preserves quotes, excludes [REDACTED])
_KEY_VALUE_QUOTED_PATTERN = re.compile(_KEY_EXPR + r"(\s*[:=]\s*)(['\"])(?!\[REDACTED\]\4)(.+?)\4")

# 6b. Unquoted assignment: key=value (excludes [REDACTED], Bearer, Basic)
_KEY_VALUE_UNQUOTED_PATTERN = re.compile(
    _KEY_EXPR + r"(\s*[:=]\s*)(?!['\"]|\[REDACTED\]|Bearer\s|Basic\s)([^\s,;\'\"\r\n\)\}\]]+)"
)


# --- Redaction Engine (Non-Authoritative Log / Display) ---


def redact_text(text: str) -> tuple[str, bool]:
    """Deterministically redact recognized secret-shaped values from text.

    Guarantees:
    - determinism: same text -> same result;
    - idempotence: redact(redact(x)) == redact(x);
    - non-leakage: output does not contain raw recognized secrets.

    Returns:
        tuple of (redacted_text, is_modified).
    """
    if not isinstance(text, str):
        raise TypeError(f"text must be a str, got {type(text).__name__}")

    sanitized = text
    is_modified = False

    # 1. PEM private key blocks
    new_text, count = _PEM_PRIVATE_KEY_PATTERN.subn(REDACTION_MARKER, sanitized)
    if count > 0:
        sanitized = new_text
        is_modified = True

    # 2. URL credentials (https://user:pass@host -> https://[REDACTED]@host)
    new_text, count = _URL_CREDENTIALS_PATTERN.subn(rf"\1{REDACTION_MARKER}@", sanitized)
    if count > 0:
        sanitized = new_text
        is_modified = True

    # 3. Bearer tokens (Bearer <token> -> Bearer [REDACTED])
    new_text, count = _AUTH_BEARER_PATTERN.subn(rf"\1{REDACTION_MARKER}", sanitized)
    if count > 0:
        sanitized = new_text
        is_modified = True

    # 4. Basic credentials (Basic <base64> -> Basic [REDACTED])
    new_text, count = _AUTH_BASIC_PATTERN.subn(rf"\1{REDACTION_MARKER}", sanitized)
    if count > 0:
        sanitized = new_text
        is_modified = True

    # 5. Token prefixes (sk-..., ghp_..., etc. -> [REDACTED])
    for pattern in _TOKEN_PREFIX_PATTERNS:
        new_text, count = pattern.subn(REDACTION_MARKER, sanitized)
        if count > 0:
            sanitized = new_text
            is_modified = True

    # 6. Key-value assignments (quoted, e.g. api_key="secret" -> api_key="[REDACTED]")
    new_text, count = _KEY_VALUE_QUOTED_PATTERN.subn(rf"\1\2\1\3\4{REDACTION_MARKER}\4", sanitized)
    if count > 0:
        sanitized = new_text
        is_modified = True

    # 7. Key-value assignments (unquoted, e.g. api_key=secret -> api_key=[REDACTED])
    new_text, count = _KEY_VALUE_UNQUOTED_PATTERN.subn(rf"\1\2\1\3{REDACTION_MARKER}", sanitized)
    if count > 0:
        sanitized = new_text
        is_modified = True

    return sanitized, is_modified


def redact_log_text(text: str) -> str:
    """Deterministically redact secret-shaped values from non-authoritative log text."""
    redacted, _ = redact_text(text)
    return redacted


def redact_for_display(data: Any) -> Any:
    """Recursively redact secret-shaped values in arbitrary structures for display.

    Never modifies authoritative facts in-place; returns a sanitized copy.
    """
    if isinstance(data, str):
        return redact_log_text(data)
    if isinstance(data, dict):
        result: dict[str, Any] = {}
        for k, v in data.items():
            if is_sensitive_key(str(k)):
                result[k] = REDACTION_MARKER if v else v
            else:
                result[k] = redact_for_display(v)
        return result
    if isinstance(data, list):
        return [redact_for_display(item) for item in data]
    if isinstance(data, tuple):
        return tuple(redact_for_display(item) for item in data)
    if hasattr(data, "to_dict") and callable(getattr(data, "to_dict")):
        return redact_for_display(data.to_dict())
    return data


# --- Secret Finding & Detection ---


def find_secret_findings(text: str) -> tuple[SecretFinding, ...]:
    """Identify secret locations in text returning only safe non-leaking metadata.

    Returned findings NEVER contain raw secret values.
    """
    if not isinstance(text, str):
        raise TypeError(f"text must be a str, got {type(text).__name__}")

    findings: list[SecretFinding] = []

    for match in _PEM_PRIVATE_KEY_PATTERN.finditer(text):
        findings.append(
            SecretFinding(
                rule_id="PEM_PRIVATE_KEY",
                category=SecretCategory.PEM_PRIVATE_KEY,
                start=match.start(),
                end=match.end(),
            )
        )

    for match in _URL_CREDENTIALS_PATTERN.finditer(text):
        findings.append(
            SecretFinding(
                rule_id="URL_CREDENTIALS",
                category=SecretCategory.URL_CREDENTIALS,
                start=match.start(2),
                end=match.end(2),
            )
        )

    for match in _AUTH_BEARER_PATTERN.finditer(text):
        findings.append(
            SecretFinding(
                rule_id="AUTH_BEARER",
                category=SecretCategory.AUTH_BEARER,
                start=match.start(),
                end=match.end(),
            )
        )

    for match in _AUTH_BASIC_PATTERN.finditer(text):
        findings.append(
            SecretFinding(
                rule_id="AUTH_BASIC",
                category=SecretCategory.AUTH_BASIC,
                start=match.start(),
                end=match.end(),
            )
        )

    for pattern in _TOKEN_PREFIX_PATTERNS:
        for match in pattern.finditer(text):
            findings.append(
                SecretFinding(
                    rule_id="TOKEN_PREFIX",
                    category=SecretCategory.TOKEN_PREFIX,
                    start=match.start(),
                    end=match.end(),
                )
            )

    for match in _KEY_VALUE_QUOTED_PATTERN.finditer(text):
        findings.append(
            SecretFinding(
                rule_id="KEY_VALUE_ASSIGNMENT",
                category=SecretCategory.KEY_VALUE_ASSIGNMENT,
                start=match.start(),
                end=match.end(),
            )
        )

    for match in _KEY_VALUE_UNQUOTED_PATTERN.finditer(text):
        findings.append(
            SecretFinding(
                rule_id="KEY_VALUE_ASSIGNMENT",
                category=SecretCategory.KEY_VALUE_ASSIGNMENT,
                start=match.start(),
                end=match.end(),
            )
        )

    return tuple(sorted(findings, key=lambda f: (f.start, f.end)))


def contains_secret(text: str) -> bool:
    """Return True if text contains any recognized unredacted secret pattern."""
    if not isinstance(text, str):
        raise TypeError(f"text must be a str, got {type(text).__name__}")
    findings = find_secret_findings(text)
    return len(findings) > 0


# --- Authoritative Persistence Boundary Validation ---


def validate_no_secrets(value: Any, path: str = "") -> None:
    """Validate that value contains no raw secrets.

    Raises SecretPersistenceError on violation without echoing raw secrets.
    """
    if isinstance(value, str):
        findings = find_secret_findings(value)
        if findings:
            first = findings[0]
            raise SecretPersistenceError(
                rule_id=first.rule_id,
                path=path or "text",
                category="SECRET_PERSISTENCE_FORBIDDEN",
            )
        return

    if isinstance(value, (list, tuple)):
        for idx, item in enumerate(value):
            item_path = f"{path}[{idx}]" if path else f"[{idx}]"
            validate_no_secrets(item, item_path)
        return

    if isinstance(value, dict):
        for k, v in value.items():
            key_str = str(k)
            item_path = f"{path}.{key_str}" if path else key_str
            if is_sensitive_key(key_str):
                if isinstance(v, str) and v and v != REDACTION_MARKER:
                    raise SecretPersistenceError(
                        rule_id="SENSITIVE_KEY",
                        path=item_path,
                        category="SECRET_PERSISTENCE_FORBIDDEN",
                    )
            validate_no_secrets(v, item_path)
        return


def validate_execution_command_for_persistence(command: Any, path: str = "command") -> None:
    """Validate that ExecutionCommand carries no forbidden raw secrets."""
    if command is None:
        return

    # Check argv
    argv = getattr(command, "argv", ())
    for idx, arg in enumerate(argv):
        arg_path = f"{path}.argv[{idx}]"
        validate_no_secrets(arg, arg_path)

    # Check cwd
    cwd = getattr(command, "cwd", None)
    if cwd is not None:
        validate_no_secrets(cwd, f"{path}.cwd")

    # Check env pairs
    env = getattr(command, "env", ())
    for k, v in env:
        env_path = f"{path}.env[{k}]"
        if is_sensitive_key(k):
            if v and v != REDACTION_MARKER:
                raise SecretPersistenceError(
                    rule_id="SENSITIVE_ENV_KEY",
                    path=env_path,
                    category="SECRET_PERSISTENCE_FORBIDDEN",
                )
        validate_no_secrets(v, env_path)


def validate_evidence_record_for_persistence(record: Any, path: str = "") -> None:
    """Validate an EvidenceRecord against forbidden durable-secret persistence rules.

    Fails closed: if any authoritative fact contains secret-shaped material,
    raises SecretPersistenceError. Rejection never echoes raw secrets.
    """
    prefix = f"{path}." if path else ""

    # 1. Validate command (argv, cwd, env)
    cmd = getattr(record, "command", None)
    if cmd is not None:
        validate_execution_command_for_persistence(cmd, f"{prefix}command")

    # 2. Validate candidate descriptions or locator if present
    candidate = getattr(record, "candidate", None)
    if candidate is not None:
        desc = getattr(candidate, "description", "")
        if desc:
            validate_no_secrets(desc, f"{prefix}candidate.description")
        source = getattr(candidate, "source", None)
        if source is not None:
            loc = getattr(source, "locator", "")
            if loc:
                validate_no_secrets(loc, f"{prefix}candidate.source.locator")

    # 3. Validate causal_binding descriptions
    cb = getattr(record, "causal_binding", None)
    if cb is not None:
        witness = getattr(cb, "witness", None)
        if witness is not None:
            w_desc = getattr(witness, "description", "")
            if w_desc:
                validate_no_secrets(w_desc, f"{prefix}causal_binding.witness.description")

    # 4. Validate artifacts descriptions
    artifacts = getattr(record, "artifacts", ())
    for idx, art in enumerate(artifacts):
        art_desc = getattr(art, "description", "")
        if art_desc:
            validate_no_secrets(art_desc, f"{prefix}artifacts[{idx}].description")
