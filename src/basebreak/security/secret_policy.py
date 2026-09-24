"""Deterministic secret redaction engine and persistence boundary rules.

Provides provider-neutral deterministic secret-shaped value detection, redaction,
and forbidden persistence enforcement. Distinguishes non-authoritative log/display
redaction from authoritative evidence fail-closed persistence boundaries.
"""

from __future__ import annotations

import re
from collections.abc import Mapping
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
    Diagnostic paths use structural and index representations to ensure
    attacker-controlled keys are never echoed into error metadata.
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

    if isinstance(value, (dict, Mapping)):
        for idx, (k, v) in enumerate(value.items()):
            key_path = f"{path}[{idx}].key" if path else f"[{idx}].key"
            val_path = f"{path}[{idx}].value" if path else f"[{idx}].value"

            # Check mapping key itself for secret-shaped material
            if isinstance(k, str):
                validate_no_secrets(k, key_path)
            else:
                validate_no_secrets(k, key_path)

            # Check sensitive key rule
            key_str = str(k) if isinstance(k, str) else ""
            if key_str and is_sensitive_key(key_str):
                if isinstance(v, str) and v and v != REDACTION_MARKER:
                    raise SecretPersistenceError(
                        rule_id="SENSITIVE_KEY",
                        path=val_path,
                        category="SECRET_PERSISTENCE_FORBIDDEN",
                    )
            validate_no_secrets(v, val_path)
        return


def validate_source_identity_for_persistence(source: Any, path: str = "source") -> None:
    """Validate that SourceIdentity contains no raw secrets in its string fields."""
    if source is None:
        return
    locator = getattr(source, "locator", None)
    if isinstance(locator, str) and locator:
        validate_no_secrets(locator, f"{path}.locator")
    subpath = getattr(source, "subpath", None)
    if isinstance(subpath, str) and subpath:
        validate_no_secrets(subpath, f"{path}.subpath")
    req_ref = getattr(source, "requested_ref", None)
    if req_ref is not None:
        name = getattr(req_ref, "name", None)
        if isinstance(name, str) and name:
            validate_no_secrets(name, f"{path}.requested_ref.name")


def validate_candidate_identity_for_persistence(candidate: Any, path: str = "candidate") -> None:
    """Validate that CandidateIdentity contains no raw secrets in its string fields."""
    if candidate is None:
        return
    cand_id = getattr(candidate, "candidate_id", None)
    if isinstance(cand_id, str) and cand_id:
        validate_no_secrets(cand_id, f"{path}.candidate_id")
    source = getattr(candidate, "source", None)
    if source is not None:
        validate_source_identity_for_persistence(source, f"{path}.source")
    desc = getattr(candidate, "description", None)
    if isinstance(desc, str) and desc:
        validate_no_secrets(desc, f"{path}.description")


def validate_causal_binding_for_persistence(binding: Any, path: str = "causal_binding") -> None:
    """Validate that CausalBinding contains no raw secrets in its string fields."""
    if binding is None:
        return
    req_id = getattr(binding, "requirement_id", None)
    if isinstance(req_id, str) and req_id:
        validate_no_secrets(req_id, f"{path}.requirement_id")
    witness = getattr(binding, "witness", None)
    if witness is not None:
        w_id = getattr(witness, "witness_id", None)
        if isinstance(w_id, str) and w_id:
            validate_no_secrets(w_id, f"{path}.witness.witness_id")
        w_desc = getattr(witness, "description", None)
        if isinstance(w_desc, str) and w_desc:
            validate_no_secrets(w_desc, f"{path}.witness.description")
    base_src = getattr(binding, "base_source", None)
    if base_src is not None:
        validate_source_identity_for_persistence(base_src, f"{path}.base_source")
    cand = getattr(binding, "candidate", None)
    if cand is not None:
        validate_candidate_identity_for_persistence(cand, f"{path}.candidate")
    cf = getattr(binding, "counterfactual", None)
    if cf is not None:
        cf_id = getattr(cf, "counterfactual_id", None)
        if isinstance(cf_id, str) and cf_id:
            validate_no_secrets(cf_id, f"{path}.counterfactual.counterfactual_id")
        target_cand = getattr(cf, "target_candidate", None)
        if target_cand is not None:
            validate_candidate_identity_for_persistence(
                target_cand, f"{path}.counterfactual.target_candidate"
            )
        cf_desc = getattr(cf, "description", None)
        if isinstance(cf_desc, str) and cf_desc:
            validate_no_secrets(cf_desc, f"{path}.counterfactual.description")


def validate_artifact_reference_for_persistence(art: Any, path: str = "artifact") -> None:
    """Validate that ArtifactReference contains no raw secrets in its media_type."""
    if art is None:
        return
    media_type = getattr(art, "media_type", None)
    if isinstance(media_type, str) and media_type:
        validate_no_secrets(media_type, f"{path}.media_type")


def validate_execution_command_for_persistence(command: Any, path: str = "command") -> None:
    """Validate that ExecutionCommand carries no forbidden raw secrets.

    Validates argv, cwd, and environment variable keys and values.
    Uses structural indexing for environment variables (command.env[idx].key/value)
    so attacker-controlled keys are never echoed into error paths.
    """
    if command is None:
        return

    # Check argv
    argv = getattr(command, "argv", ())
    for idx, arg in enumerate(argv):
        arg_path = f"{path}.argv[{idx}]"
        if isinstance(arg, str):
            validate_no_secrets(arg, arg_path)

    # Check cwd
    cwd = getattr(command, "cwd", None)
    if cwd is not None and isinstance(cwd, str):
        validate_no_secrets(cwd, f"{path}.cwd")

    # Check env pairs
    env = getattr(command, "env", ())
    if isinstance(env, dict):
        env_items = list(env.items())
    elif isinstance(env, (list, tuple)):
        env_items = list(env)
    else:
        env_items = []

    for idx, item in enumerate(env_items):
        if isinstance(item, (tuple, list)) and len(item) == 2:
            k, v = item
            key_path = f"{path}.env[{idx}].key"
            val_path = f"{path}.env[{idx}].value"

            # Check key text itself for secret-shaped material
            if isinstance(k, str):
                validate_no_secrets(k, key_path)

            # Check sensitive key rule
            if isinstance(k, str) and is_sensitive_key(k):
                if isinstance(v, str) and v and v != REDACTION_MARKER:
                    raise SecretPersistenceError(
                        rule_id="SENSITIVE_ENV_KEY",
                        path=val_path,
                        category="SECRET_PERSISTENCE_FORBIDDEN",
                    )

            # Check value text
            if isinstance(v, str):
                validate_no_secrets(v, val_path)


def validate_evidence_record_for_persistence(record: Any, path: str = "") -> None:
    """Validate an EvidenceRecord against forbidden durable-secret persistence rules.

    Fails closed: if any authoritative fact contains secret-shaped material,
    raises SecretPersistenceError. Rejection never echoes raw secrets.
    Covers all serialized string-bearing fields reachable from EvidenceRecord:
    evidence_id, run_id, candidate, causal_binding, command, result, artifacts.
    """
    prefix = f"{path}." if path else ""

    # 1. Validate evidence_id
    ev_id = getattr(record, "evidence_id", None)
    if ev_id is not None:
        raw_ev = getattr(ev_id, "evidence_id", ev_id)
        if isinstance(raw_ev, str) and raw_ev:
            validate_no_secrets(raw_ev, f"{prefix}evidence_id")

    # 2. Validate run_id
    run_id = getattr(record, "run_id", None)
    if run_id is not None:
        raw_run = getattr(run_id, "run_id", run_id)
        if isinstance(raw_run, str) and raw_run:
            validate_no_secrets(raw_run, f"{prefix}run_id")

    # 3. Validate command (argv, cwd, env keys/values)
    cmd = getattr(record, "command", None)
    if cmd is not None:
        validate_execution_command_for_persistence(cmd, f"{prefix}command")

    # 4. Validate candidate (candidate_id, source, description)
    candidate = getattr(record, "candidate", None)
    if candidate is not None:
        validate_candidate_identity_for_persistence(candidate, f"{prefix}candidate")

    # 5. Validate causal_binding (requirement_id, witness, base_source, candidate, counterfactual)
    cb = getattr(record, "causal_binding", None)
    if cb is not None:
        validate_causal_binding_for_persistence(cb, f"{prefix}causal_binding")

    # 6. Validate result if present
    res = getattr(record, "result", None)
    if res is not None:
        for attr in ("description", "message", "narrative"):
            val = getattr(res, attr, None)
            if isinstance(val, str) and val:
                validate_no_secrets(val, f"{prefix}result.{attr}")

    # 7. Validate artifacts (media_type for each artifact; no fake description)
    artifacts = getattr(record, "artifacts", ())
    for idx, art in enumerate(artifacts):
        validate_artifact_reference_for_persistence(art, f"{prefix}artifacts[{idx}]")
