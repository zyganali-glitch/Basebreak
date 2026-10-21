"""Deterministic secret redaction engine and persistence boundary rules.

Provides provider-neutral deterministic secret-shaped value detection, redaction,
and forbidden persistence enforcement. Distinguishes non-authoritative log/display
redaction from authoritative evidence fail-closed persistence boundaries.
"""

from __future__ import annotations

import ast
import bisect
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

# 3a. Explicit Authorization header context with Bearer tokens (allows short credentials)
_AUTH_HEADER_BEARER_PATTERN = re.compile(
    r"(?i)(['\"]?\b(?:authorization|proxy-authorization|auth)\b['\"]?\s*[:=]\s*['\"]?Bearer\s+)"
    r"(?!\[REDACTED\])[A-Za-z0-9_\-\.~+=/]+"
)

# 3b. Explicit Authorization header context with Basic credentials (allows short credentials)
_AUTH_HEADER_BASIC_PATTERN = re.compile(
    r"(?i)(['\"]?\b(?:authorization|proxy-authorization|auth)\b['\"]?\s*[:=]\s*['\"]?Basic\s+)"
    r"(?!\[REDACTED\])[A-Za-z0-9+/=]+"
)

# 4a. Bare Bearer tokens (must be >= 8 chars and contain non-alphabetic chars)
_AUTH_BARE_BEARER_PATTERN = re.compile(
    r"(?i)\b(Bearer\s+)(?!\[REDACTED\])(?=[A-Za-z0-9_\-\.~+=/]*[0-9_\-\.~+=/])[A-Za-z0-9_\-\.~+=/]{8,}"
)

# 4b. Bare Basic credentials (must be >= 8 chars and contain non-alphabetic chars)
_AUTH_BARE_BASIC_PATTERN = re.compile(
    r"(?i)\b(Basic\s+)(?!\[REDACTED\])(?=[A-Za-z0-9+/=]*[0-9+/=])[A-Za-z0-9+/=]{8,}"
)

# Backward-compatibility aliases
_AUTH_BEARER_PATTERN = _AUTH_HEADER_BEARER_PATTERN
_AUTH_BASIC_PATTERN = _AUTH_HEADER_BASIC_PATTERN

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

    # 3a. Header Bearer tokens (Authorization: Bearer <token> -> Authorization: Bearer [REDACTED])
    new_text, count = _AUTH_HEADER_BEARER_PATTERN.subn(rf"\1{REDACTION_MARKER}", sanitized)
    if count > 0:
        sanitized = new_text
        is_modified = True

    # 3b. Header Basic credentials (Authorization: Basic <data> -> Basic [REDACTED])
    new_text, count = _AUTH_HEADER_BASIC_PATTERN.subn(rf"\1{REDACTION_MARKER}", sanitized)
    if count > 0:
        sanitized = new_text
        is_modified = True

    # 4a. Bare Bearer tokens (Bearer <token> -> Bearer [REDACTED])
    new_text, count = _AUTH_BARE_BEARER_PATTERN.subn(rf"\1{REDACTION_MARKER}", sanitized)
    if count > 0:
        sanitized = new_text
        is_modified = True

    # 4b. Bare Basic credentials (Basic <base64> -> Basic [REDACTED])
    new_text, count = _AUTH_BARE_BASIC_PATTERN.subn(rf"\1{REDACTION_MARKER}", sanitized)
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
    Sanitizes secret-bearing mapping keys and handles collision safety deterministically.
    Sensitive schema keys (e.g. API_KEY) remain structurally recognizable, while their
    values are redacted.
    """
    if isinstance(data, str):
        return redact_log_text(data)
    if isinstance(data, (dict, Mapping)):
        result: dict[Any, Any] = {}
        for k, v in data.items():
            if isinstance(k, str):
                sanitized_k = redact_log_text(k)
            else:
                sanitized_k = redact_for_display(k)

            final_k = sanitized_k
            collision_idx = 1
            while final_k in result:
                collision_idx += 1
                if isinstance(sanitized_k, str):
                    final_k = f"{sanitized_k}#{collision_idx}"
                else:
                    final_k = (sanitized_k, collision_idx)

            key_str = str(k) if isinstance(k, str) else str(sanitized_k)
            if is_sensitive_key(key_str):
                result[final_k] = REDACTION_MARKER if v else v
            else:
                result[final_k] = redact_for_display(v)
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

    for match in _AUTH_HEADER_BEARER_PATTERN.finditer(text):
        findings.append(
            SecretFinding(
                rule_id="AUTH_BEARER",
                category=SecretCategory.AUTH_BEARER,
                start=match.start(),
                end=match.end(),
            )
        )

    for match in _AUTH_HEADER_BASIC_PATTERN.finditer(text):
        findings.append(
            SecretFinding(
                rule_id="AUTH_BASIC",
                category=SecretCategory.AUTH_BASIC,
                start=match.start(),
                end=match.end(),
            )
        )

    for match in _AUTH_BARE_BEARER_PATTERN.finditer(text):
        findings.append(
            SecretFinding(
                rule_id="AUTH_BEARER",
                category=SecretCategory.AUTH_BEARER,
                start=match.start(),
                end=match.end(),
            )
        )

    for match in _AUTH_BARE_BASIC_PATTERN.finditer(text):
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

    # Deduplicate overlapping findings (e.g. bare sub-matches contained within header matches)
    filtered: list[SecretFinding] = []
    for f in sorted(findings, key=lambda x: (x.start, -x.end)):
        if not filtered or f.end > filtered[-1].end:
            filtered.append(f)

    return tuple(sorted(filtered, key=lambda f: (f.start, f.end)))


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


# --- Context-Aware Source-Code Patch Validation (P-27.06 surgical repair) ---
#
# Root cause: the generic KEY_VALUE_ASSIGNMENT rule also matches ordinary Python
# source expressions such as ``token = secrets.token_hex(16)``, ``token = new_token``
# or ``token = None``, none of which embed a credential value. Applying the generic
# rule verbatim to model-generated candidate patches therefore rejects benign code.
#
# Repair semantics (strictly bounded, fail-closed):
# - Only applies at explicit source-code patch boundaries
#   (``validate_no_secrets_in_source_patch``). The generic ``validate_no_secrets``
#   boundary used for logs, JSON evidence, receipts, environment variables,
#   provider responses and other non-code text is unchanged.
# - Only KEY_VALUE_ASSIGNMENT findings are eligible for exemption. Every other
#   category (PEM keys, URL credentials, Authorization headers, token prefixes)
#   remains strictly forbidden even inside Python source patches.
# - A KEY_VALUE_ASSIGNMENT finding is exempt only when ALL of the following hold:
#   1. the patch text carries at least one ``diff --git`` file header;
#   2. the finding lies on an added, removed, or context hunk line of a file whose
#      path ends with a Python source suffix (``.py`` / ``.pyi``);
#   3. the marker-stripped line parses as exactly one Python statement;
#   4. that statement binds at least one sensitive-named key, and every sensitive
#      binding's value/annotation expression contains no embedded string or bytes
#      literal (hardcoded credential values remain forbidden).
# - Anything ambiguous or malformed (headerless diffs, non-Python files, unparseable
#   lines, multi-statement lines, comments, string literals) fails closed to the
#   strict generic verdict.


_PYTHON_SOURCE_SUFFIXES: tuple[str, ...] = (".py", ".pyi")

_DIFF_GIT_QUOTED_HEADER_PATTERN = re.compile(r'^"(?:a/|b/)?(.+?)"\s+"(?:a/|b/)?(.+?)"$')


def _parse_diff_git_new_path(line: str) -> str | None:
    """Extract the target file path from a ``diff --git X Y`` header line.

    Handles both canonical order (``a/path b/path``), inverted order produced by
    reverse-delta construction (``b/path a/path``), ``/dev/null`` sides, and
    git-quoted paths. Returns None when the line is not a recognizable header.
    """
    stripped = line.rstrip("\r\n")
    prefix = "diff --git "
    if not stripped.startswith(prefix):
        return None
    rest = stripped[len(prefix) :]
    tokens: list[str] | None = None
    if rest.startswith('"'):
        match = _DIFF_GIT_QUOTED_HEADER_PATTERN.match(rest)
        if match is None:
            return None
        tokens = [f"a/{match.group(1)}", f"b/{match.group(2)}"]
    else:
        tokens = rest.split(" ")
    if len(tokens) != 2:
        return None
    for token in tokens:
        if token.startswith(("a/", "b/")) and token not in ("a/", "b/"):
            return token[2:]
    return None


def _is_python_source_path(file_path: str) -> bool:
    """Determine whether a diff target path is a Python source file."""
    normalized = file_path.strip().replace("\\", "/").lower()
    return normalized.endswith(_PYTHON_SOURCE_SUFFIXES)


def _sensitive_binding_expressions(statement: ast.stmt) -> list[ast.expr]:
    """Collect value/annotation expressions bound to sensitive-named keys.

    Covers assignments (``=``, annotated, augmented, walrus), keyword arguments,
    function parameter annotations/defaults, and dictionary literal entries whose
    key is a sensitive name. Returns an empty list when the statement binds no
    sensitive-named key (callers must treat that as not provably nonsecret).
    """
    bound: list[ast.expr] = []

    for node in ast.walk(statement):
        if isinstance(node, ast.Assign):
            if isinstance(node.value, ast.expr):
                for target in node.targets:
                    if isinstance(target, ast.Name) and is_sensitive_key(target.id):
                        bound.append(node.value)
        elif isinstance(node, ast.AnnAssign):
            if isinstance(node.target, ast.Name) and is_sensitive_key(node.target.id):
                if isinstance(node.value, ast.expr):
                    bound.append(node.value)
                elif isinstance(node.annotation, ast.expr):
                    bound.append(node.annotation)
        elif isinstance(node, ast.AugAssign):
            if isinstance(node.target, ast.Name) and is_sensitive_key(node.target.id):
                if isinstance(node.value, ast.expr):
                    bound.append(node.value)
        elif isinstance(node, ast.NamedExpr):
            if isinstance(node.target, ast.Name) and is_sensitive_key(node.target.id):
                if isinstance(node.value, ast.expr):
                    bound.append(node.value)
        elif isinstance(node, ast.keyword):
            if node.arg is not None and is_sensitive_key(node.arg):
                if isinstance(node.value, ast.expr):
                    bound.append(node.value)
        elif isinstance(node, ast.arg):
            if is_sensitive_key(node.arg):
                if isinstance(node.annotation, ast.expr):
                    bound.append(node.annotation)
        elif isinstance(node, ast.arguments):
            # Positional defaults align with the tail of node.args; keyword-only
            # defaults align with node.kwonlyargs (None means no default).
            positional_defaults = node.defaults
            offset = len(node.args) - len(positional_defaults)
            for arg, default in zip(node.args[offset:], positional_defaults):
                if is_sensitive_key(arg.arg) and isinstance(default, ast.expr):
                    bound.append(default)
            for kw_arg, kw_default in zip(node.kwonlyargs, node.kw_defaults):
                if kw_default is not None and is_sensitive_key(kw_arg.arg):
                    if isinstance(kw_default, ast.expr):
                        bound.append(kw_default)
        elif isinstance(node, ast.Dict):
            for key, value in zip(node.keys, node.values):
                if (
                    isinstance(key, ast.Constant)
                    and isinstance(key.value, str)
                    and is_sensitive_key(key.value)
                    and isinstance(value, ast.expr)
                ):
                    bound.append(value)

    return bound


def _contains_embedded_literal_text(expression: ast.expr) -> bool:
    """Return True when the expression embeds any string or bytes literal.

    A hardcoded credential value must appear as a string/bytes literal; runtime
    references (names, calls, attributes, subscripts) and non-string constants
    (None, bools, numbers) cannot embed one. Fails closed: any string or bytes
    literal anywhere in the expression disqualifies the exemption.
    """
    for node in ast.walk(expression):
        if isinstance(node, ast.Constant) and isinstance(node.value, (str, bytes)):
            return True
    return False


def _is_provably_nonsecret_python_line(code_line: str) -> bool:
    """Return True when a single Python line binds sensitive keys only to
    provably nonsecret runtime expressions (no embedded string/bytes literals).

    A diff line containing only a block header (``def``/``class``/``if``/...) ends
    with ``:`` and cannot parse alone, so it is completed with a placeholder
    ``...`` body before parsing; the placeholder cannot introduce bindings or
    literals, leaving the header's annotations/defaults as the only evaluated
    content. Fails closed: syntax errors, multiple statements, comments, empty
    parses, and statements without any sensitive-named binding are never exempt.
    """
    # Strip the diff marker, surrounding indentation, and the line terminator so a
    # single indented statement parses at module level.
    source = code_line.strip()
    if not source:
        return False
    try:
        tree = ast.parse(source, mode="exec")
    except (SyntaxError, ValueError):
        if not source.endswith(":"):
            return False
        try:
            tree = ast.parse(source + " ...", mode="exec")
        except (SyntaxError, ValueError):
            return False
    statements = tree.body
    if len(statements) != 1 or not isinstance(statements[0], ast.stmt):
        return False
    bound = _sensitive_binding_expressions(statements[0])
    if not bound:
        return False
    return all(not _contains_embedded_literal_text(expr) for expr in bound)


def _source_patch_exempt_line_indices(patch_text: str) -> tuple[set[int], list[str], bool]:
    """Compute the set of hunk-line indices eligible for the Python-source exemption.

    Returns (exempt_line_indices, lines, saw_diff_header). Lines are only eligible
    when they carry a unified-diff marker (``+``, ``-``, or `` ``), belong to a
    ``.py``/``.pyi`` file declared by a preceding ``diff --git`` header, and parse
    as one provably nonsecret Python statement.
    """
    lines = patch_text.splitlines(keepends=True)
    exempt: set[int] = set()
    saw_diff_header = False
    current_file_is_python = False

    for idx, line in enumerate(lines):
        header_path = _parse_diff_git_new_path(line)
        if header_path is not None:
            saw_diff_header = True
            current_file_is_python = _is_python_source_path(header_path)
            continue
        if not line.startswith(("+", "-", " ")):
            continue
        if not saw_diff_header or not current_file_is_python:
            continue
        if _is_provably_nonsecret_python_line(line[1:]):
            exempt.add(idx)

    return exempt, lines, saw_diff_header


def validate_no_secrets_in_source_patch(patch_text: str, path: str = "") -> None:
    """Validate that a unified source-code patch contains no raw secrets.

    Context-aware boundary for actual source-code patches: detection is identical
    to :func:`validate_no_secrets`, except that a ``KEY_VALUE_ASSIGNMENT`` finding
    is permitted only when it lies on an added/removed/context line of a Python
    source file inside the diff and that single line parses as exactly one Python
    statement whose sensitive-named bindings are provably nonsecret runtime
    expressions. Hardcoded string/bytes credential literals, every other secret
    category, non-Python files, and malformed or headerless diffs remain strictly
    forbidden. Fails closed on any ambiguity.

    Raises SecretPersistenceError on violation without echoing raw secrets.
    """
    if not isinstance(patch_text, str):
        raise TypeError(f"patch_text must be a str, got {type(patch_text).__name__}")

    findings = find_secret_findings(patch_text)
    if not findings:
        return

    exempt, lines, saw_diff_header = _source_patch_exempt_line_indices(patch_text)
    if not lines or not saw_diff_header:
        # Not a recognizable unified diff: fail closed with the strict generic rules.
        validate_no_secrets(patch_text, path=path)
        return

    line_start_offsets: list[int] = []
    position = 0
    for line in lines:
        line_start_offsets.append(position)
        position += len(line)

    for finding in findings:
        line_index = bisect.bisect_right(line_start_offsets, finding.start) - 1
        if finding.category is SecretCategory.KEY_VALUE_ASSIGNMENT and line_index in exempt:
            continue
        raise SecretPersistenceError(
            rule_id=finding.rule_id,
            path=path or "source_patch",
            category="SECRET_PERSISTENCE_FORBIDDEN",
        )


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
