"""Bounded, sanitized execution diagnostics for the Basebreak trusted verifier bridge (P-27.06).

Preserves diagnostic facts (syntax, import, collection, setup, test assertion,
infrastructure, timeout) in protected operator-only storage without leaking sealed
witness code, secret tokens, or private prompts to the Builder or public judge.
"""

from __future__ import annotations

import dataclasses
import hashlib
import json
import os
import pathlib
import re
from enum import Enum
from typing import Any, Mapping, Sequence

MAX_DIAGNOSTIC_EXCERPT_CHARS: int = 1024

_SECRET_BEARER_PATTERN = re.compile(r"(?i)\b(bearer\s+[A-Za-z0-9_\-\.]{12,})\b")
_SECRET_KEY_PATTERN = re.compile(r"(?i)\b((?:sk|nvd|key|token|secret)[\-_][A-Za-z0-9_\-]{16,})\b")
_WITNESS_SEALED_CODE_PATTERNS = [
    re.compile(r"(?i)\btest_single_use_witness\b"),
    re.compile(r"(?i)\bwit-reset-vault\b"),
    re.compile(r"(?i)assert\s+second_res\b"),
    re.compile(r"(?i)assert\s+first_res\b"),
    re.compile(r"(?i)assert\s+True\s+is\s+False\b"),
    re.compile(r"(?i)assert\s+False\s+is\s+True\b"),
]


class DiagnosticCategory(str, Enum):
    """High-level execution failure or outcome classification."""

    PASS = "PASS"
    SYNTAX = "SYNTAX"
    IMPORT = "IMPORT"
    COLLECTION = "COLLECTION"
    SETUP = "SETUP"
    TEST = "TEST"
    INFRASTRUCTURE = "INFRASTRUCTURE"
    TIMEOUT = "TIMEOUT"
    UNKNOWN = "UNKNOWN"


def sanitize_diagnostic_excerpt(
    text: str,
    *,
    max_chars: int = MAX_DIAGNOSTIC_EXCERPT_CHARS,
    redact_witness: bool = True,
) -> str:
    """Sanitize and truncate stdout/stderr excerpt for diagnostic preservation.

    Guarantees:
    - Never leaks secret tokens or bearer credentials (redacted to [REDACTED_SECRET]).
    - If redact_witness is True, witness-specific function names and assertions are redacted.
    - Strips ANSI escape sequences.
    - Truncated strictly within max_chars.
    """
    if not isinstance(text, str) or not text.strip():
        return ""

    # Strip ANSI escape sequences
    clean = re.sub(r"\x1b\[[0-9;]*[mGKH]", "", text)

    # Redact secret credentials
    clean = _SECRET_BEARER_PATTERN.sub("[REDACTED_BEARER]", clean)
    clean = _SECRET_KEY_PATTERN.sub("[REDACTED_KEY]", clean)

    if redact_witness:
        for pat in _WITNESS_SEALED_CODE_PATTERNS:
            clean = pat.sub("[SEALED_WITNESS_REDACTED]", clean)

    clean = clean.strip()
    if len(clean) > max_chars:
        return clean[:max_chars] + "... [truncated]"
    return clean


def classify_execution_diagnostic(
    *,
    exit_code: int | None,
    termination_status: Any,
    stdout: str = "",
    stderr: str = "",
) -> DiagnosticCategory:
    """Classify execution outcome into a high-level diagnostic category."""
    status_str = str(getattr(termination_status, "value", termination_status) or "").upper()
    if status_str == "TIMED_OUT":
        return DiagnosticCategory.TIMEOUT
    if status_str in ("CANCELLED", "FAILED_TO_START"):
        return DiagnosticCategory.INFRASTRUCTURE

    combined = f"{stdout}\n{stderr}".lower()

    if exit_code == 0:
        return DiagnosticCategory.PASS

    # Syntax / Indentation errors
    if "indentationerror" in combined or "syntaxerror" in combined:
        return DiagnosticCategory.SYNTAX

    # Import / ModuleNotFound errors
    if "modulenotfounderror" in combined or "importerror" in combined:
        return DiagnosticCategory.IMPORT

    # Pytest collection errors (exit code 2 or explicit collection failure)
    if (
        exit_code in (2, 3, 4)
        or "error during collection" in combined
        or "error collecting" in combined
    ):
        return DiagnosticCategory.COLLECTION

    # Pytest exit code 5 (no tests collected)
    if exit_code == 5 or "collected 0 items" in combined:
        return DiagnosticCategory.COLLECTION

    # Setup / environment failure
    if "failed to deploy witness" in combined or "cannot create directory" in combined:
        return DiagnosticCategory.SETUP

    # Test failure (exit code 1 with assertions)
    if exit_code == 1:
        if "assertionerror" in combined or "failed" in combined:
            return DiagnosticCategory.TEST
        return DiagnosticCategory.TEST

    if exit_code is None:
        return DiagnosticCategory.INFRASTRUCTURE

    return DiagnosticCategory.UNKNOWN


@dataclasses.dataclass(frozen=True, slots=True)
class WorldDiagnostic:
    """Diagnostic fact for a single execution world."""

    world: str
    sandbox_id: str
    exit_code: int | None
    outcome: str
    diagnostic_category: DiagnosticCategory
    stdout_digest: str
    stderr_digest: str
    safe_stdout_excerpt: str | None = None
    safe_stderr_excerpt: str | None = None

    def to_dict(self) -> dict[str, Any]:
        return {
            "diagnostic_category": self.diagnostic_category.value,
            "exit_code": self.exit_code,
            "outcome": self.outcome,
            "safe_stderr_excerpt": self.safe_stderr_excerpt,
            "safe_stdout_excerpt": self.safe_stdout_excerpt,
            "sandbox_id": self.sandbox_id,
            "stderr_digest": self.stderr_digest,
            "stdout_digest": self.stdout_digest,
            "world": self.world,
        }

    @classmethod
    def from_dict(cls, data: Mapping[str, Any]) -> WorldDiagnostic:
        raw_cat = str(data.get("diagnostic_category", "UNKNOWN")).upper()
        try:
            category = DiagnosticCategory(raw_cat)
        except ValueError:
            category = DiagnosticCategory.UNKNOWN
        return cls(
            world=str(data.get("world", "")),
            sandbox_id=str(data.get("sandbox_id", "")),
            exit_code=data.get("exit_code"),
            outcome=str(data.get("outcome", "")),
            diagnostic_category=category,
            stdout_digest=str(data.get("stdout_digest", "")),
            stderr_digest=str(data.get("stderr_digest", "")),
            safe_stdout_excerpt=data.get("safe_stdout_excerpt"),
            safe_stderr_excerpt=data.get("safe_stderr_excerpt"),
        )


@dataclasses.dataclass(frozen=True, slots=True)
class ExecutionDiagnosticRecord:
    """Auditable, bound diagnostic record stored in protected operator storage."""

    request_id: str
    source_commit_id: str
    candidate_patch_digest: str | None
    candidate_tree_digest: str | None
    world_diagnostics: tuple[WorldDiagnostic, ...]
    overall_verdict: str
    created_at_utc: str

    def to_dict(self) -> dict[str, Any]:
        return {
            "candidate_patch_digest": self.candidate_patch_digest,
            "candidate_tree_digest": self.candidate_tree_digest,
            "created_at_utc": self.created_at_utc,
            "overall_verdict": self.overall_verdict,
            "request_id": self.request_id,
            "source_commit_id": self.source_commit_id,
            "world_diagnostics": [w.to_dict() for w in self.world_diagnostics],
        }

    @classmethod
    def from_dict(cls, data: Mapping[str, Any]) -> ExecutionDiagnosticRecord:
        raw_worlds = data.get("world_diagnostics", [])
        worlds = (
            tuple(WorldDiagnostic.from_dict(w) for w in raw_worlds)
            if isinstance(raw_worlds, Sequence)
            else ()
        )
        return cls(
            request_id=str(data.get("request_id", "")),
            source_commit_id=str(data.get("source_commit_id", "")),
            candidate_patch_digest=data.get("candidate_patch_digest"),
            candidate_tree_digest=data.get("candidate_tree_digest"),
            world_diagnostics=worlds,
            overall_verdict=str(data.get("overall_verdict", "INCONCLUSIVE")),
            created_at_utc=str(data.get("created_at_utc", "")),
        )


def _diag_path(state_dir: pathlib.Path | str, request_id: str) -> pathlib.Path:
    safe = hashlib.sha256(request_id.encode("utf-8")).hexdigest()
    return pathlib.Path(state_dir) / f"diag-{safe}.json"


def record_execution_diagnostics(
    state_dir: pathlib.Path | str,
    record: ExecutionDiagnosticRecord,
) -> pathlib.Path:
    """Atomically record execution diagnostics in protected storage (mode 0600)."""
    p = _diag_path(state_dir, record.request_id)
    tmp = p.with_name(p.name + ".tmp")
    data_bytes = json.dumps(record.to_dict(), indent=2, sort_keys=True).encode("utf-8")

    fd = os.open(tmp, os.O_CREAT | os.O_WRONLY | os.O_TRUNC, 0o600)
    try:
        with os.fdopen(fd, "wb") as f:
            f.write(data_bytes)
        os.replace(tmp, p)
    except Exception:
        if tmp.exists():
            try:
                tmp.unlink()
            except OSError:
                pass
        raise
    return p


def load_execution_diagnostics(
    state_dir: pathlib.Path | str,
    request_id: str,
) -> ExecutionDiagnosticRecord | None:
    """Read back execution diagnostic record from protected storage."""
    p = _diag_path(state_dir, request_id)
    if not p.is_file():
        return None
    try:
        data = json.loads(p.read_text(encoding="utf-8"))
        if isinstance(data, dict):
            return ExecutionDiagnosticRecord.from_dict(data)
    except Exception:
        pass
    return None
