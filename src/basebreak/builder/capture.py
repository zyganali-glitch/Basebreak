"""Candidate identity, diff, tree hash, and Builder-authored test capture.

P-07.04: Captures exact candidate identity after deterministic workspace mutation
and execution, binding the candidate state to trusted base identity, exact tree hash,
unified diff, and separately identifying Builder-authored tests.

Core Invariants:
1. Deterministic candidate capture: binds base source identity, exact candidate tree
   identity, unified diff identity, and lists of added/modified/deleted files.
2. Builder-Authored Test Law:
   - Builder-authored tests are development evidence only.
   - Distinguishably marked with is_builder_authored=True.
   - Zero verification authority: is_authoritative is strictly False, grants_pass is False.
   - Passing Builder-authored tests never certify the candidate or grant PASS.
3. Cryptographic digest bindings:
   - FrozenContract digest
   - Builder context digest
   - Source/base revision
   - Candidate tree digest
   - Patch digest
4. Fail-closed against malformed candidate evidence or tampered digests.
5. Provider neutrality: zero adapter imports, zero provider-specific identifiers.
"""

from __future__ import annotations

import difflib
import json
import re
from collections.abc import Mapping, Sequence
from dataclasses import dataclass
from typing import Any

from basebreak.builder.execution import (
    CandidateExecutionResult,
    CommandExecutionRecord,
)
from basebreak.builder.loop import BuilderProposal, FileActionType
from basebreak.domain.execution import SandboxIdentity, TerminationStatus
from basebreak.domain.source import CommitRevision, SourceIdentity
from basebreak.domain.verdict import EvidenceProvenance
from basebreak.evidence.artifact import compute_bytes_digest
from basebreak.security.protected_surfaces import normalize_repo_path

_HEX_64_PATTERN = re.compile(r"^[0-9a-f]{64}$")
_HEX_40_OR_64_PATTERN = re.compile(r"^([0-9a-f]{40}|[0-9a-f]{64})$")

_TEST_PATH_PATTERNS = re.compile(
    r"(^|/)(tests?|spec)/|(_test|_spec|\btest_)\w*\.py$",
    re.IGNORECASE,
)
_TEST_COMMAND_PATTERNS = re.compile(
    r"(\bpytest\b|\bunittest\b|\btest\b)",
    re.IGNORECASE,
)


# --- Exceptions ---


class CandidateCaptureError(Exception):
    """Base exception for all candidate capture failures."""


class MalformedCandidateEvidenceError(CandidateCaptureError):
    """Raised when candidate evidence or digests are malformed or invalid."""


class BinaryDiffUnsupportedError(CandidateCaptureError):
    """Raised when binary diff content cannot be canonically represented."""


# --- Data Records ---


@dataclass(frozen=True, slots=True)
class BuilderAuthoredTest:
    """Development evidence of a test authored or executed by the Builder.

    Builder-Authored Test Law:
    - Marked distinguishably as Builder-authored (is_builder_authored=True).
    - Possesses ZERO verification authority (is_authoritative=False, grants_pass=False).
    - Passing tests never grant PASS or certify the candidate.
    """

    path: str
    command: str
    exit_code: int | None
    stdout_digest: str
    stderr_digest: str
    duration_seconds: float | None
    status: TerminationStatus
    is_builder_authored: bool = True
    is_authoritative: bool = False
    grants_pass: bool = False

    def __post_init__(self) -> None:
        if not isinstance(self.path, str) or not self.path.strip():
            raise ValueError("path must be a non-empty string")
        if not isinstance(self.command, str):
            raise TypeError("command must be a str")
        if self.exit_code is not None:
            if not isinstance(self.exit_code, int) or isinstance(self.exit_code, bool):
                raise TypeError("exit_code must be an integer or None")
        if not isinstance(self.stdout_digest, str):
            raise TypeError("stdout_digest must be a str")
        if self.stdout_digest and len(self.stdout_digest) != 64:
            raise ValueError("stdout_digest must be a 64-char hex string or empty")
        if not isinstance(self.stderr_digest, str):
            raise TypeError("stderr_digest must be a str")
        if self.stderr_digest and len(self.stderr_digest) != 64:
            raise ValueError("stderr_digest must be a 64-char hex string or empty")
        if self.duration_seconds is not None:
            if not isinstance(self.duration_seconds, (int, float)) or isinstance(
                self.duration_seconds, bool
            ):
                raise TypeError("duration_seconds must be a float or None")
        if not isinstance(self.status, TerminationStatus):
            raise TypeError(f"status must be TerminationStatus, got {type(self.status).__name__}")
        if self.is_builder_authored is not True:
            raise ValueError("BuilderAuthoredTest is_builder_authored must be strictly True")
        if self.is_authoritative is not False:
            raise ValueError("BuilderAuthoredTest is_authoritative must be strictly False")
        if self.grants_pass is not False:
            raise ValueError("BuilderAuthoredTest grants_pass must be strictly False")

    def to_dict(self) -> dict[str, Any]:
        """Serialize BuilderAuthoredTest to dictionary."""
        return {
            "command": self.command,
            "duration_seconds": self.duration_seconds,
            "exit_code": self.exit_code,
            "grants_pass": self.grants_pass,
            "is_authoritative": self.is_authoritative,
            "is_builder_authored": self.is_builder_authored,
            "path": self.path,
            "status": self.status.value,
            "stderr_digest": self.stderr_digest,
            "stdout_digest": self.stdout_digest,
        }

    @classmethod
    def from_dict(cls, data: Mapping[str, Any]) -> BuilderAuthoredTest:
        """Deserialize BuilderAuthoredTest from dictionary with strict validation."""
        if not isinstance(data, Mapping):
            raise MalformedCandidateEvidenceError(f"Expected mapping, got {type(data).__name__}")

        try:
            raw_status = data.get("status")
            if not isinstance(raw_status, str):
                raise ValueError(f"Invalid status: {raw_status!r}")
            status = TerminationStatus(raw_status)

            exit_code_raw = data.get("exit_code")
            exit_code = int(exit_code_raw) if exit_code_raw is not None else None

            dur_raw = data.get("duration_seconds")
            duration = float(dur_raw) if dur_raw is not None else None

            is_builder = data.get("is_builder_authored", True)
            is_auth = data.get("is_authoritative", False)
            grants_p = data.get("grants_pass", False)

            return cls(
                path=str(data.get("path", "")),
                command=str(data.get("command", "")),
                exit_code=exit_code,
                stdout_digest=str(data.get("stdout_digest", "")),
                stderr_digest=str(data.get("stderr_digest", "")),
                duration_seconds=duration,
                status=status,
                is_builder_authored=is_builder,
                is_authoritative=is_auth,
                grants_pass=grants_p,
            )
        except (ValueError, TypeError, KeyError) as exc:
            raise MalformedCandidateEvidenceError(
                f"Failed to deserialize BuilderAuthoredTest: {exc}"
            ) from exc


@dataclass(frozen=True, slots=True)
class CandidateSnapshot:
    """Deterministic snapshot capturing exact candidate state and cryptographic identity.

    Mechanically and cryptographically binds:
    - candidate_id (str)
    - source_identity (SourceIdentity)
    - candidate_tree_digest (64 hex chars or 40 hex chars for git tree)
    - patch_digest (64 hex chars)
    - patch_text (unified diff string)
    - files_added (tuple of normalized paths, sorted)
    - files_modified (tuple of normalized paths, sorted)
    - files_deleted (tuple of normalized paths, sorted)
    - builder_authored_tests (tuple of BuilderAuthoredTest)
    - frozen_contract_digest (64 hex chars)
    - context_digest (64 hex chars)
    - sandbox_identity (SandboxIdentity | None)
    - duration_seconds (float)
    - provenance (EvidenceProvenance)
    - is_authoritative (strictly False)
    """

    candidate_id: str
    source_identity: SourceIdentity
    candidate_tree_digest: str
    patch_digest: str
    patch_text: str
    files_added: tuple[str, ...]
    files_modified: tuple[str, ...]
    files_deleted: tuple[str, ...]
    builder_authored_tests: tuple[BuilderAuthoredTest, ...]
    frozen_contract_digest: str
    context_digest: str
    sandbox_identity: SandboxIdentity | None = None
    duration_seconds: float = 0.0
    provenance: EvidenceProvenance = EvidenceProvenance.LOCAL_EXECUTION
    is_authoritative: bool = False

    def __post_init__(self) -> None:
        if not isinstance(self.candidate_id, str) or not self.candidate_id.strip():
            raise MalformedCandidateEvidenceError("candidate_id must be a non-empty string")
        if not isinstance(self.source_identity, SourceIdentity):
            s_type = type(self.source_identity).__name__
            raise TypeError(f"source_identity must be SourceIdentity, got {s_type}")
        if not isinstance(self.candidate_tree_digest, str) or not _HEX_40_OR_64_PATTERN.match(
            self.candidate_tree_digest
        ):
            raise MalformedCandidateEvidenceError(
                f"candidate_tree_digest must be a 40 or 64 hex char string, "
                f"got {self.candidate_tree_digest!r}"
            )
        if not isinstance(self.patch_text, str):
            raise TypeError(f"patch_text must be str, got {type(self.patch_text).__name__}")
        if not isinstance(self.patch_digest, str) or not _HEX_64_PATTERN.match(self.patch_digest):
            raise MalformedCandidateEvidenceError(
                f"patch_digest must be a 64 hex char string, got {self.patch_digest!r}"
            )
        computed_patch_digest = compute_bytes_digest(self.patch_text.encode("utf-8")).value
        if self.patch_digest != computed_patch_digest:
            raise MalformedCandidateEvidenceError(
                f"patch_digest {self.patch_digest!r} does not match computed SHA-256 "
                f"digest of patch_text {computed_patch_digest!r}"
            )

        # Validate changed files lists: canonicality, deterministic sorted order,
        # no duplicates, mutually disjoint
        for attr in ("files_added", "files_modified", "files_deleted"):
            val = getattr(self, attr)
            if not isinstance(val, tuple):
                if isinstance(val, Sequence):
                    val = tuple(val)
                    object.__setattr__(self, attr, val)
                else:
                    raise TypeError(f"{attr} must be a sequence of strings")

            for item in val:
                if not isinstance(item, str) or not item.strip():
                    raise MalformedCandidateEvidenceError(
                        f"{attr} entry must be a non-empty string"
                    )
                norm = normalize_repo_path(item)
                if item != norm:
                    raise MalformedCandidateEvidenceError(
                        f"Path in {attr} is not normalized: {item!r} (expected {norm!r})"
                    )

            if len(val) != len(set(val)):
                raise MalformedCandidateEvidenceError(f"Duplicate path detected in {attr}: {val}")

            if list(val) != sorted(val):
                raise MalformedCandidateEvidenceError(
                    f"{attr} must be in deterministic sorted order: {val}"
                )

        set_added = set(self.files_added)
        set_modified = set(self.files_modified)
        set_deleted = set(self.files_deleted)
        if set_added & set_modified:
            raise MalformedCandidateEvidenceError(
                f"files_added and files_modified overlap on: {sorted(set_added & set_modified)}"
            )
        if set_added & set_deleted:
            raise MalformedCandidateEvidenceError(
                f"files_added and files_deleted overlap on: {sorted(set_added & set_deleted)}"
            )
        if set_modified & set_deleted:
            raise MalformedCandidateEvidenceError(
                f"files_modified and files_deleted overlap on: {sorted(set_modified & set_deleted)}"
            )

        if not isinstance(self.builder_authored_tests, tuple):
            if isinstance(self.builder_authored_tests, Sequence):
                object.__setattr__(
                    self, "builder_authored_tests", tuple(self.builder_authored_tests)
                )
            else:
                raise TypeError("builder_authored_tests must be a sequence of BuilderAuthoredTest")
        for t in self.builder_authored_tests:
            if not isinstance(t, BuilderAuthoredTest):
                t_type = type(t).__name__
                raise TypeError(
                    f"builder_authored_tests entry must be BuilderAuthoredTest, got {t_type}"
                )

        if not isinstance(self.frozen_contract_digest, str) or not _HEX_64_PATTERN.match(
            self.frozen_contract_digest
        ):
            raise MalformedCandidateEvidenceError(
                f"frozen_contract_digest must be a 64 hex char string, "
                f"got {self.frozen_contract_digest!r}"
            )
        if not isinstance(self.context_digest, str) or not _HEX_64_PATTERN.match(
            self.context_digest
        ):
            raise MalformedCandidateEvidenceError(
                f"context_digest must be a 64 hex char string, got {self.context_digest!r}"
            )

        if self.sandbox_identity is not None and not isinstance(
            self.sandbox_identity, SandboxIdentity
        ):
            sbx_type = type(self.sandbox_identity).__name__
            raise TypeError(f"sandbox_identity must be SandboxIdentity or None, got {sbx_type}")

        if not isinstance(self.duration_seconds, (int, float)) or isinstance(
            self.duration_seconds, bool
        ):
            raise TypeError("duration_seconds must be a float")
        if self.duration_seconds < 0.0:
            raise ValueError("duration_seconds must not be negative")

        if not isinstance(self.provenance, EvidenceProvenance):
            raise TypeError(
                f"provenance must be EvidenceProvenance, got {type(self.provenance).__name__}"
            )
        if self.is_authoritative is not False:
            raise ValueError("CandidateSnapshot is_authoritative must be strictly False")

    @property
    def total_changed_files_count(self) -> int:
        """Total number of unique files added, modified, or deleted."""
        return len(self.files_added) + len(self.files_modified) + len(self.files_deleted)

    @property
    def is_no_change(self) -> bool:
        """True if the candidate introduced zero file changes relative to base."""
        return self.total_changed_files_count == 0

    def to_dict(self) -> dict[str, Any]:
        """Serialize CandidateSnapshot to dictionary."""
        return {
            "builder_authored_tests": [t.to_dict() for t in self.builder_authored_tests],
            "candidate_id": self.candidate_id,
            "candidate_tree_digest": self.candidate_tree_digest,
            "context_digest": self.context_digest,
            "duration_seconds": self.duration_seconds,
            "files_added": list(self.files_added),
            "files_deleted": list(self.files_deleted),
            "files_modified": list(self.files_modified),
            "frozen_contract_digest": self.frozen_contract_digest,
            "is_authoritative": self.is_authoritative,
            "patch_digest": self.patch_digest,
            "patch_text": self.patch_text,
            "provenance": self.provenance.value,
            "sandbox_id": (self.sandbox_identity.sandbox_id if self.sandbox_identity else None),
            "source_commit_id": self.source_identity.resolved_commit_id,
            "source_locator": self.source_identity.locator,
            "source_subpath": self.source_identity.subpath,
        }

    @classmethod
    def from_dict(cls, data: Mapping[str, Any]) -> CandidateSnapshot:
        """Deserialize CandidateSnapshot from dictionary with strict validation."""
        if not isinstance(data, Mapping):
            raise MalformedCandidateEvidenceError(f"Expected mapping, got {type(data).__name__}")

        try:
            raw_tests = data.get("builder_authored_tests", [])
            if not isinstance(raw_tests, (list, tuple)):
                raise TypeError("builder_authored_tests must be a list")
            tests = tuple(BuilderAuthoredTest.from_dict(t) for t in raw_tests)

            raw_prov = data.get("provenance", "LOCAL_EXECUTION")
            prov = EvidenceProvenance(raw_prov)

            sbx_id_raw = data.get("sandbox_id")
            sbx_id = SandboxIdentity(sandbox_id=str(sbx_id_raw)) if sbx_id_raw else None

            src_id = SourceIdentity(
                locator=str(data.get("source_locator", "")),
                revision=CommitRevision(str(data.get("source_commit_id", ""))),
                subpath=data.get("source_subpath"),
            )

            raw_added = data.get("files_added", ())
            raw_mod = data.get("files_modified", ())
            raw_del = data.get("files_deleted", ())
            if (
                not isinstance(raw_added, (list, tuple))
                or not isinstance(raw_mod, (list, tuple))
                or not isinstance(raw_del, (list, tuple))
            ):
                raise TypeError(
                    "files_added, files_modified, files_deleted must be lists or tuples"
                )

            return cls(
                candidate_id=str(data.get("candidate_id", "")),
                source_identity=src_id,
                candidate_tree_digest=str(data.get("candidate_tree_digest", "")),
                patch_digest=str(data.get("patch_digest", "")),
                patch_text=str(data.get("patch_text", "")),
                files_added=tuple(str(x) for x in raw_added),
                files_modified=tuple(str(x) for x in raw_mod),
                files_deleted=tuple(str(x) for x in raw_del),
                builder_authored_tests=tests,
                frozen_contract_digest=str(data.get("frozen_contract_digest", "")),
                context_digest=str(data.get("context_digest", "")),
                sandbox_identity=sbx_id,
                duration_seconds=float(data.get("duration_seconds", 0.0)),
                provenance=prov,
                is_authoritative=False,
            )
        except (ValueError, TypeError, KeyError) as exc:
            raise MalformedCandidateEvidenceError(
                f"Failed to deserialize CandidateSnapshot: {exc}"
            ) from exc


# --- Deterministic Diff & Tree Identity Primitives ---


def generate_unified_diff(
    base_files: Mapping[str, str | bytes],
    candidate_files: Mapping[str, str | bytes],
) -> str:
    """Generate deterministic canonical unified diff between base and candidate files.

    Enforces:
    - Canonical sorting of file paths.
    - Standard unified diff format with 'a/{path}' and 'b/{path}'.
    - Additions: '--- /dev/null' to '+++ b/{path}'.
    - Deletions: '--- a/{path}' to '+++ /dev/null'.
    - Trailing newlines normalized.
    - Binary content rejection.
    """
    all_paths = sorted(set(base_files.keys()) | set(candidate_files.keys()))
    diff_chunks: list[str] = []

    for path in all_paths:
        norm_path = normalize_repo_path(path)
        base_raw = base_files.get(path)
        cand_raw = candidate_files.get(path)

        if base_raw == cand_raw:
            continue

        base_content: str | None = None
        if base_raw is not None:
            if isinstance(base_raw, bytes):
                try:
                    base_content = base_raw.decode("utf-8")
                except UnicodeDecodeError as exc:
                    raise BinaryDiffUnsupportedError(
                        f"Binary file cannot be represented in unified diff: {norm_path}"
                    ) from exc
            else:
                base_content = base_raw
            if "\x00" in base_content:
                raise BinaryDiffUnsupportedError(
                    f"File with null bytes cannot be represented in unified diff: {norm_path}"
                )

        cand_content: str | None = None
        if cand_raw is not None:
            if isinstance(cand_raw, bytes):
                try:
                    cand_content = cand_raw.decode("utf-8")
                except UnicodeDecodeError as exc:
                    raise BinaryDiffUnsupportedError(
                        f"Binary file cannot be represented in unified diff: {norm_path}"
                    ) from exc
            else:
                cand_content = cand_raw
            if "\x00" in cand_content:
                raise BinaryDiffUnsupportedError(
                    f"File with null bytes cannot be represented in unified diff: {norm_path}"
                )

        base_lines = base_content.splitlines(keepends=True) if base_content is not None else []
        cand_lines = cand_content.splitlines(keepends=True) if cand_content is not None else []

        from_file = f"a/{norm_path}" if base_content is not None else "/dev/null"
        to_file = f"b/{norm_path}" if cand_content is not None else "/dev/null"

        hunks = list(
            difflib.unified_diff(
                base_lines,
                cand_lines,
                fromfile=from_file,
                tofile=to_file,
                lineterm="\n",
            )
        )
        if hunks:
            diff_chunks.append("".join(hunks))

    return "".join(diff_chunks)


def compute_tree_digest(files: Mapping[str, str | bytes]) -> str:
    """Compute deterministic content-addressed SHA-256 tree digest of candidate files.

    Enforces:
    - Canonical path sorting.
    - Normalization of all repository-relative paths.
    - Individual file content digest computation.
    - Composition into canonical payload before root hashing.
    """
    sorted_paths = sorted(files.keys())
    entries: list[dict[str, str]] = []

    for path in sorted_paths:
        norm_path = normalize_repo_path(path)
        content = files[path]
        content_bytes = content.encode("utf-8") if isinstance(content, str) else content
        digest = compute_bytes_digest(content_bytes).value
        entries.append({"digest": digest, "path": norm_path})

    tree_payload = json.dumps(
        {"entries": entries},
        sort_keys=True,
        separators=(",", ":"),
        ensure_ascii=False,
    ).encode("utf-8")
    return compute_bytes_digest(tree_payload).value


def identify_builder_authored_tests(
    execution_result: CandidateExecutionResult,
) -> tuple[BuilderAuthoredTest, ...]:
    """Identify Builder-authored tests from candidate mutations and command executions.

    Builder-Authored Test Law:
    - Tests added or modified by Builder are flagged as Builder-authored.
    - Classification ORIGINATES strictly from Builder-created/modified test files.
    - Broad/generic test commands (e.g. pytest) never manufacture a BuilderAuthoredTest
      when zero Builder-authored test files exist.
    - Zero verification authority:
      is_builder_authored=True, is_authoritative=False, grants_pass=False.
    """
    builder_test_files: set[str] = set()
    for mut in execution_result.file_mutations:
        if _TEST_PATH_PATTERNS.search(mut.path) and mut.action != FileActionType.DELETE:
            builder_test_files.add(normalize_repo_path(mut.path))

    # If Builder authored zero test files, NO tests can be classified as Builder-authored
    if not builder_test_files:
        return ()

    tests: list[BuilderAuthoredTest] = []
    executed_test_files: set[str] = set()

    for tf in sorted(builder_test_files):
        tf_basename = tf.split("/")[-1]
        matching_commands: list[CommandExecutionRecord] = []

        # 1. Look for commands specifically mentioning tf or its basename
        for cmd in execution_result.command_executions:
            if tf in cmd.command or (
                tf_basename in cmd.command and _TEST_COMMAND_PATTERNS.search(cmd.command)
            ):
                matching_commands.append(cmd)

        # 2. If no command explicitly mentioned tf, check for broad test commands
        if not matching_commands:
            for cmd in execution_result.command_executions:
                if _TEST_COMMAND_PATTERNS.search(cmd.command):
                    # Check if command targets another specific test file
                    targets_other = False
                    for part in cmd.command.split():
                        part_clean = part.strip()
                        if (
                            _TEST_PATH_PATTERNS.search(part_clean)
                            and part_clean != tf
                            and part_clean != tf_basename
                        ):
                            targets_other = True
                            break
                    if not targets_other:
                        matching_commands.append(cmd)

        for cmd in matching_commands:
            executed_test_files.add(tf)
            tests.append(
                BuilderAuthoredTest(
                    path=tf,
                    command=cmd.command,
                    exit_code=cmd.exit_code,
                    stdout_digest=cmd.stdout_digest,
                    stderr_digest=cmd.stderr_digest,
                    duration_seconds=cmd.duration_seconds,
                    status=cmd.status,
                    is_builder_authored=True,
                    is_authoritative=False,
                    grants_pass=False,
                )
            )

        # 3. If tf was not executed by any command, record as unexecuted
        if tf not in executed_test_files:
            tests.append(
                BuilderAuthoredTest(
                    path=tf,
                    command="",
                    exit_code=None,
                    stdout_digest="",
                    stderr_digest="",
                    duration_seconds=None,
                    status=TerminationStatus.FAILED_TO_START,
                    is_builder_authored=True,
                    is_authoritative=False,
                    grants_pass=False,
                )
            )

    return tuple(sorted(tests, key=lambda t: (t.path, t.command)))


# --- Candidate Capture Implementation ---


def capture_candidate_from_files(
    *,
    base_files: Mapping[str, str | bytes],
    candidate_files: Mapping[str, str | bytes],
    source_identity: SourceIdentity,
    frozen_contract_digest: str,
    context_digest: str,
    builder_authored_tests: Sequence[BuilderAuthoredTest] = (),
    sandbox_identity: SandboxIdentity | None = None,
    duration_seconds: float = 0.0,
    provenance: EvidenceProvenance = EvidenceProvenance.LOCAL_EXECUTION,
    candidate_id: str | None = None,
) -> CandidateSnapshot:
    """Capture candidate snapshot deterministically from base and candidate file mappings.

    In-memory file mappings represent deterministic non-live helper evidence only.
    Permits only non-live provenance (LOCAL_EXECUTION or FIXTURE).
    Fails closed if LIVE_NEBIUS or RECORDED_LIVE provenance is supplied.
    """
    if not isinstance(provenance, EvidenceProvenance):
        raise TypeError(f"provenance must be EvidenceProvenance, got {type(provenance).__name__}")
    if provenance in (EvidenceProvenance.LIVE_NEBIUS, EvidenceProvenance.RECORDED_LIVE):
        raise MalformedCandidateEvidenceError(
            f"In-memory file mapping capture cannot be assigned live provenance "
            f"{provenance.value!r}; live candidate state must be captured from sandbox"
        )
    if provenance not in (EvidenceProvenance.LOCAL_EXECUTION, EvidenceProvenance.FIXTURE):
        raise MalformedCandidateEvidenceError(
            f"Unsupported provenance {provenance.value!r} for in-memory file mapping capture; "
            f"must be {EvidenceProvenance.LOCAL_EXECUTION.value} or "
            f"{EvidenceProvenance.FIXTURE.value}"
        )

    norm_base = {normalize_repo_path(p): v for p, v in base_files.items()}
    norm_cand = {normalize_repo_path(p): v for p, v in candidate_files.items()}

    added: list[str] = []
    modified: list[str] = []
    deleted: list[str] = []

    for path, cand_val in norm_cand.items():
        if path not in norm_base:
            added.append(path)
        elif cand_val != norm_base[path]:
            modified.append(path)

    for path in norm_base:
        if path not in norm_cand:
            deleted.append(path)

    added.sort()
    modified.sort()
    deleted.sort()

    diff_text = generate_unified_diff(norm_base, norm_cand)
    patch_digest = compute_bytes_digest(diff_text.encode("utf-8")).value
    tree_digest = compute_tree_digest(norm_cand)
    cid = candidate_id or f"cand-{patch_digest[:16]}"

    return CandidateSnapshot(
        candidate_id=cid,
        source_identity=source_identity,
        candidate_tree_digest=tree_digest,
        patch_digest=patch_digest,
        patch_text=diff_text,
        files_added=tuple(added),
        files_modified=tuple(modified),
        files_deleted=tuple(deleted),
        builder_authored_tests=tuple(builder_authored_tests),
        frozen_contract_digest=frozen_contract_digest,
        context_digest=context_digest,
        sandbox_identity=sandbox_identity,
        duration_seconds=duration_seconds,
        provenance=provenance,
        is_authoritative=False,
    )


def capture_candidate_from_execution(
    execution_result: CandidateExecutionResult,
    base_files: Mapping[str, str | bytes],
    *,
    candidate_files: Mapping[str, str | bytes] | None = None,
    proposal: BuilderProposal | None = None,
    candidate_id: str | None = None,
) -> CandidateSnapshot:
    """Capture candidate snapshot deterministically from execution result and base files.

    Enforces actual-state candidate identity:
    - In-memory file mapping capture fails closed if execution_result has live provenance
      (LIVE_NEBIUS or RECORDED_LIVE); live candidate state must be captured directly from
      sandbox via capture_candidate_from_sandbox.
    - Deriving candidate identity from BuilderProposal is strictly forbidden and fails closed.
    - Actual candidate state must be provided via candidate_files mapping or direct sandbox capture.
    """
    if not isinstance(execution_result, CandidateExecutionResult):
        r_type = type(execution_result).__name__
        raise TypeError(f"execution_result must be CandidateExecutionResult, got {r_type}")

    if execution_result.provenance in (
        EvidenceProvenance.LIVE_NEBIUS,
        EvidenceProvenance.RECORDED_LIVE,
    ):
        raise MalformedCandidateEvidenceError(
            f"Cannot capture candidate from in-memory file mapping for live execution provenance "
            f"{execution_result.provenance.value!r}; live candidate state must be captured "
            "directly from sandbox via capture_candidate_from_sandbox"
        )

    if proposal is not None:
        raise MalformedCandidateEvidenceError(
            "Deriving candidate identity from BuilderProposal is strictly forbidden; "
            "candidate identity must reflect actual post-execution filesystem state"
        )

    if candidate_files is not None:
        resolved_cand = dict(candidate_files)
    else:
        if not execution_result.file_mutations:
            resolved_cand = dict(base_files)
        else:
            raise MalformedCandidateEvidenceError(
                "candidate_files must be provided to capture candidate state when mutations exist; "
                "reconstructing candidate state from proposal is strictly forbidden"
            )

    builder_tests = identify_builder_authored_tests(execution_result)

    return capture_candidate_from_files(
        base_files=base_files,
        candidate_files=resolved_cand,
        source_identity=execution_result.source_identity,
        frozen_contract_digest=execution_result.frozen_contract_digest,
        context_digest=execution_result.context_digest,
        builder_authored_tests=builder_tests,
        sandbox_identity=execution_result.sandbox_identity,
        duration_seconds=execution_result.total_duration_seconds,
        provenance=execution_result.provenance,
        candidate_id=candidate_id,
    )


def parse_git_name_status(
    status_output: str,
) -> tuple[tuple[str, ...], tuple[str, ...], tuple[str, ...]]:
    """Parse git diff --name-status output into added, modified, deleted file tuples.

    Enforces deterministic sorting, normalization, and mutual disjointness.
    Renames/copies are represented deterministically: old path = deleted, new path = added.
    """
    added_set: set[str] = set()
    modified_set: set[str] = set()
    deleted_set: set[str] = set()

    for line in status_output.splitlines():
        trimmed = line.strip()
        if not trimmed:
            continue
        parts = trimmed.split("\t") if "\t" in trimmed else trimmed.split(maxsplit=2)
        status_code = parts[0].strip()
        if len(parts) < 2:
            raise MalformedCandidateEvidenceError(f"Malformed git name-status line: {line!r}")
        path = parts[1].strip()
        if not path:
            raise MalformedCandidateEvidenceError(f"Empty path in git name-status line: {line!r}")

        if status_code.startswith("A") or status_code == "??":
            added_set.add(normalize_repo_path(path))
        elif status_code.startswith("M"):
            modified_set.add(normalize_repo_path(path))
        elif status_code.startswith("D"):
            deleted_set.add(normalize_repo_path(path))
        elif status_code.startswith("R"):
            # Rename: old path = deleted, new path = added
            deleted_set.add(normalize_repo_path(path))
            if len(parts) >= 3 and parts[2].strip():
                added_set.add(normalize_repo_path(parts[2].strip()))
            else:
                raise MalformedCandidateEvidenceError(
                    f"Git rename status line missing target path: {line!r}"
                )
        elif status_code.startswith("C"):
            # Copy: target path = added
            if len(parts) >= 3 and parts[2].strip():
                added_set.add(normalize_repo_path(parts[2].strip()))
            else:
                added_set.add(normalize_repo_path(path))
        elif status_code.startswith("T"):
            # Type change: treated as modified
            modified_set.add(normalize_repo_path(path))
        else:
            raise MalformedCandidateEvidenceError(
                f"Unrecognized git name-status code {status_code!r} in line: {line!r}"
            )

    modified_set -= added_set
    deleted_set -= added_set | modified_set

    return (
        tuple(sorted(added_set)),
        tuple(sorted(modified_set)),
        tuple(sorted(deleted_set)),
    )


def capture_candidate_from_sandbox(
    sandbox_adapter: Any,
    sandbox_handle: Any,
    execution_result: CandidateExecutionResult,
    *,
    workspace_path: str | None = None,
    candidate_id: str | None = None,
    timeout_seconds: int = 60,
) -> CandidateSnapshot:
    """Capture candidate snapshot directly from disposable candidate sandbox via git.

    Enforces:
    1. sandbox_handle exposes deterministic SandboxIdentity.
    2. sandbox_handle.sandbox_identity strictly equals execution_result.sandbox_identity.
    3. exact workspace binding to execution_result.workspace_path.
    4. separate bounded commands against the same sandbox handle and workspace
       for deterministic facts:
       - git rev-parse --show-toplevel
       - git rev-parse HEAD
       - git add -A
       - git write-tree
       - git diff --name-status --no-renames --cached HEAD
       - git diff --binary --full-index --cached HEAD
    5. diff command stdout becomes patch_text directly (no regex sentinel extraction).
    6. reproducible git binary patch or fail closed with BinaryDiffUnsupportedError.
    7. rename semantics: rename old.py -> new.py is preserved deterministically as
       old=deleted, new=added.
    """
    if sandbox_adapter is None:
        raise MalformedCandidateEvidenceError("sandbox_adapter must not be None")
    if sandbox_handle is None:
        raise MalformedCandidateEvidenceError("sandbox_handle must not be None")
    if not isinstance(execution_result, CandidateExecutionResult):
        r_type = type(execution_result).__name__
        raise TypeError(f"execution_result must be CandidateExecutionResult, got {r_type}")

    # 1 & 2. Sandbox identity validation
    handle_sbx_id = getattr(sandbox_handle, "sandbox_identity", None)
    if handle_sbx_id is None or not isinstance(handle_sbx_id, SandboxIdentity):
        raise MalformedCandidateEvidenceError(
            "sandbox_handle lacks a valid deterministic SandboxIdentity"
        )
    if not handle_sbx_id.sandbox_id or not handle_sbx_id.sandbox_id.strip():
        raise MalformedCandidateEvidenceError(
            "sandbox_handle contains an empty or whitespace sandbox_id"
        )
    if handle_sbx_id != execution_result.sandbox_identity:
        raise MalformedCandidateEvidenceError(
            f"Sandbox identity mismatch: sandbox_handle has {handle_sbx_id.sandbox_id!r}, "
            f"but execution_result has {execution_result.sandbox_identity.sandbox_id!r}"
        )

    # 3. Exact workspace binding
    expected_ws = execution_result.workspace_path.rstrip("/")
    if not expected_ws:
        raise MalformedCandidateEvidenceError("workspace_path must not be empty")
    if workspace_path is not None and workspace_path.rstrip("/") != expected_ws:
        raise MalformedCandidateEvidenceError(
            f"Workspace path mismatch: provided workspace {workspace_path!r} does not "
            f"match execution_result.workspace_path {execution_result.workspace_path!r}"
        )
    clean_ws = expected_ws
    bounded_timeout = min(max(timeout_seconds, 1), 600)

    def _run_cmd(cmd: str) -> str:
        try:
            res = sandbox_adapter.execute_command(
                sandbox_handle,
                cmd,
                working_dir=clean_ws,
                timeout_seconds=bounded_timeout,
            )
        except Exception as exc:
            raise CandidateCaptureError(
                f"Failed to execute capture command {cmd!r} in sandbox: {exc}"
            ) from exc

        if res is None:
            raise CandidateCaptureError(
                f"Sandbox execution returned None for capture command {cmd!r}"
            )

        exit_code = getattr(res, "exit_code", -1)
        if exit_code != 0:
            raw_stderr = getattr(res, "stderr", "")
            raise CandidateCaptureError(
                f"Candidate capture command {cmd!r} failed inside sandbox with "
                f"exit {exit_code}: {raw_stderr}"
            )
        return getattr(res, "stdout", "")

    # 4a. Verify repo top-level matches expected workspace
    toplevel_raw = _run_cmd("git rev-parse --show-toplevel")
    actual_toplevel = toplevel_raw.strip().rstrip("/")
    if not actual_toplevel:
        raise MalformedCandidateEvidenceError(
            "Could not parse git repo top-level from sandbox capture output"
        )
    if actual_toplevel != clean_ws:
        raise MalformedCandidateEvidenceError(
            f"Sandbox git repository top-level {actual_toplevel!r} does not match "
            f"expected candidate workspace {clean_ws!r}"
        )

    # 4b. Verify git HEAD matches execution_result.source_identity.resolved_commit_id
    head_raw = _run_cmd("git rev-parse HEAD")
    actual_head = head_raw.strip().lower()
    if not _HEX_40_OR_64_PATTERN.match(actual_head):
        raise MalformedCandidateEvidenceError(
            f"Could not parse valid git HEAD commit hash from sandbox capture output: {head_raw!r}"
        )
    expected_head = execution_result.source_identity.resolved_commit_id.lower()
    if actual_head != expected_head:
        raise MalformedCandidateEvidenceError(
            f"Sandbox git HEAD {actual_head!r} does not match expected "
            f"source commit {expected_head!r}"
        )

    # 4c. Stage all working tree changes
    _run_cmd("git add -A")

    # 4d. Write tree and get tree SHA
    tree_raw = _run_cmd("git write-tree")
    tree_sha = tree_raw.strip().lower()
    if not _HEX_40_OR_64_PATTERN.match(tree_sha):
        raise MalformedCandidateEvidenceError(
            f"Could not parse valid git write-tree hash from sandbox capture output: {tree_raw!r}"
        )

    # 4e. Changed-file status via --name-status --no-renames --cached HEAD
    name_status_raw = _run_cmd("git diff --name-status --no-renames --cached HEAD")
    files_added, files_modified, files_deleted = parse_git_name_status(name_status_raw)

    # 4f. Full binary diff via --binary --full-index --cached HEAD
    # Stdout itself becomes patch_text directly (no sentinel delimiters)
    diff_text = _run_cmd("git diff --binary --full-index --cached HEAD")
    if re.search(r"Binary files\s+.*\s+differ", diff_text):
        raise BinaryDiffUnsupportedError(
            "Non-reproducible binary diff detected: git reported binary files differ "
            "without reproducible binary patch"
        )
    patch_digest = compute_bytes_digest(diff_text.encode("utf-8")).value

    # Identify Builder-authored tests
    builder_tests = identify_builder_authored_tests(execution_result)

    cid = candidate_id or f"cand-{patch_digest[:16]}"

    return CandidateSnapshot(
        candidate_id=cid,
        source_identity=execution_result.source_identity,
        candidate_tree_digest=tree_sha,
        patch_digest=patch_digest,
        patch_text=diff_text,
        files_added=files_added,
        files_modified=files_modified,
        files_deleted=files_deleted,
        builder_authored_tests=builder_tests,
        frozen_contract_digest=execution_result.frozen_contract_digest,
        context_digest=execution_result.context_digest,
        sandbox_identity=execution_result.sandbox_identity,
        duration_seconds=execution_result.total_duration_seconds,
        provenance=execution_result.provenance,
        is_authoritative=False,
    )


__all__ = [
    "BinaryDiffUnsupportedError",
    "BuilderAuthoredTest",
    "CandidateCaptureError",
    "CandidateSnapshot",
    "MalformedCandidateEvidenceError",
    "capture_candidate_from_execution",
    "capture_candidate_from_files",
    "capture_candidate_from_sandbox",
    "compute_tree_digest",
    "generate_unified_diff",
    "identify_builder_authored_tests",
    "parse_git_name_status",
]
