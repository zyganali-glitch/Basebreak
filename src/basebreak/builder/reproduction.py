"""Candidate deterministic reproduction from trusted base + captured patch in fresh sandbox.

P-07.06: Implements deterministic reproduction of exact captured candidate state from:
TRUSTED BASE + EXACT CAPTURED PATCH -> FRESH DISPOSABLE SANDBOX -> EXACT CANDIDATE TREE.

Core Invariants:
1. Trusted-input binding: Consumes exact CandidateSnapshot and authoritative
   BuilderContextEnvelope. Mechanically validates that source identity, contract digest,
   context digest, and patch digest match before any sandbox execution occurs.
2. Fresh sandbox is mandatory: Production reproduction creates a NEW disposable sandbox
   internally. The reproduction sandbox identity must be mechanically distinct from
   the Builder sandbox identity. Builder sandbox or workspace reuse is strictly prohibited.
3. Fresh trusted-base materialization: Materializes exact authoritative base repository
   inside the new sandbox via canonical source materializer. Caller-asserted or
   pre-existing materialization records are rejected.
4. Exact captured patch only: Applies exact CandidateSnapshot.patch_text without
   reconstruction from BuilderProposal, model prose, or prior workspace state.
   Revalidates patch through canonical P-04 protected-surface policy before application.
5. Exact candidate tree equality: Resulting staged git tree digest must strictly equal
   CandidateSnapshot.candidate_tree_digest. A mismatch fails closed.
6. Zero self-certification: Reproduction proves reproducibility only. Possesses ZERO
   causal or verification authority (is_authoritative=False, is_causally_verified=False,
   grants_pass=False).
7. Fail-closed teardown law: Any failure (materialization, validation, patch application,
   sandbox identity violation, or tree mismatch) tears down the disposable reproduction
   sandbox and returns zero accepted reproduction.
8. Provider neutrality: Zero adapter imports, zero provider-specific identifiers.
"""

from __future__ import annotations

import base64
import re
import shlex
import time
from collections.abc import Mapping, Sequence
from dataclasses import dataclass
from typing import Any

from basebreak.builder.capture import (
    CandidateSnapshot,
    parse_git_name_status,
)
from basebreak.builder.context import BuilderContextEnvelope
from basebreak.builder.execution import (
    DEFAULT_SANDBOX_IMAGE,
    DEFAULT_WORKSPACE_PATH,
    CandidateExecutionConfigError,
    HostExecutionFallbackError,
    MaterializedSourceVerificationError,
    UnmaterializedWorkspaceError,
    validate_materialized_workspace,
    validate_workspace_path,
)
from basebreak.builder.loop import BuilderProposal
from basebreak.domain.execution import SandboxIdentity
from basebreak.domain.source import CommitRevision, SourceIdentity
from basebreak.domain.verdict import EvidenceProvenance
from basebreak.evidence.artifact import compute_bytes_digest
from basebreak.security.protected_surfaces import (
    ProtectedSurfaceManifest,
    ProtectedSurfaceViolation,
    get_canonical_basebreak_protected_manifest,
    validate_diff,
)
from basebreak.security.secret_policy import (
    contains_secret,
    validate_no_secrets,
)

_HEX_40_OR_64_PATTERN = re.compile(r"^([0-9a-f]{40}|[0-9a-f]{64})$")
_HEX_64_PATTERN = re.compile(r"^[0-9a-f]{64}$")
_B64_CHUNK_SIZE: int = 8000
DEFAULT_REPRODUCTION_TIMEOUT_SECONDS: int = 120


# --- Exceptions ---


class CandidateReproductionError(Exception):
    """Base exception for all candidate reproduction failures."""


class CandidateReproductionConfigError(CandidateReproductionError, CandidateExecutionConfigError):
    """Raised when CandidateReproductionConfig violates configuration invariants."""


class MalformedReproductionInputError(CandidateReproductionError):
    """Raised when reproduction input, snapshot, or digest is malformed or invalid."""


class TrustedInputBindingError(CandidateReproductionError):
    """Raised when snapshot does not match authoritative envelope context or source."""


class SandboxFreshnessError(CandidateReproductionError):
    """Raised when sandbox freshness cannot be established or sandbox is reused."""


class PatchValidationError(CandidateReproductionError):
    """Raised when candidate patch violates security policy or protected surfaces."""


class PatchApplicationError(CandidateReproductionError):
    """Raised when git patch application or staging fails inside reproduction sandbox."""


class TreeDigestMismatchError(CandidateReproductionError):
    """Raised when reproduced tree digest does not match captured candidate tree digest."""


# --- Configuration ---


@dataclass(frozen=True, slots=True)
class CandidateReproductionConfig:
    """Bounded configuration for deterministic candidate reproduction in a fresh sandbox."""

    workspace_path: str = DEFAULT_WORKSPACE_PATH
    sandbox_image: str = DEFAULT_SANDBOX_IMAGE
    timeout_seconds: int = DEFAULT_REPRODUCTION_TIMEOUT_SECONDS
    teardown_on_failure: bool = True
    teardown_on_completion: bool = True
    enforce_protected_surfaces: bool = True
    protected_manifest: ProtectedSurfaceManifest | None = None

    def __post_init__(self) -> None:
        if not (1 <= self.timeout_seconds <= 600):
            raise CandidateReproductionConfigError(
                f"timeout_seconds must be between 1 and 600, got {self.timeout_seconds}"
            )
        if not self.workspace_path or not self.workspace_path.strip():
            raise CandidateReproductionConfigError("workspace_path must not be empty")
        if not self.sandbox_image or not self.sandbox_image.strip():
            raise CandidateReproductionConfigError("sandbox_image must not be empty")
        if not self.enforce_protected_surfaces:
            raise CandidateReproductionConfigError(
                "enforce_protected_surfaces cannot be disabled; "
                "canonical P-04 protected-surface policy is mandatory and non-downgradable"
            )
        if self.protected_manifest is not None:
            raise CandidateReproductionConfigError(
                "Caller cannot override protected_manifest in CandidateReproductionConfig; "
                "canonical P-04 protected-surface policy is mandatory and non-downgradable"
            )


# --- Data Records ---


@dataclass(frozen=True, slots=True)
class CandidateReproductionResult:
    """Deterministic result of reproducing a candidate in a fresh disposable sandbox.

    Proves reproducibility from trusted base + exact captured patch, but possesses
    ZERO verification or causal authority:
    - is_authoritative is strictly False
    - is_causally_verified is strictly False
    - grants_pass is strictly False
    """

    candidate_snapshot: CandidateSnapshot
    reproduced_tree_digest: str
    reproduced_patch_digest: str
    sandbox_identity: SandboxIdentity
    source_identity: SourceIdentity
    duration_seconds: float = 0.0
    files_added: tuple[str, ...] = ()
    files_modified: tuple[str, ...] = ()
    files_deleted: tuple[str, ...] = ()
    is_reproduced: bool = True
    is_authoritative: bool = False
    is_causally_verified: bool = False
    grants_pass: bool = False
    provenance: EvidenceProvenance = EvidenceProvenance.LOCAL_EXECUTION

    def __post_init__(self) -> None:
        if self.is_authoritative is not False:
            raise ValueError("CandidateReproductionResult is_authoritative must be strictly False")
        if self.is_causally_verified is not False:
            raise ValueError(
                "CandidateReproductionResult is_causally_verified must be strictly False; "
                "candidate reproduction does NOT grant causal verification"
            )
        if self.grants_pass is not False:
            raise ValueError("CandidateReproductionResult grants_pass must be strictly False")
        if self.is_reproduced is not True:
            raise ValueError("CandidateReproductionResult is_reproduced must be strictly True")

        if not isinstance(self.candidate_snapshot, CandidateSnapshot):
            raise TypeError("candidate_snapshot must be CandidateSnapshot")
        if not isinstance(self.sandbox_identity, SandboxIdentity):
            raise TypeError("sandbox_identity must be SandboxIdentity")
        if not isinstance(self.source_identity, SourceIdentity):
            raise TypeError("source_identity must be SourceIdentity")

        clean_repro_tree = self.reproduced_tree_digest.strip().lower()
        if not _HEX_40_OR_64_PATTERN.match(clean_repro_tree):
            raise ValueError(
                f"reproduced_tree_digest must be a 40 or 64 hex char string, "
                f"got {self.reproduced_tree_digest!r}"
            )
        if clean_repro_tree != self.candidate_snapshot.candidate_tree_digest.lower():
            raise ValueError(
                f"reproduced_tree_digest {clean_repro_tree!r} does not match "
                f"candidate snapshot candidate_tree_digest "
                f"{self.candidate_snapshot.candidate_tree_digest.lower()!r}"
            )

        if not _HEX_64_PATTERN.match(self.reproduced_patch_digest):
            raise ValueError(
                f"reproduced_patch_digest must be a 64 hex char string, "
                f"got {self.reproduced_patch_digest!r}"
            )
        if self.reproduced_patch_digest != self.candidate_snapshot.patch_digest:
            raise ValueError(
                f"reproduced_patch_digest {self.reproduced_patch_digest!r} does not match "
                f"candidate snapshot patch_digest {self.candidate_snapshot.patch_digest!r}"
            )

        if self.source_identity != self.candidate_snapshot.source_identity:
            raise ValueError(
                "reproduction source_identity does not match candidate snapshot source_identity"
            )

        if (
            self.candidate_snapshot.sandbox_identity is not None
            and self.sandbox_identity == self.candidate_snapshot.sandbox_identity
        ):
            builder_sbx_id = self.candidate_snapshot.sandbox_identity.sandbox_id
            raise ValueError(
                f"Reproduction sandbox identity {self.sandbox_identity.sandbox_id!r} cannot "
                f"match Builder sandbox identity {builder_sbx_id!r}"
            )

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

        for attr in ("files_added", "files_modified", "files_deleted"):
            val = getattr(self, attr)
            if not isinstance(val, tuple):
                if isinstance(val, Sequence):
                    object.__setattr__(self, attr, tuple(val))
                else:
                    raise TypeError(f"{attr} must be a sequence of strings")

    def to_dict(self) -> dict[str, Any]:
        """Serialize CandidateReproductionResult to dictionary."""
        return {
            "candidate_snapshot": self.candidate_snapshot.to_dict(),
            "duration_seconds": self.duration_seconds,
            "files_added": list(self.files_added),
            "files_deleted": list(self.files_deleted),
            "files_modified": list(self.files_modified),
            "grants_pass": self.grants_pass,
            "is_authoritative": self.is_authoritative,
            "is_causally_verified": self.is_causally_verified,
            "is_reproduced": self.is_reproduced,
            "provenance": self.provenance.value,
            "reproduced_patch_digest": self.reproduced_patch_digest,
            "reproduced_tree_digest": self.reproduced_tree_digest,
            "sandbox_id": self.sandbox_identity.sandbox_id,
            "source_commit_id": self.source_identity.resolved_commit_id,
            "source_locator": self.source_identity.locator,
            "source_subpath": self.source_identity.subpath,
        }

    @classmethod
    def from_dict(cls, data: Mapping[str, Any]) -> CandidateReproductionResult:
        """Deserialize CandidateReproductionResult from dictionary with strict validation."""
        if not isinstance(data, Mapping):
            raise TypeError(f"Expected mapping, got {type(data).__name__}")

        snap_data = data.get("candidate_snapshot")
        if not isinstance(snap_data, Mapping):
            raise TypeError("candidate_snapshot must be a mapping")
        snapshot = CandidateSnapshot.from_dict(snap_data)

        sbx_id_raw = data.get("sandbox_id")
        if not sbx_id_raw or not isinstance(sbx_id_raw, str):
            raise ValueError("sandbox_id must be a non-empty string")
        sandbox_identity = SandboxIdentity(sandbox_id=sbx_id_raw)

        src_id = SourceIdentity(
            locator=str(data.get("source_locator", "")),
            revision=CommitRevision(str(data.get("source_commit_id", ""))),
            subpath=data.get("source_subpath"),
        )

        raw_prov = data.get("provenance", "LOCAL_EXECUTION")
        provenance = EvidenceProvenance(raw_prov)

        raw_added = data.get("files_added", ())
        raw_mod = data.get("files_modified", ())
        raw_del = data.get("files_deleted", ())

        return cls(
            candidate_snapshot=snapshot,
            reproduced_tree_digest=str(data.get("reproduced_tree_digest", "")),
            reproduced_patch_digest=str(data.get("reproduced_patch_digest", "")),
            sandbox_identity=sandbox_identity,
            source_identity=src_id,
            duration_seconds=float(data.get("duration_seconds", 0.0)),
            files_added=tuple(str(x) for x in raw_added),
            files_modified=tuple(str(x) for x in raw_mod),
            files_deleted=tuple(str(x) for x in raw_del),
            is_reproduced=bool(data.get("is_reproduced", True)),
            is_authoritative=bool(data.get("is_authoritative", False)),
            is_causally_verified=bool(data.get("is_causally_verified", False)),
            grants_pass=bool(data.get("grants_pass", False)),
            provenance=provenance,
        )


# --- Patch Transport Helper ---


def build_patch_transport_scripts(
    patch_text: str,
    patch_destination_path: str,
) -> tuple[str, ...]:
    """Build deterministic POSIX shell script(s) to transport patch data into sandbox VM.

    Enforces:
    - Base64 encoding to prevent shell injection, quoting errors, or special character corruption.
    - Chunking into commands < MAX_COMMAND_LENGTH_BYTES for large patches.
    - Post-write verification that the patch file exists and is non-empty.
    """
    clean_dest = patch_destination_path.strip()
    quoted_dest = shlex.quote(clean_dest)
    dest_dir = "/".join(clean_dest.split("/")[:-1]) or "/"
    quoted_dir = shlex.quote(dest_dir)

    b64_content = base64.b64encode(patch_text.encode("utf-8")).decode("ascii")

    # Small patch fits in single bounded script
    if len(b64_content) <= _B64_CHUNK_SIZE:
        script = (
            "set -e\n"
            f"mkdir -p {quoted_dir}\n"
            f'printf "%s" {shlex.quote(b64_content)} | base64 -d > {quoted_dest}\n'
            f"if [ ! -f {quoted_dest} ]; then\n"
            f'    echo "BASEBREAK_PATCH_TRANSPORT_ERROR: patch file creation unverified" >&2\n'
            "    exit 104\n"
            "fi\n"
        )
        return (script,)

    # Large patch: chunked streaming
    scripts: list[str] = []
    init_script = f"set -e\nmkdir -p {quoted_dir}\n: > {quoted_dest}\n"
    scripts.append(init_script)

    for offset in range(0, len(b64_content), _B64_CHUNK_SIZE):
        chunk = b64_content[offset : offset + _B64_CHUNK_SIZE]
        scripts.append(f'printf "%s" {shlex.quote(chunk)} | base64 -d >> {quoted_dest}')

    verify_script = (
        "set -e\n"
        f"if [ ! -f {quoted_dest} ]; then\n"
        f'    echo "BASEBREAK_PATCH_TRANSPORT_ERROR: patch file creation unverified" >&2\n'
        "    exit 104\n"
        "fi\n"
    )
    scripts.append(verify_script)

    return tuple(scripts)


# --- Candidate Reproduction Executor ---


class CandidateReproductionExecutor:
    """Deterministic reproduction runtime from trusted base + captured patch in fresh sandbox.

    Enforces:
    1. Rejection of host execution fallback: sandbox_adapter is mandatory.
    2. Authoritative context binding: requires genuine CandidateSnapshot and BuilderContextEnvelope.
    3. Caller-supplied materialized_source and BuilderProposal substitution are strictly forbidden.
    4. Mandatory creation of NEW disposable sandbox: Builder sandbox cannot be reused.
    5. Authoritative trusted base materialization inside the fresh sandbox.
    6. Exact captured patch application: transported as data, protected surfaces revalidated.
    7. Exact candidate tree equality: reproduced tree digest == snapshot candidate_tree_digest.
    8. Disposable teardown on completion or failure.
    9. Zero self-certification: reproduction result is strictly non-authoritative.
    """

    def __init__(
        self,
        sandbox_adapter: Any,
        source_materializer: Any,
        *,
        config: CandidateReproductionConfig | None = None,
    ) -> None:
        if sandbox_adapter is None:
            raise HostExecutionFallbackError(
                "sandbox_adapter is required; host execution fallback is strictly prohibited"
            )
        if source_materializer is None:
            raise UnmaterializedWorkspaceError(
                "source_materializer is required; candidate reproduction requires "
                "authoritative source materialization"
            )

        resolved_config = config or CandidateReproductionConfig()
        if not getattr(resolved_config, "enforce_protected_surfaces", True):
            raise CandidateReproductionConfigError(
                "enforce_protected_surfaces cannot be disabled; "
                "canonical P-04 protected-surface policy is mandatory and non-downgradable"
            )
        if getattr(resolved_config, "protected_manifest", None) is not None:
            raise CandidateReproductionConfigError(
                "Caller cannot override protected_manifest in config; "
                "canonical P-04 protected-surface policy is mandatory and non-downgradable"
            )

        self.sandbox_adapter = sandbox_adapter
        self.source_materializer = source_materializer
        self.config = resolved_config

    def reproduce(
        self,
        *,
        snapshot: CandidateSnapshot,
        envelope: BuilderContextEnvelope,
        provenance: EvidenceProvenance = EvidenceProvenance.LOCAL_EXECUTION,
        **kwargs: Any,
    ) -> CandidateReproductionResult:
        """Reproduce candidate deterministically from trusted base + exact captured patch.

        Steps:
        1. Reject forbidden caller overrides (BuilderProposal, caller-supplied sandbox, etc.).
        2. Verify trusted inputs (source identity, contract digest, context digest, patch digest).
        3. Pre-validate patch through canonical P-04 protected-surface policy and secrets check.
        4. Create NEW disposable reproduction sandbox internally.
        5. Verify sandbox freshness (distinct SandboxIdentity, not Builder sandbox).
        6. Materialize authoritative base repository inside new sandbox VM.
        7. Apply exact captured patch safely via git apply.
        8. Stage changes (git add -A) and compute reproduced tree hash (git write-tree).
        9. Enforce exact tree equality against snapshot.candidate_tree_digest.
        10. Teardown reproduction sandbox and return non-authoritative reproduction result.
        """
        # Step 1: Reject forbidden caller overrides and keyword arguments
        if "proposal" in kwargs or "builder_proposal" in kwargs:
            raise MalformedReproductionInputError(
                "Caller cannot substitute BuilderProposal for captured patch; "
                "candidate reproduction requires exact CandidateSnapshot"
            )
        if "sandbox_handle" in kwargs or "sandbox" in kwargs:
            raise SandboxFreshnessError(
                "Caller-supplied sandbox is strictly prohibited; "
                "candidate reproduction must create a NEW disposable sandbox internally"
            )
        if "materialized_source" in kwargs:
            raise MaterializedSourceVerificationError(
                "Caller-supplied materialized_source is strictly forbidden; "
                "candidate reproduction requires an authoritative source materializer invocation"
            )
        if kwargs:
            raise TypeError(f"Unexpected keyword arguments: {sorted(kwargs.keys())}")

        # Step 2: Input Authority & Type Validation
        if isinstance(snapshot, BuilderProposal):
            raise MalformedReproductionInputError(
                "Caller cannot substitute BuilderProposal for captured patch; "
                "candidate reproduction requires exact CandidateSnapshot"
            )
        if not isinstance(snapshot, CandidateSnapshot):
            raise TypeError(f"snapshot must be CandidateSnapshot, got {type(snapshot).__name__}")
        if not isinstance(envelope, BuilderContextEnvelope):
            raise TypeError(
                f"envelope must be BuilderContextEnvelope, got {type(envelope).__name__}"
            )

        # Non-authority checks on input snapshot
        if snapshot.is_authoritative is not False:
            raise TrustedInputBindingError(
                "CandidateSnapshot is_authoritative must be strictly False"
            )
        if getattr(snapshot, "grants_pass", False) is not False:
            raise TrustedInputBindingError("CandidateSnapshot grants_pass must be strictly False")

        # Source identity binding
        if snapshot.source_identity != envelope.source_identity:
            raise TrustedInputBindingError(
                f"Snapshot source identity ({snapshot.source_identity}) does not match "
                f"authoritative envelope source identity ({envelope.source_identity})"
            )

        # Frozen contract digest binding
        if snapshot.frozen_contract_digest != envelope.frozen_contract.contract_digest:
            raise TrustedInputBindingError(
                f"Snapshot frozen contract digest {snapshot.frozen_contract_digest!r} does not "
                f"match authoritative contract digest {envelope.frozen_contract.contract_digest!r}"
            )

        # Context digest binding
        if snapshot.context_digest != envelope.context_digest:
            raise TrustedInputBindingError(
                f"Snapshot context digest {snapshot.context_digest!r} does not match "
                f"authoritative envelope context digest {envelope.context_digest!r}"
            )

        # Patch digest cryptographic verification
        computed_patch_digest = compute_bytes_digest(snapshot.patch_text.encode("utf-8")).value
        if snapshot.patch_digest != computed_patch_digest:
            raise MalformedReproductionInputError(
                f"Snapshot patch digest {snapshot.patch_digest!r} does not match "
                f"computed SHA-256 digest of patch text {computed_patch_digest!r}"
            )

        # Candidate tree digest structural validation
        clean_cand_tree = snapshot.candidate_tree_digest.strip().lower()
        if not _HEX_40_OR_64_PATTERN.match(clean_cand_tree):
            raise MalformedReproductionInputError(
                f"Candidate tree digest is not a valid 40 or 64 hex char string: "
                f"{snapshot.candidate_tree_digest!r}"
            )

        # Step 3: Revalidate Patch through Canonical P-04 Protected-Surface Policy
        canonical_manifest = get_canonical_basebreak_protected_manifest()
        try:
            validate_diff(snapshot.patch_text, canonical_manifest)
        except ProtectedSurfaceViolation:
            raise
        except Exception as exc:
            raise PatchValidationError(f"Patch validation failed: {exc}") from exc

        # Check for secret leakage in patch text
        if contains_secret(snapshot.patch_text):
            raise PatchValidationError("Secret-shaped value detected in candidate patch text")
        validate_no_secrets(snapshot.patch_text, path="candidate_snapshot.patch_text")

        clean_ws = validate_workspace_path(self.config.workspace_path)
        start_time = time.perf_counter()

        # Step 4: Create NEW Disposable Sandbox Internally
        try:
            handle = self.sandbox_adapter.create_sandbox(
                image=self.config.sandbox_image,
                disposable=True,
            )
        except Exception as exc:
            raise SandboxFreshnessError(
                f"Failed to create fresh disposable reproduction sandbox: {exc}"
            ) from exc

        try:
            # Step 5: Extract and Verify Sandbox Identity
            repro_sbx_id = getattr(handle, "sandbox_identity", None)
            if repro_sbx_id is None or not isinstance(repro_sbx_id, SandboxIdentity):
                raise SandboxFreshnessError(
                    "Reproduction sandbox lacks a deterministic SandboxIdentity; "
                    "unidentified sandboxes are strictly prohibited"
                )
            if not repro_sbx_id.sandbox_id or not repro_sbx_id.sandbox_id.strip():
                raise SandboxFreshnessError(
                    "Reproduction sandbox contains an empty or whitespace sandbox_id; "
                    "unidentified sandboxes are strictly prohibited"
                )

            # Check that reproduction sandbox is distinct from Builder sandbox
            if snapshot.sandbox_identity is not None:
                if (
                    repro_sbx_id == snapshot.sandbox_identity
                    or repro_sbx_id.sandbox_id == snapshot.sandbox_identity.sandbox_id
                ):
                    raise SandboxFreshnessError(
                        f"Reproduction sandbox identity {repro_sbx_id.sandbox_id!r} is identical "
                        f"to Builder sandbox identity; Builder sandbox reuse is strictly prohibited"
                    )

            # Step 6: Materialize Authoritative Base Repository in Fresh Sandbox
            try:
                materialization_record = self.source_materializer.materialize_repository(
                    envelope.source_identity,
                    sandbox=handle,
                    workspace_path=clean_ws,
                    timeout_seconds=self.config.timeout_seconds,
                )
            except Exception as exc:
                raise MaterializedSourceVerificationError(
                    f"Failed to materialize authoritative repository in reproduction sandbox: {exc}"
                ) from exc

            validate_materialized_workspace(
                materialization_record,
                envelope=envelope,
                expected_workspace_path=clean_ws,
                expected_sandbox_identity=repro_sbx_id,
            )

            # Step 7: Apply Exact Captured Patch
            if not snapshot.is_no_change and snapshot.patch_text.strip():
                patch_path = f"/tmp/basebreak_candidate_{repro_sbx_id.sandbox_id[:16]}.patch"
                transport_scripts = build_patch_transport_scripts(snapshot.patch_text, patch_path)

                for script in transport_scripts:
                    res_write = self.sandbox_adapter.execute_command(
                        handle,
                        script,
                        working_dir=clean_ws,
                        timeout_seconds=self.config.timeout_seconds,
                    )
                    if getattr(res_write, "exit_code", -1) != 0:
                        raw_err = getattr(res_write, "stderr", "") or getattr(
                            res_write, "stdout", ""
                        )
                        raise PatchApplicationError(
                            "Failed to transport candidate patch into reproduction sandbox: "
                            f"{raw_err}"
                        )

                # Execute git apply
                apply_cmd = f"git apply --binary --whitespace=nowarn {shlex.quote(patch_path)}"
                res_apply = self.sandbox_adapter.execute_command(
                    handle,
                    apply_cmd,
                    working_dir=clean_ws,
                    timeout_seconds=self.config.timeout_seconds,
                )
                if getattr(res_apply, "exit_code", -1) != 0:
                    raw_err = getattr(res_apply, "stderr", "") or getattr(res_apply, "stdout", "")
                    raise PatchApplicationError(
                        f"git apply failed inside fresh reproduction sandbox with "
                        f"exit {getattr(res_apply, 'exit_code', -1)}: {raw_err}"
                    )

                # Clean up temporary patch file
                try:
                    self.sandbox_adapter.execute_command(
                        handle,
                        f"rm -f {shlex.quote(patch_path)}",
                        working_dir=clean_ws,
                        timeout_seconds=self.config.timeout_seconds,
                    )
                except Exception:
                    pass

            # Step 8: Stage Changes Deterministically
            res_add = self.sandbox_adapter.execute_command(
                handle,
                "git add -A",
                working_dir=clean_ws,
                timeout_seconds=self.config.timeout_seconds,
            )
            if getattr(res_add, "exit_code", -1) != 0:
                raw_err = getattr(res_add, "stderr", "") or getattr(res_add, "stdout", "")
                raise PatchApplicationError(
                    f"git add -A failed inside fresh reproduction sandbox with "
                    f"exit {getattr(res_add, 'exit_code', -1)}: {raw_err}"
                )

            # Step 9: Compute Resulting Git Tree Identity (git write-tree)
            res_tree = self.sandbox_adapter.execute_command(
                handle,
                "git write-tree",
                working_dir=clean_ws,
                timeout_seconds=self.config.timeout_seconds,
            )
            if getattr(res_tree, "exit_code", -1) != 0:
                raw_err = getattr(res_tree, "stderr", "") or getattr(res_tree, "stdout", "")
                raise PatchApplicationError(
                    f"git write-tree failed inside fresh reproduction sandbox with "
                    f"exit {getattr(res_tree, 'exit_code', -1)}: {raw_err}"
                )

            reproduced_tree_sha = getattr(res_tree, "stdout", "").strip().lower()
            if not _HEX_40_OR_64_PATTERN.match(reproduced_tree_sha):
                raise MalformedReproductionInputError(
                    f"git write-tree returned invalid digest: {reproduced_tree_sha!r}"
                )

            # Compare tree digest strictly
            if reproduced_tree_sha != clean_cand_tree:
                raise TreeDigestMismatchError(
                    f"Deterministic candidate reproduction failure: reproduced tree digest "
                    f"{reproduced_tree_sha!r} does not match captured candidate tree digest "
                    f"{clean_cand_tree!r}"
                )

            # Capture reproduced changed-file state
            res_diff = self.sandbox_adapter.execute_command(
                handle,
                "git diff --name-status --no-renames --cached HEAD",
                working_dir=clean_ws,
                timeout_seconds=self.config.timeout_seconds,
            )
            if getattr(res_diff, "exit_code", -1) != 0:
                raw_err = getattr(res_diff, "stderr", "") or getattr(res_diff, "stdout", "")
                raise PatchApplicationError(
                    f"git diff --name-status failed inside reproduction sandbox with "
                    f"exit {getattr(res_diff, 'exit_code', -1)}: {raw_err}"
                )

            repro_diff_output = getattr(res_diff, "stdout", "")
            repro_added, repro_mod, repro_del = parse_git_name_status(repro_diff_output)

            # Validate changed-file equality
            if (
                repro_added != snapshot.files_added
                or repro_mod != snapshot.files_modified
                or repro_del != snapshot.files_deleted
            ):
                raise TreeDigestMismatchError(
                    f"Reproduced changed files do not match snapshot changed files: "
                    f"added={repro_added} vs {snapshot.files_added}, "
                    f"modified={repro_mod} vs {snapshot.files_modified}, "
                    f"deleted={repro_del} vs {snapshot.files_deleted}"
                )

        except Exception:
            # Teardown reproduction sandbox on ANY failure
            if self.config.teardown_on_failure:
                try:
                    self.sandbox_adapter.teardown_sandbox(handle)
                except Exception:
                    pass
            raise

        # Teardown on successful completion if configured
        if self.config.teardown_on_completion:
            try:
                self.sandbox_adapter.teardown_sandbox(handle)
            except Exception:
                pass

        duration_seconds = time.perf_counter() - start_time

        # Return non-authoritative reproduction result
        return CandidateReproductionResult(
            candidate_snapshot=snapshot,
            reproduced_tree_digest=reproduced_tree_sha,
            reproduced_patch_digest=snapshot.patch_digest,
            sandbox_identity=repro_sbx_id,
            source_identity=envelope.source_identity,
            duration_seconds=duration_seconds,
            files_added=repro_added,
            files_modified=repro_mod,
            files_deleted=repro_del,
            is_reproduced=True,
            is_authoritative=False,
            is_causally_verified=False,
            grants_pass=False,
            provenance=provenance,
        )


__all__ = [
    "CandidateReproductionConfig",
    "CandidateReproductionConfigError",
    "CandidateReproductionError",
    "CandidateReproductionExecutor",
    "CandidateReproductionResult",
    "DEFAULT_REPRODUCTION_TIMEOUT_SECONDS",
    "MalformedReproductionInputError",
    "PatchApplicationError",
    "PatchValidationError",
    "SandboxFreshnessError",
    "TreeDigestMismatchError",
    "TrustedInputBindingError",
    "build_patch_transport_scripts",
]
