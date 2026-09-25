"""Sandbox execution security policy derived from proven platform capability.

Codifies Basebreak's bounded execution, network, process, filesystem, and secret
boundaries based strictly on live platform realities proven in P-01 discovery
(disposable VM execution, container image lifecycle, teardown observability,
and outbound HTTPS) while explicitly marking unproven provider guarantees as UNPROVEN.
Integrates with P-04.02 secret redaction and P-04.04 protected surface enforcement.
"""

from __future__ import annotations

import re
from collections.abc import Mapping
from dataclasses import dataclass
from enum import Enum
from typing import Any

from basebreak.security.protected_surfaces import (
    ProtectedSurfaceManifest,
    get_canonical_basebreak_protected_manifest,
    validate_diff,
)
from basebreak.security.secret_policy import (
    SecretPersistenceError,
    find_secret_findings,
    is_sensitive_key,
    validate_no_secrets,
)

# --- Provider-Advertised Limits (Frozen from P-01.03 Live /whoami Observation) ---

PROVIDER_MAX_TIMEOUT_SECONDS: int = 3600
PROVIDER_MAX_CONCURRENCY: int = 50
PROVIDER_MAX_LAYER_BYTES: int = 12_884_901_888  # 12 GB
PROVIDER_IMAGES_IMPORT_MAX_CONCURRENCY: int = 8
PROVIDER_IMAGES_IMPORT_MAX_TIMEOUT: int = 3600

# --- Basebreak Operational Ceilings (Safe Operational Defaults) ---

DEFAULT_SANDBOX_TIMEOUT_SECONDS: int = 180
MAX_SANDBOX_TIMEOUT_SECONDS: int = 600  # Strict operational upper bound (<= 3600)
MIN_SANDBOX_TIMEOUT_SECONDS: int = 1

DEFAULT_SANDBOX_CONCURRENCY: int = 2  # BASE and CANDIDATE parallel runs
MAX_SANDBOX_CONCURRENCY: int = 4  # Operational upper bound (<= 50)

DEFAULT_MAX_OUTPUT_BYTES: int = 65_536  # 64 KB, matches BoundedStreamCapture default
CEILING_MAX_OUTPUT_BYTES: int = 1_048_576  # 1 MB operational ceiling

DEFAULT_MAX_LAYER_BYTES: int = 2_147_483_648  # 2 GB (well below 12 GB provider cap)

MAX_COMMANDS_PER_RUN: int = 10
MAX_COMMAND_LENGTH_BYTES: int = 16_384  # 16 KB command string upper limit


# --- Platform Capabilities & Provenance Taxonomy ---


class CapabilityStatus(str, Enum):
    """Classification of platform capability verification status."""

    PROVEN_SUPPORTED = "PROVEN_SUPPORTED"
    DOCUMENTED_ONLY = "DOCUMENTED_ONLY"
    UNPROVEN = "UNPROVEN"
    UNSUPPORTED = "UNSUPPORTED"


class SandboxCapability(str, Enum):
    """Platform and sandbox execution capabilities investigated in Basebreak."""

    DISPOSABLE_EXECUTION = "DISPOSABLE_EXECUTION"
    CHECKPOINT_SNAPSHOT = "CHECKPOINT_SNAPSHOT"
    FORK_FROM_IMAGE = "FORK_FROM_IMAGE"
    TEARDOWN_OBSERVABILITY = "TEARDOWN_OBSERVABILITY"
    OUTBOUND_HTTPS = "OUTBOUND_HTTPS"
    ARBITRARY_EGRESS_FILTERING = "ARBITRARY_EGRESS_FILTERING"
    INBOUND_NETWORK_ISOLATION = "INBOUND_NETWORK_ISOLATION"
    CPU_HARD_QUOTA = "CPU_HARD_QUOTA"
    MEMORY_HARD_KILL = "MEMORY_HARD_KILL"
    PID_PROCESS_LIMIT = "PID_PROCESS_LIMIT"
    SYSCALL_FILTERING = "SYSCALL_FILTERING"
    FILESYSTEM_MOUNT_RESTRICTIONS = "FILESYSTEM_MOUNT_RESTRICTIONS"
    PROVIDER_SECRET_PROTECTION = "PROVIDER_SECRET_PROTECTION"
    SEALED_VERIFIER_ISOLATION = "SEALED_VERIFIER_ISOLATION"


@dataclass(frozen=True, slots=True)
class CapabilityRecord:
    """Fact record defining the verified status of a platform capability."""

    capability: SandboxCapability
    status: CapabilityStatus
    provenance: str
    description: str
    notes: str


PLATFORM_CAPABILITIES: dict[SandboxCapability, CapabilityRecord] = {
    SandboxCapability.DISPOSABLE_EXECUTION: CapabilityRecord(
        capability=SandboxCapability.DISPOSABLE_EXECUTION,
        status=CapabilityStatus.PROVEN_SUPPORTED,
        provenance="RECORDED_LIVE",
        description=(
            "Disposable VM execution terminates with exit code and leaves no persistent layer."
        ),
        notes="Verified in P-01.03 live run (0.338s duration, result_image_uuid: null).",
    ),
    SandboxCapability.CHECKPOINT_SNAPSHOT: CapabilityRecord(
        capability=SandboxCapability.CHECKPOINT_SNAPSHOT,
        status=CapabilityStatus.PROVEN_SUPPORTED,
        provenance="RECORDED_LIVE",
        description=(
            "Non-disposable execution captures post-command state into an immutable "
            "child image layer."
        ),
        notes="Verified in P-01.03 live run (image UUID 28f5d6d6-... created).",
    ),
    SandboxCapability.FORK_FROM_IMAGE: CapabilityRecord(
        capability=SandboxCapability.FORK_FROM_IMAGE,
        status=CapabilityStatus.PROVEN_SUPPORTED,
        provenance="RECORDED_LIVE",
        description="Spawning new execution instances targeting an existing image UUID.",
        notes="Verified in P-01.03 live run by executing against child snapshot image.",
    ),
    SandboxCapability.TEARDOWN_OBSERVABILITY: CapabilityRecord(
        capability=SandboxCapability.TEARDOWN_OBSERVABILITY,
        status=CapabilityStatus.PROVEN_SUPPORTED,
        provenance="RECORDED_LIVE",
        description=(
            "Account operations stat reflects running instance count returning to 0 "
            "after termination."
        ),
        notes="Verified in P-01.03, P-01.04, and P-01.05 via GET /sandboxes/v1/whoami.",
    ),
    SandboxCapability.OUTBOUND_HTTPS: CapabilityRecord(
        capability=SandboxCapability.OUTBOUND_HTTPS,
        status=CapabilityStatus.PROVEN_SUPPORTED,
        provenance="RECORDED_LIVE",
        description="Outbound network egress over HTTPS is enabled by default.",
        notes="Verified in P-01.04 by cloning github.com repository and downloading uv packages.",
    ),
    SandboxCapability.ARBITRARY_EGRESS_FILTERING: CapabilityRecord(
        capability=SandboxCapability.ARBITRARY_EGRESS_FILTERING,
        status=CapabilityStatus.UNSUPPORTED,
        provenance="OFFICIAL_DOC",
        description=(
            "Granular domain/IP allowlist or denylist egress filtering at the provider layer."
        ),
        notes=(
            "Token Factory Sandboxes API exposes only binary networking enabled/disabled, "
            "no domain filtering."
        ),
    ),
    SandboxCapability.INBOUND_NETWORK_ISOLATION: CapabilityRecord(
        capability=SandboxCapability.INBOUND_NETWORK_ISOLATION,
        status=CapabilityStatus.UNPROVEN,
        provenance="UNPROVEN",
        description=(
            "Platform guarantees on inbound network traffic isolation and port listening behavior."
        ),
        notes="Not tested in P-01; no ingress port forwarding semantics verified.",
    ),
    SandboxCapability.CPU_HARD_QUOTA: CapabilityRecord(
        capability=SandboxCapability.CPU_HARD_QUOTA,
        status=CapabilityStatus.UNPROVEN,
        provenance="UNPROVEN",
        description=(
            "Hard enforcement of CPU core limits or CPU throttling inside the container VM."
        ),
        notes="Live execution recorded consumed CPU duration, but hard quota limits are unproven.",
    ),
    SandboxCapability.MEMORY_HARD_KILL: CapabilityRecord(
        capability=SandboxCapability.MEMORY_HARD_KILL,
        status=CapabilityStatus.UNPROVEN,
        provenance="UNPROVEN",
        description="Deterministic OOM killer behavior when memory exceeds allocated limits.",
        notes=(
            "Live execution recorded memory usage, but OOM kill thresholds are unproven; "
            "no crash probes run."
        ),
    ),
    SandboxCapability.PID_PROCESS_LIMIT: CapabilityRecord(
        capability=SandboxCapability.PID_PROCESS_LIMIT,
        status=CapabilityStatus.UNPROVEN,
        provenance="UNPROVEN",
        description="Platform pids.max or RLIMIT_NPROC ceiling preventing fork-bombs.",
        notes=(
            "Platform PID ceilings (pids.max) and child-process termination semantics "
            "under process explosion are unproven at the provider level. Basebreak "
            "enforces operational timeouts and disposable VM teardown as application "
            "policy, but mechanical containment of fork-bombs remains UNPROVEN "
            "until validated by runtime adapters/probes."
        ),
    ),
    SandboxCapability.SYSCALL_FILTERING: CapabilityRecord(
        capability=SandboxCapability.SYSCALL_FILTERING,
        status=CapabilityStatus.UNPROVEN,
        provenance="UNPROVEN",
        description=(
            "Seccomp, AppArmor, or capability-dropping restrictions on container VM syscalls."
        ),
        notes="Container VM runs as root; specific syscall filtering profiles are unproven.",
    ),
    SandboxCapability.FILESYSTEM_MOUNT_RESTRICTIONS: CapabilityRecord(
        capability=SandboxCapability.FILESYSTEM_MOUNT_RESTRICTIONS,
        status=CapabilityStatus.UNPROVEN,
        provenance="UNPROVEN",
        description="Read-only rootfs or restricted host volume mount isolation.",
        notes="Default rootfs is read-write; fine-grained mount restrictions are unproven.",
    ),
    SandboxCapability.PROVIDER_SECRET_PROTECTION: CapabilityRecord(
        capability=SandboxCapability.PROVIDER_SECRET_PROTECTION,
        status=CapabilityStatus.UNSUPPORTED,
        provenance="POLICY_DERIVED",
        description=(
            "Provider-level memory or environment isolation preventing guest code "
            "from reading secrets."
        ),
        notes=(
            "Target repository runs as root in VM. Provider does not protect secrets "
            "passed to guest."
        ),
    ),
    SandboxCapability.SEALED_VERIFIER_ISOLATION: CapabilityRecord(
        capability=SandboxCapability.SEALED_VERIFIER_ISOLATION,
        status=CapabilityStatus.UNSUPPORTED,
        provenance="POLICY_DERIVED",
        description="Provider-native isolation between builder and verifier challenge assets.",
        notes=(
            "Token Factory is a general sandbox runner. Verifier isolation must be "
            "enforced by Basebreak."
        ),
    ),
}


def get_capability_record(capability: SandboxCapability) -> CapabilityRecord:
    """Retrieve the authoritative capability record for a given capability."""
    return PLATFORM_CAPABILITIES[capability]


def is_capability_proven(capability: SandboxCapability) -> bool:
    """Return True if and only if the capability is proven supported live."""
    return PLATFORM_CAPABILITIES[capability].status == CapabilityStatus.PROVEN_SUPPORTED


# --- Policy Enums & Modes ---


class SandboxExecutionMode(str, Enum):
    """Sandbox execution lifecycle mode."""

    DISPOSABLE = "DISPOSABLE"  # disposable: true (default for verification)
    CHECKPOINT = "CHECKPOINT"  # disposable: false (captures immutable image layer)


class SandboxNetworkMode(str, Enum):
    """Sandbox network egress mode."""

    DISABLED = "DISABLED"  # networking: { "enabled": false }
    EGRESS_REQUIRED = "EGRESS_REQUIRED"  # networking: { "enabled": true }


# --- Exceptions ---


class SandboxPolicyError(Exception):
    """Base exception for all sandbox security policy violations."""


class ResourceBudgetError(SandboxPolicyError):
    """Raised when execution parameters violate resource budgets."""


class NetworkPolicyError(SandboxPolicyError):
    """Raised when execution violates network security policy."""


class ProcessPolicyError(SandboxPolicyError):
    """Raised when execution violates process security policy."""


class FilesystemPolicyError(SandboxPolicyError):
    """Raised when execution violates filesystem or image policy."""


class WorkspaceIsolationError(SandboxPolicyError):
    """Raised when an execution violates two-world clean workspace isolation."""


# --- Resource Budget Contract ---


@dataclass(frozen=True, slots=True)
class SandboxResourceBudget:
    """Resource budget constraints for sandbox execution."""

    timeout_seconds: int = DEFAULT_SANDBOX_TIMEOUT_SECONDS
    max_concurrency: int = DEFAULT_SANDBOX_CONCURRENCY
    max_output_bytes: int = DEFAULT_MAX_OUTPUT_BYTES
    max_layer_bytes: int = DEFAULT_MAX_LAYER_BYTES
    max_commands: int = MAX_COMMANDS_PER_RUN

    def validate(self) -> None:
        """Validate budget against provider limits and Basebreak operational ceilings."""
        if self.timeout_seconds < MIN_SANDBOX_TIMEOUT_SECONDS:
            raise ResourceBudgetError(
                f"timeout_seconds ({self.timeout_seconds}) must be >= {MIN_SANDBOX_TIMEOUT_SECONDS}"
            )
        if self.timeout_seconds > MAX_SANDBOX_TIMEOUT_SECONDS:
            raise ResourceBudgetError(
                f"timeout_seconds ({self.timeout_seconds}) exceeds Basebreak operational ceiling "
                f"of {MAX_SANDBOX_TIMEOUT_SECONDS}s "
                f"(provider limit is {PROVIDER_MAX_TIMEOUT_SECONDS}s)"
            )
        if self.max_concurrency < 1:
            raise ResourceBudgetError(f"max_concurrency ({self.max_concurrency}) must be >= 1")
        if self.max_concurrency > MAX_SANDBOX_CONCURRENCY:
            raise ResourceBudgetError(
                f"max_concurrency ({self.max_concurrency}) exceeds Basebreak operational ceiling "
                f"of {MAX_SANDBOX_CONCURRENCY} (provider limit is {PROVIDER_MAX_CONCURRENCY})"
            )
        if self.max_output_bytes < 1:
            raise ResourceBudgetError(f"max_output_bytes ({self.max_output_bytes}) must be >= 1")
        if self.max_output_bytes > CEILING_MAX_OUTPUT_BYTES:
            raise ResourceBudgetError(
                f"max_output_bytes ({self.max_output_bytes}) exceeds Basebreak ceiling "
                f"of {CEILING_MAX_OUTPUT_BYTES} bytes"
            )
        if self.max_layer_bytes < 1:
            raise ResourceBudgetError(f"max_layer_bytes ({self.max_layer_bytes}) must be >= 1")
        if self.max_layer_bytes > PROVIDER_MAX_LAYER_BYTES:
            raise ResourceBudgetError(
                f"max_layer_bytes ({self.max_layer_bytes}) exceeds provider limit "
                f"of {PROVIDER_MAX_LAYER_BYTES} bytes"
            )
        if self.max_commands < 1:
            raise ResourceBudgetError(f"max_commands ({self.max_commands}) must be >= 1")
        if self.max_commands > MAX_COMMANDS_PER_RUN:
            raise ResourceBudgetError(
                f"max_commands ({self.max_commands}) exceeds Basebreak limit "
                f"of {MAX_COMMANDS_PER_RUN}"
            )

    def to_dict(self) -> dict[str, Any]:
        """Serialize budget to a deterministic dictionary."""
        return {
            "timeout_seconds": self.timeout_seconds,
            "max_concurrency": self.max_concurrency,
            "max_output_bytes": self.max_output_bytes,
            "max_layer_bytes": self.max_layer_bytes,
            "max_commands": self.max_commands,
        }


# --- Image and Command Validators ---

_TAG_IMAGE_PATTERN: re.Pattern[str] = re.compile(r"^tag:[a-zA-Z0-9_\-\./:]+$")
_UUID_IMAGE_PATTERN: re.Pattern[str] = re.compile(
    r"^[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}$|"
    r"^[0-9a-fA-F]{32}$"
)


def validate_image_identifier(image: str) -> None:
    """Validate that the image identifier conforms to tag or UUID format."""
    if not isinstance(image, str) or not image.strip():
        raise FilesystemPolicyError("Sandbox image identifier must be a non-empty string.")
    img = image.strip()
    if not (_TAG_IMAGE_PATTERN.match(img) or _UUID_IMAGE_PATTERN.match(img)):
        raise FilesystemPolicyError(
            f"Invalid sandbox image identifier: '{image}'. Must be a 'tag:<image>' "
            "reference or a valid hexadecimal UUID."
        )


def validate_command_string(command: str) -> None:
    """Validate command string for safety, size bounds, and absence of raw secrets."""
    if not isinstance(command, str) or not command.strip():
        raise ProcessPolicyError("Sandbox command must be a non-empty string.")
    cmd_bytes = command.encode("utf-8")
    if len(cmd_bytes) > MAX_COMMAND_LENGTH_BYTES:
        raise ProcessPolicyError(
            f"Sandbox command size ({len(cmd_bytes)} bytes) exceeds maximum "
            f"allowed length of {MAX_COMMAND_LENGTH_BYTES} bytes."
        )
    if "\x00" in command:
        raise ProcessPolicyError("Sandbox command cannot contain null bytes.")

    # Validate against raw secrets using P-04.02 secret detection
    findings = find_secret_findings(command)
    if findings:
        raise ProcessPolicyError(
            f"Sandbox command contains forbidden secret-shaped value: rule {findings[0].rule_id}."
        )


# --- Sandbox Execution Security Policy ---


@dataclass(frozen=True, slots=True)
class SandboxExecutionPolicy:
    """Frozen security policy governing sandbox executions."""

    budget: SandboxResourceBudget = SandboxResourceBudget()
    default_network_mode: SandboxNetworkMode = SandboxNetworkMode.DISABLED
    allow_network_egress: bool = True
    enforce_clean_workspace: bool = True
    prohibit_mutable_checkpoint_reuse: bool = True
    enforce_secret_policy: bool = True
    enforce_protected_surfaces: bool = True

    def validate_execution_request(
        self,
        *,
        command: str,
        image: str,
        execution_mode: SandboxExecutionMode,
        network_mode: SandboxNetworkMode,
        env: Mapping[str, str] | None = None,
        timeout_seconds: int | None = None,
        diff_content: str | None = None,
        protected_manifest: ProtectedSurfaceManifest | None = None,
        is_verification_run: bool = False,
    ) -> None:
        """Validate an execution request against all policy dimensions.

        Raises:
            ResourceBudgetError: If timeout or budget bounds are violated.
            ProcessPolicyError: If command string violates process policy.
            FilesystemPolicyError: If image or filesystem mode is invalid.
            NetworkPolicyError: If network mode rules or egress secrets are violated.
            WorkspaceIsolationError: If verification run violates clean disposable mode.
            ProtectedSurfaceViolation: If candidate diff mutates protected files.
            SecretPersistenceError: If environment variables contain secrets.
        """
        # 1. Resource Budget Check
        self.budget.validate()
        effective_timeout = (
            timeout_seconds if timeout_seconds is not None else self.budget.timeout_seconds
        )
        if effective_timeout < MIN_SANDBOX_TIMEOUT_SECONDS:
            raise ResourceBudgetError(
                f"effective timeout ({effective_timeout}) must be >= {MIN_SANDBOX_TIMEOUT_SECONDS}"
            )
        if effective_timeout > MAX_SANDBOX_TIMEOUT_SECONDS:
            raise ResourceBudgetError(
                f"effective timeout ({effective_timeout}) exceeds Basebreak ceiling "
                f"of {MAX_SANDBOX_TIMEOUT_SECONDS}s"
            )

        # 2. Image Validation
        validate_image_identifier(image)

        # 3. Command Validation
        validate_command_string(command)

        # 4. Filesystem & Workspace Mode Check
        if is_verification_run and self.enforce_clean_workspace:
            if execution_mode != SandboxExecutionMode.DISPOSABLE:
                raise WorkspaceIsolationError(
                    f"Verification run must use {SandboxExecutionMode.DISPOSABLE.value} mode "
                    f"to guarantee zero workspace bleeding. Got: {execution_mode.value}"
                )

        # 5. Environment & Secret Policy Integration (P-04.02)
        if self.enforce_secret_policy and env:
            for key, val in env.items():
                if is_sensitive_key(key):
                    raise SecretPersistenceError(
                        rule_id="SENSITIVE_KEY",
                        path=f"env.{key}",
                        category="FORBIDDEN_SENSITIVE_KEY",
                    )
            # Use canonical validator from P-04.02
            validate_no_secrets(env, path="sandbox_environment")

        # 6. Network Policy Enforcement
        if network_mode == SandboxNetworkMode.EGRESS_REQUIRED:
            if not self.allow_network_egress:
                raise NetworkPolicyError("Network egress is explicitly disabled by sandbox policy.")
            # Fail-closed secret policy: egress mode MUST NOT contain any sensitive or secret data
            if env:
                findings_env = find_secret_findings(str(env))
                if findings_env:
                    rule = findings_env[0].rule_id
                    raise NetworkPolicyError(
                        f"Network egress execution contains secret finding {rule}."
                    )

        # 7. Protected Surface Diff Validation Integration (P-04.04)
        if self.enforce_protected_surfaces and diff_content is not None:
            manifest = (
                protected_manifest
                if protected_manifest is not None
                else get_canonical_basebreak_protected_manifest()
            )
            # validate_diff raises ProtectedSurfaceViolation if any protected file is touched
            validate_diff(diff_content, manifest)


# --- Two-Clean-Environment Workspace Isolation Authority ---


def validate_two_world_isolation(
    *,
    base_execution_id: str,
    candidate_execution_id: str,
    base_image: str,
    candidate_image: str,
    base_mode: SandboxExecutionMode,
    candidate_mode: SandboxExecutionMode,
) -> None:
    """Validate that BASE and CANDIDATE executions satisfy the two-clean-environment invariant.

    Guarantees:
    1. BASE and CANDIDATE operate in distinct platform execution instances;
    2. Both executions use DISPOSABLE mode (zero workspace bleeding);
    3. Neither execution depends on mutable output from the other.

    Raises:
        WorkspaceIsolationError: If any clean-environment isolation invariant is violated.
    """
    if not base_execution_id or not candidate_execution_id:
        raise WorkspaceIsolationError("Both execution IDs must be non-empty strings.")

    if base_execution_id == candidate_execution_id:
        raise WorkspaceIsolationError(
            f"BASE and CANDIDATE cannot share the same execution identity: '{base_execution_id}'"
        )

    if base_mode != SandboxExecutionMode.DISPOSABLE:
        msg = (
            f"BASE execution must be {SandboxExecutionMode.DISPOSABLE.value}. "
            f"Got: {base_mode.value}"
        )
        raise WorkspaceIsolationError(msg)

    if candidate_mode != SandboxExecutionMode.DISPOSABLE:
        msg = (
            f"CANDIDATE execution must be {SandboxExecutionMode.DISPOSABLE.value}. "
            f"Got: {candidate_mode.value}"
        )
        raise WorkspaceIsolationError(msg)

    validate_image_identifier(base_image)
    validate_image_identifier(candidate_image)
