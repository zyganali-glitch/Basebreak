"""Separate verifier execution sandbox and workspace isolation primitives.

P-08.02: Create separate verifier sandbox/context with no Builder workspace inheritance.

Core Invariants:
1. Fresh sandbox mandatory: Verifier execution must occur in a freshly created sandbox.
   Reusing a Builder sandbox handle or sandbox ID is strictly prohibited.
2. Zero workspace inheritance: Verifier workspace must NOT inherit any Builder mutable files,
   host mounts, or workspace state. Workspace is freshly materialized from trusted source.
3. Deterministic identity: Verifier sandbox identity is independently recorded.
   Missing or ambiguous sandbox identity fails closed.
4. No host-execution fallback: If sandbox creation or execution fails, execution must NEVER
   fall back to the host machine.
5. No simulation fallback: Live execution paths (LIVE_NEBIUS) must NEVER silently fall back
   to mocks or simulation.
6. Zero self-certification: Verifier sandbox session is strictly an isolated
   execution environment, possessing zero causal verification authority
   (is_authoritative=False, is_causally_verified=False).
7. Provider neutrality: Zero adapter imports, zero provider-specific identifiers.
"""

from __future__ import annotations

import inspect
import re
import uuid
from collections.abc import Sequence
from dataclasses import dataclass
from typing import Any

from basebreak.domain.causal import ExecutionWorld
from basebreak.domain.execution import SandboxIdentity
from basebreak.domain.source import SourceIdentity
from basebreak.domain.verdict import EvidenceProvenance
from basebreak.verifier.context import VerifierContextEnvelope

DEFAULT_VERIFIER_WORKSPACE_PATH: str = "/verifier_workspace"
DEFAULT_VERIFIER_SANDBOX_IMAGE: str = "tag:astral/uv:python3.11-alpine"
DEFAULT_VERIFIER_TIMEOUT_SECONDS: int = 120

_HEX_40_OR_64_PATTERN = re.compile(r"^([0-9a-f]{40}|[0-9a-f]{64})$", re.IGNORECASE)


def _prepare_materializer_args(
    fn: Any,
    *,
    source_identity: SourceIdentity,
    created_identity: SandboxIdentity,
    workspace_path: str,
    world: ExecutionWorld,
    context_envelope: VerifierContextEnvelope | None = None,
    candidate_tree_digest: str | None = None,
    sandbox_adapter: Any = None,
) -> tuple[tuple[Any, ...], dict[str, Any]]:
    """Deterministically inspect callable signature and prepare arguments before invocation.

    Prevents broad TypeError trial-and-error retry loops.
    """
    try:
        sig = inspect.signature(fn)
    except (ValueError, TypeError):
        fallback_kwargs: dict[str, Any] = {
            "source_identity": source_identity,
            "sandbox_identity": created_identity,
            "workspace_path": workspace_path,
        }
        if context_envelope is not None:
            fallback_kwargs["context_envelope"] = context_envelope
        return (), fallback_kwargs

    params = sig.parameters
    has_var_keyword = any(p.kind == inspect.Parameter.VAR_KEYWORD for p in params.values())

    available_facts: dict[str, Any] = {
        "source_identity": source_identity,
        "workspace_path": workspace_path,
        "world": world,
    }
    if context_envelope is not None:
        available_facts["context_envelope"] = context_envelope
        available_facts["envelope"] = context_envelope
        if context_envelope.candidate_patch_text is not None:
            available_facts["candidate_patch_text"] = context_envelope.candidate_patch_text
            available_facts["patch_text"] = context_envelope.candidate_patch_text
    if world == ExecutionWorld.CANDIDATE:
        if candidate_tree_digest is not None:
            available_facts["candidate_tree_digest"] = candidate_tree_digest
            available_facts["expected_tree_sha"] = candidate_tree_digest
        elif context_envelope is not None and context_envelope.candidate_tree_digest is not None:
            available_facts["candidate_tree_digest"] = context_envelope.candidate_tree_digest
            available_facts["expected_tree_sha"] = context_envelope.candidate_tree_digest
    if sandbox_adapter is not None:
        available_facts["sandbox_adapter"] = sandbox_adapter
        available_facts["adapter"] = sandbox_adapter

    if "sandbox" in params and "sandbox_identity" not in params:
        available_facts["sandbox"] = created_identity
    elif "sandbox_identity" in params and "sandbox" not in params:
        available_facts["sandbox_identity"] = created_identity
    else:
        available_facts["sandbox_identity"] = created_identity
        if "sandbox" in params or has_var_keyword:
            available_facts["sandbox"] = created_identity

    if has_var_keyword:
        call_kwargs = dict(available_facts)
        call_kwargs["sandbox"] = created_identity
        call_kwargs["sandbox_identity"] = created_identity
        return (), call_kwargs

    call_args: list[Any] = []
    call_kwargs = {}

    for name, param in params.items():
        if param.kind == inspect.Parameter.POSITIONAL_ONLY:
            if name in available_facts:
                call_args.append(available_facts[name])
            elif name in ("source", "repo_source"):
                call_args.append(source_identity)
            elif name in ("workspace", "target_workspace"):
                call_args.append(workspace_path)
            elif name in ("sbx", "sandbox"):
                call_args.append(created_identity)
            else:
                if param.default is inspect.Parameter.empty:
                    raise VerifierMaterializationError(
                        f"Materializer parameter {name!r} cannot be resolved from trusted facts"
                    )
        elif param.kind in (
            inspect.Parameter.POSITIONAL_OR_KEYWORD,
            inspect.Parameter.KEYWORD_ONLY,
        ):
            if name in available_facts:
                call_kwargs[name] = available_facts[name]
            elif name in ("source", "repo_source"):
                call_kwargs[name] = source_identity
            elif name in ("workspace", "target_workspace"):
                call_kwargs[name] = workspace_path
            elif name in ("sbx",):
                call_kwargs[name] = created_identity
            else:
                if param.default is inspect.Parameter.empty:
                    raise VerifierMaterializationError(
                        f"Materializer parameter {name!r} cannot be resolved from trusted facts"
                    )

    return tuple(call_args), call_kwargs


def _extract_materialization_fact(result: Any, *keys: str) -> Any:
    """Extract a named attribute or dict key from a materialization result."""
    for key in keys:
        if isinstance(result, dict) and key in result:
            val = result[key]
            if val is not None:
                return val
        if hasattr(result, key):
            val = getattr(result, key)
            if val is not None:
                return val
    return None


# --- Exceptions ---


class VerifierSandboxError(Exception):
    """Base exception for all verifier sandbox and isolation errors."""


class MissingSandboxIdentityError(VerifierSandboxError):
    """Raised when sandbox identity is missing, empty, whitespace, or invalid."""


class BuilderSandboxReuseError(VerifierSandboxError):
    """Raised when verifier attempts to reuse a Builder sandbox handle or ID."""


class BuilderWorkspaceInheritanceError(VerifierSandboxError):
    """Raised when verifier workspace collides with or inherits from Builder workspace."""


class HostExecutionFallbackError(VerifierSandboxError):
    """Raised when verifier execution attempts to fall back to the host machine."""


class SimulationFallbackError(VerifierSandboxError):
    """Raised when a live-configured execution path silently uses a simulated adapter."""


class VerifierMaterializationError(VerifierSandboxError):
    """Raised when clean repository materialization inside verifier sandbox fails."""


class VerifierTreeDigestMismatchError(VerifierSandboxError):
    """Raised when materialized verifier tree digest does not match expected digest."""


# --- Configuration ---


@dataclass(frozen=True, slots=True)
class VerifierSandboxConfig:
    """Bounded configuration for isolated verifier sandbox creation."""

    workspace_path: str = DEFAULT_VERIFIER_WORKSPACE_PATH
    sandbox_image: str = DEFAULT_VERIFIER_SANDBOX_IMAGE
    timeout_seconds: int = DEFAULT_VERIFIER_TIMEOUT_SECONDS
    teardown_on_failure: bool = True

    def __post_init__(self) -> None:
        if not isinstance(self.workspace_path, str):
            raise TypeError("workspace_path must be a string")
        path = self.workspace_path.strip()
        if not path or not path.startswith("/"):
            raise VerifierSandboxError(
                f"workspace_path must be an absolute POSIX path starting with '/', got {path!r}"
            )
        if (
            isinstance(self.timeout_seconds, bool)
            or not isinstance(self.timeout_seconds, int)
            or self.timeout_seconds <= 0
        ):
            raise VerifierSandboxError("timeout_seconds must be a positive integer")
        if not isinstance(self.teardown_on_failure, bool):
            raise VerifierSandboxError("teardown_on_failure must be a boolean")


# --- Session Record ---


@dataclass(frozen=True, slots=True)
class VerifierSandboxSession:
    """Deterministic record of an isolated verifier sandbox session.

    Possesses ZERO causal verdict authority (is_authoritative=False, is_causally_verified=False).
    """

    session_id: str
    sandbox_identity: SandboxIdentity
    world: ExecutionWorld
    context_digest: str
    workspace_path: str
    materialized_commit_id: str
    materialized_tree_digest: str
    provenance: EvidenceProvenance
    is_authoritative: bool = False
    is_causally_verified: bool = False
    grants_pass: bool = False

    def __post_init__(self) -> None:
        if not isinstance(self.session_id, str) or not self.session_id.strip():
            raise VerifierSandboxError("session_id must be a non-empty string")
        if not isinstance(self.sandbox_identity, SandboxIdentity):
            raise TypeError("sandbox_identity must be an instance of SandboxIdentity")
        if not isinstance(self.world, ExecutionWorld):
            raise TypeError("world must be an instance of ExecutionWorld")
        if not isinstance(self.context_digest, str) or len(self.context_digest) != 64:
            raise VerifierSandboxError("context_digest must be a 64-char hex string")
        if not isinstance(self.workspace_path, str) or not self.workspace_path.startswith("/"):
            raise VerifierSandboxError("workspace_path must be an absolute POSIX path")
        if (
            not isinstance(self.materialized_commit_id, str)
            or len(self.materialized_commit_id) != 40
        ):
            raise VerifierSandboxError("materialized_commit_id must be a 40-char commit SHA")
        if not isinstance(self.materialized_tree_digest, str) or not _HEX_40_OR_64_PATTERN.match(
            self.materialized_tree_digest
        ):
            raise VerifierSandboxError("materialized_tree_digest must be 40 or 64 hex characters")
        if not isinstance(self.provenance, EvidenceProvenance):
            raise TypeError("provenance must be EvidenceProvenance")

        if self.is_authoritative is not False:
            raise VerifierSandboxError("is_authoritative must be strictly False")
        if self.is_causally_verified is not False:
            raise VerifierSandboxError("is_causally_verified must be strictly False")
        if self.grants_pass is not False:
            raise VerifierSandboxError("grants_pass must be strictly False")

    def to_dict(self) -> dict[str, Any]:
        """Serialize session to dictionary."""
        return {
            "context_digest": self.context_digest,
            "grants_pass": self.grants_pass,
            "is_authoritative": self.is_authoritative,
            "is_causally_verified": self.is_causally_verified,
            "materialized_commit_id": self.materialized_commit_id,
            "materialized_tree_digest": self.materialized_tree_digest,
            "provenance": self.provenance.value,
            "sandbox_id": self.sandbox_identity.sandbox_id,
            "session_id": self.session_id,
            "workspace_path": self.workspace_path,
            "world": self.world.value,
        }


# --- Verifier Sandbox Manager ---


class VerifierSandboxManager:
    """Manages creation and validation of isolated Verifier execution sandboxes.

    Enforces that Verifier executes in a clean sandbox with zero Builder state inheritance.
    """

    def __init__(
        self,
        config: VerifierSandboxConfig | None = None,
        *,
        known_builder_sandbox_ids: Sequence[str] = (),
        forbidden_workspace_paths: Sequence[str] = (
            "/workspace",
            "/workspace/candidate",
            "/builder_workspace",
        ),
    ) -> None:
        self.config = config or VerifierSandboxConfig()
        self.known_builder_sandbox_ids = frozenset(
            str(sid).strip() for sid in known_builder_sandbox_ids
        )
        self.forbidden_workspace_paths = frozenset(
            str(p).strip() for p in forbidden_workspace_paths
        )

        # Validate that verifier workspace path does not collide with forbidden builder paths
        if self.config.workspace_path in self.forbidden_workspace_paths:
            raise BuilderWorkspaceInheritanceError(
                f"Verifier workspace path {self.config.workspace_path!r} collides with "
                f"forbidden Builder workspace paths"
            )

    def create_isolated_verifier_sandbox(
        self,
        *,
        context_envelope: VerifierContextEnvelope,
        world: ExecutionWorld,
        sandbox_adapter: Any,
        materializer: Any | None = None,
        candidate_tree_digest: str | None = None,
        provenance: EvidenceProvenance = EvidenceProvenance.LOCAL_EXECUTION,
    ) -> VerifierSandboxSession:
        """Create and materialize a freshly isolated verifier sandbox.

        Guarantees:
        1. Non-null, non-fallback sandbox adapter.
        2. Sandbox identity is valid and distinct from all known Builder sandboxes.
        3. Fresh repository materialization from trusted context envelope.
        4. No inheritance of Builder workspace files or paths.
        5. Exact tree digest verification.
        6. Fail-closed cleanup on any error.
        """
        # 1. World validation
        if not isinstance(world, ExecutionWorld):
            raise TypeError(f"world must be ExecutionWorld, got {type(world).__name__}")
        if world == ExecutionWorld.CANDIDATE and not context_envelope.is_candidate_verification:
            raise VerifierSandboxError(
                "Cannot create CANDIDATE verifier sandbox without candidate data "
                "in context envelope"
            )

        # 2. Host execution fallback prevention
        if sandbox_adapter is None:
            raise HostExecutionFallbackError(
                "Sandbox adapter is None; host execution fallback is strictly prohibited"
            )

        # 3. Provenance & simulation fallback check
        if not isinstance(provenance, EvidenceProvenance):
            raise TypeError(
                f"provenance must be EvidenceProvenance, got {type(provenance).__name__}"
            )

        adapter_name = sandbox_adapter.__class__.__name__
        is_simulated = (
            getattr(sandbox_adapter, "is_simulation", False)
            or "Mock" in adapter_name
            or "Simulat" in adapter_name
        )
        if provenance == EvidenceProvenance.LIVE_NEBIUS and is_simulated:
            raise SimulationFallbackError(
                f"Adapter {adapter_name} is simulated; cannot claim LIVE_NEBIUS provenance"
            )

        # 4. Create fresh sandbox
        created_identity: Any = None
        try:
            if hasattr(sandbox_adapter, "create_sandbox"):
                sbx_fn = sandbox_adapter.create_sandbox
            elif callable(sandbox_adapter):
                sbx_fn = sandbox_adapter
            else:
                raise HostExecutionFallbackError(
                    f"Unsupported sandbox adapter type: {adapter_name}"
                )

            import inspect as _insp

            sig = _insp.signature(sbx_fn)
            params = sig.parameters
            has_var = any(p.kind == _insp.Parameter.VAR_KEYWORD for p in params.values())
            sbx_kwargs: dict[str, Any] = {}
            if "image" in params or has_var:
                sbx_kwargs["image"] = self.config.sandbox_image
            if "timeout_seconds" in params or has_var:
                sbx_kwargs["timeout_seconds"] = self.config.timeout_seconds
            if "disposable" in params or has_var:
                sbx_kwargs["disposable"] = False

            created_identity = sbx_fn(**sbx_kwargs)
        except (HostExecutionFallbackError, SimulationFallbackError):
            raise
        except Exception as exc:
            raise HostExecutionFallbackError(
                f"Failed to create fresh sandbox via adapter: {exc}"
            ) from exc

        # 5. Validate sandbox identity
        if created_identity is None:
            raise MissingSandboxIdentityError("Sandbox adapter returned None sandbox identity")

        # Unwrap if adapter returned a tuple/record with sandbox_identity
        if not isinstance(created_identity, SandboxIdentity):
            if hasattr(created_identity, "sandbox_identity"):
                created_identity = created_identity.sandbox_identity
            elif isinstance(created_identity, str):
                sid_str = created_identity.strip()
                if not sid_str:
                    raise MissingSandboxIdentityError("Sandbox ID string is empty or whitespace")
                created_identity = SandboxIdentity(sandbox_id=sid_str)
            else:
                raise MissingSandboxIdentityError(
                    f"Expected SandboxIdentity, got {type(created_identity).__name__}"
                )

        sid = created_identity.sandbox_id.strip()
        if not sid:
            raise MissingSandboxIdentityError("Sandbox identity string is empty or whitespace")

        # 6. Builder sandbox reuse check
        if sid in self.known_builder_sandbox_ids:
            self._teardown_sandbox(sandbox_adapter, created_identity)
            raise BuilderSandboxReuseError(
                f"Verifier attempted to reuse Builder sandbox identity {sid!r}"
            )

        # 7. Mandatory Materialization & Deterministic Fact Verification
        session_id = f"v-sbx-{uuid.uuid4().hex[:12]}"
        try:
            if materializer is None:
                raise VerifierMaterializationError(
                    "Materializer is mandatory; verifier sandbox session requires deterministic "
                    "repository materialization proof"
                )

            # 1. Resolve target materialization callable deterministically
            target_fn: Any
            if hasattr(materializer, "materialize_clean_base") and callable(
                materializer.materialize_clean_base
            ):
                target_fn = materializer.materialize_clean_base
            elif hasattr(materializer, "materialize_repository") and callable(
                materializer.materialize_repository
            ):
                target_fn = materializer.materialize_repository
            elif callable(materializer):
                target_fn = materializer
            else:
                raise VerifierMaterializationError(
                    f"Invalid materializer: {type(materializer).__name__} is neither callable "
                    f"nor implements materialize_repository / materialize_clean_base"
                )

            # 2. Inspect signature before invocation to prepare arguments deterministically
            call_args, call_kwargs = _prepare_materializer_args(
                target_fn,
                source_identity=context_envelope.source_identity,
                created_identity=created_identity,
                workspace_path=self.config.workspace_path,
                world=world,
                context_envelope=context_envelope,
                candidate_tree_digest=candidate_tree_digest,
                sandbox_adapter=sandbox_adapter,
            )

            # 3. Exactly ONE execution attempt — no retry, no broad TypeError catching
            mat_result = target_fn(*call_args, **call_kwargs)

            if mat_result is None:
                raise VerifierMaterializationError(
                    "Materializer returned None; deterministic materialization proof is required"
                )

            # --- Fact 1: Resolved Commit Verification ---
            actual_commit = _extract_materialization_fact(
                mat_result,
                "resolved_commit_sha",
                "materialized_commit_id",
                "commit_id",
                "commit_sha",
                "commit",
            )
            if (
                actual_commit is None
                or not isinstance(actual_commit, str)
                or not actual_commit.strip()
            ):
                raise VerifierMaterializationError(
                    "Materializer result missing required resolved commit"
                )
            actual_commit = actual_commit.strip()
            if not _HEX_40_OR_64_PATTERN.match(actual_commit):
                raise VerifierMaterializationError(
                    f"Materialized commit {actual_commit!r} is not a valid hex commit hash"
                )
            expected_commit = context_envelope.source_identity.resolved_commit_id
            if actual_commit.lower() != expected_commit.lower():
                raise VerifierMaterializationError(
                    f"Materialized commit {actual_commit!r} does not match authoritative "
                    f"context commit {expected_commit!r}"
                )

            # --- Fact 2: Tree Digest Verification ---
            actual_tree = _extract_materialization_fact(
                mat_result,
                "resolved_tree_sha",
                "materialized_tree_digest",
                "tree_digest",
                "tree_sha",
                "tree",
            )
            if actual_tree is None or not isinstance(actual_tree, str) or not actual_tree.strip():
                raise VerifierMaterializationError(
                    "Materializer result missing required tree digest"
                )
            actual_tree = actual_tree.strip().lower()
            if not _HEX_40_OR_64_PATTERN.match(actual_tree):
                raise VerifierMaterializationError(
                    f"Materialized tree digest is syntactically invalid: {actual_tree!r}"
                )

            # Candidate tree digest verification
            if candidate_tree_digest is not None:
                expected_cand_tree = candidate_tree_digest.strip().lower()
                if actual_tree != expected_cand_tree:
                    raise VerifierTreeDigestMismatchError(
                        f"Materialized tree digest {actual_tree!r} does not match "
                        f"expected candidate tree digest {candidate_tree_digest!r}"
                    )
            elif (
                world == ExecutionWorld.CANDIDATE
                and context_envelope.candidate_tree_digest is not None
            ):
                expected_cand_tree = context_envelope.candidate_tree_digest.strip().lower()
                if actual_tree != expected_cand_tree:
                    raise VerifierTreeDigestMismatchError(
                        f"Materialized candidate tree digest {actual_tree!r} does not match "
                        f"authoritative candidate tree digest {expected_cand_tree!r}"
                    )

            # --- Fact 3: Workspace Path Verification ---
            actual_workspace = _extract_materialization_fact(
                mat_result,
                "workspace_path",
                "workspace",
            )
            if (
                actual_workspace is None
                or not isinstance(actual_workspace, str)
                or not actual_workspace.strip()
            ):
                raise VerifierMaterializationError(
                    "Materializer result missing required workspace_path"
                )
            clean_mat_ws = actual_workspace.strip().rstrip("/")
            clean_expected_ws = self.config.workspace_path.strip().rstrip("/")
            if clean_mat_ws in self.forbidden_workspace_paths:
                raise BuilderWorkspaceInheritanceError(
                    f"Materialized workspace path {actual_workspace!r} collides with "
                    f"forbidden Builder workspace paths"
                )
            if clean_mat_ws != clean_expected_ws:
                raise VerifierMaterializationError(
                    f"Materialized workspace path {actual_workspace!r} does not match "
                    f"isolated verifier workspace path {self.config.workspace_path!r}"
                )

            # --- Fact 4: Source Binding / Locator Verification (where available) ---
            mat_source_obj = _extract_materialization_fact(mat_result, "source_identity")
            if mat_source_obj is not None:
                mat_loc = getattr(mat_source_obj, "locator", None)
                if mat_loc is None and isinstance(mat_source_obj, dict):
                    mat_loc = mat_source_obj.get("locator")
            else:
                mat_loc = _extract_materialization_fact(mat_result, "source_locator", "locator")

            if mat_loc is not None:
                if not isinstance(mat_loc, str) or not mat_loc.strip():
                    raise VerifierMaterializationError(
                        "Materialized source locator is empty or invalid"
                    )
                if mat_loc.strip() != context_envelope.source_identity.locator.strip():
                    raise VerifierMaterializationError(
                        f"Materialized source locator {mat_loc!r} does not match "
                        f"authoritative context locator "
                        f"{context_envelope.source_identity.locator!r}"
                    )

            # --- Fact 5: Sandbox Identity Binding Verification (where available) ---
            mat_sbx = _extract_materialization_fact(
                mat_result,
                "sandbox_identity",
                "sandbox_id",
                "sandbox",
            )
            if mat_sbx is not None:
                if isinstance(mat_sbx, SandboxIdentity):
                    actual_sbx_id = mat_sbx.sandbox_id
                elif hasattr(mat_sbx, "sandbox_id"):
                    actual_sbx_id = getattr(mat_sbx, "sandbox_id")
                elif isinstance(mat_sbx, str):
                    actual_sbx_id = mat_sbx
                else:
                    raise VerifierMaterializationError(
                        "Invalid sandbox identity type in materializer result: "
                        f"{type(mat_sbx).__name__}"
                    )
                actual_sbx_id = actual_sbx_id.strip()
                if not actual_sbx_id:
                    raise VerifierMaterializationError(
                        "Materializer result contains empty sandbox ID"
                    )
                if actual_sbx_id in self.known_builder_sandbox_ids:
                    raise BuilderSandboxReuseError(
                        "Materializer result bound to known Builder sandbox identity "
                        f"{actual_sbx_id!r}"
                    )
                if actual_sbx_id != created_identity.sandbox_id.strip():
                    raise VerifierMaterializationError(
                        f"Materializer result sandbox ID {actual_sbx_id!r} does not match "
                        f"newly created verifier sandbox ID {created_identity.sandbox_id!r}"
                    )

            # --- Fact 6: Verification Status Flag Check (where present) ---
            if hasattr(mat_result, "is_verified"):
                if getattr(mat_result, "is_verified") is not True:
                    raise VerifierMaterializationError(
                        "Materializer result indicates materialization verification failed "
                        f"(is_verified={getattr(mat_result, 'is_verified')!r})"
                    )

            return VerifierSandboxSession(
                session_id=session_id,
                sandbox_identity=created_identity,
                world=world,
                context_digest=context_envelope.context_digest,
                workspace_path=self.config.workspace_path,
                materialized_commit_id=actual_commit,
                materialized_tree_digest=actual_tree,
                provenance=provenance,
                is_authoritative=False,
                is_causally_verified=False,
                grants_pass=False,
            )

        except Exception:
            if self.config.teardown_on_failure:
                self._teardown_sandbox(sandbox_adapter, created_identity)
            raise

    def _teardown_sandbox(self, sandbox_adapter: Any, sandbox_identity: SandboxIdentity) -> None:
        """Safely attempt to teardown sandbox upon failure or isolation breach."""
        try:
            if hasattr(sandbox_adapter, "teardown_sandbox"):
                sandbox_adapter.teardown_sandbox(sandbox_identity)
        except Exception:
            pass
