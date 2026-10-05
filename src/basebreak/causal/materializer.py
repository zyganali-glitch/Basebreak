"""Canonical repository materializer for causal two-world verification.

P-10.01: Materialize trusted base repository in isolated sandbox.
P-10.02: Materialize exact candidate state from trusted base + captured patch
         using canonical P-07 candidate reproduction authority.

Invariants:
1. Clean base materialization strictly from authoritative SourceIdentity.
2. Canonical P-04 protected-surface enforcement prior to patch application.
3. Canonical secret safety enforcement.
4. Exact bit-for-bit candidate tree verification via git write-tree.
5. Rejection of unmaterialized workspaces or tampered digests.
6. Zero self-certification (is_authoritative=False, is_causally_verified=False).
"""

from __future__ import annotations

import base64
import re
import shlex
from typing import Any

from basebreak.adapters.nebius.materialization import (
    MaterializedSourceRecord,
    NebiusSourceMaterializer,
    validate_workspace_path,
)
from basebreak.domain.causal import ExecutionWorld
from basebreak.domain.execution import SandboxIdentity
from basebreak.domain.source import SourceIdentity
from basebreak.security.protected_surfaces import (
    get_canonical_basebreak_protected_manifest,
    validate_diff,
)
from basebreak.security.secret_policy import validate_no_secrets
from basebreak.verifier.context import VerifierContextEnvelope
from basebreak.verifier.sandbox import (
    VerifierMaterializationError,
    VerifierTreeDigestMismatchError,
)

_COMMIT_RE = re.compile(r"BASEBREAK_RESOLVED_COMMIT=([0-9a-fA-F]{40,64})")
_TREE_RE = re.compile(r"BASEBREAK_RESOLVED_TREE=([0-9a-fA-F]{40,64})")
_ALT_COMMIT_RE = re.compile(r"RESOLVED_BASE_SHA=([0-9a-fA-F]{40,64})")
_ALT_TREE_RE = re.compile(r"TREE_SHA=([0-9a-fA-F]{40,64})")


class CausalRepositoryMaterializer:
    """Canonical repository materializer supporting BASE and CANDIDATE worlds."""

    def __init__(
        self,
        adapter: Any,
        source_materializer: Any | None = None,
    ) -> None:
        if adapter is None:
            raise TypeError("adapter must not be None")
        self.adapter = adapter
        if source_materializer is not None:
            self.source_materializer = source_materializer
        else:
            self.source_materializer = NebiusSourceMaterializer(adapter=adapter)

    def materialize_repository(
        self,
        source_identity: SourceIdentity,
        *,
        sandbox: Any = None,
        workspace_path: str = "/verifier_workspace",
        world: ExecutionWorld = ExecutionWorld.BASE,
        context_envelope: VerifierContextEnvelope | None = None,
        expected_tree_sha: str | None = None,
        disposable: bool = False,
        timeout_seconds: int = 120,
        **kwargs: Any,
    ) -> MaterializedSourceRecord:
        """Materialize repository into sandbox VM for the requested world.

        Under BASE:
        - Materializes clean repository from source_identity at resolved_commit_id.

        Under CANDIDATE:
        - Materializes clean base repository first.
        - Validates candidate patch against canonical P-04 protected-surface manifest.
        - Validates candidate patch against secret policy.
        - Applies candidate patch via canonical P-07 script (git apply, git add -A, git write-tree).
        - Verifies exact candidate tree equality.
        """
        clean_ws = validate_workspace_path(workspace_path)

        # 1. Base world materialization
        if world == ExecutionWorld.BASE or (
            world != ExecutionWorld.CANDIDATE and not context_envelope
        ):
            record = self.source_materializer.materialize_repository(
                source_identity=source_identity,
                sandbox=sandbox,
                workspace_path=clean_ws,
                expected_tree_sha=expected_tree_sha,
                disposable=False,
                timeout_seconds=timeout_seconds,
            )
            if not isinstance(record, MaterializedSourceRecord):
                raise VerifierMaterializationError(
                    f"Expected MaterializedSourceRecord, got {type(record).__name__}"
                )
            return record

        # 2. Candidate world materialization
        # Step A: Materialize clean base repository first (must retain image if chained)
        base_res = self.source_materializer.materialize_repository(
            source_identity=source_identity,
            sandbox=sandbox,
            workspace_path=clean_ws,
            disposable=False,
            timeout_seconds=timeout_seconds,
        )
        if not isinstance(base_res, MaterializedSourceRecord):
            raise VerifierMaterializationError(
                f"Expected MaterializedSourceRecord, got {type(base_res).__name__}"
            )
        base_record: MaterializedSourceRecord = base_res

        # Step B: Extract candidate patch
        patch_text: str | None = None
        if context_envelope is not None:
            patch_text = context_envelope.candidate_patch_text
        if patch_text is None:
            patch_text = kwargs.get("candidate_patch_text") or kwargs.get("patch_text")
        if not patch_text or not isinstance(patch_text, str) or not patch_text.strip():
            raise VerifierMaterializationError(
                "Cannot materialize CANDIDATE world without valid candidate_patch_text in context"
            )

        # Step C: Revalidate patch through Canonical P-04 Protected Surface Policy
        canonical_manifest = get_canonical_basebreak_protected_manifest()
        validate_diff(patch_text, canonical_manifest)

        # Step D: Canonical Secret Safety Check
        validate_no_secrets(patch_text, path="candidate_patch_text")

        # Step E: Apply Exact Captured Patch via Canonical P-07 Script
        sbx_id = getattr(sandbox, "sandbox_id", None) or getattr(
            base_record.sandbox_identity, "sandbox_id", "sbx-repro"
        )
        if hasattr(sandbox, "sandbox_identity"):
            sbx_id = sandbox.sandbox_identity.sandbox_id
        patch_path = f"/tmp/basebreak_candidate_{str(sbx_id)[:16]}.patch"
        b64_patch = base64.b64encode(patch_text.encode("utf-8")).decode("ascii")

        bundle_script = (
            "set -e\n"
            f"cd {shlex.quote(clean_ws)}\n"
            f'printf "%s" {shlex.quote(b64_patch)} | base64 -d > {shlex.quote(patch_path)}\n'
            f"git apply --binary --whitespace=nowarn {shlex.quote(patch_path)}\n"
            f"rm -f {shlex.quote(patch_path)}\n"
            "git add -A\n"
            'echo "BASEBREAK_RESOLVED_COMMIT=$(git rev-parse HEAD)"\n'
            'echo "BASEBREAK_RESOLVED_TREE=$(git write-tree)"\n'
        )

        exec_res = self.adapter.execute_command(
            sandbox,
            bundle_script,
            working_dir=clean_ws,
            timeout_seconds=timeout_seconds,
            disposable=False,
        )

        exit_code = getattr(exec_res, "exit_code", None)
        if exit_code is None and hasattr(exec_res, "result"):
            exit_code = getattr(exec_res.result, "exit_code", None)
        if exit_code != 0:
            err = getattr(exec_res, "stderr", "") or getattr(exec_res, "stdout", "")
            raise VerifierMaterializationError(
                f"Failed to apply candidate patch in sandbox workspace (exit {exit_code}): {err}"
            )

        stdout = getattr(exec_res, "stdout", "") or ""
        commit_match = _COMMIT_RE.search(stdout) or _ALT_COMMIT_RE.search(stdout)
        tree_match = _TREE_RE.search(stdout) or _ALT_TREE_RE.search(stdout)

        if not commit_match or not tree_match:
            raise VerifierMaterializationError(
                "Candidate patch applied but failed to resolve commit or tree hash from sandbox"
            )

        resolved_commit = commit_match.group(1).lower()
        resolved_tree = tree_match.group(1).lower()

        # Step F: Validate against authoritative context envelope
        expected_cand_tree = (
            expected_tree_sha.strip().lower()
            if expected_tree_sha
            else (
                context_envelope.candidate_tree_digest.strip().lower()
                if context_envelope and context_envelope.candidate_tree_digest
                else None
            )
        )
        if expected_cand_tree and resolved_tree != expected_cand_tree:
            raise VerifierTreeDigestMismatchError(
                f"Materialized candidate tree digest {resolved_tree!r} does not match "
                f"expected candidate tree digest {expected_cand_tree!r}"
            )

        target_identity = getattr(base_record, "sandbox_identity", None)
        if target_identity is None:
            if isinstance(sandbox, SandboxIdentity):
                target_identity = sandbox
            elif hasattr(sandbox, "sandbox_identity"):
                target_identity = sandbox.sandbox_identity
            else:
                target_identity = SandboxIdentity(sandbox_id=str(sbx_id))

        return MaterializedSourceRecord(
            source_identity=source_identity,
            resolved_commit_sha=resolved_commit,
            resolved_tree_sha=resolved_tree,
            workspace_path=clean_ws,
            sandbox_identity=target_identity,
            operation_id=getattr(exec_res, "operation_id", base_record.operation_id),
            duration_seconds=getattr(exec_res, "duration_seconds", None),
            result_image_uuid=getattr(exec_res, "result_image_uuid", None),
            is_verified=True,
            is_clean_workspace=True,
            is_fresh_sandbox=False,
        )


# Export canonical alias
GitRepositoryMaterializer = CausalRepositoryMaterializer
