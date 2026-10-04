"""Mechanical separation and boundary enforcement between Builder and Verifier.

P-08.04: Prevent Builder access to hidden witness implementation/artifacts.

Core Invariants:
1. Deny-by-default asset separation: Verifier assets and sealed witness implementations
   cannot be accessed, enumerated, or inferred through Builder context or workspace.
2. Repository enumeration filtering: File enumeration surfaces for Builder strictly
   filter out all verifier and witness paths.
3. Environment variable safety: Builder process environments must not receive verifier
   secrets, tokens, or witness paths.
4. Error output sanitization: Verifier errors returned to Builder or stored publicly
   are mechanically sanitized to prevent leaking witness implementation or assertion code.
5. Serialization & result isolation: Public results and serialized candidate snapshots
   must never leak sealed witness contents.
6. Protected surface binding: Reuses canonical ProtectedSurfaceManifest to prevent
   Builder patches from modifying, adding, or deleting verifier code or witness assets.
7. Provider neutrality: Zero adapter imports, zero provider-specific identifiers.
"""

from __future__ import annotations

import re
from collections.abc import Iterable, Mapping, Sequence
from typing import Any

from basebreak.builder.context import DEFAULT_VERIFIER_PROTECTED_PREFIXES
from basebreak.security.protected_surfaces import (
    PathSecurityError,
    PathTraversalError,
    ProtectedSurfaceManifest,
    get_canonical_basebreak_protected_manifest,
    normalize_repo_path,
    parse_unified_diff_changes,
    validate_protected_surfaces,
)
from basebreak.security.secret_policy import contains_secret
from basebreak.verifier.witness_store import SealedWitnessRecord, TrustedWitnessVault

REDACTED_WITNESS_TEXT: str = "[REDACTED_WITNESS_CONTENT]"
REDACTED_WITNESS_ID: str = "[REDACTED_WITNESS_ID]"
REDACTED_WITNESS_DIGEST: str = "[REDACTED_WITNESS_DIGEST]"
REDACTED_VERIFIER_PATH: str = "[REDACTED_VERIFIER_PATH]"

# Extended set of verifier and witness prefixes
VERIFIER_DIRECTORY_PREFIXES: frozenset[str] = frozenset(
    DEFAULT_VERIFIER_PROTECTED_PREFIXES
    | {
        "src/basebreak/verifier",
        ".verifier",
        "_verifier",
        "verifier_workspace",
        ".sealed_vault",
        "sealed_witnesses",
    }
)

_VERIFIER_ENV_KEY_PATTERN = re.compile(r"(?i)(?:VERIFIER|WITNESS|SEALED_VAULT|VAULT_SECRET)")
_VERIFIER_PATH_PATTERN = re.compile(
    r"(?:/verifier_workspace/[^\s\"']+|src/basebreak/verifier/[^\s\"']+|tests/verifier/[^\s\"']+)"
)


# --- Exceptions ---


class VerifierBoundaryError(Exception):
    """Base exception for all Verifier boundary and isolation violations."""


class VerifierAssetExclusionError(VerifierBoundaryError):
    """Raised when Builder attempts to access or admit verifier or witness assets."""


class VerifierEnvironmentLeakageError(VerifierBoundaryError):
    """Raised when Builder execution environment contains verifier secrets or witness paths."""


class WitnessLeakageInResultError(VerifierBoundaryError):
    """Raised when unredacted witness implementation is detected in public results."""


# --- Verifier Boundary Enforcer ---


class VerifierBoundaryEnforcer:
    """Mechanically enforces the boundary between Builder runtime and Verifier assets."""

    def __init__(
        self,
        protected_prefixes: frozenset[str] = VERIFIER_DIRECTORY_PREFIXES,
    ) -> None:
        self.protected_prefixes = protected_prefixes

    def is_verifier_asset_path(
        self,
        path: str,
        vault: TrustedWitnessVault | None = None,
    ) -> bool:
        """Return True if path represents a verifier or sealed witness asset."""
        if not isinstance(path, str):
            return False

        try:
            norm = normalize_repo_path(path)
        except (PathSecurityError, PathTraversalError):
            return True  # Path traversal attempts are treated as boundary breaches

        # 1. Prefix checks
        for prefix in self.protected_prefixes:
            clean_pref = prefix.strip("/")
            if norm == clean_pref or norm.startswith(clean_pref + "/"):
                return True

        # 2. Vault artifact paths check
        if vault is not None:
            for wid in vault.list_sealed_witness_ids():
                try:
                    record = vault.get_witness(wid)
                    for art in record.artifacts:
                        if norm == art.path:
                            return True
                except Exception:
                    continue

        return False

    def validate_builder_context_path(
        self,
        path: str,
        vault: TrustedWitnessVault | None = None,
    ) -> None:
        """Validate that a requested Builder context path does not access verifier assets."""
        if self.is_verifier_asset_path(path, vault):
            raise VerifierAssetExclusionError(
                f"Builder context path {path!r} is a protected verifier or witness asset"
            )

    def filter_repository_paths_for_builder(
        self,
        paths: Iterable[str],
        vault: TrustedWitnessVault | None = None,
    ) -> list[str]:
        """Mechanically filter out verifier and witness paths from repository file enumeration."""
        allowed: list[str] = []
        for p in paths:
            if not isinstance(p, str):
                continue
            if not self.is_verifier_asset_path(p, vault):
                allowed.append(p)
        return sorted(allowed)

    def validate_builder_env(
        self,
        env: Mapping[str, str] | Sequence[tuple[str, str]],
    ) -> None:
        """Ensure Builder environment variables do not leak verifier secrets or paths."""
        pairs: list[tuple[str, str]] = []
        if isinstance(env, Mapping):
            pairs = list(env.items())
        elif isinstance(env, Sequence):
            for item in env:
                if isinstance(item, (tuple, list)) and len(item) == 2:
                    pairs.append((str(item[0]), str(item[1])))

        for k, v in pairs:
            if _VERIFIER_ENV_KEY_PATTERN.search(k):
                raise VerifierEnvironmentLeakageError(
                    f"Builder environment variable {k!r} leaks verifier authority or token"
                )
            if any(pref in v for pref in self.protected_prefixes):
                raise VerifierEnvironmentLeakageError(
                    f"Builder environment variable {k!r} references verifier protected path"
                )
            if contains_secret(v):
                raise VerifierEnvironmentLeakageError(
                    f"Builder environment variable {k!r} contains credential"
                )

    def sanitize_verifier_error_output(
        self,
        error_text: str,
        vault: TrustedWitnessVault | None = None,
        sealed_records: Sequence[SealedWitnessRecord] = (),
    ) -> str:
        """Mechanically sanitize error output to prevent leaking witness code or digests."""
        if not isinstance(error_text, str) or not error_text:
            return ""

        sanitized = error_text

        # 1. Collect witness records to redact
        records: list[SealedWitnessRecord] = list(sealed_records)
        if vault is not None:
            for wid in vault.list_sealed_witness_ids():
                try:
                    records.append(vault.get_witness(wid))
                except Exception:
                    pass

        # 2. Redact witness artifacts content, seal digests, and signatures
        for rec in records:
            # Redact witness ID
            if rec.witness_id in sanitized:
                sanitized = sanitized.replace(rec.witness_id, REDACTED_WITNESS_ID)
            # Redact seal digest
            if rec.seal_digest in sanitized:
                sanitized = sanitized.replace(rec.seal_digest, REDACTED_WITNESS_DIGEST)
            # Redact vault signature
            if rec.vault_signature in sanitized:
                sanitized = sanitized.replace(rec.vault_signature, REDACTED_WITNESS_DIGEST)

            # Redact artifact content lines
            for art in rec.artifacts:
                # Redact artifact path
                if art.path in sanitized:
                    sanitized = sanitized.replace(art.path, REDACTED_VERIFIER_PATH)
                # Redact content lines
                for line in art.content.splitlines():
                    cleaned_line = line.strip()
                    if len(cleaned_line) > 5 and cleaned_line in sanitized:
                        sanitized = sanitized.replace(cleaned_line, REDACTED_WITNESS_TEXT)

        # 3. Redact any remaining internal verifier workspace paths
        sanitized = _VERIFIER_PATH_PATTERN.sub(REDACTED_VERIFIER_PATH, sanitized)

        return sanitized

    def validate_candidate_patch_isolation(
        self,
        patch_text: str,
        vault: TrustedWitnessVault | None = None,
    ) -> None:
        """Validate candidate patch using canonical ProtectedSurfaceManifest and verifier rules.

        Fails closed with ProtectedSurfaceViolation if patch attempts to add, modify,
        or delete any verifier or witness asset.
        """
        if not isinstance(patch_text, str):
            raise TypeError("patch_text must be a string")

        changes = parse_unified_diff_changes(patch_text)
        manifest = get_canonical_basebreak_protected_manifest()

        extra_prefixes = set(self.protected_prefixes)
        exact_files = set(manifest.exact_files)
        if vault is not None:
            for wid in vault.list_sealed_witness_ids():
                try:
                    record = vault.get_witness(wid)
                    for art in record.artifacts:
                        exact_files.add(art.path)
                except Exception:
                    pass

        active_manifest = ProtectedSurfaceManifest(
            exact_files=frozenset(exact_files),
            directory_prefixes=frozenset(set(manifest.directory_prefixes) | extra_prefixes),
            description="Canonical protected manifest with verifier boundary",
        )
        validate_protected_surfaces(changes, active_manifest)

    def validate_public_result_isolation(
        self,
        data: Any,
        vault: TrustedWitnessVault | None = None,
        sealed_records: Sequence[SealedWitnessRecord] = (),
    ) -> None:
        """Recursively inspect results or evidence dictionaries for witness code leakage."""
        records: list[SealedWitnessRecord] = list(sealed_records)
        if vault is not None:
            for wid in vault.list_sealed_witness_ids():
                try:
                    records.append(vault.get_witness(wid))
                except Exception:
                    pass

        # Collect distinct sensitive witness fragments
        forbidden_snippets: list[str] = []
        for r in records:
            forbidden_snippets.append(r.vault_signature)
            for a in r.artifacts:
                for line in a.content.splitlines():
                    cl = line.strip()
                    if len(cl) > 8:
                        forbidden_snippets.append(cl)

        def _scan(obj: Any) -> None:
            if isinstance(obj, str):
                for snip in forbidden_snippets:
                    if snip in obj:
                        raise WitnessLeakageInResultError(
                            "Public result or evidence data contains unredacted "
                            "witness implementation"
                        )
            elif isinstance(obj, Mapping):
                for k, v in obj.items():
                    _scan(k)
                    _scan(v)
            elif isinstance(obj, Sequence) and not isinstance(obj, (bytes, bytearray)):
                for item in obj:
                    _scan(item)

        _scan(data)
