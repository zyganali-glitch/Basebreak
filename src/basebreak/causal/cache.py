"""Safe deterministic execution cache and reuse engine for causal verification.

P-12.03: Cache/reuse safe deterministic executions to control cost.

Basebreak Thesis:
"If the patch matters, the base must break."

Invariants Enforced:
1. Exact execution identity binding:
   Cache key binds all behaviorally relevant facts:
   - source_locator
   - source_commit_id
   - source_subpath
   - candidate_tree_digest
   - retained_patch_digest
   - subtracted_delta_digest
   - frozen_contract_digest
   - sealed_witness_digest
   - requirement_id
   - execution_command
   - provenance
2. Rejection of reuse on any identity mismatch.
3. Strict provenance preservation:
   - FIXTURE -> LIVE_NEBIUS substitution: STRICTLY FORBIDDEN.
   - LOCAL_EXECUTION -> LIVE_NEBIUS substitution: STRICTLY FORBIDDEN.
   - RECORDED_LIVE -> current LIVE_NEBIUS substitution: STRICTLY FORBIDDEN.
   - Cache hit preserves original evidence provenance.
4. Zero authority gain from reuse:
   - is_authoritative = False
   - grants_pass = False
   - is_causally_verified = False
5. Tamper detection:
   - Corrupted, modified, or stale cache entries fail closed.
6. Auditable audit trail:
   - Hit/miss/rejection status and typed rejection reason for every lookup.
"""

from __future__ import annotations

import hashlib
import json
import re
from collections.abc import Mapping, Sequence
from dataclasses import dataclass
from datetime import datetime, timezone
from enum import Enum
from typing import Any

from basebreak.causal.slice import (
    LOCAL_TEST_RUNTIME_CONFIG_DIGEST,
    CausalSliceScope,
    SubsetExecutionFact,
    TestedPatchSubset,
    create_subset_execution_fact,
)
from basebreak.domain.verdict import EvidenceProvenance
from basebreak.verifier.witness_result import WitnessOutcome

_HEX_40_PATTERN = re.compile(r"^[0-9a-f]{40}$")
_HEX_64_PATTERN = re.compile(r"^[0-9a-f]{64}$")
_HEX_40_OR_64_PATTERN = re.compile(r"^([0-9a-f]{40}|[0-9a-f]{64})$")


class CacheError(Exception):
    """Base exception for deterministic execution cache errors."""


class CacheTamperingError(CacheError):
    """Raised when a cached entry or key fails cryptographic integrity verification."""


class ForbiddenProvenanceSubstitutionError(CacheError):
    """Raised when an attempt is made to substitute lower-authority provenance for higher."""


class CacheRejectionReason(str, Enum):
    """Auditable reasons for cache miss or reuse rejection."""

    NONE = "NONE"
    MISSING_ENTRY = "MISSING_ENTRY"
    CONTRACT_MISMATCH = "CONTRACT_MISMATCH"
    WITNESS_MISMATCH = "WITNESS_MISMATCH"
    SOURCE_MISMATCH = "SOURCE_MISMATCH"
    TREE_MISMATCH = "TREE_MISMATCH"
    PATCH_MISMATCH = "PATCH_MISMATCH"
    DELTA_MISMATCH = "DELTA_MISMATCH"
    REQUIREMENT_MISMATCH = "REQUIREMENT_MISMATCH"
    COMMAND_MISMATCH = "COMMAND_MISMATCH"
    RUNTIME_CONFIG_MISMATCH = "RUNTIME_CONFIG_MISMATCH"
    PROVENANCE_MISMATCH = "PROVENANCE_MISMATCH"
    FORBIDDEN_PROVENANCE_SUBSTITUTION = "FORBIDDEN_PROVENANCE_SUBSTITUTION"
    TAMPERED_ENTRY = "TAMPERED_ENTRY"
    STALE_ENTRY = "STALE_ENTRY"
    BUILDER_SANDBOX_REUSE = "BUILDER_SANDBOX_REUSE"
    MUTABLE_WORKSPACE_REUSE = "MUTABLE_WORKSPACE_REUSE"


# --- Cache Key ---


def compute_cache_key_digest(payload: Mapping[str, Any]) -> str:
    """Compute deterministic SHA-256 digest of canonical cache key payload."""
    canonical_bytes = json.dumps(
        payload, sort_keys=True, separators=(",", ":"), ensure_ascii=False
    ).encode("utf-8")
    return hashlib.sha256(canonical_bytes).hexdigest()


@dataclass(frozen=True, slots=True)
class ExecutionCacheKey:
    """Immutable, cryptographically bound cache key for deterministic execution reuse."""

    source_locator: str
    source_commit_id: str
    source_subpath: str
    candidate_tree_digest: str
    retained_patch_digest: str
    subtracted_delta_digest: str
    frozen_contract_digest: str
    sealed_witness_digest: str
    requirement_id: str
    execution_command: tuple[str, ...]
    provenance: EvidenceProvenance
    runtime_config_digest: str
    key_digest: str

    def __post_init__(self) -> None:
        if not isinstance(self.source_locator, str) or not self.source_locator.strip():
            raise ValueError("source_locator must be a non-empty string")
        if not isinstance(self.source_commit_id, str) or not _HEX_40_PATTERN.match(
            self.source_commit_id
        ):
            raise ValueError(f"source_commit_id must be 40 hex chars: {self.source_commit_id!r}")
        if not isinstance(self.candidate_tree_digest, str) or not _HEX_40_OR_64_PATTERN.match(
            self.candidate_tree_digest
        ):
            raise ValueError(
                f"candidate_tree_digest must be 40 or 64 hex chars: {self.candidate_tree_digest!r}"
            )
        if not isinstance(self.retained_patch_digest, str) or not _HEX_64_PATTERN.match(
            self.retained_patch_digest
        ):
            raise ValueError(
                f"retained_patch_digest must be 64 hex chars: {self.retained_patch_digest!r}"
            )
        if not isinstance(self.subtracted_delta_digest, str) or not _HEX_64_PATTERN.match(
            self.subtracted_delta_digest
        ):
            raise ValueError(
                f"subtracted_delta_digest must be 64 hex chars: {self.subtracted_delta_digest!r}"
            )
        if not isinstance(self.frozen_contract_digest, str) or not _HEX_64_PATTERN.match(
            self.frozen_contract_digest
        ):
            raise ValueError(
                f"frozen_contract_digest must be 64 hex chars: {self.frozen_contract_digest!r}"
            )
        if not isinstance(self.sealed_witness_digest, str) or not _HEX_64_PATTERN.match(
            self.sealed_witness_digest
        ):
            raise ValueError(
                f"sealed_witness_digest must be 64 hex chars: {self.sealed_witness_digest!r}"
            )
        if not isinstance(self.requirement_id, str) or not self.requirement_id.strip():
            raise ValueError("requirement_id must be a non-empty string")
        if not isinstance(self.provenance, EvidenceProvenance):
            raise TypeError(
                f"provenance must be EvidenceProvenance, got {type(self.provenance).__name__}"
            )
        if not isinstance(self.runtime_config_digest, str) or not _HEX_64_PATTERN.match(
            self.runtime_config_digest
        ):
            raise ValueError(
                f"runtime_config_digest must be 64 hex chars: {self.runtime_config_digest!r}"
            )
        if (
            self.provenance == EvidenceProvenance.LIVE_NEBIUS
            and self.runtime_config_digest == LOCAL_TEST_RUNTIME_CONFIG_DIGEST
        ):
            raise ForbiddenProvenanceSubstitutionError(
                "LOCAL_TEST_RUNTIME_CONFIG_DIGEST cannot satisfy LIVE_NEBIUS evidence"
            )
        if not isinstance(self.key_digest, str) or not _HEX_64_PATTERN.match(self.key_digest):
            raise ValueError(f"key_digest must be 64 hex chars: {self.key_digest!r}")

        # Verify key digest integrity
        computed = compute_cache_key_digest(self._build_payload())
        if self.key_digest != computed:
            raise CacheTamperingError(
                f"key_digest mismatch: expected {self.key_digest}, computed {computed}"
            )

    def _build_payload(self) -> dict[str, Any]:
        return {
            "candidate_tree_digest": self.candidate_tree_digest,
            "execution_command": list(self.execution_command),
            "frozen_contract_digest": self.frozen_contract_digest,
            "provenance": self.provenance.value,
            "retained_patch_digest": self.retained_patch_digest,
            "requirement_id": self.requirement_id,
            "runtime_config_digest": self.runtime_config_digest,
            "sealed_witness_digest": self.sealed_witness_digest,
            "source_commit_id": self.source_commit_id,
            "source_locator": self.source_locator,
            "source_subpath": self.source_subpath,
            "subtracted_delta_digest": self.subtracted_delta_digest,
        }

    def to_dict(self) -> dict[str, Any]:
        d = self._build_payload()
        d["key_digest"] = self.key_digest
        return d


def create_execution_cache_key(
    *,
    source_locator: str,
    source_commit_id: str,
    source_subpath: str = "",
    candidate_tree_digest: str,
    retained_patch_digest: str,
    subtracted_delta_digest: str,
    frozen_contract_digest: str,
    sealed_witness_digest: str,
    requirement_id: str,
    execution_command: Sequence[str] | str,
    provenance: EvidenceProvenance,
    runtime_config_digest: str = LOCAL_TEST_RUNTIME_CONFIG_DIGEST,
) -> ExecutionCacheKey:
    """Construct an authentic ExecutionCacheKey with verified SHA-256 digest."""
    cmd_tuple: tuple[str, ...]
    if isinstance(execution_command, str):
        cmd_tuple = tuple(execution_command.split())
    else:
        cmd_tuple = tuple(str(c) for c in execution_command)

    rc_digest = runtime_config_digest.strip().lower()

    payload = {
        "candidate_tree_digest": candidate_tree_digest.strip().lower(),
        "execution_command": list(cmd_tuple),
        "frozen_contract_digest": frozen_contract_digest.strip().lower(),
        "provenance": provenance.value,
        "retained_patch_digest": retained_patch_digest.strip().lower(),
        "requirement_id": requirement_id.strip(),
        "runtime_config_digest": rc_digest,
        "sealed_witness_digest": sealed_witness_digest.strip().lower(),
        "source_commit_id": source_commit_id.strip().lower(),
        "source_locator": source_locator.strip(),
        "source_subpath": source_subpath.strip(),
        "subtracted_delta_digest": subtracted_delta_digest.strip().lower(),
    }
    digest = compute_cache_key_digest(payload)

    return ExecutionCacheKey(
        source_locator=source_locator.strip(),
        source_commit_id=source_commit_id.strip().lower(),
        source_subpath=source_subpath.strip(),
        candidate_tree_digest=candidate_tree_digest.strip().lower(),
        retained_patch_digest=retained_patch_digest.strip().lower(),
        subtracted_delta_digest=subtracted_delta_digest.strip().lower(),
        frozen_contract_digest=frozen_contract_digest.strip().lower(),
        sealed_witness_digest=sealed_witness_digest.strip().lower(),
        requirement_id=requirement_id.strip(),
        execution_command=cmd_tuple,
        provenance=provenance,
        runtime_config_digest=rc_digest,
        key_digest=digest,
    )


# --- Cache Entry ---


def compute_cache_entry_digest(payload: Mapping[str, Any]) -> str:
    """Compute deterministic SHA-256 digest of canonical cache entry payload."""
    canonical_bytes = json.dumps(
        payload, sort_keys=True, separators=(",", ":"), ensure_ascii=False
    ).encode("utf-8")
    return hashlib.sha256(canonical_bytes).hexdigest()


@dataclass(frozen=True, slots=True)
class ExecutionCacheEntry:
    """Immutable, authenticated cached execution outcome record.

    Guarantees:
    - Retains original evidence provenance.
    - Zero authority: is_authoritative = False, grants_pass = False,
      is_causally_verified = False.
    - Cryptographic digest tamper detection.
    """

    key: ExecutionCacheKey
    outcome: WitnessOutcome
    exit_code: int | None
    stdout_digest: str
    stderr_digest: str
    result_digest: str
    duration_seconds: float
    provenance: EvidenceProvenance
    created_at_utc: str
    entry_digest: str
    execution_fact: SubsetExecutionFact | None = None
    is_authoritative: bool = False
    grants_pass: bool = False
    is_causally_verified: bool = False

    def __post_init__(self) -> None:
        if self.is_authoritative is not False:
            raise CacheTamperingError(
                "ExecutionCacheEntry cannot assert authority: is_authoritative must be False"
            )
        if self.grants_pass is not False:
            raise CacheTamperingError(
                "ExecutionCacheEntry cannot grant pass: grants_pass must be False"
            )
        if self.is_causally_verified is not False:
            raise CacheTamperingError(
                "ExecutionCacheEntry cannot assert verification: is_causally_verified must be False"
            )

        if not isinstance(self.key, ExecutionCacheKey):
            raise TypeError(f"key must be ExecutionCacheKey, got {type(self.key).__name__}")
        if not isinstance(self.outcome, WitnessOutcome):
            raise TypeError(f"outcome must be WitnessOutcome, got {type(self.outcome).__name__}")
        if not isinstance(self.provenance, EvidenceProvenance):
            raise TypeError(
                f"provenance must be EvidenceProvenance, got {type(self.provenance).__name__}"
            )

        # Provenance preservation invariant: entry provenance must match key provenance
        if self.provenance != self.key.provenance:
            raise ForbiddenProvenanceSubstitutionError(
                f"Provenance mismatch between entry ({self.provenance.value}) "
                f"and key ({self.key.provenance.value})"
            )

        if self.execution_fact is not None:
            if not isinstance(self.execution_fact, SubsetExecutionFact):
                fact_type = type(self.execution_fact).__name__
                raise TypeError(f"execution_fact must be SubsetExecutionFact, got {fact_type}")
            if self.execution_fact.provenance != self.provenance:
                raise ForbiddenProvenanceSubstitutionError(
                    "Cached execution_fact provenance must match entry provenance"
                )
            if self.execution_fact.runtime_config_digest != self.key.runtime_config_digest:
                raise CacheTamperingError(
                    "execution_fact runtime_config_digest must match key runtime_config_digest"
                )

        # Cryptographic verification
        computed = compute_cache_entry_digest(self._build_payload())
        if self.entry_digest != computed:
            raise CacheTamperingError(
                f"entry_digest mismatch: expected {self.entry_digest}, computed {computed}"
            )

    def _build_payload(self) -> dict[str, Any]:
        return {
            "created_at_utc": self.created_at_utc,
            "duration_seconds": round(float(self.duration_seconds), 4),
            "execution_fact_digest": self.execution_fact.execution_digest
            if self.execution_fact
            else "",
            "exit_code": self.exit_code,
            "key": self.key.to_dict(),
            "outcome": self.outcome.value,
            "provenance": self.provenance.value,
            "result_digest": self.result_digest,
            "stderr_digest": self.stderr_digest,
            "stdout_digest": self.stdout_digest,
        }

    def to_dict(self) -> dict[str, Any]:
        d = self._build_payload()
        d["entry_digest"] = self.entry_digest
        d["grants_pass"] = self.grants_pass
        d["is_authoritative"] = self.is_authoritative
        d["is_causally_verified"] = self.is_causally_verified
        return d

    def to_execution_fact(
        self,
        *,
        subset: TestedPatchSubset | None = None,
        scope: CausalSliceScope | None = None,
    ) -> SubsetExecutionFact:
        """Derive or return authentic structured SubsetExecutionFact from cached entry."""
        if self.execution_fact is not None:
            return self.execution_fact
        if subset is None or scope is None:
            raise ValueError("subset and scope are required when execution_fact is None")
        return create_subset_execution_fact(
            subset=subset,
            scope=scope,
            outcome=self.outcome,
            runtime_config_digest=self.key.runtime_config_digest,
            execution_command=self.key.execution_command,
            exit_code=self.exit_code,
            stdout_digest=self.stdout_digest,
            stderr_digest=self.stderr_digest,
            duration_seconds=self.duration_seconds,
            provenance=self.provenance,
            created_at_utc=self.created_at_utc,
        )


def create_execution_cache_entry(
    *,
    key: ExecutionCacheKey,
    outcome: WitnessOutcome,
    exit_code: int | None = 0,
    stdout_digest: str = "0" * 64,
    stderr_digest: str = "0" * 64,
    result_digest: str = "0" * 64,
    duration_seconds: float = 0.0,
    created_at_utc: str | None = None,
    execution_fact: SubsetExecutionFact | None = None,
) -> ExecutionCacheEntry:
    """Create an authentic ExecutionCacheEntry bound to key."""
    timestamp = created_at_utc or datetime.now(timezone.utc).isoformat()
    payload = {
        "created_at_utc": timestamp,
        "duration_seconds": round(float(duration_seconds), 4),
        "execution_fact_digest": execution_fact.execution_digest if execution_fact else "",
        "exit_code": exit_code,
        "key": key.to_dict(),
        "outcome": outcome.value,
        "provenance": key.provenance.value,
        "result_digest": result_digest,
        "stderr_digest": stderr_digest,
        "stdout_digest": stdout_digest,
    }
    digest = compute_cache_entry_digest(payload)

    return ExecutionCacheEntry(
        key=key,
        outcome=outcome,
        exit_code=exit_code,
        stdout_digest=stdout_digest,
        stderr_digest=stderr_digest,
        result_digest=result_digest,
        duration_seconds=duration_seconds,
        provenance=key.provenance,
        created_at_utc=timestamp,
        entry_digest=digest,
        execution_fact=execution_fact,
        is_authoritative=False,
        grants_pass=False,
        is_causally_verified=False,
    )


# --- Lookup Result ---


@dataclass(frozen=True, slots=True)
class CacheLookupResult:
    """Auditable result of a cache lookup attempt."""

    hit: bool
    entry: ExecutionCacheEntry | None
    rejection_reason: CacheRejectionReason
    message: str


# --- Deterministic Execution Cache Engine ---


class DeterministicExecutionCache:
    """Provider-neutral deterministic cache for safe witness execution reuse.

    Enforces:
    1. Exact behavioral identity matching across 11 cryptographic dimensions.
    2. Strict provenance preservation: lower provenance cannot satisfy higher provenance.
    3. Tamper detection on retrieved entries.
    4. Auditable reason for every hit, miss, or rejection.
    5. Zero authority gain.
    """

    def __init__(self) -> None:
        self._entries: dict[str, ExecutionCacheEntry] = {}
        self._hits: int = 0
        self._misses: int = 0
        self._rejections: int = 0
        self._audit_log: list[CacheLookupResult] = []

    @property
    def total_entries(self) -> int:
        return len(self._entries)

    @property
    def hits_count(self) -> int:
        return self._hits

    @property
    def misses_count(self) -> int:
        return self._misses

    @property
    def rejections_count(self) -> int:
        return self._rejections

    def store_entry(self, entry: ExecutionCacheEntry) -> None:
        """Store an authentic ExecutionCacheEntry."""
        if not isinstance(entry, ExecutionCacheEntry):
            raise TypeError(f"entry must be ExecutionCacheEntry, got {type(entry).__name__}")
        self._entries[entry.key.key_digest] = entry

    def store(
        self,
        *,
        subset: TestedPatchSubset,
        scope: CausalSliceScope,
        outcome: WitnessOutcome,
        execution_command: Sequence[str] | str = ("pytest",),
        runtime_config_digest: str = LOCAL_TEST_RUNTIME_CONFIG_DIGEST,
        exit_code: int | None = 0,
        stdout_digest: str = "0" * 64,
        stderr_digest: str = "0" * 64,
        result_digest: str = "0" * 64,
        duration_seconds: float = 0.0,
        fact: SubsetExecutionFact | None = None,
    ) -> ExecutionCacheEntry:
        """Construct and store cache entry directly from subset and scope."""
        key = create_execution_cache_key(
            source_locator=scope.source_locator,
            source_commit_id=scope.source_commit_id,
            source_subpath=scope.source_subpath,
            candidate_tree_digest=scope.candidate_tree_digest,
            retained_patch_digest=subset.retained_patch_digest,
            subtracted_delta_digest=subset.subtracted_delta_digest,
            frozen_contract_digest=scope.frozen_contract_digest,
            sealed_witness_digest=scope.sealed_witness_digest,
            requirement_id=scope.requirement_id,
            execution_command=execution_command,
            provenance=scope.provenance,
            runtime_config_digest=runtime_config_digest,
        )
        exec_fact = fact or create_subset_execution_fact(
            subset=subset,
            scope=scope,
            outcome=outcome,
            runtime_config_digest=runtime_config_digest,
            execution_command=execution_command,
            exit_code=exit_code,
            stdout_digest=stdout_digest,
            stderr_digest=stderr_digest,
            duration_seconds=duration_seconds,
            provenance=scope.provenance,
        )
        entry = create_execution_cache_entry(
            key=key,
            outcome=outcome,
            exit_code=exit_code,
            stdout_digest=stdout_digest,
            stderr_digest=stderr_digest,
            result_digest=exec_fact.execution_digest
            if result_digest == "0" * 64
            else result_digest,
            duration_seconds=duration_seconds,
            execution_fact=exec_fact,
        )
        self.store_entry(entry)
        return entry

    def store_fact(
        self,
        fact: SubsetExecutionFact,
        *,
        subset: TestedPatchSubset,
        scope: CausalSliceScope,
    ) -> ExecutionCacheEntry:
        """Store an authentic SubsetExecutionFact directly."""
        key = create_execution_cache_key(
            source_locator=scope.source_locator,
            source_commit_id=scope.source_commit_id,
            source_subpath=scope.source_subpath,
            candidate_tree_digest=scope.candidate_tree_digest,
            retained_patch_digest=subset.retained_patch_digest,
            subtracted_delta_digest=subset.subtracted_delta_digest,
            frozen_contract_digest=scope.frozen_contract_digest,
            sealed_witness_digest=scope.sealed_witness_digest,
            requirement_id=scope.requirement_id,
            execution_command=fact.execution_command,
            provenance=fact.provenance,
            runtime_config_digest=fact.runtime_config_digest,
        )
        entry = create_execution_cache_entry(
            key=key,
            outcome=fact.outcome,
            exit_code=fact.exit_code,
            stdout_digest=fact.stdout_digest,
            stderr_digest=fact.stderr_digest,
            result_digest=fact.execution_digest,
            duration_seconds=fact.duration_seconds,
            created_at_utc=fact.created_at_utc or None,
            execution_fact=fact,
        )
        self.store_entry(entry)
        return entry

    def lookup_by_key(
        self,
        key: ExecutionCacheKey,
        *,
        requested_provenance: EvidenceProvenance | None = None,
    ) -> CacheLookupResult:
        """Look up execution outcome using exact ExecutionCacheKey."""
        if not isinstance(key, ExecutionCacheKey):
            raise TypeError(f"key must be ExecutionCacheKey, got {type(key).__name__}")

        req_prov = requested_provenance or key.provenance

        # Check if entry exists in store
        entry = self._entries.get(key.key_digest)
        if entry is None:
            self._misses += 1
            res = CacheLookupResult(
                hit=False,
                entry=None,
                rejection_reason=CacheRejectionReason.MISSING_ENTRY,
                message=f"No cache entry found for key digest {key.key_digest[:16]}",
            )
            self._audit_log.append(res)
            return res

        # Validate entry integrity (tamper detection)
        computed_entry_digest = compute_cache_entry_digest(entry._build_payload())
        if entry.entry_digest != computed_entry_digest:
            self._rejections += 1
            res = CacheLookupResult(
                hit=False,
                entry=None,
                rejection_reason=CacheRejectionReason.TAMPERED_ENTRY,
                message="Cached entry failed cryptographic integrity check (tampering detected)",
            )
            self._audit_log.append(res)
            return res

        # Identity check 1: Frozen contract digest
        if entry.key.frozen_contract_digest != key.frozen_contract_digest:
            self._rejections += 1
            res = CacheLookupResult(
                hit=False,
                entry=None,
                rejection_reason=CacheRejectionReason.CONTRACT_MISMATCH,
                message="Frozen contract digest mismatch between lookup key and cache entry",
            )
            self._audit_log.append(res)
            return res

        # Identity check 2: Sealed witness digest
        if entry.key.sealed_witness_digest != key.sealed_witness_digest:
            self._rejections += 1
            res = CacheLookupResult(
                hit=False,
                entry=None,
                rejection_reason=CacheRejectionReason.WITNESS_MISMATCH,
                message="Sealed witness digest mismatch between lookup key and cache entry",
            )
            self._audit_log.append(res)
            return res

        # Identity check 3: Source commit ID
        if entry.key.source_commit_id != key.source_commit_id:
            self._rejections += 1
            res = CacheLookupResult(
                hit=False,
                entry=None,
                rejection_reason=CacheRejectionReason.SOURCE_MISMATCH,
                message="Source commit ID mismatch between lookup key and cache entry",
            )
            self._audit_log.append(res)
            return res

        # Identity check 4: Retained patch digest
        if entry.key.retained_patch_digest != key.retained_patch_digest:
            self._rejections += 1
            res = CacheLookupResult(
                hit=False,
                entry=None,
                rejection_reason=CacheRejectionReason.PATCH_MISMATCH,
                message="Retained patch digest mismatch between lookup key and cache entry",
            )
            self._audit_log.append(res)
            return res

        # Identity check 5: Subtracted delta digest
        if entry.key.subtracted_delta_digest != key.subtracted_delta_digest:
            self._rejections += 1
            res = CacheLookupResult(
                hit=False,
                entry=None,
                rejection_reason=CacheRejectionReason.DELTA_MISMATCH,
                message="Subtracted delta digest mismatch between lookup key and cache entry",
            )
            self._audit_log.append(res)
            return res

        # Identity check 6: Requirement ID
        if entry.key.requirement_id != key.requirement_id:
            self._rejections += 1
            res = CacheLookupResult(
                hit=False,
                entry=None,
                rejection_reason=CacheRejectionReason.REQUIREMENT_MISMATCH,
                message="Requirement ID mismatch between lookup key and cache entry",
            )
            self._audit_log.append(res)
            return res

        # Identity check 7: Execution command
        if entry.key.execution_command != key.execution_command:
            self._rejections += 1
            res = CacheLookupResult(
                hit=False,
                entry=None,
                rejection_reason=CacheRejectionReason.COMMAND_MISMATCH,
                message="Execution command mismatch between lookup key and cache entry",
            )
            self._audit_log.append(res)
            return res

        # Identity check 8: Runtime configuration digest
        if entry.key.runtime_config_digest != key.runtime_config_digest:
            self._rejections += 1
            res = CacheLookupResult(
                hit=False,
                entry=None,
                rejection_reason=CacheRejectionReason.RUNTIME_CONFIG_MISMATCH,
                message="Runtime configuration digest mismatch between lookup key and cache entry",
            )
            self._audit_log.append(res)
            return res

        # Identity check 9: Strict Provenance Preservation Law
        # Lower authority cannot satisfy higher authority:
        # e.g. FIXTURE cannot satisfy LIVE_NEBIUS; LOCAL_EXECUTION cannot satisfy LIVE_NEBIUS.
        if (
            req_prov == EvidenceProvenance.LIVE_NEBIUS
            and entry.provenance != EvidenceProvenance.LIVE_NEBIUS
        ):
            self._rejections += 1
            res = CacheLookupResult(
                hit=False,
                entry=None,
                rejection_reason=CacheRejectionReason.FORBIDDEN_PROVENANCE_SUBSTITUTION,
                message=(
                    f"Forbidden provenance substitution: cannot satisfy {req_prov.value} "
                    f"using cached {entry.provenance.value} evidence"
                ),
            )
            self._audit_log.append(res)
            return res

        if req_prov != entry.provenance:
            self._rejections += 1
            res = CacheLookupResult(
                hit=False,
                entry=None,
                rejection_reason=CacheRejectionReason.PROVENANCE_MISMATCH,
                message=(
                    f"Provenance mismatch: requested {req_prov.value}, "
                    f"cached entry has {entry.provenance.value}"
                ),
            )
            self._audit_log.append(res)
            return res

        # All deterministic identity dimensions match
        self._hits += 1
        res = CacheLookupResult(
            hit=True,
            entry=entry,
            rejection_reason=CacheRejectionReason.NONE,
            message="Deterministic cache hit with verified identity and preserved provenance",
        )
        self._audit_log.append(res)
        return res

    def lookup(
        self,
        *,
        subset: TestedPatchSubset,
        scope: CausalSliceScope,
        execution_command: Sequence[str] | str = ("pytest",),
        runtime_config_digest: str = LOCAL_TEST_RUNTIME_CONFIG_DIGEST,
        requested_provenance: EvidenceProvenance | None = None,
    ) -> CacheLookupResult:
        """Convenience lookup directly from subset and scope."""
        key = create_execution_cache_key(
            source_locator=scope.source_locator,
            source_commit_id=scope.source_commit_id,
            source_subpath=scope.source_subpath,
            candidate_tree_digest=scope.candidate_tree_digest,
            retained_patch_digest=subset.retained_patch_digest,
            subtracted_delta_digest=subset.subtracted_delta_digest,
            frozen_contract_digest=scope.frozen_contract_digest,
            sealed_witness_digest=scope.sealed_witness_digest,
            requirement_id=scope.requirement_id,
            execution_command=execution_command,
            provenance=requested_provenance or scope.provenance,
            runtime_config_digest=runtime_config_digest,
        )
        return self.lookup_by_key(key, requested_provenance=requested_provenance)


__all__ = [
    "CacheError",
    "CacheLookupResult",
    "CacheRejectionReason",
    "CacheTamperingError",
    "DeterministicExecutionCache",
    "ExecutionCacheEntry",
    "ExecutionCacheKey",
    "ForbiddenProvenanceSubstitutionError",
    "compute_cache_entry_digest",
    "compute_cache_key_digest",
    "create_execution_cache_entry",
    "create_execution_cache_key",
]
