"""Unit and adversarial tests for P-12.03: Safe deterministic execution cache and reuse."""

from __future__ import annotations

from typing import Any

import pytest

from basebreak.builder.capture import CandidateSnapshot
from basebreak.causal.cache import (
    CacheRejectionReason,
    CacheTamperingError,
    DeterministicExecutionCache,
    ExecutionCacheEntry,
    ExecutionCacheKey,
    ForbiddenProvenanceSubstitutionError,
    create_execution_cache_entry,
    create_execution_cache_key,
)
from basebreak.causal.minimizer import (
    BoundedSubsetMinimizer,
)
from basebreak.causal.slice import SubsetExecutionFact, create_subset_execution_fact
from basebreak.domain.source import CommitRevision, SourceIdentity
from basebreak.domain.verdict import EvidenceProvenance
from basebreak.evidence.artifact import compute_bytes_digest
from basebreak.verifier.witness_result import WitnessOutcome

FROZEN_CONTRACT = "a" * 64
SEALED_WITNESS = "b" * 64
BASE_COMMIT = "c" * 40
CAND_TREE = "d" * 40
REPO_LOCATOR = "https://github.com/example/repo.git"
REQ_ID = "REQ-CACHE-001"

PATCH_TEXT = (
    "diff --git a/src/math.py b/src/math.py\n"
    "index 1111111..2222222 100644\n"
    "--- a/src/math.py\n"
    "+++ b/src/math.py\n"
    "@@ -1,2 +1,3 @@\n"
    " def div(a, b):\n"
    "+    if b == 0: raise ValueError('zero')\n"
    "     return a / b\n"
)


def _make_key(
    provenance: EvidenceProvenance = EvidenceProvenance.LOCAL_EXECUTION,
    frozen_contract_digest: str = FROZEN_CONTRACT,
    sealed_witness_digest: str = SEALED_WITNESS,
    source_commit_id: str = BASE_COMMIT,
    retained_patch_digest: str = "1" * 64,
    subtracted_delta_digest: str = "2" * 64,
    requirement_id: str = REQ_ID,
    execution_command: tuple[str, ...] = ("pytest", "tests/test_math.py"),
) -> ExecutionCacheKey:
    return create_execution_cache_key(
        source_locator=REPO_LOCATOR,
        source_commit_id=source_commit_id,
        source_subpath="src/math.py",
        candidate_tree_digest=CAND_TREE,
        retained_patch_digest=retained_patch_digest,
        subtracted_delta_digest=subtracted_delta_digest,
        frozen_contract_digest=frozen_contract_digest,
        sealed_witness_digest=sealed_witness_digest,
        requirement_id=requirement_id,
        execution_command=execution_command,
        provenance=provenance,
    )


class TestExecutionCacheKeyBinding:
    """Tests exact identity binding of ExecutionCacheKey."""

    def test_key_creation_and_digest_computation(self) -> None:
        key = _make_key()
        assert key.source_locator == REPO_LOCATOR
        assert key.source_commit_id == BASE_COMMIT
        assert key.frozen_contract_digest == FROZEN_CONTRACT
        assert key.sealed_witness_digest == SEALED_WITNESS
        assert key.provenance == EvidenceProvenance.LOCAL_EXECUTION
        assert len(key.key_digest) == 64

    def test_key_digest_is_deterministic(self) -> None:
        key1 = _make_key()
        key2 = _make_key()
        assert key1.key_digest == key2.key_digest

    def test_key_digest_changes_on_any_field_variation(self) -> None:
        key_base = _make_key()
        key_diff_contract = _make_key(frozen_contract_digest="f" * 64)
        key_diff_witness = _make_key(sealed_witness_digest="e" * 64)
        key_diff_commit = _make_key(source_commit_id="9" * 40)
        key_diff_patch = _make_key(retained_patch_digest="8" * 64)
        key_diff_prov = _make_key(provenance=EvidenceProvenance.FIXTURE)

        assert key_base.key_digest != key_diff_contract.key_digest
        assert key_base.key_digest != key_diff_witness.key_digest
        assert key_base.key_digest != key_diff_commit.key_digest
        assert key_base.key_digest != key_diff_patch.key_digest
        assert key_base.key_digest != key_diff_prov.key_digest


class TestDeterministicExecutionCacheLookupAndReuse:
    """Tests cache storage, hits, misses, and identity mismatch rejections."""

    def test_cache_miss_on_empty_cache(self) -> None:
        cache = DeterministicExecutionCache()
        key = _make_key()
        res = cache.lookup_by_key(key)
        assert res.hit is False
        assert res.entry is None
        assert res.rejection_reason == CacheRejectionReason.MISSING_ENTRY
        assert cache.misses_count == 1
        assert cache.hits_count == 0

    def test_cache_store_and_successful_hit(self) -> None:
        cache = DeterministicExecutionCache()
        key = _make_key()
        entry = create_execution_cache_entry(
            key=key,
            outcome=WitnessOutcome.PASS,
            exit_code=0,
            stdout_digest="1" * 64,
            stderr_digest="0" * 64,
            duration_seconds=1.23,
        )
        cache.store_entry(entry)

        res = cache.lookup_by_key(key)
        assert res.hit is True
        assert res.entry is not None
        assert res.entry.outcome == WitnessOutcome.PASS
        assert res.entry.exit_code == 0
        assert res.rejection_reason == CacheRejectionReason.NONE
        assert cache.hits_count == 1

    def test_rejection_on_contract_mismatch(self) -> None:
        cache = DeterministicExecutionCache()
        key = _make_key(frozen_contract_digest=FROZEN_CONTRACT)
        entry = create_execution_cache_entry(key=key, outcome=WitnessOutcome.PASS)
        cache.store_entry(entry)

        lookup_key = _make_key(frozen_contract_digest="9" * 64)
        # Because key digest differs, it's a miss
        res = cache.lookup_by_key(lookup_key)
        assert res.hit is False
        assert res.rejection_reason == CacheRejectionReason.MISSING_ENTRY

    def test_strictly_forbids_fixture_to_live_nebius_substitution(self) -> None:
        cache = DeterministicExecutionCache()
        key_fixture = _make_key(provenance=EvidenceProvenance.FIXTURE)
        entry_fixture = create_execution_cache_entry(key=key_fixture, outcome=WitnessOutcome.PASS)
        cache.store_entry(entry_fixture)

        # Attempt to lookup fixture entry while requesting LIVE_NEBIUS provenance
        res = cache.lookup_by_key(
            key_fixture,
            requested_provenance=EvidenceProvenance.LIVE_NEBIUS,
        )
        assert res.hit is False
        assert res.rejection_reason == CacheRejectionReason.FORBIDDEN_PROVENANCE_SUBSTITUTION
        assert "Forbidden provenance substitution" in res.message
        assert cache.rejections_count == 1

    def test_strictly_forbids_local_to_live_nebius_substitution(self) -> None:
        cache = DeterministicExecutionCache()
        key_local = _make_key(provenance=EvidenceProvenance.LOCAL_EXECUTION)
        entry_local = create_execution_cache_entry(key=key_local, outcome=WitnessOutcome.PASS)
        cache.store_entry(entry_local)

        res = cache.lookup_by_key(
            key_local,
            requested_provenance=EvidenceProvenance.LIVE_NEBIUS,
        )
        assert res.hit is False
        assert res.rejection_reason == CacheRejectionReason.FORBIDDEN_PROVENANCE_SUBSTITUTION

    def test_strictly_forbids_recorded_live_to_current_live_substitution(self) -> None:
        cache = DeterministicExecutionCache()
        key_rec = _make_key(provenance=EvidenceProvenance.RECORDED_LIVE)
        entry_rec = create_execution_cache_entry(key=key_rec, outcome=WitnessOutcome.PASS)
        cache.store_entry(entry_rec)

        res = cache.lookup_by_key(
            key_rec,
            requested_provenance=EvidenceProvenance.LIVE_NEBIUS,
        )
        assert res.hit is False
        assert res.rejection_reason == CacheRejectionReason.FORBIDDEN_PROVENANCE_SUBSTITUTION

    def test_tampered_cache_entry_rejected_on_construction(self) -> None:
        key = _make_key()
        entry = create_execution_cache_entry(key=key, outcome=WitnessOutcome.PASS)

        with pytest.raises(CacheTamperingError, match="entry_digest mismatch"):
            ExecutionCacheEntry(
                key=key,
                outcome=WitnessOutcome.FAIL,
                exit_code=1,
                stdout_digest=entry.stdout_digest,
                stderr_digest=entry.stderr_digest,
                result_digest=entry.result_digest,
                duration_seconds=entry.duration_seconds,
                provenance=entry.provenance,
                created_at_utc=entry.created_at_utc,
                entry_digest=entry.entry_digest,  # Old digest!
                is_authoritative=False,
                grants_pass=False,
                is_causally_verified=False,
            )

    def test_in_memory_mutated_entry_rejected_on_lookup(self) -> None:
        cache = DeterministicExecutionCache()
        key = _make_key()
        entry = create_execution_cache_entry(key=key, outcome=WitnessOutcome.PASS)
        cache.store_entry(entry)

        # Mutate frozen field via object.__setattr__ to simulate memory tampering
        object.__setattr__(entry, "outcome", WitnessOutcome.FAIL)

        res = cache.lookup_by_key(key)
        assert res.hit is False
        assert res.rejection_reason == CacheRejectionReason.TAMPERED_ENTRY
        assert cache.rejections_count == 1

    def test_entry_with_provenance_mismatch_fails_construction(self) -> None:
        key = _make_key(provenance=EvidenceProvenance.LOCAL_EXECUTION)
        with pytest.raises(ForbiddenProvenanceSubstitutionError):
            ExecutionCacheEntry(
                key=key,
                outcome=WitnessOutcome.PASS,
                exit_code=0,
                stdout_digest="0" * 64,
                stderr_digest="0" * 64,
                result_digest="0" * 64,
                duration_seconds=0.0,
                provenance=EvidenceProvenance.LIVE_NEBIUS,  # Mismatch with key!
                created_at_utc="2026-10-07T00:00:00Z",
                entry_digest="0" * 64,
            )

    def test_entry_asserting_authority_fails_closed(self) -> None:
        key = _make_key()
        with pytest.raises(CacheTamperingError, match="is_authoritative must be False"):
            ExecutionCacheEntry(
                key=key,
                outcome=WitnessOutcome.PASS,
                exit_code=0,
                stdout_digest="0" * 64,
                stderr_digest="0" * 64,
                result_digest="0" * 64,
                duration_seconds=0.0,
                provenance=key.provenance,
                created_at_utc="2026-10-07T00:00:00Z",
                entry_digest="0" * 64,
                is_authoritative=True,  # Forbidden!
            )


class TestMinimizerCacheIntegration:
    """Tests BoundedSubsetMinimizer integration with DeterministicExecutionCache."""

    def test_minimizer_reuses_cached_execution_and_avoids_redundant_calls(self) -> None:
        p_digest = compute_bytes_digest(PATCH_TEXT.encode("utf-8")).value
        source = SourceIdentity(locator=REPO_LOCATOR, revision=CommitRevision(BASE_COMMIT))
        snap = CandidateSnapshot(
            candidate_id="cand-cache-test",
            source_identity=source,
            candidate_tree_digest=CAND_TREE,
            patch_digest=p_digest,
            patch_text=PATCH_TEXT,
            files_added=(),
            files_modified=("src/math.py",),
            files_deleted=(),
            builder_authored_tests=(),
            frozen_contract_digest=FROZEN_CONTRACT,
            context_digest="f" * 64,
            provenance=EvidenceProvenance.LOCAL_EXECUTION,
        )

        cache = DeterministicExecutionCache()
        call_count = 0

        def mock_callback(sub: Any, sc: Any) -> SubsetExecutionFact:
            nonlocal call_count
            call_count += 1
            return create_subset_execution_fact(
                subset=sub,
                scope=sc,
                outcome=WitnessOutcome.PASS,
                exit_code=0,
            )

        # Run 1: Cold cache -> calls callback
        minimizer1 = BoundedSubsetMinimizer(execution_callback=mock_callback, cache=cache)
        res1 = minimizer1.minimize(
            snapshot=snap,
            frozen_contract_digest=FROZEN_CONTRACT,
            sealed_witness_digest=SEALED_WITNESS,
            requirement_id=REQ_ID,
            base_outcome=WitnessOutcome.FAIL,
        )

        assert call_count == 1
        assert cache.total_entries == 1
        assert res1.evaluated_subsets[0].is_cached is False

        # Run 2: Hot cache with identical snapshot and scope -> cache hit!
        minimizer2 = BoundedSubsetMinimizer(execution_callback=mock_callback, cache=cache)
        res2 = minimizer2.minimize(
            snapshot=snap,
            frozen_contract_digest=FROZEN_CONTRACT,
            sealed_witness_digest=SEALED_WITNESS,
            requirement_id=REQ_ID,
            base_outcome=WitnessOutcome.FAIL,
        )

        # Callback was NOT called again!
        assert call_count == 1
        assert cache.hits_count == 1
        assert res2.evaluated_subsets[0].is_cached is True
        assert res2.minimal_subset is not None
