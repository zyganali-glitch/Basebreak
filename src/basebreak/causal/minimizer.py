"""Bounded hunk and subset minimization algorithm for causal slice verification.

P-12.02: Implement bounded hunk/subset minimization algorithm.

Basebreak Thesis:
"If the patch matters, the base must break."

Minimizer Objective:
Derive canonical patch units (exact parsed hunks) from the verified CandidateSnapshot,
and systematically explore bounded subsets to determine which tested subset of changes
is necessary under the exact frozen contract and sealed witness.

Invariants Enforced:
1. Deterministic authority: Runtime facts have final authority; models have zero authority.
2. Fixed baseline & witness: source identity, base commit, frozen contract, sealed witness,
   requirement identity, and verdict semantics remain strictly fixed across every execution.
3. Varying surface: candidate patch subset only.
4. Isolated materialization: Each tested subset is materialized in an isolated verifier context.
5. Anti-collapse invariant: ERROR != FAIL, TIMEOUT != FAIL.
6. Non-monotonic safety: Interacting hunks, non-monotonic behaviors, and multiple alternative
   sufficient subsets are detected and explicitly reported; greedy search results are never
   mislabeled as globally minimal.
7. Budget bounds: Search terminates deterministically within explicit configurable bounds.
8. Non-formal-proof disclaimer: Mandatory disclaimer is attached to every produced slice.
9. Zero self-certification: is_authoritative = False, grants_pass = False,
   is_causally_verified = False, claims_global_minimality = False.
"""

from __future__ import annotations

from collections.abc import Callable, Sequence
from dataclasses import dataclass, field
from typing import Any

from basebreak.builder.capture import CandidateSnapshot
from basebreak.causal.slice import (
    LOCAL_TEST_RUNTIME_CONFIG_DIGEST,
    BoundedCausalSlice,
    CausalSliceScope,
    CausalSliceStatus,
    ModelSliceProposal,
    NonFormalProofDisclaimer,
    SliceAuthorityError,
    SliceIdentityMismatchError,
    SliceScopeTamperingError,
    SliceSearchCompleteness,
    SubsetExecutionFact,
    TestedPatchSubset,
    create_bounded_causal_slice,
    create_canonical_disclaimer,
    create_causal_slice_scope,
    validate_no_prohibited_terms,
    verify_subset_execution_fact_integrity,
)
from basebreak.causal.subtraction import (
    EmptySubtractionError,
    InvalidSubtractionError,
    ParsedCandidatePatch,
    ParsedDiffHunk,
    SubtractionStrategyType,
    _reconstruct_file_diff_with_hunks,
    parse_candidate_patch,
)
from basebreak.domain.verdict import EvidenceProvenance
from basebreak.evidence.artifact import compute_bytes_digest
from basebreak.security.protected_surfaces import (
    ProtectedSurfaceViolation,
    get_canonical_basebreak_protected_manifest,
    validate_diff,
)
from basebreak.security.secret_policy import (
    SecretPersistenceError,
    validate_no_secrets,
)
from basebreak.verifier.witness_result import WitnessOutcome


class MinimizerError(Exception):
    """Base exception for causal slice minimizer failures."""


class BudgetExhaustedError(MinimizerError):
    """Raised when search budget is exhausted before finding a definitive slice."""


# --- Search Budget ---


@dataclass(frozen=True, slots=True)
class SliceSearchBudget:
    """Explicit configurable bounds for causal slice minimization search."""

    max_iterations: int = 20
    max_subsets_tested: int = 20
    max_depth: int = 5
    allow_model_ordering: bool = True

    def __post_init__(self) -> None:
        if isinstance(self.max_iterations, bool) or not isinstance(self.max_iterations, int):
            raise TypeError("max_iterations must be an integer")
        if self.max_iterations <= 0:
            raise ValueError(f"max_iterations must be positive, got {self.max_iterations}")

        if isinstance(self.max_subsets_tested, bool) or not isinstance(
            self.max_subsets_tested, int
        ):
            raise TypeError("max_subsets_tested must be an integer")
        if self.max_subsets_tested <= 0:
            raise ValueError(f"max_subsets_tested must be positive, got {self.max_subsets_tested}")

        if isinstance(self.max_depth, bool) or not isinstance(self.max_depth, int):
            raise TypeError("max_depth must be an integer")
        if self.max_depth <= 0:
            raise ValueError(f"max_depth must be positive, got {self.max_depth}")

        if not isinstance(self.allow_model_ordering, bool):
            raise TypeError("allow_model_ordering must be a boolean")


# --- Patch Unit ---


@dataclass(frozen=True, slots=True)
class PatchUnit:
    """Canonical searchable patch unit representing an exact parsed unified diff hunk."""

    hunk_id: str
    file_path: str
    hunk_index: int
    hunk_digest: str
    old_start: int
    old_length: int
    new_start: int
    new_length: int
    lines: tuple[str, ...]

    @classmethod
    def from_parsed_hunk(cls, hunk: ParsedDiffHunk) -> PatchUnit:
        return cls(
            hunk_id=hunk.hunk_id,
            file_path=hunk.file_path,
            hunk_index=hunk.hunk_index,
            hunk_digest=hunk.hunk_digest,
            old_start=hunk.old_start,
            old_length=hunk.old_length,
            new_start=hunk.new_start,
            new_length=hunk.new_length,
            lines=hunk.lines,
        )


# --- Evaluation Records ---


@dataclass(frozen=True, slots=True)
class SubsetEvaluationRecord:
    """Deterministic record of an executed subset under the sealed witness."""

    subset: TestedPatchSubset
    execution_fact: SubsetExecutionFact
    is_cached: bool = False
    evaluation_order: int = 0
    rejection_reason: str | None = None

    def __post_init__(self) -> None:
        if not isinstance(self.subset, TestedPatchSubset):
            raise TypeError(f"subset must be TestedPatchSubset, got {type(self.subset).__name__}")
        if not isinstance(self.execution_fact, SubsetExecutionFact):
            fact_type = type(self.execution_fact).__name__
            raise TypeError(f"execution_fact must be SubsetExecutionFact, got {fact_type}")
        if self.execution_fact.subset_id != self.subset.subset_id:
            raise SliceIdentityMismatchError(
                f"SubsetEvaluationRecord subset_id mismatch: "
                f"fact has {self.execution_fact.subset_id!r}, "
                f"subset has {self.subset.subset_id!r}"
            )
        if self.execution_fact.retained_patch_digest != self.subset.retained_patch_digest:
            raise SliceIdentityMismatchError(
                "SubsetEvaluationRecord retained_patch_digest mismatch: fact has "
                f"{self.execution_fact.retained_patch_digest}, "
                f"subset has {self.subset.retained_patch_digest}"
            )
        if self.execution_fact.subtracted_delta_digest != self.subset.subtracted_delta_digest:
            raise SliceIdentityMismatchError(
                "SubsetEvaluationRecord subtracted_delta_digest mismatch: fact has "
                f"{self.execution_fact.subtracted_delta_digest}, "
                f"subset has {self.subset.subtracted_delta_digest}"
            )
        if not verify_subset_execution_fact_integrity(self.execution_fact):
            raise SliceScopeTamperingError(
                f"execution_fact failed integrity check: {self.execution_fact.execution_digest}"
            )

    @property
    def outcome(self) -> WitnessOutcome:
        return self.execution_fact.outcome


@dataclass(frozen=True, slots=True)
class BoundedMinimizerResult:
    """Complete, deterministic result bundle of bounded causal slice minimization."""

    status: CausalSliceStatus
    completeness: SliceSearchCompleteness
    minimal_subset: TestedPatchSubset | None
    alternative_subsets: tuple[TestedPatchSubset, ...]
    evaluated_subsets: tuple[SubsetEvaluationRecord, ...]
    iterations_used: int
    summary_label: str
    scope: CausalSliceScope
    disclaimer: NonFormalProofDisclaimer
    search_budget: SliceSearchBudget = field(default_factory=SliceSearchBudget)
    runtime_config_digest: str = LOCAL_TEST_RUNTIME_CONFIG_DIGEST
    slice_artifact: BoundedCausalSlice | None = None
    is_authoritative: bool = False
    grants_pass: bool = False
    is_causally_verified: bool = False
    claims_global_minimality: bool = False

    def __post_init__(self) -> None:
        if self.is_authoritative is not False:
            raise SliceAuthorityError(
                "BoundedMinimizerResult cannot assert authority: is_authoritative must be False"
            )
        if self.grants_pass is not False:
            raise SliceAuthorityError(
                "BoundedMinimizerResult cannot grant pass: grants_pass must be False"
            )
        if self.is_causally_verified is not False:
            raise SliceAuthorityError(
                "BoundedMinimizerResult cannot assert verification: "
                "is_causally_verified must be False"
            )
        if self.claims_global_minimality is not False:
            raise SliceAuthorityError(
                "BoundedMinimizerResult cannot claim global minimality: "
                "claims_global_minimality must be False"
            )
        validate_no_prohibited_terms(self.summary_label, "summary_label")


# --- Reconstruct Subset Patch Helper ---


def reconstruct_subset_patch(
    parsed_patch: ParsedCandidatePatch,
    retained_hunk_ids: Sequence[str],
) -> tuple[str, str, tuple[str, ...], tuple[str, ...], tuple[str, ...], tuple[str, ...]]:
    """Deterministically reconstruct retained patch text and subtracted delta text.

    Returns:
        (retained_patch_text, subtracted_delta_text,
         retained_files, retained_hunk_ids,
         subtracted_files, subtracted_hunk_ids)
    """
    retained_id_set = set(retained_hunk_ids)

    retained_file_chunks: list[str] = []
    subtracted_file_chunks: list[str] = []
    retained_files: list[str] = []
    subtracted_files: list[str] = []
    actual_retained_hunks: list[str] = []
    actual_subtracted_hunks: list[str] = []

    for f in parsed_patch.files:
        f_retained = [h for h in f.hunks if h.hunk_id in retained_id_set]
        f_subtracted = [h for h in f.hunks if h.hunk_id not in retained_id_set]

        if f_retained:
            retained_files.append(f.file_path)
            actual_retained_hunks.extend(h.hunk_id for h in f_retained)
            ret_diff = _reconstruct_file_diff_with_hunks(f, f_retained)
            if ret_diff:
                retained_file_chunks.append(ret_diff)

        if f_subtracted:
            subtracted_files.append(f.file_path)
            actual_subtracted_hunks.extend(h.hunk_id for h in f_subtracted)
            sub_diff = _reconstruct_file_diff_with_hunks(f, f_subtracted)
            if sub_diff:
                subtracted_file_chunks.append(sub_diff)

    retained_patch_text = "".join(retained_file_chunks)
    subtracted_delta_text = "".join(subtracted_file_chunks)

    return (
        retained_patch_text,
        subtracted_delta_text,
        tuple(sorted(set(retained_files))),
        tuple(sorted(actual_retained_hunks)),
        tuple(sorted(set(subtracted_files))),
        tuple(sorted(actual_subtracted_hunks)),
    )


def create_tested_patch_subset_from_hunks(
    parsed_patch: ParsedCandidatePatch,
    retained_hunk_ids: Sequence[str],
) -> TestedPatchSubset:
    """Create a validated TestedPatchSubset from a selected set of hunk IDs."""
    (
        retained_patch_text,
        subtracted_delta_text,
        retained_files,
        actual_retained_hunk_ids,
        subtracted_files,
        actual_subtracted_hunk_ids,
    ) = reconstruct_subset_patch(parsed_patch, retained_hunk_ids)

    if not actual_retained_hunk_ids:
        raise EmptySubtractionError("TestedPatchSubset must have at least one retained hunk")

    # Security & policy validations on the reconstructed retained patch
    manifest = get_canonical_basebreak_protected_manifest()
    try:
        validate_diff(retained_patch_text, manifest)
        if subtracted_delta_text:
            validate_diff(subtracted_delta_text, manifest)
    except ProtectedSurfaceViolation as exc:
        raise ProtectedSurfaceViolation(
            f"Reconstructed patch subset violates protected surface: {exc}"
        ) from exc

    try:
        validate_no_secrets(retained_patch_text, path="retained_patch_text")
        if subtracted_delta_text:
            validate_no_secrets(subtracted_delta_text, path="subtracted_delta_text")
    except SecretPersistenceError:
        raise

    retained_digest = compute_bytes_digest(retained_patch_text.encode("utf-8")).value
    subtracted_digest = (
        compute_bytes_digest(subtracted_delta_text.encode("utf-8")).value
        if subtracted_delta_text
        else "0" * 64
    )

    subset_id = f"subset-{retained_digest[:16]}"

    return TestedPatchSubset(
        subset_id=subset_id,
        strategy_type=SubtractionStrategyType.HUNK_LEVEL_REVERT,
        retained_files=retained_files,
        retained_hunk_ids=actual_retained_hunk_ids,
        subtracted_files=subtracted_files,
        subtracted_hunk_ids=actual_subtracted_hunk_ids,
        retained_patch_digest=retained_digest,
        subtracted_delta_digest=subtracted_digest,
        is_empty=False,
        is_authoritative=False,
        grants_pass=False,
        is_causally_verified=False,
    )


# --- Bounded Minimizer Engine ---


class BoundedSubsetMinimizer:
    """Deterministic bounded hunk and subset minimization engine.

    Executes a bounded search over candidate patch hunks against an identical
    sealed witness to discover a witness-relative tested necessary subset.
    """

    def __init__(
        self,
        *,
        execution_callback: Callable[[TestedPatchSubset, CausalSliceScope], SubsetExecutionFact]
        | None = None,
        cache: Any | None = None,
        budget: SliceSearchBudget | None = None,
        runtime_config_digest: str = LOCAL_TEST_RUNTIME_CONFIG_DIGEST,
        execution_command: Sequence[str] | str = ("pytest",),
    ) -> None:
        if execution_callback is not None and not callable(execution_callback):
            raise TypeError("execution_callback must be callable")
        self.execution_callback = execution_callback
        self.cache = cache
        self.budget = budget or SliceSearchBudget()
        self.runtime_config_digest = runtime_config_digest.strip().lower()
        if isinstance(execution_command, str):
            self.execution_command: tuple[str, ...] = tuple(execution_command.split())
        else:
            self.execution_command = tuple(str(c) for c in execution_command)

    @classmethod
    def derive_patch_units(cls, snapshot: CandidateSnapshot) -> tuple[PatchUnit, ...]:
        """Mechanically parse exact candidate patch into canonical searchable PatchUnits."""
        if not isinstance(snapshot, CandidateSnapshot):
            raise TypeError(f"snapshot must be CandidateSnapshot, got {type(snapshot).__name__}")
        parsed = parse_candidate_patch(snapshot.patch_text)
        units: list[PatchUnit] = []
        for f in parsed.files:
            for h in f.hunks:
                units.append(PatchUnit.from_parsed_hunk(h))
        # Ensure deterministic ordering: (file_path, hunk_index, old_start)
        units.sort(key=lambda u: (u.file_path, u.hunk_index, u.old_start))
        return tuple(units)

    def _validate_execution_fact(
        self,
        fact: SubsetExecutionFact,
        *,
        subset: TestedPatchSubset,
        scope: CausalSliceScope,
    ) -> None:
        """Mechanically validate that returned execution fact matches requested subset and scope."""
        if fact.subset_id != subset.subset_id:
            raise SliceIdentityMismatchError(
                f"Execution fact subset_id mismatch: {fact.subset_id!r} != {subset.subset_id!r}"
            )
        if fact.retained_patch_digest != subset.retained_patch_digest:
            raise SliceIdentityMismatchError(
                f"Execution fact retained_patch_digest mismatch: "
                f"{fact.retained_patch_digest} != {subset.retained_patch_digest}"
            )
        if fact.subtracted_delta_digest != subset.subtracted_delta_digest:
            raise SliceIdentityMismatchError(
                f"Execution fact subtracted_delta_digest mismatch: "
                f"{fact.subtracted_delta_digest} != {subset.subtracted_delta_digest}"
            )
        if fact.scope_digest != scope.scope_digest:
            raise SliceIdentityMismatchError(
                f"Execution fact scope_digest mismatch: {fact.scope_digest} != {scope.scope_digest}"
            )
        if fact.frozen_contract_digest != scope.frozen_contract_digest:
            raise SliceIdentityMismatchError(
                f"Execution fact frozen_contract_digest mismatch: "
                f"{fact.frozen_contract_digest} != {scope.frozen_contract_digest}"
            )
        if fact.sealed_witness_digest != scope.sealed_witness_digest:
            raise SliceIdentityMismatchError(
                f"Execution fact sealed_witness_digest mismatch: "
                f"{fact.sealed_witness_digest} != {scope.sealed_witness_digest}"
            )
        if fact.requirement_id != scope.requirement_id:
            raise SliceIdentityMismatchError(
                f"Execution fact requirement_id mismatch: "
                f"{fact.requirement_id} != {scope.requirement_id}"
            )
        if fact.candidate_id != scope.candidate_id:
            raise SliceIdentityMismatchError(
                f"Execution fact candidate_id mismatch: {fact.candidate_id} != {scope.candidate_id}"
            )
        if fact.tree_digest != scope.candidate_tree_digest:
            raise SliceIdentityMismatchError(
                f"Execution fact tree_digest mismatch: "
                f"{fact.tree_digest} != {scope.candidate_tree_digest}"
            )
        if fact.runtime_config_digest != self.runtime_config_digest:
            raise SliceIdentityMismatchError(
                f"Execution fact runtime_config_digest mismatch: "
                f"{fact.runtime_config_digest} != {self.runtime_config_digest}"
            )
        if fact.provenance != scope.provenance:
            raise SliceIdentityMismatchError(
                f"Execution fact provenance mismatch: "
                f"{fact.provenance.value} != {scope.provenance.value}"
            )
        if not verify_subset_execution_fact_integrity(fact):
            raise SliceScopeTamperingError(
                f"Execution fact failed integrity verification: {fact.execution_digest}"
            )

    def _evaluate_subset(
        self,
        subset: TestedPatchSubset,
        scope: CausalSliceScope,
        eval_order: int,
    ) -> SubsetEvaluationRecord:
        """Evaluate a single subset, utilizing cache when available and valid."""
        # Check cache if provided
        if self.cache is not None:
            cached_res = self.cache.lookup(
                subset=subset,
                scope=scope,
                execution_command=self.execution_command,
                runtime_config_digest=self.runtime_config_digest,
                requested_provenance=scope.provenance,
            )
            if cached_res.hit and cached_res.entry is not None:
                cached_fact = cached_res.entry.to_execution_fact(subset=subset, scope=scope)
                self._validate_execution_fact(cached_fact, subset=subset, scope=scope)
                return SubsetEvaluationRecord(
                    subset=subset,
                    execution_fact=cached_fact,
                    is_cached=True,
                    evaluation_order=eval_order,
                )

        if self.execution_callback is None:
            raise MinimizerError("No execution_callback provided and cache missed")

        # Run fresh execution via callback
        raw_result = self.execution_callback(subset, scope)
        if isinstance(raw_result, WitnessOutcome):
            raise TypeError(
                f"execution_callback returned naked WitnessOutcome ({raw_result.value}); "
                "naked WitnessOutcome is no longer sufficient for authentic production "
                "evidence. Must return a verified SubsetExecutionFact."
            )
        if not isinstance(raw_result, SubsetExecutionFact):
            raise TypeError(
                f"execution_callback returned {type(raw_result).__name__}, "
                "expected SubsetExecutionFact"
            )

        fact = raw_result
        self._validate_execution_fact(fact, subset=subset, scope=scope)

        # Record in cache if available
        if self.cache is not None:
            self.cache.store_fact(fact=fact, subset=subset, scope=scope)

        return SubsetEvaluationRecord(
            subset=subset,
            execution_fact=fact,
            is_cached=False,
            evaluation_order=eval_order,
        )

    def minimize(
        self,
        *,
        snapshot: CandidateSnapshot,
        frozen_contract_digest: str,
        sealed_witness_digest: str,
        requirement_id: str,
        base_outcome: WitnessOutcome = WitnessOutcome.FAIL,
        model_proposal: ModelSliceProposal | None = None,
        provenance: EvidenceProvenance = EvidenceProvenance.LOCAL_EXECUTION,
        disclaimer: NonFormalProofDisclaimer | None = None,
        created_at_utc: str | None = None,
    ) -> BoundedMinimizerResult:
        """Execute bounded hunk minimization over candidate snapshot.

        Steps:
        1. Establish immutable scope.
        2. Validate base outcome (must be FAIL).
        3. Derive canonical patch units.
        4. Validate and test full candidate (must be PASS).
        5. If single hunk: conclude tested necessary subset.
        6. Explore proper subsets within budget bounds.
        7. Detect interactions, non-monotonic behaviors, and multiple sufficient subsets.
        8. Construct BoundedCausalSlice artifact and return authentic result.
        """
        if provenance == EvidenceProvenance.LIVE_NEBIUS and (
            self.runtime_config_digest == LOCAL_TEST_RUNTIME_CONFIG_DIGEST
        ):
            raise MinimizerError(
                "LOCAL_TEST_RUNTIME_CONFIG_DIGEST cannot satisfy LIVE_NEBIUS evidence; "
                "an authentic runtime_config_digest must be provided"
            )

        disc = disclaimer or create_canonical_disclaimer()
        scope = create_causal_slice_scope(
            snapshot=snapshot,
            frozen_contract_digest=frozen_contract_digest,
            sealed_witness_digest=sealed_witness_digest,
            requirement_id=requirement_id,
            provenance=provenance,
            disclaimer=disc,
        )

        eval_records: list[SubsetEvaluationRecord] = []
        eval_counter = 0

        # Anti-collapse & Baseline Invariant: Base must be FAIL
        if base_outcome != WitnessOutcome.FAIL:
            return BoundedMinimizerResult(
                status=CausalSliceStatus.INVALID_SUBSET,
                completeness=SliceSearchCompleteness.EXHAUSTIVE_BOUNDED,
                minimal_subset=None,
                alternative_subsets=(),
                evaluated_subsets=(),
                iterations_used=0,
                summary_label=(
                    f"base outcome is {base_outcome.value}, not FAIL; cannot establish necessity"
                ),
                scope=scope,
                disclaimer=disc,
                slice_artifact=None,
            )

        # Parse canonical patch and derive patch units
        parsed_patch = parse_candidate_patch(snapshot.patch_text)
        units = self.derive_patch_units(snapshot)
        if not units:
            raise EmptySubtractionError("Candidate patch contains zero hunks")

        all_hunk_ids = tuple(u.hunk_id for u in units)

        # Build full candidate subset
        full_subset = create_tested_patch_subset_from_hunks(parsed_patch, all_hunk_ids)

        # Test full candidate
        eval_counter += 1
        full_eval = self._evaluate_subset(full_subset, scope, eval_counter)
        eval_records.append(full_eval)

        # Anti-collapse & Candidate Invariant: Full candidate must be PASS
        if full_eval.outcome != WitnessOutcome.PASS:
            # ERROR or TIMEOUT must not collapse into FAIL
            status = (
                CausalSliceStatus.INVALID_SUBSET
                if full_eval.outcome in (WitnessOutcome.ERROR, WitnessOutcome.TIMEOUT)
                else CausalSliceStatus.INCONCLUSIVE_INTERACTION
            )
            return BoundedMinimizerResult(
                status=status,
                completeness=SliceSearchCompleteness.BOUNDED_GREEDY,
                minimal_subset=None,
                alternative_subsets=(),
                evaluated_subsets=tuple(eval_records),
                iterations_used=eval_counter,
                summary_label=f"full candidate outcome is {full_eval.outcome.value}, not PASS",
                scope=scope,
                disclaimer=disc,
                search_budget=self.budget,
                runtime_config_digest=self.runtime_config_digest,
                slice_artifact=None,
            )

        n_units = len(units)

        # Single hunk case: full candidate has 1 hunk, base failed, full passed.
        # No proper non-empty subset exists. That single hunk is tested necessary subset.
        if n_units == 1:
            single_slice_art = create_bounded_causal_slice(
                slice_id=f"slice-{full_subset.retained_patch_digest[:16]}",
                scope=scope,
                tested_subset=full_subset,
                status=CausalSliceStatus.TESTED_NECESSARY_SUBSET,
                completeness=SliceSearchCompleteness.EXHAUSTIVE_BOUNDED,
                summary_label="single hunk candidate is tested necessary subset under witness",
                disclaimer=disc,
                created_at_utc=created_at_utc,
            )
            return BoundedMinimizerResult(
                status=CausalSliceStatus.TESTED_NECESSARY_SUBSET,
                completeness=SliceSearchCompleteness.EXHAUSTIVE_BOUNDED,
                minimal_subset=full_subset,
                alternative_subsets=(),
                evaluated_subsets=tuple(eval_records),
                iterations_used=eval_counter,
                summary_label="single hunk candidate is tested necessary subset under witness",
                scope=scope,
                disclaimer=disc,
                search_budget=self.budget,
                runtime_config_digest=self.runtime_config_digest,
                slice_artifact=single_slice_art,
            )

        # Multi-hunk case (N > 1)
        candidate_subsets_to_test: list[tuple[str, ...]] = []

        if model_proposal is not None:
            # Model proposal has zero verdict authority
            if model_proposal.is_authoritative or model_proposal.claims_minimality:
                raise SliceAuthorityError(
                    "ModelSliceProposal cannot assert authority or claim minimality"
                )
            if self.budget.allow_model_ordering and model_proposal.proposed_retained_hunks:
                # Prioritize testing model-suggested retained hunks if valid
                proposed = tuple(
                    h for h in model_proposal.proposed_retained_hunks if h in all_hunk_ids
                )
                if proposed and len(proposed) < n_units:
                    candidate_subsets_to_test.append(proposed)

        # Standard deterministic search order:
        # 1. 1-omission: H \ {h_i} for each hunk (test removing each hunk)
        for h_id in all_hunk_ids:
            subset_ids = tuple(x for x in all_hunk_ids if x != h_id)
            if subset_ids and subset_ids not in candidate_subsets_to_test:
                candidate_subsets_to_test.append(subset_ids)

        # 2. 1-retention: {h_i} for each hunk (test each hunk alone)
        for h_id in all_hunk_ids:
            subset_ids = (h_id,)
            if subset_ids not in candidate_subsets_to_test:
                candidate_subsets_to_test.append(subset_ids)

        # If N >= 3, also test pairs if within depth and budget
        if n_units >= 3 and self.budget.max_depth >= 2:
            for i in range(n_units):
                for j in range(i + 1, n_units):
                    pair = (units[i].hunk_id, units[j].hunk_id)
                    if pair not in candidate_subsets_to_test:
                        candidate_subsets_to_test.append(pair)

        # Run bounded search
        passing_subsets: list[TestedPatchSubset] = []
        budget_exhausted = False
        non_monotonic_detected = False
        error_or_timeout_detected = False

        for candidate_hunk_ids in candidate_subsets_to_test:
            if (
                eval_counter >= self.budget.max_subsets_tested
                or eval_counter >= self.budget.max_iterations
            ):
                budget_exhausted = True
                break

            try:
                sub = create_tested_patch_subset_from_hunks(parsed_patch, candidate_hunk_ids)
            except (EmptySubtractionError, InvalidSubtractionError, ProtectedSurfaceViolation):
                continue

            eval_counter += 1
            eval_record = self._evaluate_subset(sub, scope, eval_counter)
            eval_records.append(eval_record)

            if eval_record.outcome == WitnessOutcome.PASS:
                passing_subsets.append(sub)
            elif eval_record.outcome in (WitnessOutcome.ERROR, WitnessOutcome.TIMEOUT):
                error_or_timeout_detected = True

        # Analyze outcomes
        single_hunk_passing = [s for s in passing_subsets if len(s.retained_hunk_ids) == 1]
        if len(single_hunk_passing) >= 2:
            pair_hunks: set[str] = set()
            for s in single_hunk_passing:
                pair_hunks.update(s.retained_hunk_ids)
            for rec in eval_records:
                if (
                    set(rec.subset.retained_hunk_ids) == pair_hunks
                    and rec.outcome == WitnessOutcome.FAIL
                ):
                    non_monotonic_detected = True
                    break

        # Decision Logic:
        final_status: CausalSliceStatus
        final_completeness: SliceSearchCompleteness
        final_label: str
        chosen_minimal: TestedPatchSubset | None = None
        alternative_subsets: tuple[TestedPatchSubset, ...] = ()

        if non_monotonic_detected:
            final_status = CausalSliceStatus.INCONCLUSIVE_INTERACTION
            final_completeness = (
                SliceSearchCompleteness.PARTIAL_ABORTED
                if budget_exhausted
                else SliceSearchCompleteness.EXHAUSTIVE_BOUNDED
            )
            final_label = "non-monotonic interaction detected among candidate patch hunks"

        elif len(single_hunk_passing) > 1:
            # Multiple distinct single hunks passed independently
            final_status = CausalSliceStatus.MULTIPLE_SUFFICIENT_SUBSETS
            final_completeness = (
                SliceSearchCompleteness.PARTIAL_ABORTED
                if budget_exhausted
                else SliceSearchCompleteness.EXHAUSTIVE_BOUNDED
            )
            alternative_subsets = tuple(single_hunk_passing)
            final_label = (
                f"{len(single_hunk_passing)} alternative sufficient subsets "
                "discovered under witness"
            )
            chosen_minimal = single_hunk_passing[0]

        elif budget_exhausted and not passing_subsets:
            final_status = CausalSliceStatus.INCONCLUSIVE_INCOMPLETE
            final_completeness = SliceSearchCompleteness.PARTIAL_ABORTED
            final_label = "search budget exhausted before determining necessary subset"

        elif not passing_subsets:
            # If errors or timeouts occurred, cannot definitively conclude NO_REDUCTION_FOUND
            if error_or_timeout_detected:
                final_status = CausalSliceStatus.AMBIGUOUS_SLICE
                final_completeness = SliceSearchCompleteness.PARTIAL_ABORTED
                final_label = (
                    "search encountered execution error or timeout; slice result is ambiguous"
                )
            else:
                final_status = CausalSliceStatus.NO_REDUCTION_FOUND
                final_completeness = (
                    SliceSearchCompleteness.PARTIAL_ABORTED
                    if budget_exhausted
                    else SliceSearchCompleteness.EXHAUSTIVE_BOUNDED
                )
                chosen_minimal = full_subset
                final_label = (
                    "no proper subset sufficient; all hunks required together under witness"
                )

        else:
            sorted_passing = sorted(passing_subsets, key=lambda s: len(s.retained_hunk_ids))
            min_size = len(sorted_passing[0].retained_hunk_ids)
            minimal_candidates = [s for s in sorted_passing if len(s.retained_hunk_ids) == min_size]

            if len(minimal_candidates) > 1:
                final_status = CausalSliceStatus.MULTIPLE_SUFFICIENT_SUBSETS
                final_completeness = (
                    SliceSearchCompleteness.PARTIAL_ABORTED
                    if budget_exhausted
                    else SliceSearchCompleteness.EXHAUSTIVE_BOUNDED
                )
                alternative_subsets = tuple(minimal_candidates)
                final_label = (
                    f"multiple ({len(minimal_candidates)}) sufficient subsets "
                    f"of size {min_size} discovered"
                )
                chosen_minimal = minimal_candidates[0]
            else:
                chosen_minimal = minimal_candidates[0]
                final_status = CausalSliceStatus.TESTED_NECESSARY_SUBSET
                final_completeness = (
                    SliceSearchCompleteness.BOUNDED_GREEDY
                    if budget_exhausted
                    else SliceSearchCompleteness.EXHAUSTIVE_BOUNDED
                )
                n_removed = len(chosen_minimal.subtracted_hunk_ids)
                final_label = (
                    f"tested necessary subset found ({n_removed} irrelevant hunks removed)"
                )

        # Construct BoundedCausalSlice artifact if a minimal subset was chosen
        slice_art: BoundedCausalSlice | None = None
        if chosen_minimal is not None:
            slice_art = create_bounded_causal_slice(
                slice_id=f"slice-{chosen_minimal.retained_patch_digest[:16]}",
                scope=scope,
                tested_subset=chosen_minimal,
                status=final_status,
                completeness=final_completeness,
                summary_label=final_label,
                disclaimer=disc,
                created_at_utc=created_at_utc,
            )

        return BoundedMinimizerResult(
            status=final_status,
            completeness=final_completeness,
            minimal_subset=chosen_minimal,
            alternative_subsets=alternative_subsets,
            evaluated_subsets=tuple(eval_records),
            iterations_used=eval_counter,
            summary_label=final_label,
            scope=scope,
            disclaimer=disc,
            search_budget=self.budget,
            runtime_config_digest=self.runtime_config_digest,
            slice_artifact=slice_art,
            is_authoritative=False,
            grants_pass=False,
            is_causally_verified=False,
            claims_global_minimality=False,
        )


__all__ = [
    "BoundedMinimizerResult",
    "BoundedSubsetMinimizer",
    "BudgetExhaustedError",
    "MinimizerError",
    "PatchUnit",
    "SliceSearchBudget",
    "SubsetEvaluationRecord",
    "create_tested_patch_subset_from_hunks",
    "reconstruct_subset_patch",
]
