"""Cryptographically bound evidence receipt for minimal causal slice verification.

P-12.04: Bind requirement -> witness -> minimal necessary candidate slice.

Basebreak Thesis:
"If the patch matters, the base must break."

Binding Invariants:
Unbroken deterministic cryptographic custody chain:
requirement_id
-> frozen_contract_digest
-> sealed_witness_digest
-> source_identity (locator, commit_id, subpath)
-> candidate_id, candidate_tree_digest, candidate_patch_digest
-> slice_artifact (BoundedCausalSlice)
-> search_budget (SliceSearchBudget)
-> tested_subsets (tuple[TestedPatchSubset, ...])
-> evaluated_outcomes
-> counterfactual_delta_digests
-> status (CausalSliceStatus)
-> completeness (SliceSearchCompleteness)
-> provenance (EvidenceProvenance)
-> disclaimer (NonFormalProofDisclaimer)
-> receipt_digest (SHA-256 over canonical JSON)

Authority Boundary Invariants:
- is_authoritative = False
- grants_pass = False
- is_causally_verified = False
- claims_global_minimality = False
The slice receipt possesses ZERO independent verdict authority. It MUST NOT
independently upgrade candidate verification status. If upstream candidate evidence
is invalid or inconclusive, slice evidence remains non-verifying.
"""

from __future__ import annotations

import hashlib
import json
import re
from collections.abc import Mapping, Sequence
from dataclasses import dataclass
from datetime import datetime, timezone
from typing import Any

from basebreak.causal.minimizer import BoundedMinimizerResult, SliceSearchBudget
from basebreak.causal.slice import (
    LOCAL_TEST_RUNTIME_CONFIG_DIGEST,
    BoundedCausalSlice,
    CausalSliceError,
    CausalSliceStatus,
    DisclaimerMissingError,
    NonFormalProofDisclaimer,
    SliceAuthorityError,
    SliceIdentityMismatchError,
    SliceSearchCompleteness,
    SubsetExecutionFact,
    TestedPatchSubset,
    create_bounded_causal_slice,
    create_canonical_disclaimer,
    verify_slice_integrity,
    verify_subset_execution_fact_integrity,
)
from basebreak.domain.verdict import EvidenceProvenance, PreliminaryVerdict

CAUSAL_SLICE_RECEIPT_SCHEMA_VERSION: str = "1.0.0"

_HEX_40_PATTERN = re.compile(r"^[0-9a-f]{40}$")
_HEX_64_PATTERN = re.compile(r"^[0-9a-f]{64}$")
_HEX_40_OR_64_PATTERN = re.compile(r"^([0-9a-f]{40}|[0-9a-f]{64})$")


class SliceReceiptError(CausalSliceError):
    """Base exception for causal slice receipt errors."""


class SliceReceiptIntegrityError(SliceReceiptError):
    """Raised when causal slice receipt violates domain constraints or format."""


class SliceReceiptTamperingError(SliceReceiptError):
    """Raised when causal slice receipt facts do not match the cryptographic digest."""


def compute_slice_receipt_digest(payload: Mapping[str, Any]) -> str:
    """Compute deterministic SHA-256 digest of canonical slice receipt payload."""
    canonical_bytes = json.dumps(
        payload, sort_keys=True, separators=(",", ":"), ensure_ascii=False
    ).encode("utf-8")
    return hashlib.sha256(canonical_bytes).hexdigest()


@dataclass(frozen=True, slots=True)
class CausalSliceReceipt:
    """Authentic, cryptographically bound evidence receipt for causal slice minimization.

    Binds requirement -> frozen contract -> sealed witness -> source identity ->
    candidate snapshot facts -> tested subsets -> slice artifact -> budget ->
    disclaimer -> receipt digest.

    Guarantees:
    - Zero verdict authority: is_authoritative = False, grants_pass = False,
      is_causally_verified = False, claims_global_minimality = False.
    - Full cryptographic tamper detection.
    """

    requirement_id: str
    frozen_contract_digest: str
    sealed_witness_digest: str
    witness_id: str
    source_locator: str
    source_commit_id: str
    source_subpath: str
    candidate_id: str
    candidate_tree_digest: str
    candidate_patch_digest: str
    slice_artifact: BoundedCausalSlice
    search_budget: SliceSearchBudget
    tested_subsets: tuple[TestedPatchSubset, ...]
    evaluated_outcomes: tuple[str, ...]
    counterfactual_delta_digests: tuple[str, ...]
    execution_facts: tuple[SubsetExecutionFact, ...]
    runtime_config_digest: str
    status: CausalSliceStatus
    completeness: SliceSearchCompleteness
    provenance: EvidenceProvenance
    disclaimer: NonFormalProofDisclaimer
    created_at_utc: str
    receipt_digest: str
    schema_version: str = CAUSAL_SLICE_RECEIPT_SCHEMA_VERSION
    is_authoritative: bool = False
    grants_pass: bool = False
    is_causally_verified: bool = False
    claims_global_minimality: bool = False

    def __post_init__(self) -> None:
        if self.is_authoritative is not False:
            raise SliceAuthorityError(
                "CausalSliceReceipt cannot assert authority: is_authoritative must be False"
            )
        if self.grants_pass is not False:
            raise SliceAuthorityError(
                "CausalSliceReceipt cannot grant pass: grants_pass must be False"
            )
        if self.is_causally_verified is not False:
            raise SliceAuthorityError(
                "CausalSliceReceipt cannot assert verification: is_causally_verified must be False"
            )
        if self.claims_global_minimality is not False:
            raise SliceAuthorityError(
                "CausalSliceReceipt cannot claim global minimality: "
                "claims_global_minimality must be False"
            )

        if not isinstance(self.requirement_id, str) or not self.requirement_id.strip():
            raise SliceReceiptIntegrityError("requirement_id must be a non-empty string")
        if not isinstance(self.frozen_contract_digest, str) or not _HEX_64_PATTERN.match(
            self.frozen_contract_digest
        ):
            raise SliceReceiptIntegrityError(
                f"frozen_contract_digest must be 64 hex chars: {self.frozen_contract_digest!r}"
            )
        if not isinstance(self.sealed_witness_digest, str) or not _HEX_64_PATTERN.match(
            self.sealed_witness_digest
        ):
            raise SliceReceiptIntegrityError(
                f"sealed_witness_digest must be 64 hex chars: {self.sealed_witness_digest!r}"
            )
        if not isinstance(self.witness_id, str) or not self.witness_id.strip():
            raise SliceReceiptIntegrityError("witness_id must be a non-empty string")
        if not isinstance(self.source_locator, str) or not self.source_locator.strip():
            raise SliceReceiptIntegrityError("source_locator must be a non-empty string")
        if not isinstance(self.source_commit_id, str) or not _HEX_40_PATTERN.match(
            self.source_commit_id
        ):
            raise SliceReceiptIntegrityError(
                f"source_commit_id must be 40 hex chars: {self.source_commit_id!r}"
            )
        if not isinstance(self.candidate_id, str) or not self.candidate_id.strip():
            raise SliceReceiptIntegrityError("candidate_id must be a non-empty string")
        if not isinstance(self.candidate_tree_digest, str) or not _HEX_40_OR_64_PATTERN.match(
            self.candidate_tree_digest
        ):
            raise SliceReceiptIntegrityError(
                f"candidate_tree_digest must be 40 or 64 hex chars: {self.candidate_tree_digest!r}"
            )
        if not isinstance(self.candidate_patch_digest, str) or not _HEX_64_PATTERN.match(
            self.candidate_patch_digest
        ):
            raise SliceReceiptIntegrityError(
                f"candidate_patch_digest must be 64 hex chars: {self.candidate_patch_digest!r}"
            )
        if not isinstance(self.runtime_config_digest, str) or not _HEX_64_PATTERN.match(
            self.runtime_config_digest
        ):
            raise SliceReceiptIntegrityError(
                f"runtime_config_digest must be 64 hex chars: {self.runtime_config_digest!r}"
            )

        if not isinstance(self.slice_artifact, BoundedCausalSlice):
            art_type = type(self.slice_artifact).__name__
            raise TypeError(f"slice_artifact must be BoundedCausalSlice, got {art_type}")
        if not isinstance(self.search_budget, SliceSearchBudget):
            raise TypeError(
                f"search_budget must be SliceSearchBudget, got {type(self.search_budget).__name__}"
            )
        if not isinstance(self.status, CausalSliceStatus):
            raise TypeError(f"status must be CausalSliceStatus, got {type(self.status).__name__}")
        if not isinstance(self.completeness, SliceSearchCompleteness):
            comp_type = type(self.completeness).__name__
            raise TypeError(f"completeness must be SliceSearchCompleteness, got {comp_type}")
        if not isinstance(self.provenance, EvidenceProvenance):
            raise TypeError(
                f"provenance must be EvidenceProvenance, got {type(self.provenance).__name__}"
            )
        if not isinstance(self.disclaimer, NonFormalProofDisclaimer):
            raise DisclaimerMissingError("disclaimer must be NonFormalProofDisclaimer")

        if self.provenance == EvidenceProvenance.LIVE_NEBIUS and (
            self.runtime_config_digest == LOCAL_TEST_RUNTIME_CONFIG_DIGEST
        ):
            raise SliceReceiptIntegrityError(
                "LOCAL_TEST_RUNTIME_CONFIG_DIGEST cannot satisfy LIVE_NEBIUS provenance"
            )

        # Count alignment
        if len(self.tested_subsets) != len(self.execution_facts):
            raise SliceReceiptIntegrityError(
                f"Count mismatch: tested_subsets count ({len(self.tested_subsets)}) "
                f"!= execution_facts count ({len(self.execution_facts)})"
            )
        if len(self.tested_subsets) != len(self.evaluated_outcomes):
            raise SliceReceiptIntegrityError(
                f"Count mismatch: tested_subsets count ({len(self.tested_subsets)}) "
                f"!= evaluated_outcomes count ({len(self.evaluated_outcomes)})"
            )
        if len(self.tested_subsets) != len(self.counterfactual_delta_digests):
            raise SliceReceiptIntegrityError(
                f"Count mismatch: tested_subsets count ({len(self.tested_subsets)}) "
                f"!= counterfactual_delta_digests count ({len(self.counterfactual_delta_digests)})"
            )

        # Subset to execution fact 1-to-1 mechanical binding
        for i, (subset, fact, outcome_str, delta_digest) in enumerate(
            zip(
                self.tested_subsets,
                self.execution_facts,
                self.evaluated_outcomes,
                self.counterfactual_delta_digests,
                strict=True,
            )
        ):
            if not isinstance(fact, SubsetExecutionFact):
                raise TypeError(
                    f"execution_facts[{i}] must be SubsetExecutionFact, got {type(fact).__name__}"
                )
            if not verify_subset_execution_fact_integrity(fact):
                raise SliceReceiptTamperingError(
                    f"execution_facts[{i}] failed cryptographic integrity verification"
                )

            if fact.subset_id != subset.subset_id:
                raise SliceIdentityMismatchError(
                    f"Subset ID mismatch at index {i}: fact has {fact.subset_id!r}, "
                    f"subset has {subset.subset_id!r}"
                )
            if fact.retained_patch_digest != subset.retained_patch_digest:
                raise SliceIdentityMismatchError(
                    f"retained_patch_digest mismatch at index {i}: fact has "
                    f"{fact.retained_patch_digest}, subset has {subset.retained_patch_digest}"
                )
            if fact.subtracted_delta_digest != subset.subtracted_delta_digest:
                raise SliceIdentityMismatchError(
                    f"subtracted_delta_digest mismatch at index {i}: fact has "
                    f"{fact.subtracted_delta_digest}, subset has {subset.subtracted_delta_digest}"
                )
            if delta_digest != subset.subtracted_delta_digest:
                raise SliceIdentityMismatchError(
                    f"counterfactual_delta_digests[{i}] mismatch: expected "
                    f"{subset.subtracted_delta_digest}, got {delta_digest}"
                )
            if outcome_str != fact.outcome.value:
                raise SliceIdentityMismatchError(
                    f"evaluated_outcomes[{i}] mismatch: claimed {outcome_str!r}, "
                    f"but actual execution fact outcome is {fact.outcome.value!r}"
                )

            # Binding fact to scope and receipt identity
            if fact.scope_digest != self.slice_artifact.scope.scope_digest:
                raise SliceIdentityMismatchError(
                    f"scope_digest mismatch at index {i}: fact has {fact.scope_digest}, "
                    f"slice scope has {self.slice_artifact.scope.scope_digest}"
                )
            if fact.frozen_contract_digest != self.frozen_contract_digest:
                raise SliceIdentityMismatchError(
                    f"frozen_contract_digest mismatch at index {i}: fact has "
                    f"{fact.frozen_contract_digest}, receipt has {self.frozen_contract_digest}"
                )
            if fact.sealed_witness_digest != self.sealed_witness_digest:
                raise SliceIdentityMismatchError(
                    f"sealed_witness_digest mismatch at index {i}: fact has "
                    f"{fact.sealed_witness_digest}, receipt has {self.sealed_witness_digest}"
                )
            if fact.requirement_id != self.requirement_id:
                raise SliceIdentityMismatchError(
                    f"requirement_id mismatch at index {i}: fact has {fact.requirement_id}, "
                    f"receipt has {self.requirement_id}"
                )
            if fact.candidate_id != self.candidate_id:
                raise SliceIdentityMismatchError(
                    f"candidate_id mismatch at index {i}: fact has {fact.candidate_id}, "
                    f"receipt has {self.candidate_id}"
                )
            if fact.tree_digest != self.candidate_tree_digest:
                raise SliceIdentityMismatchError(
                    f"candidate_tree_digest mismatch at index {i}: fact has {fact.tree_digest}, "
                    f"receipt has {self.candidate_tree_digest}"
                )
            if fact.runtime_config_digest != self.runtime_config_digest:
                raise SliceIdentityMismatchError(
                    f"runtime_config_digest mismatch at index {i}: fact has "
                    f"{fact.runtime_config_digest}, receipt has {self.runtime_config_digest}"
                )

            # Provenance cannot be upgraded
            if self.provenance == EvidenceProvenance.LIVE_NEBIUS and (
                fact.provenance != EvidenceProvenance.LIVE_NEBIUS
            ):
                raise SliceReceiptIntegrityError(
                    f"Provenance upgrade forbidden: receipt claims LIVE_NEBIUS but "
                    f"execution_facts[{i}] has {fact.provenance.value}"
                )
            if fact.provenance != self.provenance:
                raise SliceReceiptIntegrityError(
                    f"Provenance mismatch at index {i}: fact has {fact.provenance.value}, "
                    f"receipt has {self.provenance.value}"
                )

        # Identity binding verification against the slice artifact
        if self.slice_artifact.scope.frozen_contract_digest != self.frozen_contract_digest:
            raise SliceIdentityMismatchError(
                f"frozen_contract_digest mismatch: receipt has {self.frozen_contract_digest}, "
                f"slice has {self.slice_artifact.scope.frozen_contract_digest}"
            )
        if self.slice_artifact.scope.sealed_witness_digest != self.sealed_witness_digest:
            raise SliceIdentityMismatchError(
                f"sealed_witness_digest mismatch: receipt has {self.sealed_witness_digest}, "
                f"slice has {self.slice_artifact.scope.sealed_witness_digest}"
            )
        if self.slice_artifact.scope.requirement_id != self.requirement_id:
            raise SliceIdentityMismatchError(
                f"requirement_id mismatch: receipt has {self.requirement_id}, "
                f"slice has {self.slice_artifact.scope.requirement_id}"
            )
        if self.slice_artifact.scope.candidate_id != self.candidate_id:
            raise SliceIdentityMismatchError(
                f"candidate_id mismatch: receipt has {self.candidate_id}, "
                f"slice has {self.slice_artifact.scope.candidate_id}"
            )
        if self.slice_artifact.scope.source_commit_id != self.source_commit_id:
            raise SliceIdentityMismatchError(
                f"source_commit_id mismatch: receipt has {self.source_commit_id}, "
                f"slice has {self.slice_artifact.scope.source_commit_id}"
            )
        if self.slice_artifact.scope.candidate_tree_digest != self.candidate_tree_digest:
            raise SliceIdentityMismatchError(
                f"candidate_tree_digest mismatch: receipt has {self.candidate_tree_digest}, "
                f"slice has {self.slice_artifact.scope.candidate_tree_digest}"
            )
        if self.slice_artifact.scope.candidate_patch_digest != self.candidate_patch_digest:
            raise SliceIdentityMismatchError(
                f"candidate_patch_digest mismatch: receipt has {self.candidate_patch_digest}, "
                f"slice has {self.slice_artifact.scope.candidate_patch_digest}"
            )
        if self.slice_artifact.status != self.status:
            raise SliceIdentityMismatchError(
                f"status mismatch: receipt has {self.status.value}, "
                f"slice has {self.slice_artifact.status.value}"
            )
        if self.slice_artifact.completeness != self.completeness:
            raise SliceIdentityMismatchError(
                f"completeness mismatch: receipt has {self.completeness.value}, "
                f"slice has {self.slice_artifact.completeness.value}"
            )
        if self.slice_artifact.scope.provenance != self.provenance:
            raise SliceIdentityMismatchError(
                f"provenance mismatch: receipt has {self.provenance.value}, "
                f"slice scope has {self.slice_artifact.scope.provenance.value}"
            )

        # Cryptographic integrity check
        payload = self._build_payload()
        computed = compute_slice_receipt_digest(payload)
        if self.receipt_digest != computed:
            raise SliceReceiptTamperingError(
                f"receipt_digest mismatch: expected {self.receipt_digest}, computed {computed}"
            )

    def _build_payload(self) -> dict[str, Any]:
        return {
            "candidate_id": self.candidate_id,
            "candidate_patch_digest": self.candidate_patch_digest,
            "candidate_tree_digest": self.candidate_tree_digest,
            "completeness": self.completeness.value,
            "counterfactual_delta_digests": list(self.counterfactual_delta_digests),
            "created_at_utc": self.created_at_utc,
            "disclaimer": self.disclaimer.to_dict(),
            "evaluated_outcomes": list(self.evaluated_outcomes),
            "execution_facts": [f.to_dict() for f in self.execution_facts],
            "frozen_contract_digest": self.frozen_contract_digest,
            "provenance": self.provenance.value,
            "requirement_id": self.requirement_id,
            "runtime_config_digest": self.runtime_config_digest,
            "schema_version": self.schema_version,
            "sealed_witness_digest": self.sealed_witness_digest,
            "search_budget": {
                "allow_model_ordering": self.search_budget.allow_model_ordering,
                "max_depth": self.search_budget.max_depth,
                "max_iterations": self.search_budget.max_iterations,
                "max_subsets_tested": self.search_budget.max_subsets_tested,
            },
            "slice_artifact": self.slice_artifact.to_dict(),
            "source_commit_id": self.source_commit_id,
            "source_locator": self.source_locator,
            "source_subpath": self.source_subpath,
            "status": self.status.value,
            "tested_subsets": [s.to_dict() for s in self.tested_subsets],
            "witness_id": self.witness_id,
        }

    def to_dict(self) -> dict[str, Any]:
        payload = self._build_payload()
        payload["claims_global_minimality"] = self.claims_global_minimality
        payload["grants_pass"] = self.grants_pass
        payload["is_authoritative"] = self.is_authoritative
        payload["is_causally_verified"] = self.is_causally_verified
        payload["receipt_digest"] = self.receipt_digest
        return payload

    def to_json(self) -> str:
        return json.dumps(self.to_dict(), sort_keys=True, indent=2)

    @classmethod
    def from_dict(cls, data: Mapping[str, Any]) -> CausalSliceReceipt:
        if not isinstance(data, Mapping):
            raise SliceReceiptTamperingError(f"Expected mapping, got {type(data).__name__}")

        if data.get("is_authoritative") is True:
            raise SliceAuthorityError("is_authoritative cannot be True in serialized receipt")
        if data.get("grants_pass") is True:
            raise SliceAuthorityError("grants_pass cannot be True in serialized receipt")
        if data.get("is_causally_verified") is True:
            raise SliceAuthorityError("is_causally_verified cannot be True in serialized receipt")
        if data.get("claims_global_minimality") is True:
            raise SliceAuthorityError(
                "claims_global_minimality cannot be True in serialized receipt"
            )

        try:
            disc_data = data.get("disclaimer")
            if not disc_data:
                raise DisclaimerMissingError("disclaimer is missing from serialized receipt")
            disclaimer = NonFormalProofDisclaimer.from_dict(disc_data)

            slice_art = BoundedCausalSlice.from_dict(data["slice_artifact"])
            budget_data = data.get("search_budget", {})
            budget = SliceSearchBudget(
                max_iterations=int(budget_data.get("max_iterations", 20)),
                max_subsets_tested=int(budget_data.get("max_subsets_tested", 20)),
                max_depth=int(budget_data.get("max_depth", 5)),
                allow_model_ordering=bool(budget_data.get("allow_model_ordering", True)),
            )

            tested_subs = tuple(
                TestedPatchSubset.from_dict(s) for s in data.get("tested_subsets", ())
            )
            exec_facts = tuple(
                SubsetExecutionFact.from_dict(f) for f in data.get("execution_facts", ())
            )
            runtime_cfg = str(data.get("runtime_config_digest", LOCAL_TEST_RUNTIME_CONFIG_DIGEST))

            return cls(
                requirement_id=str(data["requirement_id"]),
                frozen_contract_digest=str(data["frozen_contract_digest"]),
                sealed_witness_digest=str(data["sealed_witness_digest"]),
                witness_id=str(data["witness_id"]),
                source_locator=str(data["source_locator"]),
                source_commit_id=str(data["source_commit_id"]),
                source_subpath=str(data.get("source_subpath", "")),
                candidate_id=str(data["candidate_id"]),
                candidate_tree_digest=str(data["candidate_tree_digest"]),
                candidate_patch_digest=str(data["candidate_patch_digest"]),
                slice_artifact=slice_art,
                search_budget=budget,
                tested_subsets=tested_subs,
                evaluated_outcomes=tuple(str(o) for o in data.get("evaluated_outcomes", ())),
                counterfactual_delta_digests=tuple(
                    str(d) for d in data.get("counterfactual_delta_digests", ())
                ),
                execution_facts=exec_facts,
                runtime_config_digest=runtime_cfg,
                status=CausalSliceStatus(str(data["status"])),
                completeness=SliceSearchCompleteness(str(data["completeness"])),
                provenance=EvidenceProvenance(str(data["provenance"])),
                disclaimer=disclaimer,
                created_at_utc=str(data["created_at_utc"]),
                receipt_digest=str(data["receipt_digest"]),
                schema_version=str(data.get("schema_version", CAUSAL_SLICE_RECEIPT_SCHEMA_VERSION)),
                is_authoritative=False,
                grants_pass=False,
                is_causally_verified=False,
                claims_global_minimality=False,
            )
        except CausalSliceError:
            raise
        except (KeyError, ValueError, TypeError) as exc:
            raise SliceReceiptTamperingError(
                f"Failed to deserialize CausalSliceReceipt: {exc}"
            ) from exc

    @classmethod
    def from_json(cls, json_str: str) -> CausalSliceReceipt:
        try:
            data = json.loads(json_str)
        except json.JSONDecodeError as exc:
            raise SliceReceiptTamperingError(f"Invalid JSON: {exc}") from exc
        return cls.from_dict(data)

    def render_markdown(self) -> str:
        """Render judge-inspectable markdown representation prominently displaying disclaimer."""
        lines = [
            f"# Basebreak Minimal Causal Slice Receipt: `{self.slice_artifact.slice_id}`",
            "",
            "> Thesis: *If the patch matters, the base must break.*",
            "",
            "## Summary",
            f"- **Receipt Digest**: `{self.receipt_digest}`",
            f"- **Status**: `{self.status.value}`",
            f"- **Search Completeness**: `{self.completeness.value}`",
            f"- **Provenance**: `{self.provenance.value}`",
            f"- **Runtime Config**: `{self.runtime_config_digest}`",
            f"- **Execution Facts Bound**: {len(self.execution_facts)}",
            f"- **Created At**: `{self.created_at_utc}`",
            "",
            "## Cryptographic Custody Chain",
            f"- **Requirement ID**: `{self.requirement_id}`",
            f"- **Frozen Contract**: `{self.frozen_contract_digest}`",
            f"- **Witness ID**: `{self.witness_id}`",
            f"- **Witness Seal**: `{self.sealed_witness_digest}`",
            f"- **Source Commit**: `{self.source_commit_id}`",
            f"- **Candidate ID**: `{self.candidate_id}`",
            f"- **Candidate Tree**: `{self.candidate_tree_digest}`",
            f"- **Candidate Patch**: `{self.candidate_patch_digest}`",
            f"- **Slice Digest**: `{self.slice_artifact.slice_digest}`",
            "",
            "## Authority Boundary",
            "- **Authoritative**: `False`",
            "- **Grants Pass**: `False`",
            "- **Causally Verified**: `False`",
            "- **Claims Global Minimality**: `False`",
            "",
            "## Search Exploration",
            f"- **Subsets Evaluated**: {len(self.tested_subsets)}",
            f"- **Budget Bounds**: max_iterations={self.search_budget.max_iterations}, "
            f"max_subsets_tested={self.search_budget.max_subsets_tested}, "
            f"max_depth={self.search_budget.max_depth}",
            "",
            "## Mandatory Non-Formal-Proof Disclaimer",
            f"> **Notice**: {self.disclaimer.statement}",
            "",
            "### Disclaimed Properties",
            "- **Mathematical Program Proof**: Disclaimed (`False`)",
            "- **Global Minimality**: Disclaimed (`False`)",
            "- **Universal Necessity**: Disclaimed (`False`)",
            "- **Untested Input Guarantees**: Disclaimed (`False`)",
            "- **Semantic Equivalence Beyond Witness**: Disclaimed (`False`)",
            "- **Formal Verification**: Disclaimed (`False`)",
        ]
        return "\n".join(lines)

    render_markdown_summary = render_markdown


def create_causal_slice_receipt(
    *,
    requirement_id: str,
    frozen_contract_digest: str,
    sealed_witness_digest: str,
    witness_id: str,
    source_locator: str,
    source_commit_id: str,
    source_subpath: str = "",
    candidate_id: str,
    candidate_tree_digest: str,
    candidate_patch_digest: str,
    slice_artifact: BoundedCausalSlice,
    search_budget: SliceSearchBudget,
    execution_facts: Sequence[SubsetExecutionFact] = (),
    runtime_config_digest: str = LOCAL_TEST_RUNTIME_CONFIG_DIGEST,
    tested_subsets: Sequence[TestedPatchSubset] = (),
    evaluated_outcomes: Sequence[str] | None = None,
    counterfactual_delta_digests: Sequence[str] | None = None,
    status: CausalSliceStatus = CausalSliceStatus.TESTED_NECESSARY_SUBSET,
    completeness: SliceSearchCompleteness = SliceSearchCompleteness.EXHAUSTIVE_BOUNDED,
    provenance: EvidenceProvenance = EvidenceProvenance.LOCAL_EXECUTION,
    disclaimer: NonFormalProofDisclaimer | None = None,
    created_at_utc: str | None = None,
) -> CausalSliceReceipt:
    """Factory to construct an authentic, cryptographically bound CausalSliceReceipt."""
    timestamp = created_at_utc or datetime.now(timezone.utc).isoformat()
    disc = disclaimer or slice_artifact.disclaimer or create_canonical_disclaimer()

    outcomes = (
        tuple(evaluated_outcomes)
        if evaluated_outcomes is not None
        else tuple(f.outcome.value for f in execution_facts)
    )
    deltas = (
        tuple(counterfactual_delta_digests)
        if counterfactual_delta_digests is not None
        else tuple(s.subtracted_delta_digest for s in tested_subsets)
    )

    payload = {
        "candidate_id": candidate_id,
        "candidate_patch_digest": candidate_patch_digest,
        "candidate_tree_digest": candidate_tree_digest,
        "completeness": completeness.value,
        "counterfactual_delta_digests": list(deltas),
        "created_at_utc": timestamp,
        "disclaimer": disc.to_dict(),
        "evaluated_outcomes": list(outcomes),
        "execution_facts": [f.to_dict() for f in execution_facts],
        "frozen_contract_digest": frozen_contract_digest,
        "provenance": provenance.value,
        "requirement_id": requirement_id,
        "runtime_config_digest": runtime_config_digest,
        "schema_version": CAUSAL_SLICE_RECEIPT_SCHEMA_VERSION,
        "sealed_witness_digest": sealed_witness_digest,
        "search_budget": {
            "allow_model_ordering": search_budget.allow_model_ordering,
            "max_depth": search_budget.max_depth,
            "max_iterations": search_budget.max_iterations,
            "max_subsets_tested": search_budget.max_subsets_tested,
        },
        "slice_artifact": slice_artifact.to_dict(),
        "source_commit_id": source_commit_id,
        "source_locator": source_locator,
        "source_subpath": source_subpath,
        "status": status.value,
        "tested_subsets": [s.to_dict() for s in tested_subsets],
        "witness_id": witness_id,
    }
    digest = compute_slice_receipt_digest(payload)

    return CausalSliceReceipt(
        requirement_id=requirement_id,
        frozen_contract_digest=frozen_contract_digest,
        sealed_witness_digest=sealed_witness_digest,
        witness_id=witness_id,
        source_locator=source_locator,
        source_commit_id=source_commit_id,
        source_subpath=source_subpath,
        candidate_id=candidate_id,
        candidate_tree_digest=candidate_tree_digest,
        candidate_patch_digest=candidate_patch_digest,
        slice_artifact=slice_artifact,
        search_budget=search_budget,
        tested_subsets=tuple(tested_subsets),
        evaluated_outcomes=outcomes,
        counterfactual_delta_digests=deltas,
        execution_facts=tuple(execution_facts),
        runtime_config_digest=runtime_config_digest,
        status=status,
        completeness=completeness,
        provenance=provenance,
        disclaimer=disc,
        created_at_utc=timestamp,
        receipt_digest=digest,
        schema_version=CAUSAL_SLICE_RECEIPT_SCHEMA_VERSION,
        is_authoritative=False,
        grants_pass=False,
        is_causally_verified=False,
        claims_global_minimality=False,
    )


def create_causal_slice_receipt_from_result(
    result: BoundedMinimizerResult,
    *,
    witness_id: str,
    disclaimer: NonFormalProofDisclaimer | None = None,
    created_at_utc: str | None = None,
) -> CausalSliceReceipt:
    """Canonical factory to derive an authentic CausalSliceReceipt from BoundedMinimizerResult.

    Mechanically derives evaluated subsets, execution facts, outcomes, and counterfactual deltas
    directly from result.evaluated_subsets.
    """
    if not isinstance(result, BoundedMinimizerResult):
        raise TypeError(f"result must be BoundedMinimizerResult, got {type(result).__name__}")
    if not isinstance(witness_id, str) or not witness_id.strip():
        raise SliceReceiptIntegrityError("witness_id must be a non-empty string")

    tested_subsets = tuple(rec.subset for rec in result.evaluated_subsets)
    execution_facts = tuple(rec.execution_fact for rec in result.evaluated_subsets)
    evaluated_outcomes = tuple(rec.execution_fact.outcome.value for rec in result.evaluated_subsets)
    counterfactual_delta_digests = tuple(
        rec.subset.subtracted_delta_digest for rec in result.evaluated_subsets
    )

    disc = disclaimer or result.disclaimer
    slice_art = result.slice_artifact
    if slice_art is None:
        subset = result.minimal_subset or (tested_subsets[0] if tested_subsets else None)
        if subset is None:
            raise SliceReceiptIntegrityError(
                "Cannot derive slice receipt from result with no evaluated subsets or artifact"
            )
        slice_art = create_bounded_causal_slice(
            slice_id=f"slice-{subset.retained_patch_digest[:16]}",
            scope=result.scope,
            tested_subset=subset,
            status=result.status,
            completeness=result.completeness,
            summary_label=result.summary_label,
            disclaimer=disc,
        )

    if slice_art.status != result.status:
        raise SliceIdentityMismatchError(
            f"Receipt status must match minimizer result: "
            f"{result.status.value} != {slice_art.status.value}"
        )
    if slice_art.completeness != result.completeness:
        raise SliceIdentityMismatchError(
            f"Receipt completeness must match minimizer result: "
            f"{result.completeness.value} != {slice_art.completeness.value}"
        )

    return create_causal_slice_receipt(
        requirement_id=result.scope.requirement_id,
        frozen_contract_digest=result.scope.frozen_contract_digest,
        sealed_witness_digest=result.scope.sealed_witness_digest,
        witness_id=witness_id,
        source_locator=result.scope.source_locator,
        source_commit_id=result.scope.source_commit_id,
        source_subpath=result.scope.source_subpath,
        candidate_id=result.scope.candidate_id,
        candidate_tree_digest=result.scope.candidate_tree_digest,
        candidate_patch_digest=result.scope.candidate_patch_digest,
        slice_artifact=slice_art,
        search_budget=result.search_budget,
        execution_facts=execution_facts,
        runtime_config_digest=result.runtime_config_digest,
        tested_subsets=tested_subsets,
        evaluated_outcomes=evaluated_outcomes,
        counterfactual_delta_digests=counterfactual_delta_digests,
        status=result.status,
        completeness=result.completeness,
        provenance=result.scope.provenance,
        disclaimer=disc,
        created_at_utc=created_at_utc,
    )


def verify_slice_receipt_integrity(receipt: CausalSliceReceipt) -> bool:
    """Deterministically verify that a CausalSliceReceipt has not been tampered with."""
    if not isinstance(receipt, CausalSliceReceipt):
        return False
    if receipt.is_authoritative is not False:
        return False
    if receipt.grants_pass is not False:
        return False
    if receipt.is_causally_verified is not False:
        return False
    if receipt.claims_global_minimality is not False:
        return False
    # Verify underlying slice integrity as well
    if not verify_slice_integrity(receipt.slice_artifact):
        return False
    try:
        payload = receipt._build_payload()
        computed = compute_slice_receipt_digest(payload)
        return computed == receipt.receipt_digest
    except Exception:
        return False


def validate_upstream_evidence_compatibility(
    receipt: CausalSliceReceipt,
    upstream_verdict: PreliminaryVerdict,
) -> bool:
    """Validate that slice evidence cannot upgrade an unverified or inconclusive candidate.

    Rule: If upstream candidate evidence is NOT verified, slice evidence remains
    strictly non-verifying.
    """
    if not isinstance(receipt, CausalSliceReceipt):
        raise TypeError("receipt must be CausalSliceReceipt")
    if not isinstance(upstream_verdict, PreliminaryVerdict):
        raise TypeError("upstream_verdict must be PreliminaryVerdict")

    # A slice receipt NEVER upgrades verification status independently
    if upstream_verdict != PreliminaryVerdict.VERIFIED:
        return False
    return verify_slice_receipt_integrity(receipt)


__all__ = [
    "CAUSAL_SLICE_RECEIPT_SCHEMA_VERSION",
    "CausalSliceReceipt",
    "SliceReceiptError",
    "SliceReceiptIntegrityError",
    "SliceReceiptTamperingError",
    "compute_slice_receipt_digest",
    "create_causal_slice_receipt",
    "create_causal_slice_receipt_from_result",
    "validate_upstream_evidence_compatibility",
    "verify_slice_receipt_integrity",
]
