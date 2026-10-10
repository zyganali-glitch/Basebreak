"""Grounded Contract evidence records and deterministic digest binding.

P-16.03: Bind release-note/CVE/API facts into Grounded Contract evidence.

Authority & Invariants:
1. Provider-neutral: domain models in grounding/ have zero imports from adapters/.
2. Immutability: GroundedFact and GroundedContractBinding are frozen dataclasses.
3. Content-addressed: Every fact and binding carries a 64-hex SHA-256 digest over canonical JSON.
4. Separate historical record: Grounding binds to FrozenContract without modifying
   the frozen contract digest.
5. Offline auditable: Once recorded, evidence can be audited without network access
   or revisiting live URLs.
6. Uncertainty & freshness: Explicit states (CERTAIN, UNCERTAIN, CONTRADICTORY, INSUFFICIENT)
   prevent papering over ambiguities or contradictory advisories.
7. Fixture vs Observation: Distinguishes true provider observations from offline fixtures.
"""

from __future__ import annotations

import hashlib
import json
from collections.abc import Mapping, Sequence
from dataclasses import dataclass
from enum import Enum
from typing import Any

from basebreak.compiler.freeze import FrozenContract
from basebreak.grounding.materiality import GroundingMateriality, MaterialityDecision


class FreshnessState(str, Enum):
    """Temporal freshness state of retrieved external information."""

    FRESH = "FRESH"
    STALE = "STALE"
    UNKNOWN = "UNKNOWN"


class UncertaintyState(str, Enum):
    """Epistemic certainty/conflict state of external fact claims."""

    CERTAIN = "CERTAIN"
    UNCERTAIN = "UNCERTAIN"
    CONTRADICTORY = "CONTRADICTORY"
    INSUFFICIENT = "INSUFFICIENT"


def compute_grounded_fact_digest(payload: Mapping[str, Any]) -> str:
    """Compute deterministic SHA-256 digest over canonical JSON representation."""
    canonical = json.dumps(
        dict(payload),
        sort_keys=True,
        separators=(",", ":"),
        ensure_ascii=True,
    )
    return hashlib.sha256(canonical.encode("utf-8")).hexdigest()


@dataclass(frozen=True, slots=True)
class GroundedFact:
    """Immutable, provider-neutral record of an observed or supplied external technical fact."""

    fact_id: str
    contract_digest: str
    requirement_id: str
    source_url: str
    publisher: str
    retrieved_claim: str
    observation_timestamp: str
    published_date: str | None
    retrieval_provider: str
    provider_response_id: str | None
    materiality: GroundingMateriality
    is_fixture: bool
    freshness_state: FreshnessState
    uncertainty_state: UncertaintyState
    evidence_digest: str

    def __post_init__(self) -> None:
        if not self.fact_id:
            raise ValueError("fact_id must not be empty")
        if not self.contract_digest or len(self.contract_digest) != 64:
            raise ValueError("contract_digest must be a 64-hex SHA-256 string")
        if not self.requirement_id:
            raise ValueError("requirement_id must not be empty")
        if not self.source_url:
            raise ValueError("source_url must not be empty")
        if not self.publisher:
            raise ValueError("publisher must not be empty")
        if not self.retrieved_claim:
            raise ValueError("retrieved_claim must not be empty")
        if not self.observation_timestamp:
            raise ValueError("observation_timestamp must not be empty")
        if not self.retrieval_provider:
            raise ValueError("retrieval_provider must not be empty")
        if not isinstance(self.materiality, GroundingMateriality):
            raise TypeError(
                f"materiality must be GroundingMateriality, got {type(self.materiality).__name__}"
            )
        if not isinstance(self.freshness_state, FreshnessState):
            raise TypeError(
                f"freshness_state must be FreshnessState, got {type(self.freshness_state).__name__}"
            )
        if not isinstance(self.uncertainty_state, UncertaintyState):
            tname = type(self.uncertainty_state).__name__
            raise TypeError(f"uncertainty_state must be UncertaintyState, got {tname}")

        expected = compute_grounded_fact_digest(
            {
                "fact_id": self.fact_id,
                "contract_digest": self.contract_digest,
                "requirement_id": self.requirement_id,
                "source_url": self.source_url,
                "publisher": self.publisher,
                "retrieved_claim": self.retrieved_claim,
                "observation_timestamp": self.observation_timestamp,
                "published_date": self.published_date,
                "retrieval_provider": self.retrieval_provider,
                "provider_response_id": self.provider_response_id,
                "materiality": self.materiality.value,
                "is_fixture": self.is_fixture,
                "freshness_state": self.freshness_state.value,
                "uncertainty_state": self.uncertainty_state.value,
            }
        )
        if self.evidence_digest != expected:
            raise ValueError(
                f"evidence_digest mismatch: declared '{self.evidence_digest}', "
                f"computed '{expected}'"
            )


def verify_grounded_fact_digest(fact: GroundedFact) -> bool:
    """Verify integrity of a GroundedFact record."""
    expected = compute_grounded_fact_digest(
        {
            "fact_id": fact.fact_id,
            "contract_digest": fact.contract_digest,
            "requirement_id": fact.requirement_id,
            "source_url": fact.source_url,
            "publisher": fact.publisher,
            "retrieved_claim": fact.retrieved_claim,
            "observation_timestamp": fact.observation_timestamp,
            "published_date": fact.published_date,
            "retrieval_provider": fact.retrieval_provider,
            "provider_response_id": fact.provider_response_id,
            "materiality": fact.materiality.value,
            "is_fixture": fact.is_fixture,
            "freshness_state": fact.freshness_state.value,
            "uncertainty_state": fact.uncertainty_state.value,
        }
    )
    return fact.evidence_digest == expected


@dataclass(frozen=True, slots=True)
class GroundedContractBinding:
    """Immutable, digest-verified binding of GroundedFact records to a FrozenContract."""

    binding_id: str
    contract_digest: str
    materiality_decision_digest: str
    facts: tuple[GroundedFact, ...]
    binding_timestamp: str
    overall_uncertainty: UncertaintyState
    binding_digest: str

    def __post_init__(self) -> None:
        if not self.binding_id:
            raise ValueError("binding_id must not be empty")
        if not self.contract_digest or len(self.contract_digest) != 64:
            raise ValueError("contract_digest must be a 64-hex SHA-256 string")
        if not self.materiality_decision_digest or len(self.materiality_decision_digest) != 64:
            raise ValueError("materiality_decision_digest must be a 64-hex SHA-256 string")
        if not self.binding_timestamp:
            raise ValueError("binding_timestamp must not be empty")
        if not isinstance(self.overall_uncertainty, UncertaintyState):
            raise TypeError(
                f"overall_uncertainty must be UncertaintyState, "
                f"got {type(self.overall_uncertainty).__name__}"
            )

        # Ensure all facts match contract_digest
        for f in self.facts:
            if f.contract_digest != self.contract_digest:
                raise ValueError(
                    f"Fact contract_digest '{f.contract_digest}' does not match "
                    f"binding contract_digest '{self.contract_digest}'"
                )

        expected = compute_grounded_fact_digest(
            {
                "binding_id": self.binding_id,
                "contract_digest": self.contract_digest,
                "materiality_decision_digest": self.materiality_decision_digest,
                "facts": [f.evidence_digest for f in self.facts],
                "binding_timestamp": self.binding_timestamp,
                "overall_uncertainty": self.overall_uncertainty.value,
            }
        )
        if self.binding_digest != expected:
            raise ValueError(
                f"binding_digest mismatch: declared '{self.binding_digest}', computed '{expected}'"
            )


def verify_grounded_binding_digest(binding: GroundedContractBinding) -> bool:
    """Verify integrity of a GroundedContractBinding."""
    expected = compute_grounded_fact_digest(
        {
            "binding_id": binding.binding_id,
            "contract_digest": binding.contract_digest,
            "materiality_decision_digest": binding.materiality_decision_digest,
            "facts": [f.evidence_digest for f in binding.facts],
            "binding_timestamp": binding.binding_timestamp,
            "overall_uncertainty": binding.overall_uncertainty.value,
        }
    )
    return binding.binding_digest == expected


def reconcile_fact_uncertainty(facts: Sequence[GroundedFact]) -> UncertaintyState:
    """Deterministically aggregate uncertainty states across multiple GroundedFact records."""
    if not facts:
        return UncertaintyState.INSUFFICIENT

    states = {f.uncertainty_state for f in facts}
    if UncertaintyState.CONTRADICTORY in states:
        return UncertaintyState.CONTRADICTORY
    if UncertaintyState.UNCERTAIN in states:
        return UncertaintyState.UNCERTAIN
    if UncertaintyState.INSUFFICIENT in states:
        return UncertaintyState.INSUFFICIENT
    return UncertaintyState.CERTAIN


def create_grounded_fact(
    contract: FrozenContract,
    requirement_id: str,
    source_url: str,
    publisher: str,
    retrieved_claim: str,
    *,
    materiality: GroundingMateriality,
    observation_timestamp: str,
    published_date: str | None = None,
    retrieval_provider: str = "tavily",
    provider_response_id: str | None = None,
    is_fixture: bool = False,
    freshness_state: FreshnessState = FreshnessState.FRESH,
    uncertainty_state: UncertaintyState = UncertaintyState.CERTAIN,
    fact_id: str | None = None,
) -> GroundedFact:
    """Factory creating an immutable, digest-verified GroundedFact."""
    if not isinstance(contract, FrozenContract):
        raise TypeError(f"contract must be FrozenContract, got {type(contract).__name__}")

    url_hash = hashlib.sha256(source_url.encode("utf-8")).hexdigest()[:8]
    f_id = fact_id or f"fact-{contract.contract_digest[:8]}-{url_hash}"
    payload = {
        "fact_id": f_id,
        "contract_digest": contract.contract_digest,
        "requirement_id": requirement_id,
        "source_url": source_url,
        "publisher": publisher,
        "retrieved_claim": retrieved_claim,
        "observation_timestamp": observation_timestamp,
        "published_date": published_date,
        "retrieval_provider": retrieval_provider,
        "provider_response_id": provider_response_id,
        "materiality": materiality.value,
        "is_fixture": is_fixture,
        "freshness_state": freshness_state.value,
        "uncertainty_state": uncertainty_state.value,
    }
    digest = compute_grounded_fact_digest(payload)
    return GroundedFact(
        fact_id=f_id,
        contract_digest=contract.contract_digest,
        requirement_id=requirement_id,
        source_url=source_url,
        publisher=publisher,
        retrieved_claim=retrieved_claim,
        observation_timestamp=observation_timestamp,
        published_date=published_date,
        retrieval_provider=retrieval_provider,
        provider_response_id=provider_response_id,
        materiality=materiality,
        is_fixture=is_fixture,
        freshness_state=freshness_state,
        uncertainty_state=uncertainty_state,
        evidence_digest=digest,
    )


def create_grounded_binding(
    contract: FrozenContract,
    decision: MaterialityDecision,
    facts: Sequence[GroundedFact],
    binding_timestamp: str,
    binding_id: str | None = None,
) -> GroundedContractBinding:
    """Bind a set of GroundedFact records to a FrozenContract and MaterialityDecision."""
    if not isinstance(contract, FrozenContract):
        raise TypeError(f"contract must be FrozenContract, got {type(contract).__name__}")
    if not isinstance(decision, MaterialityDecision):
        raise TypeError(f"decision must be MaterialityDecision, got {type(decision).__name__}")
    if decision.contract_digest != contract.contract_digest:
        raise ValueError("Decision contract_digest does not match FrozenContract digest")

    from basebreak.grounding.materiality import verify_materiality_digest

    if not verify_materiality_digest(decision):
        raise ValueError(
            "MaterialityDecision digest verification failed; cannot bind corrupted decision."
        )

    for f in facts:
        if f.contract_digest != contract.contract_digest:
            raise ValueError(
                f"Fact contract_digest '{f.contract_digest}' does not match "
                f"contract digest '{contract.contract_digest}'"
            )
        if f.requirement_id != decision.requirement_id:
            raise ValueError(
                f"Fact requirement_id '{f.requirement_id}' does not match "
                f"decision requirement_id '{decision.requirement_id}'"
            )

    overall = reconcile_fact_uncertainty(facts)
    b_id = binding_id or f"bind-{contract.contract_digest[:8]}-{decision.decision_id[-8:]}"
    payload = {
        "binding_id": b_id,
        "contract_digest": contract.contract_digest,
        "materiality_decision_digest": decision.decision_digest,
        "facts": [f.evidence_digest for f in facts],
        "binding_timestamp": binding_timestamp,
        "overall_uncertainty": overall.value,
    }
    binding_digest = compute_grounded_fact_digest(payload)
    return GroundedContractBinding(
        binding_id=b_id,
        contract_digest=contract.contract_digest,
        materiality_decision_digest=decision.decision_digest,
        facts=tuple(facts),
        binding_timestamp=binding_timestamp,
        overall_uncertainty=overall,
        binding_digest=binding_digest,
    )
