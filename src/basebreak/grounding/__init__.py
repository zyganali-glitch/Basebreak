"""Provider-neutral external grounding and authority firewall package.

P-16: External Grounding & Tavily.

Provider-neutral domain and evidence models: zero imports from adapters/.
"""

from .evidence import (
    FreshnessState,
    GroundedContractBinding,
    GroundedFact,
    TrustedProviderObservation,
    UncertaintyState,
    compute_grounded_fact_digest,
    compute_trusted_observation_digest,
    create_grounded_binding,
    create_grounded_fact,
    create_trusted_observation,
    reconcile_fact_uncertainty,
    validate_trusted_observation_contract,
    verify_grounded_binding_digest,
    verify_grounded_fact_digest,
    verify_trusted_observation_digest,
)
from .firewall import (
    GroundingFirewallResult,
    GroundingStatus,
    compute_firewall_digest,
    detect_fake_authority_claim,
    detect_prompt_injection,
    evaluate_grounding_firewall,
    validate_grounding_provenance,
)
from .materiality import (
    AUTHORITATIVE_CVE_DOMAINS,
    AUTHORITATIVE_DEP_API_DOMAINS,
    CVE_PATTERN,
    GroundingCategory,
    GroundingMateriality,
    MaterialityDecision,
    compute_materiality_digest,
    evaluate_grounding_materiality,
    verify_materiality_digest,
)

__all__ = [
    "AUTHORITATIVE_CVE_DOMAINS",
    "AUTHORITATIVE_DEP_API_DOMAINS",
    "CVE_PATTERN",
    "FreshnessState",
    "GroundedContractBinding",
    "GroundedFact",
    "GroundingCategory",
    "GroundingFirewallResult",
    "GroundingMateriality",
    "GroundingStatus",
    "MaterialityDecision",
    "TrustedProviderObservation",
    "UncertaintyState",
    "compute_firewall_digest",
    "compute_grounded_fact_digest",
    "compute_materiality_digest",
    "compute_trusted_observation_digest",
    "create_grounded_binding",
    "create_grounded_fact",
    "create_trusted_observation",
    "detect_fake_authority_claim",
    "detect_prompt_injection",
    "evaluate_grounding_firewall",
    "evaluate_grounding_materiality",
    "reconcile_fact_uncertainty",
    "validate_grounding_provenance",
    "validate_trusted_observation_contract",
    "verify_grounded_binding_digest",
    "verify_grounded_fact_digest",
    "verify_materiality_digest",
    "verify_trusted_observation_digest",
]
