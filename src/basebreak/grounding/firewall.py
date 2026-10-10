"""Deterministic authority firewall preventing web evidence from overriding execution truth.

P-16.04: Prevent web evidence from overriding deterministic execution.

Core Invariants:
1. Authority Primacy:
   - "If the patch matters, the base must break."
   - Web evidence is UNTRUSTED DATA and CANNOT certify code behavior.
   - Deterministic execution facts (BASE/CANDIDATE/Counterfactual witness results,
     protected surface integrity, resource budget constraints) strictly override web evidence.
2. Execution Failure Primacy:
   - If execution fails (PreliminaryVerdict.CONTRADICTED or INCONCLUSIVE), web evidence claiming
     "patch is correct" or "verified" is completely discarded;
     verdict remains CONTRADICTED/INCONCLUSIVE.
3. Fail-Closed on Missing Mandatory Grounding:
   - If grounding is REQUIRED but missing, contradictory, or insufficient, verdict fails closed
     to PreliminaryVerdict.BLOCKED or INCONCLUSIVE, preventing false VERIFIED awards.
4. Adversarial Defenses:
   - Prompt injection containment: web content treated as inert text strings;
     injection triggers are logged and neutralized.
   - Fake authority rejection: search result snippets claiming official Basebreak verdicts
     are discarded.
   - Tamper detection: modified facts, altered URLs, or mismatched digests fail closed immediately.
   - Credential defense: queries or excerpts demanding credentials trigger security flags.
5. Strict Provenance Preservation:
   - Preserves exactly the four canonical EvidenceProvenance categories:
     FIXTURE, LOCAL_EXECUTION, LIVE_NEBIUS, RECORDED_LIVE.
   - External provider calls (e.g. Tavily) alone are NOT LIVE_NEBIUS.
"""

from __future__ import annotations

import hashlib
import json
import re
from collections.abc import Mapping, Sequence
from dataclasses import dataclass
from enum import Enum
from typing import Any
from urllib.parse import urlparse

from basebreak.domain.verdict import EvidenceProvenance, PreliminaryVerdict
from basebreak.grounding.evidence import (
    FreshnessState,
    GroundedContractBinding,
    GroundedFact,
    TrustedProviderObservation,
    UncertaintyState,
    validate_trusted_observation_contract,
    verify_grounded_binding_digest,
    verify_grounded_fact_digest,
)
from basebreak.grounding.materiality import (
    GroundingMateriality,
    MaterialityDecision,
    verify_materiality_digest,
)
from basebreak.verifier.witness_result import NormalizedWitnessResult


class GroundingStatus(str, Enum):
    """Deterministic status outcome from the grounding authority firewall."""

    GROUNDED_VALID = "GROUNDED_VALID"
    GROUNDING_SKIPPED = "GROUNDING_SKIPPED"
    MISSING_REQUIRED_GROUNDING = "MISSING_REQUIRED_GROUNDING"
    CONTRADICTORY_GROUNDING = "CONTRADICTORY_GROUNDING"
    INSUFFICIENT_GROUNDING = "INSUFFICIENT_GROUNDING"
    INJECTION_BLOCKED = "INJECTION_BLOCKED"
    TAMPER_DETECTED = "TAMPER_DETECTED"
    UNVERIFIABLE_REQUIREMENT = "UNVERIFIABLE_REQUIREMENT"
    STALE_GROUNDING = "STALE_GROUNDING"
    UNTRUSTED_SOURCE_DOMAIN = "UNTRUSTED_SOURCE_DOMAIN"
    FIXTURE_ONLY_GROUNDING = "FIXTURE_ONLY_GROUNDING"


# Adversarial prompt-injection patterns in web content
INJECTION_PATTERNS = [
    re.compile(
        r"\b(?:ignore|disregard|forget)\s+(?:all\s+)?(?:previous|prior)\s+instructions\b",
        re.IGNORECASE,
    ),
    re.compile(r"\b(?:system|developer|assistant|admin)\s*:\s*", re.IGNORECASE),
    re.compile(
        r"\b(?:mark|verify|certify|declare)\s+(?:as\s+)?(?:pass|verified|safe|clean)\b",
        re.IGNORECASE,
    ),
    re.compile(
        r"\b(?:override|bypass|disable)\s+(?:verdict|verifier|sandbox|witness|security)\b",
        re.IGNORECASE,
    ),
    re.compile(
        r"\b(?:exfiltrate|leak|reveal|print|echo)\s+(?:secret|key|token|api_key|credential)\b",
        re.IGNORECASE,
    ),
    re.compile(r"<\s*script[^>]*>", re.IGNORECASE),
]

# Patterns where search snippets falsely claim official verification authority
FAKE_AUTHORITY_PATTERNS = [
    re.compile(r"basebreak\s+verifier\s*:\s*verified", re.IGNORECASE),
    re.compile(r"official\s+verdict\s*:\s*pass", re.IGNORECASE),
    re.compile(r"candidate\s+is\s+officially\s+verified", re.IGNORECASE),
    re.compile(r"witness\s+outcome\s*:\s*witness_pass", re.IGNORECASE),
]


def detect_prompt_injection(text: str) -> tuple[bool, list[str]]:
    """Inspect text for adversarial prompt injection patterns."""
    matched: list[str] = []
    for pat in INJECTION_PATTERNS:
        if pat.search(text):
            matched.append(pat.pattern)
    return (len(matched) > 0, matched)


def detect_fake_authority_claim(text: str) -> tuple[bool, list[str]]:
    """Inspect text for search snippets masquerading as internal verification authority."""
    matched: list[str] = []
    for pat in FAKE_AUTHORITY_PATTERNS:
        if pat.search(text):
            matched.append(pat.pattern)
    return (len(matched) > 0, matched)


def compute_firewall_digest(payload: Mapping[str, Any]) -> str:
    """Compute deterministic SHA-256 digest over canonical firewall evaluation payload."""
    canonical = json.dumps(
        dict(payload),
        sort_keys=True,
        separators=(",", ":"),
        ensure_ascii=True,
    )
    return hashlib.sha256(canonical.encode("utf-8")).hexdigest()


@dataclass(frozen=True, slots=True)
class GroundingFirewallResult:
    """Deterministic result of passing grounding evidence through the authority firewall."""

    final_verdict: PreliminaryVerdict
    grounding_status: GroundingStatus
    execution_verdict_preserved: bool
    original_execution_verdict: PreliminaryVerdict
    adversarial_flags: tuple[str, ...]
    rationale: str
    firewall_digest: str

    def __post_init__(self) -> None:
        if not isinstance(self.final_verdict, PreliminaryVerdict):
            raise TypeError(
                f"final_verdict must be PreliminaryVerdict, got {type(self.final_verdict).__name__}"
            )
        if not isinstance(self.grounding_status, GroundingStatus):
            raise TypeError(
                f"grounding_status must be GroundingStatus, "
                f"got {type(self.grounding_status).__name__}"
            )
        if not isinstance(self.original_execution_verdict, PreliminaryVerdict):
            raise TypeError(
                f"original_execution_verdict must be PreliminaryVerdict, "
                f"got {type(self.original_execution_verdict).__name__}"
            )


def validate_grounding_provenance(
    fact: GroundedFact,
    declared_provenance: EvidenceProvenance,
) -> None:
    """Verify that external grounding evidence does not violate Basebreak provenance invariants.

    Invariants:
    1. A fixture (is_fixture=True) cannot declare LIVE_NEBIUS or LOCAL_EXECUTION.
    2. A web retrieval (even real live Tavily) is NOT LIVE_NEBIUS (provenance category laundering).
    3. Exactly the 4 canonical categories are recognized.
    """
    if not isinstance(declared_provenance, EvidenceProvenance):
        raise TypeError(
            f"declared_provenance must be EvidenceProvenance, "
            f"got {type(declared_provenance).__name__}"
        )

    # External web search is never LIVE_NEBIUS
    if declared_provenance == EvidenceProvenance.LIVE_NEBIUS:
        raise ValueError(
            "Forbidden provenance: external web search (Tavily) alone cannot "
            "claim LIVE_NEBIUS provenance."
        )

    # Fixture cannot claim live or local execution
    if fact.is_fixture and declared_provenance != EvidenceProvenance.FIXTURE:
        raise ValueError(
            f"Provenance laundering rejected: fixture evidence cannot declare "
            f"'{declared_provenance.value}'."
        )


def evaluate_grounding_firewall(
    materiality: MaterialityDecision,
    binding: GroundedContractBinding | None,
    execution_verdict: PreliminaryVerdict,
    *,
    witness_results: Sequence[NormalizedWitnessResult] | None = None,
    protected_surface_violated: bool = False,
    budget_exhausted: bool = False,
    verified_observation_ids: Sequence[str] | None = None,
    trusted_observations: Sequence[TrustedProviderObservation] | None = None,
) -> GroundingFirewallResult:
    """Evaluate grounding evidence against deterministic execution facts with authority firewall.

    Invariants Enforced:
    1. Protected surface violation -> verdict CONTRADICTED (web evidence ignored).
    2. Budget exhaustion -> verdict BLOCKED (web evidence ignored).
    3. Witness / Execution Failure Primacy:
       If execution_verdict is CONTRADICTED or INCONCLUSIVE, web evidence CANNOT override it.
    4. Mandatory Grounding Gate:
       If materiality is REQUIRED and binding is missing/empty -> PreliminaryVerdict.BLOCKED.
    5. Contradictory / Insufficient Mandatory Grounding:
       If materiality is REQUIRED and uncertainty is CONTRADICTORY -> INCONCLUSIVE / BLOCKED.
       If materiality is REQUIRED and uncertainty is INSUFFICIENT -> BLOCKED.
    6. Tamper Detection:
       If any digest in binding fails verification -> status TAMPER_DETECTED, verdict BLOCKED.
    7. Adversarial Containment:
       If prompt injection or fake authority claims are detected in web content -> flags recorded,
       untrusted claims discarded.
    8. Observation Trust Boundary:
       Arbitrary caller-provided strings (verified_observation_ids) NEVER establish provider
       observation authority. Actual observation authority must come from
       TrustedProviderObservation.
    9. Not Applicable:
       If materiality is NOT_APPLICABLE -> web evidence ignored, status GROUNDING_SKIPPED,
       verdict = execution_verdict.
    """
    adversarial_flags: list[str] = []

    # 0a. Arbitrary caller-provided strings can NEVER establish verified external-provider execution
    if verified_observation_ids:
        adversarial_flags.append("forged_observation_authority:arbitrary_caller_strings")

    # 0b. Validate trusted provider observations from trustworthy runtime boundary
    valid_trusted_obs: list[TrustedProviderObservation] = []
    if trusted_observations is not None:
        for obs in trusted_observations:
            try:
                validate_trusted_observation_contract(obs)
                valid_trusted_obs.append(obs)
            except (TypeError, ValueError) as err:
                obs_id = getattr(obs, "observation_id", "invalid")
                adversarial_flags.append(f"tamper:observation_digest_mismatch:{obs_id}")
                return _make_firewall_result(
                    final_verdict=PreliminaryVerdict.BLOCKED,
                    status=GroundingStatus.TAMPER_DETECTED,
                    execution_verdict=execution_verdict,
                    flags=tuple(adversarial_flags),
                    rationale=f"Trusted observation validation failed for '{obs_id}': {err}",
                )

    # 0c. Verify MaterialityDecision integrity
    if not verify_materiality_digest(materiality):
        adversarial_flags.append("tamper:materiality_decision_digest_mismatch")
        return _make_firewall_result(
            final_verdict=PreliminaryVerdict.BLOCKED,
            status=GroundingStatus.TAMPER_DETECTED,
            execution_verdict=execution_verdict,
            flags=tuple(adversarial_flags),
            rationale="MaterialityDecision integrity verification failed; tampering detected.",
        )

    # 1. Protected surface violation is fatal
    if protected_surface_violated:
        return _make_firewall_result(
            final_verdict=PreliminaryVerdict.CONTRADICTED,
            status=GroundingStatus.GROUNDING_SKIPPED,
            execution_verdict=execution_verdict,
            flags=tuple(adversarial_flags),
            rationale=(
                "Protected surface mutation detected; "
                "candidate rejected regardless of web evidence."
            ),
        )

    # 2. Budget exhaustion fails closed
    if budget_exhausted:
        return _make_firewall_result(
            final_verdict=PreliminaryVerdict.BLOCKED,
            status=GroundingStatus.GROUNDING_SKIPPED,
            execution_verdict=execution_verdict,
            flags=tuple(adversarial_flags),
            rationale=(
                "Verification budget exhausted; verification blocked regardless of web evidence."
            ),
        )

    # 3. Execution Failure Primacy: if witness execution failed, candidate CANNOT pass
    if execution_verdict in (PreliminaryVerdict.CONTRADICTED, PreliminaryVerdict.INCONCLUSIVE):
        # Even if web results claim success, execution failure stands!
        if binding:
            for fact in binding.facts:
                has_fake_auth, auth_pats = detect_fake_authority_claim(fact.retrieved_claim)
                if has_fake_auth:
                    adversarial_flags.extend([f"fake_authority:{p}" for p in auth_pats])
        return _make_firewall_result(
            final_verdict=execution_verdict,
            status=GroundingStatus.GROUNDING_SKIPPED
            if materiality.materiality == GroundingMateriality.NOT_APPLICABLE
            else GroundingStatus.GROUNDED_VALID,
            execution_verdict=execution_verdict,
            flags=tuple(adversarial_flags),
            rationale=(
                f"Deterministic execution verdict '{execution_verdict.value}' "
                "has absolute authority over web claims."
            ),
        )

    # 4. Unverifiable requirement
    if materiality.materiality == GroundingMateriality.UNVERIFIABLE:
        return _make_firewall_result(
            final_verdict=PreliminaryVerdict.BLOCKED,
            status=GroundingStatus.UNVERIFIABLE_REQUIREMENT,
            execution_verdict=execution_verdict,
            flags=tuple(adversarial_flags),
            rationale="Task demands unverifiable external facts; fail-closed BLOCKED.",
        )

    # 5. Self-contained (NOT_APPLICABLE)
    if materiality.materiality == GroundingMateriality.NOT_APPLICABLE:
        return _make_firewall_result(
            final_verdict=execution_verdict,
            status=GroundingStatus.GROUNDING_SKIPPED,
            execution_verdict=execution_verdict,
            flags=tuple(adversarial_flags),
            rationale=(
                "External grounding is not applicable; "
                "verification relies purely on deterministic execution."
            ),
        )

    # 6. Check binding existence for REQUIRED or OPTIONAL
    if binding is None or len(binding.facts) == 0:
        if materiality.materiality == GroundingMateriality.REQUIRED:
            return _make_firewall_result(
                final_verdict=PreliminaryVerdict.BLOCKED,
                status=GroundingStatus.MISSING_REQUIRED_GROUNDING,
                execution_verdict=execution_verdict,
                flags=tuple(adversarial_flags),
                rationale=(
                    "Required external grounding was not executed or produced no facts; "
                    "fail-closed BLOCKED."
                ),
            )
        # OPTIONAL missing -> execution verdict preserved
        return _make_firewall_result(
            final_verdict=execution_verdict,
            status=GroundingStatus.GROUNDING_SKIPPED,
            execution_verdict=execution_verdict,
            flags=tuple(adversarial_flags),
            rationale=(
                "Optional external grounding not present; "
                "proceeding with deterministic execution verdict."
            ),
        )

    # 7. Tamper verification of binding and facts
    if not verify_grounded_binding_digest(binding):
        adversarial_flags.append("tamper:binding_digest_mismatch")
        return _make_firewall_result(
            final_verdict=PreliminaryVerdict.BLOCKED,
            status=GroundingStatus.TAMPER_DETECTED,
            execution_verdict=execution_verdict,
            flags=tuple(adversarial_flags),
            rationale="GroundedContractBinding digest verification failed; tampering detected.",
        )

    # 7b. Binding-to-decision context integrity checks
    if binding.materiality_decision_digest != materiality.decision_digest:
        adversarial_flags.append("tamper:materiality_digest_mismatch")
        return _make_firewall_result(
            final_verdict=PreliminaryVerdict.BLOCKED,
            status=GroundingStatus.TAMPER_DETECTED,
            execution_verdict=execution_verdict,
            flags=tuple(adversarial_flags),
            rationale=(
                f"Binding materiality digest '{binding.materiality_decision_digest}' does not "
                f"match incoming MaterialityDecision digest '{materiality.decision_digest}'."
            ),
        )

    if binding.contract_digest != materiality.contract_digest:
        adversarial_flags.append("tamper:contract_digest_mismatch")
        return _make_firewall_result(
            final_verdict=PreliminaryVerdict.BLOCKED,
            status=GroundingStatus.TAMPER_DETECTED,
            execution_verdict=execution_verdict,
            flags=tuple(adversarial_flags),
            rationale=(
                f"Binding contract digest '{binding.contract_digest}' does not "
                "match incoming MaterialityDecision contract digest "
                f"'{materiality.contract_digest}'."
            ),
        )

    for fact in binding.facts:
        if not verify_grounded_fact_digest(fact):
            adversarial_flags.append(f"tamper:fact_digest_mismatch:{fact.fact_id}")
            return _make_firewall_result(
                final_verdict=PreliminaryVerdict.BLOCKED,
                status=GroundingStatus.TAMPER_DETECTED,
                execution_verdict=execution_verdict,
                flags=tuple(adversarial_flags),
                rationale=(
                    f"GroundedFact '{fact.fact_id}' digest verification failed; tampering detected."
                ),
            )

        # 7c. Fact-to-context checks: contract_digest and requirement_id
        if fact.contract_digest != materiality.contract_digest:
            adversarial_flags.append(f"tamper:fact_contract_mismatch:{fact.fact_id}")
            return _make_firewall_result(
                final_verdict=PreliminaryVerdict.BLOCKED,
                status=GroundingStatus.TAMPER_DETECTED,
                execution_verdict=execution_verdict,
                flags=tuple(adversarial_flags),
                rationale=(
                    f"Fact '{fact.fact_id}' contract_digest does not match MaterialityDecision."
                ),
            )

        if fact.requirement_id != materiality.requirement_id:
            adversarial_flags.append(f"tamper:fact_requirement_mismatch:{fact.fact_id}")
            return _make_firewall_result(
                final_verdict=PreliminaryVerdict.BLOCKED,
                status=GroundingStatus.TAMPER_DETECTED,
                execution_verdict=execution_verdict,
                flags=tuple(adversarial_flags),
                rationale=(
                    f"Fact '{fact.fact_id}' requirement_id does not match MaterialityDecision."
                ),
            )

        # 7d. Mandatory grounding security, domain, freshness, and fake certainty checks
        if materiality.materiality == GroundingMateriality.REQUIRED:
            if not fact.source_url.startswith("https://"):
                adversarial_flags.append(f"insecure_url:{fact.fact_id}")
                return _make_firewall_result(
                    final_verdict=PreliminaryVerdict.BLOCKED,
                    status=GroundingStatus.INSUFFICIENT_GROUNDING,
                    execution_verdict=execution_verdict,
                    flags=tuple(adversarial_flags),
                    rationale=f"Mandatory grounding source '{fact.source_url}' is not HTTPS.",
                )

            if materiality.allowed_domains:
                parsed_dom = urlparse(fact.source_url).netloc.lower()
                if not any(
                    parsed_dom == d or parsed_dom.endswith("." + d)
                    for d in materiality.allowed_domains
                ):
                    adversarial_flags.append(f"untrusted_domain:{parsed_dom}")
                    return _make_firewall_result(
                        final_verdict=PreliminaryVerdict.BLOCKED,
                        status=GroundingStatus.UNTRUSTED_SOURCE_DOMAIN,
                        execution_verdict=execution_verdict,
                        flags=tuple(adversarial_flags),
                        rationale=(
                            f"Mandatory grounding source domain '{parsed_dom}' "
                            "is not in allowed domains."
                        ),
                    )

            if fact.freshness_state == FreshnessState.STALE:
                adversarial_flags.append(f"stale_fact:{fact.fact_id}")
                return _make_firewall_result(
                    final_verdict=PreliminaryVerdict.BLOCKED,
                    status=GroundingStatus.STALE_GROUNDING,
                    execution_verdict=execution_verdict,
                    flags=tuple(adversarial_flags),
                    rationale=(
                        f"Mandatory grounding fact '{fact.fact_id}' is stale; fail-closed BLOCKED."
                    ),
                )

            # Fake certainty check: fact claims CERTAIN without corroborating external reference
            is_certain = fact.uncertainty_state == UncertaintyState.CERTAIN
            if is_certain and materiality.external_reference:
                if materiality.external_reference.lower() not in fact.retrieved_claim.lower():
                    adversarial_flags.append(f"fake_certainty:{fact.fact_id}")
                    return _make_firewall_result(
                        final_verdict=PreliminaryVerdict.BLOCKED,
                        status=GroundingStatus.INSUFFICIENT_GROUNDING,
                        execution_verdict=execution_verdict,
                        flags=tuple(adversarial_flags),
                        rationale=(
                            f"Fact '{fact.fact_id}' claims CERTAIN but claim text does not "
                            f"corroborate external reference '{materiality.external_reference}'."
                        ),
                    )

        # 8. Check for adversarial injection in fact claims
        has_inj, inj_pats = detect_prompt_injection(fact.retrieved_claim)
        if has_inj:
            adversarial_flags.extend([f"injection:{p}" for p in inj_pats])

        has_auth, auth_pats = detect_fake_authority_claim(fact.retrieved_claim)
        if has_auth:
            adversarial_flags.extend([f"fake_authority:{p}" for p in auth_pats])

    # If adversarial injection was detected, evaluate if clean facts remain
    if any(f.startswith("injection:") for f in adversarial_flags):
        # We neutralize the injection and flag it
        if materiality.materiality == GroundingMateriality.REQUIRED:
            # If all facts had injections, fail closed
            clean_facts = [
                f for f in binding.facts if not detect_prompt_injection(f.retrieved_claim)[0]
            ]
            if not clean_facts:
                return _make_firewall_result(
                    final_verdict=PreliminaryVerdict.BLOCKED,
                    status=GroundingStatus.INJECTION_BLOCKED,
                    execution_verdict=execution_verdict,
                    flags=tuple(adversarial_flags),
                    rationale=(
                        "All mandatory grounding facts contained prompt injection payloads; "
                        "fail-closed BLOCKED."
                    ),
                )

    # 9. Uncertainty checks
    if binding.overall_uncertainty == UncertaintyState.CONTRADICTORY:
        if materiality.materiality == GroundingMateriality.REQUIRED:
            return _make_firewall_result(
                final_verdict=PreliminaryVerdict.INCONCLUSIVE,
                status=GroundingStatus.CONTRADICTORY_GROUNDING,
                execution_verdict=execution_verdict,
                flags=tuple(adversarial_flags),
                rationale=(
                    "Mandatory external grounding facts are contradictory; "
                    "fail-closed INCONCLUSIVE."
                ),
            )

    if binding.overall_uncertainty in (UncertaintyState.INSUFFICIENT, UncertaintyState.UNCERTAIN):
        if materiality.materiality == GroundingMateriality.REQUIRED:
            return _make_firewall_result(
                final_verdict=PreliminaryVerdict.BLOCKED,
                status=GroundingStatus.INSUFFICIENT_GROUNDING,
                execution_verdict=execution_verdict,
                flags=tuple(adversarial_flags),
                rationale=(
                    f"Mandatory external grounding facts are {binding.overall_uncertainty.value}; "
                    "fail-closed BLOCKED."
                ),
            )

    # 10. Fixture & Live Observation Enforcement:
    # A REQUIRED grounding decision with only fixture facts must never return
    # GROUNDED_VALID / VERIFIED.
    # Furthermore, caller-supplied is_fixture=False without verified provider observation
    # identity from the trusted runtime boundary cannot certify live provider execution.
    if materiality.materiality == GroundingMateriality.REQUIRED:
        if all(f.is_fixture for f in binding.facts):
            adversarial_flags.append("fixture_only:mandatory_grounding")
            return _make_firewall_result(
                final_verdict=PreliminaryVerdict.BLOCKED,
                status=GroundingStatus.FIXTURE_ONLY_GROUNDING,
                execution_verdict=execution_verdict,
                flags=tuple(adversarial_flags),
                rationale=(
                    "Mandatory external grounding requirement contains only fixture evidence; "
                    "offline fixtures cannot satisfy required live grounding; fail-closed BLOCKED."
                ),
            )

        # Build map of verified trusted live observations from runtime boundary
        trusted_live_map: dict[str, TrustedProviderObservation] = {
            obs.observation_id: obs
            for obs in valid_trusted_obs
            if obs.is_live_execution and obs.provenance == EvidenceProvenance.LOCAL_EXECUTION
        }

        unverified_facts = [
            f
            for f in binding.facts
            if not f.is_fixture
            and (
                not f.provider_response_id
                or f.provider_response_id not in trusted_live_map
                or trusted_live_map[f.provider_response_id].provider_name != f.retrieval_provider
            )
        ]
        if unverified_facts:
            adversarial_flags.append("unverified_live_claim:missing_observation_authority")
            return _make_firewall_result(
                final_verdict=PreliminaryVerdict.BLOCKED,
                status=GroundingStatus.INSUFFICIENT_GROUNDING,
                execution_verdict=execution_verdict,
                flags=tuple(adversarial_flags),
                rationale=(
                    "Caller-supplied is_fixture=False without verified provider observation "
                    "authority from trusted runtime boundary cannot certify live provider "
                    "execution; arbitrary caller strings rejected; fail-closed BLOCKED."
                ),
            )

    # For OPTIONAL grounding, fixture-only evidence does not block but does not claim GROUNDED_VALID
    if materiality.materiality == GroundingMateriality.OPTIONAL:
        if all(f.is_fixture for f in binding.facts):
            return _make_firewall_result(
                final_verdict=execution_verdict,
                status=GroundingStatus.FIXTURE_ONLY_GROUNDING,
                execution_verdict=execution_verdict,
                flags=tuple(adversarial_flags),
                rationale=(
                    "Optional external grounding consists of offline fixture evidence; "
                    "proceeding with deterministic execution verdict."
                ),
            )

    # All checks passed: valid grounding preserves execution verdict
    return _make_firewall_result(
        final_verdict=execution_verdict,
        status=GroundingStatus.GROUNDED_VALID,
        execution_verdict=execution_verdict,
        flags=tuple(adversarial_flags),
        rationale="External grounding validated successfully and bound to execution facts.",
    )


def _make_firewall_result(
    final_verdict: PreliminaryVerdict,
    status: GroundingStatus,
    execution_verdict: PreliminaryVerdict,
    flags: tuple[str, ...],
    rationale: str,
) -> GroundingFirewallResult:
    payload = {
        "final_verdict": final_verdict.value,
        "grounding_status": status.value,
        "execution_verdict_preserved": (final_verdict == execution_verdict),
        "original_execution_verdict": execution_verdict.value,
        "adversarial_flags": list(flags),
        "rationale": rationale,
    }
    digest = compute_firewall_digest(payload)
    return GroundingFirewallResult(
        final_verdict=final_verdict,
        grounding_status=status,
        execution_verdict_preserved=(final_verdict == execution_verdict),
        original_execution_verdict=execution_verdict,
        adversarial_flags=flags,
        rationale=rationale,
        firewall_digest=digest,
    )
