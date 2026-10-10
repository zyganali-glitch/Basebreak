"""Deterministic grounding materiality policy and decision contracts.

P-16.01: Define when external current facts are materially required.

Authority & Invariants:
1. Thesis: Basebreak verifies causal code behavior: "If the patch matters, the base must break."
2. External current facts may inform a contract or establish technical context, but CANNOT
   certify code behavior.
3. Ordinary bug fixes, refactors, and performance changes NEVER depend on web search.
   Mentioning a technology (e.g. 'Python', 'Flask', 'HTTP') does NOT trigger grounding.
4. Materiality is partitioned deterministically:
   - REQUIRED: External current facts are mandatory for correctness (e.g. CVE advisory,
     authoritative dependency migration breaking changes).
   - OPTIONAL: External facts provide non-blocking enrichment.
   - NOT_APPLICABLE: Task is self-contained and verifiable from pinned repository
     and frozen contract.
   - UNVERIFIABLE: Task demands unverifiable or contradictory external facts.
5. All decisions produce immutable, content-addressed decision records with canonical digests.
6. Fail-closed: Missing required grounding prevents false VERIFIED verdicts.
"""

from __future__ import annotations

import hashlib
import json
import re
from collections.abc import Mapping, Sequence
from dataclasses import dataclass
from enum import Enum
from typing import Any

from basebreak.compiler.freeze import FrozenContract, FrozenRequirement
from basebreak.domain.semantics import ChangeClass


class GroundingMateriality(str, Enum):
    """Deterministic materiality classification for external current facts."""

    REQUIRED = "REQUIRED"
    OPTIONAL = "OPTIONAL"
    NOT_APPLICABLE = "NOT_APPLICABLE"
    UNVERIFIABLE = "UNVERIFIABLE"


class GroundingCategory(str, Enum):
    """Category of external technical fact."""

    CVE_SECURITY_ADVISORY = "CVE_SECURITY_ADVISORY"
    DEP_API_MIGRATION = "DEP_API_MIGRATION"
    GENERAL_TECHNICAL_FACT = "GENERAL_TECHNICAL_FACT"


# Regex to detect standard CVE identifiers: CVE-YYYY-NNNN+
CVE_PATTERN = re.compile(r"\bCVE-\d{4}-\d{4,8}\b", re.IGNORECASE)

# Default allowlisted authoritative domains for security advisories
AUTHORITATIVE_CVE_DOMAINS: tuple[str, ...] = (
    "nvd.nist.gov",
    "cve.org",
    "github.com",
    "osv.dev",
    "security.snyk.io",
)

# Default allowlisted authoritative domains for dependency / API migrations
AUTHORITATIVE_DEP_API_DOMAINS: tuple[str, ...] = (
    "pypi.org",
    "docs.python.org",
    "github.com",
    "readthedocs.io",
)


def compute_materiality_digest(payload: Mapping[str, Any]) -> str:
    """Compute deterministic SHA-256 digest over canonical JSON representation."""
    canonical = json.dumps(
        dict(payload),
        sort_keys=True,
        separators=(",", ":"),
        ensure_ascii=True,
    )
    return hashlib.sha256(canonical.encode("utf-8")).hexdigest()


@dataclass(frozen=True, slots=True)
class MaterialityDecision:
    """Deterministic, immutable record of whether external grounding is required."""

    decision_id: str
    contract_digest: str
    requirement_id: str
    materiality: GroundingMateriality
    category: GroundingCategory | None
    external_reference: str | None
    permitted_query: str | None
    allowed_domains: tuple[str, ...]
    rationale: str
    decision_digest: str

    def __post_init__(self) -> None:
        if not self.decision_id or not isinstance(self.decision_id, str):
            raise ValueError("decision_id must be a non-empty string")
        if not self.contract_digest or len(self.contract_digest) != 64:
            raise ValueError("contract_digest must be a 64-hex SHA-256 string")
        if not self.requirement_id or not isinstance(self.requirement_id, str):
            raise ValueError("requirement_id must be a non-empty string")
        if not isinstance(self.materiality, GroundingMateriality):
            raise TypeError(
                f"materiality must be GroundingMateriality, got {type(self.materiality).__name__}"
            )
        if self.category is not None and not isinstance(self.category, GroundingCategory):
            raise TypeError(
                f"category must be GroundingCategory or None, got {type(self.category).__name__}"
            )
        if not self.rationale:
            raise ValueError("rationale must not be empty")

        # Verify digest
        expected_digest = compute_materiality_digest(
            {
                "decision_id": self.decision_id,
                "contract_digest": self.contract_digest,
                "requirement_id": self.requirement_id,
                "materiality": self.materiality.value,
                "category": self.category.value if self.category else None,
                "external_reference": self.external_reference,
                "permitted_query": self.permitted_query,
                "allowed_domains": list(self.allowed_domains),
                "rationale": self.rationale,
            }
        )
        if self.decision_digest != expected_digest:
            raise ValueError(
                f"decision_digest mismatch: declared '{self.decision_digest}', "
                f"computed '{expected_digest}'"
            )


def verify_materiality_digest(decision: MaterialityDecision) -> bool:
    """Verify integrity of a MaterialityDecision."""
    expected = compute_materiality_digest(
        {
            "decision_id": decision.decision_id,
            "contract_digest": decision.contract_digest,
            "requirement_id": decision.requirement_id,
            "materiality": decision.materiality.value,
            "category": decision.category.value if decision.category else None,
            "external_reference": decision.external_reference,
            "permitted_query": decision.permitted_query,
            "allowed_domains": list(decision.allowed_domains),
            "rationale": decision.rationale,
        }
    )
    return decision.decision_digest == expected


def _build_decision(
    decision_id: str,
    contract_digest: str,
    requirement_id: str,
    materiality: GroundingMateriality,
    category: GroundingCategory | None,
    external_reference: str | None,
    permitted_query: str | None,
    allowed_domains: tuple[str, ...],
    rationale: str,
) -> MaterialityDecision:
    payload: dict[str, Any] = {
        "decision_id": decision_id,
        "contract_digest": contract_digest,
        "requirement_id": requirement_id,
        "materiality": materiality.value,
        "category": category.value if category else None,
        "external_reference": external_reference,
        "permitted_query": permitted_query,
        "allowed_domains": list(allowed_domains),
        "rationale": rationale,
    }
    digest = compute_materiality_digest(payload)
    return MaterialityDecision(
        decision_id=decision_id,
        contract_digest=contract_digest,
        requirement_id=requirement_id,
        materiality=materiality,
        category=category,
        external_reference=external_reference,
        permitted_query=permitted_query,
        allowed_domains=allowed_domains,
        rationale=rationale,
        decision_digest=digest,
    )


def evaluate_grounding_materiality(
    contract: FrozenContract,
    requirement: FrozenRequirement | None = None,
    *,
    external_reference: str | None = None,
    forced_unverifiable: bool = False,
    custom_allowed_domains: Sequence[str] | None = None,
    force_optional: bool = False,
) -> MaterialityDecision:
    """Determine whether external grounding is required for a requirement/contract.

    Rules:
    1. If forced_unverifiable is True: UNVERIFIABLE.
    2. ChangeClass.SECURITY_FIX:
       - If CVE identifier or explicit security advisory is referenced:
         materiality = REQUIRED (or OPTIONAL if force_optional).
         category = CVE_SECURITY_ADVISORY.
         allowed_domains = AUTHORITATIVE_CVE_DOMAINS (or custom).
       - If no external advisory needed (self-contained reproducer):
         materiality = NOT_APPLICABLE.
    3. ChangeClass.DEP_API_CHANGE:
       - If external dependency migration / release note specification is referenced:
         materiality = REQUIRED (or OPTIONAL if force_optional).
         category = DEP_API_MIGRATION.
         allowed_domains = AUTHORITATIVE_DEP_API_DOMAINS (or custom).
       - If self-contained within repository:
         materiality = NOT_APPLICABLE.
    4. ChangeClass.BUG_FIX, PERFORMANCE, REFACTOR, NEW_FEATURE:
       - Default = NOT_APPLICABLE.
       - Mentions of standard programming languages, packages, or libraries do NOT trigger search.
    """
    if not isinstance(contract, FrozenContract):
        raise TypeError(f"contract must be FrozenContract, got {type(contract).__name__}")

    req_id = requirement.requirement_id if requirement else "GLOBAL_CONTRACT"
    req_text = ""
    if requirement:
        req_text = f"{requirement.statement} {requirement.citation} {requirement.rationale}"
    elif contract.requirements:
        req_text = " ".join(
            f"{r.statement} {r.citation} {r.rationale}" for r in contract.requirements
        )

    # Check for forced unverifiable
    if forced_unverifiable:
        return _build_decision(
            decision_id=f"mat-{contract.contract_digest[:8]}-{req_id}-unverifiable",
            contract_digest=contract.contract_digest,
            requirement_id=req_id,
            materiality=GroundingMateriality.UNVERIFIABLE,
            category=None,
            external_reference=external_reference,
            permitted_query=None,
            allowed_domains=(),
            rationale=(
                "External fact requirement is contradictory, ambiguous, or impossible to verify."
            ),
        )

    # Check for SECURITY_FIX
    if contract.change_class == ChangeClass.SECURITY_FIX:
        # Check text or explicit reference for CVE
        cve_match = CVE_PATTERN.search(req_text) or (
            CVE_PATTERN.search(external_reference) if external_reference else None
        )
        has_advisory = (
            cve_match
            or (external_reference and "advisory" in external_reference.lower())
            or "advisory" in req_text.lower()
            or "cve" in req_text.lower()
        )

        if has_advisory:
            ref_str = (
                cve_match.group(0).upper()
                if cve_match
                else (external_reference or "SECURITY_ADVISORY")
            )
            query = f"{ref_str} security advisory vulnerability"
            domains = (
                tuple(custom_allowed_domains)
                if custom_allowed_domains
                else AUTHORITATIVE_CVE_DOMAINS
            )
            materiality = (
                GroundingMateriality.OPTIONAL if force_optional else GroundingMateriality.REQUIRED
            )
            rationale = (
                f"Security fix requires grounding against authoritative advisory ({ref_str}) "
                f"to establish vulnerability conditions and affected scope."
            )
            return _build_decision(
                decision_id=f"mat-{contract.contract_digest[:8]}-{req_id}-cve",
                contract_digest=contract.contract_digest,
                requirement_id=req_id,
                materiality=materiality,
                category=GroundingCategory.CVE_SECURITY_ADVISORY,
                external_reference=ref_str,
                permitted_query=query,
                allowed_domains=domains,
                rationale=rationale,
            )

        # Self-contained security fix
        return _build_decision(
            decision_id=f"mat-{contract.contract_digest[:8]}-{req_id}-sec-self",
            contract_digest=contract.contract_digest,
            requirement_id=req_id,
            materiality=GroundingMateriality.NOT_APPLICABLE,
            category=None,
            external_reference=None,
            permitted_query=None,
            allowed_domains=(),
            rationale=(
                "Security fix is self-contained with reproducible in-repo harness; "
                "no external CVE grounding required."
            ),
        )

    # Check for DEP_API_CHANGE
    if contract.change_class == ChangeClass.DEP_API_CHANGE:
        # Check if migration requires external facts (e.g. release notes or breaking changes)
        is_migration = external_reference is not None or any(
            kw in req_text.lower()
            for kw in ("migration", "upgrade", "breaking change", "release notes", "deprecat")
        )
        if is_migration:
            ref_str = external_reference or "EXTERNAL_API_MIGRATION"
            query = f"{ref_str} migration guide breaking changes release notes"
            domains = (
                tuple(custom_allowed_domains)
                if custom_allowed_domains
                else AUTHORITATIVE_DEP_API_DOMAINS
            )
            materiality = (
                GroundingMateriality.OPTIONAL if force_optional else GroundingMateriality.REQUIRED
            )
            rationale = (
                f"Dependency/API migration requires grounding against authoritative release notes "
                f"({ref_str}) to verify target interface semantics."
            )
            return _build_decision(
                decision_id=f"mat-{contract.contract_digest[:8]}-{req_id}-dep",
                contract_digest=contract.contract_digest,
                requirement_id=req_id,
                materiality=materiality,
                category=GroundingCategory.DEP_API_MIGRATION,
                external_reference=ref_str,
                permitted_query=query,
                allowed_domains=domains,
                rationale=rationale,
            )

        return _build_decision(
            decision_id=f"mat-{contract.contract_digest[:8]}-{req_id}-dep-self",
            contract_digest=contract.contract_digest,
            requirement_id=req_id,
            materiality=GroundingMateriality.NOT_APPLICABLE,
            category=None,
            external_reference=None,
            permitted_query=None,
            allowed_domains=(),
            rationale=(
                "Dependency/API change is fully specified by pinned in-repo contract; "
                "external grounding skipped."
            ),
        )

    # All other change classes (BUG_FIX, PERFORMANCE, REFACTOR, NEW_FEATURE):
    # Ordinary bug fixes and code improvements are strictly self-contained.
    return _build_decision(
        decision_id=f"mat-{contract.contract_digest[:8]}-{req_id}-self",
        contract_digest=contract.contract_digest,
        requirement_id=req_id,
        materiality=GroundingMateriality.NOT_APPLICABLE,
        category=None,
        external_reference=None,
        permitted_query=None,
        allowed_domains=(),
        rationale=(
            f"ChangeClass.{contract.change_class.name} is fully verifiable from pinned repository "
            "and frozen contract; external search is prohibited and not applicable."
        ),
    )
