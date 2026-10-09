"""Deterministic risk feature extraction and policy levels.

P-15.01: Define deterministic risk features and policy levels under the
Basebreak causal verification authority model.

Authority Model & Invariants:
1. Deterministic classification facts govern:
   Risk classification is computed strictly from verified source, contract,
   and candidate facts. Model prose and builder confidence possess zero authority.
2. Explicit policy levels:
   LOW, MEDIUM, HIGH with strict deterministic ordering (LOW < MEDIUM < HIGH).
3. Fail-closed conservative elevation:
   Untrusted, missing, or contradictory inputs fail closed to HIGH risk.
4. Independent causal witness preservation:
   No risk level (even LOW) may bypass an independently required causal witness.
5. Monotonicity invariant:
   Adding risk factors or widening blast radius never decreases risk level.
6. Zero provider imports, zero network calls, zero model imports.
"""

from __future__ import annotations

import hashlib
import json
import re
from collections.abc import Mapping, Sequence
from dataclasses import dataclass
from enum import Enum
from typing import Any

from basebreak.compiler.freeze import FrozenContract
from basebreak.compiler.semantics import CertaintyLevel, ChangeClass
from basebreak.security.protected_surfaces import (
    ProtectedSurfaceManifest,
    get_canonical_basebreak_protected_manifest,
    is_path_protected,
)

RISK_POLICY_SCHEMA_VERSION: str = "1.0.0"

_DIGEST_PATTERN = re.compile(r"^[0-9a-f]{64}$")

# Patterns matching security-sensitive paths in software repositories
_SECURITY_PATH_PATTERNS = (
    re.compile(r"(?:^|/)(?:auth|authentication|authorization)(?:/|\.|$)", re.IGNORECASE),
    re.compile(r"(?:^|/)(?:crypto|cryptography|tls|ssl)(?:/|\.|$)", re.IGNORECASE),
    re.compile(r"(?:^|/)(?:secret|credential|token|key|password|jwt)(?:/|\.|$)", re.IGNORECASE),
    re.compile(r"(?:^|/)(?:permission|rbac|acl|policy|sandbox_policy)(?:/|\.|$)", re.IGNORECASE),
    re.compile(r"(?:^|/)(?:security|audit|sanitizer)(?:/|\.|$)", re.IGNORECASE),
)

# Patterns matching packaging and dependency configuration files
_DEPENDENCY_FILE_PATTERNS = (
    re.compile(
        r"(?:^|/)(?:requirements[^\s/]*\.txt|pyproject\.toml|uv\.lock|Pipfile(?:\.lock)?|poetry\.lock|setup\.cfg|setup\.py)$",
        re.IGNORECASE,
    ),
    re.compile(
        r"(?:^|/)(?:package\.json|package-lock\.json|yarn\.lock|pnpm-lock\.yaml)$", re.IGNORECASE
    ),
    re.compile(
        r"(?:^|/)(?:Cargo\.toml|Cargo\.lock|go\.mod|go\.sum|pom\.xml|build\.gradle)$", re.IGNORECASE
    ),
)

# Patterns matching public interface / API files
_PUBLIC_API_PATTERNS = (
    re.compile(r"(?:^|/)(?:__init__\.py)$"),
    re.compile(
        r"(?:^|/)(?:api|routes|endpoints|controllers|schema|interfaces)(?:/|\.|$)", re.IGNORECASE
    ),
    re.compile(
        r"(?:^|/)(?:openapi\.json|swagger\.json|openapi\.yaml|swagger\.yaml)$", re.IGNORECASE
    ),
)


class RiskLevel(str, Enum):
    """Deterministic risk levels for verification policy.

    Strict total order: LOW < MEDIUM < HIGH.
    """

    LOW = "LOW"
    MEDIUM = "MEDIUM"
    HIGH = "HIGH"

    @property
    def rank(self) -> int:
        match self:
            case RiskLevel.LOW:
                return 1
            case RiskLevel.MEDIUM:
                return 2
            case RiskLevel.HIGH:
                return 3

    def __lt__(self, other: Any) -> bool:
        if not isinstance(other, RiskLevel):
            return NotImplemented
        return self.rank < other.rank

    def __le__(self, other: Any) -> bool:
        if not isinstance(other, RiskLevel):
            return NotImplemented
        return self.rank <= other.rank

    def __gt__(self, other: Any) -> bool:
        if not isinstance(other, RiskLevel):
            return NotImplemented
        return self.rank > other.rank

    def __ge__(self, other: Any) -> bool:
        if not isinstance(other, RiskLevel):
            return NotImplemented
        return self.rank >= other.rank


class RiskFeatureError(Exception):
    """Base exception for risk feature errors."""


class InvalidRiskInputError(RiskFeatureError):
    """Raised when input to risk classification is malformed or invalid."""


class RiskTamperingError(RiskFeatureError):
    """Raised when risk classification digest does not match recomputed SHA-256."""


@dataclass(frozen=True, slots=True)
class RiskFeatureSet:
    """Immutable, deterministic feature set extracted from validated change facts.

    Every attribute is strictly typed, deterministic, and inspectable.
    """

    change_class: ChangeClass
    certainty: CertaintyLevel = CertaintyLevel.CONFIDENT
    touched_paths: tuple[str, ...] = ()
    touched_protected_surfaces: tuple[str, ...] = ()
    touched_security_sensitive_paths: tuple[str, ...] = ()
    changed_files_count: int = 0
    changed_lines_count: int = 0
    affects_public_api: bool = False
    affects_dependencies: bool = False
    has_contractual_obligations: bool = False
    has_untrusted_metadata: bool = False
    has_contradictory_signals: bool = False

    def __post_init__(self) -> None:
        if not isinstance(self.change_class, ChangeClass):
            cls_name = type(self.change_class).__name__
            raise InvalidRiskInputError(f"change_class must be ChangeClass, got {cls_name}")
        if not isinstance(self.certainty, CertaintyLevel):
            cert_name = type(self.certainty).__name__
            raise InvalidRiskInputError(f"certainty must be CertaintyLevel, got {cert_name}")
        if (
            isinstance(self.changed_files_count, bool)
            or not isinstance(self.changed_files_count, int)
            or self.changed_files_count < 0
        ):
            raise InvalidRiskInputError(
                f"changed_files_count must be a non-negative int, got {self.changed_files_count!r}"
            )
        if (
            isinstance(self.changed_lines_count, bool)
            or not isinstance(self.changed_lines_count, int)
            or self.changed_lines_count < 0
        ):
            raise InvalidRiskInputError(
                f"changed_lines_count must be a non-negative int, got {self.changed_lines_count!r}"
            )

        # Enforce canonical sorted tuples without duplicates
        for attr_name, val in (
            ("touched_paths", self.touched_paths),
            ("touched_protected_surfaces", self.touched_protected_surfaces),
            ("touched_security_sensitive_paths", self.touched_security_sensitive_paths),
        ):
            if not isinstance(val, tuple):
                raise InvalidRiskInputError(
                    f"{attr_name} must be a tuple, got {type(val).__name__}"
                )
            for item in val:
                if not isinstance(item, str) or not item.strip():
                    raise InvalidRiskInputError(
                        f"items in {attr_name} must be non-empty strings, got {item!r}"
                    )
            if list(val) != sorted(set(val)):
                raise InvalidRiskInputError(f"{attr_name} must be sorted without duplicates")

    def to_dict(self) -> dict[str, Any]:
        """Serialize feature set to deterministic dictionary."""
        return {
            "affects_dependencies": self.affects_dependencies,
            "affects_public_api": self.affects_public_api,
            "certainty": self.certainty.value,
            "change_class": self.change_class.value,
            "changed_files_count": self.changed_files_count,
            "changed_lines_count": self.changed_lines_count,
            "has_contractual_obligations": self.has_contractual_obligations,
            "has_contradictory_signals": self.has_contradictory_signals,
            "has_untrusted_metadata": self.has_untrusted_metadata,
            "touched_paths": list(self.touched_paths),
            "touched_protected_surfaces": list(self.touched_protected_surfaces),
            "touched_security_sensitive_paths": list(self.touched_security_sensitive_paths),
        }


@dataclass(frozen=True, slots=True)
class RiskClassification:
    """Tamper-evident, reproducible risk classification record."""

    schema_version: str
    risk_level: RiskLevel
    features: RiskFeatureSet
    elevation_reasons: tuple[str, ...]
    classification_digest: str
    is_authoritative: bool = False  # Invariant: zero unverified authority

    def __post_init__(self) -> None:
        if self.schema_version != RISK_POLICY_SCHEMA_VERSION:
            exp = RISK_POLICY_SCHEMA_VERSION
            raise InvalidRiskInputError(
                f"Unsupported schema_version {self.schema_version!r}, expected {exp!r}"
            )
        if not isinstance(self.risk_level, RiskLevel):
            raise InvalidRiskInputError(
                f"risk_level must be RiskLevel, got {type(self.risk_level).__name__}"
            )
        if not isinstance(self.features, RiskFeatureSet):
            raise InvalidRiskInputError(
                f"features must be RiskFeatureSet, got {type(self.features).__name__}"
            )
        if not isinstance(self.elevation_reasons, tuple):
            raise InvalidRiskInputError("elevation_reasons must be a tuple")
        if not _DIGEST_PATTERN.match(self.classification_digest):
            raise InvalidRiskInputError(
                f"classification_digest must be 64-char hex, got {self.classification_digest!r}"
            )
        if self.is_authoritative is not False:
            raise InvalidRiskInputError(
                "is_authoritative must be False; risk classification cannot self-certify"
            )

    def to_dict(self) -> dict[str, Any]:
        """Serialize risk classification to deterministic dictionary."""
        return {
            "classification_digest": self.classification_digest,
            "elevation_reasons": list(self.elevation_reasons),
            "features": self.features.to_dict(),
            "is_authoritative": self.is_authoritative,
            "risk_level": self.risk_level.value,
            "schema_version": self.schema_version,
        }


def canonical_risk_bytes(payload: Mapping[str, Any]) -> bytes:
    """Encode payload as canonical deterministic UTF-8 JSON bytes."""
    return json.dumps(
        payload,
        sort_keys=True,
        separators=(",", ":"),
        ensure_ascii=False,
    ).encode("utf-8")


def compute_risk_digest(payload: Mapping[str, Any]) -> str:
    """Compute SHA-256 digest over canonical payload excluding classification_digest."""
    clean = {k: v for k, v in payload.items() if k != "classification_digest"}
    return hashlib.sha256(canonical_risk_bytes(clean)).hexdigest()


def is_security_sensitive_path(path: str) -> bool:
    """Check if repository path matches known security-sensitive patterns."""
    norm = path.replace("\\", "/").strip().lower()
    return any(p.search(norm) is not None for p in _SECURITY_PATH_PATTERNS)


def is_dependency_path(path: str) -> bool:
    """Check if repository path matches known packaging or dependency files."""
    norm = path.replace("\\", "/").strip().lower()
    return any(p.search(norm) is not None for p in _DEPENDENCY_FILE_PATTERNS)


def is_public_api_path(path: str) -> bool:
    """Check if repository path matches known public API or module export files."""
    norm = path.replace("\\", "/").strip().lower()
    return any(p.search(norm) is not None for p in _PUBLIC_API_PATTERNS)


def extract_risk_features(
    *,
    change_class: ChangeClass,
    certainty: CertaintyLevel = CertaintyLevel.CONFIDENT,
    changed_files: Sequence[str] = (),
    changed_lines_count: int = 0,
    has_contractual_obligations: bool = False,
    has_untrusted_metadata: bool = False,
    has_contradictory_signals: bool = False,
    manifest: ProtectedSurfaceManifest | None = None,
) -> RiskFeatureSet:
    """Deterministically extract risk features from validated facts."""
    norm_paths: list[str] = []
    protected_paths: list[str] = []
    security_paths: list[str] = []
    affects_deps = False
    affects_api = False

    active_manifest = manifest or get_canonical_basebreak_protected_manifest()

    for p in changed_files:
        norm = p.replace("\\", "/").strip()
        if not norm:
            continue
        norm_paths.append(norm)

        # Check protected surfaces
        if is_path_protected(norm, manifest=active_manifest):
            protected_paths.append(norm)

        # Check security-sensitive paths
        if is_security_sensitive_path(norm):
            security_paths.append(norm)

        # Check dependencies
        if is_dependency_path(norm):
            affects_deps = True

        # Check public API
        if is_public_api_path(norm):
            affects_api = True

    canonical_paths = tuple(sorted(set(norm_paths)))
    canonical_protected = tuple(sorted(set(protected_paths)))
    canonical_security = tuple(sorted(set(security_paths)))

    files_count = len(canonical_paths)

    return RiskFeatureSet(
        change_class=change_class,
        certainty=certainty,
        touched_paths=canonical_paths,
        touched_protected_surfaces=canonical_protected,
        touched_security_sensitive_paths=canonical_security,
        changed_files_count=files_count,
        changed_lines_count=changed_lines_count,
        affects_public_api=affects_api,
        affects_dependencies=affects_deps,
        has_contractual_obligations=has_contractual_obligations,
        has_untrusted_metadata=has_untrusted_metadata,
        has_contradictory_signals=has_contradictory_signals,
    )


def extract_risk_features_from_contract(
    contract: FrozenContract,
    *,
    changed_files: Sequence[str] = (),
    changed_lines_count: int = 0,
    has_untrusted_metadata: bool = False,
    manifest: ProtectedSurfaceManifest | None = None,
) -> RiskFeatureSet:
    """Extract risk features using an immutable FrozenContract as the authority source."""
    if not isinstance(contract, FrozenContract):
        raise InvalidRiskInputError(
            f"contract must be a FrozenContract, got {type(contract).__name__}"
        )

    has_contradictory = contract.certainty == CertaintyLevel.UNKNOWN
    has_obligations = len(contract.requirements) > 0

    return extract_risk_features(
        change_class=contract.change_class,
        certainty=contract.certainty,
        changed_files=changed_files,
        changed_lines_count=changed_lines_count,
        has_contractual_obligations=has_obligations,
        has_untrusted_metadata=has_untrusted_metadata,
        has_contradictory_signals=has_contradictory,
        manifest=manifest,
    )


def classify_risk(features: RiskFeatureSet) -> RiskClassification:
    """Deterministically classify risk level and return a signed, verifiable RiskClassification.

    Classification Rules:
    1. HIGH risk triggers (Fail-Closed / Safety-Critical):
       - has_untrusted_metadata == True
       - has_contradictory_signals == True
       - certainty == UNKNOWN
       - touched_protected_surfaces is non-empty
       - change_class == SECURITY_FIX
       - touched_security_sensitive_paths is non-empty
       - changed_files_count >= 10 OR changed_lines_count >= 500 (wide blast radius)
    2. MEDIUM risk triggers (Moderate Scope / Elevated Scrutiny):
       - certainty == AMBIGUOUS
       - change_class in (PERFORMANCE, DEP_API_CHANGE)
       - changed_files_count >= 3 OR changed_lines_count >= 100
       - affects_public_api == True
       - affects_dependencies == True
    3. LOW risk:
       - Localized, confident changes with no high/medium risk signals.
    """
    if not isinstance(features, RiskFeatureSet):
        raise InvalidRiskInputError(
            f"features must be RiskFeatureSet, got {type(features).__name__}"
        )

    reasons: list[str] = []

    # --- HIGH RISK EVALUATION ---
    if features.has_untrusted_metadata:
        reasons.append("Untrusted metadata detected: fail-closed elevation to HIGH risk")
    if features.has_contradictory_signals:
        reasons.append("Contradictory classification signals detected: elevated to HIGH risk")
    if features.certainty == CertaintyLevel.UNKNOWN:
        reasons.append("Semantic certainty is UNKNOWN: fail-closed elevation to HIGH risk")
    if features.touched_protected_surfaces:
        reasons.append(
            f"Touches {len(features.touched_protected_surfaces)} protected surface(s): "
            + ", ".join(features.touched_protected_surfaces[:3])
        )
    if features.change_class == ChangeClass.SECURITY_FIX:
        reasons.append("SECURITY_FIX changes are inherently HIGH risk")
    if features.touched_security_sensitive_paths:
        reasons.append(
            f"Touches {len(features.touched_security_sensitive_paths)} security-sensitive path(s): "
            + ", ".join(features.touched_security_sensitive_paths[:3])
        )
    if features.changed_files_count >= 10 or features.changed_lines_count >= 500:
        fc = features.changed_files_count
        lc = features.changed_lines_count
        reasons.append(f"Large blast radius ({fc} files, {lc} lines)")

    if reasons:
        final_level = RiskLevel.HIGH
    else:
        # --- MEDIUM RISK EVALUATION ---
        if features.certainty == CertaintyLevel.AMBIGUOUS:
            reasons.append("Semantic certainty is AMBIGUOUS: elevated to MEDIUM risk")
        if features.change_class in (ChangeClass.PERFORMANCE, ChangeClass.DEP_API_CHANGE):
            reasons.append(
                f"{features.change_class.value} requires measured parity/migration verification"
            )
        if features.changed_files_count >= 3 or features.changed_lines_count >= 100:
            fc = features.changed_files_count
            lc = features.changed_lines_count
            reasons.append(f"Moderate scope ({fc} files, {lc} lines)")
        if features.affects_public_api:
            reasons.append("Modifies public API surface")
        if features.affects_dependencies:
            reasons.append("Modifies packaging or external dependencies")

        if reasons:
            final_level = RiskLevel.MEDIUM
        else:
            final_level = RiskLevel.LOW
            reasons.append("Localized scope with confident change semantics and clean boundaries")

    reasons_tuple = tuple(reasons)

    # Compute deterministic digest
    raw_payload: dict[str, Any] = {
        "elevation_reasons": list(reasons_tuple),
        "features": features.to_dict(),
        "is_authoritative": False,
        "risk_level": final_level.value,
        "schema_version": RISK_POLICY_SCHEMA_VERSION,
    }
    digest = compute_risk_digest(raw_payload)

    return RiskClassification(
        schema_version=RISK_POLICY_SCHEMA_VERSION,
        risk_level=final_level,
        features=features,
        elevation_reasons=reasons_tuple,
        classification_digest=digest,
        is_authoritative=False,
    )


def verify_risk_classification_integrity(classification: RiskClassification) -> None:
    """Verify cryptographic and deterministic derivation integrity of RiskClassification record.

    Raises:
        InvalidRiskInputError: If input is not a RiskClassification.
        RiskTamperingError: If declared digest does not match recomputed SHA-256,
            or if the classification risk level, elevation reasons, or digest
            contradict deterministic derivation from the underlying RiskFeatureSet.
    """
    if not isinstance(classification, RiskClassification):
        raise InvalidRiskInputError(
            f"classification must be RiskClassification, got {type(classification).__name__}"
        )

    # 1. Cryptographic self-consistency check
    recomputed = compute_risk_digest(classification.to_dict())
    if classification.classification_digest != recomputed:
        dec = classification.classification_digest
        raise RiskTamperingError(
            f"Risk classification digest mismatch: declared {dec}, recomputed {recomputed}"
        )

    # 2. Independent derivation check from validated feature set
    expected = classify_risk(classification.features)
    if classification.risk_level != expected.risk_level:
        raise RiskTamperingError(
            f"Risk level {classification.risk_level.value} contradicts deterministic derivation "
            f"{expected.risk_level.value} from features"
        )
    if classification.elevation_reasons != expected.elevation_reasons:
        raise RiskTamperingError(
            "Elevation reasons contradict deterministic derivation from features"
        )
    if classification.classification_digest != expected.classification_digest:
        raise RiskTamperingError(
            f"Classification digest {classification.classification_digest} contradicts "
            f"deterministic derivation {expected.classification_digest} from features"
        )
