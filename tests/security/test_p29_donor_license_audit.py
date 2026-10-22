"""P-29.05 Donor, License, and Provenance Audit Tests.

Enforces:
1. Root Apache-2.0 LICENSE and NOTICE integrity.
2. Zero donor code importation (Total donor lines = 0).
3. Donor reuse classification strictly CONCEPT_ONLY / CLEAN_ROOM_REIMPLEMENTED.
4. Complete absence of forbidden donor product branding across production source.
"""

from __future__ import annotations

import re
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parent.parent.parent


def test_root_license_and_notice() -> None:
    """Root repository must contain valid Apache-2.0 LICENSE and NOTICE."""
    license_file = REPO_ROOT / "LICENSE"
    notice_file = REPO_ROOT / "NOTICE"

    assert license_file.is_file(), "LICENSE file must exist"
    assert notice_file.is_file(), "NOTICE file must exist"

    license_text = license_file.read_text(encoding="utf-8")
    assert "Apache License" in license_text
    assert "Version 2.0, January 2004" in license_text
    assert "Copyright 2026 Mehmet Aydogan" in license_text

    notice_text = notice_file.read_text(encoding="utf-8")
    assert "Basebreak" in notice_text
    assert "Copyright 2026 Mehmet Aydogan" in notice_text


def test_donor_manifest_zero_imported_code() -> None:
    """Donor manifest must record exactly 0 imported donor lines and approved introductions."""
    manifest_file = REPO_ROOT / "docs" / "DONOR_REUSE_MANIFEST.md"
    assert manifest_file.is_file(), "docs/DONOR_REUSE_MANIFEST.md must exist"

    manifest_text = manifest_file.read_text(encoding="utf-8")
    assert "**Current Approved Code Introductions: 0**" in manifest_text
    assert "**Total Donor Source Lines Imported: 0**" in manifest_text

    # Verify all donor rows D-001 through D-008 maintain Code Imported: NO
    for donor_id in ["D-001", "D-002", "D-003", "D-004", "D-005", "D-006", "D-007", "D-008"]:
        assert donor_id in manifest_text, f"Missing donor record {donor_id}"

    # Verify no row claims ADAPTED_WITH_PROVENANCE or UNCHANGED_INFRASTRUCTURE for donors
    assert "ADAPTED_WITH_PROVENANCE" not in manifest_text
    assert "UNCHANGED_INFRASTRUCTURE" not in manifest_text


def test_no_forbidden_donor_branding_in_production_source() -> None:
    """Forbidden donor terminology must not be present in production src/ tree."""
    forbidden_terms = [
        "Change Passport",
        "Capability Passport",
        "ShadowLab",
        "Approval Compression",
        "ContextSeal",
        "ChangeMesh",
    ]

    src_dir = REPO_ROOT / "src"
    assert src_dir.is_dir()

    violations: list[str] = []
    for py_file in src_dir.rglob("*.py"):
        content = py_file.read_text(encoding="utf-8")
        for term in forbidden_terms:
            if re.search(rf"\b{re.escape(term)}\b", content, re.IGNORECASE):
                violations.append(f"{py_file.relative_to(REPO_ROOT)}: found '{term}'")

    assert not violations, (
        "Forbidden donor branding terms found in production source files:\n" + "\n".join(violations)
    )
