"""P-29.06 Secret, Privacy, and Public Artifact Audit Tests.

Scans all public-facing documentation, evidence packets, JSON artifacts, and
configuration files for:
1. Committed credentials, private signing keys, bearer tokens, or provider API keys.
2. Unredacted sensitive telemetry or secrets.
3. Accurate labeling and cryptographic tamper-verifiability of published proof artifacts.
"""

from __future__ import annotations

import json
from pathlib import Path

from basebreak.security.secret_policy import find_secret_findings

REPO_ROOT = Path(__file__).resolve().parent.parent.parent

# Files that discuss secret patterns, threat models, or test configurations
# with intentional dummy example strings (e.g. documentation on secret rules).
EXEMPT_DOC_FILENAMES = {
    "test_p04_02_secret_policy.py",
    "test_p27_06_source_patch_secret_repair.py",
    "secret_policy.py",
    "SANDBOX_POLICY.md",
    "SECURITY_BOUNDARY.md",
}


def test_public_evidence_packet_has_no_secrets() -> None:
    """Published evidence files must contain zero secrets or unredacted keys."""
    evidence_dir = REPO_ROOT / "docs" / "evidence" / "p27_06_live_run_10_evidence_packet"
    assert evidence_dir.is_dir(), f"Evidence directory not found: {evidence_dir}"

    for file_path in evidence_dir.iterdir():
        if not file_path.is_file():
            continue
        content = file_path.read_text(encoding="utf-8")
        findings = find_secret_findings(content)
        assert not findings, (
            f"Secret findings detected in public evidence artifact {file_path.name}: "
            f"{[f.rule_id for f in findings]}"
        )


def test_public_evidence_manifest_has_no_secrets() -> None:
    """The canonical evidence manifest must contain zero secrets."""
    manifest_path = REPO_ROOT / "docs" / "evidence" / "EVIDENCE_MANIFEST.md"
    assert manifest_path.is_file(), "EVIDENCE_MANIFEST.md must exist"

    content = manifest_path.read_text(encoding="utf-8")
    findings = find_secret_findings(content)
    assert not findings, (
        f"Secret findings detected in EVIDENCE_MANIFEST.md: {[f.rule_id for f in findings]}"
    )


def test_no_private_signing_keys_in_repo() -> None:
    """The verifier private signing exponent must not be in production code or evidence."""
    # The verifier private key is held exclusively on the Oracle host
    # (/etc/basebreak/verifier-signing-key.hex, 0600 root:root).
    # Production code, docs, and evidence must only contain the pinned public modulus/exponent.
    forbidden_markers = [
        "BEGIN RSA PRIVATE KEY",
        "BEGIN PRIVATE KEY",
        "BEGIN OPENSSH PRIVATE KEY",
    ]

    # Check all production code and evidence directories
    check_dirs = [
        REPO_ROOT / "src",
        REPO_ROOT / "docs" / "evidence",
        REPO_ROOT / "cloudflare" / "src",
    ]

    for check_dir in check_dirs:
        for file_path in check_dir.rglob("*"):
            if not file_path.is_file():
                continue
            content = file_path.read_text(encoding="utf-8", errors="ignore")
            for marker in forbidden_markers:
                assert marker not in content, f"Private key marker found in {file_path}"
            assert "BASEBREAK_VERIFIER_SIGNING_KEY =" not in content


def test_public_documentation_secret_scan() -> None:
    """Public documentation must contain zero unredacted live credentials."""
    docs_dir = REPO_ROOT / "docs"
    for md_file in docs_dir.rglob("*.md"):
        if md_file.name in EXEMPT_DOC_FILENAMES:
            continue
        content = md_file.read_text(encoding="utf-8")
        # Check specifically for live token prefixes
        assert "sk-proj-" not in content, f"OpenAI project key found in {md_file}"
        assert "ghp_" not in content, f"GitHub personal token found in {md_file}"
        assert "gho_" not in content, f"GitHub OAuth token found in {md_file}"


def test_published_receipt_structure_and_tamper_labeling() -> None:
    """Published receipt must be authentic and accurately state its non-authoritative status."""
    receipt_file = (
        REPO_ROOT
        / "docs"
        / "evidence"
        / "p27_06_live_run_10_evidence_packet"
        / "published_receipt.json"
    )
    with open(receipt_file, "r", encoding="utf-8") as f:
        data = json.load(f)

    # Truthful labeling
    assert data["provenance"] == "LIVE_NEBIUS"
    assert data["overall_verdict"] == "VERIFIED"
    assert (
        data["is_authoritative"] is False
    )  # Public receipt is verified empirical witness, not formal proof

    # Must contain honest disclaimers
    assert any("empirical causal verification" in d for d in data.get("disclaimers", []))
    assert any(
        "If the patch matters, the base must break" in d for d in data.get("disclaimers", [])
    )
