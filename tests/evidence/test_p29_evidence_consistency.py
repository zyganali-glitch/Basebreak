"""P-29.01 / P-29.02 / P-29.04 Evidence Consistency & Cryptographic Audit Tests.

Enforces deterministic truth across the published verification audit markdown,
the canonical published receipt JSON, the verifier-signed receipt proof, and both
Python and Node.js cryptographic verifiers.
"""

from __future__ import annotations

import json
import re
import shutil
import subprocess
from pathlib import Path

import pytest

from basebreak.causal.public_receipt import (
    PublicVerificationReceipt,
    verify_public_receipt_integrity,
)
from basebreak.deployment.live_bridge import verify_receipt_proof

REPO_ROOT = Path(__file__).resolve().parent.parent.parent
EVIDENCE_DIR = REPO_ROOT / "docs" / "evidence" / "p27_06_live_run_10_evidence_packet"
AUDIT_MD_PATH = EVIDENCE_DIR / "VERIFICATION_AUDIT.md"
RECEIPT_JSON_PATH = EVIDENCE_DIR / "published_receipt.json"
PROOF_JSON_PATH = EVIDENCE_DIR / "receipt_proof.json"


def test_audit_markdown_disallows_historical_inaccuracies() -> None:
    """The published audit markdown must not contain known erroneous claims."""
    assert AUDIT_MD_PATH.is_file(), f"Missing audit file: {AUDIT_MD_PATH}"
    content = AUDIT_MD_PATH.read_text(encoding="utf-8")

    # Inaccuracy 1: Wrong candidate tree digest
    assert "8931eb6" not in content, (
        "VERIFICATION_AUDIT.md contains obsolete/wrong candidate tree digest '8931eb6...'. "
        "The authentic receipt binds '6c4f46cbb51119d8e93534a1e2ee922498ee450b'."
    )

    # Inaccuracy 2: Erroneous '5/5 tests' claim
    assert "5/5 tests" not in content, (
        "VERIFICATION_AUDIT.md incorrectly claims '5/5 tests passed'. "
        "The historical run executed one sealed witness test (1 passed in 0.04s)."
    )

    # Inaccuracy 3: Misrepresenting custom raw RSA as standard PKCS#1 v1.5
    # Must not claim the signature algorithm IS PKCS#1 v1.5
    assert not re.search(r"Signature Algorithm\*?:\s*RSA PKCS#1 v1\.5", content, re.IGNORECASE), (
        "VERIFICATION_AUDIT.md misrepresents the signature algorithm as standard RSA PKCS#1 v1.5. "
        "The verifier runtime actually uses raw modular-exponent RSA without PKCS#1 padding."
    )


def test_audit_markdown_and_json_exact_binding() -> None:
    """Values stated in VERIFICATION_AUDIT.md must exactly match the JSON artifacts."""
    content = AUDIT_MD_PATH.read_text(encoding="utf-8")
    with open(RECEIPT_JSON_PATH, "r", encoding="utf-8") as f:
        receipt_data = json.load(f)
    with open(PROOF_JSON_PATH, "r", encoding="utf-8") as f:
        proof_data = json.load(f)

    # Candidate tree digest
    expected_tree = "6c4f46cbb51119d8e93534a1e2ee922498ee450b"
    assert expected_tree in content
    assert receipt_data["candidate_tree_digest"] == expected_tree
    assert proof_data["candidate_tree_digest"] == expected_tree

    # Candidate patch digest
    expected_patch = "5f3ac8d9dcef8b046c58f58f3d2c44a340b13191235637169b781cf54abe592e"
    assert expected_patch in content
    assert receipt_data["candidate_patch_digest"] == expected_patch
    assert proof_data["candidate_patch_digest"] == expected_patch

    # Source commit ID
    expected_source = "80b43b84014fa61b941c7ebcd87836a56dcd7c92"
    assert expected_source in content
    assert receipt_data["source_commit_id"] == expected_source
    assert proof_data["source_commit_id"] == expected_source

    # Run ID
    expected_run_id = "run_78fd00b7-4afa-4703-bce0-9998d6e6c7d9"
    assert expected_run_id in content

    # Receipt digest
    expected_rcpt_digest = "a7857896f3f701264bed995f3b0a70115a9ab007a84d5deece3ae8bcef876500"
    assert expected_rcpt_digest in content
    assert receipt_data["receipt_digest"] == expected_rcpt_digest
    assert proof_data["receipt_digest"] == expected_rcpt_digest

    # Proof digest
    expected_proof_digest = "e738d961e200f1df07af046d6a0adc56b7284b13b469249359ae0120e9a6cd2a"
    assert expected_proof_digest in content
    assert proof_data["proof_digest"] == expected_proof_digest

    # Verdict and Provenance
    assert "VERIFIED" in content
    assert receipt_data["overall_verdict"] == "VERIFIED"
    assert proof_data["overall_verdict"] == "VERIFIED"
    assert receipt_data["provenance"] == "LIVE_NEBIUS"
    assert proof_data["provenance"] == "LIVE_NEBIUS"


def test_three_world_outcomes_consistency() -> None:
    """The three-world execution facts must reflect the causal invariant.

    Invariant: BASE=FAIL, CANDIDATE=PASS, COUNTERFACTUAL=FAIL.
    """
    with open(RECEIPT_JSON_PATH, "r", encoding="utf-8") as f:
        receipt_data = json.load(f)
    with open(PROOF_JSON_PATH, "r", encoding="utf-8") as f:
        proof_data = json.load(f)

    # Proof execution checks
    base_exec = proof_data["base_execution"]
    cand_exec = proof_data["candidate_execution"]
    cf_exec = proof_data["counterfactual_execution"]

    assert base_exec["outcome"] == "FAIL"
    assert base_exec["exit_code"] == 1
    assert cand_exec["outcome"] == "PASS"
    assert cand_exec["exit_code"] == 0
    assert cf_exec["outcome"] == "FAIL"
    assert cf_exec["exit_code"] == 1

    # Counterfactual tree reverts exactly to base tree
    assert base_exec["tree_digest"] == cf_exec["tree_digest"]
    assert cand_exec["tree_digest"] != base_exec["tree_digest"]
    assert cand_exec["tree_digest"] == "6c4f46cbb51119d8e93534a1e2ee922498ee450b"

    # Receipt coverage summary must show 1 witness and 1 requirement
    cov = receipt_data["coverage_summary"]
    assert cov["total_requirements"] == 1
    assert cov["verified_count"] == 1
    assert cov["is_fully_verified"] is True
    assert len(receipt_data["witnesses"]) == 1
    assert receipt_data["witnesses"][0]["witness_id"] == "wit-reset-vault-live-001"


def test_python_cryptographic_verification() -> None:
    """Independent Python verification of the published receipt and RSA proof."""
    with open(RECEIPT_JSON_PATH, "r", encoding="utf-8") as f:
        receipt_data = json.load(f)
    with open(PROOF_JSON_PATH, "r", encoding="utf-8") as f:
        proof_data = json.load(f)

    rcpt = PublicVerificationReceipt.from_dict(receipt_data)
    verify_public_receipt_integrity(rcpt)
    assert verify_receipt_proof(rcpt, proof_data) is True


def test_node_cryptographic_verification() -> None:
    """Independent Node.js verification using Cloudflare Worker cryptographic routines."""
    node_exe = shutil.which("node")
    if not node_exe:
        pytest.skip("Node.js runtime not found on PATH.")

    node_script = """
    const fs = require('fs');
    const { computeReceiptDigest } = require('./cloudflare/src/crypto_utils');
    const { verifyBridgeReceiptProof } = require('./cloudflare/src/provider_dispatcher');

    const rcptPath = 'docs/evidence/p27_06_live_run_10_evidence_packet/published_receipt.json';
    const receipt = JSON.parse(fs.readFileSync(rcptPath, 'utf8'));
    const computedDigest = computeReceiptDigest(receipt);
    if (computedDigest !== receipt.receipt_digest) {
        throw new Error('Receipt digest mismatch: ' + computedDigest);
    }

    const proofPath = 'docs/evidence/p27_06_live_run_10_evidence_packet/receipt_proof.json';
    const proof = JSON.parse(fs.readFileSync(proofPath, 'utf8'));
    verifyBridgeReceiptProof({
        receipt,
        proof,
        expectedSourceCommitId: receipt.source_commit_id,
        expectedProvenance: 'LIVE_NEBIUS',
    });
    console.log('NODE_VERIFICATION_SUCCESS');
    """

    res = subprocess.run(
        [node_exe, "-e", node_script],
        cwd=REPO_ROOT,
        capture_output=True,
        text=True,
    )
    assert res.returncode == 0, (
        f"Node verification failed:\nSTDOUT: {res.stdout}\nSTDERR: {res.stderr}"
    )
    assert "NODE_VERIFICATION_SUCCESS" in res.stdout
