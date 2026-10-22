"""P-27.06 cross-language receipt wire canonicalization regression tests.

Eighth-live-run repair (2026-10-22, run_d82ee30a): the deployed Worker rejected a
genuine COMPLETED LIVE_NEBIUS bridge receipt with "Receipt digest verification
failed" because the wire receipt (``to_dict``) preserved insertion-ordered lists
and integral-valued floats (``0.0``, ``30.0``) while the digest was computed over
``build_canonical_public_receipt_payload`` (sorted lists) — and ECMAScript
``JSON.parse`` cannot distinguish ``0.0`` from ``0`` at all.

Repair invariants proven here (all LOCAL_EXECUTION / FIXTURE):

1. the wire dictionary (minus ``receipt_digest``) IS the canonical digest payload;
2. canonical payload bytes never contain integral-valued floats (portable numbers);
3. list fields are emitted sorted on the wire;
4. create -> to_json -> parse -> from_dict round-trips with integrity verification;
5. a genuine Python receipt verifies under the ECMAScript canonicalization
   (executed via ``node`` against ``cloudflare/src/crypto_utils.js``; skipped
   when ``node`` is unavailable).
"""

from __future__ import annotations

import json
import shutil
import subprocess
from pathlib import Path
from typing import Any

import pytest

from basebreak.causal.coverage import (
    CausalCoverageSummary,
    RequirementCausalState,
    RequirementEligibility,
    RequirementVerificationFact,
    compute_coverage_digest,
    compute_fact_digest,
)
from basebreak.causal.public_receipt import (
    PublicCounterfactualFact,
    PublicExecutionFact,
    PublicVerificationReceipt,
    PublicWitnessFact,
    build_canonical_public_receipt_payload,
    compute_public_receipt_digest,
    create_public_verification_receipt,
)
from basebreak.causal.reconciliation import CausalTransition
from basebreak.domain.causal import ExecutionWorld
from basebreak.domain.execution import TerminationStatus
from basebreak.domain.semantics import ChangeClass
from basebreak.domain.verdict import EvidenceProvenance, PreliminaryVerdict
from basebreak.verifier.witness_result import WitnessOutcome

REPO_ROOT = Path(__file__).resolve().parents[2]
SOURCE_COMMIT = "80b43b84014fa61b941c7ebcd87836a56dcd7c92"
CONTRACT_DIGEST = "93eeeb2cc7eb02a988da3c8a8543ad40b4816608c1452d048ff62ee93702f812"


def _execution(
    world: ExecutionWorld, sandbox: str, outcome: WitnessOutcome, exit_code: int
) -> PublicExecutionFact:
    return PublicExecutionFact(
        world=world,
        sandbox_id=sandbox,
        source_commit_id=SOURCE_COMMIT,
        tree_digest="7" * 40,
        outcome=outcome,
        exit_code=exit_code,
        termination_status=TerminationStatus.COMPLETED,
        duration_seconds=1.5,
        stdout_digest="2" * 64,
        stderr_digest="3" * 64,
    )


def _build_receipt() -> PublicVerificationReceipt:
    rationale = "BASE failed, CANDIDATE passed, COUNTERFACTUAL failed — çğıöşü."
    fact = RequirementVerificationFact(
        requirement_id="REQ-RESET-001",
        causal_state=RequirementCausalState.VERIFIED,
        change_class=ChangeClass.BUG_FIX,
        eligibility=RequirementEligibility.ELIGIBLE,
        execution_obligation="FAIL_TO_PASS_WITH_COUNTERFACTUAL",
        preliminary_verdict=PreliminaryVerdict.VERIFIED,
        transition=CausalTransition.CAUSAL_TRIPLET_VERIFIED,
        rationale=rationale,
        witness_id="wit-fixture-001",
        witness_digest="e" * 64,
        fact_digest=compute_fact_digest(
            requirement_id="REQ-RESET-001",
            change_class=ChangeClass.BUG_FIX,
            eligibility=RequirementEligibility.ELIGIBLE,
            causal_state=RequirementCausalState.VERIFIED,
            preliminary_verdict=PreliminaryVerdict.VERIFIED,
            transition=CausalTransition.CAUSAL_TRIPLET_VERIFIED,
            witness_id="wit-fixture-001",
            witness_digest="e" * 64,
            execution_obligation="FAIL_TO_PASS_WITH_COUNTERFACTUAL",
            rationale=rationale,
        ),
    )
    coverage = CausalCoverageSummary(
        contract_digest=CONTRACT_DIGEST,
        total_requirements=1,
        eligible_count=1,
        excluded_count=0,
        verified_count=1,
        not_run_count=0,
        inconclusive_count=0,
        contradicted_count=0,
        blocked_count=0,
        coverage_ratio=1.0,
        coverage_percentage=100.0,
        is_fully_verified=True,
        overall_verdict=PreliminaryVerdict.VERIFIED,
        per_requirement_facts=(fact,),
        coverage_digest=compute_coverage_digest(
            contract_digest=CONTRACT_DIGEST,
            total_requirements=1,
            eligible_count=1,
            excluded_count=0,
            verified_count=1,
            not_run_count=0,
            inconclusive_count=0,
            contradicted_count=0,
            blocked_count=0,
            coverage_ratio=1.0,
            coverage_percentage=100.0,
            is_fully_verified=True,
            overall_verdict=PreliminaryVerdict.VERIFIED,
            per_requirement_facts=(fact,),
        ),
    )
    counterfactual = PublicCounterfactualFact(
        candidate_tree_digest="7" * 40,
        delta_digest="a" * 64,
        is_required=True,
        outcome=WitnessOutcome.FAIL,
        execution_fact=_execution(
            ExecutionWorld.COUNTERFACTUAL, "sbx-fx-cf", WitnessOutcome.FAIL, 1
        ),
        absence_rationale=None,
    )
    return create_public_verification_receipt(
        frozen_contract_digest=CONTRACT_DIGEST,
        task_id="TASK-RESET-VAULT-001",
        repo_locator="https://github.com/zyganali-glitch/Basebreak.git",
        source_commit_id=SOURCE_COMMIT,
        candidate_tree_digest="7" * 40,
        coverage_summary=coverage,
        executions=(
            _execution(ExecutionWorld.BASE, "sbx-fx-base", WitnessOutcome.FAIL, 1),
            _execution(ExecutionWorld.CANDIDATE, "sbx-fx-cand", WitnessOutcome.PASS, 0),
        ),
        witnesses=(
            PublicWitnessFact(
                witness_id="wit-fixture-001",
                witness_digest="e" * 64,
                lock_digest="f" * 64,
                requirement_id="REQ-RESET-001",
                execution_command=("python", "-m", "pytest", "witness.py", "-q"),
                timeout_seconds=30.0,
            ),
        ),
        overall_verdict=PreliminaryVerdict.VERIFIED,
        provenance=EvidenceProvenance.LOCAL_EXECUTION,
        candidate_patch_digest="0" * 64,
        counterfactual=counterfactual,
        runtime_identities=(
            "zzz-identity-last",
            "aaa-identity-first",
            "mmm-identity-middle",
        ),
        timing={"total_duration_seconds": 3.0, "created_at_utc": "2026-10-22T00:00:00+00:00"},
        not_run_obligations=("zzz-obligation", "aaa-obligation"),
        disclaimers=(
            "Zzz comes last alphabetically.",
            "Aaa comes first alphabetically.",
            "Non-ASCII: çğıöşü — must round-trip.",
        ),
    )


def _assert_no_integral_floats(value: Any) -> None:
    if isinstance(value, bool) or value is None:
        return
    if isinstance(value, float):
        assert not value.is_integer(), f"integral-valued float in canonical payload: {value!r}"
        return
    if isinstance(value, dict):
        for v in value.values():
            _assert_no_integral_floats(v)
        return
    if isinstance(value, (list, tuple)):
        for v in value:
            _assert_no_integral_floats(v)


def test_wire_dict_is_exactly_the_canonical_digest_payload() -> None:
    receipt = _build_receipt()
    wire = receipt.to_dict()
    canonical = build_canonical_public_receipt_payload(
        schema_version=receipt.schema_version,
        frozen_contract_digest=receipt.frozen_contract_digest,
        task_id=receipt.task_id,
        repo_locator=receipt.repo_locator,
        source_commit_id=receipt.source_commit_id,
        candidate_tree_digest=receipt.candidate_tree_digest,
        candidate_patch_digest=receipt.candidate_patch_digest,
        counterfactual=receipt.counterfactual,
        coverage_summary=receipt.coverage_summary,
        witnesses=receipt.witnesses,
        executions=receipt.executions,
        overall_verdict=receipt.overall_verdict,
        provenance=receipt.provenance,
        runtime_identities=receipt.runtime_identities,
        timing=receipt.timing,
        accounting=receipt.accounting,
        not_run_obligations=receipt.not_run_obligations,
        signature_strategy=receipt.signature_strategy,
        signature=receipt.signature,
        is_authoritative=receipt.is_authoritative,
        disclaimers=receipt.disclaimers,
    )
    assert {k: v for k, v in wire.items() if k != "receipt_digest"} == canonical


def test_canonical_payload_contains_no_integral_valued_floats() -> None:
    receipt = _build_receipt()
    wire = receipt.to_dict()
    _assert_no_integral_floats(wire)
    canonical_bytes = json.dumps(
        {k: v for k, v in wire.items() if k != "receipt_digest"},
        sort_keys=True,
        separators=(",", ":"),
    )
    # The historical failure shape ("0.0", "30.0") must never appear.
    assert '"coverage_percentage":100' in canonical_bytes
    assert '"coverage_ratio":1,' in canonical_bytes
    assert '"timeout_seconds":30' in canonical_bytes
    assert '"total_duration_seconds":3}' in canonical_bytes
    assert ":0.0" not in canonical_bytes
    assert ":30.0" not in canonical_bytes


def test_wire_list_fields_are_sorted() -> None:
    receipt = _build_receipt()
    wire = receipt.to_dict()
    assert wire["runtime_identities"] == sorted(receipt.runtime_identities)
    assert wire["disclaimers"] == sorted(receipt.disclaimers)
    assert wire["not_run_obligations"] == sorted(receipt.not_run_obligations)


def test_receipt_round_trips_through_json_with_intact_digest() -> None:
    receipt = _build_receipt()
    wire_json = receipt.to_json()
    parsed = json.loads(wire_json)
    assert (
        compute_public_receipt_digest({k: v for k, v in parsed.items() if k != "receipt_digest"})
        == parsed["receipt_digest"]
    )
    restored = PublicVerificationReceipt.from_dict(parsed)
    assert restored.receipt_digest == receipt.receipt_digest
    assert restored.to_dict() == parsed


def test_digest_is_reproducible_from_pure_wire_bytes() -> None:
    """The exact invariant the Cloudflare Worker relies upon."""
    receipt = _build_receipt()
    # Simulate the HTTP wire: serialize, transport as text, re-parse.
    transported = json.loads(json.dumps(receipt.to_dict()))
    recomputed = compute_public_receipt_digest(
        {k: v for k, v in transported.items() if k != "receipt_digest"}
    )
    assert recomputed == transported["receipt_digest"]


_NODE_SCRIPT = """
import fs from "node:fs";
import { computeReceiptDigest, verifyReceiptIntegrity } from "__CRYPTO_UTILS_URL__";
const receipt = JSON.parse(
  fs.readFileSync(process.argv[2], "utf8").replace(/^\\uFEFF/, "")
);
process.stdout.write(
  JSON.stringify({
    recomputed: computeReceiptDigest(receipt),
    declared: receipt.receipt_digest,
    verified: verifyReceiptIntegrity(receipt),
  })
);
"""


def test_ecmascript_canonicalization_reproduces_python_digest(
    tmp_path: Path,
) -> None:
    node = shutil.which("node")
    if node is None:
        pytest.skip("node is not available in this environment")
    receipt = _build_receipt()
    wire_file = tmp_path / "receipt.json"
    wire_file.write_text(json.dumps(receipt.to_dict()), encoding="utf-8")
    script_file = tmp_path / "check.mjs"
    crypto_utils_uri = (REPO_ROOT / "cloudflare" / "src" / "crypto_utils.js").as_uri()
    script_file.write_text(
        _NODE_SCRIPT.replace("__CRYPTO_UTILS_URL__", crypto_utils_uri),
        encoding="utf-8",
    )
    result = subprocess.run(
        [node, str(script_file), str(wire_file)],
        capture_output=True,
        text=True,
        timeout=60,
        cwd=str(REPO_ROOT),
    )
    assert result.returncode == 0, result.stderr
    payload = json.loads(result.stdout)
    assert payload["declared"] == receipt.receipt_digest
    assert payload["recomputed"] == receipt.receipt_digest
    assert payload["verified"] is True
