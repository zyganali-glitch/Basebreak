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
    PublicReceiptIntegrityError,
    PublicVerificationReceipt,
    PublicWitnessFact,
    _canonical_receipt_json_bytes,
    _ecmascript_number_bytes,
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


# --- P-27.06 residual-defect repair: cross-language NUMBER canonicalization ------------
#
# Python json.dumps and ECMAScript JSON.stringify serialize the same non-integral
# double differently whenever the shortest round-trip form crosses an exponent
# threshold (Python: adjusted exponent < -4 or >= 16, two-digit exponents like
# "1e-05"; ECMAScript: < -6 or > 21, unpadded exponents like "1e-7"). Receipts
# with small fractional timings (e.g. duration_seconds=0.00001) therefore failed
# Worker verification even after the first canonicalization repair.


@pytest.mark.parametrize(
    ("value", "expected"),
    [
        (0.00001, "0.00001"),
        (0.000001, "0.000001"),
        (1e-07, "1e-7"),
        (1e-08, "1e-8"),
        (5e-324, "5e-324"),
        (2.2250738585072014e-308, "2.2250738585072014e-308"),
        (1.7976931348623157e308, "1.7976931348623157e+308"),
        (0.0001, "0.0001"),
        (0.5, "0.5"),
        (-2.5, "-2.5"),
        (123.456, "123.456"),
        (0.30000000000000004, "0.30000000000000004"),
        (100.0, "100"),
        (0.0, "0"),
        (-0.0, "0"),
        (1e16, "10000000000000000"),
        (1.5e16, "15000000000000000"),
        (1e20, "100000000000000000000"),
        (1e21, "1e+21"),
        (1e22, "1e+22"),
        (-1e-05, "-0.00001"),
        (-1e21, "-1e+21"),
    ],
)
def test_ecmascript_number_bytes_boundaries(value: float, expected: str) -> None:
    assert _ecmascript_number_bytes(value) == expected


def test_canonical_serializer_rejects_unsupported_numbers_fail_closed() -> None:
    for bad_float in (float("nan"), float("inf"), float("-inf")):
        with pytest.raises(PublicReceiptIntegrityError):
            _canonical_receipt_json_bytes(bad_float)
    for bad_int in (2**53, -(2**53), 10**30, -(10**30)):
        with pytest.raises(PublicReceiptIntegrityError):
            _canonical_receipt_json_bytes(bad_int)
    # Safe integers are accepted and serialize as plain decimals.
    assert _canonical_receipt_json_bytes(2**53 - 1) == str(2**53 - 1)
    assert _canonical_receipt_json_bytes(0) == "0"


def test_canonical_serializer_rejects_unsupported_keys_and_types_fail_closed() -> None:
    with pytest.raises(PublicReceiptIntegrityError):
        _canonical_receipt_json_bytes({"ç": 1})
    with pytest.raises(PublicReceiptIntegrityError):
        _canonical_receipt_json_bytes({42: 1})
    with pytest.raises(PublicReceiptIntegrityError):
        _canonical_receipt_json_bytes(b"bytes")
    # ASCII keys serialize exactly like json.dumps (ensure_ascii parity).
    assert _canonical_receipt_json_bytes({"a": 1, "b": "x"}) == '{"a":1,"b":"x"}'
    assert _canonical_receipt_json_bytes({"s": "ç"}) == '{"s":"\\u00e7"}'


def test_wire_digest_uses_ecmascript_bytes_for_small_fractional_floats() -> None:
    fixtures = REPO_ROOT / "cloudflare" / "test" / "fixtures"
    receipt_dict = json.loads(
        (fixtures / "python_public_receipt_fixture_small_floats.json").read_text(encoding="utf-8")
    )
    payload = {k: v for k, v in receipt_dict.items() if k != "receipt_digest"}
    # The wire text itself carries Python-style exponent notation...
    assert "e-05" in json.dumps(payload)
    # ...but the DIGEST bytes must use the ECMAScript form.
    digest_text = _canonical_receipt_json_bytes(payload)
    assert '"coverage_percentage":33.333333333333336' in digest_text
    assert '"coverage_ratio":0.3333333333333333' in digest_text
    assert '"duration_seconds":0.00001' in digest_text
    assert '"total_duration_seconds":0.0000425' in digest_text
    assert compute_public_receipt_digest(payload) == receipt_dict["receipt_digest"]


def test_committed_fixture_digests_are_stable() -> None:
    """Backward compatibility: the first canonicalization repair's committed
    fixture digest is unchanged by the number-canonicalization repair, and the
    small-floats fixture (the residual-defect evidence) verifies."""
    fixtures = REPO_ROOT / "cloudflare" / "test" / "fixtures"
    original = json.loads(
        (fixtures / "python_public_receipt_fixture.json").read_text(encoding="utf-8")
    )
    assert original["receipt_digest"] == (
        "458d1fd5d79ef08836b15237c55f95b9ba51f6aa645189da30ccabbb09e0de60"
    )
    small = json.loads(
        (fixtures / "python_public_receipt_fixture_small_floats.json").read_text(encoding="utf-8")
    )
    assert small["receipt_digest"] == (
        "f0d751974b2a197774ac28f5f166b037aba7c2b112438618637bfb6b0452629b"
    )
    # Both committed fixtures re-verify under the current Python rules.
    PublicVerificationReceipt.from_dict(original)
    PublicVerificationReceipt.from_dict(small)
    # The small-floats fixture genuinely contains sub-1e-4 fractional values
    # whose Python json.dumps form uses exponent notation.
    durations = [e["duration_seconds"] for e in small["executions"]]
    assert any(d < 1e-4 for d in durations)
    assert "e-05" in json.dumps(small["timing"])


_NODE_FUZZ_SCRIPT = """
import fs from "node:fs";
const values = JSON.parse(fs.readFileSync(process.argv[2], "utf8"));
const out = [];
for (const v of values) {
  out.push(JSON.stringify(JSON.parse(v)));
}
process.stdout.write(JSON.stringify(out));
"""


def test_cross_language_number_fuzz_agreement(tmp_path: Path) -> None:
    """Random doubles (fixed seed) + boundaries: Python's ECMAScript formatter
    must agree with a real Node process on every serialized number."""
    node = shutil.which("node")
    if node is None:
        pytest.skip("node is not available in this environment")
    import math
    import random
    import struct

    rng = random.Random(20261022)

    def _random_finite_double() -> float:
        while True:
            bits = rng.getrandbits(64)
            value = float(struct.unpack("<d", struct.pack("<Q", bits))[0])
            if math.isfinite(value):
                return value

    values = [
        0.00001,
        0.0000125,
        0.00002,
        0.0000425,
        1e-07,
        5e-324,
        1e16,
        1.5e16,
        1e21,
        1e22,
        1.7976931348623157e308,
        0.5,
        -2.5,
        123.456,
        1 / 3,
        100 / 3,
        0.30000000000000004,
    ] + [_random_finite_double() for _ in range(300)]
    literals = [repr(v) for v in values]
    values_file = tmp_path / "values.json"
    values_file.write_text(json.dumps(literals), encoding="utf-8")
    script_file = tmp_path / "fuzz.mjs"
    script_file.write_text(_NODE_FUZZ_SCRIPT, encoding="utf-8")
    result = subprocess.run(
        [node, str(script_file), str(values_file)],
        capture_output=True,
        text=True,
        timeout=120,
        cwd=str(REPO_ROOT),
    )
    assert result.returncode == 0, result.stderr
    js_bytes = json.loads(result.stdout)
    mismatches = [
        (lit, _ecmascript_number_bytes(val), js)
        for lit, val, js in zip(literals, values, js_bytes)
        if _ecmascript_number_bytes(val) != js
    ]
    assert not mismatches, mismatches[:10]


def test_small_fractional_receipt_verifies_cross_language(tmp_path: Path) -> None:
    """A genuine Python receipt with sub-1e-4 fractional timings verifies under
    the production Node verifier (the residual defect's CANDIDATE=PASS proof)."""
    node = shutil.which("node")
    if node is None:
        pytest.skip("node is not available in this environment")
    fixtures = REPO_ROOT / "cloudflare" / "test" / "fixtures"
    receipt = json.loads(
        (fixtures / "python_public_receipt_fixture_small_floats.json").read_text(encoding="utf-8")
    )
    wire_file = tmp_path / "receipt.json"
    wire_file.write_text(json.dumps(receipt), encoding="utf-8")
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
    assert payload["verified"] is True
    assert payload["recomputed"] == receipt["receipt_digest"]
