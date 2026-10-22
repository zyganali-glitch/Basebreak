"""Generate a Python-built public receipt fixture for cross-language digest tests.

P-27.06 eighth-run repair evidence generator (LOCAL_EXECUTION / FIXTURE):
builds a receipt exactly like the trusted bridge does — including integral-valued
floats, deliberately UNSORTED list fields, and a non-ASCII rationale character —
serializes it to JSON, and writes the wire JSON for the Node regression test that
verifies the ECMAScript canonicalization reproduces the identical digest.
"""

from __future__ import annotations

import dataclasses
import json
import sys
from pathlib import Path

REPO = Path(__file__).resolve().parents[3]
sys.path.insert(0, str(REPO / "src"))

from basebreak.causal.coverage import (  # noqa: E402
    CausalCoverageSummary,
    RequirementCausalState,
    RequirementEligibility,
    RequirementVerificationFact,
    compute_coverage_digest,
    compute_fact_digest,
)
from basebreak.causal.public_receipt import (  # noqa: E402
    PublicCounterfactualFact,
    PublicExecutionFact,
    PublicVerificationReceipt,
    PublicWitnessFact,
    create_public_verification_receipt,
)
from basebreak.causal.reconciliation import CausalTransition  # noqa: E402
from basebreak.domain.causal import ExecutionWorld  # noqa: E402
from basebreak.domain.execution import TerminationStatus  # noqa: E402
from basebreak.domain.semantics import ChangeClass  # noqa: E402
from basebreak.domain.verdict import EvidenceProvenance, PreliminaryVerdict  # noqa: E402
from basebreak.verifier.witness_result import WitnessOutcome  # noqa: E402

SOURCE_COMMIT = "80b43b84014fa61b941c7ebcd87836a56dcd7c92"
CONTRACT_DIGEST = "93eeeb2cc7eb02a988da3c8a8543ad40b4816608c1452d048ff62ee93702f812"
NON_ASCII_NOTE = "Non-ASCII: çğıöşü — must round-trip via \\u escapes."


def _execution(
    world: ExecutionWorld,
    sandbox: str,
    tree: str,
    outcome: WitnessOutcome,
    exit_code: int,
    duration: float,
) -> PublicExecutionFact:
    return PublicExecutionFact(
        world=world,
        sandbox_id=sandbox,
        source_commit_id=SOURCE_COMMIT,
        tree_digest=tree,
        outcome=outcome,
        exit_code=exit_code,
        termination_status=TerminationStatus.COMPLETED,
        duration_seconds=duration,
        stdout_digest="2" * 64,
        stderr_digest="3" * 64,
    )


def main() -> None:
    executions = [
        _execution(ExecutionWorld.BASE, "sbx-fixture-base", "8" * 40, WitnessOutcome.FAIL, 1, 1.5),
        _execution(
            ExecutionWorld.CANDIDATE,
            "sbx-fixture-candidate",
            "7" * 40,
            WitnessOutcome.PASS,
            0,
            2.25,
        ),
    ]
    counterfactual = PublicCounterfactualFact(
        candidate_tree_digest="7" * 40,
        delta_digest="a" * 64,
        is_required=True,
        outcome=WitnessOutcome.FAIL,
        execution_fact=_execution(
            ExecutionWorld.COUNTERFACTUAL, "sbx-fixture-cf", "8" * 40, WitnessOutcome.FAIL, 1, 1.75
        ),
        absence_rationale=None,
    )
    fact = RequirementVerificationFact(
        requirement_id="REQ-RESET-001",
        causal_state=RequirementCausalState.VERIFIED,
        change_class=ChangeClass.BUG_FIX,
        eligibility=RequirementEligibility.ELIGIBLE,
        execution_obligation="FAIL_TO_PASS_WITH_COUNTERFACTUAL",
        preliminary_verdict=PreliminaryVerdict.VERIFIED,
        transition=CausalTransition.CAUSAL_TRIPLET_VERIFIED,
        rationale="BASE failed, CANDIDATE passed, COUNTERFACTUAL failed — çğıöşü.",
        witness_id="wit-fixture-001",
        witness_digest="e" * 64,
        fact_digest="0" * 64,
    )
    fact = dataclasses.replace(
        fact,
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
            rationale="BASE failed, CANDIDATE passed, COUNTERFACTUAL failed — çğıöşü.",
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
        coverage_digest="0" * 64,
    )
    coverage = dataclasses.replace(
        coverage,
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
    witnesses = (
        PublicWitnessFact(
            witness_id="wit-fixture-001",
            witness_digest="e" * 64,
            lock_digest="f" * 64,
            requirement_id="REQ-RESET-001",
            execution_command=("python", "-m", "pytest", "witness.py", "-q"),
            timeout_seconds=30.0,
        ),
    )
    receipt = create_public_verification_receipt(
        frozen_contract_digest=CONTRACT_DIGEST,
        task_id="TASK-RESET-VAULT-001",
        repo_locator="https://github.com/zyganali-glitch/Basebreak.git",
        source_commit_id=SOURCE_COMMIT,
        candidate_tree_digest="7" * 40,
        coverage_summary=coverage,
        executions=executions,
        witnesses=witnesses,
        overall_verdict=PreliminaryVerdict.VERIFIED,
        provenance=EvidenceProvenance.LOCAL_EXECUTION,
        candidate_patch_digest="0" * 64,
        counterfactual=counterfactual,
        runtime_identities=(
            "zzz-identity-last",
            "aaa-identity-first",
            "mmm-identity-middle",
        ),
        timing={"total_duration_seconds": 5.5, "created_at_utc": "2026-10-22T00:00:00+00:00"},
        not_run_obligations=(),
        disclaimers=(
            "Zzz comes last alphabetically.",
            "Aaa comes first alphabetically.",
            NON_ASCII_NOTE,
        ),
    )
    wire = receipt.to_dict()
    # Round-trip through JSON exactly like the HTTP wire transport.
    parsed = json.loads(json.dumps(wire))
    PublicVerificationReceipt.from_dict(parsed)  # must verify under Python too
    out = Path(__file__).with_name("python_public_receipt_fixture.json")
    out.write_text(json.dumps(parsed, indent=2, sort_keys=True), encoding="utf-8")
    print("fixture written:", out)
    print("receipt_digest:", parsed["receipt_digest"])


if __name__ == "__main__":
    main()
