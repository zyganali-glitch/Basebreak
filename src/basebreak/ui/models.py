"""Data models for Judge & Operator UI (P-22).

Extracts and normalizes facts from PublicVerificationReceipt, run metadata,
and events into a structured, tamper-evident view model for presentation.
"""

from __future__ import annotations

import json
from dataclasses import dataclass
from typing import Any

from basebreak.causal.coverage import (
    CausalCoverageSummary,
    RequirementCausalState,
    RequirementEligibility,
    RequirementVerificationFact,
)
from basebreak.causal.public_receipt import (
    PublicCostAccountingFact,
    PublicCounterfactualFact,
    PublicExecutionFact,
    PublicVerificationReceipt,
    PublicWitnessFact,
    verify_public_receipt_integrity,
)
from basebreak.causal.reconciliation import CausalTransition
from basebreak.domain.causal import ExecutionWorld
from basebreak.domain.execution import TerminationStatus
from basebreak.domain.semantics import ChangeClass
from basebreak.domain.verdict import EvidenceProvenance, PreliminaryVerdict
from basebreak.verifier.witness_result import WitnessOutcome


@dataclass(frozen=True)
class TimelineStep:
    """Factual execution stage in the Basebreak lifecycle."""

    name: str
    stage_id: str
    status: str  # COMPLETED, RUNNING, BLOCKED, NOT_RUN, SKIPPED, TAMPERED
    details: str
    duration_seconds: float | None = None
    is_live_action: bool = False


@dataclass(frozen=True)
class RequirementRow:
    """Requirement-witness-slice mapping row for the judge table."""

    requirement_id: str
    semantic_class: str
    description: str
    outcome: str
    witness_id: str
    witness_digest: str
    slice_status: str
    slice_detail: str


@dataclass(frozen=True)
class JudgeViewData:
    """Consolidated deterministic view model for Judge UI."""

    thesis: str
    run_id: str
    verdict: str
    verdict_badge_class: str
    provenance: str
    provenance_badge_class: str
    provenance_description: str
    is_authoritative: bool
    created_at_utc: str
    duration_seconds: float | None
    causal_transition: str
    base_world: dict[str, Any]
    candidate_world: dict[str, Any]
    counterfactual_world: dict[str, Any]
    timeline_steps: list[TimelineStep]
    requirements: list[RequirementRow]
    receipt_digest: str
    receipt_verified: bool
    source_commit_sha: str
    candidate_tree_digest: str
    candidate_patch_digest: str
    not_run_obligations: list[str]
    cost_accounting: dict[str, Any]
    disclaimer: str = (
        "Basebreak produces empirical causal evidence under sealed behavioral witnesses. "
        "It does not constitute a mathematical or formal proof of universal program correctness."
    )
    raw_receipt_json: str = ""


def _parse_receipt_unvalidated(data: dict[str, Any]) -> PublicVerificationReceipt:
    """Construct PublicVerificationReceipt without mandatory integrity verification."""
    executions = []
    for ex_raw in data.get("executions", ()):
        executions.append(
            PublicExecutionFact(
                world=ExecutionWorld(ex_raw["world"]),
                sandbox_id=ex_raw["sandbox_id"],
                source_commit_id=ex_raw["source_commit_id"],
                tree_digest=ex_raw["tree_digest"],
                outcome=WitnessOutcome(ex_raw["outcome"]),
                exit_code=ex_raw.get("exit_code"),
                termination_status=TerminationStatus(ex_raw["termination_status"]),
                stdout_digest=ex_raw["stdout_digest"],
                stderr_digest=ex_raw["stderr_digest"],
                duration_seconds=float(ex_raw["duration_seconds"]),
                stdout_excerpt=ex_raw.get("stdout_excerpt"),
                stderr_excerpt=ex_raw.get("stderr_excerpt"),
            )
        )

    witnesses = []
    for w_raw in data.get("witnesses", ()):
        witnesses.append(
            PublicWitnessFact(
                witness_id=w_raw["witness_id"],
                witness_digest=w_raw["witness_digest"],
                lock_digest=w_raw.get("lock_digest"),
                requirement_id=w_raw.get("requirement_id"),
                execution_command=tuple(w_raw.get("execution_command", ())),
                timeout_seconds=float(w_raw.get("timeout_seconds", 30.0)),
            )
        )

    cf_fact = None
    cf_raw = data.get("counterfactual")
    if cf_raw is not None:
        cf_exec_fact = None
        if cf_raw.get("execution_fact") is not None:
            ex_data = cf_raw["execution_fact"]
            cf_exec_fact = PublicExecutionFact(
                world=ExecutionWorld(ex_data["world"]),
                sandbox_id=ex_data["sandbox_id"],
                source_commit_id=ex_data["source_commit_id"],
                tree_digest=ex_data["tree_digest"],
                outcome=WitnessOutcome(ex_data["outcome"]),
                exit_code=ex_data.get("exit_code"),
                termination_status=TerminationStatus(ex_data["termination_status"]),
                stdout_digest=ex_data["stdout_digest"],
                stderr_digest=ex_data["stderr_digest"],
                duration_seconds=float(ex_data["duration_seconds"]),
                stdout_excerpt=ex_data.get("stdout_excerpt"),
                stderr_excerpt=ex_data.get("stderr_excerpt"),
            )
        cf_fact = PublicCounterfactualFact(
            is_required=bool(cf_raw["is_required"]),
            candidate_tree_digest=cf_raw.get("candidate_tree_digest"),
            delta_digest=cf_raw.get("delta_digest"),
            outcome=WitnessOutcome(cf_raw["outcome"]) if cf_raw.get("outcome") else None,
            execution_fact=cf_exec_fact,
            absence_rationale=cf_raw.get("absence_rationale"),
        )

    ac_fact = None
    ac_raw = data.get("accounting")
    if ac_raw is not None:
        ac_fact = PublicCostAccountingFact(
            model_call_count=int(ac_raw.get("model_call_count", 0)),
            prompt_tokens=int(ac_raw.get("prompt_tokens", 0)),
            completion_tokens=int(ac_raw.get("completion_tokens", 0)),
            sandbox_runtime_seconds=float(ac_raw.get("sandbox_runtime_seconds", 0.0)),
            estimated_cost_usd=(
                float(ac_raw["estimated_cost_usd"])
                if ac_raw.get("estimated_cost_usd") is not None
                else None
            ),
            currency=str(ac_raw.get("currency", "USD")),
            is_metered=bool(ac_raw.get("is_metered", False)),
        )

    cov_raw = data["coverage_summary"]
    req_facts = []
    for rf_raw in cov_raw.get("per_requirement_facts", ()):
        req_facts.append(
            RequirementVerificationFact(
                requirement_id=rf_raw["requirement_id"],
                change_class=ChangeClass(rf_raw["change_class"]),
                eligibility=RequirementEligibility(rf_raw["eligibility"]),
                causal_state=RequirementCausalState(rf_raw["causal_state"]),
                preliminary_verdict=PreliminaryVerdict(rf_raw["preliminary_verdict"]),
                transition=(
                    CausalTransition(rf_raw["transition"]) if rf_raw.get("transition") else None
                ),
                witness_id=rf_raw.get("witness_id"),
                witness_digest=rf_raw.get("witness_digest"),
                execution_obligation=rf_raw["execution_obligation"],
                rationale=rf_raw["rationale"],
                fact_digest=rf_raw["fact_digest"],
            )
        )

    cov_summary = CausalCoverageSummary(
        contract_digest=cov_raw["contract_digest"],
        total_requirements=int(cov_raw["total_requirements"]),
        eligible_count=int(cov_raw["eligible_count"]),
        excluded_count=int(cov_raw["excluded_count"]),
        verified_count=int(cov_raw["verified_count"]),
        not_run_count=int(cov_raw["not_run_count"]),
        inconclusive_count=int(cov_raw["inconclusive_count"]),
        contradicted_count=int(cov_raw["contradicted_count"]),
        blocked_count=int(cov_raw["blocked_count"]),
        coverage_ratio=(
            float(cov_raw["coverage_ratio"]) if cov_raw.get("coverage_ratio") is not None else None
        ),
        coverage_percentage=(
            float(cov_raw["coverage_percentage"])
            if cov_raw.get("coverage_percentage") is not None
            else None
        ),
        is_fully_verified=bool(cov_raw["is_fully_verified"]),
        overall_verdict=PreliminaryVerdict(cov_raw["overall_verdict"]),
        per_requirement_facts=tuple(req_facts),
        coverage_digest=cov_raw["coverage_digest"],
    )

    return PublicVerificationReceipt(
        schema_version=data["schema_version"],
        receipt_digest=data["receipt_digest"],
        frozen_contract_digest=data["frozen_contract_digest"],
        task_id=data["task_id"],
        repo_locator=data["repo_locator"],
        source_commit_id=data["source_commit_id"],
        candidate_tree_digest=data["candidate_tree_digest"],
        candidate_patch_digest=data.get("candidate_patch_digest"),
        counterfactual=cf_fact,
        coverage_summary=cov_summary,
        witnesses=tuple(witnesses),
        executions=tuple(executions),
        overall_verdict=PreliminaryVerdict(data["overall_verdict"]),
        provenance=EvidenceProvenance(data["provenance"]),
        runtime_identities=tuple(data.get("runtime_identities", ())),
        timing=dict(data.get("timing", {})),
        accounting=ac_fact,
        not_run_obligations=tuple(data.get("not_run_obligations", ())),
        signature_strategy=data.get("signature_strategy", "SHA256_DIGEST_ONLY"),
        signature=data.get("signature"),
        is_authoritative=bool(data.get("is_authoritative", False)),
        disclaimers=tuple(data.get("disclaimers", ())),
    )


def build_judge_view_data(
    receipt_or_dict: PublicVerificationReceipt | dict[str, Any],
    run_meta: dict[str, Any] | None = None,
    events: list[Any] | None = None,
) -> JudgeViewData:
    """Construct a JudgeViewData instance from authentic execution facts."""
    receipt_verified = True
    if isinstance(receipt_or_dict, dict):
        try:
            rc = PublicVerificationReceipt.from_dict(receipt_or_dict)
        except Exception:
            receipt_verified = False
            rc = _parse_receipt_unvalidated(receipt_or_dict)
    else:
        rc = receipt_or_dict
        try:
            verify_public_receipt_integrity(rc)
            receipt_verified = True
        except Exception:
            receipt_verified = False

    meta = run_meta or {}
    run_id = meta.get("run_id") or rc.task_id or "run-unknown"
    verdict = rc.overall_verdict.value.upper()

    verdict_badge_classes = {
        "VERIFIED": "badge-verified",
        "CONTRADICTED": "badge-contradicted",
        "INCONCLUSIVE": "badge-inconclusive",
        "BLOCKED": "badge-blocked",
        "NOT_RUN": "badge-not-run",
    }
    verdict_badge_class = verdict_badge_classes.get(verdict, "badge-inconclusive")

    provenance_str = rc.provenance.value.upper()
    prov_classes = {
        "LIVE_NEBIUS": "badge-live",
        "RECORDED_LIVE": "badge-recorded",
        "LOCAL_EXECUTION": "badge-local",
        "FIXTURE": "badge-fixture",
    }
    prov_badge_class = prov_classes.get(provenance_str, "badge-local")

    prov_descriptions = {
        "LIVE_NEBIUS": "Executed live inside isolated Nebius Cloud Sandboxes.",
        "RECORDED_LIVE": (
            "Immutable replay of a certified live run bound to an exact source commit."
        ),
        "LOCAL_EXECUTION": "Executed locally inside a sanitized, isolated local process.",
        "FIXTURE": "Validated against deterministic offline verification fixtures.",
    }
    prov_desc = prov_descriptions.get(provenance_str, "Execution provenance recorded.")

    # Find worlds in executions tuple
    base_exec = next((e for e in rc.executions if e.world == ExecutionWorld.BASE), None)
    cand_exec = next((e for e in rc.executions if e.world == ExecutionWorld.CANDIDATE), None)

    if base_exec:
        base_world = {
            "status": base_exec.termination_status.value,
            "exit_code": base_exec.exit_code,
            "outcome": base_exec.outcome.value.upper(),
            "digest": base_exec.stdout_digest,
            "sandbox_id": base_exec.sandbox_id,
            "stdout_snippet": base_exec.stdout_digest[:16],
        }
    else:
        base_world = {
            "status": "NOT_RUN",
            "exit_code": None,
            "outcome": "NOT_RUN",
            "digest": "none",
            "sandbox_id": "none",
            "stdout_snippet": "none",
        }

    if cand_exec:
        cand_world = {
            "status": cand_exec.termination_status.value,
            "exit_code": cand_exec.exit_code,
            "outcome": cand_exec.outcome.value.upper(),
            "digest": cand_exec.stdout_digest,
            "sandbox_id": cand_exec.sandbox_id,
            "stdout_snippet": cand_exec.stdout_digest[:16],
        }
    else:
        cand_world = {
            "status": "NOT_RUN",
            "exit_code": None,
            "outcome": "NOT_RUN",
            "digest": "none",
            "sandbox_id": "none",
            "stdout_snippet": "none",
        }

    # Counterfactual world
    cf_fact = rc.counterfactual
    if cf_fact and cf_fact.execution_fact:
        cf_exec = cf_fact.execution_fact
        cf_world = {
            "present": True,
            "status": cf_exec.termination_status.value,
            "exit_code": cf_exec.exit_code,
            "outcome": cf_exec.outcome.value.upper(),
            "digest": cf_exec.stdout_digest,
            "delta_digest": cf_fact.delta_digest or "none",
            "sandbox_id": cf_exec.sandbox_id,
        }
        cf_label = cf_exec.outcome.value.upper()
    elif cf_fact and cf_fact.outcome:
        cf_world = {
            "present": True,
            "status": "COMPLETED",
            "exit_code": None,
            "outcome": cf_fact.outcome.value.upper(),
            "digest": "none",
            "delta_digest": cf_fact.delta_digest or "none",
            "sandbox_id": "N/A",
        }
        cf_label = cf_fact.outcome.value.upper()
    else:
        cf_world = {
            "present": False,
            "status": "NOT_RUN",
            "exit_code": None,
            "outcome": "NOT_RUN",
            "digest": "none",
            "delta_digest": "none",
            "sandbox_id": "none",
        }
        cf_label = "NOT_RUN"

    causal_transition = f"BASE={base_world['outcome']} -> CANDIDATE={cand_world['outcome']}"
    if cf_world["present"]:
        causal_transition += f" -> COUNTERFACTUAL={cf_label}"

    # Timing
    timing_dict = rc.timing or {}
    created_at_utc = timing_dict.get("created_at_utc", "UNKNOWN")
    duration_seconds = timing_dict.get("total_duration_seconds")

    # Factual timeline
    timeline_steps = [
        TimelineStep(
            name="1. Task Ingestion & Invariant Lock",
            stage_id="task_ingestion",
            status="COMPLETED",
            details=f"Target: {rc.repo_locator} @ {rc.source_commit_id[:8]}",
            is_live_action=False,
        ),
        TimelineStep(
            name="2. Contract Compilation",
            stage_id="contract_compilation",
            status="COMPLETED",
            details=f"Frozen Contract Digest: {rc.frozen_contract_digest[:16]}...",
            is_live_action=False,
        ),
        TimelineStep(
            name="3. Builder Execution Boundary",
            stage_id="builder_execution",
            status="COMPLETED" if rc.candidate_patch_digest else "NOT_RUN",
            details=f"Patch Digest: {(rc.candidate_patch_digest or 'none')[:16]}...",
            is_live_action=(provenance_str == "LIVE_NEBIUS"),
        ),
        TimelineStep(
            name="4. Sealed Witness Generation",
            stage_id="witness_generation",
            status="COMPLETED" if rc.witnesses else "NOT_RUN",
            details=f"{len(rc.witnesses)} witness(es) locked before candidate execution.",
            is_live_action=(provenance_str == "LIVE_NEBIUS"),
        ),
        TimelineStep(
            name="5. Causal Two-World Engine",
            stage_id="causal_engine",
            status="COMPLETED"
            if (base_world["outcome"] != "NOT_RUN" and cand_world["outcome"] != "NOT_RUN")
            else "NOT_RUN",
            details=(
                f"BASE: {base_world['outcome']} (exit {base_world['exit_code']}), "
                f"CANDIDATE: {cand_world['outcome']} (exit {cand_world['exit_code']})"
            ),
            is_live_action=(provenance_str == "LIVE_NEBIUS"),
        ),
        TimelineStep(
            name="6. Counterfactual Third Run",
            stage_id="counterfactual_run",
            status="COMPLETED" if cf_world["present"] else "NOT_RUN",
            details=(
                f"Outcome: {cf_world['outcome']} (Delta: {str(cf_world['delta_digest'])[:12]}...)"
                if cf_world["present"]
                else "Not required by risk budget policy."
            ),
            is_live_action=(provenance_str == "LIVE_NEBIUS"),
        ),
        TimelineStep(
            name="7. Minimal Causal Slice",
            stage_id="causal_slice",
            status="NOT_RUN",
            details="Slice minimizer NOT_RUN (no causal slice record).",
            is_live_action=False,
        ),
        TimelineStep(
            name="8. Public Receipt Issuance & Integrity",
            stage_id="receipt_issuance",
            status="COMPLETED" if receipt_verified else "TAMPERED",
            details=(
                f"Digest: {rc.receipt_digest[:16]}... "
                f"(Integrity: {'VALID' if receipt_verified else 'INVALID'})"
            ),
            is_live_action=False,
        ),
    ]

    # Requirement rows from coverage_summary per_requirement_facts
    req_rows: list[RequirementRow] = []
    cov = rc.coverage_summary
    if hasattr(cov, "per_requirement_facts"):
        for fact in cov.per_requirement_facts:
            req_rows.append(
                RequirementRow(
                    requirement_id=fact.requirement_id,
                    semantic_class=fact.change_class.value
                    if hasattr(fact.change_class, "value")
                    else str(fact.change_class),
                    description=fact.rationale,
                    outcome=fact.preliminary_verdict.value.upper()
                    if hasattr(fact.preliminary_verdict, "value")
                    else str(fact.preliminary_verdict),
                    witness_id=fact.witness_id or "wit-sealed",
                    witness_digest=fact.witness_digest or "sealed",
                    slice_status="UNSLICED",
                    slice_detail="N/A",
                )
            )

    # Fallback to witnesses if no per_requirement_facts
    if not req_rows and rc.witnesses:
        for w in rc.witnesses:
            req_rows.append(
                RequirementRow(
                    requirement_id=w.requirement_id or "REQ-001",
                    semantic_class="BUG_FIX",
                    description=f"Sealed witness validation for {w.requirement_id or 'REQ-001'}",
                    outcome=verdict,
                    witness_id=w.witness_id,
                    witness_digest=w.witness_digest,
                    slice_status="UNSLICED",
                    slice_detail="N/A",
                )
            )

    # Cost accounting
    acct = rc.accounting
    if acct and acct.is_metered:
        cost_accounting = {
            "total_tokens": acct.prompt_tokens + acct.completion_tokens,
            "input_tokens": acct.prompt_tokens,
            "output_tokens": acct.completion_tokens,
            "sandboxes_created": len(rc.runtime_identities),
            "estimated_cost_usd": acct.estimated_cost_usd,
            "is_metered": True,
        }
    else:
        cost_accounting = {
            "total_tokens": None,
            "input_tokens": None,
            "output_tokens": None,
            "sandboxes_created": len(rc.runtime_identities),
            "estimated_cost_usd": None,
            "is_metered": False,
        }

    raw_json = json.dumps(rc.to_dict(), indent=2, sort_keys=True)

    return JudgeViewData(
        thesis="If the patch matters, the base must break.",
        run_id=run_id,
        verdict=verdict,
        verdict_badge_class=verdict_badge_class,
        provenance=provenance_str,
        provenance_badge_class=prov_badge_class,
        provenance_description=prov_desc,
        is_authoritative=rc.is_authoritative,
        created_at_utc=created_at_utc,
        duration_seconds=duration_seconds,
        causal_transition=causal_transition,
        base_world=base_world,
        candidate_world=cand_world,
        counterfactual_world=cf_world,
        timeline_steps=timeline_steps,
        requirements=req_rows,
        receipt_digest=rc.receipt_digest,
        receipt_verified=receipt_verified,
        source_commit_sha=rc.source_commit_id,
        candidate_tree_digest=rc.candidate_tree_digest,
        candidate_patch_digest=rc.candidate_patch_digest or "none",
        not_run_obligations=list(rc.not_run_obligations),
        cost_accounting=cost_accounting,
        raw_receipt_json=raw_json,
    )
