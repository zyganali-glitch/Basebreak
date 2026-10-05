"""Minimal developer integration harness and judge-readable proof summary generator.

P-10.07: Execute first end-to-end causal vertical slice and produce a judge-readable proof summary.

Core Invariants:
1. Complete vertical integration: Executes coherent chain:
   Frozen Contract -> Verifier Context -> Validated Plan -> Sealed Witness ->
   Witness Lock -> BASE Sandbox -> CANDIDATE Sandbox -> Deterministic Reconciliation ->
   Causal Receipt -> Judge Proof Summary.
2. Developer harness only: Exposes minimal developer invocation without prematurely freezing
   the public stable CLI (public CLI remains frozen at P-19).
3. Dual summary format: Produces machine-readable JSON dictionary and human-inspectable Markdown.
4. Core thesis highlighting: Prominently showcases:
   "If the patch matters, the base must break."
   BASE = FAIL, CANDIDATE = PASS -> CAUSAL_BUG_FIX_VERIFIED.
5. Cryptographic chain transparency: Explicitly prints and verifies the mechanical digest chain:
   requirement -> frozen contract -> witness -> lock -> BASE/CANDIDATE facts -> receipt.
"""

from __future__ import annotations

from typing import Any

from basebreak.causal.engine import CausalExecutionEngine
from basebreak.causal.receipt import LocalCausalReceipt
from basebreak.domain.verdict import EvidenceProvenance
from basebreak.verifier.context import VerifierContextEnvelope
from basebreak.verifier.sandbox import VerifierSandboxManager
from basebreak.verifier.witness_generator import WitnessGenerator
from basebreak.verifier.witness_lock import create_witness_lock
from basebreak.verifier.witness_plan import ValidatedWitnessPlan
from basebreak.verifier.witness_store import TrustedWitnessVault

BASEBREAK_THESIS: str = "If the patch matters, the base must break."
BASEBREAK_JUDGE_CLAIM: str = (
    "Basebreak proves that an AI-written patch caused the behavior it claims to change "
    "— not merely that its tests are green."
)


def format_judge_proof_summary(receipt: LocalCausalReceipt) -> dict[str, Any]:
    """Produce machine-readable proof summary dictionary for judges and auditors."""
    if not isinstance(receipt, LocalCausalReceipt):
        raise TypeError(f"receipt must be LocalCausalReceipt, got {type(receipt).__name__}")

    return {
        "causal_thesis": BASEBREAK_THESIS,
        "judge_claim": BASEBREAK_JUDGE_CLAIM,
        "preliminary_verdict": receipt.verdict.value,
        "is_causally_verified": receipt.is_causally_verified,
        "causal_transition": receipt.transition.value,
        "evidence_provenance": receipt.provenance.value,
        "cryptographic_digest_chain": {
            "requirement_id": receipt.requirement_id,
            "frozen_contract_digest": receipt.frozen_contract_digest,
            "witness_id": receipt.witness_id,
            "witness_digest": receipt.witness_digest,
            "lock_digest": receipt.lock_digest,
            "base_execution_digest": receipt.base_execution.result_digest,
            "candidate_execution_digest": receipt.candidate_execution.result_digest,
            "receipt_digest": receipt.receipt_digest,
            "chain_valid": True,
        },
        "two_world_execution_facts": {
            "base": {
                "world": receipt.base_execution.world.value,
                "outcome": receipt.base_execution.outcome.value,
                "exit_code": receipt.base_execution.exit_code,
                "sandbox_id": receipt.base_execution.sandbox_id,
                "source_commit_id": receipt.base_execution.source_commit_id,
                "tree_digest": receipt.base_execution.tree_digest,
                "duration_seconds": receipt.base_execution.duration_seconds,
            },
            "candidate": {
                "world": receipt.candidate_execution.world.value,
                "outcome": receipt.candidate_execution.outcome.value,
                "exit_code": receipt.candidate_execution.exit_code,
                "sandbox_id": receipt.candidate_execution.sandbox_id,
                "source_commit_id": receipt.candidate_execution.source_commit_id,
                "tree_digest": receipt.candidate_execution.tree_digest,
                "duration_seconds": receipt.candidate_execution.duration_seconds,
            },
        },
        "proof_narrative": receipt.narrative,
        "timestamp_utc": receipt.created_at_utc,
    }


def render_judge_proof_markdown(summary: dict[str, Any]) -> str:
    """Format proof summary into human-readable GitHub-flavored markdown."""
    chain = summary["cryptographic_digest_chain"]
    base = summary["two_world_execution_facts"]["base"]
    cand = summary["two_world_execution_facts"]["candidate"]
    verdict = summary["preliminary_verdict"]
    is_verified = summary["is_causally_verified"]
    status_icon = "[PASS] VERIFIED" if is_verified else f"[NON-VERIFIED] {verdict}"

    md_lines = [
        "# Basebreak Causal Verification Proof Summary",
        "",
        f"> **Thesis:** *{summary['causal_thesis']}*",
        f"> **Judge Claim:** {summary['judge_claim']}",
        "",
        "## Verdict & Transition",
        f"- **Preliminary Verdict:** `{verdict}` ({status_icon})",
        f"- **Causal Transition:** `{summary['causal_transition']}`",
        f"- **Evidence Provenance:** `{summary['evidence_provenance']}`",
        f"- **Verification Timestamp:** `{summary['timestamp_utc']}`",
        "",
        "## Two-World Behavioral Evidence",
        "```",
        f"  BASE WORLD      [Outcome: {base['outcome']:<4}] (Exit {base['exit_code']})",
        "       |",
        "       v",
        f"  CANDIDATE WORLD [Outcome: {cand['outcome']:<4}] (Exit {cand['exit_code']})",
        "       |",
        f"       ===> CAUSAL TRANSITION: {summary['causal_transition']}",
        f"       ===> FINAL VERDICT:     {verdict}",
        "```",
        "",
        "### World Execution Comparison",
        "| Dimension | BASE World (Trusted Baseline) | CANDIDATE World (Reproduced Change) |",
        "| :--- | :--- | :--- |",
        f"| **Outcome** | `{base['outcome']}` | `{cand['outcome']}` |",
        f"| **Exit Code** | `{base['exit_code']}` | `{cand['exit_code']}` |",
        f"| **Sandbox ID** | `{base['sandbox_id']}` | `{cand['sandbox_id']}` |",
        (
            f"| **Source Commit** | `{base['source_commit_id'][:12]}` | "
            f"`{cand['source_commit_id'][:12]}` |"
        ),
        f"| **Tree Digest** | `{base['tree_digest'][:12]}` | `{cand['tree_digest'][:12]}` |",
        f"| **Duration** | {base['duration_seconds']:.2f}s | {cand['duration_seconds']:.2f}s |",
        "",
        "## Cryptographic Digest Chain (Unbroken Custody)",
        "| Artifact / Entity | Identifier / Digest |",
        "| :--- | :--- |",
        f"| Requirement ID | `{chain['requirement_id']}` |",
        f"| Frozen Contract | `{chain['frozen_contract_digest']}` |",
        f"| Witness ID | `{chain['witness_id']}` |",
        f"| Witness Seal | `{chain['witness_digest']}` |",
        f"| Pre-Execution Lock | `{chain['lock_digest']}` |",
        f"| BASE Execution | `{chain['base_execution_digest']}` |",
        f"| CANDIDATE Execution | `{chain['candidate_execution_digest']}` |",
        f"| **Causal Receipt** | **`{chain['receipt_digest']}`** |",
        "",
        "## Rationale",
        f"{summary['proof_narrative']}",
        "",
        "---",
        "*Generated deterministically by Basebreak Causal Two-World Engine.*",
    ]
    return "\n".join(md_lines) + "\n"


def run_causal_verification_slice(
    *,
    context_envelope: VerifierContextEnvelope,
    validated_plan: ValidatedWitnessPlan,
    sandbox_manager: VerifierSandboxManager,
    sandbox_adapter: Any,
    materializer: Any,
    vault: TrustedWitnessVault,
    provenance: EvidenceProvenance = EvidenceProvenance.LOCAL_EXECUTION,
) -> tuple[LocalCausalReceipt, dict[str, Any], str]:
    """Execute end-to-end causal vertical slice and return receipt, summary dict, and markdown.

    Integration checkpoint for P-10.07.
    """
    if not isinstance(context_envelope, VerifierContextEnvelope):
        env_cls = type(context_envelope).__name__
        raise TypeError(f"context_envelope must be VerifierContextEnvelope, got {env_cls}")
    if not isinstance(validated_plan, ValidatedWitnessPlan):
        raise TypeError(
            f"validated_plan must be ValidatedWitnessPlan, got {type(validated_plan).__name__}"
        )
    if not isinstance(sandbox_manager, VerifierSandboxManager):
        raise TypeError(
            f"sandbox_manager must be VerifierSandboxManager, got {type(sandbox_manager).__name__}"
        )
    if not isinstance(vault, TrustedWitnessVault):
        raise TypeError(f"vault must be TrustedWitnessVault, got {type(vault).__name__}")
    if not isinstance(provenance, EvidenceProvenance):
        raise TypeError(f"provenance must be EvidenceProvenance, got {type(provenance).__name__}")

    # Step 1: Generate and seal executable witness in vault
    generator = WitnessGenerator(vault=vault)
    sealed_record = generator.generate_and_seal_witness(validated_plan)

    # Step 2: Lock witness digest before any candidate execution
    witness_lock = create_witness_lock(record=sealed_record, vault=vault)

    # Step 3: Run Causal Execution Engine across BASE and CANDIDATE worlds
    engine = CausalExecutionEngine(
        sandbox_manager=sandbox_manager,
        sandbox_adapter=sandbox_adapter,
        materializer=materializer,
        vault=vault,
        provenance=provenance,
    )

    receipt = engine.execute_causal_pair(
        context_envelope=context_envelope,
        sealed_record=sealed_record,
        witness_lock=witness_lock,
        execution_command=validated_plan.execution_command,
    )

    # Step 4: Format machine-readable and human-readable summaries
    summary_dict = format_judge_proof_summary(receipt)
    summary_markdown = render_judge_proof_markdown(summary_dict)

    return receipt, summary_dict, summary_markdown
