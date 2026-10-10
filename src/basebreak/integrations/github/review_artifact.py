"""GitHub PR review comment and artifact generator.

P-20.03: Generates rich, judge-ready GitHub PR review Markdown comment
without external mutation, guaranteed secret-free.
"""

from __future__ import annotations

from typing import Any

from basebreak.causal.public_receipt import (
    CANONICAL_RECEIPT_THESIS,
    PublicVerificationReceipt,
)
from basebreak.domain.verdict import PreliminaryVerdict
from basebreak.security.secret_policy import redact_text


def generate_pr_review_comment(
    receipt: PublicVerificationReceipt,
    run_metadata: dict[str, Any] | None = None,
) -> str:
    """Generate structured, secret-safe GitHub PR review comment markdown.

    Includes:
    - Thesis and judge claim
    - Verdict and causal coverage metrics
    - Triplet behavioral execution table (BASE / CANDIDATE / COUNTERFACTUAL)
    - Per-requirement status
    - Cryptographic receipt digest and verification command
    """
    if not isinstance(receipt, PublicVerificationReceipt):
        raise TypeError(f"receipt must be PublicVerificationReceipt, got {type(receipt).__name__}")

    cov = receipt.coverage_summary
    cov_ratio_str = (
        f"{cov.coverage_percentage:.1f}%" if cov.coverage_percentage is not None else "N/A"
    )

    verdict_badge = (
        "🟢 **VERIFIED**"
        if receipt.overall_verdict == PreliminaryVerdict.VERIFIED
        else f"🔴 **{receipt.overall_verdict.value}**"
    )

    lines = [
        "## 🛡️ Basebreak Causal Verification Report",
        "",
        f"> **Thesis:** *{CANONICAL_RECEIPT_THESIS}*",
        "> *Proving an AI patch caused behavior — not merely that tests are green.*",
        "",
        "### Summary",
        "| Metric | Value |",
        "| :--- | :--- |",
        f"| **Verdict** | {verdict_badge} |",
        (
            f"| **Causal Coverage** | `{cov_ratio_str}` "
            f"({cov.verified_count}/{cov.eligible_count} eligible) |"
        ),
        f"| **Provenance** | `{receipt.provenance.value}` |",
        f"| **Base Commit** | `{receipt.source_commit_id[:12]}` |",
        f"| **Candidate Tree** | `{receipt.candidate_tree_digest[:12]}` |",
        f"| **Receipt Digest** | `{receipt.receipt_digest}` |",
        "",
        "### Behavioral Evidence (Three-World Triplet)",
        "| World | Sandbox ID | Outcome | Exit Code | Duration |",
        "| :--- | :--- | :--- | :--- | :--- |",
    ]

    for ex in receipt.executions:
        exit_code_str = str(ex.exit_code) if ex.exit_code is not None else "N/A"
        outcome_icon = "❌" if ex.outcome.value == "FAIL" else "✅"
        lines.append(
            f"| `{ex.world.value}` | `{ex.sandbox_id}` | {outcome_icon} `{ex.outcome.value}` | "
            f"`{exit_code_str}` | {ex.duration_seconds:.2f}s |"
        )

    if receipt.counterfactual is not None and receipt.counterfactual.is_required:
        cf_res = (
            receipt.counterfactual.outcome.value
            if receipt.counterfactual.outcome
            else "N/A"
        )
        lines.extend([
            "",
            "### Counterfactual Subtraction Check (P-11)",
            f"- **Delta Digest:** `{receipt.counterfactual.delta_digest}`",
            f"- **Outcome on Delta Subtraction:** `{cf_res}` (Target: FAIL)",
            "- **Causal Invariant:** Base broke, Candidate passed, Subtraction broke.",
        ])

    lines.extend([
        "",
        "### Requirement Causal Status",
        "| Requirement ID | Change Class | Causal State | Verdict | Explanation |",
        "| :--- | :--- | :--- | :--- | :--- |",
    ])

    for rf in cov.per_requirement_facts:
        lines.append(
            f"| `{rf.requirement_id}` | `{rf.change_class.value}` | `{rf.causal_state.value}` | "
            f"`{rf.preliminary_verdict.value}` | {rf.rationale} |"
        )

    lines.extend([
        "",
        "### Audit & Verification",
        "```bash",
        f"basebreak receipt {receipt.task_id}",
        "```",
        "*Report generated deterministically with zero model authority.*",
    ])

    raw_markdown = "\n".join(lines)
    safe_markdown, _ = redact_text(raw_markdown)
    return safe_markdown
