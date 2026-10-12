"""HTML renderer for Judge & Operator UI (P-22).

Produces a responsive, accessible single-screen judge interface
with zero fake animations, honest provenance badges, and cryptographic verification.
"""

from __future__ import annotations

import html
from typing import Any

from basebreak.causal.public_receipt import PublicVerificationReceipt
from basebreak.ui.models import JudgeViewData, build_judge_view_data


def render_judge_ui_html(
    receipt_or_data: PublicVerificationReceipt | dict[str, Any] | JudgeViewData,
    run_meta: dict[str, Any] | None = None,
) -> str:
    """Render a standalone, responsive, single-screen Judge UI HTML document."""
    if isinstance(receipt_or_data, JudgeViewData):
        data = receipt_or_data
    else:
        data = build_judge_view_data(receipt_or_data, run_meta=run_meta)

    # Escape dynamic text for safety
    thesis_safe = html.escape(data.thesis)
    run_id_safe = html.escape(data.run_id)
    verdict_safe = html.escape(data.verdict)
    prov_safe = html.escape(data.provenance)
    prov_desc_safe = html.escape(data.provenance_description)
    transition_safe = html.escape(data.causal_transition)
    receipt_digest_safe = html.escape(data.receipt_digest)
    source_sha_safe = html.escape(data.source_commit_sha)
    tree_digest_safe = html.escape(data.candidate_tree_digest)
    patch_digest_safe = html.escape(data.candidate_patch_digest)
    disclaimer_safe = html.escape(data.disclaimer)

    integrity_class = "badge-valid" if data.receipt_verified else "badge-invalid"
    integrity_text = (
        "AUTHENTIC (SHA-256 Verified)" if data.receipt_verified else "TAMPERED / INVALID"
    )

    # Format timeline HTML
    timeline_items_html = []
    for step in data.timeline_steps:
        st_class = {
            "COMPLETED": "step-completed",
            "RUNNING": "step-running",
            "BLOCKED": "step-blocked",
            "NOT_RUN": "step-not-run",
            "TAMPERED": "step-tampered",
        }.get(step.status, "step-not-run")

        live_tag = '<span class="tag-live">LIVE</span>' if step.is_live_action else ""
        timeline_items_html.append(
            f"""
            <div class="timeline-step {st_class}">
                <div class="step-header">
                    <span class="step-indicator"></span>
                    <span class="step-name">{html.escape(step.name)}</span>
                    <span class="step-status">{html.escape(step.status)}</span>
                    {live_tag}
                </div>
                <div class="step-details">{html.escape(step.details)}</div>
            </div>
            """
        )
    timeline_html = "\n".join(timeline_items_html)

    # Format requirement rows HTML
    req_rows_html = []
    for r in data.requirements:
        outcome_class = {
            "VERIFIED": "text-verified",
            "PASS": "text-verified",
            "FAIL": "text-fail",
            "CONTRADICTED": "text-fail",
            "INCONCLUSIVE": "text-inconclusive",
            "BLOCKED": "text-blocked",
            "NOT_RUN": "text-not-run",
        }.get(r.outcome, "text-inconclusive")

        w_id_safe = html.escape(r.witness_id)
        w_dig_short = html.escape(r.witness_digest[:12])
        slice_st_safe = html.escape(r.slice_status)
        slice_det_safe = html.escape(r.slice_detail)

        req_rows_html.append(
            f"""
            <tr>
                <td class="req-id"><code>{html.escape(r.requirement_id)}</code></td>
                <td><span class="req-class">{html.escape(r.semantic_class)}</span></td>
                <td>{html.escape(r.description)}</td>
                <td class="outcome-cell">
                    <strong class="{outcome_class}">{html.escape(r.outcome)}</strong>
                </td>
                <td><code>{w_id_safe}</code><br><small>{w_dig_short}...</small></td>
                <td>
                    <span class="slice-badge">{slice_st_safe}</span>
                    <br><small>{slice_det_safe}</small>
                </td>
            </tr>
            """
        )
    if req_rows_html:
        requirements_table_html = "\n".join(req_rows_html)
    else:
        requirements_table_html = (
            "<tr><td colspan='6'>No individual requirement breakdown available.</td></tr>"
        )

    # Format not-run obligations
    if data.not_run_obligations:
        items = "".join(
            f"<li><code>{html.escape(item)}</code></li>" for item in data.not_run_obligations
        )
        not_run_html = f"""
        <div class="not-run-box">
            <h4>Honest NOT_RUN Obligations:</h4>
            <ul>{items}</ul>
        </div>
        """
    else:
        not_run_html = "<div class='not-run-box-empty'>All planned obligations executed.</div>"

    cf_outcome_class = (
        "text-fail" if data.counterfactual_world["outcome"] == "FAIL" else "text-not-run"
    )
    base_sbx_safe = html.escape(str(data.base_world["sandbox_id"]))
    cand_sbx_safe = html.escape(str(data.candidate_world["sandbox_id"]))
    cf_exit_safe = html.escape(str(data.counterfactual_world["exit_code"]))
    cf_delta_short = html.escape(str(data.counterfactual_world["delta_digest"])[:12])

    tokens_in = data.cost_accounting["input_tokens"]
    tokens_out = data.cost_accounting["output_tokens"]
    tokens_tot = data.cost_accounting["total_tokens"]
    sbx_count = data.cost_accounting["sandboxes_created"]
    cost_usd = data.cost_accounting["estimated_cost_usd"]

    # Format distinct verdict banner (P-28.04)
    v_upper = data.verdict.upper()
    if "VERIFIED" in v_upper and "NOT" not in v_upper:
        verdict_banner_html = (
            '<div class="verdict-banner banner-verified" role="status">'
            "<strong>CAUSAL VERIFICATION SUCCESS:</strong> "
            "The patch was proved to cause the claimed behavioral fix. "
            "Defect failed on Base, passed on Candidate, and re-failed "
            "when the patch delta was subtracted."
            "</div>"
        )
    elif "CONTRADICTED" in v_upper:
        verdict_banner_html = (
            '<div class="verdict-banner banner-contradicted" role="alert">'
            "<strong>CAUSAL CONTRADICTION DETECTED:</strong> Causal invariant violated! "
            "Base did not fail, or Candidate did not pass. Ordinary CI may have reported green, "
            "but Basebreak caught the causal inconsistency!"
            "</div>"
        )
    elif "INCONCLUSIVE" in v_upper:
        verdict_banner_html = (
            '<div class="verdict-banner banner-inconclusive" role="status">'
            "<strong>INCONCLUSIVE EXECUTION:</strong> "
            "Execution timed out or encountered infrastructure failure. "
            "Under Basebreak anti-collapse laws, timeouts never count as passes or failures."
            "</div>"
        )
    elif "BLOCKED" in v_upper:
        verdict_banner_html = (
            '<div class="verdict-banner banner-blocked" role="status">'
            "<strong>EXECUTION BLOCKED:</strong> "
            "Security policy, contract violation, moving symbolic git ref, "
            "or budget floor stopped execution fail-closed."
            "</div>"
        )
    else:
        verdict_banner_html = (
            '<div class="verdict-banner banner-not-run" role="status">'
            "<strong>NOT_RUN / AWAITING EXECUTION:</strong> "
            "Live external provider credentials or operator "
            "credit authorization were not provided. Honest non-execution."
            "</div>"
        )

    return f"""<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Basebreak Judge &amp; Operator Verification Dashboard — {run_id_safe}</title>
    <style>
        :root {{
            --bg-primary: #0f172a;
            --bg-card: #1e293b;
            --bg-card-alt: #334155;
            --text-main: #f8fafc;
            --text-muted: #94a3b8;
            --border: #475569;
            --accent: #38bdf8;
            --green: #4ade80;
            --red: #f87171;
            --amber: #fbbf24;
            --purple: #c084fc;
            --blue: #60a5fa;
        }}
        * {{ box-sizing: border-box; margin: 0; padding: 0; }}
        :focus-visible {{
            outline: 2px solid var(--accent);
            outline-offset: 2px;
        }}
        body {{
            font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, sans-serif;
            background-color: var(--bg-primary);
            color: var(--text-main);
            padding: 1.5rem;
            line-height: 1.5;
        }}
        .container {{
            max-width: 1200px;
            margin: 0 auto;
            display: flex;
            flex-direction: column;
            gap: 1.5rem;
        }}
        .header {{
            background: linear-gradient(135deg, #1e293b 0%, #0f172a 100%);
            border: 1px solid var(--border);
            border-radius: 12px;
            padding: 1.5rem;
            display: flex;
            justify-content: space-between;
            align-items: center;
            flex-wrap: wrap;
            gap: 1rem;
        }}
        .thesis-box h1 {{
            font-size: 1.6rem;
            font-weight: 800;
            color: #fff;
            letter-spacing: -0.02em;
        }}
        .thesis-statement {{
            font-size: 1.15rem;
            font-weight: 600;
            color: var(--accent);
            margin-top: 0.25rem;
            font-style: italic;
        }}
        .verdict-box {{
            display: flex;
            flex-direction: column;
            align-items: flex-end;
            gap: 0.5rem;
        }}
        .badge {{
            display: inline-block;
            padding: 0.35rem 0.9rem;
            border-radius: 9999px;
            font-weight: 700;
            font-size: 0.95rem;
            letter-spacing: 0.05em;
            text-transform: uppercase;
        }}
        .badge-verified {{
            background: rgba(74, 222, 128, 0.2);
            color: var(--green);
            border: 1px solid var(--green);
        }}
        .badge-contradicted {{
            background: rgba(248, 113, 113, 0.2);
            color: var(--red);
            border: 1px solid var(--red);
        }}
        .badge-inconclusive {{
            background: rgba(251, 191, 36, 0.2);
            color: var(--amber);
            border: 1px solid var(--amber);
        }}
        .badge-blocked {{
            background: rgba(148, 163, 184, 0.2);
            color: var(--text-muted);
            border: 1px solid var(--border);
        }}
        .badge-not-run {{
            background: rgba(96, 165, 250, 0.2);
            color: var(--blue);
            border: 1px solid var(--blue);
        }}
        .badge-live {{
            background: rgba(192, 132, 252, 0.2);
            color: var(--purple);
            border: 1px solid var(--purple);
        }}
        .badge-recorded {{
            background: rgba(56, 189, 248, 0.2);
            color: var(--accent);
            border: 1px solid var(--accent);
        }}
        .badge-local {{
            background: rgba(100, 116, 139, 0.2);
            color: #cbd5e1;
            border: 1px solid #64748b;
        }}
        .badge-fixture {{
            background: rgba(148, 163, 184, 0.15);
            color: #94a3b8;
            border: 1px solid #475569;
        }}
        .badge-valid {{ background: rgba(74, 222, 128, 0.2); color: var(--green); }}
        .badge-invalid {{ background: rgba(248, 113, 113, 0.2); color: var(--red); }}

        .verdict-banner {{
            padding: 0.9rem 1.25rem;
            border-radius: 8px;
            font-size: 0.95rem;
            line-height: 1.5;
            border-width: 1px;
            border-style: solid;
        }}
        .banner-verified {{
            background: rgba(74, 222, 128, 0.12); border-color: var(--green); color: #dcfce7;
        }}
        .banner-contradicted {{
            background: rgba(248, 113, 113, 0.12); border-color: var(--red); color: #fee2e2;
        }}
        .banner-inconclusive {{
            background: rgba(251, 191, 36, 0.12); border-color: var(--amber); color: #fef3c7;
        }}
        .banner-blocked {{
            background: rgba(148, 163, 184, 0.12); border-color: var(--border); color: #f1f5f9;
        }}
        .banner-not-run {{
            background: rgba(96, 165, 250, 0.12); border-color: var(--blue); color: #dbeafe;
        }}

        .step-tag {{
            font-size: 0.72rem;
            text-transform: uppercase;
            letter-spacing: 0.05em;
            color: var(--accent);
            font-weight: 700;
            margin-bottom: 0.25rem;
            display: block;
        }}

        .causal-grid {{
            display: grid;
            grid-template-columns: repeat(auto-fit, minmax(320px, 1fr));
            gap: 1.25rem;
        }}
        .card {{
            background: var(--bg-card);
            border: 1px solid var(--border);
            border-radius: 10px;
            padding: 1.25rem;
        }}
        .card h2, .card h3 {{
            font-size: 1.1rem;
            color: var(--accent);
            margin-bottom: 0.75rem;
            border-bottom: 1px solid var(--border);
            padding-bottom: 0.4rem;
        }}

        .worlds-container {{
            display: grid;
            grid-template-columns: repeat(auto-fit, minmax(220px, 1fr));
            gap: 1rem;
            margin-top: 0.5rem;
        }}
        .world-box {{
            background: var(--bg-card-alt);
            border-radius: 8px;
            padding: 1rem;
            display: flex;
            flex-direction: column;
            gap: 0.5rem;
        }}
        .world-title {{
            font-weight: 700;
            font-size: 0.95rem;
            text-transform: uppercase;
        }}
        .world-outcome {{ font-size: 1.5rem; font-weight: 900; }}
        .text-fail {{ color: var(--red); }}
        .text-verified {{ color: var(--green); }}
        .text-inconclusive {{ color: var(--amber); }}
        .text-blocked {{ color: var(--text-muted); }}
        .text-not-run {{ color: var(--blue); }}

        .transition-summary {{
            margin-top: 1rem;
            padding: 0.75rem;
            background: #0b1329;
            border: 1px solid var(--accent);
            border-radius: 6px;
            text-align: center;
            font-weight: 700;
            font-size: 1.05rem;
            color: #fff;
        }}

        .explainer-card {{
            background: var(--bg-card);
            border: 1px solid var(--border);
            border-radius: 10px;
            padding: 1.25rem;
        }}
        .explainer-grid {{
            display: grid;
            grid-template-columns: repeat(auto-fit, minmax(280px, 1fr));
            gap: 1.25rem;
            margin-top: 0.75rem;
        }}
        .explainer-col {{
            background: var(--bg-card-alt);
            border-radius: 8px;
            padding: 1rem;
        }}
        .explainer-col.ci-col {{ border-left: 4px solid var(--amber); }}
        .explainer-col.basebreak-col {{ border-left: 4px solid var(--green); }}
        .explainer-p {{
            font-size: 0.88rem;
            color: var(--text-main);
            margin-bottom: 0.5rem;
        }}
        .explainer-list {{
            padding-left: 1.25rem;
            font-size: 0.83rem;
            color: var(--text-muted);
            display: flex;
            flex-direction: column;
            gap: 0.35rem;
        }}
        .explainer-list strong {{ color: var(--text-main); }}
        .explainer-banner {{
            margin-top: 1rem;
            padding: 0.65rem 0.9rem;
            background: #0b1329;
            border: 1px solid var(--accent);
            border-radius: 6px;
            font-size: 0.88rem;
            color: #fff;
            text-align: center;
        }}

        .timeline {{
            display: flex;
            flex-direction: column;
            gap: 0.5rem;
        }}
        .timeline-step {{
            background: var(--bg-card-alt);
            border-left: 4px solid var(--border);
            padding: 0.6rem 0.8rem;
            border-radius: 4px;
        }}
        .step-completed {{ border-left-color: var(--green); }}
        .step-running {{ border-left-color: var(--amber); }}
        .step-blocked {{ border-left-color: var(--red); }}
        .step-not-run {{ border-left-color: var(--text-muted); opacity: 0.75; }}
        .step-tampered {{ border-left-color: var(--red); background: rgba(248, 113, 113, 0.1); }}

        .step-header {{
            display: flex;
            justify-content: space-between;
            align-items: center;
            font-size: 0.9rem;
            font-weight: 600;
        }}
        .step-status {{
            font-size: 0.75rem;
            padding: 0.15rem 0.4rem;
            border-radius: 4px;
            background: rgba(0,0,0,0.3);
        }}
        .tag-live {{
            background: var(--purple);
            color: #fff;
            font-size: 0.65rem;
            padding: 0.1rem 0.3rem;
            border-radius: 3px;
            font-weight: bold;
        }}
        .step-details {{
            font-size: 0.8rem;
            color: var(--text-muted);
            margin-top: 0.25rem;
            word-break: break-all;
        }}

        table {{
            width: 100%;
            border-collapse: collapse;
            font-size: 0.85rem;
            margin-top: 0.5rem;
        }}
        th, td {{
            text-align: left;
            padding: 0.6rem;
            border-bottom: 1px solid var(--border);
        }}
        th {{
            color: var(--accent);
            font-weight: 600;
            text-transform: uppercase;
            font-size: 0.75rem;
        }}
        code {{
            background: rgba(0,0,0,0.3);
            padding: 0.15rem 0.35rem;
            border-radius: 4px;
            font-family: ui-monospace, SFMono-Regular, Consolas, monospace;
            font-size: 0.82rem;
            color: #e2e8f0;
            word-break: break-all;
            overflow-wrap: anywhere;
        }}

        .receipt-facts {{
            display: flex;
            flex-direction: column;
            gap: 0.4rem;
            font-size: 0.85rem;
        }}
        .receipt-facts span.label {{
            color: var(--text-muted);
            font-weight: 600;
        }}
        .not-run-box {{
            background: rgba(248, 113, 113, 0.08);
            border: 1px solid rgba(248, 113, 113, 0.3);
            border-radius: 6px;
            padding: 0.75rem;
            margin-top: 0.75rem;
        }}
        .not-run-box h4 {{
            color: var(--red);
            font-size: 0.85rem;
            margin-bottom: 0.3rem;
        }}
        .not-run-box ul {{
            padding-left: 1.25rem;
            font-size: 0.8rem;
            color: #fca5a5;
        }}
        .not-run-box-empty {{
            color: var(--green);
            font-size: 0.85rem;
            margin-top: 0.5rem;
        }}

        .telemetry-row {{
            display: flex;
            justify-content: space-between;
            background: var(--bg-card-alt);
            padding: 0.6rem 0.8rem;
            border-radius: 6px;
            margin-top: 0.5rem;
            font-size: 0.85rem;
            flex-wrap: wrap;
            gap: 0.5rem;
        }}
        .disclaimer-box {{
            font-size: 0.75rem;
            color: var(--text-muted);
            border-top: 1px solid var(--border);
            padding-top: 0.75rem;
            text-align: center;
        }}

        @media (max-width: 768px) {{
            body {{ padding: 0.75rem; }}
            .header {{ flex-direction: column; align-items: flex-start; }}
            .verdict-box {{ align-items: flex-start; }}
            .causal-grid {{ grid-template-columns: 1fr; }}
            .worlds-container {{ grid-template-columns: 1fr; }}
            .explainer-grid {{ grid-template-columns: 1fr; }}
        }}
    </style>
</head>
<body>
    <div class="container">
        <!-- P-22.01 & P-28.02: Single-Screen Causal Story Header -->
        <header class="header">
            <div class="thesis-box">
                <h1>BASEBREAK VERIFICATION RUNTIME</h1>
                <div class="thesis-statement">“{thesis_safe}”</div>
                <div style="font-size: 0.85rem; color: var(--text-muted); margin-top: 0.4rem;">
                    Run: <code>{run_id_safe}</code> &bull; Timestamp: {data.created_at_utc}
                </div>
            </div>
            <div class="verdict-box">
                <span class="badge {data.verdict_badge_class}">{verdict_safe}</span>
                <span class="badge {data.provenance_badge_class}">{prov_safe}</span>
                <small style="color: var(--text-muted);">{prov_desc_safe}</small>
            </div>
        </header>

        <!-- P-28.04: Distinct Honest Verdict Banner -->
        {verdict_banner_html}

        <!-- P-22.03 & P-28.03: Three-World Behavioral Comparison -->
        <section class="card" aria-labelledby="causal-triplet-heading">
            <h2 id="causal-triplet-heading">Three-World Causal Verification</h2>
            <div class="worlds-container">
                <div class="world-box">
                    <span class="step-tag">[1. Reproduce Defect on Base]</span>
                    <span class="world-title">1. Base (Clean Source)</span>
                    <span class="world-outcome text-fail">{data.base_world["outcome"]}</span>
                    <small>Exit: <code>{data.base_world["exit_code"]}</code></small>
                    <small>Sandbox: <code>{base_sbx_safe}</code></small>
                </div>
                <div class="world-box">
                    <span class="step-tag">[2. Confirm Fix on Candidate]</span>
                    <span class="world-title">2. Candidate (With Patch)</span>
                    <span class="world-outcome text-verified">
                        {data.candidate_world["outcome"]}
                    </span>
                    <small>Exit: <code>{data.candidate_world["exit_code"]}</code></small>
                    <small>Sandbox: <code>{cand_sbx_safe}</code></small>
                </div>
                <div class="world-box">
                    <span class="step-tag">[3. Prove Delta Necessity]</span>
                    <span class="world-title">3. Counterfactual (Delta Subtracted)</span>
                    <span class="world-outcome {cf_outcome_class}">
                        {data.counterfactual_world["outcome"]}
                    </span>
                    <small>Exit: <code>{cf_exit_safe}</code></small>
                    <small>Delta: <code>{cf_delta_short}</code></small>
                </div>
            </div>
            <div class="transition-summary">
                Causal Transition: <code>{transition_safe}</code>
            </div>
        </section>

        <!-- P-28.02: Why Green CI Lies vs. What Basebreak Proves -->
        <section class="card explainer-card" aria-labelledby="why-basebreak-heading">
            <h2 id="why-basebreak-heading">
                Why Ordinary Green CI Lies &bull; What Basebreak Proves
            </h2>
            <div class="explainer-grid">
                <div class="explainer-col ci-col">
                    <h3>Ordinary Green CI</h3>
                    <p class="explainer-p">
                        <strong>Only tests Candidate:</strong>
                        CI runs test suites against the new patch. If tests pass, it merges.
                    </p>
                    <ul class="explainer-list">
                        <li>⚠️ <strong>The Fallacy:</strong> Green tests do NOT prove the fix.</li>
                        <li>⚠️ <strong>Vacuous Tests:</strong>
                            Tests may pass vacuously (trivial assertions, wrong precondition).</li>
                        <li>⚠️ <strong>Unbroken Base:</strong>
                            If test never failed on buggy Base, it proves nothing about patch!</li>
                    </ul>
                </div>
                <div class="explainer-col basebreak-col">
                    <h3>Basebreak Causal Verification</h3>
                    <p class="explainer-p">
                        <strong>Proves Causal Necessity:</strong>
                        Executes identical witness across three isolated worlds.
                    </p>
                    <ul class="explainer-list">
                        <li>✅ <strong>Base = FAIL:</strong>
                            Witness verifies that defect genuinely broke the unpatched source.</li>
                        <li>✅ <strong>Candidate = PASS:</strong>
                            Identical witness confirms patch resolves the failure.</li>
                        <li>✅ <strong>Counterfactual = FAIL:</strong>
                            Subtracting patch delta causes failure to return.</li>
                    </ul>
                </div>
            </div>
            <div class="explainer-banner">
                <strong>Causal Invariant:</strong>
                <code>BASE(FAIL) &rarr; CANDIDATE(PASS) &rarr; COUNTERFACTUAL(FAIL)</code>
                &bull; Provenance: <strong>{prov_safe}</strong>
            </div>
        </section>

        <!-- P-22.02: Execution Stage Timeline & P-22.05: Receipt Inspection -->
        <div class="causal-grid">
            <section class="card" aria-labelledby="timeline-heading">
                <h2 id="timeline-heading">Execution Stage Timeline</h2>
                <div class="timeline">
                    {timeline_html}
                </div>
            </section>

            <section class="card" aria-labelledby="receipt-heading">
                <h2 id="receipt-heading">Cryptographic Public Receipt &amp; Integrity</h2>
                <div class="receipt-facts">
                    <div><span class="label">Receipt Digest:</span>
                         <code>{receipt_digest_safe}</code></div>
                    <div><span class="label">Integrity Status:</span>
                         <span class="badge {integrity_class}">{integrity_text}</span></div>
                    <div><span class="label">Source Commit:</span>
                         <code>{source_sha_safe}</code></div>
                    <div><span class="label">Candidate Tree:</span>
                         <code>{tree_digest_safe}</code></div>
                    <div><span class="label">Candidate Patch:</span>
                         <code>{patch_digest_safe}</code></div>
                </div>

                <h3 style="margin-top: 1rem;">Verification Telemetry</h3>
                <div class="telemetry-row">
                    <span>Tokens: {tokens_tot:,} (in: {tokens_in:,}, out: {tokens_out:,})</span>
                    <span>Sandboxes: {sbx_count}</span>
                    <span>Cost: ${cost_usd:.4f}</span>
                </div>

                {not_run_html}
            </section>
        </div>

        <!-- P-22.04: Requirement -> Witness -> Causal-Slice Map -->
        <section class="card" aria-labelledby="req-map-heading">
            <h2 id="req-map-heading">Requirement &rarr; Sealed Witness &rarr; Causal-Slice Map</h2>
            <div style="overflow-x: auto;" role="region"
                 aria-label="Scrollable requirements table" tabindex="0">
                <table>
                    <thead>
                        <tr>
                            <th scope="col">Requirement</th>
                            <th scope="col">Class</th>
                            <th scope="col">Description</th>
                            <th scope="col">Causal Outcome</th>
                            <th scope="col">Sealed Witness</th>
                            <th scope="col">Causal Slice</th>
                        </tr>
                    </thead>
                    <tbody>
                        {requirements_table_html}
                    </tbody>
                </table>
            </div>
        </section>

        <!-- P-22.06: Responsive Judge Mode & Disclaimer -->
        <footer class="disclaimer-box">
            {disclaimer_safe}
        </footer>
    </div>
</body>
</html>
"""
