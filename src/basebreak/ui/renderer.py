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
            --green: #22c55e;
            --red: #ef4444;
            --amber: #f59e0b;
            --purple: #a855f7;
            --blue: #3b82f6;
        }}
        * {{ box-sizing: border-box; margin: 0; padding: 0; }}
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
            background: rgba(34, 197, 94, 0.2);
            color: var(--green);
            border: 1px solid var(--green);
        }}
        .badge-contradicted {{
            background: rgba(239, 68, 68, 0.2);
            color: var(--red);
            border: 1px solid var(--red);
        }}
        .badge-inconclusive {{
            background: rgba(245, 158, 11, 0.2);
            color: var(--amber);
            border: 1px solid var(--amber);
        }}
        .badge-blocked {{
            background: rgba(148, 163, 184, 0.2);
            color: var(--text-muted);
            border: 1px solid var(--border);
        }}
        .badge-not-run {{
            background: rgba(59, 130, 246, 0.2);
            color: var(--blue);
            border: 1px solid var(--blue);
        }}
        .badge-live {{
            background: rgba(168, 85, 247, 0.2);
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
        .badge-valid {{ background: rgba(34, 197, 94, 0.2); color: var(--green); }}
        .badge-invalid {{ background: rgba(239, 68, 68, 0.2); color: var(--red); }}

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
        .step-tampered {{ border-left-color: var(--red); background: rgba(239, 68, 68, 0.1); }}

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
            background: rgba(239, 68, 68, 0.08);
            border: 1px solid rgba(239, 68, 68, 0.3);
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
        }}
        .disclaimer-box {{
            font-size: 0.75rem;
            color: var(--text-muted);
            border-top: 1px solid var(--border);
            padding-top: 0.75rem;
            text-align: center;
        }}
    </style>
</head>
<body>
    <div class="container">
        <!-- P-22.01: Single-Screen Causal Story Header -->
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

        <!-- P-22.03: Three-World Behavioral Comparison -->
        <section class="card">
            <h2>Three-World Causal Verification</h2>
            <div class="worlds-container">
                <div class="world-box">
                    <span class="world-title">1. Base (Clean Source)</span>
                    <span class="world-outcome text-fail">{data.base_world["outcome"]}</span>
                    <small>Exit: <code>{data.base_world["exit_code"]}</code></small>
                    <small>Sandbox: <code>{base_sbx_safe}</code></small>
                </div>
                <div class="world-box">
                    <span class="world-title">2. Candidate (With Patch)</span>
                    <span class="world-outcome text-verified">
                        {data.candidate_world["outcome"]}
                    </span>
                    <small>Exit: <code>{data.candidate_world["exit_code"]}</code></small>
                    <small>Sandbox: <code>{cand_sbx_safe}</code></small>
                </div>
                <div class="world-box">
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

        <!-- P-22.02: Execution Stage Timeline & P-22.05: Receipt Inspection -->
        <div class="causal-grid">
            <section class="card">
                <h2>Execution Stage Timeline</h2>
                <div class="timeline">
                    {timeline_html}
                </div>
            </section>

            <section class="card">
                <h2>Cryptographic Public Receipt &amp; Integrity</h2>
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
        <section class="card">
            <h2>Requirement &rarr; Sealed Witness &rarr; Causal-Slice Map</h2>
            <div style="overflow-x: auto;">
                <table>
                    <thead>
                        <tr>
                            <th>Requirement</th>
                            <th>Class</th>
                            <th>Description</th>
                            <th>Causal Outcome</th>
                            <th>Sealed Witness</th>
                            <th>Causal Slice</th>
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
