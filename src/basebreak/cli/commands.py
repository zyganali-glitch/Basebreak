"""Command implementations for Basebreak CLI.

P-19.01 - P-19.04: verify, status, evidence, receipt, config commands.
"""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path
from typing import Any

from basebreak.causal.public_receipt import (
    PublicVerificationReceipt,
    render_receipt_markdown,
    render_receipt_terminal,
    verify_public_receipt_integrity,
)
from basebreak.cli.config import BasebreakConfig
from basebreak.cli.persistence import (
    RunCorruptError,
    RunNotFoundError,
    RunPersistenceManager,
)
from basebreak.cli.runner import execute_verification_pipeline
from basebreak.security.secret_policy import redact_text


def _print_safe(text: str, file: Any = None) -> None:
    """Print text with mandatory deterministic secret redaction."""
    redacted, _ = redact_text(text)
    target_file = file if file is not None else sys.stdout
    print(redacted, file=target_file)


def run_verify_command(args: argparse.Namespace, config: BasebreakConfig) -> int:
    """Execute 'verify' command."""
    target = getattr(args, "target", None)
    repo = getattr(args, "repo", None)
    patch = getattr(args, "patch", None)
    base_sha = getattr(args, "base_sha", None)
    candidate_sha = getattr(args, "candidate_sha", None)
    change_class = getattr(args, "change_class", "BUG_FIX") or "BUG_FIX"
    allow_live = getattr(args, "allow_live", False)
    fmt = getattr(args, "format", config.default_format) or "text"
    output_path = getattr(args, "output", None)

    # Allow test overrides if provided in namespace
    base_override = getattr(args, "base_outcome_override", None)
    cand_override = getattr(args, "candidate_outcome_override", None)
    cf_override = getattr(args, "cf_outcome_override", None)

    res = execute_verification_pipeline(
        target=target,
        repo=repo,
        patch=patch,
        base_sha=base_sha,
        candidate_sha=candidate_sha,
        change_class_name=change_class,
        allow_live=allow_live,
        config=config,
        base_outcome_override=base_override,
        candidate_outcome_override=cand_override,
        cf_outcome_override=cf_override,
    )

    if fmt == "json":
        out_data = {
            "run_id": res.run_id,
            "status": res.status,
            "exit_code": res.exit_code,
            "thesis": res.thesis,
            "message": res.message,
            "causal_transition": res.causal_transition,
            "metadata": res.metadata,
            "receipt": res.receipt.to_dict() if res.receipt else None,
        }
        content = json.dumps(out_data, indent=2, sort_keys=True)
    else:
        status_badge = f"[{res.status}]"
        sep = "=" * 70
        lines = [
            sep,
            "BASEBREAK CAUSAL VERIFICATION RUN",
            f"Thesis: {res.thesis}",
            sep,
            f"Run ID:            {res.run_id}",
            f"Target:            {target or repo or 'N/A'}",
            f"Status:            {status_badge}",
            f"Exit Code:         {res.exit_code}",
            f"Causal Transition: {res.causal_transition or 'N/A'}",
            f"Message:           {res.message}",
            "-" * 70,
        ]
        if res.world_states:
            lines.append("BEHAVIORAL EVIDENCE:")
            for world, facts in res.world_states.items():
                lines.append(
                    f"  {world:15s} -> Outcome: {facts.get('outcome', 'N/A'):6s} "
                    f"(Exit: {facts.get('exit_code', 'N/A')}, "
                    f"Sandbox: {facts.get('sandbox_id', 'N/A')})"
                )
        if res.receipt is not None:
            lines.extend(
                [
                    "-" * 70,
                    f"Receipt Digest:    {res.receipt.receipt_digest}",
                    f"Coverage Ratio:    {res.receipt.coverage_summary.coverage_percentage}%",
                ]
            )
        lines.append(sep)
        content = "\n".join(lines)

    _print_safe(content)

    if output_path:
        p = Path(output_path)
        p.parent.mkdir(parents=True, exist_ok=True)
        safe_content, _ = redact_text(content)
        p.write_text(safe_content, encoding="utf-8")

    return res.exit_code


def run_status_command(args: argparse.Namespace, config: BasebreakConfig) -> int:
    """Execute 'status' command."""
    run_id = args.run_id
    fmt = getattr(args, "format", config.default_format) or "text"
    persistence = RunPersistenceManager(config.runs_dir)

    try:
        metadata = persistence.load_metadata(run_id)
    except (RunNotFoundError, RunCorruptError) as exc:
        _print_safe(f"Error loading run '{run_id}': {exc}", file=sys.stderr)
        return 2

    if fmt == "json":
        _print_safe(json.dumps(metadata, indent=2, sort_keys=True))
    else:
        sep = "=" * 60
        lines = [
            sep,
            f"BASEBREAK RUN STATUS: {run_id}",
            sep,
            f"Status:            [{metadata.get('status', 'UNKNOWN')}]",
            f"Exit Code:         {metadata.get('exit_code', 'N/A')}",
            f"Target:            {metadata.get('target', 'N/A')}",
            f"Change Class:      {metadata.get('change_class', 'N/A')}",
            f"Causal Transition: {metadata.get('causal_transition', 'N/A')}",
            f"Created At:        {metadata.get('created_at', 'N/A')}",
        ]
        if metadata.get("error_message"):
            lines.append(f"Error / Reason:    {metadata.get('error_message')}")
        lines.append(sep)
        _print_safe("\n".join(lines))

    exit_code = metadata.get("exit_code", 0)
    return int(exit_code) if isinstance(exit_code, int) else 0


def run_evidence_command(args: argparse.Namespace, config: BasebreakConfig) -> int:
    """Execute 'evidence' command."""
    run_id = args.run_id
    fmt = getattr(args, "format", config.default_format) or "text"
    output_path = getattr(args, "output", None)
    persistence = RunPersistenceManager(config.runs_dir)

    try:
        evidence = persistence.load_evidence(run_id)
    except (RunNotFoundError, RunCorruptError) as exc:
        _print_safe(f"Error loading evidence for '{run_id}': {exc}", file=sys.stderr)
        return 2

    if fmt == "json":
        content = json.dumps(evidence, indent=2, sort_keys=True)
    else:
        lines = [
            f"EVIDENCE RECORDS FOR RUN: {run_id} ({len(evidence)} items)",
            "=" * 60,
        ]
        for idx, item in enumerate(evidence, 1):
            world = item.get("world", "UNKNOWN")
            fact = item.get("fact", {})
            lines.extend(
                [
                    f"[{idx}] World: {world}",
                    f"    Outcome:     {fact.get('outcome', 'N/A')}",
                    f"    Exit Code:   {fact.get('exit_code', 'N/A')}",
                    f"    Sandbox ID:  {fact.get('sandbox_id', 'N/A')}",
                    f"    Duration:    {fact.get('duration_seconds', 0.0)}s",
                    f"    Tree Digest: {fact.get('tree_digest', 'N/A')}",
                    "-" * 40,
                ]
            )
        content = "\n".join(lines)

    _print_safe(content)

    if output_path:
        p = Path(output_path)
        p.parent.mkdir(parents=True, exist_ok=True)
        safe_content, _ = redact_text(content)
        p.write_text(safe_content, encoding="utf-8")

    return 0


def run_receipt_command(args: argparse.Namespace, config: BasebreakConfig) -> int:
    """Execute 'receipt' command."""
    run_id = args.run_id
    fmt = getattr(args, "format", "text")
    output_path = getattr(args, "output", None)
    persistence = RunPersistenceManager(config.runs_dir)

    try:
        raw_receipt = persistence.load_receipt(run_id)
        if raw_receipt is None:
            _print_safe(f"No public receipt found for run '{run_id}'.", file=sys.stderr)
            return 2
    except (RunNotFoundError, RunCorruptError) as exc:
        _print_safe(f"Error loading receipt for '{run_id}': {exc}", file=sys.stderr)
        return 2

    try:
        receipt = PublicVerificationReceipt.from_dict(raw_receipt)
        verify_public_receipt_integrity(receipt)
    except Exception as exc:
        _print_safe(f"Receipt integrity verification failed for '{run_id}': {exc}", file=sys.stderr)
        return 2

    if fmt == "json":
        content = receipt.to_json(indent=2)
    elif fmt == "markdown":
        content = render_receipt_markdown(receipt)
    else:
        content = render_receipt_terminal(receipt)

    _print_safe(content)

    if output_path:
        p = Path(output_path)
        p.parent.mkdir(parents=True, exist_ok=True)
        safe_content, _ = redact_text(content)
        p.write_text(safe_content, encoding="utf-8")

    return 0


def run_config_command(args: argparse.Namespace, config: BasebreakConfig) -> int:
    """Execute 'config' command."""
    fmt = getattr(args, "format", "text")
    safe_dict = config.to_safe_dict()

    if fmt == "json":
        _print_safe(json.dumps(safe_dict, indent=2, sort_keys=True))
    else:
        sep = "=" * 60
        lines = [
            sep,
            "BASEBREAK EFFECTIVE CONFIGURATION",
            sep,
            f"Offline Mode:        {safe_dict.get('offline_mode')}",
            f"Zero Cost Mode:      {safe_dict.get('zero_cost_mode')}",
            f"Allow Live:          {safe_dict.get('allow_live')}",
            f"Sandbox Provider:    {safe_dict.get('sandbox_provider')}",
            f"Promo Stop Floor:    ${safe_dict.get('token_factory_promo_stop_threshold'):.2f}",
            f"Runs Directory:      {safe_dict.get('runs_dir')}",
            f"Default Format:      {safe_dict.get('default_format')}",
            sep,
            "Policy: Target personal spend strictly $0.00.",
            sep,
        ]
        _print_safe("\n".join(lines))

    return 0
