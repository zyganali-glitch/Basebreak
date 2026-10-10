"""Main CLI entry point for Basebreak.

Console script entry point: basebreak = "basebreak.cli.main:main"
Provides commands: verify, status, evidence, receipt, config.
"""

from __future__ import annotations

import argparse
import sys
from typing import Sequence

from basebreak.cli.commands import (
    run_config_command,
    run_evidence_command,
    run_receipt_command,
    run_status_command,
    run_verify_command,
)
from basebreak.cli.config import BasebreakConfig, ConfigValidationError
from basebreak.security.secret_policy import redact_text

BASEBREAK_VERSION: str = "0.1.0"


def _safe_stderr(msg: str) -> None:
    redacted, _ = redact_text(msg)
    print(redacted, file=sys.stderr)


def build_parser() -> argparse.ArgumentParser:
    """Build the command-line argument parser for Basebreak."""
    parser = argparse.ArgumentParser(
        prog="basebreak",
        description="Basebreak: Causal verification runtime for AI-written software changes.\n"
        "Thesis: If the patch matters, the base must break.",
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    parser.add_argument("--version", action="version", version=f"basebreak {BASEBREAK_VERSION}")
    parser.add_argument(
        "--config", dest="config_path", help="Path to Basebreak configuration JSON file"
    )
    parser.add_argument("--runs-dir", dest="runs_dir", help="Override directory for stored runs")

    subparsers = parser.add_subparsers(dest="command", help="Available subcommands")

    # verify
    verify_p = subparsers.add_parser("verify", help="Verify causal behavioral effect of a patch")
    verify_p.add_argument("target", nargs="?", help="Target repository directory or locator")
    verify_p.add_argument("--repo", help="Target repository directory or locator")
    verify_p.add_argument("--patch", help="Path to patch file or inline diff")
    verify_p.add_argument("--base-sha", help="40-char base commit SHA")
    verify_p.add_argument("--candidate-sha", help="40-char candidate commit SHA")
    verify_p.add_argument(
        "--change-class",
        default="BUG_FIX",
        choices=[
            "BUG_FIX",
            "FEATURE",
            "SECURITY_FIX",
            "REFACTOR",
            "PERFORMANCE",
            "DEP_API_CHANGE",
        ],
        help="Semantic change class (default: BUG_FIX)",
    )
    verify_p.add_argument(
        "--allow-live", action="store_true", help="Explicit opt-in to live provider execution"
    )
    verify_p.add_argument(
        "--format", choices=["text", "json"], default="text", help="Output format"
    )
    verify_p.add_argument("--output", help="Save output to file")

    # status
    status_p = subparsers.add_parser(
        "status", help="Inspect status of an existing verification run"
    )
    status_p.add_argument("run_id", help="Verification run ID")
    status_p.add_argument(
        "--format", choices=["text", "json"], default="text", help="Output format"
    )

    # evidence
    evidence_p = subparsers.add_parser(
        "evidence", help="Inspect or export evidence for a verification run"
    )
    evidence_p.add_argument("run_id", help="Verification run ID")
    evidence_p.add_argument(
        "--format", choices=["text", "json"], default="text", help="Output format"
    )
    evidence_p.add_argument("--output", help="Save evidence export to file")

    # receipt
    receipt_p = subparsers.add_parser(
        "receipt", help="Render public verification receipt for a run"
    )
    receipt_p.add_argument("run_id", help="Verification run ID")
    receipt_p.add_argument(
        "--format", choices=["text", "json", "markdown"], default="text", help="Output format"
    )
    receipt_p.add_argument("--output", help="Save receipt export to file")

    # config
    config_p = subparsers.add_parser("config", help="Inspect or validate effective configuration")
    config_p.add_argument(
        "--format", choices=["text", "json"], default="text", help="Output format"
    )

    return parser


def main(argv: Sequence[str] | None = None) -> int:
    """CLI entry point returning exit code (0: VERIFIED, 1: CONTRADICTED, 2: BLOCKED/ERROR)."""
    parser = build_parser()
    args = parser.parse_args(argv)

    if not args.command:
        parser.print_help()
        return 2

    # Load configuration
    try:
        if args.config_path:
            config = BasebreakConfig.from_file(args.config_path)
        else:
            config = BasebreakConfig()
    except (FileNotFoundError, ConfigValidationError) as exc:
        _safe_stderr(f"Configuration error: {exc}")
        return 2

    if args.runs_dir:
        config.runs_dir = args.runs_dir

    if args.command == "verify":
        return run_verify_command(args, config)
    elif args.command == "status":
        return run_status_command(args, config)
    elif args.command == "evidence":
        return run_evidence_command(args, config)
    elif args.command == "receipt":
        return run_receipt_command(args, config)
    elif args.command == "config":
        return run_config_command(args, config)
    else:
        _safe_stderr(f"Unknown command: {args.command}")
        return 2


if __name__ == "__main__":
    sys.exit(main())
