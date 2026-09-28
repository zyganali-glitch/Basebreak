"""Command-line interface adapter for deterministic contract review.

P-06.05: Human-editable contract review surface / CLI.
Provides inspect, edit, add, remove, validate, approve, and reject subcommands.
All business logic and validation authority reside in review.py and validator.py.
"""

from __future__ import annotations

import argparse
import json
import os
from collections.abc import Sequence
from pathlib import Path
from typing import Any

from basebreak.compiler.ingestion import NormalizedTask
from basebreak.compiler.review import (
    ReviewBundle,
    ReviewError,
    ReviewExitCode,
    ReviewOperationError,
    ReviewSchemaError,
    ReviewSession,
    create_review_bundle,
    create_review_bundle_from_contract,
)
from basebreak.compiler.semantics import (
    ChangeSemanticsClassification,
)
from basebreak.compiler.validator import (
    ContractValidationError,
    UnresolvedChangeClassError,
    ValidatedContract,
)
from basebreak.security.secret_policy import redact_log_text


def _safe_write_json(path: Path, data: dict[str, Any]) -> None:
    """Deterministically and atomically write JSON data to file.

    Guarantees no partial or corrupt file is written by writing to a temporary file
    in the same directory and performing an atomic rename/replace.
    """
    content = json.dumps(data, indent=2, sort_keys=True)
    temp_path = path.with_suffix(f"{path.suffix}.tmp.{os.getpid()}")
    try:
        temp_path.write_text(content, encoding="utf-8")
        temp_path.replace(path)
    except Exception:
        if temp_path.exists():
            try:
                temp_path.unlink()
            except OSError:
                pass
        raise


def _load_bundle(bundle_path: Path) -> ReviewBundle:
    """Load and validate a ReviewBundle from JSON file."""
    if not bundle_path.exists():
        raise ReviewOperationError(f"Review bundle file not found: {bundle_path}")
    try:
        content = bundle_path.read_text(encoding="utf-8")
    except Exception as e:
        safe_err = redact_log_text(str(e))
        raise ReviewOperationError(f"Failed to read review bundle file: {safe_err}") from e

    try:
        return ReviewBundle.from_json(content)
    except (ReviewSchemaError, TypeError, ValueError) as e:
        safe_err = redact_log_text(str(e))
        raise ReviewSchemaError(f"Malformed or invalid review bundle: {safe_err}") from e


def _format_requirements(session: ReviewSession) -> str:
    """Format requirements in deterministic order for terminal display."""
    items = session.get_requirements_display()
    lines: list[str] = []
    lines.append(f"Total Requirements: {len(items)}")
    lines.append("-" * 60)
    for it in items:
        lines.append(f"[{it['index']}] ID: {it['requirement_id']}")
        lines.append(f"    Statement: {it['statement']}")
        lines.append(
            f"    Citation:  {it['citation']!r} [{it['citation_start']}:{it['citation_end']}]"
        )
        if it["rationale"]:
            lines.append(f"    Rationale: {it['rationale']}")
        lines.append("-" * 60)
    return "\n".join(lines)


def cmd_inspect(args: argparse.Namespace) -> int:
    """Inspect task identity, change semantics, and requirements draft."""
    bundle_path = Path(args.bundle)
    try:
        bundle = _load_bundle(bundle_path)
    except ReviewSchemaError as e:
        safe_print(f"Schema Error: {e}", is_err=True)
        return ReviewExitCode.SCHEMA_ERROR
    except ReviewOperationError as e:
        safe_print(f"Error: {e}", is_err=True)
        return ReviewExitCode.IO_ERROR

    session = ReviewSession(bundle)
    summary = session.inspect_summary()

    safe_print("=" * 60)
    safe_print("BASEBREAK CONTRACT REVIEW INSPECTION")
    safe_print("=" * 60)
    safe_print(f"Task Digest:    {summary['task_digest']}")
    safe_print(f"Raw Digest:     {summary['raw_digest']}")
    safe_print(
        f"Task Size:      {summary['byte_length']} bytes, "
        f"{summary['character_count']} chars, {summary['line_count']} lines"
    )
    safe_print(f"Task Summary:   {summary['safe_summary']}")
    safe_print("-" * 60)
    safe_print("CANONICAL CHANGE SEMANTICS:")
    safe_print(f"Change Class:   {summary['change_class']}")
    safe_print(f"Certainty:      {summary['certainty']}")
    safe_print(f"Confidence:     {summary['confidence']}")
    safe_print(f"Rationale:      {summary['semantics_rationale']}")
    safe_print("-" * 60)
    safe_print("ACCEPTANCE REQUIREMENTS:")
    safe_print(_format_requirements(session))

    # Revalidation status
    try:
        contract = session.revalidate()
        safe_print("VALIDATION STATUS: VALID")
        safe_print(f"Rules Passed: {', '.join(contract.validation_rules_passed)}")
    except UnresolvedChangeClassError as e:
        safe_print(f"VALIDATION STATUS: UNRESOLVED SEMANTICS ({e})", is_err=True)
        return ReviewExitCode.SEMANTICS_UNRESOLVED
    except ContractValidationError as e:
        safe_print(f"VALIDATION STATUS: INVALID ({e})", is_err=True)
        return ReviewExitCode.VALIDATION_ERROR

    return ReviewExitCode.SUCCESS


def cmd_edit_statement(args: argparse.Namespace) -> int:
    """Edit the statement of a requirement.

    Fail-closed: revalidates before writing. If revalidation fails, writes no file.
    """
    bundle_path = Path(args.bundle)
    out_path = Path(args.output) if args.output else bundle_path

    try:
        bundle = _load_bundle(bundle_path)
    except ReviewSchemaError as e:
        safe_print(f"Schema Error: {e}", is_err=True)
        return ReviewExitCode.SCHEMA_ERROR
    except ReviewOperationError as e:
        safe_print(f"Error: {e}", is_err=True)
        return ReviewExitCode.IO_ERROR

    session = ReviewSession(bundle)
    try:
        session.edit_statement(args.index, args.statement)
    except ReviewOperationError as e:
        safe_print(f"Invalid Operation: {e}", is_err=True)
        return ReviewExitCode.INVALID_OPERATION

    try:
        session.revalidate()
    except UnresolvedChangeClassError as e:
        safe_print(f"Semantics Error: {e}", is_err=True)
        return ReviewExitCode.SEMANTICS_UNRESOLVED
    except (ContractValidationError, ValueError, TypeError) as e:
        safe_print(f"Validation Error: {e}", is_err=True)
        return ReviewExitCode.VALIDATION_ERROR

    updated_bundle = session.to_bundle()
    try:
        _safe_write_json(out_path, updated_bundle.to_dict())
    except Exception as e:
        safe_print(f"IO Error writing updated bundle: {e}", is_err=True)
        return ReviewExitCode.IO_ERROR

    safe_print(f"Successfully updated statement for requirement [{args.index}].")
    return ReviewExitCode.SUCCESS


def cmd_edit_rationale(args: argparse.Namespace) -> int:
    """Edit the rationale of a requirement.

    Fail-closed: revalidates before writing. If revalidation fails, writes no file.
    """
    bundle_path = Path(args.bundle)
    out_path = Path(args.output) if args.output else bundle_path

    try:
        bundle = _load_bundle(bundle_path)
    except ReviewSchemaError as e:
        safe_print(f"Schema Error: {e}", is_err=True)
        return ReviewExitCode.SCHEMA_ERROR
    except ReviewOperationError as e:
        safe_print(f"Error: {e}", is_err=True)
        return ReviewExitCode.IO_ERROR

    session = ReviewSession(bundle)
    try:
        session.edit_rationale(args.index, args.rationale)
    except ReviewOperationError as e:
        safe_print(f"Invalid Operation: {e}", is_err=True)
        return ReviewExitCode.INVALID_OPERATION

    try:
        session.revalidate()
    except UnresolvedChangeClassError as e:
        safe_print(f"Semantics Error: {e}", is_err=True)
        return ReviewExitCode.SEMANTICS_UNRESOLVED
    except (ContractValidationError, ValueError, TypeError) as e:
        safe_print(f"Validation Error: {e}", is_err=True)
        return ReviewExitCode.VALIDATION_ERROR

    updated_bundle = session.to_bundle()
    try:
        _safe_write_json(out_path, updated_bundle.to_dict())
    except Exception as e:
        safe_print(f"IO Error writing updated bundle: {e}", is_err=True)
        return ReviewExitCode.IO_ERROR

    safe_print(f"Successfully updated rationale for requirement [{args.index}].")
    return ReviewExitCode.SUCCESS


def cmd_edit_citation(args: argparse.Namespace) -> int:
    """Edit citation and its exact span offsets together.

    Fail-closed: revalidates before writing. If revalidation fails, writes no file.
    """
    bundle_path = Path(args.bundle)
    out_path = Path(args.output) if args.output else bundle_path

    try:
        bundle = _load_bundle(bundle_path)
    except ReviewSchemaError as e:
        safe_print(f"Schema Error: {e}", is_err=True)
        return ReviewExitCode.SCHEMA_ERROR
    except ReviewOperationError as e:
        safe_print(f"Error: {e}", is_err=True)
        return ReviewExitCode.IO_ERROR

    session = ReviewSession(bundle)
    try:
        session.edit_citation(
            args.index,
            args.citation,
            args.citation_start,
            args.citation_end,
        )
    except ReviewOperationError as e:
        safe_print(f"Invalid Operation: {e}", is_err=True)
        return ReviewExitCode.INVALID_OPERATION

    try:
        session.revalidate()
    except UnresolvedChangeClassError as e:
        safe_print(f"Semantics Error: {e}", is_err=True)
        return ReviewExitCode.SEMANTICS_UNRESOLVED
    except (ContractValidationError, ValueError, TypeError) as e:
        safe_print(f"Validation Error: {e}", is_err=True)
        return ReviewExitCode.VALIDATION_ERROR

    updated_bundle = session.to_bundle()
    try:
        _safe_write_json(out_path, updated_bundle.to_dict())
    except Exception as e:
        safe_print(f"IO Error writing updated bundle: {e}", is_err=True)
        return ReviewExitCode.IO_ERROR

    safe_print(f"Successfully updated citation for requirement [{args.index}].")
    return ReviewExitCode.SUCCESS


def cmd_add_req(args: argparse.Namespace) -> int:
    """Add a new requirement to the review draft.

    Fail-closed: revalidates before writing. If revalidation fails, writes no file.
    """
    bundle_path = Path(args.bundle)
    out_path = Path(args.output) if args.output else bundle_path

    try:
        bundle = _load_bundle(bundle_path)
    except ReviewSchemaError as e:
        safe_print(f"Schema Error: {e}", is_err=True)
        return ReviewExitCode.SCHEMA_ERROR
    except ReviewOperationError as e:
        safe_print(f"Error: {e}", is_err=True)
        return ReviewExitCode.IO_ERROR

    session = ReviewSession(bundle)
    try:
        session.add_requirement(
            statement=args.statement,
            citation=args.citation,
            citation_start=args.citation_start,
            citation_end=args.citation_end,
            rationale=args.rationale or "",
        )
    except ReviewOperationError as e:
        safe_print(f"Invalid Operation: {e}", is_err=True)
        return ReviewExitCode.INVALID_OPERATION

    try:
        session.revalidate()
    except UnresolvedChangeClassError as e:
        safe_print(f"Semantics Error: {e}", is_err=True)
        return ReviewExitCode.SEMANTICS_UNRESOLVED
    except (ContractValidationError, ValueError, TypeError) as e:
        safe_print(f"Validation Error: {e}", is_err=True)
        return ReviewExitCode.VALIDATION_ERROR

    updated_bundle = session.to_bundle()
    try:
        _safe_write_json(out_path, updated_bundle.to_dict())
    except Exception as e:
        safe_print(f"IO Error writing updated bundle: {e}", is_err=True)
        return ReviewExitCode.IO_ERROR

    safe_print(f"Successfully added requirement (new count: {len(session.requirements)}).")
    return ReviewExitCode.SUCCESS


def cmd_remove_req(args: argparse.Namespace) -> int:
    """Remove a requirement from the review draft.

    Fail-closed: revalidates before writing. If revalidation fails, writes no file.
    """
    bundle_path = Path(args.bundle)
    out_path = Path(args.output) if args.output else bundle_path

    try:
        bundle = _load_bundle(bundle_path)
    except ReviewSchemaError as e:
        safe_print(f"Schema Error: {e}", is_err=True)
        return ReviewExitCode.SCHEMA_ERROR
    except ReviewOperationError as e:
        safe_print(f"Error: {e}", is_err=True)
        return ReviewExitCode.IO_ERROR

    session = ReviewSession(bundle)
    try:
        session.remove_requirement(args.index)
    except ReviewOperationError as e:
        safe_print(f"Invalid Operation: {e}", is_err=True)
        return ReviewExitCode.INVALID_OPERATION

    try:
        session.revalidate()
    except UnresolvedChangeClassError as e:
        safe_print(f"Semantics Error: {e}", is_err=True)
        return ReviewExitCode.SEMANTICS_UNRESOLVED
    except (ContractValidationError, ValueError, TypeError) as e:
        safe_print(f"Validation Error: {e}", is_err=True)
        return ReviewExitCode.VALIDATION_ERROR

    updated_bundle = session.to_bundle()
    try:
        _safe_write_json(out_path, updated_bundle.to_dict())
    except Exception as e:
        safe_print(f"IO Error writing updated bundle: {e}", is_err=True)
        return ReviewExitCode.IO_ERROR

    safe_print(
        f"Successfully removed requirement [{args.index}] (new count: {len(session.requirements)})."
    )
    return ReviewExitCode.SUCCESS


def cmd_validate(args: argparse.Namespace) -> int:
    """Revalidate current draft against P-06.04 authority."""
    bundle_path = Path(args.bundle)
    try:
        bundle = _load_bundle(bundle_path)
    except ReviewSchemaError as e:
        safe_print(f"Schema Error: {e}", is_err=True)
        return ReviewExitCode.SCHEMA_ERROR
    except ReviewOperationError as e:
        safe_print(f"Error: {e}", is_err=True)
        return ReviewExitCode.IO_ERROR

    session = ReviewSession(bundle)
    try:
        contract = session.revalidate()
    except UnresolvedChangeClassError as e:
        safe_print(f"Semantics Error: {e}", is_err=True)
        return ReviewExitCode.SEMANTICS_UNRESOLVED
    except (ContractValidationError, ValueError, TypeError) as e:
        safe_print(f"Validation Error: {e}", is_err=True)
        return ReviewExitCode.VALIDATION_ERROR

    safe_print("VALIDATION PASSED")
    safe_print(f"Requirements Validated: {len(contract.requirements)}")
    safe_print(f"Rules Passed:           {', '.join(contract.validation_rules_passed)}")
    return ReviewExitCode.SUCCESS


def cmd_approve(args: argparse.Namespace) -> int:
    """Revalidate and approve reviewed contract draft.

    FAIL-CLOSED LAW:
    Does NOT write output if validation fails!
    """
    bundle_path = Path(args.bundle)
    out_path = Path(args.output)

    try:
        bundle = _load_bundle(bundle_path)
    except ReviewSchemaError as e:
        safe_print(f"Schema Error: {e}", is_err=True)
        return ReviewExitCode.SCHEMA_ERROR
    except ReviewOperationError as e:
        safe_print(f"Error: {e}", is_err=True)
        return ReviewExitCode.IO_ERROR

    session = ReviewSession(bundle)
    note = args.note or ""

    try:
        result = session.approve(reviewer_note=note)
    except UnresolvedChangeClassError as e:
        safe_print(f"Cannot approve: unresolved change semantics: {e}", is_err=True)
        return ReviewExitCode.SEMANTICS_UNRESOLVED
    except (ReviewError, ContractValidationError, ValueError, TypeError) as e:
        safe_print(f"Approval rejected: {e}", is_err=True)
        return ReviewExitCode.VALIDATION_ERROR

    try:
        _safe_write_json(out_path, result.to_dict())
    except Exception as e:
        safe_print(f"IO Error writing review result: {e}", is_err=True)
        return ReviewExitCode.IO_ERROR

    safe_print(f"APPROVAL SUCCESS: Contract ready for freeze. Result written to {out_path}.")
    return ReviewExitCode.SUCCESS


def cmd_reject(args: argparse.Namespace) -> int:
    """Explicitly reject reviewed contract draft."""
    bundle_path = Path(args.bundle)
    out_path = Path(args.output)

    try:
        bundle = _load_bundle(bundle_path)
    except ReviewSchemaError as e:
        safe_print(f"Schema Error: {e}", is_err=True)
        return ReviewExitCode.SCHEMA_ERROR
    except ReviewOperationError as e:
        safe_print(f"Error: {e}", is_err=True)
        return ReviewExitCode.IO_ERROR

    session = ReviewSession(bundle)
    note = args.note or ""

    result = session.reject(reviewer_note=note)

    try:
        _safe_write_json(out_path, result.to_dict())
    except Exception as e:
        safe_print(f"IO Error writing review result: {e}", is_err=True)
        return ReviewExitCode.IO_ERROR

    safe_print(f"REJECTED: Contract review rejected. Result written to {out_path}.")
    return ReviewExitCode.SUCCESS


def cmd_create_bundle(args: argparse.Namespace) -> int:
    """Create a ReviewBundle from task, semantics, and requirements or contract."""
    task_path = Path(args.task)
    sem_path = Path(args.semantics)
    out_path = Path(args.output)

    try:
        task_data = json.loads(task_path.read_text(encoding="utf-8"))
        task = NormalizedTask.from_dict(task_data)
    except Exception as e:
        safe_print(f"Failed to load task from {task_path}: {e}", is_err=True)
        return ReviewExitCode.SCHEMA_ERROR

    try:
        sem_data = json.loads(sem_path.read_text(encoding="utf-8"))
        semantics = ChangeSemanticsClassification.from_dict(sem_data)
    except Exception as e:
        safe_print(f"Failed to load semantics from {sem_path}: {e}", is_err=True)
        return ReviewExitCode.SCHEMA_ERROR

    if args.contract:
        contract_path = Path(args.contract)
        try:
            contract_data = json.loads(contract_path.read_text(encoding="utf-8"))
            contract = ValidatedContract.from_dict(contract_data)
        except Exception as e:
            safe_print(f"Failed to load contract from {contract_path}: {e}", is_err=True)
            return ReviewExitCode.SCHEMA_ERROR

        try:
            bundle = create_review_bundle_from_contract(task, semantics, contract)
        except UnresolvedChangeClassError as e:
            safe_print(f"Cannot create bundle: unresolved semantics: {e}", is_err=True)
            return ReviewExitCode.SEMANTICS_UNRESOLVED
        except (ContractValidationError, ValueError, TypeError) as e:
            safe_print(f"Cannot create bundle from contract: {e}", is_err=True)
            return ReviewExitCode.VALIDATION_ERROR
    elif args.requirements:
        req_path = Path(args.requirements)
        try:
            req_data = json.loads(req_path.read_text(encoding="utf-8"))
            raw_reqs = req_data if isinstance(req_data, list) else req_data.get("requirements", [])
            bundle = create_review_bundle(task, semantics, raw_reqs)
        except Exception as e:
            safe_print(f"Failed to load requirements from {req_path}: {e}", is_err=True)
            return ReviewExitCode.SCHEMA_ERROR
    else:
        safe_print("Must provide either --contract or --requirements", is_err=True)
        return ReviewExitCode.INVALID_OPERATION

    try:
        _safe_write_json(out_path, bundle.to_dict())
    except Exception as e:
        safe_print(f"Failed to write bundle to {out_path}: {e}", is_err=True)
        return ReviewExitCode.IO_ERROR

    safe_print(f"Created review bundle at {out_path}.")
    return ReviewExitCode.SUCCESS


def safe_print(message: str, is_err: bool = False) -> None:
    """Print message to stdout or stderr with secret redaction."""
    safe_msg = redact_log_text(str(message))
    if is_err:
        import sys

        sys.stderr.write(safe_msg + "\n")
    else:
        print(safe_msg)


def build_parser() -> argparse.ArgumentParser:
    """Build the argument parser for the review CLI."""
    parser = argparse.ArgumentParser(
        prog="basebreak.compiler.review_cli",
        description="Deterministic contract review surface for Basebreak.",
    )
    subparsers = parser.add_subparsers(dest="command", required=True)

    # inspect
    p_inspect = subparsers.add_parser("inspect", help="Inspect review bundle")
    p_inspect.add_argument("--bundle", required=True, help="Path to ReviewBundle JSON")

    # edit-statement
    p_edit_stmt = subparsers.add_parser("edit-statement", help="Edit requirement statement")
    p_edit_stmt.add_argument("--bundle", required=True, help="Path to ReviewBundle JSON")
    p_edit_stmt.add_argument(
        "--index", required=True, type=int, help="0-based index of requirement"
    )
    p_edit_stmt.add_argument("--statement", required=True, help="New statement text")
    p_edit_stmt.add_argument(
        "--output", help="Optional output path (defaults to overwriting bundle)"
    )

    # edit-rationale
    p_edit_rat = subparsers.add_parser("edit-rationale", help="Edit requirement rationale")
    p_edit_rat.add_argument("--bundle", required=True, help="Path to ReviewBundle JSON")
    p_edit_rat.add_argument("--index", required=True, type=int, help="0-based index of requirement")
    p_edit_rat.add_argument("--rationale", required=True, help="New rationale text")
    p_edit_rat.add_argument(
        "--output", help="Optional output path (defaults to overwriting bundle)"
    )

    # edit-citation
    p_edit_cit = subparsers.add_parser("edit-citation", help="Edit citation and span offsets")
    p_edit_cit.add_argument("--bundle", required=True, help="Path to ReviewBundle JSON")
    p_edit_cit.add_argument("--index", required=True, type=int, help="0-based index of requirement")
    p_edit_cit.add_argument("--citation", required=True, help="New citation verbatim text")
    p_edit_cit.add_argument(
        "--citation-start", required=True, type=int, help="0-based start character offset"
    )
    p_edit_cit.add_argument(
        "--citation-end", required=True, type=int, help="0-based end character offset"
    )
    p_edit_cit.add_argument(
        "--output", help="Optional output path (defaults to overwriting bundle)"
    )

    # add-req
    p_add = subparsers.add_parser("add-req", help="Add new proposed requirement")
    p_add.add_argument("--bundle", required=True, help="Path to ReviewBundle JSON")
    p_add.add_argument("--statement", required=True, help="Requirement statement")
    p_add.add_argument("--citation", required=True, help="Citation verbatim text")
    p_add.add_argument(
        "--citation-start", required=True, type=int, help="0-based start character offset"
    )
    p_add.add_argument(
        "--citation-end", required=True, type=int, help="0-based end character offset"
    )
    p_add.add_argument("--rationale", default="", help="Optional rationale")
    p_add.add_argument("--output", help="Optional output path (defaults to overwriting bundle)")

    # remove-req
    p_rem = subparsers.add_parser("remove-req", help="Remove requirement at index")
    p_rem.add_argument("--bundle", required=True, help="Path to ReviewBundle JSON")
    p_rem.add_argument("--index", required=True, type=int, help="0-based index of requirement")
    p_rem.add_argument("--output", help="Optional output path (defaults to overwriting bundle)")

    # validate
    p_val = subparsers.add_parser("validate", help="Revalidate draft against P-06.04 authority")
    p_val.add_argument("--bundle", required=True, help="Path to ReviewBundle JSON")

    # approve
    p_app = subparsers.add_parser("approve", help="Validate and approve draft")
    p_app.add_argument("--bundle", required=True, help="Path to ReviewBundle JSON")
    p_app.add_argument("--output", required=True, help="Output path for ReviewResult JSON")
    p_app.add_argument("--note", default="", help="Optional reviewer note")

    # reject
    p_rej = subparsers.add_parser("reject", help="Reject draft")
    p_rej.add_argument("--bundle", required=True, help="Path to ReviewBundle JSON")
    p_rej.add_argument("--output", required=True, help="Output path for ReviewResult JSON")
    p_rej.add_argument("--note", default="", help="Optional reviewer note")

    # create-bundle
    p_cb = subparsers.add_parser("create-bundle", help="Create review bundle from components")
    p_cb.add_argument("--task", required=True, help="Path to NormalizedTask JSON")
    p_cb.add_argument(
        "--semantics", required=True, help="Path to ChangeSemanticsClassification JSON"
    )
    p_cb.add_argument(
        "--requirements", help="Path to requirements JSON (list or {requirements: ...})"
    )
    p_cb.add_argument("--contract", help="Path to ValidatedContract JSON")
    p_cb.add_argument("--output", required=True, help="Output path for ReviewBundle JSON")

    return parser


def main(argv: Sequence[str] | None = None) -> int:
    """Main CLI entry point."""
    parser = build_parser()
    try:
        args = parser.parse_args(argv)
    except SystemExit as e:
        return e.code if isinstance(e.code, int) else 2

    handlers = {
        "inspect": cmd_inspect,
        "edit-statement": cmd_edit_statement,
        "edit-rationale": cmd_edit_rationale,
        "edit-citation": cmd_edit_citation,
        "add-req": cmd_add_req,
        "remove-req": cmd_remove_req,
        "validate": cmd_validate,
        "approve": cmd_approve,
        "reject": cmd_reject,
        "create-bundle": cmd_create_bundle,
    }

    handler = handlers.get(args.command)
    if not handler:
        safe_print(f"Unknown command: {args.command}", is_err=True)
        return ReviewExitCode.INVALID_OPERATION

    try:
        return handler(args)
    except Exception as e:
        safe_print(f"Unhandled CLI Error: {e}", is_err=True)
        return ReviewExitCode.INVALID_OPERATION


if __name__ == "__main__":
    import sys

    sys.exit(main())
