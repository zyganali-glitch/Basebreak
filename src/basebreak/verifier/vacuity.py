"""Mechanical detection of vacuous witnesses and invalid preconditions.

P-09.05: Detect vacuous witnesses and invalid preconditions.

Core Invariants:
1. Meaningful assertion requirement: Witness must contain and execute real assertions
   against runtime behavior. Zero assertions, empty test bodies, or constant comparisons
   are rejected.
2. Trivial pass prevention: Assertions against constants (e.g. assert True, assert 1 == 1)
   without exercising target behavior are flagged as VACUOUS_TRIVIAL_PASS.
3. Skipped suite defense: Zero tests collected, empty runs, or 100% skipped suites cannot
   masquerade as PASS.
4. Precondition validation: Missing target module/symbol, import errors, or silent setup
   failures fail closed as INVALID_PRECONDITION.
5. Absolute authority: Vacuity detection is deterministic and mechanical; model prose or
   confidence scores cannot override a vacuity finding.
"""

from __future__ import annotations

import ast
from collections.abc import Sequence
from dataclasses import dataclass
from enum import Enum

from basebreak.verifier.witness_result import NormalizedWitnessResult, WitnessOutcome
from basebreak.verifier.witness_store import WitnessArtifact


class VacuityStatus(str, Enum):
    """Classification of witness vacuity or validity."""

    VALID = "VALID"
    VACUOUS_NO_ASSERTIONS = "VACUOUS_NO_ASSERTIONS"
    VACUOUS_TRIVIAL_PASS = "VACUOUS_TRIVIAL_PASS"
    VACUOUS_SKIPPED_SUITE = "VACUOUS_SKIPPED_SUITE"
    INVALID_PRECONDITION = "INVALID_PRECONDITION"
    MALFORMED_WITNESS_CODE = "MALFORMED_WITNESS_CODE"


@dataclass(frozen=True, slots=True)
class VacuityCheckResult:
    """Deterministic result of vacuity and precondition analysis."""

    status: VacuityStatus
    is_vacuous: bool
    details: str
    assertion_count: int
    target_symbols_referenced: tuple[str, ...]

    @property
    def grants_verification(self) -> bool:
        """Only non-vacuous, valid witnesses can grant causal verification."""
        return self.status == VacuityStatus.VALID and not self.is_vacuous


def _is_constant_node(node: ast.AST) -> bool:
    """Check if an AST node is a literal constant."""
    return isinstance(node, ast.Constant)


def _is_trivial_assertion(assert_node: ast.Assert) -> bool:
    """Detect if an assertion is trivially constant (e.g. assert True, assert 1 == 1)."""
    test_node = assert_node.test

    # 1. Direct constant: assert True, assert 1, assert "hello"
    if _is_constant_node(test_node):
        return True

    # 2. Constant comparison: assert 1 == 1, assert "a" == "a", assert True is True
    if isinstance(test_node, ast.Compare):
        if _is_constant_node(test_node.left):
            if all(_is_constant_node(comp) for comp in test_node.comparators):
                return True

    return False


def analyze_artifact_code_vacuity(
    artifacts: Sequence[WitnessArtifact],
    *,
    expected_target_symbols: Sequence[str] = (),
) -> VacuityCheckResult:
    """Statically inspect witness code for assertions and target symbol references."""
    total_assertions = 0
    trivial_assertions = 0
    all_referenced_names: set[str] = set()

    for art in artifacts:
        if not art.path.endswith(".py"):
            continue

        try:
            tree = ast.parse(art.content, filename=art.path)
        except SyntaxError as exc:
            return VacuityCheckResult(
                status=VacuityStatus.MALFORMED_WITNESS_CODE,
                is_vacuous=True,
                details=f"Syntax error in witness artifact {art.path}: {exc}",
                assertion_count=0,
                target_symbols_referenced=(),
            )

        # Collect names referenced
        for node in ast.walk(tree):
            if isinstance(node, ast.Name):
                all_referenced_names.add(node.id)
            elif isinstance(node, ast.Attribute):
                all_referenced_names.add(node.attr)

            # Count assertions
            if isinstance(node, ast.Assert):
                total_assertions += 1
                if _is_trivial_assertion(node):
                    trivial_assertions += 1
            elif isinstance(node, ast.Call):
                func = node.func
                # Pytest raises or unittest assert methods
                if isinstance(func, ast.Attribute):
                    if func.attr in (
                        "raises",
                        "assertEqual",
                        "assertTrue",
                        "assertFalse",
                        "assertIn",
                        "assertIs",
                        "assertIsNotNone",
                    ):
                        total_assertions += 1
                elif isinstance(func, ast.Name):
                    if func.id == "raises":
                        total_assertions += 1

    # Evaluation
    if total_assertions == 0:
        return VacuityCheckResult(
            status=VacuityStatus.VACUOUS_NO_ASSERTIONS,
            is_vacuous=True,
            details="Witness contains zero assertion statements or checks",
            assertion_count=0,
            target_symbols_referenced=tuple(sorted(all_referenced_names)),
        )

    meaningful_assertions = total_assertions - trivial_assertions
    if meaningful_assertions <= 0:
        return VacuityCheckResult(
            status=VacuityStatus.VACUOUS_TRIVIAL_PASS,
            is_vacuous=True,
            details=f"All {total_assertions} assertions are trivial constants (e.g. assert True)",
            assertion_count=total_assertions,
            target_symbols_referenced=tuple(sorted(all_referenced_names)),
        )

    # Check target symbols if expected
    matched_targets = tuple(sorted(set(expected_target_symbols) & all_referenced_names))

    return VacuityCheckResult(
        status=VacuityStatus.VALID,
        is_vacuous=False,
        details=f"Witness contains {meaningful_assertions} meaningful assertions",
        assertion_count=meaningful_assertions,
        target_symbols_referenced=matched_targets,
    )


def analyze_runtime_execution_vacuity(
    result: NormalizedWitnessResult,
    code_check: VacuityCheckResult,
) -> VacuityCheckResult:
    """Analyze runtime execution output to detect skipped suites and invalid preconditions."""
    if code_check.is_vacuous:
        return code_check

    output_text = (result.stdout_clean + "\n" + result.stderr_clean).lower()

    # 1. Detect missing precondition / import errors
    if "modulenotfounderror" in output_text or "importerror" in output_text:
        return VacuityCheckResult(
            status=VacuityStatus.INVALID_PRECONDITION,
            is_vacuous=True,
            details="Execution failed due to missing module or import error in setup",
            assertion_count=code_check.assertion_count,
            target_symbols_referenced=code_check.target_symbols_referenced,
        )

    # 2. Detect 0 tests collected or empty test run
    if "collected 0 items" in output_text or "no tests ran" in output_text:
        return VacuityCheckResult(
            status=VacuityStatus.VACUOUS_SKIPPED_SUITE,
            is_vacuous=True,
            details="Test runner collected 0 test items",
            assertion_count=code_check.assertion_count,
            target_symbols_referenced=code_check.target_symbols_referenced,
        )

    # 3. Detect 100% skipped tests claiming PASS
    if result.outcome == WitnessOutcome.PASS:
        if "0 passed" in output_text and "skipped" in output_text:
            return VacuityCheckResult(
                status=VacuityStatus.VACUOUS_SKIPPED_SUITE,
                is_vacuous=True,
                details="Test suite passed because all tests were skipped (0 passed)",
                assertion_count=code_check.assertion_count,
                target_symbols_referenced=code_check.target_symbols_referenced,
            )

    return code_check
