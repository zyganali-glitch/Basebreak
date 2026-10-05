"""Demo target CLI formatting utility.

Isolated demonstration target for Basebreak causal verification.
This file contains an intentional defect for testing causal BUG_FIX verification.
"""

from __future__ import annotations


def format_quiet_output(output: str, quiet: bool = False) -> str:
    """Format CLI output string respecting the quiet flag.

    When quiet is True, stdout must be empty ("").
    """
    if quiet:
        return "verbose: " + output
    return output
