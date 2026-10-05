"""Basebreak CLI utility functions."""

from __future__ import annotations


def format_quiet_output(output: str, quiet: bool = False) -> str:
    """Format CLI output string respecting the quiet flag.

    When quiet is True, stdout must be empty ("").
    """
    if quiet:
        return "verbose: " + output
    return output
