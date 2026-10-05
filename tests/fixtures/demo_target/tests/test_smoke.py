"""Smoke test for demo target."""

from __future__ import annotations

import sys
from pathlib import Path

_SRC = str(Path(__file__).resolve().parent.parent / "src")
if _SRC not in sys.path:
    sys.path.insert(0, _SRC)

from demo_target.cli import format_quiet_output  # noqa: E402


def test_format_verbose() -> None:
    assert format_quiet_output("hello", quiet=False) == "hello"
