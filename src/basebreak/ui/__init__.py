"""Judge & Operator UI package for Basebreak.

P-22: Single-screen causal story, execution timeline, behavioral comparison,
requirement-witness-slice map, receipt inspection, and responsive judge mode.
"""

from __future__ import annotations

from basebreak.ui.models import JudgeViewData, build_judge_view_data
from basebreak.ui.renderer import render_judge_ui_html

__all__ = [
    "JudgeViewData",
    "build_judge_view_data",
    "render_judge_ui_html",
]
