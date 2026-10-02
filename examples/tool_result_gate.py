"""Inspect a tool's text result before the next model call."""
from __future__ import annotations

from collections.abc import Callable

from stegdetect import Limits, Policy, inspect_text


def continue_with_tool_result(tool_text: str, model_call: Callable[[str], str], *,
                              policy: Policy = Policy.BALANCED) -> dict:
    report = inspect_text(tool_text, policy=policy, limits=Limits())
    if report.status != "complete" or report.action != "allow":
        return {"status": "held", "report": report}
    return {"status": "sent", "report": report,
            "model_output": model_call(report.candidate_text)}
