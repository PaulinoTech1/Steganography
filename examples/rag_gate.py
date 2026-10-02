"""Inspect retrieved documents before assembling a model prompt.

The caller supplies source IDs; document text never selects a policy or limit.
This example checks forwarding mechanics, not semantic prompt-injection safety.
"""
from __future__ import annotations

from collections.abc import Callable, Sequence

from stegdetect import Limits, Policy, inspect_text


def answer_with_documents(question: str, documents: Sequence[tuple[str, str]],
                          model_call: Callable[[str], str], *,
                          policy: Policy = Policy.BALANCED,
                          max_documents: int = 16,
                          max_prompt_chars: int = 1_048_576) -> dict:
    """Call the model only when every document has a complete allow decision."""
    if max_documents < 1 or max_prompt_chars < 1:
        raise ValueError("trusted batch limits must be positive")
    if len(documents) > max_documents or len(question) > max_prompt_chars:
        return {"status": "held", "reason": "BATCH_LIMIT", "reports": []}
    reports = [(source_id, inspect_text(text, policy=policy, limits=Limits()))
               for source_id, text in documents]
    if any(report.status != "complete" or report.action != "allow"
           for _, report in reports):
        return {"status": "held", "reason": "DOCUMENT_HELD", "reports": reports}
    # Include separators in the aggregate budget before allocating the prompt.
    parts = [question, "\n\nRetrieved documents:\n"]
    for index, (_, report) in enumerate(reports, 1):
        parts.extend((f"\nDocument {index}:\n", report.candidate_text))
    if sum(map(len, parts)) > max_prompt_chars:
        return {"status": "held", "reason": "PROMPT_CHAR_LIMIT", "reports": reports}
    return {"status": "sent", "reason": None, "reports": reports,
            "model_output": model_call("".join(parts))}
