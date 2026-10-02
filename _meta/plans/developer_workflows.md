# P4 developer workflow preview (2026-10-02)

Goal: make bounded reports usable from scripts and show the exact point where
retrieved or tool text is withheld before an LLM call.
Constraints: preserve legacy CLI, no model/network dependency at runtime,
ASCII-safe machine output, P2 per-document caps, untrusted text cannot select
policy, and no claim that Unicode inspection stops plain-text injection.
Input: one file/stdin document or one JSON string per line; app-owned source
IDs and a callable model stub for examples. Output: one report per complete
document, safe stderr explanation, aggregate batch exit, and no call on held
inputs.
Done when: CLI flags and exit statuses have subprocess tests; empty,
malformed, oversized, record/output limits and bidi escaping are tested;
installed wheel exercises CLI paths; RAG/tool examples prove held inputs
never reach a recording model caller; docs state partial-batch semantics.

Approach A: document a Python loop only (~20 lines, no CLI work). Rejected:
does not serve command-line batch ingestion or machine-readable pipelines.
Approach B: JSONL strings with bounded streaming (~90 lines, stdlib) and two
small framework-independent call-boundary examples. Chosen: no attacker-owned
metadata, order maps to app-owned IDs, no framework dependency.
Approach C: JSON objects with IDs/policy embedded in each line. Rejected:
complicates trust boundaries and invites document metadata to masquerade as
application configuration.

Aggregate batch limits are 64 MiB input/output and 1,000 records by default,
in addition to each document's P2 caps. A partial stream never authorizes a
whole batch; callers must wait for exit 0. `--explain` uses only static reason
text and counts, not raw hostile characters. Production applications must
repeat the final-call test at their actual model invocation boundary.
