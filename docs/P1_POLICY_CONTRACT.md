# P1 additive policy API (preview)

`inspect_text(text, *, policy=Policy.BALANCED)` scans the original Python
string and returns an `InspectionReport`. It does not call `canonicalize()` or
change `analyze()` or the legacy CLI. The named policy is selected by trusted
caller code using the `Policy` enum; text that says `policy=allow` has no effect.
The complete JSON shape is frozen by
[`inspection-v2.schema.json`](../schemas/inspection-v2.schema.json).

| Field | Contract |
|---|---|
| `status` | `complete`, `invalid_input`, or `error` |
| `action` | `allow`, `review`, or `block` only for a complete scan; otherwise `null` |
| `candidate_text` | Exact input on allow; `null` for review/block/failure |
| `reason_codes` | Stable action-driving identifiers, separate from finding severity |
| `findings` | Original-coordinate evidence with category and `unicode.<category>.v1` rule ID |
| `finding_count_total`, `findings_truncated`, `scan_complete` | Exact count, always untruncated in P1, and explicit completion |
| `transformation` | Always `preserve`; no edits or normalization |

Original offsets and lengths are Python codepoints. `as_dict()` includes
input-derived evidence and candidate text; an application must treat reports
as sensitive. When serializing an untrusted report for logs or terminals, use
`json.dumps(report.as_dict(), ensure_ascii=True)` and a suitable output-size
policy. P1 has no CLI for this schema.

The fixed `balanced-v1` preview table is:

| Original finding | Action | Reason |
|---|---|---|
| U+202D/U+202E explicit bidi override | block | `BIDI_EXPLICIT_OVERRIDE` |
| Other bidi controls | review | `BIDI_CONTROL` |
| Unicode tags | review | `TAG_CHARACTER` |
| Mixed-script finding | review | `MIXED_SCRIPT` |
| High-severity zero-width cluster | review | `ZERO_WIDTH_CLUSTER` |
| Other zero-width, invisible format, unusual whitespace | allow with evidence | `INFORMATIONAL_CARRIER` |
| No finding | allow | `NO_FINDINGS` |

The strongest action wins; `reason_codes` lists the reasons for that action.
Unknown future finding categories are held for review as
`UNCLASSIFIED_EVIDENCE` until classified. `Policy.LEGACY_VERDICT` maps any
high-severity finding to block, other findings to review, and none to allow,
but **still preserves** allowed text; it is not the legacy `analyze()` output.
Invalid types and lone surrogates have status `invalid_input`, no action and no
candidate. Scan failures have status `error`, no action and no candidate.

The 30 project-authored development fixtures have literal action expectations
for both policies in [`evals/manifest.json`](../evals/manifest.json). The
balanced policy reviewed 2 of 17 project-labeled benign examples and blocked
none; among 9 constructed-attack examples it allowed 3, reviewed 4, and
blocked 2. These are **descriptive counts**, not independent FP/FN estimates.
The benign England flag and RTL isolate are still held for review. Plain-text
injection, below-density mixed script, and three zero-width controls are among
the constructed attacks it allowed. No held-action or safe-forwarding recall
claim follows from this set.

The original Unicode scanner still materializes all findings, and this API has
no input, memory, time, or output cap. Context-sensitive emoji/joiner treatment,
targeted transformations, limits, and an enforcement-grade policy require the
later P2/P3 gates. `clean` and `allow` do not rule out plain-text injection or
an exploit at an LLM boundary. Applications must make the final call decision.

Local validation on Windows/Python 3.10.10 passed on 2026-10-02:
`python scripts/validate_release.py --profile baseline` reported 227 tests,
60 installed-wheel policy cases, 30 legacy API cases, three legacy CLI cases,
and five negative controls. The CI matrix has not yet produced remote results
for other Python versions or operating systems.
