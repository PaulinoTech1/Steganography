# P1 additive policy API contract (2026-10-02)

Goal: keep original Unicode evidence distinct from an application-facing action.
Constraints: leave `analyze`, legacy CLI and all prior tests unchanged; preserve
text by default; no new detection rule, context exemption, or unmeasured limits.
Inputs: a Python `str` and trusted caller-selected `Policy` enum. Untrusted text
cannot set the policy. Outputs: typed `InspectionReport` and schema-v2 JSON.
Done when full suite, exact development action fixtures, installed-wheel API,
invalid-input and forged-policy tests pass with original baseline intact.

Approaches considered: (1) wrap `analyze()` and remap verdicts (~30 lines), but
it performs NFKC and residual scans unnecessarily; (2) scan original text once,
then apply a fixed named policy (~100 lines), chosen; (3) generic user-defined
rule engine (~200+ lines), deferred until real consumers need it. Standard library
only. New report reuses source offsets and copies finding fields.

API: `inspect_text(text, *, policy=Policy.BALANCED)` where `Policy` has
`BALANCED` and `LEGACY_VERDICT`. Policy strings/objects are rejected as caller
configuration errors. `InspectionReport.as_dict()` has exactly schema_version=2,
policy_id, status, action, reason_codes, findings, finding_count_total,
findings_truncated=false, scan_complete, candidate_text, transformation="preserve".
Finding objects include rule_id, category, severity, offset, length, detail,
codepoints. Offsets and lengths are Python codepoints in original text.

Balanced v1 table: explicit bidi overrides U+202D/U+202E -> block;
other bidi controls, tags, mixed-script findings, or high/clustered zero-width
-> review; individual zero-width, invisible format, whitespace -> allow.
Highest action wins. Reasons contain only IDs that drive the winning action.
Legacy-verdict v1 table: high -> block; other findings -> review; none -> allow.
These are provisional observation policies, not validated enforcement settings.

On complete allow, candidate_text equals the exact original string. On review
or block, candidate_text is None; the caller must hold the document. Wrong
input type or lone surrogate -> status invalid_input, action/candidate None,
no findings, scan_complete=false, stable reason. Empty string -> complete
allow with empty candidate. Scanner exceptions -> status error, no action or
candidate, stable reason; P2 will define bounded limit outcomes. No v2 CLI, transform, or forwarding helper
in this slice. The legacy CLI remains unchanged.
