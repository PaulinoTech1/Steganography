# Legacy detection contract: P0 baseline

This document records the behavior of `stegdetect` 0.1.0 at the P0 baseline.
It is a compatibility target, not a recommendation to forward `sanitized` text
or to block every `malicious` verdict. The raw development fixtures and exact
expected outcomes live in [`evals/manifest.json`](../evals/manifest.json).

`analyze(text)` scans the original Python string and returns `Report` with
`verdict`, `findings`, `sanitized`, and `as_dict()`. Finding offsets are Python
codepoint indices into the original string. The existing CLI accepts a literal
argument, a file, or stdin; JSON mode exits 0 for clean and 2 for non-clean.
Three whole JSON/exit snapshots are checked against the installed wheel in
[`evals/fixtures/legacy_cli.json`](../evals/fixtures/legacy_cli.json).

| Category | Evidence today | Legacy decision | Known limitation |
|---|---|---|---|
| `ZERO_WIDTH` | Configured format characters | Suspicious individually; some clusters malicious | Persian joiners and emoji joiners can be legitimate; three ZWSPs remain suspicious rather than malicious |
| `BIDI_OVERRIDE` | Configured direction controls | Malicious | Valid RTL isolates are also flagged |
| `MIXED_SCRIPT` | Configured look-alikes and density rule | Malicious above threshold | Below-density substitutions can stay clean; ordinary code-switching may be rewritten |
| `TAG_CHARACTER` | Unicode tags | Malicious | England emoji flag tags are flagged |
| `INVISIBLE_FORMAT` | Configured format characters | Suspicious | This is codepoint evidence, not intent |
| `SUSPICIOUS_WHITESPACE` | Configured unusual spaces | Suspicious | Legitimate typography is flagged |

The specific rule/generator/test mapping is in
[`GENERATOR_RULE_MAP.md`](GENERATOR_RULE_MAP.md). A verdict only reflects the
implemented Unicode rules. The two historical plain-text/rendering boundary
tests remain clean. No result establishes that model-bound prompt injection is
prevented.

`sanitized` is produced on *every* text, including clean text. NFKC folding and
configured confusable mapping can rewrite Russian/English code-switching,
Chinese fullwidth punctuation, and mathematical notation with zero findings.
The P0 fixtures pin this behavior. Re-running canonicalization can produce a
second composition change, for example `a\u200b\u0301` and `\u0430\u0301`.
No new policy or transform is implemented in P0.

The scanner accepts Python strings containing lone surrogates, but the CLI can
raise `UnicodeEncodeError` when output is restricted to strict UTF-8. Its error
path and exact outcome depend on the stream encoding. The P0 regression test
only proves the strict UTF-8 case. File/stdin resource limits and installed
distribution behavior across platforms remain future work beyond this baseline
smoke gate.

The protected original test files and SHA-256 values are frozen in
[`evals/protected_tests.json`](../evals/protected_tests.json). Any byte change
fails the baseline validator. The compatibility suite now adds new tests instead
of changing the old ones.
