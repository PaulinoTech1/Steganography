# Project claims ledger

Run `python scripts/validate_release.py --profile baseline` for the P0 counts
and `--profile bounded` for the later preview checks.
[`evals/claims.json`](../evals/claims.json) maps the corpus and contextual
action counts to computed metrics and fails if they drift. The command checks
the full test suite,
the exact development fixtures, the original corpus parity, deliberately broken
negative controls, and an installed wheel in a disposable environment.

| Claim | Denominator and meaning | Limit |
|---|---|---|
| Six mapped legacy categories | All category literals found in `scan_unicode()` | Generator triggering proves examples, not general recall |
| Eight protected existing test files | SHA-256 exact bytes of tests at baseline `d876974` | New tests can be added |
| 30 development fixtures | Eight project-authored synthetic source groups | Zero independent source groups; **no general FP/FN estimate** |
| 0/16 non-clean in legacy clean samples | 16 curated legitimate strings in `tests/test_false_positives.py` | Small, selected corpus; not a deployment FP rate |
| 0/800 non-malicious generated attacks | Four generator families, 200 seeded cases each | Generator-conforming cases only; not independent attacks |
| 8/8 intentional below-density evasions stayed clean | The eight tested adversarial samples | Shows a known false-negative family, not its population rate |

The development fixtures additionally expose legacy benign false alarms:
Persian and Indic joiners, family emoji, England flag tags, RTL isolate, NBSP,
thin space, and soft hyphen. These are descriptive observations. The fixture
intent label is project-authored, not independently audited. No automatic
blocking policy, false-block claim, semantic scorer, or model-outcome claim is
released by P0. Future phase gates in [`PLAN_VALIDATION.md`](PLAN_VALIDATION.md)
remain proposals until they have their own runnable validators and evidence.

P1 adds a preview decision policy measured on the **same** project-authored
development fixtures: `balanced-v1` allowed/reviewed/blocked 15/2/0 of 17
project-labeled benign examples and 3/4/2 of 9 constructed attacks. These
counts are recomputed by `scripts/evaluate.py` and checked against literal
`expected_actions` in the manifest. They are not independent accuracy rates.

P2 resource observations are in [`P2_RESOURCE_RESULTS.md`](P2_RESOURCE_RESULTS.md),
with 21 workload/size rows and 1,610 raw trials from one Windows/Python 3.10.10
run. The largest measured p95 was 1.694 s and the largest separate-worker peak
working set was 46.5 MiB. Neither number is a cross-platform guarantee or
latency SLA.

The opt-in `contextual-v1` policy allowed all 17 project-labeled benign
development fixtures and all 16 selected clean samples. Among nine
project-constructed attacks, it allowed three, reviewed four, and blocked
two. Literal outcomes are pinned in `evals/contextual-actions.json` and
verified in `tests/test_unicode_context.py`. These are descriptive counts;
there are no independent deployment FP/FN rates or semantic-safety claims.
`evals/claims.json` maps the three contextual counts to the bounded validator,
which also rejects a deliberately altered contextual action golden.

The CLI `--jsonl` mode and the two framework-independent examples are tested
for per-document and aggregate caps and for withholding held documents at a
stubbed final model-call boundary. The installed-wheel release gate repeats
six allow/hold/cap checks against repository examples loaded outside the
checkout. This does not validate a production RAG system or tool host.

The [local viewer preview](EVIDENCE_VIEWER.md) displays bounded, escaped
original-codepoint windows, report reasons and offsets, and separate preserve
candidate versus hypothetical legacy-canonicalization previews. Automated
tests cover hostile markup/bidi text and an astral offset; the installed-wheel
gate runs two viewer CLI cases. Browser accessibility and independent user
tasks have not been completed, so this is not a full viewer-usability claim.

The separate [`P3_CONTEXT_RESULTS.md`](P3_CONTEXT_RESULTS.md) profile recorded
40 timed trials across four one-megacharacter contextual workloads with no
timeouts or decision mismatches. Its largest observed p95 was 1.809 s and
largest process peak was 43.4 MiB on the same Windows runner. The 10-trial
p95 is the sample maximum and cannot establish a tail guarantee.
