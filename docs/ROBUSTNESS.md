# Robustness hardening: measured scope

Priority **1: fuzzing / robustness hardening** was chosen because a concrete
runtime problem could be reproduced and corrected without widening detection
claims. Work started on a fresh clone at
`273ad7f701d337e3e0796c50819663ef95d170e4`. The original suite passed:
**80 tests in 0.91 seconds** on Python 3.10.10 / Windows. Development tests now
require Hypothesis; production dependencies remain unchanged. The final full
suite passed: **107 tests in 42.58 seconds**, including all 80 original tests.
`git diff --check` also passed.

## Reproduced defect and change

NFKC canonically reorders combining marks. In the original path, repeated
descending combining classes caused quadratic runtime inside normalization.
Alternating U+0315 (class 232) and U+0300 (class 230) reproduced it. A second
case alternates U+FF9E, which only becomes a combining mark after compatibility
decomposition, with U+0334. Checking raw combining classes would miss that case.

The replacement decomposes each codepoint with NFKD, uses stable buckets for
nonzero combining classes between starters, and applies NFC to ordered text.
The Unicode class domain is bounded (at most 255 nonzero classes). Equal-class
order is retained, and class-zero Hangul Jamo remain available for composition.
No detection rule, severity, density threshold, or canonicalization policy was
changed. Clean-verdict text can still be rewritten.

Equivalence tests compare against standard NFKC for all 1,114,112 individual
Python codepoints, bounded arbitrary strings, and generated combinations of
marks, compatibility characters, surrogates, and Hangul. These tests support
output compatibility on those inputs; they do not exhaust all possible strings
or Python/Unicode versions.

## Timing

The recorded runtime was Python 3.10.10, Unicode database 13.0.0, on Windows
(`Windows-10-10.0.26200-SP0` as reported by Python). Timings measure `analyze()`
including original scan, canonicalization, and residual scan. Input generation
and process startup are excluded. Each hardened row is the median of three
calls in an isolated child, with a 30-second wall-clock timeout for the child.
Only one benchmark child ran at a time.

| Workload | 262,144 chars | 524,288 chars | 1,048,576 chars |
|---|---:|---:|---:|
| ASCII prose | 0.306s | 0.596s | 1.144s |
| Lone surrogates with ASCII | 0.285s | 0.579s | 1.154s |
| Nested bidi controls | 0.489s | 1.003s | 1.975s |
| Alternating Latin/Cyrillic confusables | 0.642s | 1.329s | 2.750s |
| Descending combining classes | 0.287s | 0.540s | 1.079s |
| Compatibility-decomposed combining classes | 0.367s | 0.769s | 1.477s |
| Zero-width characters | 0.546s | 1.122s | 2.313s |
| Unicode tags | 0.485s | 1.048s | 2.060s |

All 24 size/workload combinations completed without crashes or timeouts.
Four times the input took approximately **3.73–4.28 times** the median runtime.
This is evidence of linear-ish scaling on these workloads, not a proof of
worst-case linear behavior. Sizes are **Python characters**, not bytes:
1,048,576 tag characters occupy 4 MiB in UTF-8. Surrogates are Python string
values and do not have ordinary UTF-8 encodings.

The original normalization path was remeasured by substituting standard NFKC
in the same benchmark (single calls, 3-second child timeout):

| Workload | 4,096 chars | 8,192 chars | 16,384 chars | 32,768 chars | 1,048,576 chars |
|---|---:|---:|---:|---:|---:|
| Descending combining classes | 0.010s | 0.033s | 0.099s | 0.367s | timeout |
| Compatibility-decomposed combining classes | 0.009s | 0.029s | 0.102s | 0.376s | timeout |

A timeout only establishes that the original child did not finish in that
budget; it is not an exact baseline time or evidence of an infinite loop.
Raw calls, environment, and budgets are in
[baseline JSON](robustness-baseline.json) and [hardened JSON](robustness-results.json).

The regression tests run each workload at 262,144 and 1,048,576 characters
in killable subprocesses. They allow 30 seconds per child and guard fourfold
growth with `large <= 8 * small + 0.1 seconds`. This deliberately loose guard
is intended to catch quadratic regressions while tolerating timing noise.
It is not a latency SLA. Memory is not measured or capped; per-character
findings can consume substantial memory on dense carriers.

## Finite FP/FN measurements

[Corpus JSON](robustness-corpus.json) records a deterministic measurement
with seed 20261001:

| Corpus | Count | Result |
|---|---:|---|
| Existing legitimate `CLEAN_SAMPLES` | 16 | 0 flagged: **FP 0/16 (0%)** |
| Zero-width generator | 200 | 0 missed malicious verdicts |
| Bidi generator | 200 | 0 missed malicious verdicts |
| ASCII tag generator | 200 | 0 missed malicious verdicts |
| Homoglyph generator in Latin context | 200 | 0 missed malicious verdicts |
| Deliberate below-density homoglyph evasion | 8 | **8/8 undetected**, intentionally clean |

Thus the constrained in-scope generated corpus has **FN 0/800 (0%)**. Payloads
use `aeiopcx`, lengths 1–128, and fixed ASCII covers; the homoglyph family has
an explicit Latin prefix. This is not representative real-world accuracy.
The eight boundary evasions append a nonconfusable Cyrillic letter to dilute
confusable density below 90%. They are reported separately because the rule
deliberately stays silent there. Including those constructed evasions would
give 8 misses in 808 cases (about 0.99%); it would still not be a general FN rate.

Hypothesis additionally exercises all four existing generators with up to 200
examples per property and deterministic generation. Zero-width and bidi
generators receive arbitrary Unicode payloads and covers. Tag payloads use
their ASCII domain, including NUL and DEL; arbitrary Unicode tag payloads are
not supported by this generator's encoding contract. Homoglyph detection
properties hold the Latin context constant because arbitrary foreign covers
can legitimately defeat the density rule. Other properties validate reports,
offsets into original input, statistics, scattered zero-width bits, and JSON
serialization with ASCII escapes. JSON decoders can join surrogate pairs;
serialization is checked without claiming identical Python string round trips.

## Deliberately unchanged

No layer-two scorer, new carrier rule, or conservative canonicalization mode
was added. No semantic or rendering-aware protection is claimed. All existing
tests, including both out-of-scope historical boundary tests, are unchanged.
Lone-surrogate robustness applies to the Python API and escaped JSON; the
CLI's UTF-8 output behavior was not changed. Only the current runtime was tested.
There is no universal no-crash/no-hang guarantee for unbounded input or exhausted
system memory.
