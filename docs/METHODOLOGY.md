# Project methodology for maintainers and reviewers

## What the component establishes

`stegdetect` inspects Unicode carrier evidence in untrusted text before an
application may pass that text to an LLM. A finding means a configured
character or pattern occurred at an original Python-codepoint offset. It does
not establish intent, successful exploitation, or the safety of the rest of
the document. Plain-text injections and rendering-only tricks remain scope
boundaries in [`HISTORICAL_ATTACKS.md`](HISTORICAL_ATTACKS.md).

Keep three questions separate in every review and measurement:

1. **Evidence:** Was a carrier correctly located and counted on the original
   text? The six rules and generators are mapped in
   [`GENERATOR_RULE_MAP.md`](GENERATOR_RULE_MAP.md).
2. **Decision:** Did the trusted named policy choose `allow`, `review`, or
   `block` from that evidence? A held decision has no forwarding candidate.
   The policy table is in [`P1_POLICY_CONTRACT.md`](P1_POLICY_CONTRACT.md).
3. **Application outcome:** Did the caller actually withhold held, failed, or
   incomplete text from its final model call? Only an integration test at that
   boundary can establish this.

The original `analyze()` and CLI default are compatibility contracts. They
still canonicalize text, including some clean-verdict text. New work uses the
additive `inspect_text()`/`inspect_bytes()` and `--inspect` CLI path. Do not
weaken either out-of-scope test in `tests/test_historical.py` to improve a
score.

The bounded inspector emits schema v3. The committed v2 schema is retained
unchanged for earlier reports; v2 consumers must explicitly migrate to v3
before accepting new output. This is a transport contract change, even when
the named policy returns the same action.

## Change and review process

For bounded-path changes, keep the sequence reviewable:

1. Record the current branch, working-tree state, and full-suite result. Keep
   the original `analyze()` fixtures and the two historical out-of-scope tests
   intact. Check the published schema before changing report fields.
2. State the input admission, evidence-retention, output, and forwarding
   invariants. Add tests at each cap boundary, with a late deciding carrier
   after the retained-detail cap and a forced scanner failure. Compare both
   policy outcomes and uncapped evidence against the legacy scanner on
   generated Unicode inputs.
3. Implement the bounded path without changing legacy behavior. Version the
   report schema if its shape or status domain changes; retain earlier schema
   files. Verify the new schema and installed-wheel CLI output.
4. Run `python -m pytest -q`, then the full resource profile below on the
   final measured source. Review raw trials and unexpected outcomes before
   running `scripts/validate_resources.py --record`. The receipt binds results
   to source bytes; never refresh it merely to silence a mismatch.
5. Update the claims and resource table from that artifact. Run
   `python scripts/validate_release.py --profile bounded`, which checks the
   suite, protected fixtures, deliberately broken controls, source/installed
   wheel parity, and the resource receipt. Review the staged diff and confirm
   the earlier schema remains unchanged before committing.

For this P2 change, the final local gate reported 253 passing tests, 30
development fixtures, 60 installed policy cases, three bounded installed
smoke cases, five negative controls, and 21 resource rows with 1,610 trials
and zero timeouts. Those results support this implementation on the recorded
Windows runner; CI on other operating systems and Python versions is still
pending. The original v2 schema was checked against `HEAD` with no diff.

## How a change earns a claim

Write intended behavior and an adverse case before implementation. Every new
detection rule needs a generator in `samples.py`, a positive test, an evasion
or threshold test, and a legitimate-content test. Exact examples are useful
regressions but do not prove population recall.

The evaluation unit is one original document. The manifest records provenance,
source group, split, Unicode/task stratum, carrier and intent labels, expected
legacy result, named-policy action, and preservation constraint. Source and
duplicate-text leakage across splits is rejected. The current 30 examples are
all project-authored development fixtures; no independent or held-out
accuracy estimate exists. The 16 curated clean samples and 800 generated
cases are separate narrow baselines, not deployment rates. Publish raw
numerators and denominators, missed families, and versioned fixtures. See
[`CLAIMS.md`](CLAIMS.md) for current scoped counts.

Run the full suite and installed-wheel validator before merging. The validator
checks protected original test bytes, literal API/CLI outcomes, generator/rule
mapping, source/split integrity, source-vs-wheel parity, and deliberately
corrupted negative controls. A validator that prints PASS without failing a
broken control has failed its purpose. Later `core`, `enforcement`, and
`release` profiles in [`PLAN_VALIDATION.md`](PLAN_VALIDATION.md) are
specifications, not achieved gates. Independent human review is needed for
Unicode language fidelity and claim wording.

## Hostile-input contract in the additive path

`Limits()` defaults are 1,048,576 Python codepoints, 4,194,304 UTF-8 bytes for
`inspect_bytes()` and the new CLI's file/stdin read, 256 retained findings,
and 16,777,216 bytes of compact ASCII JSON. The minimum evidence cap is six,
one slot per currently mapped category. These are product settings, not proof
of safe resource use on every host. The string API receives an already
allocated object; its character limit only bounds subsequent work. The old
`analyze()` and old CLI path remain unbounded.

The bounded scanner makes a statistics pass and a finding pass. It retains
only the first capped findings plus one priority witness per observed
category, replacing an earlier bidi witness with a later explicit override.
It counts all findings and categories to the end of the admitted document.
Thus `findings_truncated=true` can coexist with `scan_complete=true`, while a
late action-driving carrier remains visible. Policy decisions use the full
summary, never just retained details. Parity tests compare uncapped small
documents against the frozen legacy scanner.

`as_dict()` is an in-memory structured view; `to_json()` is the capped,
ASCII-escaped transport. A document whose serialized report would exceed the
output budget gets `limit_exceeded` with no action or candidate instead of
truncated JSON. Admission and decode failures also have no action or
candidate. Serialization constructs the payload before checking its byte
length, so the output cap limits emitted JSON, not transient allocation.
The new CLI reads at most byte-limit-plus-one and returns exit 0
for allowed complete input, 3 for review/block, 4 for invalid/limit/error,
and argparse's 2 for usage errors. A process deadline belongs to the caller
or worker: a Python thread timeout cannot reliably stop hostile CPU work.

## Reproducing resource measurements

Install development dependencies, then run:

```bash
python -m pip install -e ".[dev]"
python benchmarks/resources.py --output docs/p2-resource-results.json
python scripts/validate_resources.py --record
python benchmarks/context_resources.py --output docs/p3-context-results.json
python scripts/validate_context_resources.py
python scripts/validate_release.py --profile bounded
```

The full profile covers ordinary text, dense zero-width, nested bidi, mixed
script, compatibility combining marks, supplementary emoji, and a final
override at 16,384, 65,536, and 1,048,576 codepoints. It uses two killable
latency workers per workload/size, five warmups per worker, 100 measured
trials for each smaller size, and 30 for a megacharacter case. Timing includes
inspection and `to_json()` but excludes process startup and input construction.
It reports raw times, median, maximum, and nearest-rank p95
(`sorted_times[ceil(.95*n)-1]`); a timeout or unexpected outcome makes the
command fail and records partial results. A separate worker reports OS
process peak RSS before input and after input, scan, and serialization. On
Windows this is PeakWorkingSetSize; on Linux/macOS it is `ru_maxrss` with
platform-specific units converted to bytes. Baseline/peak include the
interpreter. They are not `tracemalloc` heap values or universal guarantees.
The output JSON records Python, platform, processor, Unicode version, input
bytes, serialized bytes, expected action/count, and raw trials.
`scripts/validate_resources.py` recomputes row counts and percentiles from the
raw trials and checks a receipt binding the artifact to the measured source
files. A source change requires a fresh full resource run; a static CI check
of this receipt does not measure performance on that CI runner.

For a quick diagnostic, pass a subset such as `--cases ordinary zero_width
--sizes 16384 --trials-small 2 --workers 1`; label it a subset and do not use
its p95 as the full gate. Repeat the full profile on reference runners before
claiming a cross-platform budget or latency target. There is no latency SLA.

The separate contextual preview measures four 1,048,576-codepoint
constructions: repeated valid family emoji, Persian joining, simple RTL
isolates, and an unrecognized ZWJ. Each runs in a killable worker with two
warmups and 10 measured inspection-plus-serialization trials, then records
OS peak RSS. At 10 trials, nearest-rank p95 is simply the maximum and is
especially weak as a tail estimate. The artifact embeds hashes of the
measured scanner, policy, context module/data, and benchmark script;
`scripts/validate_context_resources.py` checks complete rows, raw trials,
decisions, and current source hashes. Neither profile measures an entire
RAG application or establishes a resource SLA.

When scanner, policy, schema, corpus, or limits change, update the literal
contract first, rerun affected negative controls and installed-wheel checks,
then measure resources again. Record failures and limitations rather than
editing old goldens to erase them. Changing enforcement defaults needs
independently sourced benign/adversarial holdouts, application-level
no-forwarding tests, and the later release gates.

## Unicode context and developer workflow process

The opt-in policy's [contract and data provenance](UNICODE_CONTEXT.md) pin
Emoji 18.0 source files, checksums, generator, license, exact valid
constructions, and malformed neighbors. The original evidence and default
policy are frozen separately; the new policy gets literal action goldens and
its own schema version. Compare both policies on the same development
fixtures and report held benign and allowed attack numerators separately.
Do not treat RGI validity as a benign-intent label.

The [developer workflow guide](DEVELOPER_WORKFLOWS.md) defines byte/record
budgets, stream format, exit codes, and safe explanations. Its tests use a
model-call recorder to verify that a held document or tool result cannot be
forwarded through the examples. A real integration must repeat that check at
its own final model-call boundary; a library unit test cannot verify a host
application's routing. Review batch partial-output and terminal escaping
cases before claiming CLI usability.

The final local bounded preview gate on 2026-10-02 reported 318 passing tests,
30 contextual installed-wheel fixture outcomes, two installed developer CLI
cases, 12 claim mappings, and six deliberately failing negative controls.
Its default-path resource receipt
covered 21 rows and 1,610 trials; the contextual artifact covered four rows
and 40 trials. Both recorded zero timeouts. Other operating systems, Python
versions, independent language review, and production model-call routing
remain unverified locally.
