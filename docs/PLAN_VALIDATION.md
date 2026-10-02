# Validator contracts for the project roadmap

Date: 2026-10-02. Companion: [PROJECT_PLAN.md](PROJECT_PLAN.md).
This defines implementation gates and records planning validation. The
`baseline` and `bounded` profiles now exist; `core`, `enforcement`, `viewer`, and `release`
profiles below remain specifications. No unrun gate is described as achieved.

## 1. Decision authority and evidence format

Each implementation slice has a builder and a different validator. A validator reads
the frozen specification and candidate revision, challenges one failure axis, and
runs the actual public entry point where possible. Reviewers may use agents; independent
human Unicode speakers and pilot users are needed for language/task fidelity. An
agent's opinion cannot replace a test output or a real-user observation.

Mandatory evidence receipt fields:

```json
{
  "gate_id": "V2",
  "candidate_revision": "actual git SHA",
  "spec_revision": "digest of the frozen specification",
  "policy_version": "actual version or not_applicable",
  "data_versions": {},
  "corpus_manifest_digest": "actual digest or not_applicable",
  "builder_identity": "recorded identity",
  "validator_identity": "different recorded identity",
  "environment": {"python": "actual", "os": "actual", "unicode": "actual"},
  "runs": [{"argv": [], "exit_code": 0, "output_artifact": "path"}],
  "negative_control": {"introduced_failure": "specific fault", "observed_failure": "output"},
  "limitations": [],
  "verdict": "PASS|FAIL|NOT_RUN"
}
```

The JSON is a receipt shape, not a pre-filled PASS report. Run commands independently
of the receipt and rederive key metrics from raw output. Zero tests collected, empty
corpus, missing results, missing mandatory platform, or self-supplied PASS strings fail.
Digests bind evidence to its input; they do not prove that a validator ran correctly.

Suggested implementation location: `scripts/validate_release.py`. Literal profile
matrix below defines mandatory subgates; full V1–V8 contracts are scoped by these flags:

| Profile | Mandatory gates | Earliest phase / permitted claim |
|---|---|---|
| `baseline` | V1 legacy/install baseline, V4 development schema/split integrity, V8 baseline claim map | P0: baseline evidence only |
| `bounded` | Baseline plus P2 cap/EOF tests, contextual and developer workflow tests, installed-wheel smoke, and source-bound local P2/P3 resource artifacts | P2/P3/P4 previews: scoped local observations; no cross-platform resource or enforcement guarantee |
| `core` | V1/V2/V3/V5 implementation challenges, V4 development integrity/scores, V6 automated final-boundary examples, V7 wheel/data/offline checks, V8 preview claims | P4: SDK/CLI observation preview; no validated enforcement FP claim |
| `enforcement` | Everything in core plus V4 independent holdout/sampling/bounds/action-recall gates | P4/P6: opt-in enforcement candidate for consented pilots; usability still pending |
| `viewer` | Core plus V2 display adversary, V3 browser coordinate tests, V6 browser accessibility/tasks, V8 viewer scope | P5: viewer preview; does not substitute for enforcement or pilots |
| `release` | Enforcement plus V6 three-user task/two-pipeline retention/three-pipeline sampling evidence, V7 upgrade/rollback/release workflow, V8 current release claims | P6: measured core release; publishing still separately authorized |
| `r1` | Core plus independent R1 task-label/holdout/baseline/FP-recall gates under V2/V4/V8 | R1: separate experimental advisory scorer only |

When a viewer is distributed with enforcement/release/R1, `--with-viewer` additionally
requires every viewer-specific gate. Missing pilot evidence permits only a preview,
not a full release PASS. Bounds unsupported by the sampling model fail enforcement,
while curated scores can still support a clearly scoped core preview. This matrix
does not authorize deployment/publication or make future commands available today.

Keep phase readiness and feature-release readiness separate. A P0 PASS cannot be
promoted to a core/release PASS merely because future scripts have not been written.
Inapplicable optional gates are explicitly scoped out before the run; mandatory gates
cannot be relabeled optional after failure. Local limitations are honest `NOT_RUN`;
the release matrix needs actual remote runner receipts before claiming support.

## 2. Eight validator execution contracts

| Gate | Deliverable / scope | Required evidence | Negative control |
|---|---|---|---|
| V1 compatibility | `tests/test_compatibility.py`, `tests/test_distribution.py`, CI matrix | Existing 80-test bytes unchanged; 107 baseline cases retained; full suite; installed wheel outside checkout matches public legacy API/JSON/CLI fixtures | Remove bundled file or change legacy field/exit; installed test must fail |
| V2 adversarial security | `tests/test_policy_adversarial.py`, integration/display probes | Unknown text cannot set policy/source trust; carrier after cap/EOF affects action and remains visible as decision evidence; incomplete work held; all input-derived stdout escaped | Force timeout or forged trusted role, hide the deciding carrier, or emit raw bidi in JSON; gate must fail |
| V3 Unicode/fidelity | `tests/test_unicode_context.py`, `tests/test_transformations_v2.py`, standards provenance | Exact valid fixtures have intended named-policy action; malformed near-match retains evidence; preserve output exactly equal; targeted edits change only authorized original spans | Rewrite a ZWNJ/emoji or an unrelated unflagged span; fidelity gate must fail |
| V4 evaluation | `scripts/evaluate.py`, frozen manifests, independent label audit | Recomputed FP-block/interruption, carrier and held-action recall for incumbent/new families, independent goldens, verified source separation, raw denominators and qualified uncertainty | Allow-all policy, cross-split duplicate, relabeled benign block, omitted missed family, or stale manifest must fail |
| V5 resources | `benchmarks/resources.py`, killable workers and raw runs | p50/p95 from sufficiently repeated calls; peak RSS and output sizes; admission and result caps; full scan after detail truncation; documented runner | Allocate all million findings before cap, or omit final carrier; worker/gate must fail |
| V6 developer/user | `examples/rag_gate.py`, `examples/tool_result_gate.py`, `tests/test_developer_workflows.py`, installed-wheel smoke, pilot task record | Installed package and CLI without test-only path setup; exact final model-boundary input and call counts; user comprehension and task completion | Catch error then forward original, skip final boundary, or drop supplied policy; integration gate must fail |
| V7 distribution | `tests/test_distribution.py`, wheel/sdist inventory, release workflow | Bundled Unicode data/licenses/schema; offline runtime; baseline-to-candidate upgrade and rollback; authorized publishing identity and artifacts | Remove data/license from archive, require an undeclared dependency, or unexpected network call; gate must fail |
| V8 claims/product | `docs/CLAIMS.md`, release README, usability/pilot record | Each claim has scope, fixture/run ID, version and limits; unmet goals remain targets; scope boundaries visible | Add unsupported "prevents prompt injection" or a global FP claim from synthetic cases; review must reject |

Use small file-disjoint builder changes and sequential reviews on frozen artifacts.
No parallel builder may modify the candidate while its validator is reading it.
A changed candidate invalidates the relevant receipt and needs rerunning affected gates.
Run deliberately broken controls in disposable candidate copies or isolated process
injections. Do not mutate the real source/corpus during release review. Both the local
check and aggregate validator must return nonzero; a local failure swallowed by the
wrapper is a failed validator. Human V8 still judges whether a mapped test proves the
prose, even if a machine checks that every claim has a mapping.

### V1: compatibility and installed distribution

Run source tests and installed-wheel smoke tests separately. `python -m pytest` uses
the repository's configured `pythonpath=src`; by itself it does not prove installation.
Build artifacts, create a disposable environment outside the checkout, install the
wheel, run the public CLI, and inspect the imported module path. No extra `PYTHONPATH`.

Freeze legacy fixtures for JSON keys, offsets, counts, exit codes, canonicalization,
and historical out-of-scope cases. Keep the original tests rather than deleting them
and reporting a similar count. New fixtures may expose additional limitations; do not
force legacy behavior to change to pass a new-policy expectation.

Gate runner proposal: `python scripts/validate_release.py --profile baseline`.
Expected: nonzero on changed protected tests, failed wheel smoke, or absent mandatory
baseline evidence. Full version/OS coverage is produced by CI, not simulated locally.

### V2/V3: observable hostile cases and Unicode policy

Required cases include empty input, wrong type, lone surrogate, oversized input,
invalid UTF-8 file, binary-looking input, missing file, broken pipe, forced worker kill,
unknown policy, malformed recognized context, mixed-script density dilution, and
adversarial carriers placed just beyond every evidence/output boundary.

Known examples come from official sequence/property data plus independently reviewed
human text. Testing valid Unicode is different from testing benign intent. An accepted
emoji choice sequence used as a covert channel is an accepted limitation, not proof
that recognizing an emoji makes it safe. Explainable evidence must survive context
recognition and cannot be erased by the scanned document's self-description.

Preserve mode must return unchanged complete input. Optional edits need exact mappings
for deletion, one-to-many expansion, many-to-one composition, reordering, supplementary
characters, overlapping spans, and adjacent marks. If exact targeted mapping cannot be
made reliable, ship preserve-only plus explicit legacy transforms and mark targeted
transformation unavailable. No arbitrary "confusable skeleton" forwarding.

The adversary supplies evasion cases independently of the builder's generator list.
Generator-positive tests prove the promised narrow shape; unknown covers and near-matches
are different evidence. Each new rule must pass both and publish deliberate misses.

### V4: metric definitions and label integrity

Define one evaluation unit as one original admitted document. Record source grouping
and all derivatives. Labels distinguish carrier presence, construction/task intent,
expected action for each named policy, and content-preservation constraints.

For a named policy:

```text
false_block_rate = legitimate documents with block action / legitimate documents
false_interruption_rate = legitimate documents with review or block / legitimate documents
carrier_recall = eligible carrier documents with correctly located required evidence / eligible carrier documents
action_recall = independently intervention-required documents receiving review or block / those documents
mutation_rate = accepted preserve documents whose candidate differs / accepted preserve documents
```

Eligibility, construction/task labels, family boundaries, and intervention-required
goldens are frozen independently of the candidate policy's output. For carrier recall,
match a required rule/category and an original-coordinate event from the fixture's
span set: an unrelated finding or a whole-document span with no declared sequence
bound cannot count. Detail-capped cases require a correctly located decision witness
and verified aggregate counts; they do not require displaying every encoded bit.
Freeze the exact matching rule in the corpus manifest and test broad/shifted false spans.
All golden contract fixtures must pass; the broader family holdout has the >=95% target.
An allow-all policy must fail action recall for all enforcement-claimed incumbent and
new families even if its evidence recall and clean-corpus scores are excellent.

Always show invalid/error/limit outcomes separately; a policy test must not pass by
rejecting every legitimate document as oversized. For a declared admitted holdout,
unexpected errors or limits are failures and appear in the operational interruption
count. Input limits are evaluated in a separate oversized-input suite with expected
failure labels. Report missing/unevaluable documents in the denominator ledger.
Policy FP numerators count complete scans taking the named action, while their
denominator includes every independently valid within-limit legitimate document.
Unexpected errors/limits may not shrink that denominator; they separately fail the
admitted-workload completion gate and count as operational interruptions. Zero
forward-on-held/error/incomplete is a distinct enforcement invariant, not a promise
of zero statistical detection misses. Intentional exceptions cannot be added after
the candidate fails them.

The aggregate goal does not excuse a harmful Unicode stratum. Display every stratum,
sample count, source mixture, overlaps, and a frozen weighting rule. Do not recompute
weights after seeing the failures. Show unweighted and deployment-weighted results
only when deployment weights have an independent basis.
Ten primary strata are mutually exclusive; additional tags may overlap. The balanced
corpus's average is not an estimated production-traffic average without an independently
established traffic sampling/weighting model.

Use one-sided exact Clopper–Pearson upper bounds with alpha=0.05 for the aggregate and
alpha=0.005 per primary stratum (Bonferroni simultaneous 95% for the ten frozen strata).
For nonzero failures `k<n`, the upper limit solves
`P[Binomial(n, upper) <= k] = alpha`; `k=n` gives 1. Implement a numerically stable
CDF/root or trusted inverse-beta method with fixed reference tests, including extremes.
Do not use an unspecified choice of interval to make a candidate pass.

Under independent Bernoulli sampling, zero failures/300 gives 0.9936% pointwise95 upper
and 1.7506% with alpha=.005. For the plan's simultaneous <=2% stratum gate, zero/300
passes but one/300 fails. These calculations do not establish sampling independence
or representativeness. Curated/correlated data can only support a corpus score unless
an independent evaluator justifies the sampling model. If it cannot, enforcement
validation fails and the available result is a preview/observation measurement.

For material source dependence, publish group-level sensitivity/resampling and its
sample-size limitations. An all-zero ordinary percentile bootstrap gives a zero upper
bound and is prohibited as a confidence gate for unseen errors. Report overall and
per-stratum raw counts alongside bounds. Freeze alpha, family scope, and strata before
looking at the candidate, and do not redefine the denominator to discard misses.

Holdout ledgers record access to raw cases/labels, number of evaluations, candidate
hash, and exposure state. Both successful and failed exposed/published holdouts become
regression data for future retuned releases. New policy tuning requires a new holdout;
the optional lexical experiment uses its own distinct task-labeled holdouts.

Document-level zero findings is not necessarily an FP win: a parser that inspected no
text fails the empty-input/coverage checks. Block-rate reduction achieved by allowing
every attack fails action recall. Denominator and action labels are independently audited.

### V5: honest resource accounting

Use a worker process with a process-wide deadline. Measure peak RSS with OS-appropriate
tools; `tracemalloc` alone is not process RSS. Report whether baseline interpreter/input
memory is included, and include result serialization. Separate warm latency measurement
from memory-profiler overhead. Use at least 30 measured repetitions for ordinary p95
workloads, distributed across workers. Freeze five warmups, 100 measured trials per
ordinary16/64 Ki-character workload and 30 per megacharacter workload; use nearest-rank
p95 (`sorted_times[ceil(.95*n)-1]`) plus medians, maxima, and timeout counts. The 30-run
hostile tail estimate is limited; publish raw times and do not claim a latency SLA.
Do not manufacture a reliable tail from the three historical benchmark timings.

Run dense carrier, mixed-script, nested-bidi, ordinary prose, compatibility-combining,
large transformations, serialized reports, and many-record batch cases. Validate the
contents and completeness of each report, not only how quickly the child exits.
Exercise admission limits at just below, equal, and above the bound.
The workload manifest freezes input construction, character/byte size, policy/transform,
serialization path, expected status/action/count/witness, CPU/OS/interpreter, and noise
floor. Growth uses paired small/large profiles and medians. Unexpected errors/timeouts
on admitted workloads fail even when fewer than5% of runs and below the p95 index.
Forced-timeout tests are separate expected-failure cases; they cannot be discarded
from timing data and mislabeled as normal successful scans.

Reference-runner targets are ratified before implementing optimizations. If the 256 MiB
or latency proposal is impractical, document the measured baseline and change the
product budget before freezing it; after freezing, a failing implementation needs a
fix or a profile change with rationale, not an unexplained relaxed threshold.

### V6: real integration and task acceptance

The most important E2E assertion is at the final caller: zero model calls for held or
failed inputs in enforcement mode, and expected unchanged/transformed text for allowed
complete inputs. Test retrieval, document chunking, prompt assembly, and tool-result
forwarding. Check that application-owned provenance cannot be overwritten by content.
Test async usage/cancellation at the actual example boundary.

Five proposed tasks for an unfamiliar user:

1. Install the wheel and scan a local document.
2. Add the package to a stubbed RAG or tool-result boundary.
3. Explain a carrier finding and distinguish it from confirmed malicious intent.
4. Exercise the block/review/error path and confirm the model was not called.
5. Explain why a plain-text injection can still pass and why preservation matters.

Recruit at least three independent participants; aim for five. Each participating
pipeline must have a task completion record and a two-week retention observation.
Capture elapsed time, assistance, failures, and corrections, not just satisfaction.
Small samples support task observations, not a universal usability rate.
The three-person core rubric requires each participant to complete tasks1–4 in <=15
minutes with public documentation and no builder intervention. Assistance counts as
an assisted failure; after fixes use a fresh attempt/user and retain the failed receipt.
Task5 requires correct answers to all three questions: clean does not exclude visible
injection; preserve leaves content unchanged; held action prohibits a model call even
if candidate text exists. Retention means a working integration demonstrably used on
day14 in at least two pipelines. Full pilot sampling requires >=1,000 documents in
each of three pipelines; smaller samples cannot silently earn the full release PASS.

If the viewer ships, add keyboard/screen-reader/display tasks and use actual browser
checks for escaped hostile data, CSP/no-network behavior, and coordinate alignment.
If pilots are unavailable, report that limitation and ship a developer preview rather
than manufacturing user validation from automated tests.

### V7/V8: release conditions and claim traceability

Release documentation lists package/API/policy versions, data/runtime Unicode versions,
supported platforms with actual run evidence, install/upgrade/rollback commands,
resource profile, what is detected, accepted evasions, and what remains out of scope.

Each public claim needs: exact wording, scope, named test/measurement, candidate version,
raw result, and explicit limit. Distinguish retained historical measurements from current
release measurements. No unsupported "all Unicode," "never hangs," "production-safe,"
or semantic-prevention statement. A schema/conformance claim needs conformance evidence.

Version/data-only updates still run relevant gates. Changes to policy, limits, recognized
contexts, transformations, or claimed scope need a measured behavioral diff and migration
notes. Distribution authentication establishes publishing provenance, not runtime safety.

## 3. Validation of this plan

Planning work performed:

- Inspected the current source, tests, package configuration, corpus results, and README.
- Reproduced legitimate-context flags, non-idempotent rewrite counterexamples, and the
  strict UTF-8 CLI surrogate error using bounded read-only diagnostics.
- Ran the current CLI/historical/false-positive suites: **41 passed in 0.41s**.
- Read primary Unicode and packaging documentation and OWASP's prompt-injection guidance.
- A read-only researcher independently supported the focused offline evidence/policy
  strategy and identified the generator-convention gap and genuine Unicode use cases.
- Independent adversarial and evaluation reviews challenged the frozen roadmap. Their
  findings, resulting revisions, and final dispositions are recorded separately in
  [PLAN_REVIEW.md](PLAN_REVIEW.md).

Planning validation is not implementation validation. No new API, rule, policy, corpus,
resource budget, or release validator has been implemented in this task.
