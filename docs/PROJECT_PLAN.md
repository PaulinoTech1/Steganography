# stegdetect: a practical Unicode security toolkit

Planning date: 2026-10-02. Baseline: `d876974443e1e51ef8f420d7db1b6d25abeb0595`.
Status: roadmap; P0 baseline and an additive preserve-only P1 policy API are
implemented locally. Later phases remain proposals; this document does not
authorize a release. See [P0_STATUS.md](P0_STATUS.md) and
[P1_POLICY_CONTRACT.md](P1_POLICY_CONTRACT.md) for verified scope.
Audience assumption: Python developers integrating retrieved documents and tool results
into RAG and agent applications. Researcher workflows are secondary. Revisit this
assumption after the first three user interviews.

## 1. Product decision and why it can stand out

Build a dependable, offline Unicode inspection and policy component with unusually
clear evidence: what was found, where, why the application took an action, and exactly
what changed before forwarding. Pair it with a local inspection interface and an
open, reproducible evaluation kit.

The central user job is: "Inspect untrusted text at my application boundary without
silently damaging legitimate content, creating a noisy alert stream, or hiding failures."
Success means a developer can install the package, integrate one boundary, understand
an escaped carrier finding, and exercise a blocked-input path in under 15 minutes.
That is a proposed usability target, not an observed result.

Three differentiators should earn the project's reputation:

1. **Evidence and provenance.** Stable rule IDs, original-source coordinates, explicit
   policy actions, optional transformations, reproducible data/rule versions.
2. **Useful Unicode behavior.** Recognize documented legitimate constructions;
   keep strict carrier diagnostics available; preserve content by default in the new API.
3. **Honest evaluation.** Publish missed attacks and accepted blind spots alongside
   false alarms, resource consumption, and versioned regression fixtures.

Compare three strategies before investing:

| Strategy | Strength | Principal cost or failure | Decision |
|---|---|---|---|
| General prompt-injection firewall with a lexical score | Broader headline | Meaning cannot be reliably inferred from keywords; noisy alerts and easy evasion | Research track only, with a release kill gate |
| Unicode toolkit, usable SDK/CLI, evidence viewer | Fits existing implementation; offline, inspectable output | Requires careful Unicode policy and a larger legitimate corpus | Recommended core |
| Hosted gateway with accounts, dashboards, many adapters | Central deployment | Authentication, storage/privacy, operations, and framework maintenance dominate this small core | Defer until pilots demonstrate demand |

There is no evidence yet of market uniqueness or demand. Test the product hypothesis
with three to five independent users rather than claiming superiority over all filters.
The recommendation is a focused route to a distinctive project, not a competitor ranking.

## 2. What is actually known

Repository inspection and diagnostics during planning establish:

| Observation | Evidence | Product implication |
|---|---|---|
| Six Python source modules, a Python SDK and CLI, no production dependencies | `src/stegdetect/`, `pyproject.toml` | Keep the core small and offline |
| 107 tests and previous full-suite success in 42.58s | `docs/ROBUSTNESS.md`; full run in the preceding implementation task | Useful regression baseline, not production certification |
| 41 current CLI/historical/clean-sample tests passed in 0.41s | Planning run: `python -m pytest tests/test_false_positives.py tests/test_historical.py tests/test_cli.py -q` using the existing venv | Confirmed current narrow suite; the full suite was not rerun for this documentation task |
| Legacy non-clean rate 0/16 and non-malicious rate 0/800 across four generated families | `docs/robustness-corpus.json`, `benchmarks/corpus.py` | Different definitions from new policy false-block/interruption rates; not model-boundary prevention |
| Eight below-density homoglyph evasions stayed clean | Same corpus and `tests/test_fuzz.py` | Publish the missed family and its intentional tradeoff |
| Dense findings are per codepoint; all letters and foreign letters are materialized | `scan_unicode()` in `unicode_scan.py` | Memory and output can grow much faster than users expect |
| All bidi controls are high severity, every ZWJ is a finding, all tags are high | Same scanner | Carrier evidence currently implies strong judgments about legitimate constructions |
| Clean text is canonicalized; JSON has no policy/schema version | `report.analyze()`, `Report.as_dict()` | Make forwarding and compatibility explicit |
| Only four generator functions exist for six finding categories | `samples.py`, `unicode_scan.py` | Audit the documented generator convention before expanding coverage |
| No tracked CI workflow was found | `git ls-files .github` returned no entries | Automated installed-package/version coverage is a proposed addition |

Read-only probes of today's API, not new regression tests:

| Input | Current verdict/findings | Current rewrite |
|---|---|---|
| Persian `\u0645\u06cc\u200c\u0631\u0648\u0645` | suspicious / 1 | Removes the ZWNJ |
| Family emoji `\U0001f468\u200d\U0001f469\u200d\U0001f467\u200d\U0001f466` | suspicious / 3 | Removes its three joiners |
| England emoji flag: U+1F3F4 + tags `gbeng` + U+E007F | malicious / 6 | Removes its tags |
| `Label: \u2067\u05e9\u05dc\u05d5\u05dd\u2069` | malicious / 2 | Removes both isolate controls |
| `Total:\u00a0100` | suspicious / 1 | Replaces NBSP |
| `a\u200b\u0301` | suspicious / 1 | First pass strips; second pass composes again |
| `\u0430\u0301` | clean / 0 | First pass maps Cyrillic; second pass composes again |

In a strict UTF-8 stdout probe, `cli.main(['\ud800'])` raised `UnicodeEncodeError`.
This is a CLI encoding observation, not an API scanning crash. The new API must have
an explicit invalid-Unicode contract; existing API behavior remains compatible.

The previously recorded 1,048,576-character timings were 1.079–2.750s. Peak memory,
ordinary small-document p95 latency, installed-wheel behavior on other platforms, and
real application outcomes remain unmeasured. Do not turn these unknowns into claims.
The 800 generated cases share a narrow alphabet and fixed covers. They are not 800
independent real attacks; the curated 16-case set has no defensible deployment FP bound.

## 3. Boundaries that protect the product

- Existing `analyze(text)`, `canonicalize(text)`, CLI defaults, and all original 80
  tests remain regression contracts. Do not change either historical out-of-scope test.
- Add behavior through a distinct opt-in API and CLI mode. A future default change
  requires a separately documented migration and user decision.
- Every new or expanded rule must have a generator in `samples.py`, an evasion test,
  threshold/boundary tests where applicable, and paired legitimate samples.
- Findings establish character/sequence evidence, not the author's intent or an
  LLM exploit. Policy action is separate from detection severity.
- No claim that sanitized text is safe for an LLM, that `clean` excludes plain-text
  injection, or that stripping bidi/homoglyphs removes visible instructions.
- Plain-text and rendering-only injections remain out of scope for the legacy API.
  A separate research scorer cannot silently redefine those tests or verdicts.
- No runtime network access, remote telemetry, model weights, or framework dependency
  in the core. Optional development tools and a later viewer are separate concerns.
- Never mark an unscanned or failed scan as clean. Never silently forward a truncated
  prefix, rewritten fragment, or failed document in an enforcement integration.

Unicode is legitimate application data. UTS #51 defines emoji joiners, tags, and
variation sequences; UAX #9 defines directionality controls. Those structures inform
context recognition but do not prove benign intent. [UTS #51](https://www.unicode.org/reports/tr51/),
[UAX #9](https://www.unicode.org/reports/tr9/).

## 4. Proposed architecture and contracts

Preserve the existing public entry points. Add a bounded, typed path rather than
wrapping the unbounded legacy scan and discarding findings after allocation.

```text
application-owned source/context + untrusted text
  -> validate limits and encoding
  -> bounded carrier scan + recognized-context evidence
  -> trusted application policy
  -> allow / review / block
  -> optional explicit transformation and residual scan
  -> decision + original-source evidence + forwarding candidate
```

The application enforces the decision before a model call. `review` is held for a
decision in enforcement mode; observation mode can explicitly forward unchanged text.
A caller must not treat a returned candidate as permission to call a model.

Suggested new files/symbols (design proposals, not existing interfaces):

| File | Responsibility |
|---|---|
| `src/stegdetect/inspection.py` | `inspect_text(text, *, policy, context=None) -> InspectionReport`; orchestration |
| `src/stegdetect/policy.py` | Immutable `Policy`, `Limits`, action selection; configuration belongs to the application |
| `src/stegdetect/report_v2.py` | Typed reports, schema version, status/action, rule/data versions, transformation spans |
| `src/stegdetect/unicode_scan.py` | Shared bounded evidence engine alongside compatible `scan_unicode()` |
| `src/stegdetect/unicode_context.py` | Exact emoji sequences, joiner/bidi context evidence; no blanket script exemptions |
| `src/stegdetect/canonicalize.py` | Explicit transformation options and original-coordinate edit records |
| `src/stegdetect/render.py` | Escaped bounded CLI excerpts and codepoint/UTF-16 coordinate conversion |
| `schemas/inspection-v2.schema.json` | Versioned public JSON contract; schema validation is a development gate |

Use dataclasses and the standard library initially. Do not introduce a plugin framework,
event bus, microservice, or abstract class hierarchy without concrete consumers.

### Decisions and completion state

The new report must distinguish:

- `status`: `complete`, `invalid_input`, `limit_exceeded`, or `error`.
- `action`: `allow`, `review`, or `block` under the chosen policy.
- `reason_codes`: stable IDs; caller code does not parse English explanations.
- `findings`: retained evidence spans; `finding_count_total`, category counts,
  `findings_truncated`, and `scan_complete` distinguish capped details from skipped work.
- `candidate_text`: unchanged text or the explicitly requested transformation on a
  completed scan; `None` for incomplete/error outcomes. It may also be withheld on block.
- `transformations`: actual changed spans, operation/reason, before/after lengths,
  residual categories; offsets refer to the original string with declared units.
- `schema_version`, library/rules/policy/data versions, runtime Unicode version,
  and caller-supplied opaque source ID. Do not log document bodies by default.

Both complete scans with capped findings and incomplete scans require explicit fields.
`findings_truncated=true` need not mean `scan_complete=false` if all characters and
decision evidence were processed. If an exact count cannot be completed, say so rather
than fabricating a total. Metadata cannot contain attacker-supplied policy overrides.
Bounded retention must reserve an original-coordinate representative for every
action-driving rule; a first-N prefix alone is insufficient. A document with 256 NBSPs
followed by an RLO must show that final RLO and its reason even if whitespace fills the
detail cap. Use deterministic priority retention; reject a cap smaller than the number
of possible action-driving rules or provide a separate bounded decision-evidence field.

### Recommended new policy defaults

Introduce a `balanced` policy for the new API; preserve `legacy` behavior separately.
The new default transformation is `preserve`: no rewriting of any forwarded content.
Recognized legitimate constructions and unusual whitespace are informational evidence
and ordinarily allowed. Unsupported or ambiguous carriers prompt review. Explicit
override/invalid-sequence patterns and validated encoded clusters can block, subject
to the corpus gates below. The exact classification table must be frozen in phase P1;
"valid Unicode" is never used as a synonym for trusted content.

For a recognized emoji, trust only the complete version-pinned sequence boundaries.
Extra tags, trailing payloads, repeated controls, or malformed near-matches must receive
their own evidence. Accepted constructions are an explicit blind spot: an attacker can
encode choices among legitimate characters or sequences. No Unicode filter can infer
that intent just by validating the sequence.

Balanced policy experiments begin in observation mode. Enforcement is released only
when measured false-block and interruption rates meet the gates. If a contextual rule
cannot meet them, retain diagnostic evidence and remove it from automatic blocking.

Offer an explicit `finding_spans` transform only after its edit contract is validated:
rewrite approved finding spans, preserve every unflagged span, and do not normalize
the whole document. A separate opt-in `legacy_nfkc` operation remains available with
its content-change warning. Neither operation proves semantic safety. Preserve mode
must be exactly idempotent; idempotence or composition effects of other transforms
must be tested and reported rather than assumed.

Original offsets use Python codepoints; JSON documents this. CLI may compute line and
codepoint-column coordinates on demand. The viewer must explicitly convert to UTF-16
indices and isolate bidi in displays. Grapheme highlighting is additional presentation,
not a redefinition of forensic coordinates. [UAX #29](https://www.unicode.org/reports/tr29/).

### Limits, streaming, and output

Provisional `balanced` defaults: `max_chars=1_048_576`, at most 256 retained evidence
spans, at most 128 transform spans before refusing that transformation, and excerpts
of at most 80 codepoints. Freeze these as contract values only after P0/P2 measurement.
They are product settings, not proven security limits. Retain exact aggregate counts
with bounded details; never count only the retained list as the total.

Admission limits are checked before expensive normalization/scanning. The string API
cannot prevent a caller from already allocating its input; CLI file/stdin reads must
enforce a byte limit while reading. Output serialization is separately bounded and
must not quietly drop a decision. Process-level timeouts can terminate hostile work;
timeouts belong to the hosting boundary rather than a Python thread that cannot stop it.

Prefer fixed-count passes with capped evidence over storing every letter tuple. Measure
memory including the input, report, optional output, and serialization. Avoid reserving a
large offset array for each character. The runtime scan and transformed-output scan
need separate accounted budgets.

Do not initially stream one document as independently verdictable chunks: homoglyph
density and dispersed zero-width thresholds depend on the whole document. JSONL batch
streaming is safe as a transport only when each record is a complete admitted document.
Future within-document streaming requires whole-document sufficient statistics and
cross-boundary context tests before any release claim.

## 5. Phases, deliverables, and stop gates

Implementation proceeds by gate, not by a promised date. Effort estimates assume one
experienced implementer plus independent review and access to pilot users. They are
planning ranges, not measured productivity. Corpus work starts in P0 and continues
alongside other phases; holdout collection is likely a critical dependency.

| Phase | Outcome | Effort estimate | Validators / prerequisite |
|---|---|---:|---|
| P0 — establish evidence and gates | Reproducible baseline, generator/rule map, corpus protocol, user tasks | 3–5 days | V1, V4, V8; baseline required |
| P1 — make decisions and rewriting explicit | Compatible legacy API plus typed new contract, preserve mode, rule IDs | 4–7 days | V1, V2, V3; P0 |
| P2 — bound hostile work | Input/report/output limits, bounded evidence, latency and peak-memory results | 5–8 days | V1, V2, V5; P1 |
| P3 — make Unicode policy usable | Contextual legitimate constructions, FP corpus, narrowly justified carrier additions | 7–12 days | V2, V3, V4; P1/P2 and corpus |
| P4 — make integration easy | Installed CLI, JSONL transport, standalone RAG/tool-result examples, package CI | 5–8 days | V1, V5, V6; P2/P3 |
| P5 — make evidence understandable | Local evidence viewer; escaped controls, edits, bounded report export | 5–8 days | V2, V3, V6; frozen v2 contract |
| P6 — prove useful in pilots and release | Shadow pilots, measured friction, docs/claim audit, validated wheel and release candidate | 5–8 active days plus pilot elapsed time | V4, V6, V7, V8; P4, viewer optional |
| R1 — lexical scorer experiment | Offline advisory feature experiment; held-out FP/FN and negative result if needed | 5–10 days, optional | V2, V4, V8; never blocks core release |

The core phases total about 34–56 active engineering days before overlap. Budget
approximately 8–12 working weeks including review/rework; recruitment and corpus
curation can extend elapsed time. A useful SDK/CLI milestone can ship before the viewer
or semantic experiment. Do not use a deadline to waive a failed gate.

### P0: evidence infrastructure and the first deliverable

Create `docs/DETECTION_CONTRACT.md`, `docs/GENERATOR_RULE_MAP.md`,
`evals/manifest.schema.json`, `evals/fixtures/`, `evals/splits/`,
`scripts/evaluate.py`, and a minimal `.github/workflows/ci.yml` in small PRs.

- Freeze all existing test bytes and snapshot legacy JSON/exit behavior. Record what
  each test proves; strengthen with new tests instead of rewriting old expectations.
- Map all six categories to `samples.py`. Add generators for invisible formatting and
  unusual whitespace; move or mirror Greek attack-generation coverage into that module.
  Pair each with benign and adversarial fixtures. Keep generator input domains explicit.
- Add the probes in section 2 as regression evidence with current expectations before
  introducing a new policy. An England flag is a deliberate legacy positive, not a
  reason to edit old tests to claim today's scanner has no false alarms.
- Establish per-fixture fields: ID, raw text, original source group, license/provenance,
  task/Unicode strata, carrier labels, intent label when independently known, expected
  policy action per named policy, and transformation constraints. Version the labels.
- Add fixtures for RTL isolates/overrides, Indic/Persian joiners, emoji tags/ZWJ/VS,
  typography, code, scientific notation, legitimate discussions of attacks, quotes,
  multilingual code-switching, absent carriers, and malformed Unicode.
- Reproduce baseline metrics from the wheel and from source; start clean-corpus curation
  and recruit three to five users. No automatic blocking claims from this phase.

Run the actual installed package outside the checkout, not just imports from `src`.
CI should exercise the currently advertised Python 3.9–3.13 range on Linux and Windows
before that compatibility is claimed; macOS runs at least the installed-package smoke
test. A tested, explicitly changed support policy is preferable to silently removing
old versions. Pin development dependencies per supported interpreter when needed.

### P1/P2: useful contracts and limits

Freeze a policy/action table with literal fixture outcomes and a v2 JSON schema before
implementation. Retain the legacy verdict vocabulary in legacy reports; the new API
does not reuse `malicious` as an assertion of intent.

Implement invalid type/Unicode, empty input, policy validation, limit and error paths
first. Legacy accepts its current string domain; the new transport-facing API rejects
lone surrogates with a named invalid-input outcome. Errors do not masquerade as carrier
detections. Explicit escaped inspection remains possible in a developer-only diagnostic
mode, with a different contract from normal UTF-8 forwarding.

Release P2 only when caps apply before allocation of full evidence and work continues
to the end of admitted documents. Test a carrier at the final character, evidence just
after the cap, a forced child timeout, report serialization, and transformation refusal.
No transformed text is forwarded on an incomplete residual scan.

### P3: Unicode correctness and carrier coverage

Start with exact version-pinned emoji sequence data and well-scoped joiner/isolate
context diagnostics. Pin Unicode source URLs, checksums, generation command, version,
and license. Updates occur in reviewed maintenance PRs, never runtime downloads.
Record differences between runtime normalization data and bundled context data instead
of asserting all runtimes have identical Unicode behavior. [Unicode licensing](https://unicode.org/copyright.html).

Keep UTS #39 confusable skeletons as comparison/evidence data; do not use them as
display or forwarding text. Its identifier mechanisms do not automatically validate
free-form prose. Expand detection with measured context and a precise declared scope,
not a blanket conversion of all non-Latin lookalikes. [UTS #39](https://www.unicode.org/reports/tr39/).

Evaluate variation selectors, interlinear annotations, and deprecated format controls
one family at a time. Each candidate needs the generator, independent evasion/boundary
fixtures, legitimate-context evaluation, latency/memory measurement, and a claim-to-test
entry. Repeated variation selectors may yield an anomaly; ordinary emoji selectors and
registered ideographic variation sequences must not be blanket blocked. If legitimate
uses overlap too much, publish the failed experiment and keep it out of enforcement.
[Unicode variation sequences](https://unicode.org/faq/vs.html).

### P4: developer workflows that feel finished

Keep legacy CLI behavior. Add explicit `inspect`/`--v2` paths with schema-v2 JSON,
`--explain`, named policy/transform options, and complete-document JSONL batch mode.
Use separate terminal-safe stderr diagnostics and machine-readable stdout. Define
v2 exit statuses separately: success/allowed, policy-held, and input/system failure;
do not collide with argparse's usage-error code. Decide literal numbers in P1.
Default v2 JSON uses ASCII escapes for all input-derived fields, including candidate
text, filenames, source IDs, and explanations. Valid JSON with literal bidi characters
can still mislead a terminal reader; safe excerpts alone do not solve that problem.

Provide two framework-independent examples: retrieved documents before prompt assembly,
and tool-result text before its next model call. A recorder/stub at the final model-call
boundary proves blocked/reviewed inputs never reach the caller in enforcement mode.
Preserve source IDs and allowlists as application configuration, not document metadata
that an attacker can supply. State that extraction, model permissions, and application
authorization remain separate defenses. [OWASP prompt injection guidance](https://genai.owasp.org/llmrisk/llm01-prompt-injection/).
Inspect original documents before chunking, then exercise the actual untrusted text
passed at the final call boundary with source separation intact. If extraction,
normalization, joining, or other code changes content after inspection, rescan the
changed untrusted content before forwarding. Do not normalize a trusted system prompt
and an untrusted document as one indistinguishable blob.

Avoid synchronous CPU scans inside an async event loop in examples. Demonstrate the
hosting boundary appropriate to the measured workload and cancellation semantics.
Add one optional framework adapter only after two pilot users require the same surface.
Do not maintain five framework wrappers for a two-line function call.

Distribute a wheel/sdist with bundled data and examples. Test both installation and
upgrade from the baseline wheel in disposable environments outside the source checkout.
Check README commands verbatim. Package publication and release tagging require separate
authorization; configure a restricted publishing workflow and attestations when that
release is authorized. [Packaging guidance](https://packaging.python.org/en/latest/guides/section-build-and-publish/).

### P5: a viewer that demonstrates the value

The first inspector can be a generated local HTML report consuming bounded SDK output.
It does not need accounts, storage, uploads, analytics, or a JavaScript detector rewrite.
It shows original escaped codepoints, spans, policy reasons, transformation preview,
recognized Unicode contexts, report versions, and both detected and missed examples.

Treat content as hostile display data. Escape HTML/JSON; never inject document content
as markup or interpolate it into executable scripts. Display bidi-controlled evidence
in isolated escaped form. There must be no fetches, external fonts, telemetry, or
automatic execution. Export omits original text by default; include it only on explicit
user action. Explain when a saved report contains sensitive input.

Validate keyboard operation, screen-reader labels, contrast, astral/codepoint alignment,
malicious filenames, HTML/script/closing-script payloads, and invisible/bidi examples.
Avoid presenting a reconstructed hidden payload as an executable instruction. Exact
decoding is optional and must say which encoding was assumed; not every suspicious
sequence has a recoverable message.

### P6: pilots and a release users can trust

Start with shadow mode in three independent pipelines, using consented or local
replayed documents. Log counts, timings, rule/action IDs, and opaque source IDs only;
store content only if the pilot owner explicitly enables it. Publish aggregate results
and privately preserve minimized counterexamples where disclosure is permitted.

Evaluate at least 1,000 documents per pipeline for the full pilot gate; smaller samples
are preliminary evidence and support only a preview claim. Review every proposed block and a sampled set of
allows/reviews against task labels. Count false interruptions, changed text, latency,
timeouts, override frequency, integration time, and repeated use after two weeks.

Release gates include three target-audience users independently completing the
install/integrate/explain/held-input tasks in <=15 minutes using only public docs in
fresh disposable environments, two retaining and using the integration at day 14,
and no unresolved data-loss or
forward-on-error defect. If access to users is unavailable, release as an evaluated
developer preview and state that real usability is still unvalidated.

Builder assistance counts as an assisted failure, not a passing attempt. After fixing
the usability issue, repeat with a fresh user/attempt and disclose both runs. Each
participant must correctly explain that clean text can contain plain-text injection,
preserve mode leaves content unchanged, and a held decision never authorizes a model
call merely because candidate text exists.

## 6. Evaluation design that resists flattering numbers

The evaluator must separately measure carrier detection, policy action, text fidelity,
and actual application outcomes. A carrier catch is not an LLM attack prevented.

Proposed corpus targets:

- Development: at least 2,000 legitimate documents, with licensed/consented provenance
  and diverse tasks. This is used for design and threshold selection.
- Frozen clean holdout: at least 3,000 distinct original documents across ten predeclared
  mutually exclusive primary task/Unicode strata, at least 300 per stratum. Include complete sequences, not only
  short isolated clean sentences. Do not manufacture "independence" from repeated edits
  of one source document.
- Attack holdout: at least 1,000 carrier cases across separately labeled attack families,
  including unknown covers, dispersal, threshold boundaries, malformed near-matches,
  compositional attacks, script-density dilution, and appended/prepended benign context.
  Give a new claimed family at least 100 cases; publish counts rather than pooling it away.
- Keep plain-text/rendering-only historical cases as out-of-scope controls, not FN
  entries for a carrier-specific recall metric. Report density evasion as an explicit
  missed attack family, even if it is intentionally tolerated.

Split by original document, source group, attack campaign/template, and base payload;
near-duplicates and all their mutations stay on one side. Maintain a deterministic
manifest plus a source/group leakage checker. An independent evaluator holds test
labels and runs the final release candidate; the author does not retune on holdout.
A failed holdout becomes development evidence and requires a newly frozen holdout
for the next release decision. Repeated gates on the same exposed test set overfit.
A successful holdout becomes a regression set too once published or exposed to the
builder; it is not fresh accuracy evidence for a later retuned release. Record who saw
cases/labels, the candidate hash, evaluation count, and exposure state. R1 uses different
holdouts. Ten primary strata: Latin prose/typography, RTL mixed direction, joining-control
prose, Indic, CJK/variation sequences, emoji, mixed-script prose, code/config, science/math,
and security/quoted-instruction documents. Freeze primary assignment rules and sampling
weights in P0; overlapping descriptive tags do not duplicate aggregate denominators.
Independent task/intent labels and action goldens are assigned before seeing candidate
output. A rule cannot validate itself by generating its own expected policy action.

For `balanced` enforcement, initial proposed targets are:

| Metric | Target | Interpretation |
|---|---|---|
| False blocking on legitimate holdout | <=0.5% point estimate and <=1% one-sided 95% upper bound | Blocking error, not raw diagnostic findings |
| False interruption (`review` or `block`) | <=2% overall; publish every stratum | Review also creates work and must be counted |
| Per-stratum false-block upper bound | <=2% simultaneous ten-stratum 95% bounds, >=300 samples per stratum | Bonferroni-adjusted one-sided exact bounds; do not hide minority-language harm |
| Carrier evidence recall for each claimed family, including incumbent families | >=95% on independently labeled in-scope cases | Require correctly located evidence, not an unrelated finding |
| Held-action recall for each enforcement-claimed family | >=95% review-or-block on independently labeled intervention-required cases | An allow-all policy fails; diagnostic catches alone cannot earn enforcement claims |
| Unchanged output under preserve | Exact equality for every complete accepted input | No silent NFKC/confusable rewrites |
| Known application boundary enforcement | All blocked/reviewed fixtures held before the model stub | Wiring is tested, not inferred from helper functions |

These are go/no-go design targets, not today's results. Confidence bounds require a
declared sampling model; curated or correlated synthetic cases do not establish a
deployment probability. Publish raw denominators and source strata. Use source-group
sensitivity/resampling when dependence is material and report its assumptions. Never
use an all-zero percentile bootstrap as an upper-bound proof; it returns zero without
accounting for unseen errors. Synthetic recall is a corpus score, not a binomial
confidence claim. If sampling cannot support the bound, label the score as curated
evidence and release observation/preview rather than claiming validated enforcement.

Use one-sided exact Clopper–Pearson upper bounds: alpha=0.05 overall and alpha=0.005
per primary stratum for ten simultaneous bounds. With zero errors in 300 independent
samples, the adjusted upper bound is `1 - 0.005**(1/300)`, approximately 1.751%; one error
fails the 2% stratum gate. These are conditional arithmetic under the sampling model.
False interruptions must also be <=5% in every stratum as a point-score guard.
Full metric denominators, span matching, errors/limits, and interval implementation
requirements are specified in [PLAN_VALIDATION.md](PLAN_VALIDATION.md).

Freeze held-action goldens for incumbent arbitrary-tag payloads, generated zero-width
encodings, explicit overrides, and declared homoglyph substitution shapes. Golden
contract fixtures all pass; >=95% family recall is a broader corpus target. Accepted
exceptions and intentional density misses are frozen before testing and always
published separately; a failed case cannot be retrospectively relabeled an exception.

Resource targets, to calibrate and freeze on a named CI reference machine in P0/P2:
16 Ki-character input p95 <=50ms; 64 Ki-character p95 <=200ms; admitted 1 Mi-character
hostile input <=5s p95; worker peak RSS <=256 MiB including input/output/serialization;
4x input should take <=6x time beyond timer-noise floor. These are aspirational until
measured, and legitimate reasons exist to revise them before freezing (documented
hardware or profile changes). Do not move a frozen gate merely to pass a regression.

Freeze a workload manifest with construction, sizes, policy, transform, serialization,
and expected outcomes. Use five fixed warmups, 100 measured trials for 16/64 Ki-character
workloads, and 30 for megacharacter workloads, with nearest-rank p95. Measure fresh-worker
peak RSS separately and fourfold growth on paired inputs using median times. Record
every unexpected error/timeout as a gate failure, not a discarded tail sample. Forced
timeout fixtures belong to a separate expected-failure suite. Named CPU/OS/interpreter,
noise floor, and exact limit values are frozen in P0/P2.

Measure uninstrumented latency separately from allocation profiling. Record warmup,
repeat counts, Python/Unicode versions, CPU/OS, input sizes/encoding, peak RSS method,
and failure count. No benchmark can pass solely because it wrote a JSON file: the
evaluator checks verdicts/status, full admitted input length, cap behavior, and outcomes.

## 7. Validators and how they exercise authority

Validation is a set of observable contracts, not a collection of reassuring agent
opinions. Builders and release validators are different identities. The same person
can implement several small changes; an independent reviewer reruns the relevant
gates on the frozen candidate and records actual outputs.

| ID | Validator | Required challenge and pass evidence |
|---|---|---|
| V1 | Compatibility and installation | Original 80 tests unchanged, full suite green, installed-wheel/source parity, supported interpreter/OS matrix |
| V2 | Adversarial/security reviewer | Carrier-after-cap, forged context/policy, malformed accepted sequence, timeout, script/HTML/bidi display, no network and no forwarded failures |
| V3 | Unicode and transformation reviewer | Standards-derived known sequences preserved by policy; valid near-match attacks still analyzed; original-coordinate edits and explicit content fidelity |
| V4 | Evaluation/statistics owner | Independent holdout, source separation, label audit, per-stratum FP/interruptions and misses, raw denominators, qualified bounds |
| V5 | Resource and operational reviewer | CPU/peak RSS/output measurements, threshold extremes, process termination, complete scan after detail cap, batch one-record failures |
| V6 | Developer/user acceptance | Fresh installed CLI/SDK tasks and final model boundary, no special test setup, comprehension, UI tasks when viewer ships |
| V7 | Release and supply-chain reviewer | Wheel/sdist manifests/data/license, upgrade and rollback, no core network/dependency surprises, authorized publishing path |
| V8 | Claims and product reviewer | Every README claim mapped to named evidence; accepted limitations visible; no semantic prevention claims from Unicode detection |

At least one injected known failure must make each automated validator go red. Examples:
drop an EOF finding; ignore a timeout; forward a held result; rewrite a recognized emoji;
leak a control into a terminal excerpt; contaminate a holdout with a duplicate; remove
bundled data from a wheel; add an unsupported detection claim. Then restore the fixture
or implementation and rerun the gate. Record the failing output as well as the pass.

Candidate receipts include git revision, policy/data version, corpus manifest digest,
command/exit code, relevant stdout/stderr, resource environment, detected limitations,
validator identity, and verdict. Hashes bind the evidence to a candidate; they do not
substitute for rerunning the test. `NOT RUN`, missing data, or unavailable platform
coverage cannot be summarized as `PASS`.

P0 must implement `python scripts/validate_release.py --profile baseline`; later profiles
add mandatory core, enforcement, viewer, and release gates as defined in the companion
matrix. All return nonzero for missing/failed mandatory evidence. These are planned
commands, not available scripts. A maintainer makes release decisions from receipts;
no agent can approve away an enforcement contract violation (forwarding held, errored,
or incomplete results), data corruption, or mislabeled evaluation. Statistical policy
misses are separately measured against the frozen family target and disclosed; accepted
covert-channel blind spots do not silently redefine the enforcement contract.
Detailed validator execution contracts and this plan's own reviews live in
[PLAN_VALIDATION.md](PLAN_VALIDATION.md).

## 8. Optional layer-two experiment and stop rules

An offline lexical scorer is a separate API returning feature evidence and an advisory
score, never a probability unless calibrated and independently validated. Features can
include requests to change roles, ignore instructions, disclose hidden prompts, invoke
tools, or send data externally. Simple weighted features are the initial baseline;
no weights/model service/network are required for that experiment.

Use whole-source-separated legitimate emails, code, quotations, security documentation,
translations, and task instructions. Quoted descriptions of attacks are essential FP
cases. Compare against a trivial keyword baseline, test whitespace/case/Unicode and
paraphrase evasion, and publish the miss matrix. A narrowly scoped lexical method can
lose badly on meaning-preserving paraphrases; report that rather than relabeling them.

For an advisory experiment, require <=2% legitimate false-interruption rate on an
independent >=3,000-document clean holdout and >=70% recall on a separately labeled
plain-text-injection corpus before packaging it as experimental. These are proposed
decision thresholds, not evidence that such a scorer is feasible. It cannot inherit
the Unicode corpus or be presented as production enforcement.

Kill or defer the shipping experiment after the fixed 5–10-day spike if these gates
fail, if performance is achieved only by threshold tuning on holdout, or if it adds
no practical value over the baseline. Publish the negative result and keep the useful
Unicode toolkit moving. Do not bundle a weak lexical rule into the legacy detector.

## 9. Risks, checkpoints, and decisions waiting on the owner

| Risk | Early signal | Response |
|---|---|---|
| False alarms hurt international users | High review/block rates in joiner/emoji/RTL strata | Diagnostic-only contexts; tighten scope; stop blocking rule |
| Exceptions create covert channels | Payload hidden in accepted sequence choices or near-matches | Document accepted channel; detect malformed/extraneous spans; no safety claim |
| Transformation corrupts content | Unflagged spans change or repeated rewrite changes meaning | Preserve default; block optional transform release until edit contract passes |
| Caps hide late carrier evidence | EOF/after-cap tests fail or completeness misreported | Fix bounded engine; fail closed at integration boundary |
| Corpus gives flattering scores | Duplicate/templates dominate or holdout reused | Independent source split and label review; replace exposed holdout |
| Version/Unicode drift changes decisions | Interpreter or bundled-data update changes golden evidence | Versioned behavior/diff review; migration notes and conformance tests |
| Inspector becomes an injection surface | Raw markup/bidi reaches display or report fetches external assets | Escape-only display and local browser security tests |
| Nobody retains the integration | Users disable noisy policies or need handholding | Fix developer flow and review volume before new rule count |
| Scope expands into a platform | More adapter/hosting work than detector usability | Cut optional surface until shared pilot demand exists |

Checkpoints: P0 evidence protocol, P1 frozen API/policy contract, P2 budget report,
P3 independent policy holdout, P4 install/integration recordings, and P6 release receipts.
Each checkpoint names unresolved assumptions and the next smallest executable slice.

Owner choices affecting later work: primary audience; strict security tolerance versus
balanced document fidelity; willingness to recruit pilot users; distribution through
PyPI; and whether a visual inspector is required for the first release. Current
recommendation: balanced SDK/CLI first, preserve by default, inspector next, lexical
scorer gated separately. These recommendations can be changed before implementation;
they do not authorize deployment, publication, or broad product work.

## 10. Immediate next implementation slice

Start with **P0**, not a new carrier or semantic scorer. Ship a small internal evidence
milestone: rule/generator inventory, probes pinned as additive tests, corpus schema,
installed-wheel smoke check, and one CI path. Have V1/V4/V8 demonstrate a failing gate
and a passing gate. The deliverable is a reliable baseline from which P1 can be judged.

Before executing P1, write a bounded spec with the exact API fields, policy table,
schema/exit-code values, literal test fixtures, changed files, and runnable verification
commands. Freeze and adversarially review it. Later phases get their own bounded specs;
this roadmap intentionally does not pretend that an untested future classifier has
already been designed or validated.
