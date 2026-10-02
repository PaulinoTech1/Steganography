# stegdetect

A Unicode carrier pre-filter for text sent to a language model.

`stegdetect` inspects Unicode *carriers*, not instruction meaning. It runs locally with no GPU, model weights, or network calls. The tests exercise specific carriers and legitimate samples; they do not establish prompt-injection prevention or accuracy across all languages and models.

## How it works

```
untrusted text -> analyze() -> { verdict, findings, sanitized } -> LLM
```

1. **Detect** invisible and deceptive Unicode: zero-width characters, bidi overrides, homoglyph (mixed-script) substitution, Unicode tag characters, suspicious whitespace.
2. **Verdict**: `clean`, `suspicious`, or `malicious`, with per-finding severity, offsets, and codepoints.
3. **Canonicalize**: normalize with NFKC, strip configured invisible carriers, map configured confusables to ASCII, and replace configured unusual spaces. Sanitized text can still contain plain-text injections.

Detection runs on the original text; canonicalization never destroys evidence.

Canonicalization also runs on clean-verdict text. For example, clean Chinese
fullwidth punctuation and clean Russian/English code-switching can change in
the forwarded copy (pinned in `tests/test_fuzz.py`). This work
preserves that policy; `clean` does not mean the text is unchanged.

## Additive policy API (preview)

`inspect_text()` separates Unicode evidence from a named decision policy. The
default `Policy.BALANCED` preserves every allowed input exactly. A review,
block, invalid input, or scan error has no forwarding candidate.

```python
from stegdetect import inspect_text

inspection = inspect_text(untrusted_text)
if inspection.status != "complete" or inspection.action != "allow":
    hold_for_review_or_block(inspection.as_dict())
else:
    forward_to_llm(inspection.candidate_text)
```

This is a fixed **preview policy**, not a validated prompt-injection firewall.
The 30 project-authored development fixtures include two benign examples held
for review and three constructed attacks allowed by the balanced policy. They
cannot establish a deployment false-positive or false-negative rate. See the
[policy table and limitations](docs/P1_POLICY_CONTRACT.md) and the
[versioned JSON schema](schemas/inspection-v3.schema.json). The committed
v2 schema remains available for consumers of the earlier report format;
P2 reports identify themselves as v3 because their fields and statuses changed.
The legacy
`analyze()` and CLI behavior below remain unchanged.

The additive API accepts trusted `Limits` and has a bounded UTF-8 entry
point. Defaults are 1,048,576 codepoints, 4 MiB of input bytes, 256 retained
findings, and 16 MiB of compact ASCII JSON. Truncated finding detail retains
exact whole-document counts; limit/error results expose no forwarding
candidate. `report.to_json()` enforces the output cap. The new CLI mode reads
file/stdin bytes under the byte cap:

```bash
stegdetect --inspect -f retrieved_document.txt
```

This mode exits 0 for allow, 3 for review/block, and 4 for invalid/limit/error.
The legacy CLI modes below retain their existing exits and are not
resource-bounded. See the [reviewer methodology](docs/METHODOLOGY.md) for
measurement and validation.

For legitimate emoji sequences, joining controls, and simple RTL isolates,
opt in with `inspect_text(text, policy=Policy.CONTEXTUAL)` or
`stegdetect --inspect --contextual`. This keeps all original findings and
uses [schema v4](schemas/inspection-v4.schema.json); the default policy and
schema v3 stay unchanged. The [Unicode context contract](docs/UNICODE_CONTEXT.md)
states exact recognition boundaries and measured development-set outcomes.
For scripts and applications, see [CLI batches, explanations, and tested
RAG/tool-result gates](docs/DEVELOPER_WORKFLOWS.md).

Run `python scripts/validate_release.py --profile bounded` to verify the full
suite, installed wheel, and both source-bound resource artifacts. The measured
Windows results are in [P2 default-path](docs/P2_RESOURCE_RESULTS.md) and
[P3 context](docs/P3_CONTEXT_RESULTS.md) observations; they are not
cross-platform latency or memory guarantees.

## Install

```bash
pip install .
```

## Use

```bash
# Scan text, print JSON report
stegdetect "some untrusted input"
# Scan a file
stegdetect -f retrieved_document.txt
# Pipe
curl -s https://example.com/page | stegdetect -
# Just get the sanitized text
stegdetect -f input.txt --sanitize
```

```python
from stegdetect import analyze

report = analyze(untrusted_text)
if report.verdict == "malicious":
    log(report.as_dict())
    raise BlockedError("steganographic carrier detected")
forward_to_llm(report.sanitized)
```

Exit code is 0 for clean, 2 otherwise.

## What it catches

| Carrier | Example | Severity |
|---|---|---|
| Zero-width cluster (bit-encoded payload) | `doc\u200b\u200c\u200b...` | high |
| Bidi override (display order lies) | `\u202e` ... `\u202c` | high |
| Homoglyph substitution | Cyrillic `а` for Latin `a` | high |
| Unicode tag characters | U+E0000 block | high |
| Invisible formatting | soft hyphen, Hangul fillers | medium |
| Non-standard whitespace | NBSP, thin space, em space | low |

## What it does not catch (yet)

Plain-text injections and rendering tricks without Unicode carriers remain
out of scope. The two boundary tests in `tests/test_historical.py` deliberately
return clean; see `docs/HISTORICAL_ATTACKS.md`. There is no semantic layer two.
Acrostics, synonym substitution, and paraphrase encoding are not detected.

## Test

```bash
pip install -e ".[dev]"
pytest
```

P0 adds an executable compatibility baseline:

```bash
python scripts/validate_release.py --profile baseline
```

It checks the full suite, development fixture outcomes, original
test-file hashes, five broken-input controls, and an installed wheel outside the
checkout. See [the detection contract](docs/DETECTION_CONTRACT.md),
[generator map](docs/GENERATOR_RULE_MAP.md), and [claims ledger](docs/CLAIMS.md).
The 30 P0 examples are project-authored development fixtures, with **zero
independent sources or holdout examples**. Their counts are not a general
false-positive or false-negative rate. The CI matrix is configured to run the
baseline on Python 3.9–3.13 on Linux and Windows plus macOS 3.13;
cross-platform support requires actual green CI runs.

Test layout:

- `tests/test_detector.py` — the original rule/generator pairs.
- `tests/test_adversarial.py` — one test per attack shape, including the
  deliberate boundaries (sub-threshold zero-width clusters, below-density
  homoglyphs) where the detector stays silent to avoid false positives.
- `tests/test_false_positives.py` — legitimate multilingual, emoji, math,
  and code samples that must stay clean.
- `tests/test_canonicalize.py` — canonicalizer properties: idempotent,
  offsets index into the original text, NFKC folding.
- `tests/test_cli.py` — exit codes and JSON report shape.
- `tests/test_historical.py` — reconstructions of documented attacks
  (Trojan Source, ASCII smuggling, Llama Firewall evasion) plus the two
  deliberate out-of-scope boundary tests. Full 1-to-1 mapping in
  `docs/HISTORICAL_ATTACKS.md`.
- `tests/test_fuzz.py` — reproducible Hypothesis properties over all four
  existing generators, arbitrary Python strings including lone surrogates,
  finding offsets, normalization equivalence, and deliberate density evasion.
- `tests/test_robustness.py` — isolated processes scan eight pathological
  workloads at 262,144 and 1,048,576 characters, with 30-second timeouts
  and a loose scaling regression guard.

## Measured robustness

Priority 1 (fuzzing/robustness) exposed quadratic ordering in standard NFKC
on descending combining-mark runs. The canonicalizer now decomposes each
codepoint, orders marks with stable combining-class buckets, then composes
already ordered text. Tests compare its output with standard NFKC for every
single Python codepoint and bounded generated strings, including composition
and compatibility-decomposition cases.

See [the measured results and limits](docs/ROBUSTNESS.md) for timings and
finite FP/FN counts. These are measurements on one machine, not a general
no-hang guarantee, memory limit, or proof of worst-case linear runtime.
The API tests accept lone-surrogate Python strings; this does not establish
that arbitrary surrogates can be written to UTF-8 CLI streams.

Reproduce the benchmark and corpus measurements after installing dev extras:

```bash
python benchmarks/robustness.py --output docs/robustness-results.json
python benchmarks/corpus.py --output docs/robustness-corpus.json
```

Every detection rule has a paired attack generator in `src/stegdetect/samples.py`. If you add a rule, add a generator.

## License

MIT
