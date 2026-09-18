# stegdetect

A pre-filter that catches steganographic prompt injection before it reaches a language model.

Small businesses usually can't afford frontier models, and weaker models are more vulnerable to prompt injection: poorer instruction/data discrimination, weaker system-prompt adherence, less safety tuning. `stegdetect` is model-agnostic defense for that reality. It inspects the *carrier*, not the meaning, so it works the same in front of any model, in any language, with no GPU and no weights.

## How it works

```
untrusted text -> analyze() -> { verdict, findings, sanitized } -> LLM
```

1. **Detect** invisible and deceptive Unicode: zero-width characters, bidi overrides, homoglyph (mixed-script) substitution, Unicode tag characters, suspicious whitespace.
2. **Verdict**: `clean`, `suspicious`, or `malicious`, with per-finding severity, offsets, and codepoints.
3. **Neutralize**: strip invisible carriers, map confusables to ASCII, collapse weird whitespace. Forward the sanitized text to the model.

Detection runs on the original text; canonicalization never destroys evidence.

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

Pure linguistic steganography: acrostics, synonym-substitution bit encoding, paraphrase-encoded payloads. Those need statistical analysis, which is the planned layer two. The Unicode layer is deterministic and cheap; it will never be the bottleneck.

## Test

```bash
pip install pytest
pytest
```

Every detection rule has a paired attack generator in `src/stegdetect/samples.py`. If you add a rule, add a generator.

## License

MIT
