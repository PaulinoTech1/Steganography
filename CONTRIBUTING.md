# Contributing to stegdetect

## Setup

```bash
python -m venv .venv
.venv/bin/python -m pip install -e ".[dev]"
```

Python 3.9 through 3.13 is supported; CI runs the full matrix on Ubuntu,
Windows, and macOS.

## Checks before a pull request

Run the test suite:

```bash
python -m pytest -q
```

Then run the release validator (this is what CI runs):

```bash
python scripts/validate_release.py --profile bounded
```

Both must pass. The validator runs the suite itself and additionally checks
golden files, pinned hashes, resource receipts, and the installed wheel.

## The pin discipline

Several files pin hashes of other files (bundled data, protected tests,
benchmark receipts). If you regenerate a data artifact or modify a pinned
file, you must update the corresponding pin in the same change. Hashes are
computed over LF-normalized bytes so they hold on any checkout; never pin
raw working-tree bytes from a CRLF checkout.

Regenerate pins with:

```bash
python scripts/validate_resources.py --record   # P2 receipt only; see its docstring
```

For `evals/protected_tests.json` and the emoji data pin, update the stored
hash deliberately and say so in the commit message. A stale pin fails CI;
a silently weakened test is worse.

## What to contribute

- New carrier families with historical or observed attack evidence.
- False-positive reports on legitimate text (see `docs/HISTORICAL_ATTACKS.md`
  for the honesty bar: lab-demonstrated carriers only, no claimed
  prompt-injection prevention).
- Performance measurements on new platforms.

Keep claims conservative. If a result is only demonstrated on a fixed corpus,
say so in the docs and the commit message.
