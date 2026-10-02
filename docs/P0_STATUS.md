# P0 implementation status

Local baseline run on 2026-10-02, Windows, Python 3.10.10, checkout HEAD
`d876974443e1e51ef8f420d7db1b6d25abeb0595` plus uncommitted P0 work:

```text
python scripts/validate_release.py --profile baseline
status PASS; 151 tests passed; 30 development fixtures; 6 mapped categories;
8 protected prior test files; 9 computed claims; 4 negative controls;
installed wheel: 30 API fixtures and 3 CLI JSON/exit snapshots matched;
source and installed wheel: 0/16 curated clean samples non-clean,
0/800 generated attacks non-malicious, 8/8 below-density evasions clean.
```

This is local evidence for P0 compatibility and evaluation plumbing only.
The 30 fixtures are all project-authored and in the development split; there
are no independent sources, holdout samples, or policy actions yet. The
16 clean samples and 800 generated attacks are narrow, selected corpora. The
numbers cannot establish production FP/FN, safety, or model-outcome rates.

The new CI matrix has not run remotely as part of this local implementation,
so Python 3.9/3.11/3.12/3.13, Linux, and macOS remain unverified here. P0 user
interviews and recruitment also remain pending. The repeatable task script is
in [`P0_PILOT_PROTOCOL.md`](P0_PILOT_PROTOCOL.md). A complete P0 product gate
needs those external observations and a human review of the claims ledger.

The baseline validator intentionally supports only `--profile baseline`.
Future `core`, `enforcement`, `viewer`, and `release` profiles remain specified
in [`PLAN_VALIDATION.md`](PLAN_VALIDATION.md), not implemented. A baseline PASS
does not imply those future gates passed.
