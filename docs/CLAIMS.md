# P0 claims ledger

Run `python scripts/validate_release.py --profile baseline` before repeating
these numbers. [`evals/claims.json`](../evals/claims.json) maps each count to a
computed metric and fails if it drifts. The command checks the full test suite,
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
