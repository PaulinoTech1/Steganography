# Independent planning review record

Date: 2026-10-02. This is a review of the roadmap and its validation contracts,
not evidence that any proposed feature, corpus, or release gate is implemented.

## Initial reviewed artifact

`docs/PROJECT_PLAN.md`, SHA256:
`71490098E9326F2DC7EB042411C5289E42914CB441B4FE93293D491E9E41C8C4`.

Read-only researcher `plan_research` supported the offline evidence/policy direction
and identified missing legitimate Unicode coverage, the incomplete generator mapping,
the legacy rewrite contract, and dense-report memory exposure. Its sources included
the actual scanner/reporter/tests and primary Unicode documentation. It did not run
tests or performance benchmarks.

Independent adversary `plan_adversary`: **REVISE** initial roadmap.

| Finding | Revision in the roadmap and validator contracts |
|---|---|
| Allow-all policy could pass FP and evidence gates | Independent held-action goldens and >=95% per-family intervention recall for incumbent/new enforcement claims; allow-all negative control |
| Zero false-allow language conflicted with accepted misses | Zero-tolerance boundary forwarding violations separated from published corpus misses and frozen exceptions |
| First-N details could hide the reason for a block | Reserved bounded decision-driving evidence; 256-NBSP + final-RLO example |
| P0 command depended on future unavailable gates | Literal baseline/core/enforcement/viewer/release/R1 profile matrix |
| JSON stdout could retain deceptive bidi content | ASCII-escaped default v2 JSON for every input-derived field |

The adversary independently reproduced the cap-ordering example in a bounded probe:
257 findings, with the first 256 exclusively suspicious whitespace and an RLO last.
It read the source, README, and historical boundaries. It did not edit files, install
packages, use network services, or run the full performance suite.

Independent evaluation validator `plan_evaluation_validator`: **REVISE executable
evaluation contracts; support overall direction and P0 start**.

| Finding | Revision |
|---|---|
| Legacy metrics were not the proposed policy metrics | Explicit non-clean0/16/non-malicious0/800 baseline definitions; no semantic-prevention inference |
| Denominators, independent action labels, and span matching were ambiguous | Frozen eligible units, independently labeled actions, exact-location witness matching, operational refusal ledger |
| Confidence/multiplicity/dependence could change gate outcomes | Exact Clopper–Pearson, aggregatealpha=.05, simultaneous ten-stratumalpha=.005, independent-model condition, no all-zero bootstrap gate |
| Successful exposed holdouts could be reused for tuning | Access/evaluation/exposure ledger and new holdout after exposed retuning |
| Resource targets lacked a reproducible protocol | Workload manifest, five warmups,100/30 trials, nearest-rankp95, fresh-workerRSS, paired-median growth, no dropped errors |
| User success was not tied to the15-minute goal | Unassisted three-user rubric, comprehension questions, day14 use and explicit pilot-sampling minimum |
| Optional/missing gates could masquerade as ready | Named profile matrix, scoped subgates, nonzero aggregate negative-control results, preview limits |

The evaluator checked arithmetic independently: zero failures in300 gives a one-sided
95% bound of0.9936%; adjusting ten strata withalpha=.005 gives1.7506%. One failure in300
fails the adjusted2% gate. These are conditional calculations, not proof of the sampling
model. It did not validate implementation correctness, package artifacts, or runtime
performance and made no file changes.

## Revised artifact review

The coordinator incorporated all material findings into `PROJECT_PLAN.md` and
`PLAN_VALIDATION.md`. Both validators independently confirmed the revised frozen hashes:

- `PROJECT_PLAN.md`:
  `7CD97E42FC9B89411FBA8DEA9ADCFCB0B66250A657D560E07E8D55A52F27F9A2`.
- `PLAN_VALIDATION.md`:
  `2F4F59D51F6712F1137C312AC3ABE1FC59CFA5C75B8D50B03CDF8019E1C15ECA`.

`plan_adversary`: **PROCEED with implementation planning**. All five material
objections were resolved; no remaining material contradiction was identified.

`plan_evaluation_validator`: **PROCEED — planning only**. Metric/sampling, protocol,
usability, holdout-exposure, and release-profile findings were resolved. No remaining
material ambiguity prevents preparing the P0 bounded implementation specification.

Both reviews approve consistency of the roadmap and gate design. They do not establish
future accuracy, runtime budgets, usability, or release readiness. P0 still must freeze
the literal corpus schema, sampling rules, workload fixtures, and executable commands.
The rereviews were read-only and ran no heavy workloads. This receipt was added after
review and is outside the two frozen inputs above.

## Current verification limits

Current focused tests: 41 passed in 0.41s during planning. The full 107-test pass is retained
historical evidence from the preceding implementation work, not a new run here.
No new API, automatic rule, lexical scorer, viewer, held-out corpus, resource budget,
CI/release validator, or deployment has been implemented or validated by this task.
No changes have been committed or pushed for this planning task.
