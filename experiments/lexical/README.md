# R1 lexical scorer — separate gated experiment

No lexical scorer is shipped in `stegdetect` and no lexical action feeds its
Unicode policies. Plain-text injection remains outside the detector's current
scope. The optional R1 work may begin as an offline, advisory feature scorer
with no model weights or network dependency; it must not inherit the Unicode
corpus, policy metrics, or P6 pilot outcomes.

Before packaging even an experimental scorer, freeze separate whole-source
task-labeled benign and attack sets, including quotations, email, code,
translation, and paraphrase evasions. Compare against a keyword baseline.
Require at most 2% false interruption on an independent clean holdout of at
least 3,000 documents and at least 70% recall on a separately labeled
plain-text injection set. Those are proposed gates, not achieved rates. Fail
or defer the experiment if it misses them or only works after tuning on the
holdout. It never silently changes `Policy.BALANCED` or `Policy.CONTEXTUAL`.

See [PROJECT_PLAN.md](../../docs/PROJECT_PLAN.md) section R1 and the `r1`
profile specification in [PLAN_VALIDATION.md](../../docs/PLAN_VALIDATION.md).
