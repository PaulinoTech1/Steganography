# P6 status — 2026-10-02

**NOT RUN.** Independent usefulness and production shadow-pilot validation
remain pending. The repository currently contains zero independent user-task
receipts, zero consented pipeline receipts, zero independently reviewed pilot
labels, and zero day-14 retention observations. No production FP/FN rate,
user-task completion rate, or release readiness claim is supported.

The runnable local replay instrument is `scripts/shadow_replay.py`; its tests
prove bounded metadata-only output and fail-closed incomplete status on
malformed, duplicate, and oversized records. These tests are synthetic and
do not count toward any P6 denominator. The task script and full entry/exit
criteria are in [P6_VALIDATION.md](P6_VALIDATION.md).

A two-record project-authored local rehearsal on 2026-10-02 returned one
allow and one block, wrote no source text to its outputs, and reported
`release_claim_supported=false`. It measured the runner path only; it was
not an independent user task or a consented pipeline pilot.

Required external inputs: at least three independent Python-developer
participants with an independent observer, and owners of three consented
retrieval/tool-result pipelines or authentic local replays. Each pilot needs
provenance, reviewed labels, and a day-14 follow-up. Until then, describe
the package as an evaluated developer preview only.
