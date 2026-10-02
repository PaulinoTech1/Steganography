# P6 independent tasks and shadow-pilot protocol

Status on 2026-10-02: **NOT RUN**. No independent participant sessions,
consented pipeline replays, independently reviewed labels, or day-14 retention
observations are present in this repository. Automated tests and local
project-authored replays are rehearsal evidence only. They cannot justify a
stronger usefulness, enforcement, or release claim.

## Independent user tasks

Recruit at least three Python developers who did not build this feature; aim
for five. Each receives the same wheel digest, current public README, and the
following tasks in a fresh disposable environment. Start one 15-minute timer
for tasks 1–4. The observer may record questions but may not assist. Assistance
counts as a failed unassisted attempt; preserve the result and use a fresh
participant after a fix.

1. Install the wheel and inspect a local benign multilingual document and a
   seeded carrier example.
2. Put `inspect_text()` at a stubbed RAG or tool-result boundary, using an
   application-owned policy and source ID.
3. Explain one finding's original offset, reason, and action without calling
   the finding proof of malicious intent.
4. Exercise review/block and invalid/error paths and show a recorder with zero
   model calls for held input; show an unchanged candidate for allowed input.
5. Answer all three comprehension questions: Can a plain-text injection pass
   with no findings? Does preserve mode rewrite allowed text? Can a held result
   authorize a model call? Expected answers: yes, no, no.

If the viewer is evaluated, add keyboard navigation, screen-reader reading,
contrast, and hostile-markup/astral-offset interpretation tasks. These do not
replace tasks 1–5. For each attempt, retain only an opaque participant ID,
artifact digest, Python/OS, observer ID, start/end times, task outcomes,
assistance and correction counts, comprehension answers, and optional
consented quotations. Do not store participant names, their real documents,
or credentials in the repository. An independent observer checks receipts
against recordings or direct observation; a filled form alone is not proof.

The three-person core rubric is three distinct unassisted participants each
completing tasks 1–4 within 15 minutes and answering all three questions.
Report the numerator and denominator, every failed attempt, assistance, and
elapsed times. Repeating with new users after a change does not erase prior
failures. Day-14 continued use is a separate observation, not inferred from
an initial successful task.

## Shadow pilots

Obtain owner consent for each of three independent retrieval or tool-result
pipelines. Observe the exact untrusted text at the boundary without changing
the existing model call or user outcome. Assign opaque source IDs outside the
document. Measure per-document status/action, reason/category counts, scan
latency, host timeout, override, and whether the host forwarded or changed
text. Logs should contain metadata and opaque IDs only. Task labels and
review judgments come from an independent reviewer, never the scanner's own
action. Review every proposed block and a prespecified sample of allows and
reviews. Preserve minimized counterexamples privately only with permission.

For a **local replay rehearsal** of consented JSONL, use:

```bash
python scripts/shadow_replay.py --pipeline-id opaque_p1 --input replay.jsonl --summary summary.json --events events.jsonl
```

Each input line has exactly `{"source_id":"opaque_1","text":"..."}`. The
script accepts up to 16 MiB per JSONL line, 512 MiB per run, and 10,000
records; inspection still applies its 4 MiB UTF-8 and 1,048,576-codepoint
document caps. Outputs contain no document or candidate text. Events include
opaque IDs, reasons, counts, and timing; summaries contain aggregates. The
caller must generate IDs unrelated to names or user identifiers, protect the
source replay file, and review metadata sensitivity. A malformed, duplicate,
oversized, or incomplete record makes the run incomplete. The script never
forwards text or verifies a production host, so its `replay_complete` status
is **not** a pilot or release PASS.

The full pilot threshold is at least 1,000 original documents in each of
three consented independent pipelines, with all proposed blocks and sampled
other actions independently labeled. Smaller runs are preliminary. Record
false interruptions, scanner failures, host forwarding mistakes, changed
text, latency distribution, overrides, integration time, and day-14 observed
use in at least two pipelines. Fail closed on missing labels, unverifiable
source provenance, or a forward-on-error defect. The future `release` profile
must combine these receipts with the user tasks and the other gates in
[PLAN_VALIDATION.md](PLAN_VALIDATION.md); today's `bounded` PASS does not.

## Claim boundary

The [current status](P6_STATUS.md) stays NOT RUN until real participants and
pipeline owners provide evidence. Do not treat a project-authored replay,
synthetic fixture, automated model-call recorder, or unreviewed log as an
independent pilot. The optional [lexical scorer](../experiments/lexical/README.md)
has a different corpus and gate and cannot inherit these Unicode results.
