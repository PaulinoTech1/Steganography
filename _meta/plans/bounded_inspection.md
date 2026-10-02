# P2 bounded inspection contract (2026-10-02)

Goal: bound hostile input/report/output work on the additive API and hold any
failed/incomplete result. Legacy `analyze()` and CLI default remain compatible.
Inputs: Python string plus trusted `Policy` and immutable `Limits`; new
`--inspect` CLI reads file/stdin bytes under the same admission budget.
Output: v3 report/status, capped evidence, exact counts, bounded ASCII JSON.
Done: old tests green; cap/EOF/adversarial parity tests green; process deadlines,
RSS, latency and serialization measured; reviewer methodology documented.

Approaches: (1) call `scan_unicode` then truncate (reject: dense inputs already
allocate every finding); (2) separately scan in fixed passes and retain capped
evidence (chosen, standard library, legacy untouched); (3) change legacy scan
to a shared iterator (smaller duplication but risk to frozen behavior).

Defaults: max_chars=1,048,576 Python codepoints; max_input_bytes=4,194,304
for new CLI file/stdin; max_findings=256, minimum 6; max_output_bytes=16,777,216
for compact ASCII-escaped JSON (excluding the CLI newline). Caller-chosen limits
are trusted configuration and validated. No wall-clock timeout inside Python:
hosting code must impose a process deadline. A caller-provided string is already
allocated; max_chars only bounds subsequent work.

Admission: reject over-max text before scanning; reject malformed Unicode.
New CLI reads at most max_input_bytes+1 and decodes strict UTF-8. Missing file,
decode failure, timeout/scan error, and overlimit never expose candidate_text.
`status=limit_exceeded`, `action=null`, `candidate_text=null` on admission/output
failure. Complete scan may have truncated detail with exact total/category counts;
`scan_complete=true` then means the entire input was analyzed, not all shown.

Retention: first-N detail plus one priority witness per observed category, with
explicit bidi override replacing a weaker bidi witness. At most max_findings
are returned. If the cap cannot represent all categories, hold the result.
Decision uses full counts and signals, never the retained detail subset.
`as_dict` is structured data; `to_json` is the capped serialized transport.
Output limit failure is a held `limit_exceeded` report with completed scan and
no candidate. No silent truncation of candidate text or JSON.

Metrics: worker processes with hard deadlines; five warmups per latency
worker, 100 trials per 16/64-Ki-character workload and 30 per megacharacter
workload; nearest-rank p95, raw
times, baseline and peak RSS, serialized output, environment and construction.
These are runner observations, not universal memory or latency guarantees.
