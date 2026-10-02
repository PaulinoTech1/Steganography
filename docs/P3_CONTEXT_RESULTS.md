# Opt-in Unicode context resource observations

[`p3-context-results.json`](p3-context-results.json) records a local Windows
Python 3.10.10 run on 2026-10-02. It contains four 1,048,576-codepoint
workloads, two warmups and 10 timed trials per workload, zero timeouts, and
the expected policy action/count in every trial. Each workload ran in its own
killable process with a 120-second deadline. Timing includes
`inspect_text(..., policy=Policy.CONTEXTUAL)` and compact ASCII JSON
serialization but excludes process startup and input construction. Peak
working set includes the interpreter, input, bundled emoji trie, report, and
serialized output. It is sampled in the timing worker, not per trial.

| Workload | Action | Findings | Median | Nearest-rank p95 | Peak working set | JSON bytes |
|---|---|---:|---:|---:|---:|---:|
| Repeated RGI family emoji | allow | 449,388 | 1.622 s | 1.649 s | 43.4 MiB | 9,951,561 |
| Persian ZWNJ text | allow | 174,762 | 1.484 s | 1.523 s | 34.5 MiB | 6,357,598 |
| Simple RTL isolates | allow | 349,524 | 1.768 s | 1.809 s | 34.0 MiB | 6,351,863 |
| Unrecognized ZWJ text | review | 349,525 | 1.262 s | 1.293 s | 21.9 MiB | 65,057 |

The largest observed p95 was 1.809 s and the largest observed process peak
was 43.4 MiB. With only 10 trials per row, nearest-rank p95 equals the
maximum and is a weak tail estimate. These are **one-host observations**, not
a latency SLA, memory ceiling, cross-platform guarantee, or evidence of
prompt-injection prevention. The default-policy P2 study remains in
[`P2_RESOURCE_RESULTS.md`](P2_RESOURCE_RESULTS.md).

The artifact embeds SHA-256 hashes of the measured source and data;
`python scripts/validate_context_resources.py` recomputes the timing summaries
and checks current hashes. The reproduction command and worker protocol are
in [`METHODOLOGY.md`](METHODOLOGY.md). A source change requires a fresh run.
