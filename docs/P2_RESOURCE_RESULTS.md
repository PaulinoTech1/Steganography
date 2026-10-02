# P2 resource observations: local Windows run

The full profile in [`p2-resource-results.json`](p2-resource-results.json),
bound to its measured source by
[`p2-resource-receipt.json`](p2-resource-receipt.json), finished
on 2026-10-02 with Python 3.10.10 on Windows 10 build 26200. It contains 21
workload/size rows, 1,610 raw measured trials, and zero timeouts or unexpected
decisions. Each 16K/64K row has 100 trials; each 1M row has 30. The timing
figures include inspection and compact ASCII JSON serialization. The RSS
figures come from a separate one-run memory worker and include the Python
interpreter, input, report, and serialized output. They are not paired with
each latency trial.

| 1,048,576-codepoint workload | Median | Nearest-rank p95 | Peak process working set | JSON bytes |
|---|---:|---:|---:|---:|
| Ordinary prose | 0.602 s | 0.624 s | 20.9 MiB | 1,048,845 |
| Dense zero-width | 1.678 s | 1.815 s | 23.8 MiB | 64,961 |
| Nested bidi | 1.549 s | 1.573 s | 23.5 MiB | 60,359 |
| Mixed script | 1.482 s | 1.513 s | 22.0 MiB | 50,162 |
| Compatibility combining | 0.721 s | 0.732 s | 31.9 MiB | 6,291,720 |
| Supplementary emoji | 0.408 s | 0.417 s | 46.0 MiB | 12,583,181 |
| Final-character override | 1.427 s | 1.478 s | 22.7 MiB | 49,169 |

Across this measured matrix, the largest p95 was 1.815 s and the largest
separate-worker peak was 46.0 MiB. The 1M dense zero-width and bidi cases each
counted 1,048,576 findings while retaining at most 256. The final-character
case asserted that the deciding override remained in the retained evidence.
For the seven workloads, median time grew 15.70–16.35 times from 65,536 to
1,048,576 codepoints (16 times the input), consistent with near-linear growth
on these constructions. This is empirical behavior, not a complexity proof.
These are observations on one host, not a memory ceiling, latency SLA, or
cross-platform guarantee. The 30-trial megacharacter p95 is especially limited
as a tail estimate. The old `analyze()` and old CLI were not measured in this
P2 profile and remain unbounded.

The protocol, workload construction, deadline handling, RSS source, and
reproduction command are in [`METHODOLOGY.md`](METHODOLOGY.md). No production
holdout or end-to-end model-call outcome was measured here.
