# P0 user research protocol

Target three to five independent Python developers integrating retrieved text
or tool output into an LLM application. Recruitment and interviews have **not**
occurred in P0; no user-task success rate is claimed. Do not present the
maintainer's own exercise as an independent pilot.

Ask each participant to install a built wheel in a fresh environment, inspect
a benign multilingual example and a seeded carrier example, wire one
application-owned boundary, and explain what `verdict` and `sanitized` mean.
Observe elapsed time, places where the API or CLI is confusing, whether they
notice a benign rewrite, and whether they mistakenly assume `clean` means
safe from plain-text injection. Capture exact package version, task prompt,
completion/abandonment, participant role, and consent for anonymized notes.

Use the same task wording and install artifact across participants. Record
failures and questions verbatim where permitted, without storing their real
documents or secrets. The next product decision is whether integration and
preserve-by-default behavior solve their actual task; P1 implementation should
not treat this protocol as validation of user demand.
