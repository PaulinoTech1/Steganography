# P5 local evidence viewer preview (2026-10-02)

Goal: show bounded Unicode evidence without turning hostile text into active
HTML or implying that a clean Unicode scan proves safe instructions.
Input: a UTF-8 file under the existing bounded-inspection caps. Output: a new,
self-contained local HTML page and an exit status consistent with the policy
action. No server, model, network request, or automatic browser opening.

Chosen approach: render a static page directly from the bounded report.
Codepoint cells expose invisible characters and original offsets; a single
linear pass calculates UTF-16 starts for displayed positions. Evidence rows
retain the report's original counts and truncation signal. Only short windows
and escaped transformation prefixes enter the saved page, with a 2 MiB HTML
cap. The preserve candidate and hypothetical legacy canonicalization preview
are labeled separately.

Rejected: a browser-side detector or JSON embedded in executable JavaScript.
Those would duplicate policy logic and make escaping/cap guarantees harder to
review. Also deferred: full-document export and a local web server. Neither is
needed to inspect original evidence and both expand exposure of source text.

Validation: direct tests cover markup/script/bidi escaping, codepoint and
UTF-16 coordinates after an astral character, contextual policy reasons,
preserve-versus-legacy preview, truncated detail, incomplete input, no
overwrite, and output cap. Installed-wheel smoke verifies a held hostile page
and a clean changed-by-legacy page outside the checkout. This is an automated
preview, not the planned full browser accessibility/user-task gate.
