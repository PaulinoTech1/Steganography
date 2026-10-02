# Local evidence viewer (preview)

`stegdetect-view` writes a self-contained HTML page from one UTF-8 document.
It uses the bounded inspection API and never calls a model or a remote service.
The page contains short source excerpts, so treat it as a sensitive local file.
Choose a new output path; the command refuses to overwrite an existing page.

```bash
stegdetect-view -f retrieved.txt -o evidence.html
stegdetect-view --contextual -f retrieved.txt -o contextual-evidence.html
```

Open the resulting file locally. The command writes the page even when the
inspection action is review or block. Exit 0 means a complete allow, 3 means a
complete review/block, and 4 means invalid input, a limit, or a file/rendering
failure. A generated page is evidence for a reviewer; it is never permission
to forward held text. The viewer reads at most 4 MiB of input bytes plus one
byte to detect overflow; the same 1,048,576-codepoint and 16 MiB report caps
apply as in `inspect_bytes()`.

The banner shows status, action, policy ID, and report schema version. Policy
reasons use the same static explanations as `stegdetect --inspect --explain`.
The finding table lists category, severity, codepoint, original half-open
codepoint span, and UTF-16 start. The source excerpt shows codepoints in
logical order with visible names for controls, whitespace, and combining
marks. Each cell is isolated so a bidi control cannot reorder the whole page.
Only windows around the first 32 retained findings are shown; when there are
no findings, the first 160 codepoints are shown. The table can include all
retained findings (up to the configured limit of 256). If detail was truncated,
the page says so and still shows exact whole-document finding counts.

The transformation section distinguishes two different things:

- An **allow** report's forwarding candidate is the unchanged original text;
  its escaped preview shows up to 160 codepoints. Review, block, and incomplete
  reports have no forwarding candidate.
- The **legacy canonicalization comparison** is hypothetical. It shows whether
  `canonicalize()` would change the text, the resulting codepoint length, and
  an escaped prefix. It is not the policy's forwarding copy or authorization
  to forward a held document. Its offsets are not mapped back to the source.

For example, a document containing U+202E produces a blocked decision and a
visible `U+202E` cell. A document containing only a plain-text instruction can
produce `NO_FINDINGS` and allow: this filter does not judge instruction meaning.
Contextual policy may allow a recognized Unicode sequence while retaining its
original carrier findings. The page preserves that distinction.

The generated markup has no JavaScript, forms, external fonts, images, or
remote resource references and includes a restrictive Content Security Policy. Source text
is escaped before entering HTML. Saved pages include bounded excerpts and
finding details; a short document can appear in full within those excerpts.
There is no JSON export or automatic browser opening in this preview.

To validate after changing the viewer, run:

```bash
python -m pytest -q tests/test_viewer.py
python scripts/validate_release.py --profile bounded
```

The latter builds an isolated wheel and exercises two installed
viewer CLI cases outside the checkout. The planned full `viewer` profile still
needs browser accessibility checks and independent user tasks before a broader
usability claim.
