"""Generate a bounded, static local HTML view of an inspection report."""
from __future__ import annotations

import argparse
import html
from pathlib import Path
import sys
import unicodedata

from .canonicalize import canonicalize
from .inspection import InspectionReport, Limits, inspect_bytes
from .policy import Policy
from .reasons import REASON_EXPLANATIONS


_PREVIEW_CODEPOINTS = 160
_SNIPPET_FINDINGS = 32
_HTML_BYTE_LIMIT = 2_097_152


def _escaped_preview(text: str, limit: int = _PREVIEW_CODEPOINTS) -> str:
    """Unambiguous ASCII-only source preview; never emit active bidi controls."""
    pieces = []
    for ch in text[:limit]:
        cp = ord(ch)
        pieces.append(html.escape(ch, quote=True) if 0x20 <= cp <= 0x7E and ch != "\\"
                      else f"\\u{{{cp:04X}}}")
    if len(text) > limit:
        pieces.append(" ... [preview truncated]")
    return "".join(pieces)


def _glyph(ch: str) -> str:
    name = unicodedata.name(ch, "UNNAMED CHARACTER")
    if ch.isspace() or unicodedata.category(ch)[0] in "CMZ":
        return f"[{html.escape(name)}]"
    return html.escape(ch, quote=True)


def _utf16_positions(text: str, wanted: set[int]) -> dict[int, int]:
    result: dict[int, int] = {}
    if not wanted:
        return result
    units = 0
    for offset, ch in enumerate(text):
        if offset in wanted:
            result[offset] = units
        units += 2 if ord(ch) > 0xFFFF else 1
    return result


def _snippet_indices(text: str, report: InspectionReport) -> list[int]:
    if not report.findings:
        return list(range(min(len(text), _PREVIEW_CODEPOINTS)))
    indices: set[int] = set()
    for finding in report.findings[:_SNIPPET_FINDINGS]:
        indices.update(range(max(0, finding.offset - 3),
                             min(len(text), finding.offset + min(finding.length, 1) + 4)))
    return sorted(indices)


def _render_snippet(text: str, indices: list[int], positions: dict[int, int],
                    finding_offsets: set[int]) -> str:
    if not indices:
        return "<p>Empty document.</p>"
    cells = []
    previous = -1
    for offset in indices:
        if offset > previous + 1:
            cells.append(f'<span class="gap" role="note">{offset - previous - 1} codepoints omitted</span>')
        ch = text[offset]
        cp = f"U+{ord(ch):04X}"
        name = html.escape(unicodedata.name(ch, "UNNAMED CHARACTER"), quote=True)
        marked = " finding" if offset in finding_offsets else ""
        cells.append(
            f'<span class="cell{marked}" dir="ltr" title="{name}">'
            f'<span class="glyph">{_glyph(ch)}</span>'
            f'<span class="coordinate">cp {offset} · UTF-16 {positions[offset]}</span>'
            f'<span class="codepoint">{cp}</span></span>')
        previous = offset
    if previous < len(text) - 1:
        cells.append(f'<span class="gap" role="note">{len(text) - previous - 1} codepoints omitted</span>')
    return '<div class="cells" aria-label="Original codepoints in logical order">' + "".join(cells) + "</div>"


def _render_findings(report: InspectionReport, positions: dict[int, int]) -> str:
    if not report.findings:
        return "<p>No configured Unicode carrier findings were retained.</p>"
    rows = []
    for finding in report.findings:
        rows.append(
            "<tr>"
            f"<td>{finding.offset}:{finding.offset + finding.length}</td>"
            f"<td>{positions[finding.offset]}</td>"
            f"<td><code>{html.escape(finding.codepoints)}</code></td>"
            f"<td>{html.escape(finding.category)}</td>"
            f"<td>{html.escape(finding.severity)}</td>"
            f"<td>{_escaped_preview(finding.detail, 240)}</td>"
            "</tr>")
    return ("<div class=\"table-wrap\"><table><caption>Retained findings at original offsets</caption>"
            "<thead><tr><th scope=\"col\">Codepoint span [start:end)</th>"
            "<th scope=\"col\">UTF-16 start</th><th scope=\"col\">Character</th>"
            "<th scope=\"col\">Category</th><th scope=\"col\">Severity</th>"
            "<th scope=\"col\">Detail</th></tr></thead><tbody>" + "".join(rows) +
            "</tbody></table></div>")


def _render_reasons(report: InspectionReport) -> str:
    items = []
    for code in report.reason_codes:
        explanation = REASON_EXPLANATIONS.get(code, "No explanation is registered for this code.")
        items.append(f"<li><code>{html.escape(code)}</code> — {html.escape(explanation)}</li>")
    return "<ul>" + "".join(items) + "</ul>"


def _render_transforms(text: str | None, report: InspectionReport) -> str:
    if text is None:
        return "<p>No source or transformation preview is available for this incomplete inspection.</p>"
    if report.status == "complete" and report.action == "allow":
        candidate = ("<p>The policy forwarding candidate preserves the input exactly. "
                     "Escaped prefix:</p><pre><code>" + _escaped_preview(report.candidate_text or "") +
                     "</code></pre>")
    else:
        candidate = "<p>No forwarding candidate exists for this decision.</p>"
    try:
        legacy = canonicalize(text)
    except Exception:
        hypothetical = "<p>Legacy canonicalization preview is unavailable.</p>"
    else:
        changed = "yes" if legacy != text else "no"
        hypothetical = ("<p>Legacy canonicalization changes this input: " + changed +
                        f". Output length: {len(legacy)} codepoints. Escaped prefix:</p>"
                        "<pre><code>" + _escaped_preview(legacy) + "</code></pre>")
    return (candidate + "<h3>Legacy transformation comparison</h3>"
            "<p>This is a hypothetical preview, not the policy candidate and not an "
            "authorization to forward held text.</p>" + hypothetical)


def render_document(data: bytes, *, policy: Policy = Policy.BALANCED,
                    limits: Limits = Limits()) -> tuple[str, InspectionReport]:
    """Return a local-only HTML artifact and its authoritative bounded report."""
    report = inspect_bytes(data, policy=policy, limits=limits)
    text = data.decode("utf-8") if report.status == "complete" else None
    indices = _snippet_indices(text, report) if text is not None else []
    positions = _utf16_positions(text, {finding.offset for finding in report.findings} |
                                   set(indices)) if text is not None else {}
    reasons = _render_reasons(report)
    if text is None:
        snippet = "<p>Input cannot be displayed because inspection was incomplete.</p>"
    else:
        snippet = _render_snippet(text, indices, positions,
                                  {finding.offset for finding in report.findings})
    findings = _render_findings(report, positions)
    transforms = _render_transforms(text, report)
    action = report.action if report.action is not None else "held"
    truncation = (" Retained details are truncated; the total and category counts "
                  "still cover the complete scan." if report.findings_truncated else "")
    counts = ", ".join(f"{html.escape(key)}: {value}"
                       for key, value in sorted(report.category_counts.items())) or "none"
    page = f"""<!doctype html>
<html lang="en"><head><meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<meta http-equiv="Content-Security-Policy" content="default-src 'none'; style-src 'unsafe-inline'; img-src 'none'; connect-src 'none'; form-action 'none'; base-uri 'none'">
<title>stegdetect evidence viewer</title>
<style>
:root {{ color-scheme: dark; font-family: system-ui, sans-serif; background: #101820; color: #f2f5f7; }}
body {{ max-width: 74rem; margin: auto; padding: 1.2rem; line-height: 1.5; }}
a {{ color: #8bd6ff; }} a:focus-visible {{ outline: 3px solid #ffd166; outline-offset: 3px; }}
h1,h2,h3 {{ line-height: 1.2; }} section {{ margin: 1.4rem 0; padding: 1rem; border: 1px solid #65747f; border-radius: .5rem; }}
.banner {{ border-left: .45rem solid #ffd166; padding: .65rem 1rem; background: #25313a; }}
.cells {{ display: flex; flex-wrap: wrap; gap: .35rem; }}
.cell {{ display: inline-flex; flex-direction: column; min-width: 6.5rem; max-width: 11rem; padding: .35rem; border: 1px solid #71818d; border-radius: .3rem; overflow-wrap: anywhere; unicode-bidi: isolate; }}
.cell.finding {{ border: 2px solid #ffd166; background: #352c18; }}
.glyph {{ font-size: 1.1rem; font-weight: 650; }} .coordinate,.codepoint {{ font-size: .76rem; }}
.gap {{ align-self: center; font-size: .8rem; color: #d5dde2; padding: .35rem; }}
.table-wrap {{ overflow-x: auto; }} table {{ border-collapse: collapse; width: 100%; }}
th,td {{ border: 1px solid #65747f; text-align: left; padding: .4rem; vertical-align: top; }}
th {{ background: #25313a; }} pre {{ white-space: pre-wrap; overflow-wrap: anywhere; padding: .7rem; background: #25313a; }}
code {{ overflow-wrap: anywhere; }} .muted {{ color: #d5dde2; }}
</style></head><body>
<a href="#main">Skip to evidence</a><main id="main">
<h1>stegdetect evidence viewer</h1>
<p class="muted">Static local preview. No scripts, remote assets, or model calls. Saved pages contain bounded excerpts of source text.</p>
<div class="banner" role="status"><strong>{html.escape(action.upper())}</strong> · {html.escape(report.status)} · policy {html.escape(report.policy_id)} · schema v{report.schema_version}</div>
<p>{report.finding_count_total} total findings; {len(report.findings)} retained. Categories: {counts}.{truncation}</p>
<section aria-labelledby="reasons"><h2 id="reasons">Policy reasons</h2>{reasons}
<p>These reasons describe Unicode carrier evidence, not author intent. An allow does not rule out plain-text prompt injection.</p></section>
<section aria-labelledby="source"><h2 id="source">Original source excerpt</h2>
<p>Logical order; offsets are zero-based Python codepoints. UTF-16 starts are supplied for browser coordinate comparison. Only bounded windows around the first {_SNIPPET_FINDINGS} retained findings are shown; no-finding input shows a prefix.</p>{snippet}</section>
<section aria-labelledby="findings"><h2 id="findings">Finding details</h2>{findings}</section>
<section aria-labelledby="transforms"><h2 id="transforms">Transformation previews</h2>{transforms}</section>
</main></body></html>"""
    if len(page.encode("utf-8")) > _HTML_BYTE_LIMIT:
        raise ValueError("viewer HTML exceeds its 2 MiB output limit")
    return page, report


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(prog="stegdetect-view",
                                     description="Write a static local HTML evidence viewer.")
    parser.add_argument("-f", "--file", required=True, help="UTF-8 input document")
    parser.add_argument("-o", "--output", required=True, help="New HTML file (never overwritten)")
    parser.add_argument("--contextual", action="store_true", help="Use the opt-in contextual policy")
    args = parser.parse_args(argv)
    limits = Limits()
    try:
        with Path(args.file).open("rb") as source:
            data = source.read(limits.max_input_bytes + 1)
        page, report = render_document(data, policy=(Policy.CONTEXTUAL if args.contextual
                                                     else Policy.BALANCED), limits=limits)
        with Path(args.output).open("x", encoding="utf-8", newline="\n") as output:
            output.write(page)
    except FileExistsError:
        print("viewer output already exists; choose a new file", file=sys.stderr)
        return 4
    except (OSError, ValueError):
        print("viewer input, rendering, or output failed; discard any partial output",
              file=sys.stderr)
        return 4
    print(f"local evidence page written; action={report.action or 'held'}; status={report.status}")
    return 0 if report.action == "allow" else 3 if report.status == "complete" else 4


if __name__ == "__main__":
    raise SystemExit(main())
