---
query: Unicode Emoji 18.0 RGI ZWJ tag data and UAX 9 isolate contexts
date: 2026-10-02
ttl: 30
---

Official sources: [UTS #51](https://www.unicode.org/reports/tr51/),
[UAX #9](https://www.unicode.org/reports/tr9/),
[Emoji 18.0 ZWJ data](https://www.unicode.org/Public/18.0.0/emoji/emoji-zwj-sequences.txt),
[Emoji 18.0 sequence data](https://www.unicode.org/Public/18.0.0/emoji/emoji-sequences.txt),
and [Unicode License v3](https://www.unicode.org/license.txt).

The two data files were downloaded from their versioned URLs and hashed;
`scripts/generate_emoji_context.py` rechecks those hashes and derives the
1,617-line offline table. `test_unicode_context.py` checks byte-for-byte
regeneration and a tampered installed-data rejection. RGI means recommended
for interchange, not trusted content. UAX #9 permits paired directional
isolates; the contextual policy recognizes a narrow subset and keeps all
control findings. No runtime network access is required.
