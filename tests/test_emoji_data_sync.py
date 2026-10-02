"""The pinned emoji-data checksum must match the bundled data file.

Regression test: the data file was regenerated in 35a2c1d4 without updating
_DATA_SHA256, which broke every CI job (the stale pin made recognize_context
raise, so CONTEXTUAL inspections returned status "error"). This test fails
fast in pytest instead of surfacing only in the release validator.
"""
from __future__ import annotations

import hashlib

from stegdetect import unicode_context


def test_emoji_data_checksum_matches_pin():
    # Mirrors the runtime normalization in _emoji_trie: the pin is over
    # LF-normalized bytes so it holds on CRLF checkouts too.
    raw = unicode_context._DATA.read_bytes().replace(b"\r\n", b"\n")
    assert hashlib.sha256(raw).hexdigest() == unicode_context._DATA_SHA256


def test_emoji_data_row_count():
    rows = [
        line
        for line in unicode_context._DATA.read_text(encoding="ascii").splitlines()
        if line and not line.startswith("#")
    ]
    assert len(rows) == 1617
