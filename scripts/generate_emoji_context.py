"""Derive the offline emoji context table from pinned Unicode Emoji 18 files."""
from __future__ import annotations

import hashlib
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
UPSTREAM = ROOT / "data" / "upstream" / "emoji18"
OUTPUT = ROOT / "src" / "stegdetect" / "data" / "emoji-context-18.0.txt"
SOURCES = {
    "emoji-zwj-sequences.txt": ("f61b5213bdf85a57741a9f903cb38d0f39a3d13be6ff4aca3b39857e859a9191",
                                "RGI_Emoji_ZWJ_Sequence"),
    "emoji-sequences.txt": ("1823dce71f3dd9cb0ad1976797baee4ffbdc1909756f43af8ce4c57f732843a4",
                            "RGI_Emoji_Tag_Sequence"),
}


def generate() -> str:
    rows: list[str] = []
    for name, (expected_digest, wanted_type) in SOURCES.items():
        raw = (UPSTREAM / name).read_bytes()
        if hashlib.sha256(raw).hexdigest() != expected_digest:
            raise ValueError(f"pinned Unicode source changed: {name}")
        for line in raw.decode("utf-8-sig").splitlines():
            body = line.split("#", 1)[0].strip()
            if not body:
                continue
            fields = [part.strip() for part in body.split(";")]
            if len(fields) != 3 or fields[1] != wanted_type:
                continue
            sequence = fields[0].split()
            if not sequence or any(".." in token for token in sequence):
                raise ValueError(f"unexpected sequence shape in {name}")
            rows.append(" ".join(sequence))
    if len(rows) != 1617 or len(rows) != len(set(rows)):
        raise ValueError("unexpected Emoji 18 sequence count or duplicate")
    return ("# Unicode Emoji 18.0 RGI ZWJ and tag sequences; see docs/UNICODE_CONTEXT.md\n"
            + "\n".join(rows) + "\n")


if __name__ == "__main__":
    OUTPUT.parent.mkdir(parents=True, exist_ok=True)
    OUTPUT.write_text(generate(), encoding="ascii")
    print(f"wrote {OUTPUT.relative_to(ROOT)}")
