# Generator and rule evidence map

[`evals/rule_map.json`](../evals/rule_map.json) is the machine-checked mapping.
The baseline validator discovers categories from `scan_unicode()` and rejects
a missing category, generator, test symbol, or generator that fails to trigger
its mapped category. It does **not** infer that one example proves recall on
all payloads. The linked tests and development fixtures show examples and
boundaries that can be reproduced.

| Category | `samples.py` generator | Positive and boundary evidence |
|---|---|---|
| `ZERO_WIDTH` | `zero_width_encode` | Cluster positive and three/four-character boundary |
| `BIDI_OVERRIDE` | `bidi_wrap` | Override positive; plain RTL clean |
| `MIXED_SCRIPT` | `homoglyph_swap`, `greek_homoglyph_swap` | Cyrillic and Greek positives; below-density evasion |
| `TAG_CHARACTER` | `tag_encode` | Tag positive; tagless ASCII clean |
| `INVISIBLE_FORMAT` | `invisible_format_embed` | Each configured formatting character triggers; plain text clean |
| `SUSPICIOUS_WHITESPACE` | `suspicious_whitespace_replace` | Each configured unusual space triggers; ordinary ASCII space clean |

The added generators use exact configured characters and explicit input
requirements. They are development attack/sample constructors; they are not
new detector rules. The original 80-test set and later robustness tests remain
unchanged. `python scripts/evaluate.py` validates the mapping, corpus schema,
source/split integrity, exact legacy outcomes, and protected test bytes.
