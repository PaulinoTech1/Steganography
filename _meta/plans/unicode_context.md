# P3 Unicode context slice (2026-10-02)

Goal: reduce review interruptions for exact emoji, Persian/Indic joining, and
balanced directional isolates while retaining original-coordinate evidence.
Constraints: preserve legacy `analyze()`, existing `balanced-v1` outcomes, v2/v3
schemas, input/report/output caps, no runtime network, and protected tests.
Input: admitted Unicode text plus caller-selected policy. Output: opt-in
`contextual-v1` action under schema v4; allowed text remains byte-for-byte exact.
Done when: old suite passes; legitimate and malformed/late-carrier pairs pass;
source and installed-wheel APIs/CLI agree; false-alarm counts are measured on
named fixtures; resource artifact is rebound after measured source changes.

Approach A: relax existing category rules globally (~30 lines, no dependency).
Rejected: silently changes frozen legacy and balanced-v1 decisions.
Approach B: opt-in contextual policy (~150 lines plus pinned data), exact emoji
sequence matching and narrow joiner/isolate recognition. Chosen: same evidence,
bounded additional pass, explicit policy/schema version, no new detection rule.
Approach C: general grapheme/script/bidi engine (large dependency and broader
Unicode semantics). Rejected for this measured, narrow usability slice.

Recognized context never erases findings; it only discounts specific carrier
offsets when choosing an action. An exact emoji match cannot consume extra
adjacent tags, joiners, or selectors. An override anywhere still blocks.
Accepted valid constructions can themselves carry meaning; Unicode form does
not establish benign intent or LLM safety. Variation selectors, interlinear
annotations, and deprecated format controls are deferred until each has a
generator, evasion boundary, legitimate controls, and measured FP impact.
