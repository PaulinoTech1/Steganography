"""Finite carrier FP/FN measurement, not a real-world accuracy estimate."""
import argparse
import json
from pathlib import Path
import random
import runpy

from stegdetect import analyze
from stegdetect.samples import bidi_wrap, homoglyph_swap, tag_encode, zero_width_encode


def main():
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument("--output", default="docs/robustness-corpus.json")
    args = p.parse_args()
    root = Path(__file__).resolve().parents[1]
    clean = runpy.run_path(str(root / "tests" / "test_false_positives.py"))["CLEAN_SAMPLES"]
    rng = random.Random(20261001)
    results = {"seed": 20261001, "legitimate_samples": len(clean),
               "false_positives": sum(analyze(text).verdict != "clean" for text in clean.values()),
               "attack_families": {}}
    for generator in (zero_width_encode, bidi_wrap, tag_encode, homoglyph_swap):
        misses = 0
        for _ in range(200):
            payload = "".join(rng.choice("aeiopcx") for _ in range(rng.randint(1, 128)))
            text = ("Latin " + generator(payload) if generator is homoglyph_swap
                    else generator(payload, cover="Please summarize this report. "))
            misses += analyze(text).verdict != "malicious"
        results["attack_families"][generator.__name__] = {"samples": 200, "false_negatives": misses}
    evasion = ["Latin " + homoglyph_swap("a" * n) + "\u0448" for n in range(1, 9)]
    results["deliberate_below_density_evasion"] = {
        "samples": len(evasion), "undetected": sum(analyze(text).verdict == "clean" for text in evasion)}
    Path(args.output).write_text(json.dumps(results, indent=2) + "\n", encoding="utf-8")
    print(json.dumps(results, indent=2))


if __name__ == "__main__":
    main()
