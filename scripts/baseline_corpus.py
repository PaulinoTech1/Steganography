"""Recompute the legacy 16-clean/800-generated corpus without importing pytest.

The installed-wheel smoke test invokes this same function outside the checkout.
"""
from __future__ import annotations

import ast
from pathlib import Path
import random

from stegdetect import analyze
from stegdetect.samples import bidi_wrap, homoglyph_swap, tag_encode, zero_width_encode


def _clean_samples(test_path: Path) -> dict[str, str]:
    tree = ast.parse(test_path.read_text(encoding="utf-8"))
    for node in tree.body:
        if isinstance(node, ast.Assign) and any(
                isinstance(target, ast.Name) and target.id == "CLEAN_SAMPLES"
                for target in node.targets):
            samples = ast.literal_eval(node.value)
            if len(samples) != 16 or not all(isinstance(value, str) for value in samples.values()):
                raise ValueError("unexpected legacy clean sample corpus")
            return samples
    raise ValueError("legacy clean sample corpus missing")


def measure(test_path: Path) -> dict:
    clean = _clean_samples(test_path)
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
    return results
