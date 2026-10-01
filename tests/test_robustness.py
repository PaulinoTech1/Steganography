"""Each megacharacter analysis has a killable 30-second process boundary."""
import importlib.util
from pathlib import Path

import pytest


spec = importlib.util.spec_from_file_location(
    "robustness_benchmark", Path(__file__).resolve().parents[1] / "benchmarks" / "robustness.py")
benchmark = importlib.util.module_from_spec(spec)
spec.loader.exec_module(benchmark)


@pytest.mark.parametrize("case", benchmark.CASES)
def test_megacharacter_workload_finishes_in_bounded_process(case):
    small = benchmark.isolated(case, 262144, repeats=2, timeout=30)
    large = benchmark.isolated(case, 1048576, repeats=2, timeout=30)
    # Four times the input: loose guard against a quadratic (16x) regression.
    # A fixed allowance absorbs timer noise; this is empirical, not a proof.
    assert large["median_seconds"] <= small["median_seconds"] * 8 + 0.1
