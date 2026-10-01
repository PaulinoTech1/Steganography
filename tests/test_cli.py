"""CLI smoke tests: exit codes and output shape."""
import json

from stegdetect.cli import main
from stegdetect.samples import zero_width_encode


def test_cli_clean_text_exits_zero(capsys):
    assert main(["hello world"]) == 0
    out = capsys.readouterr().out
    assert json.loads(out)["verdict"] == "clean"


def test_cli_attack_exits_two(capsys):
    assert main([zero_width_encode("hi")]) == 2
    out = capsys.readouterr().out
    assert json.loads(out)["verdict"] == "malicious"


def test_cli_suspicious_exits_two(capsys):
    assert main(["Total:\u00a0$100"]) == 2
    out = capsys.readouterr().out
    assert json.loads(out)["verdict"] == "suspicious"


def test_cli_sanitize_prints_only_text(capsys):
    assert main(["--sanitize", "a\u200bb"]) == 2
    out = capsys.readouterr().out
    assert out.strip() == "ab"


def test_cli_json_report_shape(capsys):
    main(["hi"])
    report = json.loads(capsys.readouterr().out)
    assert set(report) == {"verdict", "findings", "sanitized", "stats"}
    assert set(report["stats"]) == {
        "input_chars", "sanitized_chars", "chars_removed",
        "finding_count", "by_category", "by_severity",
        "residual_categories",
    }
