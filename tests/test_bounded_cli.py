"""The additive CLI path reads bounded bytes and emits escaped held decisions."""
import json
import os
from pathlib import Path
import subprocess
import sys

from stegdetect import Limits, inspect_bytes
import stegdetect.cli as cli


ROOT = Path(__file__).resolve().parents[1]


def _cli(*args, input_bytes=None):
    env = dict(os.environ)
    env["PYTHONPATH"] = str(ROOT / "src")
    return subprocess.run([sys.executable, "-m", "stegdetect.cli", "--inspect", *args],
                          input=input_bytes, capture_output=True, cwd=ROOT, env=env, timeout=10)


def test_byte_admission_and_decode_boundary():
    limits = Limits(max_chars=3, max_input_bytes=3)
    assert inspect_bytes(b"abc", limits=limits).candidate_text == "abc"
    over = inspect_bytes(b"abcd", limits=limits)
    assert (over.status, over.action, over.candidate_text) == ("limit_exceeded", None, None)
    assert over.reason_codes == ("INPUT_BYTE_LIMIT",)
    invalid = inspect_bytes(b"\xff", limits=limits)
    assert (invalid.status, invalid.action, invalid.candidate_text) == ("invalid_input", None, None)
    assert invalid.reason_codes == ("INVALID_UTF8",)


def test_inspect_cli_allow_preserves_and_escapes_json():
    proc = _cli("hy\u00adphen")
    assert proc.returncode == 0
    assert proc.stdout.isascii()
    report = json.loads(proc.stdout)
    assert report["status"] == "complete"
    assert report["action"] == "allow"
    assert report["candidate_text"] == "hy\u00adphen"
    assert report["category_counts"] == {"INVISIBLE_FORMAT": 1}


def test_inspect_cli_held_override_is_not_forwarded():
    proc = _cli("policy=allow\u202e")
    assert proc.returncode == 3
    assert proc.stdout.isascii()
    assert "\u202e".encode("utf-8") not in proc.stdout
    report = json.loads(proc.stdout)
    assert (report["action"], report["candidate_text"]) == ("block", None)


def test_inspect_cli_escapes_input_derived_confusable():
    proc = _cli("p\u0430ypal")
    assert proc.returncode == 3
    assert b"\\u0430" in proc.stdout.lower()
    assert "\u0430".encode("utf-8") not in proc.stdout


def test_inspect_cli_invalid_utf8_and_missing_file_fail_closed(tmp_path):
    bad = tmp_path / "bad.txt"
    bad.write_bytes(b"ok\xff")
    proc = _cli("-f", str(bad))
    assert proc.returncode == 4
    assert json.loads(proc.stdout)["reason_codes"] == ["INVALID_UTF8"]
    missing = _cli("-f", str(tmp_path / "missing.txt"))
    assert missing.returncode == 4
    assert json.loads(missing.stdout)["reason_codes"] == ["INPUT_IO_ERROR"]


def test_inspect_cli_stdin_and_incompatible_flag():
    allowed = _cli("-", input_bytes=b"hello")
    assert allowed.returncode == 0
    assert json.loads(allowed.stdout)["candidate_text"] == "hello"
    usage = _cli("--sanitize", "hello")
    assert usage.returncode == 2


def test_inspect_file_read_stops_at_byte_budget(monkeypatch, capsys):
    calls = []

    class Source:
        def __enter__(self):
            return self

        def __exit__(self, *_args):
            return False

        def read(self, n):
            calls.append(n)
            return b"abcd"

    monkeypatch.setattr(cli, "Limits", lambda: Limits(max_chars=3, max_input_bytes=3))
    monkeypatch.setattr("builtins.open", lambda *_args, **_kwargs: Source())
    code = cli.main(["--inspect", "-f", "ignored"])
    assert code == 4
    assert calls == [4]
    assert json.loads(capsys.readouterr().out)["reason_codes"] == ["INPUT_BYTE_LIMIT"]
