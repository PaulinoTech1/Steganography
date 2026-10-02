"""CLI batches and final model-call boundaries use the bounded policy result."""
import io
import json
import os
from pathlib import Path
import subprocess
import sys

from examples.rag_gate import answer_with_documents
from examples.tool_result_gate import continue_with_tool_result
from stegdetect import Limits, Policy
from stegdetect.cli import _inspect_jsonl


ROOT = Path(__file__).resolve().parents[1]


def _cli(*args, input_bytes=b""):
    env = dict(os.environ)
    env["PYTHONPATH"] = str(ROOT / "src")
    return subprocess.run([sys.executable, "-m", "stegdetect.cli", *args],
                          input=input_bytes, capture_output=True, cwd=ROOT, env=env, timeout=10)


def test_explain_uses_safe_stderr_and_keeps_json_stdout():
    proc = _cli("--inspect", "--explain", "x\u202e")
    assert proc.returncode == 3
    assert proc.stdout.isascii() and proc.stderr.isascii()
    assert b"direction override" in proc.stderr
    assert "\u202e".encode("utf-8") not in proc.stdout + proc.stderr
    assert json.loads(proc.stdout)["candidate_text"] is None


def test_contextual_cli_can_allow_exact_emoji_flag_but_not_extra_tag():
    flag = "\U0001f3f4" + "".join(chr(0xE0000 + ord(c)) for c in "gbeng") + "\U000e007f"
    allowed = _cli("--inspect", "--contextual", flag)
    assert allowed.returncode == 0
    assert json.loads(allowed.stdout)["schema_version"] == 4
    assert json.loads(allowed.stdout)["candidate_text"] == flag
    held = _cli("--inspect", "--contextual", flag + chr(0xE0061))
    assert held.returncode == 3
    assert json.loads(held.stdout)["candidate_text"] is None


def test_jsonl_batch_reports_each_document_and_aggregate_exit():
    lines = (json.dumps("ordinary") + "\n" + json.dumps("x\u202e") + "\n").encode()
    proc = _cli("--inspect", "--jsonl", "--explain", "-", input_bytes=lines)
    reports = [json.loads(line) for line in proc.stdout.splitlines()]
    assert proc.returncode == 3
    assert [report["action"] for report in reports] == ["allow", "block"]
    assert reports[1]["candidate_text"] is None
    assert proc.stdout.isascii() and proc.stderr.isascii()
    assert b"record 2" in proc.stderr


def test_jsonl_invalid_and_record_cap_fail_whole_batch():
    empty = _cli("--inspect", "--jsonl", "-", input_bytes=b"")
    assert empty.returncode == 4 and empty.stdout == b""
    malformed = _cli("--inspect", "--jsonl", "-", input_bytes=b'"ok"\n{bad}\n17\n')
    reports = [json.loads(line) for line in malformed.stdout.splitlines()]
    assert malformed.returncode == 4
    assert [report["status"] for report in reports] == [
        "complete", "invalid_input", "invalid_input"]
    assert [report["candidate_text"] for report in reports] == ["ok", None, None]
    capped = _cli("--inspect", "--jsonl", "--max-records", "1", "-",
                  input_bytes=b'"ok"\n"extra"\n')
    assert capped.returncode == 4
    assert len(capped.stdout.splitlines()) == 1


def test_jsonl_deeply_nested_invalid_json_is_held():
    nested = b"[" * 1200 + b"0" + b"]" * 1200 + b"\n"
    proc = _cli("--inspect", "--jsonl", "-", input_bytes=nested)
    assert proc.returncode == 4
    assert json.loads(proc.stdout)["reason_codes"] == ["INVALID_JSON"]


def test_jsonl_overlong_record_stops_at_bounded_read(capsys):
    source = io.BytesIO(b'"oversized"\n"following"\n')
    result = _inspect_jsonl(source, Policy.BALANCED,
                            Limits(max_input_bytes=5), False, 100)
    assert result == 4
    lines = capsys.readouterr().out.splitlines()
    assert len(lines) == 1
    assert json.loads(lines[0])["reason_codes"] == ["INPUT_BYTE_LIMIT"]
    assert source.tell() == 7


def test_jsonl_aggregate_input_and_output_caps(capsys):
    source = io.BytesIO(b'"ok"\n"ok"\n')
    assert _inspect_jsonl(source, Policy.BALANCED, Limits(), False, 100,
                          batch_input_byte_limit=5) == 4
    assert len(capsys.readouterr().out.splitlines()) == 1
    source = io.BytesIO(b'"ok"\n')
    assert _inspect_jsonl(source, Policy.BALANCED, Limits(), False, 100,
                          batch_output_byte_limit=100) == 4
    assert capsys.readouterr().out == ""


def test_invalid_cli_flag_combinations_remain_usage_errors():
    assert _cli("--contextual", "text").returncode == 2
    assert _cli("--jsonl", "--inspect", "text").returncode == 2


def test_rag_gate_does_not_call_model_with_held_document():
    calls = []
    def model(prompt):
        calls.append(prompt)
        return "answer"
    held = answer_with_documents("Question", [("trusted-1", "safe"),
                                               ("trusted-2", "payload\u202e")], model)
    assert held["status"] == "held" and calls == []
    assert held["reports"][1][1].candidate_text is None
    sent = answer_with_documents("Question", [("trusted-1", "safe")], model)
    assert sent["status"] == "sent" and len(calls) == 1
    assert "safe" in calls[0]
    capped = answer_with_documents("Question", [("trusted-1", "safe")], model,
                                   max_prompt_chars=8)
    assert capped["status"] == "held" and len(calls) == 1


def test_tool_result_gate_never_sends_failed_or_held_input():
    calls = []
    def model(text):
        calls.append(text)
        return "next"
    for value in ("x\u202e", "x\ud800"):
        assert continue_with_tool_result(value, model)["status"] == "held"
    assert calls == []
    sent = continue_with_tool_result("exact text", model)
    assert sent["status"] == "sent"
    assert calls == ["exact text"]
