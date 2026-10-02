"""Shadow replay records metadata, never document text or a release PASS."""
import io
import json

from scripts.shadow_replay import main, run_shadow
from stegdetect import Policy


def _line(source_id, text):
    return (json.dumps({"source_id": source_id, "text": text}) + "\n").encode("utf-8")


def test_complete_replay_keeps_actions_and_source_out_of_receipt():
    secret = "private-internal-document-token"
    source = io.BytesIO(_line("opaque_1", secret) + _line("opaque_2", "x\u202e"))
    events = io.StringIO()
    summary = run_shadow(source, policy=Policy.BALANCED, pipeline_id="pipeline_1",
                         events=events)
    rows = [json.loads(line) for line in events.getvalue().splitlines()]
    assert summary["status"] == "replay_complete"
    assert summary["processed_records"] == 2
    assert summary["action_or_status_counts"] == {"allow": 1, "block": 1}
    assert [row["source_id"] for row in rows] == ["opaque_1", "opaque_2"]
    assert [row["action"] for row in rows] == ["allow", "block"]
    assert all(row["elapsed_ms"] is not None for row in rows)
    assert secret not in events.getvalue() + json.dumps(summary)
    assert "candidate_text" not in events.getvalue() + json.dumps(summary)
    assert summary["labels_reviewed"] == 0
    assert summary["independent_users"] == 0
    assert summary["production_pipeline_verified"] is False
    assert summary["release_claim_supported"] is False


def test_malformed_duplicate_and_surrogate_records_make_replay_incomplete():
    source = io.BytesIO(_line("opaque_1", "ok") + b"{bad}\n" +
                        _line("opaque_1", "repeat") + _line("opaque_2", "\ud800"))
    events = io.StringIO()
    summary = run_shadow(source, policy=Policy.BALANCED, pipeline_id="pipeline_1",
                         events=events)
    rows = [json.loads(line) for line in events.getvalue().splitlines()]
    assert summary["status"] == "incomplete"
    assert summary["incomplete_reason"] == "INCOMPLETE_INSPECTION"
    assert [row["reason_codes"] for row in rows[1:]] == [
        ["INVALID_JSON"], ["DUPLICATE_SOURCE_ID"], ["INVALID_UNICODE"]]
    assert all(row["action"] is None for row in rows[1:])
    assert "repeat" not in events.getvalue()


def test_replay_caps_fail_closed_without_echoing_oversized_text():
    source = io.BytesIO(_line("opaque_1", "x" * 100))
    summary = run_shadow(source, policy=Policy.BALANCED, pipeline_id="pipeline_1",
                         max_line_bytes=20)
    assert summary["status"] == "incomplete"
    assert summary["incomplete_reason"] == "RECORD_BYTE_LIMIT"
    assert summary["processed_records"] == 0

    source = io.BytesIO(_line("opaque_1", "ok") + _line("opaque_2", "extra"))
    summary = run_shadow(source, policy=Policy.BALANCED, pipeline_id="pipeline_1",
                         max_records=1)
    assert summary["status"] == "incomplete"
    assert summary["incomplete_reason"] == "BATCH_RECORD_LIMIT"
    assert summary["processed_records"] == 1

    summary = run_shadow(io.BytesIO(b""), policy=Policy.BALANCED,
                         pipeline_id="pipeline_1")
    assert summary["status"] == "incomplete"
    assert summary["incomplete_reason"] == "EMPTY_REPLAY"

    summary = run_shadow(io.BytesIO(_line("opaque_1", "ok")),
                         policy=Policy.BALANCED, pipeline_id="pipeline_1",
                         max_total_bytes=3)
    assert summary["status"] == "incomplete"
    assert summary["incomplete_reason"] == "BATCH_INPUT_LIMIT"


def test_shadow_cli_writes_only_metadata_and_refuses_existing_summary(tmp_path, capsys):
    source = tmp_path / "source.jsonl"
    summary = tmp_path / "summary.json"
    events = tmp_path / "events.jsonl"
    source.write_bytes(_line("opaque_1", "private source text"))
    args = ["--input", str(source), "--summary", str(summary), "--events", str(events),
            "--pipeline-id", "pipeline_1"]
    assert main(args) == 0
    assert "private source text" not in summary.read_text(encoding="utf-8")
    assert "private source text" not in events.read_text(encoding="utf-8")
    before = summary.read_bytes()
    assert main(args) == 4
    assert summary.read_bytes() == before
    assert "discard any partial output" in capsys.readouterr().err
