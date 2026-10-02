"""Execute inside an isolated venv from a directory outside the source checkout."""
from __future__ import annotations

import importlib.util
import json
import os
from pathlib import Path
import subprocess
import sys

from baseline_corpus import measure
import stegdetect
from stegdetect import Limits, Policy, analyze, inspect_bytes, inspect_text


def _load_example(path: Path, name: str):
    """Load a repository example while its stegdetect import stays wheel-backed."""
    spec = importlib.util.spec_from_file_location(name, path)
    if spec is None or spec.loader is None:
        raise RuntimeError(f"cannot load example: {path}")
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def _check_installed_examples(root: Path) -> int:
    rag = _load_example(root / "examples" / "rag_gate.py", "rag_gate_example")
    tool = _load_example(root / "examples" / "tool_result_gate.py", "tool_result_gate_example")
    calls: list[str] = []

    def model_call(text: str) -> str:
        calls.append(text)
        return "recorded"

    held = rag.answer_with_documents(
        "Question", [("trusted-a", "ordinary"), ("trusted-b", "x\u202e")], model_call)
    if held["status"] != "held" or calls:
        raise AssertionError("installed RAG example forwarded a held document")
    allowed = rag.answer_with_documents("Question", [("trusted-a", "ordinary")], model_call)
    if (allowed["status"] != "sent" or len(calls) != 1 or
            "ordinary" not in calls[0] or "trusted-a" in calls[0]):
        raise AssertionError("installed RAG example changed the model boundary")
    capped = rag.answer_with_documents("Question", [("trusted-a", "ordinary")],
                                       model_call, max_prompt_chars=8)
    if capped["status"] != "held" or len(calls) != 1:
        raise AssertionError("installed RAG example ignored its prompt cap")
    if tool.continue_with_tool_result("x\u202e", model_call)["status"] != "held" or len(calls) != 1:
        raise AssertionError("installed tool example forwarded a held result")
    if tool.continue_with_tool_result("x\ud800", model_call)["status"] != "held" or len(calls) != 1:
        raise AssertionError("installed tool example forwarded invalid Unicode")
    sent = tool.continue_with_tool_result("exact tool text", model_call)
    if sent["status"] != "sent" or len(calls) != 2 or calls[1] != "exact tool text":
        raise AssertionError("installed tool example changed an allowed result")
    return 6


def main() -> int:
    if len(sys.argv) != 2:
        raise SystemExit("usage: installed_smoke.py REPO_ROOT")
    root = Path(sys.argv[1]).resolve()
    package_path = Path(stegdetect.__file__).resolve()
    if package_path.is_relative_to(root):
        raise RuntimeError(f"source import leaked into installed smoke: {package_path}")
    if not package_path.is_relative_to(Path(sys.prefix).resolve()):
        raise RuntimeError(f"not importing from isolated environment: {package_path}")
    manifest = json.loads((root / "evals" / "manifest.json").read_text(encoding="utf-8"))
    contextual_actions = json.loads((root / "evals" / "contextual-actions.json").read_text(
        encoding="utf-8"))["actions"]
    for fixture in manifest["fixtures"]:
        report = analyze(fixture["text"])
        actual = {"verdict": report.verdict,
                  "categories": sorted({finding.category for finding in report.findings}),
                  "finding_count": len(report.findings), "sanitized": report.sanitized}
        if actual != fixture["expected_legacy"]:
            raise AssertionError(f"installed API mismatch: {fixture['id']}")
        for policy, key in ((Policy.BALANCED, "balanced"),
                            (Policy.LEGACY_VERDICT, "legacy_verdict")):
            inspected = inspect_text(fixture["text"], policy=policy)
            if (inspected.status != "complete" or
                    inspected.action != fixture["expected_actions"][key] or
                    inspected.candidate_text != (fixture["text"] if inspected.action == "allow" else None)):
                raise AssertionError(f"installed policy mismatch: {key}/{fixture['id']}")
        contextual = inspect_text(fixture["text"], policy=Policy.CONTEXTUAL)
        if (contextual.schema_version != 4 or
                contextual.action != contextual_actions[fixture["id"]] or
                contextual.candidate_text != (fixture["text"] if contextual.action == "allow" else None)):
            raise AssertionError(f"installed contextual mismatch: {fixture['id']}")
    snapshot = json.loads((root / "evals" / "fixtures" / "legacy_cli.json").read_text(encoding="utf-8"))
    if snapshot.get("schema_version") != 1 or not snapshot.get("cases"):
        raise AssertionError("CLI snapshot missing or malformed")
    console = Path(sys.prefix) / ("Scripts/stegdetect.exe" if os.name == "nt" else "bin/stegdetect")
    if not console.is_file():
        raise AssertionError(f"installed console entry missing: {console}")
    env = dict(os.environ)
    env.pop("PYTHONPATH", None)
    env["PYTHONIOENCODING"] = "utf-8"
    for case in snapshot["cases"]:
        proc = subprocess.run([str(console), *case["argv"]], cwd=Path.cwd(), env=env,
                              capture_output=True, text=True, encoding="utf-8", timeout=20)
        if proc.returncode != case["exit_code"] or json.loads(proc.stdout) != case["report"]:
            raise AssertionError(f"installed CLI mismatch: {case['argv']!r}, {proc.stderr!r}")
    bounded = inspect_text("\u00a0" * 256 + "\u202e", limits=Limits(max_findings=6))
    if (bounded.schema_version != 3 or bounded.status != "complete" or bounded.action != "block" or
            bounded.finding_count_total != 257 or len(bounded.findings) != 6 or
            not any(f.offset == 256 and f.category == "BIDI_OVERRIDE" for f in bounded.findings)):
        raise AssertionError("installed bounded evidence mismatch")
    if inspect_bytes(b"\xff").status != "invalid_input":
        raise AssertionError("installed strict UTF-8 contract mismatch")
    inspect_cli = subprocess.run([str(console), "--inspect", "policy=allow\u202e"], cwd=Path.cwd(),
                                 env=env, capture_output=True, text=True,
                                 encoding="utf-8", timeout=20)
    cli_report = json.loads(inspect_cli.stdout)
    if (inspect_cli.returncode != 3 or cli_report["schema_version"] != 3 or
            cli_report["status"] != "complete" or
            cli_report["action"] != "block" or cli_report["candidate_text"] is not None or
            not inspect_cli.stdout.isascii()):
        raise AssertionError("installed bounded CLI mismatch")
    flag = "\U0001f3f4" + "".join(chr(0xE0000 + ord(c)) for c in "gbeng") + "\U000e007f"
    contextual_cli = subprocess.run([str(console), "--inspect", "--contextual", flag],
                                    cwd=Path.cwd(), env=env, capture_output=True, text=True,
                                    encoding="utf-8", timeout=20)
    if (contextual_cli.returncode != 0 or
            json.loads(contextual_cli.stdout)["candidate_text"] != flag or
            json.loads(contextual_cli.stdout)["schema_version"] != 4):
        raise AssertionError("installed contextual CLI mismatch")
    batch_cli = subprocess.run([str(console), "--inspect", "--jsonl", "-"],
                               input='"safe"\n"bad\\u202e"\n', cwd=Path.cwd(), env=env,
                               capture_output=True, text=True, encoding="utf-8", timeout=20)
    batch_reports = [json.loads(line) for line in batch_cli.stdout.splitlines()]
    if (batch_cli.returncode != 3 or len(batch_reports) != 2 or
            [row["action"] for row in batch_reports] != ["allow", "block"]):
        raise AssertionError("installed JSONL mismatch")
    integration_cases = _check_installed_examples(root)
    corpus = measure(root / "tests" / "test_false_positives.py")
    expected = json.loads((root / "docs" / "robustness-corpus.json").read_text(encoding="utf-8"))
    if corpus != expected:
        raise AssertionError("installed legacy corpus counts changed")
    print(json.dumps({"installed_module": str(package_path), "api_fixtures": len(manifest["fixtures"]),
                      "policy_cases": len(manifest["fixtures"]) * 2,
                      "contextual_cases": len(manifest["fixtures"]),
                      "cli_cases": len(snapshot["cases"]), "bounded_cases": 3,
                      "developer_cli_cases": 2,
                      "installed_integration_cases": integration_cases,
                      "corpus": corpus}, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
