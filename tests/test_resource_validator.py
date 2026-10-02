"""A stale or doctored resource report must not pass the P2 gate."""
import copy
import json

import pytest

from scripts.validate_resources import (
    ARTIFACT, RECEIPT, verify_receipt, verify_resource_artifact, verify_structure,
)


def test_full_resource_artifact_and_receipt():
    summary = verify_resource_artifact()
    assert summary["rows"] == 21
    assert summary["trials"] == 1610
    assert summary["timeouts"] == 0


def test_missing_workload_or_recomputed_timing_is_rejected():
    data = json.loads(ARTIFACT.read_text(encoding="utf-8"))
    missing = copy.deepcopy(data)
    missing["rows"].pop()
    with pytest.raises(ValueError, match="missing"):
        verify_structure(missing)
    doctored = copy.deepcopy(data)
    doctored["rows"][0]["raw_seconds"][-1] += 1
    with pytest.raises(ValueError, match="summary"):
        verify_structure(doctored)


def test_output_over_budget_and_stale_source_receipt_are_rejected():
    data = json.loads(ARTIFACT.read_text(encoding="utf-8"))
    data["rows"][0]["output_bytes"] = 16_777_217
    with pytest.raises(ValueError, match="budget"):
        verify_structure(data)
    receipt = json.loads(RECEIPT.read_text(encoding="utf-8"))
    receipt["source_sha256"]["src/stegdetect/inspection.py"] = "0" * 64
    with pytest.raises(ValueError, match="source changed"):
        verify_receipt(receipt)
