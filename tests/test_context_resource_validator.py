import json

import pytest

from scripts.validate_context_resources import ARTIFACT, verify_context_resources


def test_context_resource_artifact_is_complete_and_source_bound():
    assert verify_context_resources()["trials"] == 40


def test_context_resource_validator_rejects_dropped_trial():
    changed = json.loads(ARTIFACT.read_text(encoding="utf-8"))
    changed["rows"][0]["raw_seconds"].pop()
    with pytest.raises(ValueError):
        verify_context_resources(changed)


def test_context_resource_validator_rejects_wrong_source_hash():
    changed = json.loads(ARTIFACT.read_text(encoding="utf-8"))
    first = next(iter(changed["source_sha256"]))
    changed["source_sha256"][first] = "0" * 64
    with pytest.raises(ValueError):
        verify_context_resources(changed)
