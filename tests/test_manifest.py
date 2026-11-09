"""T1 - the manifest contract. Missing fields are validation errors, not defaults."""
from __future__ import annotations

import copy

import pytest
from pydantic import ValidationError

from autorate_portal.manifest import Manifest, payload_sha256
from conftest import split_bundle

REQUIRED = ("schema_version", "packet_id", "protocol_digest", "protocol_sha256",
            "manifest_sha256", "source_revision", "source_version", "bound_unit",
            "lane", "expected_rederived", "rubric", "distribution", "artifacts",
            "records_excluded", "excluded_records")
ARTEFACT_FIELDS = ("path", "sha256", "kind", "bytes")


def _valid(document):
    document["manifest_sha256"] = payload_sha256(document)
    return Manifest.model_validate(document)


def test_every_declared_field_is_required(built):
    document, _ = split_bundle(built[0])
    for field in REQUIRED:
        broken = copy.deepcopy(document)
        broken.pop(field)
        if field == "manifest_sha256":
            # Resealing would put the removed field back, hiding the absence.
            # Assert directly that the contract does not default it.
            with pytest.raises(ValidationError):
                Manifest.model_validate(broken)
        else:
            with pytest.raises(ValidationError):
                _valid(broken)


def test_every_artefact_field_is_required(built):
    document, _ = split_bundle(built[0])
    for field in ARTEFACT_FIELDS:
        broken = copy.deepcopy(document)
        broken["artifacts"][0].pop(field)
        with pytest.raises(ValidationError):
            _valid(broken)


def test_pinned_wheel_hash_is_required(built):
    document, _ = split_bundle(built[0])
    document["distribution"].pop("sha256")
    with pytest.raises(ValidationError):
        _valid(document)


def test_self_hash_mismatch_is_refused(built):
    document, _ = split_bundle(built[0])
    document["source_revision"] = "some-other-revision"
    with pytest.raises(ValidationError, match="manifest_sha256 mismatch"):
        Manifest.model_validate(document)


def test_absolute_and_traversal_paths_are_refused(built):
    document, _ = split_bundle(built[0])
    for bad in ("/etc/passwd", "data/../../etc/passwd", "data\\records.jsonl"):
        broken = copy.deepcopy(document)
        broken["artifacts"][0]["path"] = bad
        broken["artifacts"] = sorted(broken["artifacts"], key=lambda a: a["path"])
        with pytest.raises(ValidationError):
            _valid(broken)


def test_duplicate_and_unsorted_artefact_paths_are_refused(built):
    document, _ = split_bundle(built[0])
    dup = copy.deepcopy(document)
    # Insert at the head so the list stays sorted: the duplicate check must fire
    # on its own, not merely as a side effect of the ordering check.
    dup["artifacts"].insert(0, copy.deepcopy(dup["artifacts"][0]))
    with pytest.raises(ValidationError, match="duplicate"):
        _valid(dup)
    unsorted = copy.deepcopy(document)
    unsorted["artifacts"].reverse()
    with pytest.raises(ValidationError, match="sorted"):
        _valid(unsorted)


def test_protocol_digest_is_the_declared_prefix(built):
    document, _ = split_bundle(built[0])
    document["protocol_digest"] = "0" * 12
    with pytest.raises(ValidationError, match="prefix"):
        _valid(document)


def test_shareable_packet_cannot_declare_records_artefacts(built):
    document, _ = split_bundle(built[0])
    document["records_excluded"] = True
    document["excluded_records"] = ["data/records_feishu.jsonl"]
    with pytest.raises(ValidationError, match="cannot carry records"):
        _valid(document)


def test_extra_fields_are_refused(built):
    document, _ = split_bundle(built[0])
    document["unexpected_claim"] = "a number nobody published"
    with pytest.raises(ValidationError):
        _valid(document)


def test_valid_manifest_round_trips(built):
    document, _ = split_bundle(built[0])
    assert _valid(copy.deepcopy(document)).packet_id == document["packet_id"]
