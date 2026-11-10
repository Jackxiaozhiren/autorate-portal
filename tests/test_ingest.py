"""T5 - F1: accept only when every check passes, and never index a refusal."""
from __future__ import annotations

import io
import json
import tarfile

from sqlalchemy import select

from autorate_portal import db
from autorate_portal.ingest import (BADGE_UNVERIFIED, STATE_INCONSISTENT, STATE_REFUSED,
                                    ingest)
from autorate_portal.manifest import sha256_bytes
from conftest import reseal_manifest, rewrite_bundle, split_bundle, tamper_bundle

REGISTRY_VERSION = "0.1.2"


def _session():
    engine = db.make_engine("sqlite://")
    db.create_all(engine)
    session = db.make_session(engine)()
    session.add(db.Org(id="org-1", name="org-1"))
    session.add(db.Project(id="prj-1", org_id="org-1", name="prj-1"))
    session.flush()
    return session


def _registry(tmp_path, sha256):
    path = tmp_path / "pins.json"
    path.write_text(json.dumps({"schema": "test", "pins": [
        {"name": "autorate", "version": REGISTRY_VERSION,
         "wheel": "autorate-%s-py3-none-any.whl" % REGISTRY_VERSION, "sha256": sha256,
         "source": "https://pypi.org/pypi/autorate/%s/json" % REGISTRY_VERSION}]}),
        encoding="utf-8")
    return path


def _counts(session):
    return (len(session.scalars(select(db.Packet)).all()),
            len(session.scalars(select(db.Artifact)).all()),
            len(session.scalars(select(db.CertificateSummary)).all()))


def test_a_valid_bundle_is_indexed_with_artefacts_and_copied_summaries(built, tmp_path):
    session = _session()
    packet, manifest, _ = built

    result = ingest(session, bundle_path=packet, project_id="prj-1", actor="producer@example.test",
                    registry_path=_registry(tmp_path, manifest.distribution.sha256),
                    now="2026-11-10T12:00:00.000000+00:00")

    assert result.accepted and result.state == "indexed"
    assert result.badge == "" and result.packet_id == manifest.packet_id
    packet_rows, artifacts, summaries = _counts(session)
    assert packet_rows == 1
    assert artifacts == len(manifest.artifacts)
    assert summaries == sum(1 for a in manifest.artifacts if a.kind == "certificate")

    row = session.get(db.Packet, result.row_id)
    assert row.created_by == "producer@example.test"
    assert row.manifest_sha256 == manifest.manifest_sha256
    assert len(row.source_sha256) == 64 and row.source_sha256 != manifest.manifest_sha256

    first = db.summaries_for_project(session, project_id="prj-1")[0]
    assert first.feasible is False
    assert first.reason == "empty_feasible_set", "the reason is copied verbatim"
    assert first.bound is None and first.bound_unit is None
    assert first.n_cal == 96 and first.n_eval == 96
    assert first.alpha == "0.05", "the artefact's own digits, not a float round-trip"


def test_one_tampered_byte_is_a_named_refusal_and_nothing_is_indexed(built, tmp_path):
    session = _session()
    packet, manifest, _ = built
    tamper_bundle(packet, "data/cert_laya.json", b"tampered")

    result = ingest(session, bundle_path=packet, project_id="prj-1", actor="producer@example.test",
                    registry_path=_registry(tmp_path, manifest.distribution.sha256))

    assert result.state == STATE_REFUSED and not result.accepted
    assert result.refusals, "a refusal names what it refused"
    refusal = result.refusals[0]
    assert refusal.path == "data/cert_laya.json"
    assert refusal.expected and refusal.actual and refusal.expected != refusal.actual
    assert _counts(session) == (0, 0, 0)
    audit = list(session.scalars(select(db.AuditRow)))
    assert audit and audit[0].outcome == "denied" and audit[0].actor == "producer@example.test"


def test_an_over_cap_bundle_is_refused_with_the_byte_count_and_the_cap(built):
    session = _session()
    packet, _, _ = built
    size = packet.stat().st_size

    result = ingest(session, bundle_path=packet, project_id="prj-1", actor="a", cap=size - 1)

    assert result.state == STATE_REFUSED
    assert result.refusals[0].expected == str(size - 1)
    assert result.refusals[0].actual == str(size)
    assert "cap" in result.refusals[0].reason


def test_a_traversal_member_is_refused_and_the_actor_is_logged(built, tmp_path):
    session = _session()
    packet, manifest, _ = built
    document, files = split_bundle(packet)
    evil = tmp_path / "evil.tar"
    with tarfile.open(evil, "w") as tar:
        for name, data in [("manifest.json", json.dumps(document, sort_keys=True).encode()),
                           ("../escape.json", b"x")]:
            info = tarfile.TarInfo(name)
            info.size = len(data)
            tar.addfile(info, io.BytesIO(data))

    result = ingest(session, bundle_path=evil, project_id="prj-1", actor="intruder@example.test")

    assert result.state == STATE_REFUSED
    assert any("traverses" in refusal.reason for refusal in result.refusals)
    audit = list(session.scalars(select(db.AuditRow)))
    assert audit[0].action == "packet.ingest.traversal"
    assert audit[0].actor == "intruder@example.test"


def test_re_ingesting_the_same_manifest_is_one_row_and_no_duplicate_artefacts(built, tmp_path):
    session = _session()
    packet, manifest, _ = built
    registry = _registry(tmp_path, manifest.distribution.sha256)
    first = ingest(session, bundle_path=packet, project_id="prj-1", actor="a", registry_path=registry)
    before = _counts(session)

    second = ingest(session, bundle_path=packet, project_id="prj-1", actor="a", registry_path=registry)

    assert second.accepted and second.row_id == first.row_id
    assert "one row" in second.note
    assert _counts(session) == before


def test_the_same_packet_in_another_project_is_another_row_not_a_collision(built, tmp_path):
    session = _session()
    session.add(db.Org(id="org-2", name="org-2"))
    session.add(db.Project(id="prj-2", org_id="org-2", name="prj-2"))
    session.flush()
    packet, manifest, _ = built
    registry = _registry(tmp_path, manifest.distribution.sha256)

    mine = ingest(session, bundle_path=packet, project_id="prj-1", actor="a", registry_path=registry)
    theirs = ingest(session, bundle_path=packet, project_id="prj-2", actor="b", registry_path=registry)

    assert mine.accepted and theirs.accepted
    assert mine.row_id != theirs.row_id
    assert len(db.summaries_for_project(session, project_id="prj-1")) == 7
    assert len(db.summaries_for_project(session, project_id="prj-2")) == 7


def test_a_duplicate_records_row_is_inconsistent_and_nothing_is_indexed(built):
    session = _session()
    packet, _, _ = built
    document, files = split_bundle(packet)
    row = files["data/records_feishu.jsonl"]
    files["data/records_feishu.jsonl"] = row + row
    for artefact in document["artifacts"]:
        if artefact["path"] == "data/records_feishu.jsonl":
            artefact["sha256"] = sha256_bytes(files["data/records_feishu.jsonl"])
            artefact["bytes"] = len(files["data/records_feishu.jsonl"])
    rewrite_bundle(packet, files, reseal_manifest(document))

    result = ingest(session, bundle_path=packet, project_id="prj-1", actor="a")

    assert result.state == STATE_INCONSISTENT, "the view must be blocked, not partially filled"
    assert "records_feishu.jsonl" in result.refusals[0].reason
    assert _counts(session) == (0, 0, 0)


def test_a_distribution_the_registry_cannot_confirm_is_accepted_with_a_badge(built, tmp_path):
    session = _session()
    packet, _, _ = built
    result = ingest(session, bundle_path=packet, project_id="prj-1", actor="a",
                    registry_path=_registry(tmp_path, "0" * 64))

    assert result.accepted, "F1 rule 5 accepts it; the badge is the warning"
    assert result.badge == BADGE_UNVERIFIED
    assert "registry" in result.note


def test_a_confirmed_distribution_carries_no_badge(built, tmp_path):
    session = _session()
    packet, manifest, _ = built
    result = ingest(session, bundle_path=packet, project_id="prj-1", actor="a",
                    registry_path=_registry(tmp_path, manifest.distribution.sha256))
    assert result.badge == "" and result.note == ""
