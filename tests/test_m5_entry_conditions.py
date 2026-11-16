"""M5 entry conditions — W-F1 and W-F2, the two findings M5 must fix before it closes.

W-F1: the one `certified` row's detail said `bound: not published by this
certificate` while the artefact publishes `bound`. The artefact omits the unit,
which is a different fact from omitting the number, and the panel must say which.

W-F2: the detail group panel rendered `slices_language.json`'s four `laya`
groups beside certificates from other backends, every row carrying
`n_cal=1487`, and never named whose dataset those groups were.

Both tests read a packet built from the artefact shapes the frozen repository
publishes, not from hand-made objects, so a fix that only satisfies an object
literal does not pass.
"""
from __future__ import annotations

import json
from pathlib import Path

import pytest
from sqlalchemy import select

from autorate_portal import db
from autorate_portal.ingest import ingest
from autorate_portal.packet import build
from autorate_portal.views import (ABSENT_NUMBER, certificate_panel, slice_context,
                                   slice_rows, slice_view)

REGISTRY_VERSION = "0.1.2"

#: The shape `data/cert_severity_ordinal.json` actually publishes: a top-level
#: `bound`, no `autorate`, and no unit anywhere in the document.
ORDINAL_CERT = {
    "backend": "synthetic-ordinal", "feasible": True, "reason": None,
    "bound": 0.045180414995, "n_cal": 600, "n_eval": 600,
    "alpha": 0.05, "beta": 0.05, "delta": 0.05, "direction": "under", "shape": 1,
    "meta": {"alpha": 0.05, "beta": 0.05, "delta": 0.05, "seed": 7, "method": "aps",
             "n_cal_cases": 200, "n_eval_cases": 200},
}

#: `data/slices_language.json`'s published groups: four `laya` groups, each
#: carrying the whole pool's denominator.
SLICES_DOCUMENT = {
    "backend": "laya", "group_key": "language",
    "run": {"alpha": 0.05, "beta": 0.05, "delta": 0.05, "groups": ["language"],
            "per_group": {name: {"backend": "laya", "alpha": 0.0125, "beta": 0.05,
                                 "delta": 0.0125, "method": "aps", "feasible": False,
                                 "reason": "empty_feasible_set", "n_cal": 1487,
                                 "n_eval": 1487}
                          for name in ("de", "en", "km", "sw")}},
}


def _session():
    engine = db.make_engine("sqlite://")
    db.create_all(engine)
    session = db.make_session(engine)()
    session.add(db.Org(id="org-1", name="org-1"))
    session.add(db.Project(id="prj-1", org_id="org-1", name="prj-1"))
    session.flush()
    return session


def _registry(tmp_path: Path, sha256: str) -> Path:
    path = tmp_path / "pins.json"
    path.write_text(json.dumps({"schema": "test", "pins": [
        {"name": "autorate", "version": REGISTRY_VERSION,
         "wheel": "autorate-%s-py3-none-any.whl" % REGISTRY_VERSION, "sha256": sha256,
         "source": "https://pypi.org/pypi/autorate/%s/json" % REGISTRY_VERSION}]}),
        encoding="utf-8")
    return path


@pytest.fixture
def ordinal_built(tmp_path, source_tree, build_kwargs):
    """A packet whose ordinal certificate publishes a bound and no unit."""
    (source_tree / "data" / "cert_severity_ordinal.json").write_text(
        json.dumps(ORDINAL_CERT, sort_keys=True), encoding="utf-8")
    (source_tree / "data" / "slices_language.json").write_text(
        json.dumps(SLICES_DOCUMENT, sort_keys=True), encoding="utf-8")
    out = tmp_path / "ordinal.packet.tar"
    manifest, raw = build(source_tree, out, **build_kwargs)
    return out, manifest, raw


def test_w_f1_the_summary_copies_the_bound_the_artefact_publishes(ordinal_built, tmp_path):
    """Red before the fix: `bound` lands NULL and the view denies the number exists."""
    session = _session()
    packet, manifest, _ = ordinal_built

    ingest(session, bundle_path=packet, project_id="prj-1", actor="producer@example.test",
           registry_path=_registry(tmp_path, manifest.distribution.sha256))
    summary = session.scalars(select(db.CertificateSummary).where(
        db.CertificateSummary.task == "severity_ordinal")).one()

    assert summary.bound == "0.045180414995", "the artefact published this digit string"
    assert summary.bound_unit is None, "the artefact published no unit; none may be invented"


def test_w_f1_the_panel_names_the_missing_unit_instead_of_denying_the_bound(ordinal_built,
                                                                           tmp_path):
    """Red before the fix: `not published by this certificate` is false about the bytes."""
    session = _session()
    packet, manifest, _ = ordinal_built
    ingest(session, bundle_path=packet, project_id="prj-1", actor="producer@example.test",
           registry_path=_registry(tmp_path, manifest.distribution.sha256))
    summary = session.scalars(select(db.CertificateSummary).where(
        db.CertificateSummary.task == "severity_ordinal")).one()
    stored = db.Packet
    packet_row = session.scalars(select(stored)).one()

    panel = certificate_panel(summary=summary, packet=packet_row,
                             rubric={"alpha": 0.05, "beta": 0.05, "delta": 0.05,
                                     "method": "aps", "seed": 7},
                             certificate=ORDINAL_CERT)

    bound_line = "bound: " + ABSENT_NUMBER
    assert bound_line not in panel.body, (
        "the bound exists; calling it unpublished is a false statement about the artefact")
    assert "bound_unit" in panel.body, "the missing component has to be named"
    assert "unavailable" in panel.body
    assert "0.045180414995" not in panel.body, (
        "I2: a number without its unit must not reach the document")
    assert "autorate: " + ABSENT_NUMBER in panel.body, (
        "the artefact publishes no autorate, and that absence is still printed as absence")


def test_w_f1_a_bound_with_no_artefact_behind_it_is_still_refused():
    """The guard keeps failing closed for a caller that cannot point at published bytes."""
    session = _session()
    session.add(db.Packet(id="pkt-1", project_id="prj-1", manifest_sha256="a" * 64,
                          protocol_digest="b" * 12, source_version="0.1.2",
                          source_sha256="c" * 64, source_revision="d" * 40,
                          created_by="x", ingested_at="2026-11-16T00:00:00Z", bytes=1))
    session.flush()
    session.add(db.Artifact(id="art-1", packet_id="pkt-1", path="data/cert_x.json",
                            sha256="e" * 64, kind="certificate"))
    session.flush()

    with pytest.raises(ValueError, match="bound without its unit"):
        db.record_summary(session, artifact_id="art-1",
                          fields={"task": "x", "backend": "x", "bound": "0.1",
                                  "bound_unit": None})


def test_w_f2_the_group_panel_names_the_source_and_the_backend_it_belongs_to():
    """Red before the fix: four `laya` groups render beside any certificate, unnamed."""
    certificate = {"backend": "jev", "feasible": False, "reason": "empty_feasible_set"}

    rows = slice_rows(SLICES_DOCUMENT, source_path="data/slices_language.json")
    assert {row["source_backend"] for row in rows} == {"laya"}
    view = slice_view(pooled=certificate_panel(
        summary=db.CertificateSummary(task="jev", backend="jev", feasible=False,
                                      reason="empty_feasible_set"),
        packet=db.Packet(id="pkt-1", protocol_digest="abc123abc123"),
        rubric={}, certificate=certificate),
        companion=None, document=SLICES_DOCUMENT,
        context={**slice_context(type("M", (), {"rubric": {}, "packet_id": "pkt-1",
                                                "protocol_digest": "abc123abc123"})(),
                                 SLICES_DOCUMENT),
                 "source_path": "data/slices_language.json", "viewed_backend": "jev"})

    assert "data/slices_language.json" in view["html"], "the source artefact is named"
    assert "laya" in view["html"]
    assert "jev" in view["html"], "the reader is told these groups are not this backend's"
    assert view["notes"], "the mismatch is also a note, not only a colour"


def test_w_f2_a_matching_backend_prints_no_mismatch_note():
    document = {**SLICES_DOCUMENT, "backend": "laya"}
    view = slice_view(pooled=certificate_panel(
        summary=db.CertificateSummary(task="laya", backend="laya", feasible=False,
                                      reason="empty_feasible_set"),
        packet=db.Packet(id="pkt-1", protocol_digest="abc123abc123"),
        rubric={}, certificate=document),
        companion=None, document=document,
        context={**slice_context(type("M", (), {"rubric": {}, "packet_id": "pkt-1",
                                                "protocol_digest": "abc123abc123"})(),
                                 document), "viewed_backend": "laya"})

    assert "not this certificate" not in view["html"]
