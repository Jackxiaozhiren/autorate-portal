"""T5 — I4 / AC8: two freezes draw a boundary or draw nothing."""
from __future__ import annotations

from autorate_portal import db, trend

DIGEST_A = "aaaaaaaaaaaa"
DIGEST_B = "bbbbbbbbbbbb"


def _sessions(digests):
    engine = db.make_engine("sqlite:///:memory:")
    db.create_all(engine)
    sessions = db.make_session(engine)
    with sessions() as session:
        session.add(db.Org(id="org-1", name="org-1"))
        session.add(db.Project(id="prj-1", org_id="org-1", name="prj-1"))
        session.flush()
        for index, digest in enumerate(digests):
            packet = db.Packet(
                id="pkt-%d" % index, project_id="prj-1",
                manifest_sha256=("%064x" % index),
                protocol_digest=digest, source_version="0.1.2", source_sha256="a" * 64,
                source_revision="rev", created_by="tester",
                ingested_at="2026-11-12T0%d:00:00" % index, bytes=100)
            session.add(packet)
            session.flush()
            artefact = db.Artifact(id="art-%d" % index, packet_id=packet.id,
                                   path="data/cert_%d.json" % index,
                                   sha256="b" * 64, kind="certificate")
            session.add(artefact)
            session.flush()
            db.record_summary(session, artifact_id=artefact.id, fields={
                "task": "task-%d" % index, "backend": "fixture", "feasible": False,
                "reason": "empty_feasible_set", "autorate": None, "bound": None,
                "bound_unit": None, "n_cal": 96, "n_eval": 96,
                "alpha": "0.05", "beta": "0.05", "delta": "0.05"})
        session.commit()
    return sessions


def test_ac8_two_freezes_do_not_share_an_axis_without_a_boundary():
    sessions = _sessions((DIGEST_A, DIGEST_B))
    with sessions() as session:
        view = trend.trend_for(session, project_id="prj-1", boundary=False)

    assert view.drawn is False
    assert view.rows == ()
    assert DIGEST_A in view.reason and DIGEST_B in view.reason
    assert 'class="boundary"' not in view.html


def test_ac8_a_drawn_boundary_names_both_digests_and_computes_no_delta():
    sessions = _sessions((DIGEST_A, DIGEST_B))
    with sessions() as session:
        view = trend.trend_for(session, project_id="prj-1", boundary=True)

    assert view.drawn is True and view.boundary is True
    assert len(view.rows) == 2
    assert 'class="boundary"' in view.html
    assert DIGEST_A in view.html and DIGEST_B in view.html
    assert "no delta" in view.reason
    assert {row["protocol_digest"] for row in view.rows} == {DIGEST_A, DIGEST_B}


def test_one_freeze_draws_within_its_own_digest():
    sessions = _sessions((DIGEST_A,))
    with sessions() as session:
        view = trend.trend_for(session, project_id="prj-1")

    assert view.drawn is True
    assert "within one protocol_digest" in view.reason
    assert 'class="boundary"' not in view.html


def test_no_packets_answers_no_evidence_published_not_an_empty_green_chart():
    sessions = _sessions(())
    with sessions() as session:
        view = trend.trend_for(session, project_id="prj-1")

    assert view.digests == ()
    assert "no evidence published" in view.reason
    assert view.html


def test_the_series_rows_are_published_values_not_recomputed_ones():
    sessions = _sessions((DIGEST_A,))
    with sessions() as session:
        view = trend.trend_for(session, project_id="prj-1")
    row = view.rows[0]
    assert row["autorate"] == "not published by this certificate"
    assert row["n_cal"] == "96" and row["n_eval"] == "96"
    assert row["protocol_digest"] == DIGEST_A
