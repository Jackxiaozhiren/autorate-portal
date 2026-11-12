"""T4 — the M4 §4.4 endpoints over HTTP: scoping, audit rows, locales."""
from __future__ import annotations

import json

from fastapi.testclient import TestClient
from sqlalchemy import select

from autorate_portal import db
from autorate_portal.app import create_app
from conftest import KNOWN_LIMITS

SALT = "test-salt"


def _world4(tmp_path):
    engine = db.make_engine("sqlite:///" + str(tmp_path / "portal.db"))
    db.create_all(engine)
    sessions = db.make_session(engine)
    app = create_app(engine=engine, store_dir=tmp_path / "store", salt=SALT,
                     secret_key="k")
    with sessions() as session:
        session.add(db.Org(id="org-1", name="org-1"))
        session.add(db.Project(id="prj-1", org_id="org-1", name="prj-1"))
        session.add(db.User(id="usr-p", email="producer@example.test", display="P"))
        session.add(db.User(id="usr-v", email="viewer@example.test", display="V"))
        session.add(db.User(id="usr-c", email="compliance@example.test", display="C"))
        for user, role in (("usr-p", "producer"), ("usr-v", "viewer"),
                           ("usr-c", "compliance")):
            session.add(db.Membership(user_id=user, org_id="org-1", role=role))
        session.flush()
        producer, _ = db_token(session, "usr-p")
        viewer, _ = db_token(session, "usr-v")
        compliance, _ = db_token(session, "usr-c")
        session.commit()
    return TestClient(app), sessions, producer, viewer, compliance


def db_token(session, user_id):
    from autorate_portal import auth

    return auth.issue_token(session, user_id=user_id, project_id="prj-1", salt=SALT)


def _upload(client, token, bundle):
    return client.post("/api/v1/packets", headers={"x-api-token": token},
                       files={"file": ("packet.tar", bundle.read_bytes(),
                                       "application/x-tar")})


def _audit(sessions, action):
    with sessions() as session:
        rows = list(session.scalars(select(db.AuditRow).order_by(db.AuditRow.at)))
    return [row for row in rows if row.action == action]


def test_ac6_over_http_a_field_never_measured_is_cannot_be_bounded(tmp_path, m4_built):
    client, sessions, producer, _, _ = _world4(tmp_path)
    assert _upload(client, producer, m4_built[0]).status_code == 201

    body = client.post("/api/v1/claims/check", headers={"x-api-token": producer},
                       json={"share": "0.66", "field": "confidence", "unit": "case",
                             "population": "resolutions"}).json()

    assert body["verdict"] == "cannot_be_bounded"
    assert "A field name therefore does not say" in body["comparability"]
    assert "same-named fields are not the same quantity" in body["reason"]
    assert "denominator:" in body["provenance"]
    assert body["numbers"] == []
    assert body["html"] and _audit(sessions, "claim.check")


def test_ac5_over_http_the_synthetic_certified_autorate_refutes(tmp_path, certified_built):
    client, _, producer, _, _ = _world4(tmp_path)
    assert _upload(client, producer, certified_built[0]).status_code == 201

    body = client.post("/api/v1/claims/check", headers={"x-api-token": producer},
                       json={"share": "0.66", "field": "autorate", "unit": "case",
                             "population": "resolutions"}).json()

    assert body["verdict"] == "bounded_refutes"
    assert "0.66" in body["reason"] and "0.42" in body["reason"]
    assert [row["unit"] for row in body["numbers"]] == ["case", "case"]


def test_f4_exception_b_no_packet_returns_the_one_f1_command(tmp_path):
    client, _, _, viewer, _ = _world4(tmp_path)
    body = client.post("/api/v1/claims/check?locale=zh-Hans",
                       headers={"x-api-token": viewer},
                       json={"share": "0.66", "field": "autorate", "unit": "case",
                             "population": "resolutions"}).json()
    assert body["verdict"] == "cannot_be_bounded"
    assert "packet build" in body["reason"]
    assert body["locale"] == "zh-Hans"


def test_a_partial_claim_is_422_and_the_surface_requires_a_principal(tmp_path):
    client, _, producer, _, _ = _world4(tmp_path)
    assert client.post("/api/v1/claims/check", json={"share": "0.66"}).status_code == 401
    partial = client.post("/api/v1/claims/check", headers={"x-api-token": producer},
                          json={"share": "0.66"})
    assert partial.status_code == 422


def test_a_viewer_may_check_a_claim_but_may_not_export(tmp_path, m4_built):
    client, sessions, producer, viewer, _ = _world4(tmp_path)
    _upload(client, producer, m4_built[0])

    checked = client.post("/api/v1/claims/check", headers={"x-api-token": viewer},
                          json={"share": "0.66", "field": "confidence", "unit": "case",
                                "population": "resolutions"})
    refused = client.post("/api/v1/exports/annex_iv", headers={"x-api-token": viewer})

    assert checked.status_code == 200
    assert refused.status_code == 403
    denials = [row for row in _audit(sessions, "export.build") if row.outcome == "denied"]
    assert denials and denials[0].actor == "usr-v"


def test_f5_over_http_an_export_carries_known_limits_and_is_logged(tmp_path, m4_built):
    client, sessions, producer, _, compliance = _world4(tmp_path)
    _upload(client, producer, m4_built[0])

    response = client.post("/api/v1/exports/annex_iv",
                           headers={"x-api-token": compliance})

    assert response.status_code == 200, response.text
    document = json.loads(response.content)
    assert document["known_limits"] == KNOWN_LIMITS
    assert document["lines"] and all(line["sha256"] for line in document["lines"])
    assert response.headers["x-bundle-sha256"] == document["bundle_sha256"]
    with sessions() as session:
        assert session.scalars(select(db.ExportBundle)).all()
    assert [row for row in _audit(sessions, "export.build") if row.outcome == "allowed"]


def test_an_unknown_export_kind_is_a_named_refusal(tmp_path, m4_built):
    client, _, producer, _, compliance = _world4(tmp_path)
    _upload(client, producer, m4_built[0])
    assert client.post("/api/v1/exports/generic_aap",
                       headers={"x-api-token": compliance}).status_code == 422


def test_ac11_over_http_stale_policy_and_strict_conflict(tmp_path):
    client, sessions, _, _, _ = _world4(tmp_path)
    with sessions() as session:
        session.add(db.Packet(id="pkt-0", project_id="prj-1", manifest_sha256="f" * 64,
                              protocol_digest="aaaaaaaaaaaa", source_version="0.1.2",
                              source_sha256="a" * 64, source_revision="r",
                              created_by="t", ingested_at="2026-11-12T00:00:00", bytes=1))
        session.add(db.Packet(id="pkt-1", project_id="prj-1", manifest_sha256="e" * 64,
                              protocol_digest="bbbbbbbbbbbb", source_version="0.1.2",
                              source_sha256="c" * 64, source_revision="r2",
                              created_by="t", ingested_at="2026-11-12T01:00:00", bytes=1))
        session.add(db.Policy(id="pol-1", project_id="prj-1", name="auto",
                              packet_id="pkt-0", slices="[]", budget="0.05",
                              state="active"))
        session.commit()

    plain = client.get("/api/v1/policies/pol-1.well-known")
    strict = client.get("/api/v1/policies/pol-1.well-known?strict=1")

    assert plain.status_code == 200 and plain.json()["state"] == "stale"
    assert strict.status_code == 409 and strict.json()["state"] == "stale"
    assert client.get("/api/v1/policies/missing.well-known").status_code == 404


def test_ac8_over_http_two_freezes_need_a_boundary(tmp_path):
    client, sessions, producer, _, _ = _world4(tmp_path)
    with sessions() as session:
        for index, digest in enumerate(("aaaaaaaaaaaa", "bbbbbbbbbbbb")):
            session.add(db.Packet(id="pkt-%d" % index, project_id="prj-1",
                                  manifest_sha256=chr(ord("a") + index) * 64,
                                  protocol_digest=digest, source_version="0.1.2",
                                  source_sha256="d" * 64, source_revision="r",
                                  created_by="t",
                                  ingested_at="2026-11-12T0%d:00:00" % index, bytes=1))
        session.commit()

    without = client.get("/api/v1/trends/certificates",
                         headers={"x-api-token": producer}).json()
    with_boundary = client.get("/api/v1/trends/certificates?boundary=1",
                               headers={"x-api-token": producer}).json()

    assert without["drawn"] is False and len(without["digests"]) == 2
    assert with_boundary["drawn"] is True and 'class="boundary"' in with_boundary["html"]


def test_badge_as_shareable_over_http_has_no_records_and_a_closed_state(tmp_path, m4_built):
    client, _, producer, viewer, _ = _world4(tmp_path)
    _upload(client, producer, m4_built[0])

    body = client.get("/api/v1/badge/shareable",
                      headers={"x-api-token": viewer}).json()

    assert body["state"] == "not-certifiable"
    assert body["records_included"] is False and body["records_rows"] == 0
    assert body["denominator_line"] == "re-derived 612 /612 values"
    svg = client.get("/api/v1/badge/shareable?format=svg",
                     headers={"x-api-token": viewer})
    assert svg.status_code == 200 and b"not-certifiable" in svg.content


def test_the_claim_card_is_localized_over_http(tmp_path, m4_built):
    client, _, producer, _, _ = _world4(tmp_path)
    _upload(client, producer, m4_built[0])
    claim = {"share": "0.66", "field": "confidence", "unit": "case",
             "population": "resolutions"}

    english = client.post("/api/v1/claims/check", headers={"x-api-token": producer},
                          json=claim).json()
    chinese = client.post("/api/v1/claims/check?locale=zh-Hans",
                          headers={"x-api-token": producer}, json=claim).json()

    assert english["verdict"] == chinese["verdict"] == "cannot_be_bounded"
    assert english["html"] != chinese["html"]
    assert "判定" in chinese["html"] and "verdict" in english["html"].lower()
