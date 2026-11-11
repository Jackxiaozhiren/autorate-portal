"""T8 - Section 4.4's surface: scoped by the caller, and denials are recorded."""
from __future__ import annotations

from fastapi.testclient import TestClient
from sqlalchemy import select

from autorate_portal import auth, db
from autorate_portal.app import create_app

SALT = "test-salt"


def _world(tmp_path):
    engine = db.make_engine("sqlite:///" + str(tmp_path / "portal.db"))
    db.create_all(engine)
    sessions = db.make_session(engine)
    app = create_app(engine=engine, store_dir=tmp_path / "store", salt=SALT, secret_key="k")
    with sessions() as session:
        session.add(db.Org(id="org-1", name="org-1"))
        session.add(db.Project(id="prj-1", org_id="org-1", name="prj-1"))
        session.add(db.Project(id="prj-2", org_id="org-1", name="prj-2"))
        session.add(db.User(id="usr-p", email="producer@example.test", display="P"))
        session.add(db.User(id="usr-v", email="viewer@example.test", display="V"))
        session.add(db.Membership(user_id="usr-p", org_id="org-1", role="producer"))
        session.add(db.Membership(user_id="usr-v", org_id="org-1", role="viewer"))
        session.flush()
        producer, _ = auth.issue_token(session, user_id="usr-p", project_id="prj-1", salt=SALT)
        viewer, _ = auth.issue_token(session, user_id="usr-v", project_id="prj-1", salt=SALT)
        session.commit()
    return TestClient(app), sessions, producer, viewer


def _upload(client, token, bundle):
    return client.post("/api/v1/packets", headers={"x-api-token": token},
                       files={"file": ("packet.tar", bundle.read_bytes(), "application/x-tar")})


def _audit(sessions, action=None):
    with sessions() as session:
        rows = list(session.scalars(select(db.AuditRow).order_by(db.AuditRow.at)))
    return [row for row in rows if action is None or row.action == action]


def test_health_and_version_are_open(tmp_path):
    client, _, _, _ = _world(tmp_path)
    assert client.get("/healthz").json() == {"status": "ok"}
    body = client.get("/version").json()
    assert body["version"] and body["autorate"] == "0.1.2"


def test_without_a_token_the_surface_is_closed(tmp_path):
    client, _, _, _ = _world(tmp_path)

    assert client.get("/api/v1/certificates").status_code == 401
    assert client.get("/api/v1/certificates",
                      headers={"x-api-token": "nope"}).status_code == 401


def test_a_viewer_cannot_ingest_and_the_denial_is_written_down(tmp_path, built):
    client, sessions, _, viewer = _world(tmp_path)

    response = _upload(client, viewer, built[0])

    assert response.status_code == 403
    denials = [row for row in _audit(sessions, "packet.ingest") if row.outcome == "denied"]
    assert denials and denials[0].actor == "usr-v"
    assert denials[0].project_id == "prj-1"


def test_a_producer_ingests_and_the_certificates_are_listed_with_their_reasons(tmp_path, built):
    client, sessions, producer, _ = _world(tmp_path)

    response = _upload(client, producer, built[0])

    assert response.status_code == 201, response.text
    assert response.json()["id"].startswith("pkt-")
    listing = client.get("/api/v1/certificates", headers={"x-api-token": producer})
    rows = listing.json()
    assert len(rows) == 7
    assert {row["reason"] for row in rows} == {"empty_feasible_set"}
    assert all(row["feasible"] is False for row in rows)
    assert {row["bound"] for row in rows} == {None}, "a bound the artefact omits is not zero"
    assert [row for row in _audit(sessions, "packet.ingest") if row.outcome == "allowed"]


def test_ac13_a_viewer_reading_records_is_refused_and_named_in_the_audit(tmp_path, built):
    client, sessions, producer, viewer = _world(tmp_path)
    _upload(client, producer, built[0])
    with sessions() as session:
        records = session.scalar(select(db.Artifact).where(db.Artifact.kind == "records"))
        protocol = session.scalar(select(db.Artifact).where(db.Artifact.kind == "protocol"))
        packet_id = records.packet_id

    refused = client.get("/api/v1/packets/%s/artifacts/%s" % (packet_id, records.id),
                         headers={"x-api-token": viewer})
    allowed = client.get("/api/v1/packets/%s/artifacts/%s" % (packet_id, protocol.id),
                         headers={"x-api-token": viewer})

    assert refused.status_code == 403
    assert allowed.status_code == 200 and allowed.content
    denials = [row for row in _audit(sessions, "artifact.download") if row.outcome == "denied"]
    assert denials and denials[0].target == "artifact:%s" % records.id


def test_a_packet_from_another_project_is_not_found_not_forbidden(tmp_path, built):
    client, sessions, producer, _ = _world(tmp_path)
    _upload(client, producer, built[0])
    with sessions() as session:
        packet = session.scalar(select(db.Packet))
    assert client.get("/api/v1/packets/%s" % packet.id,
                      headers={"x-api-token": producer}).status_code == 200
    other = client.get("/api/v1/packets/%s?project=prj-2" % packet.id,
                       headers={"x-api-token": producer})
    assert other.status_code == 403, "the token is scoped; asking for another project is refused"


def test_the_slice_surface_says_no_slice_evidence_when_the_artefact_declares_none(tmp_path, built):
    client, sessions, producer, _ = _world(tmp_path)
    _upload(client, producer, built[0])
    row = client.get("/api/v1/certificates", headers={"x-api-token": producer}).json()[0]

    body = client.get("/api/v1/certificates/%s/slices" % row["id"],
                      headers={"x-api-token": producer}).json()

    assert "no_slice_evidence" in body["notes"]
    assert body["state"] == "refusal" and body["reason"] == "empty_feasible_set"


def test_the_slice_surface_renders_the_packets_published_groups_over_http(
        tmp_path, source_tree, build_kwargs):
    """C1: the four groups must reach the HTTP response, not just a direct call."""
    import json

    from autorate_portal.packet import build

    groups = {}
    for name, n in (("de", 1487), ("en", 1512), ("km", 402), ("sw", 388)):
        groups[name] = {"n_cal": n, "n_eval": n, "feasible": False,
                        "reason": "empty_feasible_set", "autorate": None,
                        "conditional_error_bound": None, "alpha": 0.0125,
                        "beta": 0.05, "delta": 0.0125, "method": "aps",
                        "meta": {"seed": 7}}
    slices = {"group_key": "language",
              "run": {"groups": ["language"], "per_group": groups,
                      "alpha": 0.05, "beta": 0.05, "delta": 0.05,
                      "corrected_alpha": 0.0125, "corrected_beta": 0.0125,
                      "corrected_delta": 0.0125}}
    (source_tree / "data" / "slices_language.json").write_text(
        json.dumps(slices), encoding="utf-8")
    bundle = tmp_path / "slices.packet.tar"
    build(source_tree, bundle, **build_kwargs)

    client, _, producer, _ = _world(tmp_path)
    assert _upload(client, producer, bundle).status_code == 201
    row = client.get("/api/v1/certificates", headers={"x-api-token": producer}).json()[0]
    body = client.get("/api/v1/certificates/%s/slices" % row["id"],
                      headers={"x-api-token": producer}).json()

    html = body["html"]
    assert html.count('<div class="slice" data-state="refusal"') == 4, html
    assert html.count("n_cal=") == 4, "each group states its own denominator"
    assert html.count('<section class="panel"') == 2, "pooled and companion side by side"
    assert "group-conditional companion / published groups" in html
    assert "empty_feasible_set" in html
    assert "no_slice_evidence" not in body["notes"], "the packet published four groups"
    assert "corrected alpha 0.0125" in html, "F3 rule 5: display the published correction"
    assert "uncorrected alpha 0.05" in html


def test_the_slice_surface_reads_the_packets_slices_artefact_not_only_the_certificate():
    import json
    from types import SimpleNamespace

    from autorate_portal.app import _slice_document

    slices = {"group_key": "language",
              "run": {"groups": ["language"],
                      "per_group": {"de": {"n_cal": 10, "n_eval": 10, "feasible": False,
                                           "reason": "empty_feasible_set"}}}}
    packet = SimpleNamespace(artifacts=[
        SimpleNamespace(path="data/cert_laya.json", kind="certificate"),
        SimpleNamespace(path="data/slices_language.json", kind="document"),
    ])
    stored = SimpleNamespace(files={"data/cert_laya.json": b"{}",
                                    "data/slices_language.json": json.dumps(slices).encode()})

    assert _slice_document(packet, stored, {}) == slices

    own = {"slices": [{"key": "lang", "value": "de", "n_cal": 5, "n_eval": 5}]}
    assert _slice_document(packet, stored, own) is own, "a certificate's own slices win"


def test_the_single_page_client_is_served_by_the_same_process(tmp_path):
    client, _, _, _ = _world(tmp_path)
    page = client.get("/")
    assert page.status_code == 200
    assert "autorate portal" in page.text
