"""AC12 — a records file that reuses a calibration case id is refused, with the
collision and the split-rollback consequence named.

The packet fixture's records artefact holds `fixture-case-1`. The collision test
uploads that id; the negative control uploads a new one and must pass, because a
guard that refuses everything would also make the first test green.
"""
from __future__ import annotations

import json

from fastapi.testclient import TestClient
from sqlalchemy import select

from autorate_portal import auth, db
from autorate_portal.app import create_app
from autorate_portal.records import SPLIT_CONSEQUENCE

SALT = "test-salt"


def _world(tmp_path):
    engine = db.make_engine("sqlite:///" + str(tmp_path / "portal.db"))
    db.create_all(engine)
    sessions = db.make_session(engine)
    app = create_app(engine=engine, store_dir=tmp_path / "store", salt=SALT, secret_key="k")
    with sessions() as session:
        session.add(db.Org(id="org-1", name="org-1"))
        session.add(db.Project(id="prj-1", org_id="org-1", name="prj-1"))
        session.add(db.User(id="usr-p", email="producer@example.test", display="P"))
        session.add(db.Membership(user_id="usr-p", org_id="org-1", role="producer"))
        session.flush()
        producer, _ = auth.issue_token(session, user_id="usr-p", project_id="prj-1", salt=SALT)
        session.commit()
    return TestClient(app), sessions, producer


def _upload_packet(client, token, bundle):
    response = client.post("/api/v1/packets", headers={"x-api-token": token},
                           files={"file": ("packet.tar", bundle.read_bytes(), "application/x-tar")})
    assert response.status_code == 201, response.text
    return response.json()


def _upload_records(client, token, rows, name="new_records.jsonl"):
    body = "".join(json.dumps(row) + "\n" for row in rows).encode("utf-8")
    return client.post("/api/v1/records", headers={"x-api-token": token},
                       files={"file": (name, body, "application/x-ndjson")})


def test_a_colliding_case_id_is_refused_naming_the_pool_and_the_consequence(tmp_path, built):
    client, sessions, producer = _world(tmp_path)
    _upload_packet(client, producer, built[0])

    response = _upload_records(client, producer, [
        {"backend": "fixture", "case_id": "fixture-case-1", "id": "row-1"}])

    assert response.status_code == 409, response.text
    body = response.json()
    assert body["accepted"] is False
    assert body["collisions"][0]["case_id"] == "fixture-case-1"
    assert body["collisions"][0]["pool"] == "data/records_feishu.jsonl"
    assert SPLIT_CONSEQUENCE in body["consequence"]
    assert "published bounds" in body["consequence"]


def test_the_refusal_changes_no_certificate_summary_and_is_written_down(tmp_path, built):
    client, sessions, producer = _world(tmp_path)
    _upload_packet(client, producer, built[0])
    with sessions() as session:
        before = [(row.id, row.autorate, row.bound, row.n_cal)
                  for row in session.scalars(select(db.CertificateSummary))]

    _upload_records(client, producer, [{"case_id": "fixture-case-1"}])

    with sessions() as session:
        after = [(row.id, row.autorate, row.bound, row.n_cal)
                 for row in session.scalars(select(db.CertificateSummary))]
        denials = [row for row in session.scalars(select(db.AuditRow))
                   if row.action == "records.ingest" and row.outcome == "denied"]
    assert after == before
    assert denials, "a refusal is an event, and the audit log is where it is kept"


def test_a_new_case_id_is_accepted_and_stored(tmp_path, built):
    client, sessions, producer = _world(tmp_path)
    _upload_packet(client, producer, built[0])

    response = _upload_records(client, producer, [
        {"backend": "fixture", "case_id": "brand-new-case", "id": "row-9"}])

    assert response.status_code == 201, response.text
    body = response.json()
    assert body["accepted"] is True and body["rows"] == 1
    assert body["sha256"] and body["stored_as"].endswith(".jsonl")


def test_a_file_without_case_ids_is_refused_as_a_records_file_at_all(tmp_path, built):
    client, _, producer = _world(tmp_path)
    _upload_packet(client, producer, built[0])

    response = _upload_records(client, producer, [{"id": "row-1", "gold": "x"}])

    assert response.status_code == 422
    assert "case_id" in response.json()["detail"]


def test_without_a_packet_there_is_no_pool_and_the_file_is_not_silently_accepted(tmp_path):
    client, _, producer = _world(tmp_path)

    response = _upload_records(client, producer, [{"case_id": "x"}])

    assert response.status_code == 409
    assert "calibration pool" in response.json()["detail"]
