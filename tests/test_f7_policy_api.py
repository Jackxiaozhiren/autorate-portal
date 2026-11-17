"""F7 over HTTP: create, versioned edit, well-known decisions, and the refusals."""
from __future__ import annotations

from pathlib import Path

from fastapi.testclient import TestClient

from autorate_portal import auth, db
from autorate_portal.app import create_app

WHEEL = b"f7-wheel"


def _app(tmp_path, bundle):
    engine = db.make_engine("sqlite:///" + str(tmp_path / "p.db"))
    db.create_all(engine)
    sessions = db.make_session(engine)
    app = create_app(engine=engine, store_dir=tmp_path / "store", salt="s", secret_key="k")
    client = TestClient(app)
    with sessions() as s:
        s.add(db.Org(id="org-1", name="org-1"))
        s.add(db.Project(id="prj-1", org_id="org-1", name="prj-1"))
        s.add(db.User(id="usr-p", email="p@example.test", display="P"))
        s.add(db.User(id="usr-v", email="v@example.test", display="V"))
        s.add(db.Membership(user_id="usr-p", org_id="org-1", role="producer"))
        s.add(db.Membership(user_id="usr-v", org_id="org-1", role="viewer"))
        s.flush()
        producer, _ = auth.issue_token(s, user_id="usr-p", project_id="prj-1", salt="s")
        viewer, _ = auth.issue_token(s, user_id="usr-v", project_id="prj-1", salt="s")
        s.commit()
    upload = client.post("/api/v1/packets", headers={"x-api-token": producer},
                         files={"file": ("f.tar", bundle.read_bytes(), "application/x-tar")})
    assert upload.status_code == 201, upload.text
    return client, producer, viewer, upload.json()["id"]


def test_create_edit_and_well_known_over_http(tmp_path, m4_built):
    client, token, _viewer, packet_id = _app(tmp_path, Path(m4_built[0]))
    created = client.post("/api/v1/policies", headers={"x-api-token": token},
                          json={"name": "rule", "packet_id": packet_id,
                                "budget": "0.05", "slices": []})
    assert created.status_code == 201, created.text
    policy_id = created.json()["id"]
    assert created.json()["version"] == 1

    edited = client.post("/api/v1/policies/%s/edit" % policy_id,
                         headers={"x-api-token": token}, json={})
    assert edited.status_code == 200, edited.text
    assert edited.json()["version"] == 2
    assert edited.json()["supersedes"] == policy_id

    well = client.get("/api/v1/policies/%s.well-known" % policy_id)
    assert well.status_code == 200, well.text
    assert well.json()["version"] == 1
    assert "decisions" in well.json()


def test_viewer_cannot_create_a_policy(tmp_path, m4_built):
    client, _token, viewer, packet_id = _app(tmp_path, Path(m4_built[0]))
    response = client.post("/api/v1/policies", headers={"x-api-token": viewer},
                           json={"name": "rule", "packet_id": packet_id,
                                 "budget": "0.05", "slices": []})
    assert response.status_code == 403
