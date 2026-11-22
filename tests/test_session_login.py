"""V2 login: a project token can be exchanged for a session, once.

The portal could read a session cookie before this change but had no endpoint
that issued one - the path was unreachable. These tests cover the three
properties that make the new endpoint safe: the cookie names its project, a
cookie-authenticated write needs the double-submit value, and a token request
does not (a typed token is not ambient authority).
"""
from __future__ import annotations

from fastapi.testclient import TestClient

from autorate_portal import auth, db
from autorate_portal.app import create_app

SALT = "test-salt"
SECRET = "test-secret-key"


def _world(tmp_path):
    engine = db.make_engine("sqlite:///" + str(tmp_path / "portal.db"))
    db.create_all(engine)
    sessions = db.make_session(engine)
    app = create_app(engine=engine, store_dir=tmp_path / "store", salt=SALT,
                     secret_key=SECRET)
    with sessions() as session:
        session.add(db.Org(id="org-1", name="org-1"))
        session.add(db.Project(id="prj-1", org_id="org-1", name="prj-1"))
        session.add(db.Project(id="prj-2", org_id="org-1", name="prj-2"))
        session.add(db.User(id="usr-p", email="producer@example.test", display="P"))
        session.add(db.Membership(user_id="usr-p", org_id="org-1", role="producer"))
        session.flush()
        producer, _ = auth.issue_token(session, user_id="usr-p", project_id="prj-1", salt=SALT)
        session.commit()
    return TestClient(app), producer


def _login(client, token):
    return client.post("/api/v1/session", json={"token": token})


def test_login_exchanges_a_token_for_a_session_and_a_csrf_value(tmp_path):
    client, token = _world(tmp_path)
    response = _login(client, token)

    assert response.status_code == 200
    body = response.json()
    assert body["role"] == "producer" and body["project_id"] == "prj-1"
    assert body["csrf"] and client.cookies.get("csrf") == body["csrf"]
    session_cookie = [value for value in response.headers.get_list("set-cookie")
                      if value.startswith("session=")]
    assert session_cookie and "HttpOnly" in session_cookie[0]
    csrf_cookie = [value for value in response.headers.get_list("set-cookie")
                   if value.startswith("csrf=")]
    assert csrf_cookie and "HttpOnly" not in csrf_cookie[0]


def test_the_session_cookie_alone_names_its_project(tmp_path):
    client, token = _world(tmp_path)
    _login(client, token)

    response = client.get("/api/v1/certificates")

    assert response.status_code == 200, response.text


def test_a_cookie_write_without_the_csrf_header_is_refused(tmp_path):
    client, token = _world(tmp_path)
    _login(client, token)

    response = client.post("/api/v1/policies", json={})

    assert response.status_code == 403
    assert "csrf" in response.json()["detail"]


def test_the_csrf_header_lets_a_cookie_write_through(tmp_path):
    client, token = _world(tmp_path)
    csrf = _login(client, token).json()["csrf"]

    response = client.post("/api/v1/policies", json={},
                           headers={"x-csrf-token": csrf})

    assert response.status_code != 403


def test_a_token_request_needs_no_csrf(tmp_path):
    client, token = _world(tmp_path)

    response = client.post("/api/v1/policies", json={},
                           headers={"x-api-token": token})

    assert response.status_code != 403


def test_a_rejected_token_issues_no_session(tmp_path):
    client, _ = _world(tmp_path)

    response = _login(client, "not-a-token")

    assert response.status_code == 401
    assert client.cookies.get("session") is None


def test_a_session_is_scoped_to_the_project_it_was_issued_for(tmp_path):
    client, token = _world(tmp_path)
    _login(client, token)

    response = client.get("/api/v1/certificates", params={"project": "prj-2"})

    assert response.status_code == 403


def test_logout_clears_the_session_and_the_next_read_is_unauthenticated(tmp_path):
    client, token = _world(tmp_path)
    csrf = _login(client, token).json()["csrf"]

    assert client.delete("/api/v1/session", headers={"x-csrf-token": csrf}).status_code == 200
    assert client.get("/api/v1/certificates").status_code == 401
