"""V2 session resume: a reload must not forget a session that is still valid.

The plan promised "sign in once, for eight hours". The page could not keep that promise with
the server it had: the cookie survived a reload, but there was no route that said whose it
was, and the csrf value lived only in the script's memory. Measured before this change:
`/api/v1/certificates` answered 200 with the cookie while a cookie write answered 403, and the
reader was asked for a token the cookie already carried.

These tests hold both halves of the fix: the route answers with the identity and the
double-submit value, and the page asks before it offers the token field.
"""
from __future__ import annotations

import json
from datetime import datetime, timedelta, timezone
from pathlib import Path

from fastapi.testclient import TestClient

from autorate_portal import auth, db
from autorate_portal.app import create_app

SALT = "test-salt"
SECRET = "test-secret-key"
ROOT = Path(__file__).resolve().parents[1]
PAGE = ROOT / "src" / "autorate_portal" / "web" / "index.html"

CLAIM = {"share": "0.66", "field": "confidence", "unit": "case", "population": "resolutions"}


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
    return app, TestClient(app), sessions, producer


def _reload(app, browser):
    """A new page with the same cookie jar: the script's memory is gone, the cookies are not."""
    return TestClient(app, cookies=dict(browser.cookies))


def test_a_reloaded_page_can_ask_who_the_cookie_is(tmp_path):
    app, browser, _, token = _world(tmp_path)
    logged_in = browser.post("/api/v1/session", json={"token": token}).json()

    reloaded = _reload(app, browser)
    response = reloaded.get("/api/v1/session")

    assert response.status_code == 200
    assert response.json() == {"actor": logged_in["actor"], "role": logged_in["role"],
                               "project_id": logged_in["project_id"],
                               "csrf": logged_in["csrf"]}


def test_the_resumed_csrf_is_the_one_a_write_needs(tmp_path):
    app, browser, _, token = _world(tmp_path)
    browser.post("/api/v1/session", json={"token": token})
    reloaded = _reload(app, browser)

    without = reloaded.post("/api/v1/claims/check", json=CLAIM)
    assert without.status_code == 403

    csrf = reloaded.get("/api/v1/session").json()["csrf"]
    with_csrf = reloaded.post("/api/v1/claims/check", json=CLAIM,
                              headers={"x-csrf-token": csrf})
    assert with_csrf.status_code == 200, with_csrf.text
    assert with_csrf.json()["verdict"] in ("bounded_supports", "bounded_refutes",
                                           "cannot_be_bounded")


def test_without_a_cookie_there_is_no_identity_and_no_new_cookie(tmp_path):
    _, client, _, _ = _world(tmp_path)
    response = client.get("/api/v1/session")

    assert response.status_code == 401
    assert response.json()["detail"] == "no session"
    assert "set-cookie" not in response.headers


def test_an_expired_cookie_is_not_an_identity(tmp_path):
    app, browser, _, token = _world(tmp_path)
    browser.post("/api/v1/session", json={"token": token})

    stale = auth.sign_session(SECRET, "producer@example.test", project_id="prj-1",
                              ttl_seconds=1,
                              now=datetime.now(timezone.utc) - timedelta(hours=9))
    expired = TestClient(app, cookies={"session": stale})
    response = expired.get("/api/v1/session")

    assert response.status_code == 401
    assert response.json()["detail"] == "no session"


def test_a_member_whose_access_is_gone_is_refused_not_a_server_error(tmp_path):
    app, browser, sessions, token = _world(tmp_path)
    browser.post("/api/v1/session", json={"token": token})
    with sessions() as session:
        session.query(db.Membership).filter(db.Membership.user_id == "usr-p").delete()
        session.commit()

    reloaded = _reload(app, browser)
    resume = reloaded.get("/api/v1/session")
    read = reloaded.get("/api/v1/certificates")

    # `principal_for_project` raises Forbidden, which is not an AuthError; catching only the
    # latter turned a revoked membership into a 500 on every route the cookie touched.
    assert resume.status_code == 403, resume.text
    assert read.status_code == 403, read.text


def test_a_lost_csrf_cookie_is_reissued_and_usable(tmp_path):
    app, browser, _, token = _world(tmp_path)
    browser.post("/api/v1/session", json={"token": token})
    reloaded = _reload(app, browser)
    reloaded.cookies.delete("csrf")

    response = reloaded.get("/api/v1/session")
    assert response.status_code == 200
    assert any(value.startswith("csrf=") for value in response.headers.get_list("set-cookie"))

    csrf = response.json()["csrf"]
    assert csrf and reloaded.cookies.get("csrf") == csrf
    write = reloaded.post("/api/v1/claims/check", json=CLAIM, headers={"x-csrf-token": csrf})
    assert write.status_code == 200, write.text


def test_the_identity_answer_is_not_cacheable(tmp_path):
    app, browser, _, token = _world(tmp_path)
    browser.post("/api/v1/session", json={"token": token})

    response = _reload(app, browser).get("/api/v1/session")
    assert response.headers["cache-control"] == "no-store"


def test_the_page_resumes_before_it_offers_the_token_field():
    text = PAGE.read_text(encoding="utf-8")

    assert 'id="signedin"' in text and 'id="token-label"' in text
    assert "async function resume" in text
    assert 'call("/api/v1/session")' in text
    # Defined but never called is the failure this guards: the bootstrap chain must run it.
    assert ".then(resume)" in text
    # A hidden flex label loses to `label { display: flex }` without this rule.
    assert "[hidden] { display: none !important; }" in text
    # The line carries two values, so it cannot use data-i18n; a language switch has to
    # rebuild it from the catalog or it stays in the language it was first rendered in.
    assert "showWho(state.who)" in text
    # "no certificates yet" is a state, not a failure, and must not sit in the alert slot.
    assert 'id="note"' in text
    assert 'note(msg("label.no_certificates"' in text


def test_the_identity_line_exists_in_both_languages_with_both_placeholders():
    catalog = json.loads((ROOT / "src" / "autorate_portal" / "catalog.json")
                         .read_text(encoding="utf-8"))
    for language in ("en", "zh-Hans"):
        line = catalog[language]["text.signed_in_as"]
        assert "{actor}" in line and "{project}" in line
