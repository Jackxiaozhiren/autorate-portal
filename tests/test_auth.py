"""T4 - Section 4.5's matrix, the token's hash, and the session's signature."""
from __future__ import annotations

from datetime import datetime, timedelta, timezone

import pytest
from sqlalchemy import select

from autorate_portal import auth, db

SALT = "test-salt"
SECRET = "test-secret-key"
NOW = datetime(2026, 11, 10, 12, 0, tzinfo=timezone.utc)


def _session():
    engine = db.make_engine("sqlite://")
    db.create_all(engine)
    return db.make_session(engine)()


def _world(session, *, role="viewer", email="person@example.test"):
    session.add(db.Org(id="org-1", name="org-1"))
    session.add(db.Project(id="prj-1", org_id="org-1", name="prj-1"))
    session.add(db.Project(id="prj-2", org_id="org-1", name="prj-2"))
    session.add(db.User(id="usr-1", email=email, display="Person"))
    session.add(db.Membership(user_id="usr-1", org_id="org-1", role=role))
    session.flush()


# --- the matrix, as a table rather than a claim -----------------------------

EXPECTED = {
    "viewer": {"read_certificates", "download_protocol"},
    "producer": {"read_certificates", "download_protocol", "download_raw", "ingest_packet",
                 "start_replay", "edit_policy"},
    "compliance": {"read_certificates", "download_protocol", "download_raw", "start_replay",
                   "export_audit"},
    "admin": set(auth.CAPABILITIES),
    "auditor": {"read_certificates", "download_protocol", "download_raw", "start_replay",
                "export_audit"},
}


def test_every_row_of_the_permission_matrix_is_what_the_table_says():
    assert set(auth.MATRIX) == set(EXPECTED)
    for role, capabilities in EXPECTED.items():
        assert auth.MATRIX[role] == frozenset(capabilities), role


def test_a_viewer_cannot_ingest_and_a_producer_can():
    assert auth.allowed("viewer", auth.INGEST_PACKET) is False
    assert auth.allowed("producer", auth.INGEST_PACKET) is True


def test_compliance_exports_but_does_not_ingest_or_edit_policy():
    assert auth.allowed("compliance", auth.EXPORT_AUDIT) is True
    assert auth.allowed("compliance", auth.INGEST_PACKET) is False
    assert auth.allowed("compliance", auth.EDIT_POLICY) is False


def test_an_auditor_reads_and_replays_but_does_not_write():
    assert auth.allowed("auditor", auth.DOWNLOAD_RAW) is True
    assert auth.allowed("auditor", auth.INGEST_PACKET) is False
    assert auth.allowed("auditor", auth.MANAGE_MEMBERS) is False


def test_only_admin_manages_members_and_an_unknown_role_fails_closed():
    assert auth.allowed("admin", auth.MANAGE_MEMBERS) is True
    assert all(auth.allowed("intern", capability) is False for capability in auth.CAPABILITIES)
    with pytest.raises(KeyError):
        auth.allowed("admin", "publish_everything")


# --- tokens ----------------------------------------------------------------

def test_a_token_is_stored_as_a_hash_and_the_plaintext_is_never_written():
    session = _session()
    _world(session)

    plaintext, row = auth.issue_token(session, user_id="usr-1", project_id="prj-1",
                                      salt=SALT, scopes=(auth.START_REPLAY,), now=NOW)

    assert row.hash == auth.token_hash(plaintext, SALT)
    assert plaintext not in row.hash
    stored = session.scalar(select(db.ApiToken))
    assert plaintext not in (stored.hash + stored.scopes)


def test_an_issued_token_identifies_the_project_and_its_role():
    session = _session()
    _world(session, role="producer")
    plaintext, _ = auth.issue_token(session, user_id="usr-1", project_id="prj-1", salt=SALT,
                                    now=NOW)

    principal = auth.principal_from_token(session, plaintext, salt=SALT, now=NOW)

    assert principal.role == "producer" and principal.project_id == "prj-1"
    assert principal.org_id == "org-1" and principal.via == "token"
    assert session.scalar(select(db.ApiToken)).last_used_at == auth._utc(NOW)


def test_an_absent_or_unknown_token_is_not_an_identity():
    session = _session()
    _world(session)
    with pytest.raises(auth.AuthError):
        auth.principal_from_token(session, "", salt=SALT, now=NOW)
    with pytest.raises(auth.AuthError):
        auth.principal_from_token(session, "not-a-token", salt=SALT, now=NOW)


def test_a_token_is_scoped_to_one_project_even_inside_one_org():
    session = _session()
    _world(session, role="admin")
    plaintext, _ = auth.issue_token(session, user_id="usr-1", project_id="prj-1", salt=SALT,
                                    now=NOW)
    principal = auth.principal_from_token(session, plaintext, salt=SALT, now=NOW)

    auth.require_project(principal, "prj-1")
    with pytest.raises(auth.Forbidden):
        auth.require_project(principal, "prj-2")


def test_revoking_the_membership_revokes_the_token_it_backed():
    session = _session()
    _world(session, role="producer")
    plaintext, _ = auth.issue_token(session, user_id="usr-1", project_id="prj-1", salt=SALT,
                                    now=NOW)
    session.delete(session.get(db.Membership, ("usr-1", "org-1")))
    session.flush()

    with pytest.raises(auth.Forbidden):
        auth.principal_from_token(session, plaintext, salt=SALT, now=NOW)


# --- sessions --------------------------------------------------------------

def test_a_session_value_round_trips_and_a_tampered_one_does_not():
    value = auth.sign_session(SECRET, "person@example.test", now=NOW)
    assert auth.read_session(SECRET, value, now=NOW) == "person@example.test"
    assert auth.read_session(SECRET, value[:-2] + "aa", now=NOW) is None
    assert auth.read_session("another-key", value, now=NOW) is None
    assert auth.read_session(SECRET, "garbage", now=NOW) is None


def test_an_expired_session_is_not_an_identity():
    value = auth.sign_session(SECRET, "person@example.test", ttl_seconds=60, now=NOW)
    assert auth.read_session(SECRET, value, now=NOW + timedelta(minutes=2)) is None


def test_the_role_comes_from_membership_not_from_the_claims():
    session = _session()
    _world(session, role="viewer")

    principal = auth.principal_for_project(session, email="person@example.test",
                                           project_id="prj-1", claims={"role": "admin"})

    assert principal.role == "viewer"
    with pytest.raises(auth.Forbidden):
        auth.require(principal, auth.INGEST_PACKET)


# --- audit -----------------------------------------------------------------

def test_a_mutation_leaves_an_audit_row_with_actor_project_target_and_time():
    session = _session()
    _world(session)
    auth.record_audit(session, actor="person@example.test", project_id="prj-1",
                      action="packet.ingest", target="packet:pkt-1", now=NOW)
    auth.record_audit(session, actor="person@example.test", project_id="prj-1",
                      action="artifact.download", target="artifact:art-1", outcome="denied",
                      now=NOW)
    session.flush()

    rows = list(session.scalars(select(db.AuditRow).order_by(db.AuditRow.action)))
    assert [(row.actor, row.project_id, row.target) for row in rows] == [
        ("person@example.test", "prj-1", "artifact:art-1"),
        ("person@example.test", "prj-1", "packet:pkt-1")]
    assert rows[0].outcome == "denied" and rows[1].outcome == "allowed"
    assert rows[0].at.startswith("2026-11-10T12:00:00")
