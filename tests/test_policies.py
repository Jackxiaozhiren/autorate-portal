"""T6 — AC11's read-only SDK surface (F7 creation stays with M5)."""
from __future__ import annotations

import pytest

from autorate_portal import db, policies

DIGEST_A = "aaaaaaaaaaaa"
DIGEST_B = "bbbbbbbbbbbb"


def _sessions(superseded: bool, *, with_packet: bool = True):
    engine = db.make_engine("sqlite:///:memory:")
    db.create_all(engine)
    sessions = db.make_session(engine)
    with sessions() as session:
        session.add(db.Org(id="org-1", name="org-1"))
        session.add(db.Project(id="prj-1", org_id="org-1", name="prj-1"))
        session.flush()
        if with_packet:
            session.add(db.Packet(
                id="pkt-0", project_id="prj-1", manifest_sha256="f" * 64,
                protocol_digest=DIGEST_A, source_version="0.1.2", source_sha256="a" * 64,
                source_revision="rev", created_by="tester",
                ingested_at="2026-11-12T00:00:00", bytes=100))
        if superseded:
            session.add(db.Packet(
                id="pkt-1", project_id="prj-1", manifest_sha256="e" * 64,
                protocol_digest=DIGEST_B, source_version="0.1.2", source_sha256="c" * 64,
                source_revision="rev2", created_by="tester",
                ingested_at="2026-11-12T01:00:00", bytes=100))
        session.add(db.Policy(id="pol-1", project_id="prj-1", name="auto-execute",
                              packet_id="pkt-0", slices="[]", budget="0.05",
                              state="active"))
        session.commit()
    return sessions


def test_ac11_a_superseded_packet_is_stale_in_the_sdk_payload():
    sessions = _sessions(True)
    with sessions() as session:
        payload = policies.sdk_payload(session, "pol-1")

    assert payload.state == policies.STALE
    assert payload.body["state"] == "stale"
    assert DIGEST_B in payload.reason
    assert payload.body["packet_id"] == "pkt-0"
    assert payload.body["protocol_digest"] == DIGEST_A


def test_ac11_strict_fetch_of_a_stale_policy_is_a_conflict():
    sessions = _sessions(True)
    with sessions() as session:
        strict = policies.sdk_payload(session, "pol-1", strict=True)
        plain = policies.sdk_payload(session, "pol-1", strict=False)
    assert strict.strict_conflict is True
    assert plain.strict_conflict is False
    assert plain.state == policies.STALE


def test_an_active_policy_stays_active_even_with_strict():
    sessions = _sessions(False)
    with sessions() as session:
        payload = policies.sdk_payload(session, "pol-1", strict=True)
    assert payload.state == policies.ACTIVE
    assert payload.strict_conflict is False
    assert "action/label arrive with F7" in payload.body["sdk_shape"]


def test_an_unknown_policy_or_a_missing_packet_is_a_named_refusal():
    sessions = _sessions(False)
    with sessions() as session:
        with pytest.raises(policies.PolicyNotFound):
            policies.sdk_payload(session, "no-such-policy")
    missing = _sessions(False, with_packet=False)
    with missing() as session:
        with pytest.raises(policies.PolicyNotFound, match="not in this store"):
            policies.sdk_payload(session, "pol-1")


def test_staleness_is_read_from_packets_not_from_a_stored_summary():
    sessions = _sessions(False)
    with sessions() as session:
        payload = policies.sdk_payload(session, "pol-1")
    assert payload.body["stale_because"] == ""
    assert payload.body["state"] == "active"
