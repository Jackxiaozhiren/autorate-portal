"""F7 — the policy is a versioned object whose budget and slices come from the
artefact, whose SDK payload carries the CLI's action/label decisions, and whose
staleness a monitor drift can cause. AC11's read-only payload stays green.

The plants for this module: drop the budget-membership comparison and a policy
may name a budget nobody published; drop the slice-membership comparison and a
router may be told to act on a group the artefact never measured; make edit
overwrite and a version is lost; remove the drift branch and a stale router
keeps acting on a certificate that no longer re-derives.
"""
from __future__ import annotations

import json

import pytest

from autorate_portal import db, monitor, policies

DIGEST_A = "a" * 12
DIGEST_B = "b" * 12
# The certificate publishes alpha 0.05; the slices artefact publishes values
# de/en/km/sw. A budget of 0.20 or a slice of "zz" is published by nobody.
CERT_DOC = {"alpha": 0.05, "delta": 0.05, "backend": "laya", "feasible": True}
SLICES_DOC = {"group_key": "language", "run": {"per_group": {
    "de": {"feasible": True}, "en": {"feasible": True},
    "km": {"feasible": False}, "sw": {"feasible": True}}}}
FILES = {
    "cert_laya.json": json.dumps(CERT_DOC).encode(),
    "slices_language.json": json.dumps(SLICES_DOC).encode(),
}


def _base(superseded: bool = False):
    engine = db.make_engine("sqlite:///:memory:")
    db.create_all(engine)
    sessions = db.make_session(engine)
    with sessions() as s:
        s.add(db.Org(id="org-1", name="org-1"))
        s.add(db.Project(id="prj-1", org_id="org-1", name="prj-1"))
        s.add(db.Packet(id="pkt-0", project_id="prj-1", manifest_sha256="f" * 64,
                        protocol_digest=DIGEST_A, source_version="0.1.2",
                        source_sha256="a" * 64, source_revision="r", created_by="t",
                        ingested_at="2026-11-16T00:00:00", bytes=100))
        if superseded:
            s.add(db.Packet(id="pkt-1", project_id="prj-1", manifest_sha256="e" * 64,
                            protocol_digest=DIGEST_B, source_version="0.1.2",
                            source_sha256="c" * 64, source_revision="r2", created_by="t",
                            ingested_at="2026-11-16T01:00:00", bytes=100))
        s.commit()
    return sessions


def _create(s, *, name="auto-rule", packet_id="pkt-0", budget="0.05",
            slices=("de", "en"), files=FILES):
    return policies.create_policy(s, project_id="prj-1", name=name,
                                  packet_id=packet_id, budget=budget, slices=slices,
                                  files=files, actor="p1@example.test")


def test_create_names_a_published_budget_and_returns_an_action_per_slice():
    sessions = _base()
    with sessions() as s:
        policy = _create(s)
        assert policy.version == 1
        assert policy.supersedes is None
        payload = policies.sdk_payload(s, policy.id)
    decisions = {d["slice"]: d["action"] for d in payload.body["decisions"]}
    # The CLI's decision vocabulary: a feasible group may auto, an infeasible
    # one escalates. Nothing is computed here — the artefact said so.
    assert decisions["de"] == "auto"
    assert decisions["en"] == "auto"
    assert payload.body["budget"] == "0.05"


def test_a_budget_nobody_published_is_refused_and_names_the_value():
    sessions = _base()
    with sessions() as s:
        with pytest.raises(policies.BudgetNotPublished) as exc:
            _create(s, budget="0.20")
    assert "0.20" in str(exc.value)
    assert "0.05" in str(exc.value), "the published value is named for correction"


def test_a_slice_absent_from_the_artefact_is_refused_and_names_the_value():
    sessions = _base()
    with sessions() as s:
        with pytest.raises(policies.SliceNotInArtefact) as exc:
            _create(s, slices=("de", "zz"))
    assert "zz" in str(exc.value)


def test_editing_creates_a_version_and_overwrites_nothing():
    sessions = _base()
    with sessions() as s:
        first = _create(s)
        second = policies.edit_policy(s, policy_id=first.id, budget="0.05",
                                      slices=("km",), files=FILES, actor="p1@example.test")
        assert second.version == 2
        assert second.supersedes == first.id
        assert first.version == 1, "the old row is not mutated"
        assert first.state == policies.SUPERSEDED
        assert [d["slice"] for d in json.loads(first.slices)] == ["de", "en"], \
            "the old slices survived"
        assert [d["slice"] for d in json.loads(second.slices)] == ["km"]


def test_a_monitor_drift_makes_the_policy_stale_and_strict_is_a_conflict():
    sessions = _base()
    with sessions() as s:
        policy = _create(s)
        s.add(db.Run(id="run-1", project_id="prj-1", argv="[]", exit_code=4,
                     started_at="2026-11-16T02:00:00Z", digest_then="d" * 64,
                     stdout_sha256="s" * 64, packet_id_in="pkt-0"))
        s.flush()
        s.add(db.MonitorResult(id="mr-1", project_id="prj-1", run_id="run-1",
                               verdict=monitor.DRIFT))
        s.commit()
    with sessions() as s:
        payload = policies.sdk_payload(s, policy.id)
        strict = policies.sdk_payload(s, policy.id, strict=True)
    assert payload.state == policies.STALE
    assert "drift" in payload.reason
    assert strict.strict_conflict is True


def test_ac11_a_superseded_packet_still_reports_stale_with_the_digest():
    sessions = _base(superseded=True)
    with sessions() as s:
        policy = _create(s)
        payload = policies.sdk_payload(s, policy.id)
        assert payload.state == policies.STALE
        assert DIGEST_B in payload.reason
        assert policies.sdk_payload(s, policy.id, strict=True).strict_conflict
