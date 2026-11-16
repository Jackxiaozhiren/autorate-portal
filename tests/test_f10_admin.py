"""F10 — every admin write sits behind MANAGE_MEMBERS, writes an audit row,
and deletion is a tombstone plus byte removal. The operator owns the registry;
with no registry configured a pin is refused, not written into the package.
"""
from __future__ import annotations

import json
from pathlib import Path

import pytest
from fastapi.testclient import TestClient
from sqlalchemy import select

from autorate_portal import auth, db
from autorate_portal.app import create_app

SHA_A = "1" * 64
SHA_B = "2" * 64


def _app(tmp_path, *, registry=None):
    Path(tmp_path).mkdir(parents=True, exist_ok=True)
    engine = db.make_engine("sqlite:///" + str(tmp_path / "a.db"))
    db.create_all(engine)
    sessions = db.make_session(engine)
    app = create_app(engine=engine, store_dir=tmp_path / "store", salt="s", secret_key="k",
                     admin_registry=registry)
    client = TestClient(app)
    with sessions() as s:
        s.add(db.Org(id="org-1", name="org-1"))
        s.add(db.Project(id="prj-1", org_id="org-1", name="prj-1"))
        for uid, role in (("usr-admin", "admin"), ("usr-view", "viewer"),
                          ("usr-comp", "compliance")):
            s.add(db.User(id=uid, email=uid + "@example.test", display=uid))
            s.add(db.Membership(user_id=uid, org_id="org-1", role=role))
        s.flush()
        tokens = {uid: auth.issue_token(s, user_id=uid, project_id="prj-1", salt="s")[0]
                  for uid in ("usr-admin", "usr-view", "usr-comp")}
        s.add(db.Packet(id="pkt-1", project_id="prj-1", manifest_sha256="f" * 64,
                        protocol_digest="a" * 12, source_version="0.1.2", source_sha256="a" * 64,
                        source_revision="r", created_by="t", ingested_at="2026-11-16T00:00:00",
                        bytes=100))
        s.commit()
    return client, tokens, sessions


def _h(token):
    return {"x-api-token": token}


ADMIN_WRITES = (
    ("/api/v1/admin/members", {"org_id": "org-1", "user_id": "usr-view", "role": "producer"}),
    ("/api/v1/admin/tokens/tok-1/revoke", {}),
    ("/api/v1/admin/packets/pkt-1/retention", {"retention_until": "2027-01-01T00:00:00Z"}),
    ("/api/v1/admin/packets/pkt-1/delete", {}),
    ("/api/v1/admin/pins", {"version": "0.2.0", "wheel": "autorate-0.2.0-py3-none-any.whl",
                            "sha256": SHA_A, "source": "https://pypi.org/pypi/autorate/0.2.0/json"}),
)


@pytest.mark.parametrize("path,body", ADMIN_WRITES)
def test_viewer_cannot_perform_any_admin_write_and_each_denial_is_audited(tmp_path, path, body):
    client, tokens, sessions = _app(tmp_path)
    response = client.post(path, headers=_h(tokens["usr-view"]), json=body)
    assert response.status_code == 403, (path, response.text)
    with sessions() as s:
        audited = s.scalars(select(db.AuditRow).where(
            db.AuditRow.outcome == "denied")).all()
    assert audited, "every denied write leaves an audit row"


def test_admin_can_set_members_roles_and_list_tokens_with_scopes(tmp_path):
    client, tokens, sessions = _app(tmp_path)
    response = client.post("/api/v1/admin/members", headers=_h(tokens["usr-admin"]),
                           json={"org_id": "org-1", "user_id": "usr-view", "role": "producer"})
    assert response.status_code == 200, response.text
    with sessions() as s:
        m = s.get(db.Membership, ("usr-view", "org-1"))
        assert m.role == "producer"
        assert auth.allowed("producer", auth.INGEST_PACKET)

    listed = client.get("/api/v1/admin/tokens", headers=_h(tokens["usr-admin"]))
    assert listed.status_code == 200
    # Only the hash is stored; no listing may reveal it.
    assert "hash" not in json.dumps(listed.json())
    assert all(row["scopes"] == [] for row in listed.json()["tokens"])


def test_deletion_tombstones_the_row_and_removes_the_bytes(tmp_path, m4_built):
    client, tokens, sessions = _app(tmp_path)
    store = tmp_path / "store"
    store.mkdir(parents=True, exist_ok=True)
    stored = store / ("f" * 64 + ".tar")
    stored.write_bytes(Path(m4_built[0]).read_bytes())
    response = client.post("/api/v1/admin/packets/pkt-1/delete",
                           headers=_h(tokens["usr-admin"]))
    assert response.status_code == 200, response.text
    assert not stored.exists(), "the bytes are gone"
    with sessions() as s:
        packet = s.get(db.Packet, "pkt-1")
        assert packet is not None and packet.tombstoned == 1, "the row stays as a tombstone"
    again = client.post("/api/v1/admin/packets/pkt-1/delete",
                        headers=_h(tokens["usr-admin"]))
    assert again.status_code == 200
    assert again.json()["detail"] == "already tombstoned"


def test_retention_and_audit_export(tmp_path):
    client, tokens, sessions = _app(tmp_path)
    set_r = client.post("/api/v1/admin/packets/pkt-1/retention",
                        headers=_h(tokens["usr-admin"]),
                        json={"retention_until": "2027-01-01T00:00:00Z"})
    assert set_r.status_code == 200, set_r.text
    with sessions() as s:
        assert s.get(db.Packet, "pkt-1").retention_until == "2027-01-01T00:00:00Z"
    exported = client.get("/api/v1/admin/audit", headers=_h(tokens["usr-comp"]))
    assert exported.status_code == 200
    actions = [r["action"] for r in exported.json()]
    assert "admin.retention.set" in actions
    viewer = client.get("/api/v1/admin/audit", headers=_h(tokens["usr-view"]))
    assert viewer.status_code == 403


def test_pin_upgrade_and_the_no_registry_refusal(tmp_path):
    registry = tmp_path / "pins.json"
    registry.write_text(json.dumps({"schema": "autorate-portal/pins@1", "pins": [
        {"name": "autorate", "version": "0.1.2",
         "wheel": "autorate-0.1.2-py3-none-any.whl", "sha256": SHA_B,
         "source": "https://pypi.org/pypi/autorate/0.1.2/json"}]}))
    client, tokens, _ = _app(tmp_path, registry=registry)
    body = {"version": "0.2.0", "wheel": "autorate-0.2.0-py3-none-any.whl",
            "sha256": SHA_A, "source": "https://pypi.org/pypi/autorate/0.2.0/json"}
    added = client.post("/api/v1/admin/pins", headers=_h(tokens["usr-admin"]), json=body)
    assert added.status_code == 200, added.text
    # A second pin at the same version is refused without upgrade.
    again = client.post("/api/v1/admin/pins", headers=_h(tokens["usr-admin"]), json=body)
    assert again.status_code == 422
    assert "upgrade" in again.json()["detail"]
    upgraded = client.post("/api/v1/admin/pins", headers=_h(tokens["usr-admin"]),
                           json={**body, "upgrade": True})
    assert upgraded.status_code == 200, upgraded.text

    no_reg, no_tokens, _ = _app(tmp_path / "noreg")
    refused = no_reg.post("/api/v1/admin/pins", headers=_h(no_tokens["usr-admin"]), json=body)
    assert refused.status_code == 422
    assert "no registry path" in refused.json()["detail"]
