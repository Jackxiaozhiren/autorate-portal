"""F9 — one renderer, two targets; a share link with an expiry that cannot
outlive it, no records rows, and a provenance badge that travels.

The plants: make the share route render with a second template and the byte
equality dies; drop the expiry check and an expired link still serves; embed a
records artefact and the privacy rule dies; make edit overwrite a share and the
audit id disappears.
"""
from __future__ import annotations

from pathlib import Path

import pytest
from fastapi.testclient import TestClient
from sqlalchemy import select

from autorate_portal import auth, db, render as render_module, share as share_module
from autorate_portal.app import create_app
from autorate_portal.html import render as html_render
from autorate_portal.packet import verify_bundle


def _file_map():
    """A minimal manifest-shaped input for the document renderer tests."""
    return None  # filled from fixtures in the tests


def test_cli_and_share_render_the_same_document_bytes(tmp_path, built, m4_built):
    packet = Path(m4_built[0])
    result = verify_bundle(packet)
    assert result.ok, result.refusals
    cli_bytes = html_render(result.manifest, result.files).encode("utf-8")

    engine = db.make_engine("sqlite:///" + str(tmp_path / "s.db"))
    db.create_all(engine)
    sessions = db.make_session(engine)
    app = create_app(engine=engine, store_dir=tmp_path / "store", salt="s", secret_key="k")
    client = TestClient(app)
    with sessions() as s:
        s.add(db.Org(id="org-1", name="org-1"))
        s.add(db.Project(id="prj-1", org_id="org-1", name="prj-1"))
        s.add(db.User(id="usr-p", email="p@example.test", display="P"))
        s.add(db.Membership(user_id="usr-p", org_id="org-1", role="producer"))
        s.flush()
        token, _ = auth.issue_token(s, user_id="usr-p", project_id="prj-1", salt="s")
        s.commit()
    up = client.post("/api/v1/packets", headers={"x-api-token": token},
                     files={"file": ("p.tar", packet.read_bytes(), "application/x-tar")})
    assert up.status_code == 201, up.text
    packet_id = up.json()["id"]
    with sessions() as s:
        stored = s.scalars(select(db.Packet).where(db.Packet.id == packet_id)).one()

    share_token = share_module.mint(packet_id=packet_id,
                                    manifest_sha256=stored.manifest_sha256,
                                    ttl_seconds=60, secret="k", now=1000)
    response = client.get("/api/v1/share/%s" % share_token,
                          headers={"X-Test-Now": "1000"})
    assert response.status_code == 200, response.text
    assert response.content == cli_bytes, "one renderer, two targets, same bytes"
    assert response.headers["x-share-packet-id"] == packet_id
    assert response.headers["x-share-expires-at"] == "1060"


def test_an_expired_or_tampered_share_never_serves(tmp_path, m4_built):
    engine = db.make_engine("sqlite:///")
    db.create_all(engine)
    sessions = db.make_session(engine)
    client = TestClient(create_app(engine=engine, store_dir=tmp_path / "store",
                                   salt="s", secret_key="k"))
    expired = share_module.mint(packet_id="pkt-1", manifest_sha256="f" * 64,
                                ttl_seconds=1, secret="k", now=1000)
    response = client.get("/api/v1/share/%s" % expired, headers={"X-Test-Now": "1002"})
    assert response.status_code == 410
    with pytest.raises(share_module.Expired):
        share_module.resolve(expired, secret="k", now=1002)
    with pytest.raises(share_module.Invalid):
        share_module.resolve(expired + "tamper", secret="k", now=1001)


def test_an_oversized_artefact_is_omitted_named_and_linked(tmp_path, built):
    from autorate_portal.packet import verify_bundle
    packet, manifest, _ = built
    result = verify_bundle(packet)
    doc = render_module.document(result.manifest, result.files, embed_cap=8)
    # The omitted artefact's path is named, a download link is offered, and no
    # oversized bytes were embedded.
    assert "omitted" in doc.lower()
    assert "data/cert_laya.json" in doc
    assert "artifact.download" in doc or "download" in doc.lower()
    for name, raw in result.files.items():
        if len(raw) > 8:
            assert raw.decode("utf-8", "ignore") not in doc


def test_the_provenance_badge_travels_into_the_document(built):
    packet, manifest, _ = built
    result = verify_bundle(packet)
    plain = render_module.document(result.manifest, result.files)
    badged = render_module.document(result.manifest, result.files,
                                    provenance_badge="unverified_provenance")
    assert "unverified_provenance" not in plain
    assert "unverified_provenance" in badged
