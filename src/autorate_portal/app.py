"""The HTTP surface of Section 4.4, scoped by the caller rather than by a filter.

Every route takes its project from the principal. There is no endpoint that
aggregates across projects, not a restricted one - Section 4.3 asks for absence,
and absence is easier to keep than a rule.

Authorisation failures are not silent: a denial writes an audit row naming the
actor, the project and the artefact, because AC13 asks for the record and not
only for the status code.
"""
from __future__ import annotations

import json
import os
from pathlib import Path

from fastapi import Depends, FastAPI, HTTPException, Request, UploadFile
from fastapi.responses import JSONResponse, Response
from fastapi.staticfiles import StaticFiles
from sqlalchemy.orm import Session

from . import auth, db
from .ingest import ingest as ingest_bundle, load_stored, packet_store
from .manifest import sha256_bytes
from .views import certificate_panel, slice_view

WEB_DIR = Path(__file__).parent / "web"
DEFAULT_SALT = "autorate-portal-salt"


def create_app(*, engine=None, store_dir: Path | None = None, salt: str | None = None,
               secret_key: str | None = None) -> FastAPI:
    engine = engine or db.make_engine()
    sessions = db.make_session(engine)
    app = FastAPI(title="autorate portal", version="0.1.0")
    app.state.engine = engine
    app.state.sessions = sessions
    app.state.store_dir = packet_store(store_dir)
    app.state.salt = salt or os.environ.get("AUTHORATE_TOKEN_SALT") or DEFAULT_SALT
    app.state.secret_key = secret_key or os.environ.get("AUTHORATE_SECRET_KEY") or "dev-only"

    def session_dependency() -> Session:
        with sessions() as session:
            yield session

    def principal(request: Request, session: Session = Depends(session_dependency)) -> auth.Principal:
        token = request.headers.get("x-api-token", "")
        asked = request.query_params.get("project", "")
        if token:
            try:
                found = auth.principal_from_token(session, token, salt=app.state.salt)
            except auth.AuthError as exc:
                raise HTTPException(status_code=401, detail=str(exc)) from exc
            if asked and asked != found.project_id:
                raise HTTPException(status_code=403, detail="this credential is scoped to another project")
            return found
        cookie = request.cookies.get("session", "")
        email = auth.read_session(app.state.secret_key, cookie) if cookie else None
        project_id = asked
        if not email or not project_id:
            raise HTTPException(status_code=401, detail="no token and no session")
        try:
            return auth.principal_for_project(session, email=email, project_id=project_id)
        except auth.AuthError as exc:
            raise HTTPException(status_code=401, detail=str(exc)) from exc

    def guard(principal_value: auth.Principal, capability: str, session: Session,
              *, action: str, target: str) -> None:
        try:
            auth.require(principal_value, capability)
        except auth.Forbidden as exc:
            auth.record_audit(session, actor=principal_value.actor,
                              project_id=principal_value.project_id, action=action,
                              target=target, outcome="denied")
            session.commit()
            raise HTTPException(status_code=403, detail=str(exc)) from exc

    @app.get("/healthz")
    def healthz() -> dict[str, str]:
        return {"status": "ok"}

    @app.get("/version")
    def version() -> dict[str, str]:
        from . import __version__
        return {"version": __version__, "autorate": "0.1.2"}

    @app.post("/api/v1/packets", status_code=201)
    def create_packet(file: UploadFile, request: Request,
                      session: Session = Depends(session_dependency),
                      who: auth.Principal = Depends(principal)) -> JSONResponse:
        guard(who, auth.INGEST_PACKET, session, action="packet.ingest", target=file.filename or "")
        incoming = app.state.store_dir / "_incoming"
        incoming.mkdir(parents=True, exist_ok=True)
        temporary = incoming / ("%s.upload" % sha256_bytes((file.filename or "packet").encode()))
        temporary.write_bytes(file.file.read())
        result = ingest_bundle(session, bundle_path=temporary, project_id=who.project_id,
                               actor=who.actor, store_dir=app.state.store_dir)
        temporary.unlink(missing_ok=True)
        session.commit()
        if not result.accepted:
            return JSONResponse(status_code=409, content={
                "state": result.state,
                "refusals": [{"path": r.path, "reason": r.reason,
                              "expected": r.expected, "actual": r.actual}
                             for r in result.refusals]})
        return JSONResponse(status_code=201, content={
            "id": result.row_id, "packet_id": result.packet_id,
            "badge": result.badge, "note": result.note})

    @app.get("/api/v1/packets/{packet_id}")
    def read_packet(packet_id: str, session: Session = Depends(session_dependency),
                    who: auth.Principal = Depends(principal)) -> dict:
        packet = _packet_for(session, who, packet_id)
        return {"id": packet.id, "manifest_sha256": packet.manifest_sha256,
                "protocol_digest": packet.protocol_digest,
                "source_version": packet.source_version,
                "source_revision": packet.source_revision,
                "ingested_at": packet.ingested_at, "bytes": packet.bytes}

    @app.get("/api/v1/packets/{packet_id}/artifacts/{artifact_id}")
    def download(packet_id: str, artifact_id: str, session: Session = Depends(session_dependency),
                 who: auth.Principal = Depends(principal)):
        packet = _packet_for(session, who, packet_id)
        artifact = session.get(db.Artifact, artifact_id)
        if artifact is None or artifact.packet_id != packet.id:
            raise HTTPException(status_code=404, detail="no such artefact in this packet")
        action = "artifact.download"
        if artifact.kind != "protocol":
            guard(who, auth.DOWNLOAD_RAW, session, action=action,
                  target="artifact:%s" % artifact.id)
        stored = load_stored(app.state.store_dir, packet.manifest_sha256)
        if stored is None or not stored.ok:
            raise HTTPException(status_code=503, detail="the packet store cannot produce this bundle")
        data = stored.files.get(artifact.path)
        if data is None or sha256_bytes(data) != artifact.sha256:
            raise HTTPException(status_code=503, detail="stored bytes do not match the manifest")
        auth.record_audit(session, actor=who.actor, project_id=who.project_id, action=action,
                          target="artifact:%s" % artifact.id)
        session.commit()
        return Response(content=data, media_type="application/octet-stream")

    @app.get("/api/v1/certificates")
    def certificates(session: Session = Depends(session_dependency),
                     who: auth.Principal = Depends(principal)) -> list[dict]:
        auth.require(who, auth.READ_CERTIFICATES)
        rows = db.summaries_for_project(session, project_id=who.project_id)
        return [{"id": row.id, "artifact_id": row.artifact_id,
                 **{key: value for key, value in db.summary_values(row).items()}}
                for row in rows]

    @app.get("/api/v1/certificates/{summary_id}/slices")
    def slices(summary_id: str, session: Session = Depends(session_dependency),
               who: auth.Principal = Depends(principal)) -> dict:
        auth.require(who, auth.READ_CERTIFICATES)
        summary = session.get(db.CertificateSummary, summary_id)
        if summary is None:
            raise HTTPException(status_code=404, detail="no such certificate")
        artifact = session.get(db.Artifact, summary.artifact_id)
        packet = _packet_for(session, who, artifact.packet_id) if artifact else None
        if artifact is None or packet is None:
            raise HTTPException(status_code=404, detail="no such certificate")
        stored = load_stored(app.state.store_dir, packet.manifest_sha256)
        if stored is None or not stored.ok:
            raise HTTPException(status_code=503, detail="the packet store cannot produce this bundle")
        document = json.loads(stored.files[artifact.path].decode("utf-8"), parse_float=str)
        panel = certificate_panel(summary=summary, packet=packet, rubric=stored.manifest.rubric,
                                  certificate=document)
        view = slice_view(pooled=panel, companion=None, document=document)
        return {"certificate": panel.title, "state": panel.state, "reason": panel.reason,
                "html": view["html"], "notes": list(view["notes"])}

    if WEB_DIR.is_dir():
        app.mount("/", StaticFiles(directory=str(WEB_DIR), html=True), name="web")
    return app


def _packet_for(session: Session, who: auth.Principal, packet_id: str) -> db.Packet:
    packet = session.get(db.Packet, packet_id)
    if packet is None or packet.project_id != who.project_id:
        raise HTTPException(status_code=404, detail="no such packet in this project")
    return packet
