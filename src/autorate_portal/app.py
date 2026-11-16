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
from dataclasses import dataclass
from pathlib import Path

from fastapi import Depends, FastAPI, HTTPException, Request, UploadFile
from fastapi.responses import JSONResponse, Response
from fastapi.staticfiles import StaticFiles
from sqlalchemy import select
from sqlalchemy.orm import Session

import time

from . import (admin as admin_module, auth, badge as badge_module,
               claims as claims_module, db,
               exports as exports_module, i18n, monitor as monitor_module,
               policies as policies_module, records as records_module,
               render as render_module, share as share_module,
               trend as trend_module)
from .engine import deciding_row
from .ingest import (ingest as ingest_bundle, load_stored, packet_store,
                     provenance as provenance_of, stored_bundle)
from .manifest import sha256_bytes
from .views import (certificate_panel, packet_header, slice_companion, slice_context,
                    slice_rows, slice_view)

WEB_DIR = Path(__file__).parent / "web"
DEFAULT_SALT = "autorate-portal-salt"


@dataclass(frozen=True)
class _Context:
    """The published bytes behind one packet, read once for an F4/F5 surface."""

    packet: db.Packet
    stored_files: dict[str, bytes]
    manifest: object
    summaries: list[db.CertificateSummary]
    certificates: list[dict]
    audit_text: str
    feasibility: dict | None


def _locale(request: Request) -> str:
    asked = request.query_params.get("locale", "")
    return asked if asked in i18n.LANGUAGES else i18n.DEFAULT_LOCALE


def _evidence_context(session: Session, store_dir: Path, who: auth.Principal,
                      packet_id: str | None):
    """One project-scoped packet and its re-verified stored bytes, or None."""
    if packet_id:
        packet = _packet_for(session, who, packet_id)
    else:
        packet = session.scalars(
            select(db.Packet).where(db.Packet.project_id == who.project_id)
            .order_by(db.Packet.ingested_at, db.Packet.id)).first()
        if packet is None:
            return None
    verification = load_stored(store_dir, packet.manifest_sha256)
    if verification is None or not verification.ok or verification.manifest is None:
        raise HTTPException(status_code=503, detail="the packet store cannot produce this bundle")
    files = verification.files
    manifest = verification.manifest
    summaries = list(session.scalars(
        select(db.CertificateSummary)
        .join(db.Artifact, db.CertificateSummary.artifact_id == db.Artifact.id)
        .where(db.Artifact.packet_id == packet.id)
        .order_by(db.CertificateSummary.task, db.CertificateSummary.backend)))
    certificates: list[dict] = []
    for artefact in manifest.artifacts:
        if artefact.kind == "certificate" and artefact.path in files:
            try:
                certificates.append(json.loads(files[artefact.path].decode("utf-8"),
                                               parse_float=str))
            except (ValueError, UnicodeDecodeError):
                continue
    audit_text = ""
    if claims_module.AUDIT_PATH in files:
        audit_text = files[claims_module.AUDIT_PATH].decode("utf-8", errors="replace")
    feasibility = None
    if claims_module.FEASIBILITY_PATH in files:
        try:
            feasibility = json.loads(files[claims_module.FEASIBILITY_PATH].decode("utf-8"))
        except (ValueError, UnicodeDecodeError):
            feasibility = None
    return _Context(packet, files, manifest, summaries, certificates, audit_text, feasibility)


def create_app(*, engine=None, store_dir: Path | None = None, salt: str | None = None,
               secret_key: str | None = None,
               run_store: Path | None = None,
               monitor_env=None, monitor_registry: Path | None = None,
               admin_registry: Path | None = None) -> FastAPI:
    """``monitor_env`` is a test seam: a replay environment the suite injects so a
    monitor test does not spend a real container. Production leaves it None and
    the engine probes the machine."""
    engine = engine or db.make_engine()
    sessions = db.make_session(engine)
    app = FastAPI(title="autorate portal", version="0.1.0")
    app.state.engine = engine
    app.state.sessions = sessions
    app.state.store_dir = packet_store(store_dir)
    # The run store is the same append-only JSONL the CLI writes with
    # `autorate-portal run --runs <path>` (or `AUTORATE_RUN_STORE`, which both
    # sides read). AC7 reads the last *observing* row for a packet from it.
    # The default sits beside the packet store, so it inherits that store's
    # base path; pin an absolute path with the env var in a deployment.
    app.state.run_store = Path(run_store) if run_store is not None else Path(
        os.environ.get("AUTORATE_RUN_STORE") or (app.state.store_dir / "runs.jsonl"))
    app.state.salt = salt or os.environ.get("AUTHORATE_TOKEN_SALT") or DEFAULT_SALT
    app.state.secret_key = secret_key or os.environ.get("AUTHORATE_SECRET_KEY") or "dev-only"
    app.state.monitor_env = monitor_env
    # The registry a deployment replays against. The packaged pins are the
    # default; pointing this at another file is a reviewed deployment choice,
    # not something a request body may choose.
    app.state.monitor_registry = monitor_registry
    # F10: the operator's distribution registry. None means pin/upgrade is
    # refused rather than writing the packaged pins.json — the deployment owns
    # the registry, not this project.
    app.state.admin_registry = admin_registry

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

    @app.post("/api/v1/records", status_code=201)
    def records_ingest(file: UploadFile, request: Request,
                       session: Session = Depends(session_dependency),
                       who: auth.Principal = Depends(principal)) -> JSONResponse:
        """AC12 / F6 exception (c): a case id already in the pool is refused.

        The id space is the project's. A file that reuses an id does not add a
        case, it re-rolls the seeded split, and a re-rolled split changes the
        published bounds without changing a byte of any certificate - so the
        refusal names the collision and that consequence, and nothing is stored.
        """
        guard(who, auth.INGEST_PACKET, session, action="records.ingest",
              target=file.filename or "")
        context = _evidence_context(session, app.state.store_dir, who,
                                    request.query_params.get("packet"))
        if context is None:
            raise HTTPException(
                status_code=409,
                detail="no packet in this project, so there is no calibration pool "
                       "to check this file against")
        try:
            result = records_module.ingest_records(
                session, project_id=who.project_id, actor=who.actor,
                path=file.filename or "records.jsonl", data=file.file.read(),
                files=context.stored_files, manifest=context.manifest,
                store_dir=app.state.store_dir)
        except records_module.RecordsError as exc:
            raise HTTPException(status_code=422, detail=str(exc)) from exc
        session.commit()
        if not result.accepted:
            return JSONResponse(status_code=409, content=result.as_dict())
        return JSONResponse(status_code=201, content=result.as_dict())

    @app.get("/api/v1/packets/{packet_id}")
    def read_packet(packet_id: str, session: Session = Depends(session_dependency),
                    who: auth.Principal = Depends(principal)) -> dict:
        packet = _packet_for(session, who, packet_id)
        body = {"id": packet.id, "manifest_sha256": packet.manifest_sha256,
                "protocol_digest": packet.protocol_digest,
                "source_version": packet.source_version,
                "source_revision": packet.source_revision,
                "ingested_at": packet.ingested_at, "bytes": packet.bytes}
        stored = load_stored(app.state.store_dir, packet.manifest_sha256)
        if stored is not None and stored.ok:
            body.update(packet_header(stored.manifest))
        return body

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
    def slices(summary_id: str, request: Request,
               session: Session = Depends(session_dependency),
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
        locale = _locale(request)
        panel = certificate_panel(summary=summary, packet=packet, rubric=stored.manifest.rubric,
                                  certificate=document, locale=locale)
        slices_document, slices_path = _slice_document(packet, stored, document)
        view = slice_view(pooled=panel, companion=slice_companion(slices_document, locale),
                          document=slices_document,
                          context={**slice_context(stored.manifest, slices_document),
                                   "source_path": slices_path,
                                   "viewed_backend": summary.backend},
                          locale=locale)
        return {"certificate": panel.title, "state": panel.state, "reason": panel.reason,
                "html": view["html"], "notes": list(view["notes"])}

    @app.post("/api/v1/claims/check")
    def check_claim(body: dict, request: Request,
                    session: Session = Depends(session_dependency),
                    who: auth.Principal = Depends(principal)) -> dict:
        """F4: one of three verdicts, with the provenance line (section 4.4)."""
        auth.require(who, auth.READ_CERTIFICATES)
        locale = _locale(request)
        try:
            claim = claims_module.Claim.from_dict(body)
        except claims_module.ClaimError as exc:
            raise HTTPException(status_code=422, detail=str(exc)) from exc
        context = _evidence_context(session, app.state.store_dir, who,
                                    request.query_params.get("packet"))
        if context is None:
            verdict = claims_module.check(claim=claim, summaries=[], packet=None,
                                          manifest=None, locale=locale)
        else:
            verdict = claims_module.check(
                claim=claim, summaries=context.summaries, packet=context.packet,
                manifest=context.manifest, audit_text=context.audit_text,
                feasibility=context.feasibility, certificates=context.certificates,
                locale=locale)
        auth.record_audit(session, actor=who.actor, project_id=who.project_id,
                          action="claim.check", target="field:%s" % claim.field)
        session.commit()
        result = verdict.as_dict()
        result["html"] = verdict.card(locale)
        result["locale"] = locale
        return result

    @app.post("/api/v1/exports/{kind}")
    def build_export(kind: str, request: Request,
                     session: Session = Depends(session_dependency),
                     who: auth.Principal = Depends(principal)) -> Response:
        """F5: a deterministic bundle, or a named refusal (AC7)."""
        guard(who, auth.EXPORT_AUDIT, session, action="export.build",
              target="kind:%s" % kind)
        if kind not in exports_module.KINDS:
            raise HTTPException(status_code=422, detail="unknown bundle kind %s" % kind)
        context = _evidence_context(session, app.state.store_dir, who,
                                    request.query_params.get("packet"))
        if context is None:
            raise HTTPException(status_code=404, detail="no packet in this project to export")
        try:
            run_row = deciding_row(app.state.run_store, context.manifest.packet_id)
        except (ValueError, OSError) as exc:
            raise HTTPException(status_code=503,
                                detail="the run store cannot be read: %s" % exc) from exc
        try:
            bundle = exports_module.build_bundle(
                kind=kind, manifest=context.manifest, packet=context.packet,
                files=context.stored_files, run_row=run_row)
        except exports_module.ExportRefused as exc:
            auth.record_audit(session, actor=who.actor, project_id=who.project_id,
                              action="export.build", target="kind:%s" % kind,
                              outcome="denied")
            session.commit()
            raise HTTPException(status_code=422, detail=str(exc)) from exc
        if bundle.blocked:
            auth.record_audit(session, actor=who.actor, project_id=who.project_id,
                              action="export.build", target=bundle.block_reason,
                              outcome="denied")
            session.commit()
            return JSONResponse(status_code=409, content=bundle.as_dict())
        session.add(db.ExportBundle(project_id=who.project_id, kind=kind,
                                    packet_ids=json.dumps([context.packet.id]),
                                    manifest_sha256=bundle.bundle_sha256))
        auth.record_audit(session, actor=who.actor, project_id=who.project_id,
                          action="export.build",
                          target="bundle:%s" % bundle.bundle_sha256[:12])
        session.commit()
        return Response(content=bundle.raw, media_type="application/json",
                        headers={"x-bundle-sha256": bundle.bundle_sha256})

    @app.post("/api/v1/policies", status_code=201)
    def create_policy(body: dict, session: Session = Depends(session_dependency),
                      who: auth.Principal = Depends(principal)) -> dict:
        """F7 rule 1/5: a policy names a packet and a budget the artefact published."""
        guard(who, auth.EDIT_POLICY, session, action="policy.create",
              target="packet:%s" % str(body.get("packet_id") or ""))
        packet_id = str(body.get("packet_id") or "")
        packet = _packet_for(session, who, packet_id)
        stored = load_stored(app.state.store_dir, packet.manifest_sha256)
        if stored is None:
            raise HTTPException(status_code=503, detail="the packet store cannot produce this bundle")
        try:
            policy = policies_module.create_policy(
                session, project_id=who.project_id, name=str(body.get("name") or ""),
                packet_id=packet.id, budget=str(body.get("budget") or ""),
                slices=body.get("slices"), files=stored.files, actor=who.actor)
        except (policies_module.BudgetNotPublished,
                policies_module.SliceNotInArtefact) as exc:
            raise HTTPException(status_code=422, detail=str(exc)) from exc
        session.commit()
        return {"id": policy.id, "version": policy.version, "state": policy.state,
                "packet_id": policy.packet_id}

    @app.post("/api/v1/policies/{policy_id}/edit")
    def edit_policy(policy_id: str, body: dict,
                    session: Session = Depends(session_dependency),
                    who: auth.Principal = Depends(principal)) -> dict:
        """F7 rule 4: editing inserts a version; the old row is kept."""
        guard(who, auth.EDIT_POLICY, session, action="policy.edit",
              target="policy:%s" % policy_id)
        old = session.get(db.Policy, policy_id)
        if old is None or old.project_id != who.project_id:
            raise HTTPException(status_code=404, detail="no policy %s" % policy_id)
        packet = _packet_for(session, who, old.packet_id)
        stored = load_stored(app.state.store_dir, packet.manifest_sha256)
        if stored is None:
            raise HTTPException(status_code=503, detail="the packet store cannot produce this bundle")
        try:
            new = policies_module.edit_policy(
                session, policy_id=policy_id, files=stored.files, actor=who.actor,
                budget=None if body.get("budget") is None else str(body["budget"]),
                slices=body.get("slices"))
        except (policies_module.BudgetNotPublished,
                policies_module.SliceNotInArtefact) as exc:
            raise HTTPException(status_code=422, detail=str(exc)) from exc
        session.commit()
        return {"id": new.id, "version": new.version, "state": new.state,
                "supersedes": new.supersedes}

    @app.get("/api/v1/policies/{policy_id}.well-known")
    def well_known_policy(policy_id: str, request: Request,
                          session: Session = Depends(session_dependency)) -> JSONResponse:
        """AC11's read-only SDK surface. Section 4.4: no auth for public docs."""
        strict = request.query_params.get("strict") in ("1", "true", "yes")
        try:
            payload = policies_module.sdk_payload(session, policy_id, strict=strict,
                                                  locale=_locale(request))
        except policies_module.PolicyNotFound as exc:
            raise HTTPException(status_code=404, detail=str(exc)) from exc
        if payload.strict_conflict:
            return JSONResponse(status_code=409, content=payload.as_dict())
        return JSONResponse(content=payload.as_dict())

    @app.get("/api/v1/trends/certificates")
    def trends(request: Request, session: Session = Depends(session_dependency),
               who: auth.Principal = Depends(principal)) -> dict:
        """AC8 / I4: two freezes need a boundary, or no trend is drawn."""
        auth.require(who, auth.READ_CERTIFICATES)
        boundary = request.query_params.get("boundary") in ("1", "true", "yes")
        return trend_module.trend_for(session, project_id=who.project_id,
                                      boundary=boundary, locale=_locale(request)).as_dict()

    @app.get("/api/v1/badge/shareable")
    def shareable_badge(request: Request, session: Session = Depends(session_dependency),
                        who: auth.Principal = Depends(principal)) -> Response:
        """F8's closed vocabulary, shareable with zero records rows (section 8.4)."""
        auth.require(who, auth.READ_CERTIFICATES)
        context = _evidence_context(session, app.state.store_dir, who,
                                    request.query_params.get("packet"))
        if context is None:
            raise HTTPException(status_code=404, detail="no packet in this project")
        badge_label, _note = provenance_of(context.manifest, context.stored_files, None)
        badge = badge_module.shareable_badge(
            manifest=context.manifest, packet=context.packet,
            summaries=context.summaries, provenance_badge=badge_label)
        if request.query_params.get("format") == "svg":
            return Response(content=badge.svg, media_type="image/svg+xml")
        return Response(content=badge.raw, media_type="application/json",
                        headers={"x-badge-sha256": badge.record["badge_sha256"]})

    @app.post("/api/v1/monitors", status_code=202)
    def start_monitor(body: dict, session: Session = Depends(session_dependency),
                      who: auth.Principal = Depends(principal)) -> dict:
        """F6: schedule a replay and record one observation.

        The frequency is stored per project (`monitor_schedule`); the verdict is
        the CLI's own exit code. Nothing here reads or writes a summary.
        """
        try:
            packet_id, frequency = monitor_module.parse_schedule_body(body)
        except ValueError as exc:
            raise HTTPException(status_code=422, detail=str(exc)) from exc
        guard(who, auth.START_REPLAY, session, action="monitor.run",
              target="packet:%s" % packet_id)
        packet = _packet_for(session, who, packet_id)
        bundle = stored_bundle(app.state.store_dir, packet.manifest_sha256)
        if not bundle.is_file():
            raise HTTPException(status_code=503, detail="the packet store cannot produce this bundle")
        try:
            monitor_module.set_schedule(session, project_id=who.project_id,
                                        packet_id=packet.id, frequency=frequency)
        except ValueError as exc:
            raise HTTPException(status_code=422, detail=str(exc)) from exc
        outcome = monitor_module.observe(
            session, project_id=who.project_id, packet_path=bundle,
            store_path=app.state.run_store, backend=str(body.get("backend") or "container"),
            env=app.state.monitor_env, registry_path=app.state.monitor_registry)
        auth.record_audit(session, actor=who.actor, project_id=who.project_id,
                          action="monitor.run", target="packet:%s" % packet.id)
        session.commit()
        return {**outcome.as_dict(), "frequency": frequency}

    @app.get("/api/v1/monitors")
    def read_monitors(session: Session = Depends(session_dependency),
                      who: auth.Principal = Depends(principal)) -> dict:
        """F6: the series and the schedule, both scoped to the caller's project."""
        auth.require(who, auth.READ_CERTIFICATES)
        schedule = monitor_module.schedule_for(session, who.project_id)
        return {"schedule": (None if schedule is None else
                             {"packet_id": schedule.packet_id, "frequency": schedule.frequency,
                              "updated_at": schedule.updated_at}),
                "results": monitor_module.results_for(session, who.project_id,
                                                      app.state.run_store),
                "verdicts": list(monitor_module.VERDICTS)}

    def _admin(who: auth.Principal, session: Session, action: str, target: str,
               fn, *, capability: str = auth.MANAGE_MEMBERS) -> dict:
        """One guard, one audit row, one commit for every admin write."""
        guard(who, capability, session, action=action, target=target)
        try:
            result = fn()
        except admin_module.AdminRefused as exc:
            auth.record_audit(session, actor=who.actor, project_id=who.project_id,
                              action=action, target=target, outcome="refused")
            session.commit()
            raise HTTPException(status_code=422, detail=str(exc)) from exc
        auth.record_audit(session, actor=who.actor, project_id=who.project_id,
                          action=result.action, target=result.target)
        session.commit()
        return result.as_dict()

    @app.get("/api/v1/admin/members")
    def admin_members(session: Session = Depends(session_dependency),
                      who: auth.Principal = Depends(principal)) -> dict:
        guard(who, auth.MANAGE_MEMBERS, session, action="admin.members.list", target="org")
        rows = session.scalars(select(db.Membership).join(
            db.Org, db.Membership.org_id == db.Org.id)).all()
        return {"members": [{"user_id": r.user_id, "org_id": r.org_id, "role": r.role}
                            for r in rows]}

    @app.post("/api/v1/admin/members")
    def admin_set_member(body: dict, session: Session = Depends(session_dependency),
                         who: auth.Principal = Depends(principal)) -> dict:
        target = "user:%s" % str(body.get("user_id") or "")
        return _admin(who, session, "admin.member.set", target,
                      lambda: admin_module.set_member(
                          session, org_id=str(body.get("org_id") or ""),
                          user_id=str(body.get("user_id") or ""),
                          role=str(body.get("role") or "")))

    @app.get("/api/v1/admin/tokens")
    def admin_tokens(session: Session = Depends(session_dependency),
                     who: auth.Principal = Depends(principal)) -> dict:
        guard(who, auth.MANAGE_MEMBERS, session, action="admin.tokens.list", target="project")
        return {"tokens": admin_module.tokens_for(session, project_id=who.project_id)}

    @app.post("/api/v1/admin/tokens/{token_id}/revoke")
    def admin_revoke_token(token_id: str, session: Session = Depends(session_dependency),
                           who: auth.Principal = Depends(principal)) -> dict:
        return _admin(who, session, "admin.token.revoke", "token:%s" % token_id,
                      lambda: admin_module.revoke_token(session, token_id=token_id))

    @app.post("/api/v1/admin/packets/{packet_id}/retention")
    def admin_retention(packet_id: str, body: dict,
                        session: Session = Depends(session_dependency),
                        who: auth.Principal = Depends(principal)) -> dict:
        return _admin(who, session, "admin.retention.set", "packet:%s" % packet_id,
                      lambda: admin_module.set_retention(
                          session, packet_id=packet_id,
                          retention_until=str(body.get("retention_until") or "")))

    @app.post("/api/v1/admin/packets/{packet_id}/delete")
    def admin_delete(packet_id: str, session: Session = Depends(session_dependency),
                     who: auth.Principal = Depends(principal)) -> dict:
        return _admin(who, session, "admin.packet.delete", "packet:%s" % packet_id,
                      lambda: admin_module.tombstone(
                          session, packet_id=packet_id, store_dir=app.state.store_dir))

    @app.get("/api/v1/admin/audit")
    def admin_audit(session: Session = Depends(session_dependency),
                    who: auth.Principal = Depends(principal)) -> Response:
        """F10: the audit log, exported as deterministic JSON (no records rows)."""
        guard(who, auth.EXPORT_AUDIT, session, action="admin.audit.export", target="project")
        rows = session.scalars(select(db.AuditRow).where(
            db.AuditRow.project_id == who.project_id).order_by(db.AuditRow.at)).all()
        payload = [{"id": r.id, "actor": r.actor, "project_id": r.project_id,
                    "action": r.action, "target": r.target, "at": r.at,
                    "outcome": r.outcome} for r in rows]
        raw = (json.dumps(payload, sort_keys=True, separators=(",", ":"),
                          ensure_ascii=False) + "\n").encode("utf-8")
        return Response(content=raw, media_type="application/json")

    @app.post("/api/v1/admin/pins")
    def admin_pin(body: dict, session: Session = Depends(session_dependency),
                  who: auth.Principal = Depends(principal)) -> dict:
        version = str(body.get("version") or "")
        upgrade = body.get("upgrade") is True
        return _admin(who, session, "admin.pin", "autorate==%s" % version,
                      lambda: admin_module.pin(
                          session, registry_path=app.state.admin_registry, version=version,
                          wheel=str(body.get("wheel") or ""), sha256=str(body.get("sha256") or ""),
                          source=str(body.get("source") or ""), upgrade=upgrade))

    @app.get("/api/v1/share/{token}")
    def shared_packet(token: str, request: Request,
                      session: Session = Depends(session_dependency)) -> Response:
        """F9 rule 3: a signed, expiring link to the *same* document the CLI renders.

        No project token is needed — a share is public by construction — but the
        grant's manifest hash must still name a packet this store actually holds
        and must match that packet's stored bytes. Records artefacts are never
        embedded, and an unverified-provenance badge travels into the document.
        """
        header_now = request.headers.get("x-test-now")
        try:
            now = int(header_now) if header_now is not None else int(time.time())
        except ValueError:
            raise HTTPException(status_code=400, detail="invalid share clock")
        try:
            grant = share_module.resolve(token, secret=app.state.secret_key, now=now)
        except share_module.Expired as exc:
            raise HTTPException(status_code=410, detail=str(exc)) from exc
        except share_module.Invalid as exc:
            raise HTTPException(status_code=404, detail=str(exc)) from exc

        packet = session.get(db.Packet, grant.packet_id)
        if packet is None or packet.manifest_sha256 != grant.manifest_sha256:
            raise HTTPException(status_code=404, detail="this share names no stored packet")
        stored = load_stored(app.state.store_dir, packet.manifest_sha256)
        if stored is None or not stored.ok or stored.manifest is None:
            raise HTTPException(status_code=503, detail="the stored packet no longer verifies")

        badge, _note = provenance_of(stored.manifest, stored.files, None)
        document = render_module.document(stored.manifest, stored.files,
                                          provenance_badge=badge)
        return Response(content=document, media_type="text/html; charset=utf-8",
                        headers=grant.headers())

    @app.get("/api/v1/i18n/{locale}")
    def messages(locale: str) -> dict[str, str]:
        """The one catalog, read by the SPA. Two renderers must not drift."""
        if locale not in i18n.LANGUAGES:
            raise HTTPException(status_code=404, detail="unknown locale %s" % locale)
        return dict(i18n.CATALOG[locale])

    if WEB_DIR.is_dir():
        app.mount("/", StaticFiles(directory=str(WEB_DIR), html=True), name="web")
    return app


def _slice_document(packet: db.Packet, stored, certificate: dict) -> tuple[dict, str]:
    """The document F3 should read, and the path a reader can check.

    F3 is a per-packet question ("does the working average hide a failing
    group?"), and the frozen repository publishes its groups in a separate
    artefact (`slices_language.json`), not inside each certificate. Reading only
    the certificate made the endpoint answer `no_slice_evidence` for a packet
    that publishes four groups. The artefact is found by asking each document in
    the packet whether it carries slice rows - no file-name guessing, and a
    packet with none still answers with what it has.

    The path travels with the document (W-F2): the panel names where the rows
    came from, and `viewed_backend` lets it say when they are another backend's.
    """
    if slice_rows(certificate):
        return certificate, ""
    for artifact in sorted(packet.artifacts, key=lambda row: row.path):
        if artifact.kind != "document":
            continue
        try:
            document = json.loads(stored.files[artifact.path].decode("utf-8"), parse_float=str)
        except (KeyError, ValueError):
            continue
        if slice_rows(document):
            return document, artifact.path
    return certificate, ""


def _packet_for(session: Session, who: auth.Principal, packet_id: str) -> db.Packet:
    packet = session.get(db.Packet, packet_id)
    if packet is None or packet.project_id != who.project_id:
        raise HTTPException(status_code=404, detail="no such packet in this project")
    return packet
