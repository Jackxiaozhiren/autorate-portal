"""Section 4.3's relational model, and the two rules it has to make structural.

I1 says ``certificate_summary`` is populated *only* by the packet parser or by a
run's captured output, and that no code path writes a bound from application
arithmetic. A comment cannot enforce that, so two choices here do:

* ``bound`` and ``autorate`` are text. A REAL column invites ``AVG``; the value
  the view must print is the digits the artefact carried, unchanged, and a
  string is the only type that keeps them unchanged.
* summaries are written through :func:`record_summary`, which accepts only
  columns the parser read and refuses a bound without its unit - so a caller
  cannot assemble a number the artefact did not contain.

Tenant isolation (Section 4.3) is the same shape: :func:`summaries_for_project`
is the read path, and it joins through ``packet.project_id`` rather than
trusting a caller-supplied filter. There is no cross-project query in this
module, not a restricted one.
"""
from __future__ import annotations

import json
import os
import uuid
from pathlib import Path
from typing import Any, Iterable

from sqlalchemy import (Boolean, CheckConstraint, ForeignKey, Integer, String, Text,
                        UniqueConstraint, create_engine, select)
from sqlalchemy.engine import Engine
from sqlalchemy.orm import (DeclarativeBase, Mapped, Session, mapped_column,
                            relationship, sessionmaker)

DB_URL_ENV = "AUTHORATE_DB_URL"
DEFAULT_DB_FILE = "autorate-portal.db"

ROLES = ("viewer", "producer", "compliance", "admin", "auditor")
ARTIFACT_KINDS = ("certificate", "document", "records", "protocol", "transcript")
POLICY_STATES = ("active", "stale", "superseded")
EXPORT_KINDS = ("annex_iv", "iso_42001", "aap")

#: Section 4.3, verbatim, as the contract the migration is checked against.
SECTION_4_3: dict[str, tuple[str, ...]] = {
    "org": ("id", "name"),
    "project": ("id", "org_id", "name"),
    "packet": ("id", "project_id", "manifest_sha256", "protocol_digest", "source_version",
               "source_sha256", "source_revision", "created_by", "ingested_at", "bytes",
               "retention_until"),
    "artifact": ("id", "packet_id", "path", "sha256", "kind"),
    "certificate_summary": ("id", "artifact_id", "task", "backend", "feasible", "reason",
                            "autorate", "bound", "bound_unit", "n_cal", "n_eval", "n_claims",
                            "alpha", "beta", "delta"),
    "run": ("id", "project_id", "argv", "exit_code", "started_at", "digest_then",
            "stdout_sha256", "packet_id_in"),
    "policy": ("id", "project_id", "name", "packet_id", "slices", "budget", "state",
               "stale_because"),
    "monitor_result": ("id", "run_id", "verdict", "drift_detail_artifact_id"),
    "user": ("id", "email", "display"),
    "membership": ("user_id", "org_id", "role"),
    "api_token": ("id", "user_id", "project_id", "hash", "scopes", "created_at", "last_used_at"),
    "export_bundle": ("id", "project_id", "kind", "packet_ids", "manifest_sha256"),
}

SUMMARY_FIELDS = tuple(name for name in SECTION_4_3["certificate_summary"] if name != "id")


class Base(DeclarativeBase):
    pass


def _new_id() -> str:
    return uuid.uuid4().hex


def _id() -> Mapped[str]:
    return mapped_column(String(32), primary_key=True, default=_new_id)


class Org(Base):
    __tablename__ = "org"
    id: Mapped[str] = _id()
    name: Mapped[str] = mapped_column(String(255), unique=True)
    projects: Mapped[list["Project"]] = relationship(back_populates="org")


class Project(Base):
    __tablename__ = "project"
    __table_args__ = (UniqueConstraint("org_id", "name", name="uq_project_org_name"),)
    id: Mapped[str] = _id()
    org_id: Mapped[str] = mapped_column(ForeignKey("org.id", ondelete="CASCADE"))
    name: Mapped[str] = mapped_column(String(255))
    org: Mapped[Org] = relationship(back_populates="projects")


class Packet(Base):
    __tablename__ = "packet"
    # AC14: ingesting the same bundle twice under one project is one packet.
    __table_args__ = (UniqueConstraint("project_id", "manifest_sha256", name="uq_packet_manifest"),)
    id: Mapped[str] = _id()
    project_id: Mapped[str] = mapped_column(ForeignKey("project.id", ondelete="CASCADE"))
    manifest_sha256: Mapped[str] = mapped_column(String(64))
    protocol_digest: Mapped[str] = mapped_column(String(255))
    source_version: Mapped[str] = mapped_column(String(255))
    source_sha256: Mapped[str] = mapped_column(String(64))
    source_revision: Mapped[str] = mapped_column(String(255))
    created_by: Mapped[str] = mapped_column(String(255))
    ingested_at: Mapped[str] = mapped_column(String(40))
    bytes: Mapped[int] = mapped_column(Integer)
    retention_until: Mapped[str | None] = mapped_column(String(40), nullable=True)
    artifacts: Mapped[list["Artifact"]] = relationship(back_populates="packet")


class Artifact(Base):
    __tablename__ = "artifact"
    __table_args__ = (
        UniqueConstraint("packet_id", "path", name="uq_artifact_path"),
        CheckConstraint("kind in %s" % str(ARTIFACT_KINDS), name="ck_artifact_kind"),
    )
    id: Mapped[str] = _id()
    packet_id: Mapped[str] = mapped_column(ForeignKey("packet.id", ondelete="CASCADE"))
    path: Mapped[str] = mapped_column(String(512))
    sha256: Mapped[str] = mapped_column(String(64))
    kind: Mapped[str] = mapped_column(String(32))
    packet: Mapped[Packet] = relationship(back_populates="artifacts")


class CertificateSummary(Base):
    __tablename__ = "certificate_summary"
    __table_args__ = (UniqueConstraint("artifact_id", "task", "backend",
                                       name="uq_summary_task_backend"),)
    id: Mapped[str] = _id()
    artifact_id: Mapped[str] = mapped_column(ForeignKey("artifact.id", ondelete="CASCADE"))
    task: Mapped[str] = mapped_column(String(255))
    backend: Mapped[str] = mapped_column(String(255))
    feasible: Mapped[bool | None] = mapped_column(Boolean, nullable=True)
    reason: Mapped[str | None] = mapped_column(Text, nullable=True)
    # Text on purpose: see the module docstring. NULL means the artefact omitted
    # it, and the view renders that absence rather than a zero.
    autorate: Mapped[str | None] = mapped_column(Text, nullable=True)
    bound: Mapped[str | None] = mapped_column(Text, nullable=True)
    bound_unit: Mapped[str | None] = mapped_column(Text, nullable=True)
    n_cal: Mapped[int | None] = mapped_column(Integer, nullable=True)
    n_eval: Mapped[int | None] = mapped_column(Integer, nullable=True)
    n_claims: Mapped[int | None] = mapped_column(Integer, nullable=True)
    alpha: Mapped[str | None] = mapped_column(Text, nullable=True)
    beta: Mapped[str | None] = mapped_column(Text, nullable=True)
    delta: Mapped[str | None] = mapped_column(Text, nullable=True)
    artifact: Mapped[Artifact] = relationship()


class Run(Base):
    __tablename__ = "run"
    id: Mapped[str] = _id()
    project_id: Mapped[str] = mapped_column(ForeignKey("project.id", ondelete="CASCADE"))
    argv: Mapped[str] = mapped_column(Text)          # JSON list, never a shell string
    exit_code: Mapped[int | None] = mapped_column(Integer, nullable=True)
    started_at: Mapped[str] = mapped_column(String(40))
    digest_then: Mapped[str] = mapped_column(String(64))
    stdout_sha256: Mapped[str] = mapped_column(String(64))
    packet_id_in: Mapped[str] = mapped_column(String(32))


class Policy(Base):
    __tablename__ = "policy"
    __table_args__ = (CheckConstraint("state in %s" % str(POLICY_STATES), name="ck_policy_state"),)
    id: Mapped[str] = _id()
    project_id: Mapped[str] = mapped_column(ForeignKey("project.id", ondelete="CASCADE"))
    name: Mapped[str] = mapped_column(String(255))
    packet_id: Mapped[str] = mapped_column(String(32))
    slices: Mapped[str] = mapped_column(Text)        # JSON
    budget: Mapped[str] = mapped_column(Text)
    state: Mapped[str] = mapped_column(String(16))
    stale_because: Mapped[str | None] = mapped_column(Text, nullable=True)


class MonitorResult(Base):
    __tablename__ = "monitor_result"
    id: Mapped[str] = _id()
    run_id: Mapped[str] = mapped_column(ForeignKey("run.id", ondelete="CASCADE"))
    verdict: Mapped[str] = mapped_column(String(32))
    drift_detail_artifact_id: Mapped[str | None] = mapped_column(
        ForeignKey("artifact.id"), nullable=True)


class User(Base):
    __tablename__ = "user"
    id: Mapped[str] = _id()
    email: Mapped[str] = mapped_column(String(320), unique=True)
    display: Mapped[str] = mapped_column(String(255))


class Membership(Base):
    __tablename__ = "membership"
    __table_args__ = (
        CheckConstraint("role in %s" % str(ROLES), name="ck_membership_role"),
    )
    user_id: Mapped[str] = mapped_column(ForeignKey("user.id", ondelete="CASCADE"),
                                         primary_key=True)
    org_id: Mapped[str] = mapped_column(ForeignKey("org.id", ondelete="CASCADE"),
                                        primary_key=True)
    role: Mapped[str] = mapped_column(String(16))


class ApiToken(Base):
    __tablename__ = "api_token"
    id: Mapped[str] = _id()
    user_id: Mapped[str] = mapped_column(ForeignKey("user.id", ondelete="CASCADE"))
    project_id: Mapped[str] = mapped_column(ForeignKey("project.id", ondelete="CASCADE"))
    hash: Mapped[str] = mapped_column(String(64), unique=True)   # the only credential stored
    scopes: Mapped[str] = mapped_column(Text)
    created_at: Mapped[str] = mapped_column(String(40))
    last_used_at: Mapped[str | None] = mapped_column(String(40), nullable=True)


class ExportBundle(Base):
    __tablename__ = "export_bundle"
    __table_args__ = (CheckConstraint("kind in %s" % str(EXPORT_KINDS), name="ck_export_kind"),)
    id: Mapped[str] = _id()
    project_id: Mapped[str] = mapped_column(ForeignKey("project.id", ondelete="CASCADE"))
    kind: Mapped[str] = mapped_column(String(16))
    packet_ids: Mapped[str] = mapped_column(Text)    # JSON
    manifest_sha256: Mapped[str] = mapped_column(String(64))


class AuditRow(Base):
    """Section 4.4: every mutating endpoint writes one. Denials are written too."""

    __tablename__ = "audit_row"
    id: Mapped[str] = _id()
    actor: Mapped[str] = mapped_column(String(320))
    project_id: Mapped[str | None] = mapped_column(String(32), nullable=True)
    action: Mapped[str] = mapped_column(String(64))
    target: Mapped[str] = mapped_column(String(512))
    at: Mapped[str] = mapped_column(String(40))
    outcome: Mapped[str] = mapped_column(String(16), default="allowed")


def database_url() -> str:
    """SQLite by default; PostgreSQL by one env var (Section 4.2)."""
    configured = os.environ.get(DB_URL_ENV)
    if configured:
        return configured
    return "sqlite:///" + str(Path(DEFAULT_DB_FILE).resolve())


def make_engine(url: str | None = None) -> Engine:
    target = url or database_url()
    args: dict[str, Any] = {}
    if target.startswith("sqlite"):
        # FastAPI runs sync endpoints in a threadpool; a SQLite connection is
        # created on one thread and reused on another.
        args["connect_args"] = {"check_same_thread": False}
    return create_engine(target, future=True, **args)


def make_session(engine: Engine) -> sessionmaker[Session]:
    return sessionmaker(bind=engine, expire_on_commit=False, future=True)


def create_all(engine: Engine) -> None:
    """Dev and test convenience. Production schema comes from Alembic (T3)."""
    Base.metadata.create_all(engine)


def record_summary(session: Session, *, artifact_id: str, fields: dict[str, Any]) -> CertificateSummary:
    """The only writer for ``certificate_summary``.

    It copies. It does not combine, average, or fill: a field absent from
    ``fields`` stays NULL and the view renders it as absent, and a bound without
    the unit the artefact printed beside it is refused rather than guessed.
    """
    unknown = sorted(set(fields) - set(SUMMARY_FIELDS))
    if unknown:
        raise ValueError("not a certificate_summary column: %s" % ", ".join(unknown))
    if fields.get("bound") is not None and not fields.get("bound_unit"):
        raise ValueError("a bound without its unit is not a certificate value")
    summary = CertificateSummary(artifact_id=artifact_id, **fields)
    session.add(summary)
    return summary


def summaries_for_project(session: Session, *, project_id: str) -> list[CertificateSummary]:
    """Section 4.3's read path: scoped by the join, not by the caller's filter."""
    statement = (
        select(CertificateSummary)
        .join(Artifact, CertificateSummary.artifact_id == Artifact.id)
        .join(Packet, Artifact.packet_id == Packet.id)
        .where(Packet.project_id == project_id)
        .order_by(CertificateSummary.task, CertificateSummary.backend)
    )
    return list(session.scalars(statement))


def summary_values(summary: CertificateSummary) -> dict[str, Any]:
    """What the view is allowed to print, with absences kept absent."""
    return {name: getattr(summary, name) for name in SUMMARY_FIELDS}


def argv_json(argv: Iterable[str]) -> str:
    return json.dumps(list(argv), separators=(",", ":"))
