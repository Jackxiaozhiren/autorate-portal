"""Section 4.5's permission matrix, and the two ways a caller is identified.

One function answers "may this role do this": :func:`allowed`. It fails closed -
an unknown role has no capabilities, and an unknown capability is a programming
error rather than a quiet ``False``. The API layer never reads a role from a
request body; a role exists only as a membership row, so the only way to claim
one is to be granted it.

Two credentials, one principal. Humans carry a signed session value; automation
carries a project-scoped token of which only a salted hash is stored. Both end
at :class:`Principal`, which carries the project it is scoped to - because
Section 4.3's isolation is a property of the caller, not a filter the handler
remembers to apply.
"""
from __future__ import annotations

import base64
import hashlib
import hmac
import json
import secrets
from dataclasses import dataclass
from datetime import datetime, timedelta, timezone

from sqlalchemy import select
from sqlalchemy.orm import Session

from . import db

READ_CERTIFICATES = "read_certificates"
DOWNLOAD_PROTOCOL = "download_protocol"
DOWNLOAD_RAW = "download_raw"
INGEST_PACKET = "ingest_packet"
START_REPLAY = "start_replay"
EDIT_POLICY = "edit_policy"
EXPORT_AUDIT = "export_audit"
MANAGE_MEMBERS = "manage_members"

CAPABILITIES = (READ_CERTIFICATES, DOWNLOAD_PROTOCOL, DOWNLOAD_RAW, INGEST_PACKET,
                START_REPLAY, EDIT_POLICY, EXPORT_AUDIT, MANAGE_MEMBERS)

#: Section 4.5, row by row. ``viewer`` downloads the protocol and digests only;
#: ``auditor`` reads within the project its grant names, which is why every
#: principal carries ``project_id``.
MATRIX: dict[str, frozenset[str]] = {
    "viewer": frozenset({READ_CERTIFICATES, DOWNLOAD_PROTOCOL}),
    "producer": frozenset({READ_CERTIFICATES, DOWNLOAD_PROTOCOL, DOWNLOAD_RAW, INGEST_PACKET,
                           START_REPLAY, EDIT_POLICY}),
    "compliance": frozenset({READ_CERTIFICATES, DOWNLOAD_PROTOCOL, DOWNLOAD_RAW, START_REPLAY,
                             EXPORT_AUDIT}),
    "admin": frozenset(CAPABILITIES),
    "auditor": frozenset({READ_CERTIFICATES, DOWNLOAD_PROTOCOL, DOWNLOAD_RAW, START_REPLAY,
                          EXPORT_AUDIT}),
}


class AuthError(Exception):
    """401: the caller is not identified."""


class Forbidden(Exception):
    """403: identified and not allowed. The API writes an audit row for it."""


@dataclass(frozen=True)
class Principal:
    actor: str
    role: str
    project_id: str
    org_id: str
    via: str

    def may(self, capability: str) -> bool:
        return allowed(self.role, capability)


def allowed(role: str, capability: str) -> bool:
    if capability not in CAPABILITIES:
        raise KeyError("unknown capability: %s" % capability)
    return capability in MATRIX.get(role, frozenset())


def require(principal: Principal, capability: str) -> None:
    if not principal.may(capability):
        raise Forbidden("%s may not %s" % (principal.role, capability))


def require_project(principal: Principal, project_id: str) -> None:
    if principal.project_id != project_id:
        raise Forbidden("this credential is scoped to another project")


def _utc(now: datetime | None = None) -> str:
    return (now or datetime.now(timezone.utc)).isoformat(timespec="microseconds")


def token_hash(secret: str, salt: str) -> str:
    return hashlib.sha256((salt + secret).encode("utf-8")).hexdigest()


def _role_and_org(session: Session, *, user_id: str, project_id: str) -> tuple[str, str]:
    project = session.get(db.Project, project_id)
    if project is None:
        raise AuthError("no such project")
    membership = session.get(db.Membership, (user_id, project.org_id))
    if membership is None:
        raise Forbidden("no membership in this project's organisation")
    return membership.role, project.org_id


def issue_token(session: Session, *, user_id: str, project_id: str, salt: str,
                scopes: tuple[str, ...] = (), secret: str | None = None,
                now: datetime | None = None) -> tuple[str, db.ApiToken]:
    """Returns the plaintext once; the row keeps only the hash."""
    plaintext = secret or secrets.token_urlsafe(32)
    row = db.ApiToken(user_id=user_id, project_id=project_id, hash=token_hash(plaintext, salt),
                      scopes=json.dumps(list(scopes)), created_at=_utc(now))
    session.add(row)
    session.flush()
    return plaintext, row


def principal_from_token(session: Session, token: str, *, salt: str,
                         now: datetime | None = None) -> Principal:
    if not token:
        raise AuthError("no token presented")
    row = session.scalar(select(db.ApiToken).where(db.ApiToken.hash == token_hash(token, salt)))
    if row is None:
        raise AuthError("unknown token")
    role, org_id = _role_and_org(session, user_id=row.user_id, project_id=row.project_id)
    row.last_used_at = _utc(now)
    return Principal(actor=row.user_id, role=role, project_id=row.project_id, org_id=org_id,
                     via="token")


def sign_session(secret_key: str, email: str, *, ttl_seconds: int = 8 * 3600,
                 now: datetime | None = None) -> str:
    expiry = int(((now or datetime.now(timezone.utc)) + timedelta(seconds=ttl_seconds)).timestamp())
    payload = "%s|%d" % (email, expiry)
    signature = hmac.new(secret_key.encode("utf-8"), payload.encode("utf-8"),
                         hashlib.sha256).hexdigest()
    return base64.urlsafe_b64encode(("%s|%s" % (payload, signature)).encode("utf-8")).decode("ascii")


def read_session(secret_key: str, value: str, *, now: datetime | None = None) -> str | None:
    """The email, or ``None``. A tampered or expired value is not an identity."""
    try:
        decoded = base64.urlsafe_b64decode(value.encode("ascii")).decode("utf-8")
        email, expiry, signature = decoded.rsplit("|", 2)
        expected = hmac.new(secret_key.encode("utf-8"), ("%s|%s" % (email, expiry)).encode("utf-8"),
                            hashlib.sha256).hexdigest()
        if not hmac.compare_digest(signature, expected):
            return None
        if int(expiry) <= int((now or datetime.now(timezone.utc)).timestamp()):
            return None
    except (ValueError, UnicodeDecodeError):
        return None
    return email


def principal_for_project(session: Session, *, email: str, project_id: str,
                          claims: dict | None = None) -> Principal:
    """A human's principal for one project.

    ``claims`` is the decoded session payload and only ``email`` is consulted:
    a role in there is not evidence, because the membership table is.
    """
    user = session.scalar(select(db.User).where(db.User.email == email))
    if user is None:
        raise AuthError("no such user")
    role, org_id = _role_and_org(session, user_id=user.id, project_id=project_id)
    return Principal(actor=email, role=role, project_id=project_id, org_id=org_id, via="session")


def record_audit(session: Session, *, actor: str, project_id: str | None, action: str,
                 target: str, outcome: str = "allowed",
                 now: datetime | None = None) -> db.AuditRow:
    row = db.AuditRow(actor=actor, project_id=project_id, action=action, target=target,
                      at=_utc(now), outcome=outcome)
    session.add(row)
    return row
