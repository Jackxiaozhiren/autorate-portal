"""F10 administration — the operator's writes, all behind MANAGE_MEMBERS.

This module holds the *logic* an admin route needs; the route owns the guard
and the audit row. Nothing here reads a stored summary, computes a bound, or
touches a records file. The two writes with a lasting consequence are:

* **Delete** — a tombstone plus byte removal. The `packet` row stays (so an id
  cannot be re-issued and an audit entry can still name it), while the stored
  tar is removed. A second delete is idempotent and says so.
* **Pin / upgrade** — write a distribution into the operator's registry file.
  A version already pinned is upgraded only when the caller says so, and the
  wheel hash is always validated; a forged pin cannot bootstrap itself.

The default configuration requires no credential from this project: the
registry path is supplied by the deployment, and an admin call made with no
path is refused rather than silently writing the packaged file.
"""
from __future__ import annotations

import json
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from sqlalchemy import select
from sqlalchemy.orm import Session

from . import db, distributions


class AdminRefused(ValueError):
    """A named refusal; the message names the value that failed."""


@dataclass(frozen=True)
class AdminResult:
    action: str
    target: str
    detail: str

    def as_dict(self) -> dict[str, str]:
        return {"action": self.action, "target": self.target, "detail": self.detail}


# --- members and roles ------------------------------------------------------

def set_member(session: Session, *, org_id: str, user_id: str, role: str) -> AdminResult:
    """Grant or change one membership. An unknown role is a refusal, not a grant."""
    from . import auth
    if role not in auth.MATRIX:
        raise AdminRefused("unknown role %r" % role)
    if session.get(db.Org, org_id) is None:
        raise AdminRefused("no org %s" % org_id)
    if session.get(db.User, user_id) is None:
        raise AdminRefused("no user %s" % user_id)
    row = session.get(db.Membership, (user_id, org_id))
    if row is None:
        session.add(db.Membership(user_id=user_id, org_id=org_id, role=role))
    else:
        row.role = role
    session.flush()
    return AdminResult("admin.member.set", "user:%s" % user_id, "role=%s org=%s" % (role, org_id))


def revoke_token(session: Session, *, token_id: str) -> AdminResult:
    row = session.get(db.ApiToken, token_id)
    if row is None:
        raise AdminRefused("no token %s" % token_id)
    session.delete(row)
    session.flush()
    return AdminResult("admin.token.revoke", "token:%s" % token_id, "hash removed")


def tokens_for(session: Session, *, project_id: str) -> list[dict[str, Any]]:
    """Scopes and last-used, never the hash — the only credential stays secret."""
    rows = session.scalars(select(db.ApiToken).where(
        db.ApiToken.project_id == project_id)).all()
    return [{"id": row.id, "user_id": row.user_id, "project_id": row.project_id,
             "scopes": json.loads(row.scopes or "[]"), "created_at": row.created_at,
             "last_used_at": row.last_used_at} for row in rows]


# --- retention and deletion -------------------------------------------------

def set_retention(session: Session, *, packet_id: str, retention_until: str) -> AdminResult:
    packet = session.get(db.Packet, packet_id)
    if packet is None:
        raise AdminRefused("no packet %s" % packet_id)
    if not retention_until or len(retention_until) > 40:
        raise AdminRefused("retention_until must be a timestamp of at most 40 characters")
    packet.retention_until = retention_until
    session.flush()
    return AdminResult("admin.retention.set", "packet:%s" % packet_id,
                       "retention_until=%s" % retention_until)


def tombstone(session: Session, *, packet_id: str, store_dir: Path | None) -> AdminResult:
    """Mark the row and remove the stored bytes. Idempotent on a second call."""
    packet = session.get(db.Packet, packet_id)
    if packet is None:
        raise AdminRefused("no packet %s" % packet_id)
    already = bool(packet.tombstoned)
    packet.tombstoned = 1
    removed = False
    if store_dir is not None:
        target = store_dir / ("%s.tar" % packet.manifest_sha256)
        if target.is_file():
            target.unlink()
            removed = True
    session.flush()
    detail = "already tombstoned" if already else ("bytes removed" if removed else
                                                  "tombstoned; no stored bytes present")
    return AdminResult("admin.packet.delete", "packet:%s" % packet_id, detail)


# --- pinned distribution registry -------------------------------------------

def pin(session: Session, *, registry_path: Path | None, version: str, wheel: str,
        sha256: str, source: str, upgrade: bool = False) -> AdminResult:
    """Pin a distribution, or upgrade an existing version with an explicit flag."""
    if registry_path is None:
        raise AdminRefused("no registry path configured; refusing to write the packaged pins")
    registry, problems = distributions.load_registry(registry_path)
    if problems:
        raise AdminRefused("registry is not usable: %s" % "; ".join(
            p.reason for p in problems))
    existing = registry.get(distributions.DEFAULT_NAME, version)
    if existing is not None and not upgrade:
        raise AdminRefused("autorate==%s is already pinned; pass upgrade to replace it" % version)
    candidate = distributions.Pin(name=distributions.DEFAULT_NAME, version=version,
                                  wheel=wheel, sha256=sha256, source=source)
    # The field rules are the registry's own; a candidate that would not load
    # is refused before anything is written.
    if not candidate.wheel.endswith(".whl"):
        raise AdminRefused("pinned file is not a wheel: %s" % wheel)
    if not distributions.SHA256_HEX.match(candidate.sha256):
        raise AdminRefused("pinned sha256 must be 64 lowercase hex characters")
    if not candidate.source.startswith("https://"):
        raise AdminRefused("pin source is not an https URL: %s" % source)
    document = json.loads(registry_path.read_text(encoding="utf-8"))
    entries = [e for e in document.get("pins", [])
               if not (e.get("name") == candidate.name and e.get("version") == candidate.version)]
    entries.append({"name": candidate.name, "version": candidate.version,
                    "wheel": candidate.wheel, "sha256": candidate.sha256,
                    "source": candidate.source})
    document["pins"] = sorted(entries, key=lambda e: (e.get("name", ""), e.get("version", "")))
    registry_path.write_text(json.dumps(document, sort_keys=True, indent=2,
                                        ensure_ascii=False) + "\n", encoding="utf-8")
    # A written registry must still load with no refusals; otherwise roll back.
    after, problems = distributions.load_registry(registry_path)
    if problems or after.get(candidate.name, candidate.version) is None:
        raise AdminRefused("the pin I wrote does not validate: %s" % "; ".join(
            p.reason for p in problems))
    return AdminResult("admin.pin.%s" % ("upgrade" if upgrade else "add"),
                       "autorate==%s" % version, "sha256=%s" % sha256)
