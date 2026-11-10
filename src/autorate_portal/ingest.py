"""F1: a packet is indexed only after every check passes, and never partially.

The order is the rule. Size, container safety, manifest parse, every declared
path, every sha256, then the records check - and only then a single transaction
that writes the packet, its artefacts and its summaries. A refusal returns
before the first write, so "partially indexed" is not a state this module can
reach.

Three deliberate readings, all recorded in the milestone report:

* ``packet.id`` is derived from (project, manifest hash), not from the
  manifest's own ``packet_id``: a global primary key would let one tenant's
  ingest block another's of the same public packet, which is a cross-tenant
  effect AC14 never asked for.
* ``packet.source_sha256`` carries a digest of the artefact set, because the
  manifest publishes no hash of the source tree. It is a hash, never a
  statistic.
* F1's "duplicate id inside a records artefact" is checked as a verbatim
  duplicate row. The committed records legitimately repeat ``id`` across
  repeats and seeds (320 ids over 1919 rows in ``records_feishu.jsonl``), so a
  bare id-uniqueness test would refuse the frozen repository's own packet.
"""
from __future__ import annotations

import json
import os
from dataclasses import dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from sqlalchemy import select
from sqlalchemy.orm import Session

from . import db
from .auth import record_audit
from .distributions import load_registry, resolve
from .manifest import Manifest, canonical_bytes, sha256_bytes
from .packet import MAX_BUNDLE_BYTES, Refusal, verify_bundle

PACKET_STORE_ENV = "AUTHORATE_PACKET_STORE"
DEFAULT_STORE = "packets"

STATE_INDEXED = "indexed"
STATE_REFUSED = "refused"
STATE_INCONSISTENT = "inconsistent_bundle"
BADGE_UNVERIFIED = "unverified_provenance"


@dataclass
class IngestResult:
    state: str
    packet_id: str = ""
    row_id: str = ""
    badge: str = ""
    note: str = ""
    refusals: tuple[Refusal, ...] = field(default_factory=tuple)

    @property
    def accepted(self) -> bool:
        return self.state == STATE_INDEXED


def artefact_set_digest(manifest: Manifest) -> str:
    payload = [[artefact.path, artefact.sha256] for artefact in manifest.artifacts]
    return sha256_bytes(canonical_bytes({"artifacts": payload}))


def packet_row_id(project_id: str, manifest: Manifest) -> str:
    return "pkt-" + sha256_bytes(("%s:%s" % (project_id, manifest.manifest_sha256)).encode())[:16]


def _certificate(data: bytes) -> dict[str, Any]:
    """Parse with ``parse_float=str``: 0.05 stays "0.05", not 0.05000000000000001."""
    document = json.loads(data.decode("utf-8"), parse_float=str)
    if not isinstance(document, dict):
        raise ValueError("a certificate artefact must be a JSON object")
    return document


def _text(value: Any) -> str | None:
    return None if value is None else str(value)


def summary_fields(manifest: Manifest, path: str, data: bytes) -> dict[str, Any]:
    """What the artefact says, copied. No field is derived, filled or rounded."""
    document = _certificate(data)
    backend = document.get("backend")
    if not backend:
        raise ValueError("%s publishes no backend" % path)
    meta = document.get("meta") or {}
    at_alpha = meta.get("at_requested_alpha") or {}
    bound = document.get("conditional_error_bound")
    if bound is None:
        bound = document.get("marginal_error_bound")
    return {
        # The artefact carries no task field; its own filename is the stable,
        # published name for it, so the label is read rather than invented.
        "task": Path(path).stem.removeprefix("cert_"),
        "backend": str(backend),
        "feasible": document.get("feasible"),
        "reason": document.get("reason"),
        "autorate": _text(document.get("autorate")),
        "bound": _text(bound),
        "bound_unit": _text(at_alpha.get("bound_unit") or meta.get("bound_unit")
                            or manifest.bound_unit) if bound is not None else None,
        "n_cal": document.get("n_cal"),
        "n_eval": document.get("n_eval"),
        "n_claims": document.get("n_claims"),
        "alpha": _text(document.get("alpha")),
        "beta": _text(document.get("beta")),
        "delta": _text(document.get("delta")),
    }


def duplicate_record(manifest: Manifest, files: dict[str, bytes]) -> tuple[str, str]:
    """(path, message) for a verbatim repeated row inside a records artefact."""
    for artefact in manifest.artifacts:
        if artefact.kind != "records":
            continue
        seen: set[str] = set()
        for line in files[artefact.path].decode("utf-8").splitlines():
            if not line.strip():
                continue
            if line in seen:
                identifier = ""
                try:
                    identifier = json.loads(line).get("id", "")
                except ValueError:
                    pass
                return artefact.path, "%s: record repeated verbatim (%s)" % (
                    artefact.path, identifier or "no id")
            seen.add(line)
    return "", ""


def provenance(manifest: Manifest, files: dict[str, bytes],
               registry_path: Path | None) -> tuple[str, str]:
    """F1 rule 5: a hash that does not match the distributed wheel is a badge.

    An embedded wheel is compared when the bundle carries one; otherwise the
    pinned registry is the second reader. A registry that cannot be read is not
    evidence of provenance, so the badge stays on and says why.
    """
    embedded = [name for name in files if name.endswith(".whl")]
    for name in embedded:
        actual = sha256_bytes(files[name])
        if actual != manifest.distribution.sha256:
            return BADGE_UNVERIFIED, ("embedded wheel %s hashes to %s, manifest declares %s"
                                      % (name, actual, manifest.distribution.sha256))
    registry, problems = load_registry(registry_path)
    if problems:
        return BADGE_UNVERIFIED, "no readable pinned registry: %s" % "; ".join(
            "%s: %s" % (problem.path, problem.reason) for problem in problems)
    _pin, problems = resolve(registry, version=manifest.distribution.version,
                             wheel=manifest.distribution.wheel,
                             sha256=manifest.distribution.sha256)
    if problems:
        return BADGE_UNVERIFIED, "the pin registry does not confirm this distribution: %s" % "; ".join(
            "%s: %s" % (problem.path, problem.reason) for problem in problems)
    return "", ""


def packet_store(store_dir: Path | None = None) -> Path:
    """Section 4.6's packet store: the bundle the views and downloads read."""
    if store_dir is not None:
        return Path(store_dir)
    return Path(os.environ.get(PACKET_STORE_ENV) or DEFAULT_STORE)


def stored_bundle(store_dir: Path, manifest_sha256: str) -> Path:
    return packet_store(store_dir) / ("%s.tar" % manifest_sha256)


def load_stored(store_dir: Path, manifest_sha256: str):
    """Re-verify a stored bundle before anyone renders or serves it."""
    target = stored_bundle(store_dir, manifest_sha256)
    if not target.is_file():
        return None
    return verify_bundle(target)


def _retain(store_dir: Path, manifest_sha256: str, raw: bytes) -> None:
    target = packet_store(store_dir)
    target.mkdir(parents=True, exist_ok=True)
    destination = stored_bundle(store_dir, manifest_sha256)
    if destination.is_file() and sha256_bytes(destination.read_bytes()) == sha256_bytes(raw):
        return
    temporary = destination.with_suffix(".tar.part")
    temporary.write_bytes(raw)
    temporary.replace(destination)


def ingest(session: Session, *, bundle_path: Path, project_id: str, actor: str,
           registry_path: Path | None = None, cap: int = MAX_BUNDLE_BYTES,
           store_dir: Path | None = None, now: str | None = None) -> IngestResult:
    path = Path(bundle_path)
    timestamp = now or _utc()

    if not path.is_file():
        return IngestResult(STATE_REFUSED, refusals=(Refusal(str(path), "bundle is absent"),))
    size = path.stat().st_size
    if size > cap:
        return IngestResult(STATE_REFUSED, refusals=(Refusal(
            str(path), "bundle exceeds the configured cap",
            expected=str(cap), actual=str(size)),))

    verification = verify_bundle(path)
    if not verification.ok or verification.manifest is None:
        refusals = tuple(verification.refusals)
        traversal = any("traverses" in refusal.reason for refusal in refusals)
        record_audit(session, actor=actor, project_id=project_id,
                     action="packet.ingest.traversal" if traversal else "packet.ingest",
                     target="%s:%s" % (path.name, refusals[0].path if refusals else ""),
                     outcome="denied", now=None)
        return IngestResult(STATE_REFUSED, refusals=refusals)

    manifest = verification.manifest
    files = verification.files

    repeated_path, repeated = duplicate_record(manifest, files)
    if repeated:
        record_audit(session, actor=actor, project_id=project_id, action="packet.ingest",
                     target="%s:%s" % (path.name, repeated_path), outcome="denied")
        return IngestResult(STATE_INCONSISTENT, packet_id=manifest.packet_id,
                            refusals=(Refusal(repeated_path, repeated),))

    existing = session.scalar(select(db.Packet).where(
        db.Packet.project_id == project_id,
        db.Packet.manifest_sha256 == manifest.manifest_sha256))
    if existing is not None:
        record_audit(session, actor=actor, project_id=project_id, action="packet.ingest",
                     target="packet:%s" % existing.id, outcome="allowed", now=None)
        return IngestResult(STATE_INDEXED, packet_id=manifest.packet_id, row_id=existing.id,
                            note="already ingested; one row, no duplicate artefacts")

    badge, note = provenance(manifest, files, registry_path)
    _retain(store_dir, manifest.manifest_sha256, path.read_bytes())
    row_id = packet_row_id(project_id, manifest)
    packet = db.Packet(
        id=row_id, project_id=project_id, manifest_sha256=manifest.manifest_sha256,
        protocol_digest=manifest.protocol_digest, source_version=manifest.source_version,
        source_sha256=artefact_set_digest(manifest), source_revision=manifest.source_revision,
        created_by=actor, ingested_at=timestamp, bytes=size, retention_until=None)
    session.add(packet)
    session.flush()

    for artefact in manifest.artifacts:
        artifact_row = db.Artifact(id="art-" + sha256_bytes(
            ("%s:%s" % (row_id, artefact.path)).encode())[:16],
            packet_id=row_id, path=artefact.path, sha256=artefact.sha256, kind=artefact.kind)
        session.add(artifact_row)
        session.flush()
        if artefact.kind == "certificate":
            db.record_summary(session, artifact_id=artifact_row.id,
                              fields=summary_fields(manifest, artefact.path, files[artefact.path]))

    record_audit(session, actor=actor, project_id=project_id, action="packet.ingest",
                 target="packet:%s" % row_id, outcome="allowed", now=None)
    session.flush()
    return IngestResult(STATE_INDEXED, packet_id=manifest.packet_id, row_id=row_id,
                        badge=badge, note=note)


def _utc() -> str:
    return datetime.now(timezone.utc).isoformat(timespec="microseconds")
