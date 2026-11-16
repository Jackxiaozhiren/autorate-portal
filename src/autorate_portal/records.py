"""AC12: new records may not reuse a case id the calibration pool already holds.

Why this is a refusal rather than a warning: `autorate`'s split is seeded, and
its key is the case id. Re-using an id does not add a case - it moves an existing
case between the two halves of the split, which re-rolls the seeded split and
therefore changes published bounds without any file looking wrong. A portal that
accepted that would be distributing numbers that no longer re-derive.

The check is deliberately conservative: the id space is the **project's**, not
per backend and not per file, because the certificate a reader is looking at was
computed from a pool whose key domain is exactly that space.

Nothing here computes a bound. It reads `case_id` strings, compares them, and
either stores the bytes beside the packet store or refuses with the collision and
its consequence named.
"""
from __future__ import annotations

import json
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Iterable

from . import auth
from .manifest import sha256_bytes

STATE_ACCEPTED = "accepted"
STATE_REFUSED = "collision"
SPLIT_CONSEQUENCE = ("a shared case id re-rolls the seeded split, and a re-rolled split changes "
                     "published bounds without changing any file's bytes")


class RecordsError(ValueError):
    """The upload is not a records file at all."""


@dataclass(frozen=True)
class Collision:
    case_id: str
    path: str            # the pool artefact that already holds the id
    incoming: str        # the uploaded file's name

    def sentence(self) -> str:
        return ("%s: case id %r already belongs to the calibration pool in %s; %s"
                % (self.incoming, self.case_id, self.path, SPLIT_CONSEQUENCE))


@dataclass(frozen=True)
class RecordsResult:
    state: str
    accepted: bool
    path: str
    case_ids: tuple[str, ...] = ()
    collisions: tuple[Collision, ...] = ()
    stored_as: str = ""
    digest: str = ""
    notes: tuple[str, ...] = field(default_factory=tuple)

    def as_dict(self) -> dict[str, Any]:
        return {"state": self.state, "accepted": self.accepted, "path": self.path,
                "rows": len(self.case_ids), "case_ids": len(set(self.case_ids)),
                "collisions": [{"case_id": c.case_id, "pool": c.path,
                                "incoming": c.incoming} for c in self.collisions],
                "stored_as": self.stored_as, "sha256": self.digest,
                "notes": list(self.notes),
                "consequence": SPLIT_CONSEQUENCE if self.collisions else ""}


def parse_records(data: bytes, path: str) -> list[dict[str, Any]]:
    """One JSON object per non-blank line; a line without `case_id` is an error."""
    rows: list[dict[str, Any]] = []
    for number, line in enumerate(data.decode("utf-8").splitlines(), 1):
        if not line.strip():
            continue
        try:
            row = json.loads(line)
        except ValueError as exc:
            raise RecordsError("%s line %d is not JSON: %s" % (path, number, exc)) from exc
        if not isinstance(row, dict):
            raise RecordsError("%s line %d is not a JSON object" % (path, number))
        case_id = row.get("case_id")
        if case_id in (None, ""):
            raise RecordsError("%s line %d publishes no case_id" % (path, number))
        rows.append(row)
    if not rows:
        raise RecordsError("%s holds no records" % path)
    return rows


def pool_index(files: dict[str, bytes], manifest) -> dict[str, str]:
    """case_id -> the packet artefact that already holds it."""
    index: dict[str, str] = {}
    for artefact in manifest.artifacts:
        if artefact.kind != "records" or artefact.path not in files:
            continue
        for row in parse_records(files[artefact.path], artefact.path):
            index.setdefault(str(row["case_id"]), artefact.path)
    return index


def collisions(rows: Iterable[dict[str, Any]], index: dict[str, str],
               incoming: str) -> tuple[Collision, ...]:
    found: dict[str, Collision] = {}
    for row in rows:
        case_id = str(row["case_id"])
        if case_id in index:
            found.setdefault(case_id, Collision(case_id=case_id, path=index[case_id],
                                                incoming=incoming))
    return tuple(found[key] for key in sorted(found))


def ingest_records(session, *, project_id: str, actor: str, path: str, data: bytes,
                   files: dict[str, bytes], manifest, store_dir: Path) -> RecordsResult:
    """Refuse on a collision; otherwise store the bytes and write one audit row.

    The stored copy is content-addressed beside the packet store, so two uploads
    of the same bytes are one file and an operator can audit what the monitor
    lane was given. No certificate summary is read or written.
    """
    rows = parse_records(data, path)
    index = pool_index(files, manifest)
    found = collisions(rows, index, path)
    if found:
        auth.record_audit(session, actor=actor, project_id=project_id,
                        action="records.ingest", target="records:%s" % path,
                        outcome="denied")
        session.flush()
        return RecordsResult(state=STATE_REFUSED, accepted=False, path=path,
                             case_ids=tuple(str(row["case_id"]) for row in rows),
                             collisions=found)

    digest = sha256_bytes(data)
    target = Path(store_dir) / "records"
    target.mkdir(parents=True, exist_ok=True)
    stored = target / ("%s.jsonl" % digest)
    if not stored.exists():
        stored.write_bytes(data)
    auth.record_audit(session, actor=actor, project_id=project_id, action="records.ingest",
                    target="records:%s" % stored.name, outcome="allowed")
    session.flush()
    distinct = len({str(row["case_id"]) for row in rows})
    notes = ([] if distinct == len(rows) else
             ["%d rows carry %d distinct case ids; the repeat is the artefact's own"
              % (len(rows), distinct)])
    return RecordsResult(state=STATE_ACCEPTED, accepted=True, path=path,
                         case_ids=tuple(str(row["case_id"]) for row in rows),
                         stored_as=str(stored), digest=digest, notes=tuple(notes))
