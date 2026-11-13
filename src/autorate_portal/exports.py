"""F5 — deterministic evidence bundles for auditors (PRD section 5, AC7).

Four rules make this a different kind of renderer from the web views:

* **Every line names its source.** A line carries the artefact path, its
  sha256, the protocol digest and the packet id. A line assembled without a
  source raises at build time (F5 rule 2); it is not emitted and patched later.
* **``known_limits`` is its own section and is not configurable away.** It is
  read verbatim from the packet's ``protocol.json``. A packet that publishes no
  ``known_limits`` key is refused, not exported with an empty section (F5
  rule 3).
* **Byte-identical output.** No clock, no locale, no caller-supplied ordering.
  The bundle's own sha256 is computed over the canonical payload and written
  into the document (F5 rule 4), so a reader can re-hash it a year later.
* **A stale source blocks the export.** A replay run whose stored ``exit_code``
  is the mismatch state blocks the bundle *before any line is assembled*, with
  that run's id (F5 exception (a), AC7): the source can stop re-deriving while
  an immutable packet's bytes stay intact. A byte-level digest mismatch is a
  second, independent trigger. When no replay run recorded a mismatch, that is
  stated plainly rather than a run id being invented.

A required heading with no source mapping emits ``no evidence published`` and
is *not* a line - that is F5 exception (b), the honest representation of a real
gap. Bundles are machine-readable JSON with fixed English headings: an export
is evidence, not a localized UI surface.
"""
from __future__ import annotations

import json
from dataclasses import dataclass
from typing import Any

from . import db, i18n
from .manifest import Manifest, canonical_bytes, sha256_bytes

KINDS = ("annex_iv", "iso_42001", "aap")
PROTOCOL_PATH = "protocol.json"
NO_EVIDENCE = "no evidence published"

#: Explicit heading -> published artefact path. Only paths in the packet's
#: artefact plan are named, and a heading whose source is absent from a packet
#: is reported as a gap rather than filled with a paraphrase of another file.
MAPPINGS: dict[str, tuple[tuple[str, str], ...]] = {
    "annex_iv": (
        ("system_description", "docs/REPORT.md"),
        ("risk_management", "docs/RESULTS.md"),
        ("data_governance", "data/inventory.md"),
        ("performance_metrics", "data/g1_feasibility.json"),
        ("validation_and_testing", "docs/VERIFICATION.md"),
        ("accuracy_robustness", "docs/SLICES.md"),
    ),
    "iso_42001": (
        ("context_and_scope", "docs/REPORT.md"),
        ("impact_assessment", "docs/AUDIT.md"),
        ("performance_evaluation", "data/resplit_200.json"),
        ("monitoring", "docs/VERIFICATION.md"),
        ("continual_improvement", "docs/ERRATA.md"),
    ),
    "aap": (
        ("claim", "protocol.json"),
        ("certificates", "data/cert_jev.json"),
        ("audit_evidence", "docs/AUDIT.md"),
        ("feasibility", "docs/FEASIBILITY.md"),
        ("slices", "data/slices_language.json"),
    ),
}


class ExportRefused(ValueError):
    """The bundle cannot be built honestly; nothing is emitted."""


@dataclass(frozen=True)
class Bundle:
    kind: str
    packet_id: str
    protocol_digest: str
    known_limits: tuple[str, ...]
    lines: tuple[dict[str, str], ...]
    gaps: tuple[str, ...]
    blocked: bool = False
    block_reason: str = ""
    run_id: str = ""
    bundle_sha256: str = ""
    raw: bytes = b""

    def as_dict(self) -> dict[str, Any]:
        return {"kind": self.kind, "packet_id": self.packet_id,
                "protocol_digest": self.protocol_digest,
                "known_limits": list(self.known_limits),
                "lines": [dict(line) for line in self.lines],
                "gaps": list(self.gaps), "blocked": self.blocked,
                "block_reason": self.block_reason, "run_id": self.run_id,
                "bundle_sha256": self.bundle_sha256}


def _line(*, heading: str, path: str, digest: str, protocol_digest: str,
          packet_id: str) -> dict[str, str]:
    """F5 rule 2: a line without its full source quadruple fails the build."""
    missing = [name for name, value in (("source_path", path), ("sha256", digest),
                                        ("protocol_digest", protocol_digest),
                                        ("packet_id", packet_id)) if not value]
    if missing:
        raise ExportRefused("a bundle line for %s has no %s" % (heading, ", ".join(missing)))
    return {"heading": heading, "source_path": path, "sha256": digest,
            "protocol_digest": protocol_digest, "packet_id": packet_id}


def _known_limits(files: dict[str, bytes]) -> tuple[str, ...]:
    try:
        protocol = json.loads(files[PROTOCOL_PATH].decode("utf-8"))
    except (KeyError, ValueError, UnicodeDecodeError) as exc:
        raise ExportRefused("protocol.json is unreadable: %s" % exc) from exc
    limits = protocol.get("known_limits")
    if not isinstance(limits, list) or not limits or not all(isinstance(x, str) for x in limits):
        raise ExportRefused("protocol.json publishes no known_limits array; "
                            "the section cannot be omitted from a bundle")
    return tuple(limits)


def replay_mismatch_run(session, packet) -> str | None:
    """AC7 / F5 exception (a): the replay run that showed the mismatch.

    This is the *trigger*, not a label. A replay can record that the source no
    longer re-derives while the stored bytes stay intact - an immutable packet
    is exactly that case - so a digest-only check would let the export through.
    ``exit_code == 4`` is the engine's recorded mismatch/refusal state; nothing
    here computes a bound or re-runs the replay.
    """
    if session is None or packet is None:
        return None
    statement = (db.select(db.Run.id)
                 .where(db.Run.packet_id_in == packet.id, db.Run.exit_code == 4)
                 .order_by(db.Run.started_at.desc()))
    row = session.scalars(statement).first()
    return str(row) if row else None


def mismatch_run_id(session, packet, locale: str = i18n.DEFAULT_LOCALE) -> str:
    """AC7: name the replay run that showed the mismatch, or say there is none."""
    found = replay_mismatch_run(session, packet)
    return found if found else i18n.t(locale, "msg.no_run_row")


def build_bundle(*, kind: str, manifest: Manifest, packet, files: dict[str, bytes],
                 session=None, locale: str = i18n.DEFAULT_LOCALE) -> Bundle:
    """Build one bundle. Refusals return a blocked Bundle, never partial bytes."""
    if kind not in KINDS:
        raise ExportRefused("unknown bundle kind %r (kinds: %s)" % (kind, ", ".join(KINDS)))
    limits = _known_limits(files)
    declared = {artefact.path: artefact for artefact in manifest.artifacts}
    protocol_digest = packet.protocol_digest
    packet_id = manifest.packet_id

    # F5 exception (a) / AC7: a replay that recorded a mismatch is the trigger.
    # Checked before any line is assembled, so a stored packet whose bytes are
    # still intact cannot be exported after its source stopped re-deriving.
    replay = replay_mismatch_run(session, packet)
    if replay:
        return Bundle(kind, packet_id, protocol_digest, limits, (), (),
                      blocked=True,
                      block_reason=i18n.t(locale, "msg.export_blocked_replay",
                                          run_id=replay),
                      run_id=replay)

    lines: list[dict[str, str]] = []
    gaps: list[str] = []
    blocked = False
    block_reason = ""
    run_id = ""

    for heading, path in MAPPINGS[kind]:
        artefact = declared.get(path)
        if artefact is None or path not in files:
            gaps.append(heading)
            continue
        actual = sha256_bytes(files[path])
        if actual != artefact.sha256:
            run_id = mismatch_run_id(session, packet, locale)
            block_reason = i18n.t(locale, "msg.export_blocked", path=path, run_id=run_id)
            blocked = True
            break
        lines.append(_line(heading=heading, path=path, digest=artefact.sha256,
                           protocol_digest=protocol_digest, packet_id=packet_id))

    if blocked:
        return Bundle(kind, packet_id, protocol_digest, limits, (), tuple(gaps),
                      blocked=True, block_reason=block_reason, run_id=run_id)

    payload: dict[str, Any] = {
        "kind": kind,
        "packet_id": packet_id,
        "protocol_digest": protocol_digest,
        "known_limits": list(limits),
        "known_limits_note": "known_limits is rendered as its own section and cannot be omitted",
        "lines": lines,
        "gaps": [{"heading": heading, "state": NO_EVIDENCE} for heading in gaps],
    }
    digest = sha256_bytes(canonical_bytes(payload))
    payload["bundle_sha256"] = digest
    raw = (json.dumps(payload, sort_keys=True, separators=(",", ":"),
                      ensure_ascii=False, indent=2) + "\n").encode("utf-8")
    return Bundle(kind, packet_id, protocol_digest, limits, tuple(lines), tuple(gaps),
                  bundle_sha256=digest, raw=raw)


def recheck(raw: bytes) -> str:
    """Recompute a bundle's own hash; a reader can verify it without the portal."""
    document = json.loads(raw.decode("utf-8"))
    declared = document.pop("bundle_sha256", "")
    computed = sha256_bytes(canonical_bytes(document))
    if computed != declared:
        raise ExportRefused("bundle hash does not match its payload")
    return computed
