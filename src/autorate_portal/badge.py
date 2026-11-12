"""badge-as-shareable (PRD 7 M4, F8 rule 3, section 8.4, F9 rule 4b).

The frozen repository's M0 badge already has a closed, honest vocabulary:
``certified``, ``not-certifiable``, ``drift``, ``not-run`` — never a boolean.
M4 makes that badge **shareable**: a self-contained JSON record plus SVG built
only from a packet's published fields, so the holder can pass it to a P3 reader
without the producing organisation being present.

Four constraints are structural rather than stylistic:

* **Zero records rows.** Only certificate/document/protocol metadata is read;
  a records artefact path appearing in the output is a refusal (section 8.4).
* **``unverified_provenance`` travels with the shareable copy** (F9 exception
  (b)): a share that loses the badge would look more certified than its source.
* **The state is text, not a hue alone** (section 11 accessibility): state
  words differ, and the SVG prints the word.
* **No network call and no publish action.** Producing a shareable artefact is
  not the irreversible public exposure that carve-out (a) holds; F9's share
  link and expiry remain M5.

The state is read from the certificate summaries, never computed: a packet
whose certificates all refuse is ``not-certifiable`` even when ``verify``
re-derived every published value. ``drift`` and ``not-run`` are named states
in the vocabulary but are not guessed from a missing replay.
"""
from __future__ import annotations

import json
from dataclasses import dataclass
from typing import Any

from . import db, emit, i18n
from .manifest import Manifest, canonical_bytes, sha256_bytes

STATES = ("certified", "not-certifiable", "drift", "not-run")
CERTIFIED, NOT_CERTIFIABLE, DRIFT, NOT_RUN = STATES

FILL = {"certified": "#1a7f37", "not-certifiable": "#9a6700",
        "drift": "#cf222e", "not-run": "#6e7781"}


class BadgeRefused(ValueError):
    pass


@dataclass(frozen=True)
class ShareableBadge:
    state: str
    packet_id: str
    protocol_digest: str
    denominator_line: str
    provenance_badge: str
    record: dict[str, Any]
    raw: bytes
    svg: str

    def as_dict(self) -> dict[str, Any]:
        return dict(self.record)


def state_for(summaries: list[db.CertificateSummary]) -> str:
    """Read the verdict off the certificates; never infer a greener one."""
    if not summaries:
        return NOT_RUN
    if any(row.feasible is True and row.autorate is not None for row in summaries):
        return CERTIFIED
    if all(row.feasible is False for row in summaries):
        return NOT_CERTIFIABLE
    return NOT_RUN


def _svg(state: str, value: str) -> str:
    left = "autorate gate"
    width_left, width_right = 96, max(80, 10 * len(state) + 16)
    width = width_left + width_right
    return ('<svg xmlns="http://www.w3.org/2000/svg" width="%d" height="20" role="img" '
            'aria-label="autorate gate: %s">'
            '<title>autorate gate: %s</title>'
            '<rect width="%d" height="20" fill="#57606a"/>'
            '<rect x="%d" width="%d" height="20" fill="%s"/>'
            '<g fill="#fff" font-family="Verdana,sans-serif" font-size="11" '
            'text-anchor="middle"><text x="%d" y="14">%s</text>'
            '<text x="%d" y="14">%s</text></g></svg>'
            % (width, emit.e(state), emit.e(state), width_left, width_left,
               width_right, FILL[state], width_left // 2, emit.e(left),
               width_left + width_right // 2, emit.e(state)))


def shareable_badge(*, manifest: Manifest, packet, summaries: list[db.CertificateSummary],
                    provenance_badge: str = "") -> ShareableBadge:
    """Deterministic JSON + SVG, with no records content and no clock."""
    state = state_for(summaries)
    if state not in STATES:
        raise BadgeRefused("state %r is outside F8's closed vocabulary" % state)

    denominator_line = "re-derived %s values" % manifest.expected_rederived
    parts = [part.strip() for part in manifest.expected_rederived.split("/")]
    record: dict[str, Any] = {
        "state": state,
        "packet_id": manifest.packet_id,
        "protocol_digest": packet.protocol_digest,
        "denominator": parts,
        "denominator_line": denominator_line,
        "provenance_badge": provenance_badge or None,
        "records_included": False,
        "records_rows": 0,
        "state_meaning": ("F8's closed vocabulary; %s is a text state, not a boolean"
                          % state),
        "certificate_states": sorted({("certified" if row.feasible is True else
                                       "refusal" if row.feasible is False else "unavailable")
                                      for row in summaries}),
    }

    # Section 8.4: a shareable copy must not carry records artefacts. Naming
    # the *excluded* records is required (F9 rule 4b), so that one field is
    # exempt from the leak check; a records path anywhere else is a refusal.
    inspectable = {key: value for key, value in record.items()
                   if key != "excluded_records"}
    leaked = sorted({artefact.path for artefact in manifest.artifacts
                     if artefact.kind == "records" and
                     artefact.path in json.dumps(inspectable, ensure_ascii=False)})
    if leaked:
        raise BadgeRefused("records artefacts reached the shareable badge: %s"
                           % ", ".join(leaked))
    record["excluded_records"] = list(manifest.excluded_records)
    if manifest.records_excluded and not manifest.excluded_records:
        raise BadgeRefused("records_excluded is true but no record is named")

    digest = sha256_bytes(canonical_bytes(record))
    record["badge_sha256"] = digest
    raw = (json.dumps(record, sort_keys=True, separators=(",", ":"),
                      ensure_ascii=False, indent=2) + "\n").encode("utf-8")
    svg = _svg(state, manifest.expected_rederived)
    return ShareableBadge(state, manifest.packet_id, packet.protocol_digest,
                          denominator_line, provenance_badge, record, raw, svg)


def state_label(locale: str, state: str) -> str:
    """F8's vocabulary is a machine value; its catalog entry is identical in
    both languages so a localized screen cannot invent a fifth state."""
    key = "badge.%s" % state
    if key not in i18n.CATALOG.get(i18n.locale_or_raise(locale), {}):
        raise BadgeRefused("unknown badge state %r" % state)
    return i18n.t(locale, key)
