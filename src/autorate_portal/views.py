"""F2 and F3: what the portal shows, and what it refuses to show.

Three rules shape this module more than the layout does.

* A refusal is a verdict, not an empty result. Its reason is printed verbatim
  from the artefact, and the panel carries no number at all - so no ``0`` can
  appear where the artefact said "no certificate exists".
* A number reaches the document only through :func:`emit.statistic`, which
  refuses without its denominator, budget, packet and unit. A refusal here
  becomes ``unavailable: <component>``, never a number with a blank beside it.
* Nothing here computes. Slices are read, counted and sorted; a correction is
  displayed only if the artefact states one, and independence is printed only
  if the artefact states it.
"""
from __future__ import annotations

from dataclasses import dataclass
from typing import Any

from . import db
from .emit import EmitRefused, components_for, e, statistic

ABSENT_NUMBER = "not published by this certificate"
NO_SLICE_EVIDENCE = "no_slice_evidence"
INDEPENDENCE_UNKNOWN = "independence not established"
DISCLOSURE = "selected on the evaluation half; nothing on it was certified"
SLICE_CAP = 20

REFUSAL = "refusal"
CERTIFIED = "certified"
UNAVAILABLE = "unavailable"


@dataclass(frozen=True)
class Panel:
    title: str
    state: str
    reason: str
    body: str
    numbers: tuple[dict[str, Any], ...] = ()

    def html(self) -> str:
        return ('<section class="panel" data-state="%s"><h2>%s</h2>'
                '<p class="state">%s</p>%s</section>'
                % (e(self.state), e(self.title), e(self.reason or self.state), self.body))


def _number(label: str, value: Any, components: dict[str, Any], *, struck: bool = False) -> tuple[dict, str]:
    try:
        markup = statistic(label=label, value=value, values=components)
    except EmitRefused as exc:
        missing = ", ".join(exc.missing)
        return ({"label": label, "value": None, "missing": exc.missing},
                '<p class="unavailable">%s: unavailable: %s</p>' % (e(label), e(missing)))
    if struck:
        markup = '<div class="struck"><s>%s</s></div>' % markup
    return {"label": label, "value": str(value), "missing": []}, markup


def _banner(mismatch: tuple[str, str]) -> str:
    return ('<p class="banner provenance-mismatch">provenance mismatch: stored digest %s, '
            'replay digest %s - the number below is struck through</p>'
            % (e(mismatch[0]), e(mismatch[1])))


def certificate_panel(*, summary: db.CertificateSummary, packet: db.Packet,
                      rubric: dict[str, Any] | None, certificate: dict[str, Any],
                      mismatch: tuple[str, str] | None = None) -> Panel:
    components = components_for(n_cal=summary.n_cal, n_eval=summary.n_eval, rubric=rubric,
                                packet_id=certificate.get("packet_id") or packet.id,
                                protocol_digest=packet.protocol_digest,
                                bound_unit=summary.bound_unit)
    title = "%s / %s" % (summary.task, summary.backend)

    if summary.feasible is None:
        return Panel(title, UNAVAILABLE, "the artefact does not state feasibility",
                     '<p class="unavailable">unavailable: feasible</p>')

    if summary.feasible is False:
        reason = summary.reason or ""
        if not reason.strip():
            return Panel(title, REFUSAL, "refusal recorded without a reason",
                         '<p class="unavailable">unavailable: reason</p>')
        return Panel(title, REFUSAL, reason, '<p class="reason">%s</p>' % e(reason))

    numbers: list[dict[str, Any]] = []
    chunks: list[str] = []
    if mismatch is not None:
        chunks.append(_banner(mismatch))
    for label, value in (("autorate", summary.autorate), ("bound", summary.bound)):
        if value is None:
            numbers.append({"label": label, "value": None, "missing": [label]})
            chunks.append('<p class="absent">%s: %s</p>' % (e(label), e(ABSENT_NUMBER)))
            continue
        record, markup = _number(label, value, components, struck=mismatch is not None)
        numbers.append(record)
        chunks.append(markup)

    diagnostic = certificate.get("closest_attempt")
    if diagnostic:
        note = certificate.get("diagnostic_note") or ""
        chunks.append('<div class="diagnostic"><p class="disclosure">%s</p>%s%s</div>'
                      % (e(DISCLOSURE), ('<p class="note">%s</p>' % e(note)) if note else "",
                         '<pre>%s</pre>' % e(str(diagnostic))))
    return Panel(title, CERTIFIED, "", "".join(chunks), tuple(numbers))


def slice_view(*, pooled: Panel, companion: Panel | None,
               document: dict[str, Any], cap: int = SLICE_CAP) -> dict[str, Any]:
    """F3: pooled and companion side by side, every number with its own n."""
    rows = document.get("slices") or []
    notes: list[str] = []
    body: list[str] = []

    if companion is None:
        notes.append(NO_SLICE_EVIDENCE)
        body.append('<p class="absent">%s</p>' % e(NO_SLICE_EVIDENCE))

    kept, excluded = _exclude_degenerate(rows)
    for key in excluded:
        notes.append("degenerate slice key excluded: %s" % key)
        body.append('<p class="note">degenerate slice key excluded: %s</p>' % e(key))

    kept, overflow = _cap(kept, cap)
    for row in kept:
        body.append(_slice_row(row))
    if overflow:
        notes.append("and %d more" % overflow)
        body.append('<p class="note">and %d more</p>' % overflow)

    shared = document.get("shared_item_note") or document.get("shared_items")
    if shared:
        body.append('<p class="shared">shared items: %s</p>' % e(str(shared)))
    else:
        notes.append(INDEPENDENCE_UNKNOWN)
        body.append('<p class="note">%s</p>' % e(INDEPENDENCE_UNKNOWN))

    if document.get("correction"):
        body.append('<p class="correction">correction (published by the artefact): %s</p>'
                    % e(str(document["correction"])))

    panels = [pooled] + ([companion] if companion is not None else [])
    return {"html": '<div class="slices">%s%s</div>' % (
        "".join(panel.html() for panel in panels), "".join(body)),
        "notes": tuple(notes), "panels": tuple(panels),
        "excluded": tuple(excluded), "overflow": overflow}


def _slice_row(row: dict[str, Any]) -> str:
    denominator = ("n_cal=%s n_eval=%s" % (row.get("n_cal"), row.get("n_eval"))
                   if row.get("n_cal") is not None and row.get("n_eval") is not None
                   else "unavailable: denominator")
    return ('<div class="slice"><p>%s: %s</p><p class="triple">%s</p></div>'
            % (e(row.get("key")), e(row.get("value")), e(denominator)))


def _exclude_degenerate(rows: list[dict[str, Any]]) -> tuple[list[dict[str, Any]], list[str]]:
    by_key: dict[str, set[Any]] = {}
    for row in rows:
        by_key.setdefault(str(row.get("key")), set()).add(row.get("value"))
    degenerate = {key for key, values in by_key.items() if len(values) < 2}
    return [row for row in rows if str(row.get("key")) not in degenerate], sorted(degenerate)


def _cap(rows: list[dict[str, Any]], cap: int) -> tuple[list[dict[str, Any]], int]:
    """Top-N by smallest n, with the remainder counted - never silently cut."""
    if len(rows) <= cap:
        return rows, 0
    ordered = sorted(rows, key=lambda row: (row.get("n") is None, row.get("n") or 0))
    return ordered[:cap], len(rows) - cap


def packet_header(manifest) -> dict[str, str]:
    """The line the portal quotes above a certificate, including the re-derived
    denominator the artefact's own verify printed. Section 6.3 compares this
    quoted string against a live run in the same job."""
    return {"packet_id": manifest.packet_id, "protocol_digest": manifest.protocol_digest,
            "source_revision": manifest.source_revision,
            "re_derived": manifest.expected_rederived}
