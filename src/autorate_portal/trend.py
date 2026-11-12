"""I4 — no cross-freeze aggregation without a boundary (PRD 4.1, 6.1, AC8).

Section 6.1's plant for I4 is "seed two packets at different digests and open
a trend". The enforcement therefore lives in the **query layer**, before a
series can be rendered: a series whose packets span two ``protocol_digest``
values is refused unless a boundary marker was requested.

Drawing the boundary does not make the two numbers comparable. The rendered
series names both digests and prints a separating line; no delta, slope or
percent is computed (I1). Numbers on either side remain the artefacts' own
published text.
"""
from __future__ import annotations

from dataclasses import dataclass

from sqlalchemy import select

from . import db, emit, i18n


@dataclass(frozen=True)
class Trend:
    drawn: bool
    reason: str
    digests: tuple[str, ...]
    boundary: bool
    rows: tuple[dict[str, str], ...]
    html: str

    def as_dict(self) -> dict:
        return {"drawn": self.drawn, "reason": self.reason,
                "digests": list(self.digests), "boundary": self.boundary,
                "rows": [dict(row) for row in self.rows], "html": self.html}


def _published_rows(session, packets: list[db.Packet]) -> tuple[dict[str, str], ...]:
    """Read stored values only; no aggregate, no delta, no recomputation."""
    rows: list[dict[str, str]] = []
    for packet in packets:
        statement = (select(db.CertificateSummary)
                     .join(db.Artifact, db.CertificateSummary.artifact_id == db.Artifact.id)
                     .where(db.Artifact.packet_id == packet.id)
                     .order_by(db.CertificateSummary.task, db.CertificateSummary.backend))
        for summary in session.scalars(statement):
            rows.append({
                "packet_id": packet.id,
                "protocol_digest": packet.protocol_digest,
                "task": str(summary.task),
                "backend": str(summary.backend),
                "autorate": str(summary.autorate) if summary.autorate is not None else
                            i18n.t(i18n.DEFAULT_LOCALE, "text.absent_number"),
                "n_cal": str(summary.n_cal) if summary.n_cal is not None else
                         i18n.t(i18n.DEFAULT_LOCALE, "text.absent_number"),
                "n_eval": str(summary.n_eval) if summary.n_eval is not None else
                          i18n.t(i18n.DEFAULT_LOCALE, "text.absent_number"),
            })
    return tuple(rows)


def _html(rows: tuple[dict[str, str], ...], digests: tuple[str, ...],
          boundary: bool, reason: str) -> str:
    parts = ['<section class="panel trend"><h2>%s</h2><p class="reason">%s</p>'
             % (emit.e(i18n.t(i18n.DEFAULT_LOCALE, "label.trend")), emit.e(reason))]
    if not rows:
        parts.append('<p class="absent">%s</p>'
                     % emit.e(i18n.t(i18n.DEFAULT_LOCALE, "text.no_evidence_published")))
    # I4's boundary is drawn once, above the whole series, and names both
    # digests. Drawing per row would let a series with no rows hide the
    # boundary altogether - which is the failure AC8 is guarding against.
    if boundary and len(digests) > 1:
        parts.append('<div class="boundary" data-digests="%s">boundary: %s | %s; '
                     'no delta is computed</div>'
                     % (emit.e(" ".join(digests)), emit.e(digests[0]),
                        emit.e(digests[-1])))
    for row in rows:
        parts.append('<div class="trend-row" data-digest="%s">'
                     '<code>%s</code> %s / %s · %s · %s</div>'
                     % (emit.e(row["protocol_digest"]), emit.e(row["packet_id"]),
                        emit.e(row["task"]), emit.e(row["backend"]),
                        emit.e(row["autorate"]), emit.e(row["n_cal"])))
    parts.append('</section>')
    return "".join(parts)


def trend_for(session, *, project_id: str, boundary: bool = False,
              locale: str = i18n.DEFAULT_LOCALE) -> Trend:
    """AC8: two freezes draw a boundary and name both digests, or draw nothing."""
    packets = list(session.scalars(
        select(db.Packet).where(db.Packet.project_id == project_id)
        .order_by(db.Packet.ingested_at, db.Packet.id)))
    digests = tuple(dict.fromkeys(packet.protocol_digest for packet in packets))

    if len(digests) > 1 and not boundary:
        first, second = digests[0], digests[1]
        reason = i18n.t(locale, "msg.boundary_required", a=first, b=second)
        return Trend(False, reason, digests, False, (), _html((), digests, False, reason))

    if len(digests) > 1:
        reason = i18n.t(locale, "msg.boundary_drawn", a=digests[0], b=digests[-1])
    elif digests:
        reason = i18n.t(locale, "msg.trend_within_digest", digest=digests[0])
    else:
        reason = i18n.t(locale, "text.no_evidence_published")

    rows = _published_rows(session, packets)
    return Trend(True, reason, digests, boundary, rows,
                 _html(rows, digests, boundary and len(digests) > 1, reason))
