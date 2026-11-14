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

from . import db, i18n
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


def _number(label: str, value: Any, components: dict[str, Any], *,
            struck: bool = False, locale: str = i18n.DEFAULT_LOCALE) -> tuple[dict, str]:
    try:
        markup = statistic(label=label, value=value, values=components)
    except EmitRefused as exc:
        missing = ", ".join(exc.missing)
        return ({"label": label, "value": None, "missing": exc.missing},
                '<p class="unavailable">%s: %s</p>'
                % (e(label), e(i18n.t(locale, "text.unavailable_component",
                                      component=missing))))
    if struck:
        markup = '<div class="struck"><s>%s</s></div>' % markup
    return {"label": label, "value": str(value), "missing": []}, markup


def _banner(mismatch: tuple[str, str], locale: str = i18n.DEFAULT_LOCALE) -> str:
    return ('<p class="banner provenance-mismatch">%s</p>'
            % e(i18n.t(locale, "text.provenance_mismatch",
                       stored=mismatch[0], replay=mismatch[1])))


def certificate_panel(*, summary: db.CertificateSummary, packet: db.Packet,
                      rubric: dict[str, Any] | None, certificate: dict[str, Any],
                      mismatch: tuple[str, str] | None = None,
                      locale: str = i18n.DEFAULT_LOCALE) -> Panel:
    components = components_for(n_cal=summary.n_cal, n_eval=summary.n_eval, rubric=rubric,
                                packet_id=certificate.get("packet_id") or packet.id,
                                protocol_digest=packet.protocol_digest,
                                bound_unit=summary.bound_unit)
    title = "%s / %s" % (summary.task, summary.backend)

    if summary.feasible is None:
        return Panel(title, UNAVAILABLE, i18n.t(locale, "text.feasibility_unstated"),
                     '<p class="unavailable">%s</p>'
                     % e(i18n.t(locale, "text.unavailable_component",
                                 component=i18n.t(locale, "label.feasible"))))

    if summary.feasible is False:
        reason = summary.reason or ""
        if not reason.strip():
            return Panel(title, REFUSAL, i18n.t(locale, "text.refusal_without_reason"),
                         '<p class="unavailable">%s</p>'
                         % e(i18n.t(locale, "text.unavailable_component",
                                     component=i18n.t(locale, "label.reason"))))
        return Panel(title, REFUSAL, reason, '<p class="reason">%s</p>' % e(reason))

    numbers: list[dict[str, Any]] = []
    chunks: list[str] = []
    if mismatch is not None:
        chunks.append(_banner(mismatch, locale))
    for label, value in (("autorate", summary.autorate), ("bound", summary.bound)):
        if value is None:
            numbers.append({"label": label, "value": None, "missing": [label]})
            chunks.append('<p class="absent">%s: %s</p>'
                          % (e(label), e(i18n.t(locale, "text.absent_number"))))
            continue
        record, markup = _number(label, value, components, struck=mismatch is not None,
                                 locale=locale)
        numbers.append(record)
        chunks.append(markup)

    diagnostic = certificate.get("closest_attempt")
    if diagnostic:
        note = certificate.get("diagnostic_note") or ""
        chunks.append('<div class="diagnostic"><p class="disclosure">%s</p>%s%s</div>'
                      % (e(i18n.t(locale, "text.disclosure")),
                         ('<p class="note">%s</p>' % e(note)) if note else "",
                         '<pre>%s</pre>' % e(str(diagnostic))))
    return Panel(title, CERTIFIED, "", "".join(chunks), tuple(numbers))


def slice_rows(document: dict[str, Any]) -> list[dict[str, Any]]:
    """F3 rule 2: the rows the artefact itself declares.

    Two published shapes exist in the frozen repository. The fixtures and the
    PRD's rule 2 describe an explicit ``slices`` array; the slices artefact
    publishes ``run.per_group`` keyed by ``group_key`` instead, with a per-group
    ``feasible``/``reason``/``envelope``. Reading only the first shape made a
    real artefact look as if it had published no slices at all, which is the
    opposite of what it says - so both are read, and neither is inferred.
    """
    declared = document.get("slices")
    if declared:
        return [dict(row) for row in declared]

    run = document.get("run") or {}
    per_group = run.get("per_group") or {}
    if not per_group:
        return []

    key = document.get("group_key") or (run.get("groups") or ["group"])[0]
    rows: list[dict[str, Any]] = []
    for name, group in per_group.items():
        group = group or {}
        n_cal, n_eval = group.get("n_cal"), group.get("n_eval")
        # F3 shows the worst slice's *bound*. The per-group rate is a different
        # quantity and is carried separately so no surface can confuse the two.
        bound = group.get("conditional_error_bound")
        if bound is None:
            bound = group.get("marginal_error_bound")
        # A group can be computed under a corrected budget of its own (the
        # committed artefact has alpha 0.0125 per group against 0.05 pooled).
        # I2 wants the budget it *was* computed under, so the group's own numbers
        # win over the certificate's whenever the artefact published them.
        rubric = {"alpha": group.get("alpha"), "beta": group.get("beta"),
                  "delta": group.get("delta"), "method": group.get("method"),
                  "seed": (group.get("meta") or {}).get("seed")}
        rows.append({"key": key, "value": name,
                     "n": n_eval if n_eval is not None else n_cal,
                     "n_cal": n_cal, "n_eval": n_eval,
                     "feasible": group.get("feasible"),
                     "reason": group.get("reason"),
                     "envelope": group.get("envelope") or [],
                     "bound": bound, "autorate": group.get("autorate"),
                     "rubric": rubric,
                     "bound_unit": (group.get("meta") or {}).get("bound_unit")})
    return rows


def published_correction(document: dict[str, Any],
                         locale: str = i18n.DEFAULT_LOCALE) -> str | None:
    """F3 rule 5: display the artefact's correction, compute none.

    The slices artefact publishes ``run.corrected_alpha``/``_beta``/``_delta``
    beside the uncorrected values; a single-value ``correction`` string is the
    other shape. Both are quoted, never derived: the portal does not apply a
    correction and does not work out what one would have been.
    """
    run = document.get("run") or {}
    corrected = {key: run.get("corrected_%s" % key) for key in ("alpha", "beta", "delta")}
    if not any(value is not None for value in corrected.values()):
        return None
    plain = {key: run.get(key) for key in ("alpha", "beta", "delta")}
    stated = ", ".join("%s %s" % (key, value) for key, value in corrected.items() if value is not None)
    base = ", ".join("%s %s" % (key, value) for key, value in plain.items() if value is not None)
    if base:
        return i18n.t(locale, "text.correction_published_base", stated=stated, base=base)
    return i18n.t(locale, "text.correction_published", stated=stated)


def slice_companion(document: dict[str, Any],
                    locale: str = i18n.DEFAULT_LOCALE) -> Panel | None:
    """F3 rules 1 and 3: the group-conditional companion, from published rows.

    There is no second certificate in a packet, so the companion panel is built
    from the group rows the artefact declares. It carries no number: where the
    simultaneous claim refuses, that refusal is the headline (rule 3), and where
    the artefact publishes neither a refusal nor a bound, the panel says so.
    A packet that declares no groups gets no companion at all, which is the case
    rule 1 labels ``no_slice_evidence``.
    """
    rows = slice_rows(document)
    if not rows:
        return None
    title = i18n.t(locale, "text.companion_title")
    reasons = [str(row["reason"]) for row in rows
               if row.get("feasible") is False and row.get("reason")]
    if reasons:
        headline = "; ".join(dict.fromkeys(reasons))
        return Panel(title, REFUSAL, headline, '<p class="reason">%s</p>' % e(headline))
    return Panel(title, UNAVAILABLE, i18n.t(locale, "text.companion_no_verdict"),
                 '<p class="unavailable">%s</p>'
                 % e(i18n.t(locale, "text.unavailable_component",
                             component=i18n.t(locale, "label.companion_verdict"))))

def slice_context(manifest, document: dict[str, Any]) -> dict[str, Any]:
    """The certificate-level half of a slice row's triple.

    The denominator is the slice's own; the budget, the packet id and the
    protocol digest are properties of the certificate the slice came from, so
    they are read once and carried into every row instead of being invented per
    group.
    """
    meta = document.get("meta") or {}
    at_alpha = meta.get("at_requested_alpha") or {}
    unit = at_alpha.get("bound_unit")
    if unit in (None, ""):
        unit = meta.get("bound_unit")
    return {"rubric": manifest.rubric, "packet_id": manifest.packet_id,
            "protocol_digest": manifest.protocol_digest, "bound_unit": unit}


def slice_view(*, pooled: Panel, companion: Panel | None,
               document: dict[str, Any], cap: int = SLICE_CAP,
               context: dict[str, Any] | None = None,
               locale: str = i18n.DEFAULT_LOCALE) -> dict[str, Any]:
    """F3: pooled and companion side by side, every number with its own n."""
    rows = slice_rows(document)
    notes: list[str] = []
    body: list[str] = []

    if companion is None:
        notes.append(i18n.t(locale, "text.no_slice_evidence"))
        body.append('<p class="absent">%s</p>' % e(i18n.t(locale, "text.no_slice_evidence")))

    kept, excluded = _exclude_degenerate(rows)
    for key in excluded:
        line = i18n.t(locale, "msg.degenerate_key_excluded", name=key)
        notes.append(line)
        body.append('<p class="note">%s</p>' % e(line))

    kept, overflow = _cap(kept, cap)
    for row in kept:
        body.append(_slice_row(row, context, locale))
    if overflow:
        line = i18n.t(locale, "msg.and_more", count=overflow)
        notes.append(line)
        body.append('<p class="note">%s</p>' % e(line))

    shared = document.get("shared_item_note") or document.get("shared_items")
    if shared:
        body.append('<p class="shared">%s</p>'
                    % e(i18n.t(locale, "text.shared_items", items=str(shared))))
    else:
        notes.append(i18n.t(locale, "text.independence_unknown"))
        body.append('<p class="note">%s</p>' % e(i18n.t(locale, "text.independence_unknown")))

    correction = document.get("correction") or published_correction(document, locale)
    if correction:
        body.append('<p class="correction">%s</p>'
                    % e(i18n.t(locale, "text.correction_label", value=str(correction))))

    panels = [pooled] + ([companion] if companion is not None else [])
    return {"html": '<div class="slices">%s%s</div>' % (
        "".join(panel.html() for panel in panels), "".join(body)),
        "notes": tuple(notes), "panels": tuple(panels),
        "excluded": tuple(excluded), "overflow": overflow}


def _slice_row(row: dict[str, Any], context: dict[str, Any] | None = None,
               locale: str = i18n.DEFAULT_LOCALE) -> str:
    """One slice: its own denominator, its own verdict.

    A group that the artefact itself refuses keeps its reason verbatim and gets
    no number (F3 rule 3 is F2's AC2 applied per group). A group that publishes
    a bound goes through :func:`emit.statistic` like every other number, so a
    missing unit renders "unavailable: bound_unit" rather than a bare figure.
    """
    def unavailable(component: str) -> str:
        return i18n.t(locale, "text.unavailable_component", component=component)

    key = row.get("key")
    denominator = ("n_cal=%s n_eval=%s" % (row.get("n_cal"), row.get("n_eval"))
                   if row.get("n_cal") is not None and row.get("n_eval") is not None
                   else unavailable(i18n.t(locale, "label.denominator")))

    if row.get("feasible") is False:
        envelope = row.get("envelope") or []
        reason = (row.get("reason") or (envelope[0] if envelope else None)
                  or i18n.t(locale, "text.reason_not_published"))
        return ('<div class="slice" data-state="refusal"><p>%s: %s</p>'
                '<p class="reason">%s</p><p class="triple">%s</p></div>'
                % (e(key), e(row.get("value")), e(reason), e(denominator)))

    if row.get("bound") is not None:
        context = context or {}
        published_rubric = row.get("rubric") or {}
        rubric = (published_rubric if any(value is not None for value in published_rubric.values())
                  else context.get("rubric"))
        values = components_for(n_cal=row.get("n_cal"), n_eval=row.get("n_eval"),
                                rubric=rubric,
                                packet_id=context.get("packet_id") or "",
                                protocol_digest=context.get("protocol_digest") or "",
                                bound_unit=row.get("bound_unit") or context.get("bound_unit"))
        label = "%s=%s" % (key, row.get("value"))
        try:
            return statistic(label=label, value=row.get("bound"), values=values)
        except EmitRefused as exc:
            return ('<div class="slice" data-state="unavailable"><p>%s: %s</p>'
                    '<p class="absent">%s</p><p class="triple">%s</p></div>'
                    % (e(key), e(row.get("value")), e(unavailable(", ".join(exc.missing))),
                       e(denominator)))

    return ('<div class="slice"><p>%s: %s</p><p class="triple">%s</p></div>'
            % (e(key), e(row.get("value")), e(denominator)))


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


def localized_state_badge(locale: str, state: str) -> str:
    """Section 11 accessibility: state differs in text, not in colour alone."""
    return ('<span class="state-badge" data-state="%s">%s</span>'
            % (e(state), e(i18n.state_word(locale, state))))


def f2_locale_artifact(*, summary: db.CertificateSummary, packet: db.Packet,
                       rubric: dict[str, Any] | None, certificate: dict[str, Any],
                       locale: str) -> str:
    """One self-contained F2 rendering in one locale, for CI artifacts.

    Section 11 asks for F2 in both languages. The panel's numbers, triples and
    the artefact's refusal reason stay **verbatim** (parity 6.3 and F2 rule 1);
    only the surrounding labels, the state word and the unit word are
    translated. A unit is never guessed: ``i18n`` returns an unlisted unit
    unchanged and the catalog completeness test keeps the two lists equal.
    """
    i18n.locale_or_raise(locale)
    panel = certificate_panel(summary=summary, packet=packet, rubric=rubric,
                              certificate=certificate, locale=locale)
    value = summary.autorate if summary.autorate is not None else summary.bound
    unit_display = (i18n.number_with_unit(locale, value, summary.bound_unit)
                    if value is not None and summary.bound_unit else "")
    parts = [
        '<!doctype html><html lang="%s"><head><meta charset="utf-8">'
        '<title>F2 · %s</title></head><body>' % (e(locale), e(panel.title)),
        '<h1>%s</h1>' % e(panel.title),
        '<p class="state">%s: %s</p>'
        % (e(i18n.t(locale, "label.state")), e(i18n.state_word(locale, panel.state))),
        '<p class="reason">%s: %s</p>'
        % (e(i18n.t(locale, "label.reason")), e(panel.reason or panel.state)),
        panel.body,
    ]
    if unit_display:
        parts.append('<p class="unit">%s: %s</p>'
                     % (e(i18n.t(locale, "label.unit")), e(unit_display)))
    parts.append('<p class="triple">%s</p>' % e(panel.title))
    parts.append('</body></html>')
    return "\n".join(parts) + "\n"
