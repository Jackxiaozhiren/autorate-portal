"""F4 — claim versus evidence (PRD section 5, AC5, AC6, I2, I3).

The business-facing feature is also the easiest place to lie, so this module
is deliberately narrow:

* It compares a claim against **published fields only**. A claim naming a field
  no certificate artefact carries (``confidence`` is the PRD's example) is
  ``cannot_be_bounded`` with the audit lane's comparability statement quoted
  verbatim. Same-named fields are not the same quantity.
* It never computes a statistic. The one numeric operation is a comparison of
  two strings as ``Decimal`` values: the claim's own share and a certified
  ``autorate`` the artefact published. No derived number is printed, and the
  printed digits are the strings the artefacts carried (section 4.1 I1 permits
  reading and counting; it forbids computing a bound, rate, mean or aggregate).
* The frozen repository's real packet publishes **no** certificate with
  ``feasible=true`` and a non-null ``autorate``. Against that packet every
  claim is therefore ``cannot_be_bounded``; ``bounded_refutes`` is reachable
  only when a published certificate supplies the number. The distinction is
  measured, not softened.
* ``cannot_be_bounded`` reads what additional data would bound the claim from
  ``data/g1_feasibility.json``'s published ``missing_pool_input`` and size
  ladder. That artefact has **no** ``n_min``/``required_n`` key, so the answer
  says so rather than inventing a sample size (F4 rule 3).
* The audit lane artefact is ``docs/AUDIT.md``, Markdown. It is quoted and
  labelled, never parsed into a machine-readable bound (F4 rule 4).
"""
from __future__ import annotations

import json
from dataclasses import dataclass
from decimal import Decimal, InvalidOperation
from typing import Any, Iterable

from . import db, emit, i18n

AUDIT_PATH = "docs/AUDIT.md"
FEASIBILITY_PATH = "data/g1_feasibility.json"
PROTOCOL_PATH = "protocol.json"

VERDICTS = ("bounded_supports", "bounded_refutes", "cannot_be_bounded")
BOUNDED_SUPPORTS, BOUNDED_REFUTES, CANNOT_BE_BOUNDED = VERDICTS

#: Exact substrings of the frozen repository's ``docs/AUDIT.md``. They are read
#: out of the packet's own bytes, so a packet whose audit lane does not publish
#: them says so instead of borrowing another repository's words.
COMPARABILITY_QUOTE = ("A field name therefore does not say which quantity a file holds; "
                       "only the program that wrote it does")
DEFINITION_SLIP_QUOTE = ("Quoting either multiple as the other is the definition slip "
                         "the two definitions make possible")
NOT_CERTIFIES_QUOTE = "Nothing here certifies a deployment"
POINT_ESTIMATE_QUOTE = ("A multiple is a point estimate and needs its interval "
                        "before it is anything else")
IMPLIED_QUOTE = ("gate compared against: `0.85` (upstream's own gating figure), "
                 "so the implied error rate is `1 - gate = 0.15`")

AUDIT_QUOTES = {
    "comparability": COMPARABILITY_QUOTE,
    "definition_slip": DEFINITION_SLIP_QUOTE,
    "nothing_certifies": NOT_CERTIFIES_QUOTE,
    "point_estimate": POINT_ESTIMATE_QUOTE,
    "implied": IMPLIED_QUOTE,
}

F1_COMMAND = ("autorate-portal packet build --source <checkout> --out packet.tar "
              "--revision <rev>")


class ClaimError(ValueError):
    """The claim is not a well-formed structured claim."""


@dataclass(frozen=True)
class Claim:
    share: str
    field: str
    unit: str
    population: str

    @classmethod
    def from_dict(cls, raw: dict[str, Any]) -> "Claim":
        missing = [name for name in ("share", "field", "unit", "population")
                   if not str(raw.get(name, "")).strip()]
        if missing:
            raise ClaimError("a claim needs share, field, unit and population; missing: %s"
                             % ", ".join(missing))
        return cls(share=str(raw["share"]).strip(), field=str(raw["field"]).strip(),
                   unit=str(raw["unit"]).strip(), population=str(raw["population"]).strip())


@dataclass(frozen=True)
class Verdict:
    verdict: str
    reason: str
    bound: str
    denominator: str
    provenance: str
    comparability: str = ""
    additional_data: str = ""
    numbers: tuple[dict[str, str], ...] = ()
    audit_labels: tuple[str, ...] = ()
    evidence: tuple[dict[str, str], ...] = ()

    def as_dict(self) -> dict[str, Any]:
        return {"verdict": self.verdict, "reason": self.reason, "bound": self.bound,
                "denominator": self.denominator, "provenance": self.provenance,
                "comparability": self.comparability, "additional_data": self.additional_data,
                "numbers": [dict(row) for row in self.numbers],
                "audit_labels": list(self.audit_labels),
                "evidence": [dict(row) for row in self.evidence]}

    def card(self, locale: str = i18n.DEFAULT_LOCALE) -> str:
        """Localized verdict card. Verdict words stay in the closed vocabulary."""
        rows = ['<section class="panel verdict" data-state="%s">' % emit.e(self.verdict),
                '<h2>%s: %s</h2>' % (emit.e(i18n.t(locale, "label.verdict")),
                                    emit.e(self.verdict)),
                '<p class="reason">%s</p>' % emit.e(self.reason)]
        for number in self.numbers:
            rows.append('<p class="claim-number">%s: <code>%s</code></p>'
                        % (emit.e(number["label"]),
                           emit.e(i18n.number_with_unit(locale, number["value"], number["unit"]))))
        if self.comparability:
            rows.append('<div class="comparability"><p>%s</p><blockquote>%s</blockquote></div>'
                        % (emit.e(i18n.t(locale, "label.comparability")),
                           emit.e(self.comparability)))
        if self.additional_data:
            rows.append('<p class="additional">%s</p>' % emit.e(self.additional_data))
        for label in self.audit_labels:
            rows.append('<p class="audit-label">%s</p>' % emit.e(label))
        rows.append('<p class="triple">%s</p>' % emit.e(self.provenance))
        rows.append('</section>')
        return "".join(rows)


def audit_quotes(text: str) -> dict[str, str]:
    """Verbatim quotes that are actually present in this packet's audit lane."""
    return {name: (quote if quote in text else "") for name, quote in AUDIT_QUOTES.items()}


def published_field_names(certificates: Iterable[dict[str, Any]]) -> frozenset[str]:
    """The field names the certificate artefacts themselves declare.

    A field name is evidence only when a certificate publishes it. The frozen
    packet's certificates declare ``autorate`` (six with a null value) but no
    ``confidence`` key at all, which is exactly AC6's case.
    """
    names: set[str] = set()
    for document in certificates:
        names.update(str(key) for key in document)
    return frozenset(names)


def _decimal(value: str) -> Decimal | None:
    try:
        return Decimal(str(value))
    except (InvalidOperation, ValueError):
        return None


def _provenance(manifest, packet, summary) -> str:
    """I2's triple in the same format ``emit.triple_html`` uses, plain text."""
    if manifest is None or packet is None:
        return ("denominator: unavailable; budget/rubric: unavailable; "
                "packet: unavailable; bound_unit: unavailable")
    values = emit.components_for(
        n_cal=summary.n_cal if summary else None, n_eval=summary.n_eval if summary else None,
        rubric=manifest.rubric, packet_id=manifest.packet_id,
        protocol_digest=packet.protocol_digest,
        bound_unit=(summary.bound_unit if summary else None) or manifest.bound_unit)
    return ("denominator: %s; budget/rubric: %s; packet: %s; bound_unit: %s"
            % (values.get("denominator"), values.get("budget/rubric"),
               values.get("packet"), values.get("bound_unit")))


def _feasibility_additional_data(feasibility: dict[str, Any] | None, locale: str) -> tuple[str, tuple[dict[str, str], ...]]:
    """F4 rule 3: read the need from published arithmetic; invent no sample size."""
    evidence: list[dict[str, str]] = []
    chunks: list[str] = []
    if not feasibility:
        chunks.append("the packet publishes no feasibility arithmetic; no additional data is named")
        return " ".join(chunks), tuple(evidence)

    missing = ""
    for row in feasibility.get("rows") or []:
        statement = row.get("missing_pool_input")
        if statement:
            missing = str(statement)
            evidence.append({"path": FEASIBILITY_PATH, "key": "rows[].missing_pool_input",
                             "value": missing})
            break
    if missing:
        chunks.append(i18n.t(locale, "msg.missing_pool", statement=missing))
    else:
        chunks.append("the feasibility artefact names no missing input")

    ladder = feasibility.get("reference") or []
    if ladder:
        first = ladder[0]
        line = i18n.t(locale, "msg.size_ladder", n=first.get("n"), k_max=first.get("k_max"),
                      rate=first.get("largest_certifiable_error_rate"),
                      accuracy=first.get("required_observed_accuracy"))
        chunks.append(line)
        evidence.append({"path": FEASIBILITY_PATH, "key": "reference[0]",
                         "value": json.dumps(first, sort_keys=True, ensure_ascii=False)})
    else:
        chunks.append("the feasibility artefact publishes no size ladder")

    has_required_n = any(key in feasibility for key in ("n_min", "required_n"))
    if not has_required_n:
        chunks.append(i18n.t(locale, "msg.no_required_sample"))
    return " ".join(chunks), tuple(evidence)


def check(*, claim: Claim, summaries: list[db.CertificateSummary], packet, manifest,
          audit_text: str = "", feasibility: dict[str, Any] | None = None,
          certificates: Iterable[dict[str, Any]] = (),
          locale: str = i18n.DEFAULT_LOCALE) -> Verdict:
    """Return exactly one of the three F4 verdicts, with its provenance line."""
    quotes = audit_quotes(audit_text)
    documents = list(certificates)
    declared = published_field_names(documents)
    summary = summaries[0] if summaries else None
    provenance = _provenance(manifest, packet, summary)
    bound = str(summary.bound) if (summary and summary.bound is not None) else \
        i18n.t(locale, "text.absent_number")
    denominator = ("n_cal=%s n_eval=%s" % (summary.n_cal, summary.n_eval)
                   if summary and summary.n_cal is not None and summary.n_eval is not None
                   else i18n.t(locale, "text.absent_number"))
    labels = (i18n.t(locale, "msg.audit_lane_quoted"),
              i18n.t(locale, "text.audit_is_markdown"))
    if quotes["implied"]:
        labels += (i18n.t(locale, "text.implied_error"),)
    if quotes["point_estimate"]:
        labels += (i18n.t(locale, "text.point_estimate"),)
    if quotes["nothing_certifies"]:
        labels += (i18n.t(locale, "text.nothing_certifies"),)

    def cannot(reason: str, *, comparability: str = "", extra: str = "",
               evidence: tuple[dict[str, str], ...] = ()) -> Verdict:
        return Verdict(CANNOT_BE_BOUNDED, reason, bound, denominator, provenance,
                       comparability=comparability, additional_data=extra,
                       audit_labels=labels, evidence=evidence)

    # F4 exception (b): no packet in the project.
    if not summaries:
        return cannot(i18n.t(locale, "msg.no_packet") + " " + F1_COMMAND)

    # F4 exception (a) / AC6: a field the packet never measured.
    if claim.field not in declared:
        comparability = " ".join(part for part in
                                 (quotes["comparability"], quotes["definition_slip"]) if part)
        if not comparability:
            comparability = ("the audit lane does not publish the comparability statement "
                             "in this packet; no substitute is quoted")
        evidence = ({"path": AUDIT_PATH, "key": "comparability", "value": comparability},)
        return cannot(i18n.t(locale, "msg.field_not_measured", field=claim.field),
                      comparability=comparability, evidence=evidence)

    # A number the packet actually published, under a certificate that says it
    # is feasible. Nothing here derives a bound: both operands are read.
    certified = next((row for row in summaries
                      if row.feasible is True and row.autorate is not None), None)
    if certified is None:
        extra, evidence = _feasibility_additional_data(feasibility, locale)
        return cannot(i18n.t(locale, "msg.no_certified_autorate"), extra=extra,
                      evidence=evidence)

    share = _decimal(claim.share)
    published = _decimal(str(certified.autorate))
    if share is None or published is None:
        return cannot("the claim share or the published autorate is not a number; "
                      "no point estimate is derived from either")

    numbers = ({"label": "claim share", "value": claim.share, "unit": claim.unit},
               {"label": "certified autorate", "value": str(certified.autorate),
                "unit": str(certified.bound_unit or manifest.bound_unit)})
    evidence = ({"path": "data/cert_*.json", "key": "autorate",
                 "value": str(certified.autorate)},)
    if share > published:
        reason = i18n.t(locale, "msg.refutes", claim_share=claim.share,
                        claim_unit=claim.unit, certified_autorate=str(certified.autorate),
                        certified_unit=str(certified.bound_unit or manifest.bound_unit))
        return Verdict(BOUNDED_REFUTES, reason, bound, denominator, provenance,
                       numbers=numbers, audit_labels=labels, evidence=evidence)
    reason = i18n.t(locale, "msg.supports", claim_share=claim.share,
                    claim_unit=claim.unit, certified_autorate=str(certified.autorate),
                    certified_unit=str(certified.bound_unit or manifest.bound_unit))
    return Verdict(BOUNDED_SUPPORTS, reason, bound, denominator, provenance,
                   numbers=numbers, audit_labels=labels, evidence=evidence)
