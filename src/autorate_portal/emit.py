"""I2's structural guard: a number cannot become text without its triple.

PRD Section 6.1 puts the enforcement at **emit** time, in the renderer, "not in
a downstream test". That distinction is the whole point: a test that reads the
finished document only observes the rule, it cannot be the mechanism. So every
number the view displays passes through :func:`statistic`, and that function
raises rather than formats when the denominator, the rubric, the packet (id and
protocol digest) or the bound's unit is missing.

The caller turns the raise into "unavailable: <component>" (I3's vocabulary for
absence). A missing unit is treated as absence, not as an empty string to print
next to a number: "0.42" with no unit is not a measurable claim.
"""
from __future__ import annotations

import html
from typing import Any

from .manifest import Manifest

ORDER = ("denominator", "budget/rubric", "packet", "bound_unit")
MISSING_NAME = {
    "denominator": "denominator",
    "budget/rubric": "budget/rubric",
    "packet": "packet id + protocol digest",
    "bound_unit": "bound_unit",
}
BUDGET_KEYS = ("alpha", "beta", "delta", "method", "seed")


class EmitRefused(Exception):
    """Raised at emit time; the number must not reach the document."""

    def __init__(self, missing: list[str]) -> None:
        self.missing = list(missing)
        super().__init__(", ".join(self.missing))


def e(value: Any) -> str:
    return html.escape(str(value), quote=True)


def _absent(value: Any) -> bool:
    if value is None:
        return True
    if isinstance(value, str) and not value.strip():
        return True
    return False


def components_for(*, n_cal: Any, n_eval: Any, rubric: dict[str, Any] | None,
                   packet_id: str, protocol_digest: str,
                   bound_unit: Any) -> dict[str, Any]:
    """The four components from stored values, for surfaces that read the row.

    ``components`` serves the builder, which holds the parsed manifest and
    certificate; this serves the portal, which holds the database. They must
    format identically, because a number rendered from the row and the same
    number rendered at build time are the same claim.
    """
    rubric = rubric or {}
    budget = [rubric.get(key) for key in BUDGET_KEYS]
    return {
        "denominator": (None if n_cal is None or n_eval is None
                        else "n_cal=%s n_eval=%s" % (n_cal, n_eval)),
        "budget/rubric": (None if any(value is None for value in budget)
                          else "alpha=%s beta=%s delta=%s method=%s seed=%s" % tuple(budget)),
        "packet": ("%s / %s" % (packet_id, protocol_digest)
                   if packet_id and protocol_digest else None),
        "bound_unit": None if _absent(bound_unit) else str(bound_unit),
    }


def components(manifest: Manifest, certificate: dict[str, Any]) -> dict[str, Any]:
    """The four things a displayed number has to carry, formatted or None."""
    meta = certificate.get("meta") or {}
    at_alpha = meta.get("at_requested_alpha") or {}
    unit = at_alpha.get("bound_unit")
    if _absent(unit):
        unit = meta.get("bound_unit")

    return components_for(n_cal=certificate.get("n_cal"), n_eval=certificate.get("n_eval"),
                          rubric=manifest.rubric, packet_id=manifest.packet_id,
                          protocol_digest=manifest.protocol_digest, bound_unit=unit)


def missing_components(values: dict[str, Any]) -> list[str]:
    return [MISSING_NAME[key] for key in ORDER if _absent(values.get(key))]


def triple_html(values: dict[str, Any]) -> str:
    """The triple as it appears beside a number, already escaped."""
    return e("denominator: %s; budget/rubric: %s; packet: %s; bound_unit: %s"
             % (values.get("denominator"), values.get("budget/rubric"),
                values.get("packet"), values.get("bound_unit")))


def statistic(*, label: str, value: Any, values: dict[str, Any]) -> str:
    """Render one number, or refuse. There is no third outcome."""
    missing = missing_components(values)
    if missing:
        raise EmitRefused(missing)
    return ('<div class="card"><div>%s: <code>%s</code></div>'
            '<p class="triple">%s</p></div>' % (e(label), e(value), triple_html(values)))
