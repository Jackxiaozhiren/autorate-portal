"""Self-contained HTML view of a packet (PRD F9, I2, I3, section 11 reproducibility).

The renderer reads numbers out of artefacts and formats them. It computes no
statistic: there is no arithmetic here, no aggregation and no percent. A number
whose (denominator, rubric, packet+digest) triple is incomplete renders as
"unavailable" (I2), and the guard that enforces it lives in ``emit.py`` so there
is exactly one place a number can become text. A refusal renders as refusal
text, never a zero, a dash or an empty card (I3). Records artefacts are never
embedded (section 8.4).
"""
from __future__ import annotations

import html
import json
from typing import Any

from . import emit
from .manifest import Manifest

STYLE = """
:root{color-scheme:light}body{font:15px/1.5 -apple-system,BlinkMacSystemFont,"Segoe UI",sans-serif;
margin:2rem auto;max-width:62rem;padding:0 1rem;color:#1f2328;background:#fff}
h1{font-size:1.5rem}h2{font-size:1.1rem;margin-top:2rem}
code,pre{font-family:ui-monospace,SFMono-Regular,Menlo,monospace;font-size:.9rem}
.card{border:1px solid #d0d7de;border-radius:6px;padding:1rem;margin:.75rem 0}
.refusal{border-left:5px solid #b35900;background:#fff8f0;padding:.75rem 1rem;margin:.5rem 0}
.refusal strong{color:#8a3b00}
.unavailable{border-left:5px solid #6e7781;background:#f6f8fa;padding:.75rem 1rem}
.triple{color:#57606a;font-size:.85rem;margin-top:.5rem}
.meta{color:#57606a;font-size:.85rem}
table{border-collapse:collapse;width:100%}td,th{border-bottom:1px solid #d8dee4;padding:.4rem;text-align:left}
"""


def e(value: Any) -> str:
    return html.escape(str(value), quote=True)


def render_certificate(manifest: Manifest, path: str, raw: bytes) -> str:
    try:
        certificate = json.loads(raw)
    except (ValueError, UnicodeDecodeError):
        return ('<div class="card refusal"><strong>NOT_INFORMATIVE</strong> — '
                'artefact %s does not parse as a certificate.</div>' % e(path))
    if not isinstance(certificate, dict):
        return ('<div class="card refusal"><strong>NOT_INFORMATIVE</strong> — '
                'artefact %s is not a certificate object.</div>' % e(path))

    values = emit.components(manifest, certificate)
    absent = sorted(emit.missing_components(values))
    head = '<h2>%s</h2>' % e(path)

    if certificate.get("feasible") is not True:
        reason = certificate.get("reason")
        state = "NOT_CERTIFIABLE" if reason else "NOT_INFORMATIVE"
        reason_text = e(reason) if reason else "no refusal reason was published by this certificate"
        envelope = certificate.get("envelope") or []
        lines = ''.join('<p>%s</p>' % e(line) for line in envelope)
        return (head + '<div class="card refusal"><strong>%s</strong> — reason: %s%s</div>'
                % (state, reason_text, lines)
                + ('<p class="triple">%s</p>' % emit.triple_html(values) if not absent else
                   '<div class="unavailable">unavailable: %s not published by this certificate</div>'
                   % e(", ".join(absent))))

    value = certificate.get("autorate")
    if value is None:
        return (head + '<div class="card refusal"><strong>NOT_INFORMATIVE</strong> — '
                'feasible is true but autorate was not published.</div>'
                + ('<p class="triple">%s</p>' % emit.triple_html(values) if not absent else
                   '<div class="unavailable">unavailable: %s not published by this certificate</div>'
                   % e(", ".join(absent))))

    try:
        return head + emit.statistic(label="autorate", value=value, values=values)
    except emit.EmitRefused as refusal:
        return (head + '<div class="card unavailable">unavailable: %s not published by this '
                'certificate; the number is not rendered.</div>'
                % e(", ".join(sorted(refusal.missing))))


def render(manifest: Manifest, files: dict[str, bytes]) -> str:
    """F9 rule 4: the CLI target delegates to the one document contract.

    Imported lazily so this module can keep owning the low-level primitives
    (``e``, ``STYLE``, ``render_certificate``) that ``render.document`` reuses
    without a module-level import cycle.
    """
    from .render import document
    return document(manifest, files)
