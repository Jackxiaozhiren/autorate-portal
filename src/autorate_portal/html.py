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
/* One paper-and-ink ramp, one accent, three text roles. Colour lives in the
   verdict and the numbers, never in the chrome. */
:root{color-scheme:light;
--bg:#f7f8fa;--surface:#fff;--raised:#eef1f5;--line:rgba(17,24,39,.09);
--text:#111827;--text-2:#4b5565;--text-3:#6b7487;
--accent:#1e4a6d;--good:#16794a;--bad:#b42318;--warn:#8a5a00;
--mono:ui-monospace,SFMono-Regular,Menlo,Consolas,monospace}
*{box-sizing:border-box}
body{font:14px/1.5 -apple-system,BlinkMacSystemFont,"Segoe UI",system-ui,sans-serif;
margin:32px auto;max-width:1120px;padding:0 32px;color:var(--text);background:var(--bg)}
h1{font-size:20px;line-height:1.2;font-weight:500;margin:0 0 24px;letter-spacing:0}
h2{font-size:15px;line-height:1.4;font-weight:500;margin:32px 0 12px;letter-spacing:0}
p{margin:0 0 8px}
code,pre{font-family:var(--mono);font-size:13px;font-variant-numeric:tabular-nums}
.card{border:1px solid var(--line);border-radius:12px;background:var(--surface);
padding:20px;margin:12px 0}
.card>:last-child{margin-bottom:0}
.refusal{border-left:2px solid var(--warn);background:var(--raised);
padding:16px 20px;margin:12px 0}
.refusal strong{color:var(--bad);font-weight:500}
.unavailable{border-left:2px solid var(--line);background:var(--raised);
padding:16px 20px;margin:12px 0;color:var(--text-2)}
.triple{color:var(--text-3);font-size:12px;margin-top:8px;font-family:var(--mono);
font-variant-numeric:tabular-nums;word-break:break-word}
.meta{color:var(--text-2);font-size:13px}
table{border-collapse:collapse;width:100%;margin-top:12px}
td,th{border-bottom:1px solid var(--line);padding:12px 8px;text-align:left;font-size:13px}
th{color:var(--text-3);font-size:12px;font-weight:400}
@media print{@page{size:A4;margin:18mm}
body{margin:0;max-width:none;padding:0;font-size:11pt;background:#fff;color:#000}
.card,.refusal,.unavailable,table{break-inside:avoid}
a{color:#000;text-decoration:none}}
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
