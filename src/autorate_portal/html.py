"""Self-contained HTML view of a packet (PRD F9, I2, I3, section 11 reproducibility).

The renderer reads numbers out of artefacts and formats them. It computes no
statistic: there is no arithmetic here, no aggregation and no percent. A number
whose (denominator, rubric, packet+digest) triple is incomplete renders as
"unavailable" (I2). A refusal renders as refusal text, never a zero, a dash or
an empty card (I3). Records artefacts are never embedded (section 8.4).
"""
from __future__ import annotations

import html
import json
from typing import Any

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


def _triple(manifest: Manifest, certificate: dict[str, Any]) -> tuple[bool, str, str]:
    """(complete, rendered triple, missing component name)."""
    n_cal = certificate.get("n_cal")
    n_eval = certificate.get("n_eval")
    rubric = manifest.rubric
    budget = [rubric.get(k) for k in ("alpha", "beta", "delta", "method", "seed")]
    unit = (certificate.get("meta") or {}).get("at_requested_alpha", {}).get("bound_unit")
    if not unit:
        unit = (certificate.get("meta") or {}).get("bound_unit")

    missing = []
    if n_cal is None or n_eval is None:
        missing.append("denominator")
    if any(v is None for v in budget):
        missing.append("budget/rubric")
    if not manifest.packet_id or not manifest.protocol_digest:
        missing.append("packet id + protocol digest")
    if unit is None:
        missing.append("bound_unit")
    if missing:
        return False, "", ", ".join(sorted(missing))

    text = ("denominator: n_cal=%s n_eval=%s; budget/rubric: alpha=%s beta=%s delta=%s "
            "method=%s seed=%s; packet: %s / %s; bound_unit: %s"
            % (n_cal, n_eval, budget[0], budget[1], budget[2], budget[3], budget[4],
               manifest.packet_id, manifest.protocol_digest, unit))
    return True, e(text), ""


def render_certificate(manifest: Manifest, path: str, raw: bytes) -> str:
    try:
        certificate = json.loads(raw)
    except (ValueError, UnicodeDecodeError):
        return ('<div class="card refusal"><strong>NOT_INFORMATIVE</strong> — '
                'artefact %s does not parse as a certificate.</div>' % e(path))
    if not isinstance(certificate, dict):
        return ('<div class="card refusal"><strong>NOT_INFORMATIVE</strong> — '
                'artefact %s is not a certificate object.</div>' % e(path))

    complete, triple, missing = _triple(manifest, certificate)
    head = '<h2>%s</h2>' % e(path)

    if certificate.get("feasible") is not True:
        reason = certificate.get("reason")
        state = "NOT_CERTIFIABLE" if reason else "NOT_INFORMATIVE"
        reason_text = e(reason) if reason else "no refusal reason was published by this certificate"
        envelope = certificate.get("envelope") or []
        lines = ''.join('<p>%s</p>' % e(line) for line in envelope)
        return (head + '<div class="card refusal"><strong>%s</strong> — reason: %s%s</div>'
                % (state, reason_text, lines)
                + ('<p class="triple">%s</p>' % triple if complete else
                   '<div class="unavailable">unavailable: %s not published by this certificate</div>'
                   % e(missing)))

    if not complete:
        return (head + '<div class="card unavailable">unavailable: %s not published by this '
                'certificate; the number is not rendered.</div>' % e(missing))

    value = certificate.get("autorate")
    if value is None:
        return (head + '<div class="card refusal"><strong>NOT_INFORMATIVE</strong> — '
                'feasible is true but autorate was not published.</div>'
                + '<p class="triple">%s</p>' % triple)
    return (head + '<div class="card"><div>autorate: <code>%s</code></div>'
            '<p class="triple">%s</p></div>' % (e(value), triple))


def render(manifest: Manifest, files: dict[str, bytes]) -> str:
    """Deterministic single-file HTML; no clock, no CDN, no script."""
    certificates = [(a.path, files[a.path]) for a in manifest.artifacts
                    if a.kind == "certificate" and a.path in files]
    records = [a.path for a in manifest.artifacts if a.kind == "records"]

    parts = [
        '<!doctype html><html lang="en"><head><meta charset="utf-8">',
        '<title>Evidence packet %s</title><style>%s</style></head><body>' % (e(manifest.packet_id), STYLE),
        '<h1>Evidence packet <code>%s</code></h1>' % e(manifest.packet_id),
        '<p class="meta">protocol digest <code>%s</code> · source revision <code>%s</code> '
        '· source version <code>%s</code> · lane <code>%s</code></p>'
        % (e(manifest.protocol_digest), e(manifest.source_revision),
           e(manifest.source_version), e(manifest.lane)),
        '<p class="meta">This view reads artefact bytes. It computes no statistic and contains no '
        'records rows.</p>',
    ]

    if records:
        parts.append('<div class="card refusal"><strong>PRIVACY</strong> — this packet declares '
                     'records artefacts; their rows are never rendered: %s</div>' % e(", ".join(records)))
    if manifest.records_excluded:
        parts.append('<div class="card">Shareable packet: records artefacts are excluded and named '
                     'here, not silently dropped: %s</div>' % e(", ".join(manifest.excluded_records)))

    for path, raw in certificates:
        parts.append(render_certificate(manifest, path, raw))

    parts.append('<h2>Reproduction</h2><div class="card">'
                 '<p>Pinned distribution: <code>%s==%s</code>, wheel <code>%s</code>, '
                 'sha256 <code>%s</code>.</p>'
                 '<pre>autorate-portal verify-packet &lt;packet.tar&gt;\n'
                 'autorate verify --protocol protocol.json  # %s</pre>'
                 '<p class="meta">A stranger needs the packet, network access to PyPI and Docker; '
                 'no access to the producing organisation.</p></div>'
                 % (e(manifest.distribution.name), e(manifest.distribution.version),
                    e(manifest.distribution.wheel), e(manifest.distribution.sha256),
                    e(manifest.expected_rederived)))

    parts.append('<h2>Declared artefacts</h2><table><tr><th>path</th><th>kind</th>'
                 '<th>sha256</th></tr>')
    for artefact in manifest.artifacts:
        parts.append('<tr><td><code>%s</code></td><td>%s</td><td><code>%s</code></td></tr>'
                     % (e(artefact.path), e(artefact.kind), e(artefact.sha256)))
    parts.append('</table></body></html>')
    return "\n".join(parts) + "\n"
