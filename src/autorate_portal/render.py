"""F9 rule 4: one component contract, two targets.

The CLI's ``packet html`` and the portal's share link call ``document`` with
the same manifest, the same file bytes, and the same options. There is one
renderer, so a certificate cannot read differently in an emailed file than it
does in a browser. Every number still comes from ``emit``; this module formats,
it computes nothing.

Two F9 options change the document without changing its contract:

* ``embed_cap`` — an artefact at or above this many bytes is not inlined. Its
  path is named and a download link is offered instead (exception (a)).
* ``provenance_badge`` — a shareable packet carrying ``unverified_provenance``
  renders that badge into the document, so the shared copy cannot look more
  certified than its source (exception (b)).
"""
from __future__ import annotations

from . import html as html_module
from .manifest import Manifest

#: Artefacts at or above this size are linked, not embedded. A third party can
#: raise it; lowering it is how a share is kept cheap. The cap is a presentation
#: choice and never changes a number or a verdict.
DEFAULT_EMBED_CAP = 256 * 1024

e = html_module.e
STYLE = html_module.STYLE


def document(manifest: Manifest, files: dict[str, bytes], *,
             embed_cap: int = DEFAULT_EMBED_CAP,
             provenance_badge: str = "") -> str:
    """The single HTML document both targets render from identical inputs."""
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

    if provenance_badge:
        parts.append('<div class="card refusal"><strong>PROVENANCE</strong> — '
                     '%s travels with this shareable copy.</div>' % e(provenance_badge))

    if records:
        parts.append('<div class="card refusal"><strong>PRIVACY</strong> — this packet declares '
                     'records artefacts; their rows are never rendered: %s</div>' % e(", ".join(records)))
    if manifest.records_excluded:
        parts.append('<div class="card">Shareable packet: records artefacts are excluded and named '
                     'here, not silently dropped: %s</div>' % e(", ".join(manifest.excluded_records)))

    omitted: list[str] = []
    for path, raw in certificates:
        if len(raw) >= embed_cap:
            omitted.append(path)
            continue
        parts.append(html_module.render_certificate(manifest, path, raw))
    if omitted:
        parts.append('<div class="card"><strong>OMITTED</strong> — artefacts above the embed cap '
                     'are not inlined; link out to the download instead: %s</div>'
                     % e(", ".join(omitted)))

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
