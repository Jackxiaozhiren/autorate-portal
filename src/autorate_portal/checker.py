"""T8: build a single-file, CDN-free self-checker for a packet.

Honesty boundary, stated because it is the failure this project exists to
prevent: the checker does **not** re-implement a statistical verdict in Python
or in JavaScript. It embeds the *published* decision rule (``tools/checker/
verifier.mjs``, a literal transcription of the frozen repository's
``gate.decide`` vocabulary) and reports only that module's verdict. The wheel
it was published with is pinned by name, sha256 and source; if the wheel cannot
be fetched and verified, the verdict is ``replay required`` — never a pass,
never a red. A node harness compares the browser rule's verdict to the
container replay's for the same packet and *records* the comparison.

The HTML has no external script, no CDN, and no clock. Its only network act is
the pinned wheel fetch, which it performs at the reader's request.
"""
from __future__ import annotations

import hashlib
from pathlib import Path
from typing import Any

TOOLS = Path(__file__).resolve().parents[2] / "tools" / "checker"
VERIFIER = TOOLS / "verifier.mjs"
WHEEL_FETCH = """async function fetchWheel() {
  try {
    const res = await fetch(PIN.source);
    if (!res.ok) return null;
    const buf = new Uint8Array(await res.arrayBuffer());
    const digest = await crypto.subtle.digest('SHA-256', buf);
    const hex = [...new Uint8Array(digest)].map(b => b.toString(16).padStart(2, '0')).join('');
    return hex === PIN.sha256 ? buf : null;
  } catch (e) { return null; }
}
"""


def build_checker(out: Path, *, wheel: str, wheel_sha256: str, source: str,
                  rule_sha256: str = "") -> dict[str, Any]:
    """Write one self-contained HTML file; there is no second artefact."""
    rule = VERIFIER.read_text(encoding="utf-8") if VERIFIER.is_file() else ""
    actual_rule_sha = hashlib.sha256(rule.encode("utf-8")).hexdigest() if rule else ""
    tag = rule_sha256 or actual_rule_sha
    pin = {"wheel": wheel, "sha256": wheel_sha256, "source": source}
    pin_json = __import__("json").dumps(pin, sort_keys=True)
    # The same bytes are shown verbatim for audit and, with only the ES-module
    # `export` keyword removed, executed by the page. There is one rule, not a
    # displayed copy and a separate implemented one.
    executable_rule = rule.replace("export function", "function").replace(
        "\nexport default publishedVerdict;", "")
    html = f"""<!doctype html>
<html lang="en"><head><meta charset="utf-8"><title>autorate certificate self-checker</title>
<style>body{{font:15px/1.5 system-ui,sans-serif;max-width:52rem;margin:2rem auto;padding:0 1rem;color:#1f2328}}
code{{font-family:ui-monospace,monospace}} .verdict{{font-size:1.3rem;font-weight:600}}
.muted{{color:#57606a}} pre{{background:#f6f8fa;padding:.75rem;overflow:auto}}</style></head>
<body><h1>Certificate self-checker</h1>
<p class="muted">This page runs the published decision rule from the pinned distribution
<code>{wheel}</code> (sha256 <code>{wheel_sha256}</code>). It computes no statistic of its own.</p>
<p class="verdict" id="verdict">replay required</p>
<details><summary>Published decision rule (sha256 <code>{tag}</code>)</summary>
<pre>{rule}</pre></details>
<script>
const PIN = {pin_json};
const PUBLISHED_RULE_SHA256 = "{tag}";
{executable_rule}
{WHEEL_FETCH}
async function check(decision) {{
  const wheel = await fetchWheel();
  if (wheel === null) return {{verdict: 'replay required', reason: 'the pinned wheel could not be fetched or verified'}};
  // The verdict comes from the embedded published rule, not from this page.
  return publishedVerdict(decision);
}}
window.autorateCheck = check;
</script></body></html>
"""
    out.parent.mkdir(parents=True, exist_ok=True)
    out.write_text(html, encoding="utf-8")
    return {"path": str(out), "bytes": len(html.encode("utf-8")),
            "wheel": wheel, "wheel_sha256": wheel_sha256,
            "published_rule_sha256": tag, "cdn": False}
