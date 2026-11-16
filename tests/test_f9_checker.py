"""T8 — the in-browser self-checker reuses the published decision rule, pins
the wheel, and degrades to `replay required` when the wheel cannot be fetched.

The browser cannot silently become a second authority. The checker's JS rule is
a literal transcription of the frozen module's `gate.decide`, tagged with that
module's sha256, and a node harness compares its verdict to the container
replay's for the same packet — recording the comparison, not asserting it.
"""
from __future__ import annotations

import json
import subprocess
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "tools"))
sys.path.insert(0, str(ROOT / "src"))

from autorate_portal.checker import build_checker  # noqa: E402


def test_checker_is_one_file_no_cdn_with_pins_and_the_published_rule(tmp_path):
    out = tmp_path / "checker.html"
    result = build_checker(out, wheel="autorate-0.1.2-py3-none-any.whl",
                           wheel_sha256="7709d3faa560417efcbd8066f6db79d741d995bbbb9b23d2d595ed2a6fb38205",
                           source="https://pypi.org/pypi/autorate/0.1.2/json",
                           rule_sha256="abc123")
    html = out.read_text(encoding="utf-8")
    assert result["path"] == str(out)
    assert "autorate-0.1.2-py3-none-any.whl" in html
    assert "7709d3faa560417efcbd8066f6db79d741d995bbbb9b23d2d595ed2a6fb38205" in html
    assert "abc123" in html
    assert "replay required" in html
    for cdn in ("cdn.jsdelivr.net", "unpkg.com", "cdnjs.cloudflare.com",
                "https://cdn", "<script src="):
        assert cdn not in html, "no CDN, no external script: %s" % cdn


def test_the_published_verdict_function_is_reused_by_the_node_harness(tmp_path):
    rule = ROOT / "tools" / "checker" / "verifier.mjs"
    harness = ROOT / "tools" / "checker" / "compare.mjs"
    assert rule.is_file() and harness.is_file()
    record = tmp_path / "comparison.json"
    proc = subprocess.run(
        ["node", str(harness), "--record", str(record),
         "--container-verdict", "holds", "--browser-verdict", "holds"],
        capture_output=True, text=True, timeout=30)
    assert proc.returncode == 0, proc.stderr
    data = json.loads(record.read_text(encoding="utf-8"))
    assert data["equal"] is True, "the comparison is recorded"
    assert data["container_verdict"] == "holds"
    assert data["browser_verdict"] == "holds"
