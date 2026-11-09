"""T4 - the renderer carries the triple and renders refusals as refusals (I2, I3)."""
from __future__ import annotations

import json
from pathlib import Path

from autorate_portal import EXIT_OK
from autorate_portal.cli import main
from autorate_portal.html import render
from autorate_portal.packet import build, verify_bundle
from conftest import CERT, RECORD_ROW, resign_bundle


def _view(path):
    result = verify_bundle(path)
    assert result.ok, result.refusals
    return render(result.manifest, result.files)


def test_refusal_renders_verbatim_and_never_as_zero(built):
    document = _view(built[0])
    assert "NOT_CERTIFIABLE" in document
    assert "empty_feasible_set" in document
    assert "no certificate exists, so no action is certified" in document
    assert "autorate: <code>0" not in document
    assert ">0</" not in document
    assert "no data" not in document.lower()


def test_missing_bound_unit_renders_unavailable_not_a_number(built, tmp_path):
    target = tmp_path / "no_unit.tar"
    target.write_bytes(built[0].read_bytes())
    broken = {**CERT, "meta": {"at_requested_alpha": {}}, "feasible": True,
              "autorate": 0.42}
    raw = json.dumps(broken, sort_keys=True, separators=(",", ":")).encode()
    resign_bundle(target, {"data/cert_laya.json": raw})
    document = _view(target)
    assert "unavailable: bound_unit" in document
    assert "0.42" not in document


def test_triple_travels_with_the_number(built, tmp_path):
    packet, manifest, _ = built
    target = tmp_path / "published.tar"
    target.write_bytes(packet.read_bytes())
    published = {**CERT, "feasible": True, "autorate": 0.42}
    raw = json.dumps(published, sort_keys=True, separators=(",", ":")).encode()
    resign_bundle(target, {"data/cert_laya.json": raw})
    document = _view(target)
    assert "0.42" in document
    assert "denominator: n_cal=96 n_eval=96" in document
    assert "budget/rubric" in document
    assert manifest.packet_id in document
    assert manifest.protocol_digest in document
    assert "bound_unit: case" in document


def test_never_embeds_records_rows_and_states_exclusion(tmp_path, source_tree, build_kwargs):
    out = tmp_path / "shareable.tar"
    build(source_tree, out, shareable=True, **build_kwargs)
    document = _view(out)
    assert b"secret-conversation-row" not in document.encode()
    assert RECORD_ROW.decode().strip() not in document
    assert "records artefacts are excluded" in document
    assert "data/records_feishu.jsonl" in document


def test_reproduction_command_and_pinned_version_are_present(built):
    document = _view(built[0])
    assert "autorate-portal verify-packet" in document
    assert "autorate==0.1.2" in document
    assert "7709d3faa560417efcbd8066f6db79d741d995bbbb9b23d2d595ed2a6fb38205" in document


def test_double_render_is_byte_identical(built):
    assert _view(built[0]).encode() == _view(built[0]).encode()


def test_renderer_has_no_arithmetic_or_statistics_import():
    """AST-level guard: prose in the docstring must not be able to trip it."""
    import ast

    source = Path(__file__).resolve().parents[1] / "src" / "autorate_portal" / "html.py"
    text = source.read_text()
    tree = ast.parse(text)
    forbidden_modules = {"numpy", "statistics", "math", "pandas", "scipy"}
    forbidden_calls = {"sum", "mean", "median", "stdev", "pstdev", "quantile",
                       "percentile", "average", "sqrt", "round"}
    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            imported = [alias.name.split(".")[0] for alias in node.names]
        elif isinstance(node, ast.ImportFrom):
            imported = [(node.module or "").split(".")[0]]
        else:
            imported = []
        assert not (set(imported) & forbidden_modules), (
            "renderer must not import a computation library: %s" % imported)
        if isinstance(node, ast.Call) and isinstance(node.func, ast.Name):
            assert node.func.id not in forbidden_calls, (
                "renderer must not compute: call to %s" % node.func.id)
    assert "<script" not in text
    assert "http://" not in text and "https://" not in text


def test_html_cli_writes_a_file(built, tmp_path, capsys):
    out = tmp_path / "view.html"
    assert main(["packet", "html", str(built[0]), "-o", str(out)]) == EXIT_OK
    assert out.read_text().startswith("<!doctype html>")
    assert "no records rows" in capsys.readouterr().out
