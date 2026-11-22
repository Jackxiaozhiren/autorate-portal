"""V2 print view: one A4 sheet an auditor can file.

Both surfaces are checked: the self-contained document (CLI `packet html` and the share link share
one renderer) and the portal page. The assertions are content-level because a stylesheet cannot be
laid out in a unit test; what can be proved here is that the print block exists, names A4, keeps
blocks from splitting, and hides the controls a paper copy does not need.
"""
from __future__ import annotations

from pathlib import Path

from autorate_portal.cli import main

ROOT = Path(__file__).resolve().parents[1]


def test_the_self_contained_document_has_a_print_sheet(built, tmp_path):
    out = tmp_path / "view.html"
    assert main(["packet", "html", str(built[0]), "-o", str(out)]) == 0
    text = out.read_text(encoding="utf-8")
    assert "@media print" in text
    assert "size:A4" in text
    assert "break-inside:avoid" in text


def test_the_portal_page_has_a_print_sheet_and_hides_its_controls():
    text = (ROOT / "src" / "autorate_portal" / "web" / "index.html").read_text(encoding="utf-8")
    assert "@media print" in text
    assert "size: A4" in text
    assert "break-inside: avoid" in text
    assert ".row, button, select, input" in text


def test_the_portal_print_sheet_does_not_inherit_a_dark_screen_preference():
    """A dark system preference must not print white text on white paper.

    The page follows ``prefers-color-scheme`` on screen. The print block has to
    opt out of that, or the filed sheet is blank where the verdict should be.
    """
    text = (ROOT / "src" / "autorate_portal" / "web" / "index.html").read_text(encoding="utf-8")
    print_block = text.split("@media print", 1)[1].split("</style>", 1)[0]
    assert "color-scheme: light" in print_block
    assert "color-scheme: light dark" not in print_block
    assert "background: #fff" in print_block
    assert "color: #000" in print_block
