"""X-02 (first half): the README may not describe a surface this tree does not have.

Narrow on purpose. A test that pins every sentence gets edited on every wording
change and then deleted, so this one asserts only the retired milestone claim and
the command that was missing from the table. Both assertions are red against the
pre-2026-11-17 README, which is the point: a documentation guard that cannot fail
is decoration.
"""
from pathlib import Path

README = Path(__file__).resolve().parents[1] / "README.md"


def test_the_readme_does_not_describe_the_http_surface_as_unimplemented():
    text = README.read_text(encoding="utf-8")
    assert "M3–M5" not in text
    assert "deliberately not implemented" not in text


def test_the_command_table_names_the_monitor_command():
    text = README.read_text(encoding="utf-8")
    assert "autorate-portal monitor" in text
