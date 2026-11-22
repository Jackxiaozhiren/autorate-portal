"""The export leaves the browser as a file, not as text on the screen.

An auditor is handed the packet and the bundle, and re-checks the bundle with `export recheck`
without help from the portal. The page used to print the response through `JSON.stringify` into a
`<pre>`, so the only copy lived on screen and a P1 could not file it.

The page now saves the bytes it received, under a name that carries the bundle hash. These tests
hold that the writer is gone, that the refusal a blocked export carries is shown as its sentence,
and that the object URL is released.
"""
from __future__ import annotations

import json
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
PAGE = ROOT / "src" / "autorate_portal" / "web" / "index.html"


def test_the_page_saves_the_bytes_it_received():
    text = PAGE.read_text(encoding="utf-8")

    assert "await response.blob()" in text
    assert "link.download = name" in text
    assert 'response.headers.get("x-bundle-sha256")' in text


def test_the_page_is_not_a_second_writer_of_the_bundle():
    text = PAGE.read_text(encoding="utf-8")

    # The old writer: parse the response, re-serialise it, put it on the page. A second
    # encoding of one bundle is a second thing to disagree with the hash.
    assert "JSON.stringify(body, null, 2)" not in text
    assert "response.blob()" in text


def test_the_file_name_carries_the_bundle_hash_prefix():
    text = PAGE.read_text(encoding="utf-8")

    # `kind` plus twelve hex characters is short enough to type into a message and long
    # enough to find the bundle again by the hash the portal published.
    assert 'digest.slice(0, 12)' in text
    assert '".json"' in text


def test_a_blocked_export_is_shown_as_its_reason():
    text = PAGE.read_text(encoding="utf-8")

    # A 409 carries `blocked`/`block_reason` as data, not a `detail` sentence; without this
    # the reader was told only "409 Conflict".
    assert "body.block_reason" in text


def test_the_download_url_is_released():
    text = PAGE.read_text(encoding="utf-8")

    assert "URL.createObjectURL(blob)" in text
    assert "URL.revokeObjectURL" in text


def test_the_export_copy_exists_in_both_languages():
    catalog = json.loads((ROOT / "src" / "autorate_portal" / "catalog.json")
                         .read_text(encoding="utf-8"))
    for language in ("en", "zh-Hans"):
        for key in ("label.download_export", "label.preview", "text.export_file"):
            assert catalog[language][key]
        line = catalog[language]["text.export_file"]
        assert all(placeholder in line for placeholder in ("{name}", "{bytes}", "{digest}"))


def test_the_export_line_is_rebuilt_when_the_language_changes():
    text = PAGE.read_text(encoding="utf-8")

    # The line and its two labels are written when the bundle arrives, so they
    # cannot carry data-i18n. Without a rebuild they keep the language they were
    # first rendered in — the same defect the identity line had.
    assert "state.exported = {" in text
    assert "if (state.exported) { renderExport(); }" in text


def test_the_badge_button_is_translated_too():
    text = PAGE.read_text(encoding="utf-8")
    catalog = json.loads((ROOT / "src" / "autorate_portal" / "catalog.json")
                         .read_text(encoding="utf-8"))

    assert 'data-i18n="label.badge"' in text
    for language in ("en", "zh-Hans"):
        assert catalog[language]["label.badge"]
