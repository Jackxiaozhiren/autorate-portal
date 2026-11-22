"""V2 first screen: the question comes before the inventory.

The page used to open on a table of certificates, which answers "what do we have" rather than the
business question "does this claim hold". The order is checked on the source because the page is a
single static document; the copy check keeps the three-answer promise visible next to the form.
"""
from __future__ import annotations

import json
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
PAGE = ROOT / "src" / "autorate_portal" / "web" / "index.html"


def test_the_claim_check_comes_before_the_certificate_table():
    text = PAGE.read_text(encoding="utf-8")
    assert text.index('data-i18n="label.check_claim"') < text.index('<table id="certificates"')


def test_the_intro_presents_a_refusal_as_a_result():
    text = PAGE.read_text(encoding="utf-8")
    assert "cannot be bounded" in text
    assert "not a failure" in text


def test_both_languages_carry_the_first_screen_copy():
    catalog = json.loads((ROOT / "src" / "autorate_portal" / "catalog.json").read_text(encoding="utf-8"))
    for language in ("en", "zh-Hans"):
        assert "label.certificates" in catalog[language]
        assert "text.claim_intro" in catalog[language]
