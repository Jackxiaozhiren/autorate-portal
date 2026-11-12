"""T8 — Section 11's Localization row, A6's zh-Hans, catalog completeness."""
from __future__ import annotations

import pytest

from autorate_portal import i18n


def test_the_catalog_is_complete_in_both_languages():
    i18n.assert_complete()
    assert i18n.LANGUAGES == ("en", "zh-Hans")
    assert i18n.keys("en") == i18n.keys("zh-Hans")


def test_unit_words_are_translated_and_an_unknown_unit_is_not_guessed():
    assert i18n.unit_word("en", "case") == ("case", True)
    assert i18n.unit_word("zh-Hans", "case") == ("案例", True)
    assert i18n.unit_word("zh-Hans", "record") == ("记录", True)
    assert i18n.unit_word("zh-Hans", "case") != i18n.unit_word("zh-Hans", "record")
    assert i18n.unit_word("zh-Hans", "unlisted-unit") == ("unlisted-unit", False)


def test_numbers_go_through_a_catalog_template_not_string_concatenation():
    assert i18n.number_with_unit("en", "0.42", "case") == "0.42 case"
    assert i18n.number_with_unit("zh-Hans", "0.42", "case") == "0.42 案例"
    assert i18n.number_with_unit("zh-Hans", "0.42", "record") == "0.42 记录"


def test_closed_machine_vocabularies_are_identical_in_both_languages():
    keys = [key for key in i18n.keys("en")
            if key.startswith(("verdict.", "badge."))]
    assert len(keys) == 7, keys
    for key in keys:
        assert i18n.t("en", key) == i18n.t("zh-Hans", key), key


def test_a_missing_key_or_locale_raises_instead_of_falling_back():
    with pytest.raises(i18n.CatalogError):
        i18n.t("en", "no.such.key")
    with pytest.raises(i18n.CatalogError):
        i18n.t("fr", "state.certified")
    with pytest.raises(i18n.CatalogError):
        i18n.state_word("en", "invented")


def test_render_states_differ_in_text_not_only_in_hue():
    for state in ("certified", "refusal", "unavailable"):
        assert i18n.state_word("en", state) != i18n.state_word("zh-Hans", state)
    assert "拒绝" in i18n.state_word("zh-Hans", "refusal")
