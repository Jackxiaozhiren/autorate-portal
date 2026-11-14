"""T9 — F2 in both languages, through one catalog, with verbatim reasons."""
from __future__ import annotations

from pathlib import Path

from autorate_portal import db, i18n
from autorate_portal.views import Panel, f2_locale_artifact, localized_state_badge, slice_view

RUBRIC = {"alpha": 0.05, "beta": 0.05, "delta": 0.05,
          "method": "aps", "seed": 7, "unit": "case"}


def _packet():
    return db.Packet(id="pkt-row-1", protocol_digest="abcdef123456",
                     manifest_sha256="f" * 64)


def _summary(**overrides):
    values = dict(task="laya", backend="fixture", feasible=False,
                  reason="empty_feasible_set", autorate=None, bound=None,
                  bound_unit="case", n_cal=96, n_eval=96,
                  alpha="0.05", beta="0.05", delta="0.05")
    values.update(overrides)
    return db.CertificateSummary(**values)


def _render(locale, summary=None):
    return f2_locale_artifact(summary=summary or _summary(), packet=_packet(),
                              rubric=RUBRIC, certificate={}, locale=locale)


def test_f2_renders_in_both_languages_with_different_state_text():
    english = _render("en")
    chinese = _render("zh-Hans")

    assert '<html lang="en">' in english
    assert '<html lang="zh-Hans">' in chinese
    assert english != chinese
    assert "refusal" in english
    assert "拒绝" in chinese
    assert chinese.count("empty_feasible_set") == english.count("empty_feasible_set")


def test_the_artefacts_refusal_reason_is_verbatim_in_both_languages():
    for locale in i18n.LANGUAGES:
        page = _render(locale)
        assert "empty_feasible_set" in page, locale
        assert "no data" not in page.lower(), locale


def test_the_unit_word_is_translated_but_the_number_is_never_reformatted():
    summary = _summary(feasible=True, reason="", autorate="0.42", bound="0.05")
    english = _render("en", summary)
    chinese = _render("zh-Hans", summary)

    assert "0.42 case" in english
    assert "0.42 案例" in chinese
    assert "0.42" in chinese and "0.42" in english
    assert "0.05" in chinese, "the bound's published digits do not change"


def test_a_refusal_carries_no_number_in_either_language():
    for locale in i18n.LANGUAGES:
        page = _render(locale)
        assert '<div class="card">' not in page
        assert "<code>" not in page, "a refusal has no statistic component"


def test_the_panel_body_is_in_the_requested_language_not_only_the_header():
    """The header was localized first; the body must follow the same locale."""
    summary = _summary(feasible=None, reason=None)
    english = _render("en", summary)
    chinese = _render("zh-Hans", summary)

    assert "unavailable: feasible" in english
    assert "不可用：可行性" in chinese
    assert "unavailable: feasible" not in chinese


def test_the_slice_panel_speaks_the_requested_locale():
    doc = {"slices": [{"key": "qtype", "value": "single", "n": 5,
                       "n_cal": 5, "n_eval": 5}]}
    view = slice_view(pooled=Panel("p", "certified", "", ""), companion=None,
                      document=doc, locale="zh-Hans")

    assert "已排除退化切片键：qtype" in view["html"]
    assert "degenerate slice key excluded" not in view["html"]


def test_the_state_badge_differs_in_text_not_only_in_hue():
    english = localized_state_badge("en", "refusal")
    chinese = localized_state_badge("zh-Hans", "refusal")
    assert english != chinese and 'data-state="refusal"' in english
    assert "拒绝" in chinese


def test_the_single_page_client_has_keyboard_reachable_controls():
    page = (Path(__file__).resolve().parents[1]
            / "src" / "autorate_portal" / "web" / "index.html").read_text(encoding="utf-8")
    assert "<label" in page and "<button" in page
    assert 'lang="en"' in page
    assert "locale" in page, "the client exposes the language switch"
