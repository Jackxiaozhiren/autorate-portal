"""T7 - F3: pooled beside its companion, every slice with its own denominator."""
from __future__ import annotations

from autorate_portal.views import (INDEPENDENCE_UNKNOWN, NO_SLICE_EVIDENCE, Panel,
                                   REFUSAL, slice_view)


def _pooled():
    return Panel("pooled / laya", "certified", "", '<div class="card">pooled 0.812</div>')


def _companion(state="certified"):
    return Panel("worst slice / laya", state,
                 "simultaneous claim refused" if state == REFUSAL else "",
                 '<div class="card">companion</div>')


def _rows():
    return [
        {"key": "lang", "value": "de", "n": 40, "n_cal": 40, "n_eval": 40},
        {"key": "lang", "value": "en", "n": 12, "n_cal": 12, "n_eval": 12},
        {"key": "lang", "value": "km", "n": 9, "n_cal": 9, "n_eval": 9},
    ]


def test_pooled_and_companion_are_rendered_side_by_side():
    view = slice_view(pooled=_pooled(), companion=_companion(), document={"slices": _rows()})

    assert view["html"].count('<section class="panel"') == 2
    assert "pooled / laya" in view["html"] and "worst slice / laya" in view["html"]


def test_a_pooled_number_without_a_companion_is_labelled_no_slice_evidence():
    view = slice_view(pooled=_pooled(), companion=None, document={"slices": _rows()})

    assert NO_SLICE_EVIDENCE in view["notes"]
    assert NO_SLICE_EVIDENCE in view["html"]
    assert view["html"].count('<section class="panel"') == 1


def test_each_slice_states_its_own_denominator():
    view = slice_view(pooled=_pooled(), companion=_companion(), document={"slices": _rows()})

    assert view["html"].count("n_cal=") == 3
    assert "n_cal=40 n_eval=40" in view["html"]
    assert "n_cal=9 n_eval=9" in view["html"]


def test_a_refusing_companion_heads_its_own_panel():
    view = slice_view(pooled=_pooled(), companion=_companion(REFUSAL),
                      document={"slices": _rows()})

    assert "simultaneous claim refused" in view["html"]
    panel = view["panels"][1]
    assert panel.state == REFUSAL and panel.reason == "simultaneous claim refused"


def test_independence_is_printed_only_when_the_artefact_states_it():
    silent = slice_view(pooled=_pooled(), companion=_companion(), document={"slices": _rows()})
    stated = slice_view(pooled=_pooled(), companion=_companion(),
                        document={"slices": _rows(),
                                  "shared_item_note": "the same 96 cases appear in every slice"})

    assert INDEPENDENCE_UNKNOWN in silent["html"]
    assert INDEPENDENCE_UNKNOWN not in stated["html"]
    assert "the same 96 cases appear in every slice" in stated["html"]


def test_a_degenerate_key_is_excluded_with_a_note_naming_it():
    rows = _rows() + [{"key": "qtype", "value": "single", "n": 5, "n_cal": 5, "n_eval": 5}]

    view = slice_view(pooled=_pooled(), companion=_companion(), document={"slices": rows})

    assert view["excluded"] == ("qtype",)
    assert "degenerate slice key excluded: qtype" in view["html"]
    assert "single" not in view["html"]


def test_an_over_cap_slice_list_keeps_the_smallest_ns_and_counts_the_rest():
    rows = [{"key": "lang", "value": "v%d" % i, "n": 100 - i, "n_cal": 100 - i, "n_eval": 100 - i}
            for i in range(5)]

    view = slice_view(pooled=_pooled(), companion=_companion(), document={"slices": rows}, cap=2)

    assert view["overflow"] == 3
    assert "and 3 more" in view["html"]
    assert "v4" in view["html"] and "v3" in view["html"], "the two smallest ns survive"
    assert "v0" not in view["html"], "the largest n was cut, not the smallest"


def test_a_correction_is_displayed_when_published_and_never_computed():
    published = slice_view(pooled=_pooled(), companion=_companion(),
                           document={"slices": _rows(), "correction": "bonferroni over 3 slices"})
    silent = slice_view(pooled=_pooled(), companion=_companion(), document={"slices": _rows()})

    assert "bonferroni over 3 slices" in published["html"]
    assert "correction" not in silent["html"]
