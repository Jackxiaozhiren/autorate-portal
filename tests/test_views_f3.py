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


def _slices_artefact(**patches):
    """The shape `data/slices_language.json` actually publishes (run.per_group)."""
    groups = {}
    for name, n in (("de", 1487), ("en", 1512), ("km", 402), ("sw", 388)):
        groups[name] = {"n_cal": n, "n_eval": n, "feasible": False, "autorate": None,
                        "conditional_error_bound": None, "marginal_error_bound": None,
                        "reason": "empty_feasible_set", "alpha": 0.0125, "beta": 0.05,
                        "delta": 0.0125, "method": "aps",
                        "envelope": ["no certificate exists, so no action is certified"],
                        "meta": {"alpha": 0.0125, "beta": 0.05, "seed": 7}}
    groups.update(patches)
    return {"group_key": "language",
            "run": {"groups": ["language"], "per_group": groups,
                    "alpha": 0.05, "beta": 0.05, "delta": 0.05,
                    "corrected_alpha": 0.0125, "corrected_beta": 0.0125, "corrected_delta": 0.0125}}


def test_a_published_slices_artefact_is_read_from_run_per_group():
    view = slice_view(pooled=_pooled(), companion=_companion(), document=_slices_artefact())

    assert 'data-state="refusal"' in view["html"]
    for name, n in (("de", 1487), ("en", 1512), ("km", 402), ("sw", 388)):
        assert "language: %s" % name in view["html"]
        assert "n_cal=%d n_eval=%d" % (n, n) in view["html"]
    assert view["html"].count("empty_feasible_set") == 4, "each group keeps its own reason"
    for chunk in view["html"].split('data-state="refusal"')[1:]:
        assert "<code>" not in chunk.split("</div>", 1)[0], "a refused group carries no number"


def test_a_group_that_refuses_carries_its_reason_and_no_number():
    row_html = slice_view(pooled=_pooled(), companion=_companion(),
                          document=_slices_artefact())["html"]

    assert '<p class="reason">empty_feasible_set</p>' in row_html
    assert "no certificate exists" not in row_html, "the envelope is not the reason"


def test_a_group_that_publishes_a_bound_goes_through_emit_and_refuses_without_a_unit():
    artefact = _slices_artefact(de={"n_cal": 100, "n_eval": 100, "feasible": True,
                                    "autorate": "0.660000", "reason": None,
                                    "conditional_error_bound": "0.310000", "alpha": 0.0125,
                                    "beta": 0.05, "delta": 0.0125, "method": "aps",
                                    "meta": {"alpha": 0.0125, "beta": 0.05, "seed": 7}})

    without_context = slice_view(pooled=_pooled(), companion=_companion(),
                                 document=artefact)["html"]
    assert "unavailable: packet id + protocol digest" in without_context
    assert "0.310000" not in without_context, "a bound without its triple is not a claim"

    without_unit = slice_view(pooled=_pooled(), companion=_companion(), document=artefact,
                              context={"rubric": {"alpha": "0.05", "beta": "0.05", "delta": "0.05",
                                                  "method": "aps", "seed": "7"},
                                       "packet_id": "pkt-row-1",
                                       "protocol_digest": "abcdef123456",
                                       "bound_unit": None})["html"]
    assert "unavailable: bound_unit" in without_unit
    assert "0.310000" not in without_unit, "a bound without its unit is not a claim"

    with_context = slice_view(pooled=_pooled(), companion=_companion(), document=artefact,
                              context={"rubric": {"alpha": "0.05", "beta": "0.05", "delta": "0.05",
                                                  "method": "aps", "seed": "7"},
                                       "packet_id": "pkt-row-1",
                                       "protocol_digest": "abcdef123456",
                                       "bound_unit": "case"})["html"]
    assert "0.310000" in with_context
    assert "pkt-row-1 / abcdef123456" in with_context
    assert "bound_unit: case" in with_context
    assert "n_cal=100 n_eval=100" in with_context
    assert "alpha=0.0125" in with_context, "the group's own budget, not the certificate's 0.05"
    assert "0.660000" not in with_context, "the rate is not the worst-slice bound"


def test_a_published_rate_is_never_rendered_as_the_worst_slice_bound():
    artefact = _slices_artefact(km={"n_cal": 402, "n_eval": 402, "feasible": True,
                                    "autorate": "0.660000", "reason": None,
                                    "conditional_error_bound": None, "marginal_error_bound": None,
                                    "alpha": 0.0125, "beta": 0.05, "delta": 0.0125, "method": "aps",
                                    "meta": {"seed": 7, "bound_unit": "case"}})

    html = slice_view(pooled=_pooled(), companion=_companion(), document=artefact)["html"]

    assert "0.660000" not in html, "a rate published beside a missing bound is not a bound"
    assert "unavailable" not in html, "a group with no bound is simply a refusal row"
    assert 'data-state="refusal"' in html


def test_the_published_correction_is_displayed_and_never_applied():
    artefact = _slices_artefact()

    html = slice_view(pooled=_pooled(), companion=_companion(), document=artefact)["html"]

    assert "correction (published by the artefact):" in html
    assert "corrected alpha 0.0125" in html
    assert "uncorrected alpha 0.05" in html
