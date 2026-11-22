"""T6: four state vocabularies, four display terms, no shared `certified`.

The machine values are contracts and stay as they are. What changes is the word
a reader sees, and the coverage assertions below are what keeps the mapping
honest after this commit: a state added to any layer without a term fails here
rather than reaching a screen under someone else's name.
"""
from __future__ import annotations

import json
from pathlib import Path

import pytest

from autorate_portal import badge, engine, i18n, monitor, vocabulary

ROOT = Path(__file__).resolve().parents[1]


def test_every_run_state_has_a_term():
    assert vocabulary.states("run") == frozenset(engine.STATES)


def test_every_badge_state_has_a_term():
    assert vocabulary.states("badge") == frozenset(badge.STATES)


def test_every_monitor_verdict_has_a_term():
    assert vocabulary.states("monitor") == frozenset(monitor.VERDICTS)


def test_every_render_state_has_a_term():
    assert vocabulary.states("certificate") == frozenset(i18n.RENDER_STATES)


def test_no_layer_calls_a_different_state_certified():
    for layer, table in vocabulary.LAYERS.items():
        for state, term in table.items():
            assert term.lower() != "certified", (layer, state)


def test_the_certificate_screen_uses_the_statistical_term():
    assert i18n.state_word("en", "certified") == "statistically feasible"
    assert i18n.state_word("en", "refusal") == "not statistically feasible"
    assert i18n.state_word("zh-Hans", "certified") == "统计可行"
    assert i18n.state_word("zh-Hans", "refusal") == "统计不可行"


def test_no_certificate_state_entry_reads_as_certified():
    catalog = json.loads((ROOT / "src" / "autorate_portal" / "catalog.json").read_text(encoding="utf-8"))
    for language, table in catalog.items():
        for key, value in table.items():
            if key.startswith("state."):
                assert value.strip().lower() != "certified", (language, key)


def test_the_badge_carries_the_qualified_term_in_its_accessible_name():
    svg = badge._svg("certified", "612 /612")
    assert "verify passed" in svg
    assert "aria-label" in svg


def test_an_unknown_state_is_a_named_error():
    with pytest.raises(vocabulary.UnknownState):
        vocabulary.display("run", "invented")
    with pytest.raises(vocabulary.UnknownState):
        vocabulary.display("invented", "certified")
