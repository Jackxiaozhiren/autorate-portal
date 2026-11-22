"""Section 11's CI step must read the state word from the catalog, not restate it.

The step and ``test_views_locale`` check the same thing. When the V1 vocabulary
guard changed the refusal state to a verdict ("not statistically feasible"), the
test followed the catalog and the step kept the old words, so the run went red on
a step whose product behaviour was already correct. One source of truth means the
step asks the catalog, not a literal.
"""
from __future__ import annotations

from pathlib import Path

WORKFLOW = Path(__file__).resolve().parents[1] / ".github" / "workflows" / "ci.yml"


def test_the_localization_step_reads_the_state_word_from_the_catalog():
    text = WORKFLOW.read_text(encoding="utf-8")
    step = text.split("Section 11 localization", 1)[1].split("- name:", 1)[0]
    assert "i18n.state_word(locale, 'refusal')" in step
    assert "'拒绝' in pages" not in step, "a translated word cannot be restated here"
    assert "'refusal' in pages" not in step, "a translated word cannot be restated here"
