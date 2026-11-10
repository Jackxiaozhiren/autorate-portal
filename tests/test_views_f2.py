"""T6 - F2: a refusal is a verdict, and a number carries its whole triple."""
from __future__ import annotations

from autorate_portal import db
from autorate_portal.views import (ABSENT_NUMBER, CERTIFIED, DISCLOSURE, REFUSAL, UNAVAILABLE,
                                   certificate_panel)

RUBRIC = {"alpha": 0.05, "beta": 0.05, "delta": 0.05, "method": "aps", "seed": 7, "unit": "case"}
DIGEST = "abcdef123456"


def _packet(digest=DIGEST):
    return db.Packet(id="pkt-row-1", protocol_digest=digest, manifest_sha256="f" * 64)


def _summary(**overrides):
    values = dict(task="laya", backend="laya", feasible=True, reason="",
                  autorate="0.812", bound="0.19", bound_unit="case",
                  n_cal=600, n_eval=600, alpha="0.05", beta="0.05", delta="0.05")
    values.update(overrides)
    return db.CertificateSummary(**values)


def _panel(summary=None, certificate=None, mismatch=None, rubric=RUBRIC):
    return certificate_panel(summary=summary or _summary(), packet=_packet(), rubric=rubric,
                             certificate=certificate or {}, mismatch=mismatch)


def test_ac2_a_refusal_prints_the_reason_verbatim_and_no_number_at_all():
    panel = _panel(_summary(feasible=False, reason="empty_feasible_set", autorate=None,
                            bound=None, bound_unit=None))

    assert panel.state == REFUSAL
    assert "empty_feasible_set" in panel.body, "the artefact's own words, not a paraphrase"
    assert panel.numbers == (), "a refusal has no numbers to show"
    assert "0" not in panel.body.replace("0.05", "")
    assert "no data" not in panel.body.lower()
    assert panel.body.strip()


def test_ac3_a_number_carries_denominator_budget_packet_and_unit_in_one_component():
    panel = _panel()

    assert panel.state == CERTIFIED
    cards = [card.split("</p></div>", 1)[0]
             for card in panel.body.split('<div class="card">')[1:]]
    assert len(cards) == len(panel.numbers) >= 1, "one card per number, no number outside a card"
    for card in cards:
        for component in ("denominator:", "budget/rubric:", "packet:", "bound_unit:"):
            assert component in card, "%s is not in the same component as its number" % component
        assert "<code>" in card, "a card without a number is not a statistic"

    autorate = next(card for card in cards if "autorate" in card)
    assert "0.812" in autorate
    assert "n_cal=600 n_eval=600" in autorate
    assert "alpha=0.05 beta=0.05 delta=0.05 method=aps seed=7" in autorate
    assert "pkt-row-1 / abcdef123456" in autorate
    assert "bound_unit: case" in autorate


def test_a_field_the_artefact_omits_reads_as_not_published_not_as_zero():
    panel = _panel(_summary(autorate=None))

    assert ABSENT_NUMBER in panel.body
    assert ">0<" not in panel.body
    assert [number for number in panel.numbers if number["label"] == "autorate"][0]["value"] is None


def test_a_number_without_its_unit_is_unavailable_rather_than_printed_alone():
    panel = _panel(_summary(bound_unit=None))

    assert "unavailable: bound_unit" in panel.body
    assert "0.19" not in panel.body, "a bound with no unit is not a measurable claim"


def test_a_provenance_mismatch_names_both_digests_and_strikes_the_number_through():
    panel = _panel(mismatch=("a" * 64, "b" * 64))

    assert "provenance mismatch" in panel.body
    assert "a" * 64 in panel.body and "b" * 64 in panel.body
    assert "<s>" in panel.body and "0.812" in panel.body
    assert panel.body.index("<s>") < panel.body.index("0.812")


def test_a_closest_attempt_appears_only_under_the_disclosure():
    certificate = {"closest_attempt": {"alpha": 0.11, "note": "near miss"},
                   "diagnostic_note": "selected on eval"}

    panel = _panel(certificate=certificate)

    assert DISCLOSURE in panel.body
    assert "selected on eval" in panel.body
    assert panel.body.index(DISCLOSURE) < panel.body.index("near miss")


def test_a_certificate_that_omits_feasibility_is_unavailable_not_assumed():
    panel = _panel(_summary(feasible=None))

    assert panel.state == UNAVAILABLE
    assert "unavailable: feasible" in panel.body
    assert panel.numbers == ()
