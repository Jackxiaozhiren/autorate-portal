"""T2 — F4 against the audit lane and the published feasibility arithmetic (AC6)."""
from __future__ import annotations

import re

from autorate_portal import claims, i18n
from conftest import M4_AUDIT_TEXT, M4_FEASIBILITY
from test_claims import CERT_DOC, _check, _summary


def test_ac6_a_field_the_packet_never_measured_is_cannot_be_bounded_with_comparability():
    verdict = _check("0.66", "confidence", summary=_summary(), audit_text=M4_AUDIT_TEXT)

    assert verdict.verdict == "cannot_be_bounded"
    assert claims.COMPARABILITY_QUOTE in verdict.comparability
    assert claims.DEFINITION_SLIP_QUOTE in verdict.comparability
    assert "same-named fields are not the same quantity" in verdict.reason
    assert verdict.numbers == ()


def test_the_audit_lane_is_labelled_markdown_and_never_parsed_into_a_bound():
    verdict = _check("0.66", "confidence", summary=_summary(), audit_text=M4_AUDIT_TEXT)

    assert any("Markdown" in label for label in verdict.audit_labels)
    assert any("quoted, not parsed" in label for label in verdict.audit_labels)
    assert verdict.bound == "not published by this certificate"
    assert not re.search(r"bound\s*=\s*0\.\d+", verdict.reason)


def test_implied_error_and_point_estimate_are_labelled_as_distinct_classes():
    verdict = _check("0.66", "confidence", summary=_summary(), audit_text=M4_AUDIT_TEXT)
    labels = set(verdict.audit_labels)
    assert i18n.t("en", "text.implied_error") in labels
    assert i18n.t("en", "text.point_estimate") in labels
    assert i18n.t("en", "text.nothing_certifies") in labels


def test_cannot_be_bounded_reads_the_published_feasibility_arithmetic():
    verdict = _check(summary=_summary(), audit_text=M4_AUDIT_TEXT,
                     feasibility=M4_FEASIBILITY)

    assert verdict.verdict == "cannot_be_bounded"
    assert "errors INSIDE the automated set" in verdict.additional_data
    assert "n=100" in verdict.additional_data and "k_max=1" in verdict.additional_data
    assert any(row["path"] == "data/g1_feasibility.json" for row in verdict.evidence)


def test_f4_rule_3_no_required_sample_size_is_invented_when_the_artefact_has_none():
    verdict = _check(summary=_summary(), feasibility=M4_FEASIBILITY)

    assert "no n_min or required_n" in verdict.additional_data
    assert not re.search(r"(n_min|required_n)\s*=\s*\d+", verdict.additional_data)
    assert "no sample size is invented" in verdict.additional_data


def test_a_packet_without_the_audit_quotes_says_so_instead_of_borrowing_words():
    verdict = _check("0.66", "confidence", summary=_summary(), audit_text="")

    assert "does not publish the comparability statement" in verdict.comparability
    assert "no substitute is quoted" in verdict.comparability


def test_a_packet_without_feasibility_arithmetic_says_so():
    verdict = _check(summary=_summary(), feasibility=None)

    assert "publishes no feasibility arithmetic" in verdict.additional_data
    assert not re.search(r"\bn\s*=\s*\d+", verdict.additional_data)


def test_the_comparability_quotes_are_verbatim_substrings_of_the_audit_fixture():
    for key, quote in claims.AUDIT_QUOTES.items():
        assert quote in M4_AUDIT_TEXT, key
    assert claims.audit_quotes(M4_AUDIT_TEXT) == claims.AUDIT_QUOTES
    assert all(value == "" for value in claims.audit_quotes("").values())


def test_published_field_names_come_from_certificates_not_from_wishful_thinking():
    names = claims.published_field_names([CERT_DOC])
    assert "autorate" in names
    assert "confidence" not in names
    assert claims.published_field_names([]) == frozenset()
