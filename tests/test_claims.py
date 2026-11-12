"""T1 — F4: three verdicts, AC5, provenance, no invented point estimate."""
from __future__ import annotations

from types import SimpleNamespace

import pytest

from autorate_portal import claims, db

RUBRIC = {"alpha": 0.05, "beta": 0.05, "delta": 0.05, "seed": 7,
          "method": "aps", "unit": "case"}
DIGEST = "abcdef123456"

CERT_DOC = {
    "alpha": 0.05, "beta": 0.05, "delta": 0.05, "backend": "fixture",
    "autorate": None, "bound": None, "feasible": False,
    "reason": "empty_feasible_set", "n_cal": 96, "n_eval": 96,
    "meta": {"at_requested_alpha": {"bound_unit": "case"}},
}


def _manifest():
    return SimpleNamespace(packet_id="pkt-fixture", protocol_digest=DIGEST,
                           rubric=RUBRIC, bound_unit="case", expected_rederived="612 /612",
                           excluded_records=[], records_excluded=False, artifacts=[])


def _packet():
    return SimpleNamespace(id="pkt-row-1", protocol_digest=DIGEST)


def _summary(**overrides):
    values = dict(task="jev", backend="fixture", feasible=False,
                  reason="empty_feasible_set", autorate=None, bound=None,
                  bound_unit="case", n_cal=96, n_eval=96, alpha="0.05",
                  beta="0.05", delta="0.05")
    values.update(overrides)
    return db.CertificateSummary(**values)


def _check(share="0.66", field="autorate", *, summary=None, certificates=None, **kwargs):
    return claims.check(
        claim=claims.Claim(share=share, field=field, unit="case", population="resolutions"),
        summaries=[summary] if summary is not None else [],
        packet=_packet(), manifest=_manifest(),
        certificates=certificates if certificates is not None else [CERT_DOC], **kwargs)


def test_the_verdict_vocabulary_is_closed_at_exactly_three():
    assert claims.VERDICTS == ("bounded_supports", "bounded_refutes", "cannot_be_bounded")


def test_ac5_a_share_above_the_certified_autorate_refutes_with_both_numbers_and_units():
    summary = _summary(feasible=True, autorate="0.42", bound="0.05", reason=None)
    verdict = _check("0.66", summary=summary,
                     certificates=[{**CERT_DOC, "feasible": True, "autorate": "0.42"}])

    assert verdict.verdict == claims.BOUNDED_REFUTES
    assert "0.66" in verdict.reason and "0.42" in verdict.reason
    assert [row["unit"] for row in verdict.numbers] == ["case", "case"]
    assert [row["value"] for row in verdict.numbers] == ["0.66", "0.42"]
    assert "denominator:" in verdict.provenance and "packet:" in verdict.provenance
    assert verdict.bound == "0.05"
    assert verdict.denominator == "n_cal=96 n_eval=96"


def test_a_share_below_the_certified_autorate_supports():
    summary = _summary(feasible=True, autorate="0.42", bound="0.05", reason=None)
    verdict = _check("0.30", summary=summary,
                     certificates=[{**CERT_DOC, "feasible": True, "autorate": "0.42"}])
    assert verdict.verdict == claims.BOUNDED_SUPPORTS


def test_the_real_refusing_packet_cannot_be_bounded_and_does_not_refute():
    verdict = _check(summary=_summary())

    assert verdict.verdict == claims.CANNOT_BE_BOUNDED
    assert "never published" in verdict.reason or "no certificate" in verdict.reason
    assert verdict.numbers == (), "no certified autorate means no invented number"


def test_f4_exception_b_no_packet_routes_to_f1_with_one_command():
    verdict = claims.check(
        claim=claims.Claim(share="0.66", field="autorate", unit="case",
                           population="resolutions"),
        summaries=[], packet=None, manifest=None)

    assert verdict.verdict == claims.CANNOT_BE_BOUNDED
    assert "packet build" in verdict.reason
    assert verdict.provenance.count("unavailable") == 4


def test_f4_rule_4_a_non_numeric_share_produces_no_point_estimate():
    summary = _summary(feasible=True, autorate="0.42", bound="0.05", reason=None)
    verdict = _check("about two thirds", summary=summary,
                     certificates=[{**CERT_DOC, "feasible": True, "autorate": "0.42"}])

    assert verdict.verdict == claims.CANNOT_BE_BOUNDED
    assert verdict.numbers == ()
    assert "no point estimate" in verdict.reason


def test_every_verdict_carries_the_i2_provenance_line():
    for verdict in (_check(summary=_summary()),
                    _check("0.66", summary=_summary(feasible=True, autorate="0.42",
                                                    bound="0.05", reason=None),
                           certificates=[{**CERT_DOC, "feasible": True, "autorate": "0.42"}])):
        for part in ("denominator:", "budget/rubric:", "packet:", "bound_unit:"):
            assert part in verdict.provenance
        assert DIGEST in verdict.provenance
        assert verdict.card().find("data-state=") >= 0


def test_claim_from_dict_refuses_a_partial_claim():
    with pytest.raises(claims.ClaimError):
        claims.Claim.from_dict({"share": "0.66", "field": "autorate"})
    assert claims.Claim.from_dict(
        {"share": "0.66", "field": "autorate", "unit": "case",
         "population": "resolutions"}).field == "autorate"
