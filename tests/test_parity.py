"""T9 - Section 6.3: a literal fixture list, and values compared as written."""
from __future__ import annotations

import json

import parity
from autorate_portal.views import packet_header


def test_an_absent_fixture_is_named_and_the_run_fails(tmp_path, capsys):
    code = parity.main(["--frozen", str(tmp_path)])

    printed = capsys.readouterr().out
    assert code == 1
    assert "PARITY FIXTURES=%d" % len(parity.ARTEFACTS) in printed
    for name in parity.ARTEFACTS:
        assert "PARITY MISSING %s" % name in printed
    assert "PARITY FAIL" in printed


def test_the_fixture_list_is_a_literal_and_covers_every_committed_certificate():
    assert isinstance(parity.ARTEFACTS, tuple)
    assert all("*" not in name and name.startswith("data/cert_") for name in parity.ARTEFACTS)
    assert len(parity.ARTEFACTS) == 7
    assert len(set(parity.ARTEFACTS)) == 7


def test_values_are_compared_as_the_artefact_wrote_them(tmp_path):
    raw = '{"feasible": true, "alpha": 0.05, "n_cal": 600, "n_eval": 600}'
    document = json.loads(raw, parse_float=str)

    expected = parity.artefact_values(document)
    assert expected["alpha"] == "0.05", "the file's digits, not a float repr"

    same = parity.compare_values({"feasible": True, "alpha": "0.05", "n_cal": 600,
                                  "n_eval": 600}, expected)
    assert not same

    rounded = parity.compare_values({"feasible": True, "alpha": "0.05000000000000001",
                                     "n_cal": 600, "n_eval": 600}, expected)
    assert rounded and "alpha" in rounded[0]


def test_a_field_the_artefact_omits_is_compared_as_absent_not_zero():
    document = json.loads('{"feasible": false, "autorate": null}', parse_float=str)
    expected = parity.artefact_values(document)

    assert parity.compare_values({"autorate": None, "feasible": False}, expected) == []
    assert parity.compare_values({"autorate": "0", "feasible": False}, expected)


def test_the_live_verify_line_is_parsed_and_must_match_the_quoted_one():
    assert parity.parse_rederived("re-derived 612 /612 values") == "612 /612"
    assert parity.parse_rederived("re-derived 649 /649 values in 3s") == "649 /649"
    assert parity.parse_rederived("no denominator here") is None

    class _Manifest:
        packet_id = "pkt-fixture"
        protocol_digest = "abcdef123456"
        source_revision = "e9b0cf1"
        expected_rederived = "612 /612"

    assert packet_header(_Manifest())["re_derived"] == "612 /612"
