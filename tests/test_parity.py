"""T9 - Section 6.3: a literal fixture list, and values compared as written."""
from __future__ import annotations

import json

import parity
from autorate_portal.views import packet_header


def test_an_absent_fixture_is_named_and_the_run_fails(tmp_path, capsys):
    named = parity.check_fixtures(tmp_path)
    assert len(named) == 11, "the literal list names eleven artefacts, whatever the tree holds"
    assert "data/cert_laya.json" in named, "a certificate is named, not inferred from a glob"
    assert "data/slices_language.json" in named, "the slices artefact is named too"
    assert "docs/AUDIT.md" in named, "M4's audit lane is named, not globbed"
    assert "data/g1_feasibility.json" in named, "M4's feasibility arithmetic is named"

    code = parity.main(["--frozen", str(tmp_path)])

    printed = capsys.readouterr().out
    assert code == 1
    assert "PARITY FIXTURES=%d" % len(parity.ALL_ARTEFACTS) in printed
    for name in parity.ALL_ARTEFACTS:
        assert "PARITY MISSING %s" % name in printed
    assert "PARITY FAIL" in printed


def test_the_fixture_list_is_a_literal_and_covers_every_committed_certificate():
    assert isinstance(parity.ARTEFACTS, tuple)
    assert all("*" not in name and name.startswith("data/cert_") for name in parity.ARTEFACTS)
    assert len(parity.ARTEFACTS) == 7
    assert len(set(parity.ARTEFACTS)) == 7
    assert parity.SLICE_ARTEFACTS == ("data/slices_language.json",)


def test_the_quoted_denominator_is_read_from_the_published_readme(tmp_path):
    (tmp_path / "README.md").write_text("a stranger reproduces `re-derived 612 /612 values`\n",
                                        encoding="utf-8")

    assert parity.published_denominator(tmp_path) == "612 /612"


def test_a_slices_artefact_renders_every_group_with_its_own_denominator():
    document = {"group_key": "language",
                "run": {"groups": ["language"],
                        "per_group": {"de": {"n_cal": 1487, "n_eval": 1487, "feasible": False,
                                             "reason": "empty_feasible_set"},
                                      "km": {"n_cal": 402, "n_eval": 402, "feasible": False,
                                             "reason": "empty_feasible_set"}}}}

    from types import SimpleNamespace
    manifest = SimpleNamespace(rubric={"alpha": 0.05}, packet_id="pkt-test",
                               protocol_digest="abcdef123456")
    total, refused, problems = parity.slice_report(document, manifest)

    assert (total, refused, problems) == (2, 2, [])


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
