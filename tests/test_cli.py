"""T5/T7 - command surface and exit-code hygiene (PRD section 13.1)."""
from __future__ import annotations

import json

import pytest

from autorate_portal import EXIT_OK, EXIT_REFUSED, EXIT_USAGE
from autorate_portal.cli import main
from conftest import tamper_bundle


def test_help_names_every_subcommand(capsys):
    with pytest.raises(SystemExit) as exc:
        main(["--help"])
    assert exc.value.code == 0
    printed = capsys.readouterr().out
    for word in ("packet", "verify-packet", "usage:"):
        assert word in printed


def test_unknown_command_is_a_usage_error(capsys):
    with pytest.raises(SystemExit) as exc:
        main(["certify"])
    assert exc.value.code == EXIT_USAGE
    assert "invalid choice" in capsys.readouterr().err


def test_build_from_an_empty_tree_refuses_and_names_the_artefact(tmp_path, build_kwargs, capsys):
    out = tmp_path / "out.tar"
    rc = main(["packet", "build", "--source", str(tmp_path / "empty"),
               "--out", str(out), "--revision", build_kwargs["source_revision"]])
    assert rc == EXIT_REFUSED
    assert "declared by the packet artefact plan" in capsys.readouterr().err
    assert not out.exists()


def test_html_on_a_tampered_packet_refuses_without_writing(built, tmp_path, capsys):
    packet, _, _ = built
    tamper_bundle(packet, "data/cert_laya.json", b"tampered")
    out = tmp_path / "view.html"
    assert main(["packet", "html", str(packet), "-o", str(out)]) == EXIT_REFUSED
    assert "nothing indexed" in capsys.readouterr().out
    assert not out.exists()


def test_exit_codes_are_distinct():
    assert len({EXIT_OK, EXIT_USAGE, 3, EXIT_REFUSED}) == 4


def test_verify_without_a_registry_still_returns_zero(built, capsys):
    assert main(["packet", "verify", str(built[0])]) == EXIT_OK
    assert "verified" in capsys.readouterr().out


def test_runs_list_names_rows_that_carry_no_channel(tmp_path, capsys):
    store = tmp_path / "runs.jsonl"
    store.write_text('{"run_id": "r1", "state": "certified"}\n', encoding="utf-8")
    assert main(["runs", "list", "--runs", str(store)]) == 0
    out = capsys.readouterr().out
    assert "unknown" in out
    assert "carry no channel" in out


def test_export_build_writes_a_recheckable_bundle(m4_built, tmp_path, capsys):
    packet, manifest, _raw = m4_built
    out = tmp_path / "annex_iv.json"

    assert main(["export", "build", str(packet), "--kind", "annex_iv", "-o", str(out)]) == EXIT_OK
    printed = capsys.readouterr().out
    assert "bundle_sha256" in printed and "gaps" in printed
    assert manifest.packet_id in printed

    written = out.read_bytes()
    assert main(["export", "recheck", str(out)]) == EXIT_OK
    assert "recheck          : ok" in capsys.readouterr().out
    assert written == out.read_bytes()


def test_export_recheck_names_a_tampered_bundle(m4_built, tmp_path, capsys):
    packet, _manifest, _raw = m4_built
    out = tmp_path / "aap.json"
    assert main(["export", "build", str(packet), "--kind", "aap", "-o", str(out)]) == EXIT_OK

    # The hash covers the canonical payload, so reformatting the file must not
    # break it; changing a value must. Tamper with a value, not with whitespace.
    document = out.read_text(encoding="utf-8")
    out.write_text(document.replace("pkt-", "pkt-0", 1), encoding="utf-8")
    assert main(["export", "recheck", str(out)]) == EXIT_REFUSED
    assert "does not match its payload" in capsys.readouterr().out


def test_export_refuses_an_unknown_kind_as_usage(tmp_path):
    with pytest.raises(SystemExit) as exc:
        main(["export", "build", "whatever.tar", "--kind", "soc2"])
    assert exc.value.code == EXIT_USAGE


def test_export_is_blocked_by_a_recorded_mismatch_and_names_the_run(m4_built, tmp_path, capsys):
    packet, manifest, _raw = m4_built
    store = tmp_path / "runs.jsonl"
    store.write_text(json.dumps({"run_id": "run-bbb", "packet_id": manifest.packet_id,
                                 "state": "mismatch"}) + "\n", encoding="utf-8")

    rc = main(["export", "build", str(packet), "--kind", "annex_iv",
               "--runs", str(store), "-o", str(tmp_path / "blocked.json")])
    printed = capsys.readouterr().out
    assert rc == EXIT_REFUSED
    assert "run-bbb" in printed
    assert not (tmp_path / "blocked.json").exists()


def test_export_on_a_tampered_packet_refuses_before_assembling(m4_built, tmp_path, capsys):
    packet, _manifest, _raw = m4_built
    tamper_bundle(packet, "docs/REPORT.md", b"tampered")
    out = tmp_path / "annex_iv.json"
    assert main(["export", "build", str(packet), "--kind", "annex_iv", "-o", str(out)]) == EXIT_REFUSED
    assert "nothing indexed" in capsys.readouterr().out
    assert not out.exists()
