"""T5/T7 - command surface and exit-code hygiene (PRD section 13.1)."""
from __future__ import annotations

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
