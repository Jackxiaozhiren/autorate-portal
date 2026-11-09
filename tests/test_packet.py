"""T2 build determinism, T3 AC1 refusal, AC14 idempotence, section 8.4 privacy."""
from __future__ import annotations

import io
import json
import tarfile

import pytest

from autorate_portal import EXIT_OK, EXIT_REFUSED
from autorate_portal.cli import main
from autorate_portal.packet import (ARTEFACT_PLAN, BundleError, MissingArtefact,
                                    build, read_bundle, verify_bundle)
from autorate_portal.registry import ingest, load
from conftest import (RECORD_ROW, rewrite_bundle, split_bundle, tamper_bundle)


def test_double_build_is_byte_identical(tmp_path, source_tree, build_kwargs):
    first = tmp_path / "one.tar"
    second = tmp_path / "two.tar"
    manifest_a, raw_a = build(source_tree, first, **build_kwargs)
    manifest_b, raw_b = build(source_tree, second, **build_kwargs)
    assert raw_a == raw_b
    assert manifest_a.manifest_sha256 == manifest_b.manifest_sha256
    assert manifest_a.packet_id == manifest_b.packet_id


def test_bundle_names_are_sorted_relative_and_manifest_first(built):
    with tarfile.open(built[0], mode="r:*") as tar:
        names = tar.getnames()
    assert names[0] == "manifest.json"
    assert names[1:] == sorted(names[1:])
    assert all(not name.startswith("/") and ".." not in name for name in names)
    assert all(member.mtime == 0 and member.uid == 0 for member in tarfile.open(built[0]).getmembers())


def test_missing_declared_artefact_is_named(tmp_path, source_tree, build_kwargs):
    (source_tree / "data" / "cert_laya.json").unlink()
    with pytest.raises(MissingArtefact, match="data/cert_laya.json"):
        build(source_tree, tmp_path / "out.tar", **build_kwargs)


def test_shareable_excludes_records_and_names_them(tmp_path, source_tree, build_kwargs):
    out = tmp_path / "shareable.tar"
    manifest, _ = build(source_tree, out, shareable=True, **build_kwargs)
    records = [path for path, kind in ARTEFACT_PLAN if kind == "records"]
    assert manifest.records_excluded is True
    assert manifest.excluded_records == sorted(records)
    assert all(a.kind != "records" for a in manifest.artifacts)
    assert all(not name.endswith(".jsonl") for name in read_bundle(out))
    assert len(manifest.artifacts) == len(ARTEFACT_PLAN) - len(records)


def test_tampered_byte_is_a_named_refusal_with_both_hashes(built):
    packet = built[0]
    expected, actual = tamper_bundle(packet, "data/cert_laya.json", b"tampered")
    result = verify_bundle(packet)
    assert result.ok is False
    refusal = next(r for r in result.refusals if r.path == "data/cert_laya.json")
    assert refusal.expected == expected
    assert refusal.actual == actual
    assert "bytes do not match" in refusal.reason
    assert result.manifest is None


def test_ac1_cli_refuses_and_indexes_nothing(built, tmp_path, capsys):
    packet = built[0]
    tamper_bundle(packet, "data/cert_laya.json", b"tampered")
    registry = tmp_path / "registry.json"
    rc = main(["packet", "verify", str(packet), "--registry", str(registry)])
    printed = capsys.readouterr().out
    assert rc == EXIT_REFUSED
    assert "REFUSED: data/cert_laya.json" in printed
    assert "nothing indexed" in printed
    assert not registry.exists()


def test_declared_artefact_absent_from_bundle_is_refused(built, tmp_path):
    document, files = split_bundle(built[0])
    files.pop("docs/RESULTS.md")
    target = tmp_path / "missing.tar"
    rewrite_bundle(target, files, json.dumps(document, sort_keys=True,
                                             separators=(",", ":")).encode())
    result = verify_bundle(target)
    refusal = next(r for r in result.refusals if r.path == "docs/RESULTS.md")
    assert "absent" in refusal.reason


def test_undeclared_file_is_refused(built, tmp_path):
    document, files = split_bundle(built[0])
    files["docs/UNDECLARED.md"] = b"a number nobody published\n"
    target = tmp_path / "extra.tar"
    rewrite_bundle(target, files, json.dumps(document, sort_keys=True,
                                             separators=(",", ":")).encode())
    result = verify_bundle(target)
    assert any(r.path == "docs/UNDECLARED.md" for r in result.refusals)


def test_path_traversal_in_bundle_is_refused(tmp_path):
    target = tmp_path / "evil.tar"
    buf = io.BytesIO()
    with tarfile.open(fileobj=buf, mode="w", format=tarfile.USTAR_FORMAT) as tar:
        info = tarfile.TarInfo("../outside.txt")
        info.size = 4
        tar.addfile(info, io.BytesIO(b"evil"))
    target.write_bytes(buf.getvalue())
    with pytest.raises(BundleError, match="traverses"):
        read_bundle(target)


def test_ac14_reingest_yields_one_row_and_no_duplicate_artefacts(built, tmp_path):
    registry = tmp_path / "registry.json"
    manifest = built[1]
    row_a, created_a = ingest(registry, manifest)
    row_b, created_b = ingest(registry, manifest)
    document = load(registry)
    assert created_a is True and created_b is False
    assert len(document["packets"]) == 1
    assert row_b == row_a
    assert len(row_b["artifacts"]) == len(manifest.artifacts)
    assert len({(a["path"], a["sha256"]) for a in row_b["artifacts"]}) == len(row_b["artifacts"])


def test_clean_packet_verifies_and_cli_returns_zero(built, tmp_path, capsys):
    packet, manifest, _ = built
    registry = tmp_path / "registry.json"
    assert main(["packet", "verify", str(packet), "--registry", str(registry)]) == EXIT_OK
    assert main(["packet", "verify", str(packet), "--registry", str(registry)]) == EXIT_OK
    printed = capsys.readouterr().out
    assert "idempotent hit" in printed
    assert manifest.packet_id in printed or "verified" in printed


def test_records_rows_are_never_written_into_the_shareable_bundle(tmp_path, source_tree,
                                                                   build_kwargs):
    out = tmp_path / "shareable.tar"
    build(source_tree, out, shareable=True, **build_kwargs)
    assert RECORD_ROW not in out.read_bytes()
