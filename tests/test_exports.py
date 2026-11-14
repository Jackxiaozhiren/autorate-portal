"""T3 — F5: source quadruples, known_limits, determinism, AC7, honest gaps."""
from __future__ import annotations

import json
from types import SimpleNamespace

import pytest

from autorate_portal import exports
from autorate_portal.engine import deciding_row, recorded_mismatch
from autorate_portal.packet import verify_bundle
from conftest import KNOWN_LIMITS


@pytest.fixture
def world(m4_built):
    path, manifest, _raw = m4_built
    verification = verify_bundle(path)
    assert verification.ok and verification.manifest is not None
    packet = SimpleNamespace(id="pkt-row-1", protocol_digest=manifest.protocol_digest,
                             ingested_at="2026-11-12T00:00:00", project_id="prj-1")
    return verification.manifest, packet, verification.files


def _build(world, kind="annex_iv", **kwargs):
    manifest, packet, files = world
    return exports.build_bundle(kind=kind, manifest=manifest, packet=packet,
                                files=files, **kwargs)


def test_the_three_kinds_match_section_4_3_and_every_line_names_its_full_source(world):
    assert exports.KINDS == ("annex_iv", "iso_42001", "aap")
    for kind in exports.KINDS:
        bundle = _build(world, kind)
        assert not bundle.blocked
        assert bundle.lines
        for line in bundle.lines:
            assert line["source_path"]
            assert len(line["sha256"]) == 64
            assert line["protocol_digest"] == world[1].protocol_digest
            assert line["packet_id"] == world[0].packet_id


def test_a_line_without_a_source_fails_the_build_of_the_bundle():
    with pytest.raises(exports.ExportRefused, match="no source_path"):
        exports._line(heading="x", path="", digest="a" * 64,
                      protocol_digest="abcdef123456", packet_id="pkt-1")
    with pytest.raises(exports.ExportRefused, match="no sha256"):
        exports._line(heading="x", path="docs/REPORT.md", digest="",
                      protocol_digest="abcdef123456", packet_id="pkt-1")


def test_known_limits_is_its_own_section_and_cannot_be_omitted(world):
    bundle = _build(world)
    assert bundle.known_limits == tuple(KNOWN_LIMITS)
    document = json.loads(bundle.raw)
    assert document["known_limits"] == KNOWN_LIMITS
    assert "cannot be omitted" in document["known_limits_note"]

    manifest, packet, files = world
    stripped = dict(files)
    stripped["protocol.json"] = json.dumps({"rubric": {}}).encode()
    with pytest.raises(exports.ExportRefused, match="known_limits"):
        exports.build_bundle(kind="annex_iv", manifest=manifest, packet=packet,
                             files=stripped)


def test_f5_rule_4_double_build_is_byte_identical_and_records_its_own_hash(world):
    first, second = _build(world), _build(world)
    assert first.raw == second.raw
    assert first.bundle_sha256 == second.bundle_sha256
    assert exports.recheck(first.raw) == first.bundle_sha256
    assert json.loads(first.raw)["bundle_sha256"] == first.bundle_sha256


def test_f5_exception_b_a_heading_without_a_source_emits_no_evidence_published(world):
    manifest, packet, files = world
    reduced = {key: value for key, value in files.items() if key != "docs/REPORT.md"}

    bundle = exports.build_bundle(kind="annex_iv", manifest=manifest, packet=packet,
                                  files=reduced)

    assert "system_description" in bundle.gaps
    document = json.loads(bundle.raw)
    gap = next(row for row in document["gaps"] if row["heading"] == "system_description")
    assert gap["state"] == exports.NO_EVIDENCE
    assert all(line["source_path"] != "docs/REPORT.md" for line in bundle.lines)


def test_ac7_a_source_that_no_longer_rederives_blocks_the_export(world):
    manifest, packet, files = world
    stale = dict(files)
    stale["docs/REPORT.md"] = stale["docs/REPORT.md"] + b"\n"

    bundle = exports.build_bundle(kind="annex_iv", manifest=manifest, packet=packet,
                                  files=stale)

    assert bundle.blocked
    assert bundle.raw == b"" and bundle.lines == ()
    assert "export blocked" in bundle.block_reason
    assert "no replay row records a mismatch" in bundle.block_reason


def test_ac7_names_the_replay_run_that_showed_the_mismatch_when_one_exists(world, m4_replay_engine):
    """The row comes from the product's own writer, keyed to this packet."""
    manifest, _packet, _files = world
    _path, _store, replay = m4_replay_engine
    row = replay(stdout="re-derived 611 /612 values\n")
    assert row["state"] == "mismatch", "the engine recorded the mismatch"
    assert row["packet_id"] == manifest.packet_id

    bundle = _build(world, run_row=row)

    assert bundle.blocked
    assert bundle.lines == ()
    assert bundle.run_id == row["run_id"]
    assert row["run_id"] in bundle.block_reason


def test_ac7_the_deciding_row_is_the_last_observation_not_the_last_line(tmp_path, world):
    """A ``not-run``/``refused`` row is not an observation: it cannot clear a mismatch.

    AC10 says ``not-run`` is never a pass; reading the literal last line would
    let one ordinary command lift a recorded mismatch and re-open the export.
    """
    manifest, _packet, _files = world
    store = tmp_path / "runs.jsonl"
    wheel = "a" * 64

    def write(*states: str, packet: str | None = None, wheel_sha256: str = wheel) -> None:
        store.write_text("".join(
            json.dumps({"run_id": "r%d" % number, "state": state,
                        "packet_id": packet or manifest.packet_id,
                        "wheel_sha256": wheel_sha256}) + "\n"
            for number, state in enumerate(states)), encoding="utf-8")

    for states in (("mismatch", "not-run"), ("mismatch", "refused")):
        write(*states)
        row = deciding_row(store, manifest.packet_id)
        assert recorded_mismatch(row), states

    write("mismatch", "certified")
    assert not recorded_mismatch(deciding_row(store, manifest.packet_id))

    write("certified", "mismatch")
    assert recorded_mismatch(deciding_row(store, manifest.packet_id))

    write("not-run")
    assert deciding_row(store, manifest.packet_id) is None

    write("mismatch", packet="another-packet")
    assert deciding_row(store, manifest.packet_id) is None

    # The pin is not part of packet_id, so a re-sealed copy shares the id and is
    # decided by the same rows. Over-blocking is fail-closed; matching the pin
    # would let a one-field manifest edit launder a recorded mismatch.
    write("mismatch", wheel_sha256="b" * 64)
    assert recorded_mismatch(deciding_row(store, manifest.packet_id))


def test_ac7_a_refused_replay_row_does_not_block_a_source_that_still_rederives(world,
                                                                                m4_replay_engine):
    """``refused`` also exits 4; only ``state == "mismatch"`` may block a bundle."""
    _path, _store, replay = m4_replay_engine
    row = replay(registry_sha256="0" * 64)
    assert row["state"] == "refused" and row["rc"] == 4

    bundle = _build(world, run_row=row)

    assert not bundle.blocked and bundle.lines


def test_ac7_the_latest_observation_for_the_packet_wins(world, m4_replay_engine):
    """A later successful replay supersedes an earlier mismatch (export time)."""
    manifest, _packet, _files = world
    _path, store, replay = m4_replay_engine
    stale = replay(stdout="re-derived 611 /612 values\n")
    fresh = replay()
    assert stale["state"] == "mismatch" and fresh["state"] == "certified"

    row = deciding_row(store, manifest.packet_id)
    assert row is not None and row["run_id"] == fresh["run_id"]

    bundle = _build(world, run_row=row)

    assert not bundle.blocked and bundle.lines
    assert bundle.run_id == ""


def test_an_unknown_kind_is_a_named_refusal_not_a_generic_bundle(world):
    with pytest.raises(exports.ExportRefused, match="unknown bundle kind"):
        _build(world, "generic_aap")
