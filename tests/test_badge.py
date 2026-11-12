"""T7 — badge-as-shareable: F8's vocabulary, zero records, provenance, determinism."""
from __future__ import annotations

from types import SimpleNamespace

import pytest

from autorate_portal import badge, db, i18n
from autorate_portal.packet import build, verify_bundle


@pytest.fixture
def world(m4_built):
    path, manifest, _raw = m4_built
    verification = verify_bundle(path)
    assert verification.ok
    packet = SimpleNamespace(id="pkt-row-1", protocol_digest=manifest.protocol_digest)
    return verification.manifest, packet


@pytest.fixture
def shareable_world(tmp_path, m4_source_tree, build_kwargs):
    out = tmp_path / "shareable.packet.tar"
    manifest, _raw = build(m4_source_tree, out, shareable=True, **build_kwargs)
    verification = verify_bundle(out)
    assert verification.ok
    packet = SimpleNamespace(id="pkt-row-1", protocol_digest=manifest.protocol_digest)
    return verification.manifest, packet


def _summary(**overrides):
    values = dict(task="jev", backend="fixture", feasible=False,
                  reason="empty_feasible_set", autorate=None, bound=None,
                  bound_unit="case", n_cal=96, n_eval=96)
    values.update(overrides)
    return db.CertificateSummary(**values)


def test_f8_vocabulary_is_closed_and_never_boolean():
    assert badge.STATES == ("certified", "not-certifiable", "drift", "not-run")
    assert badge.state_for([]) == badge.NOT_RUN
    assert badge.state_for([_summary()]) == badge.NOT_CERTIFIABLE
    assert badge.state_for([_summary(feasible=True, autorate="0.42",
                                     reason=None)]) == badge.CERTIFIED


def test_the_shareable_badge_carries_the_published_triple_and_no_records(world):
    manifest, packet = world
    result = badge.shareable_badge(manifest=manifest, packet=packet,
                                   summaries=[_summary()])

    assert result.state == "not-certifiable"
    assert result.record["packet_id"] == manifest.packet_id
    assert result.record["protocol_digest"] == packet.protocol_digest
    assert result.record["denominator_line"] == "re-derived 612 /612 values"
    assert result.record["records_included"] is False
    assert result.record["records_rows"] == 0
    assert b".jsonl" not in result.raw
    assert b"secret-conversation-row" not in result.raw
    assert "not a boolean" in result.record["state_meaning"]


def test_unverified_provenance_travels_with_the_shareable_copy(world):
    manifest, packet = world
    result = badge.shareable_badge(manifest=manifest, packet=packet,
                                   summaries=[_summary()],
                                   provenance_badge="unverified_provenance")
    assert result.provenance_badge == "unverified_provenance"
    assert result.record["provenance_badge"] == "unverified_provenance"
    assert "unverified_provenance" in result.raw.decode("utf-8")


def test_a_shareable_packet_names_its_exclusions_without_leaking_rows(shareable_world):
    manifest, packet = shareable_world
    result = badge.shareable_badge(manifest=manifest, packet=packet,
                                   summaries=[_summary()])

    assert manifest.records_excluded is True
    assert len(result.record["excluded_records"]) == 6
    assert result.record["records_included"] is False
    assert result.record["records_rows"] == 0
    assert b"secret-conversation-row" not in result.raw


def test_the_badge_is_deterministic_and_records_its_own_hash(world):
    manifest, packet = world
    first = badge.shareable_badge(manifest=manifest, packet=packet,
                                  summaries=[_summary()])
    second = badge.shareable_badge(manifest=manifest, packet=packet,
                                   summaries=[_summary()])
    assert first.raw == second.raw
    assert first.record["badge_sha256"] == second.record["badge_sha256"]
    assert len(first.record["badge_sha256"]) == 64


def test_the_svg_prints_the_state_word_not_only_a_colour(world):
    manifest, packet = world
    result = badge.shareable_badge(manifest=manifest, packet=packet,
                                   summaries=[_summary()])
    assert result.state in result.svg
    assert "aria-label" in result.svg and "<title>" in result.svg


def test_badge_state_words_are_identical_in_both_catalogs():
    for state in badge.STATES:
        assert badge.state_label("en", state) == badge.state_label("zh-Hans", state)
    with pytest.raises(badge.BadgeRefused):
        badge.state_label("en", "green")
    assert i18n.LANGUAGES == ("en", "zh-Hans")
