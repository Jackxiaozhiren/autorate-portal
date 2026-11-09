"""T6/T7 - AC9 clean replay, AC10 named not-run, and the I6 pinned-wheel guard."""
from __future__ import annotations

import subprocess

from autorate_portal import EXIT_NOT_RUN, EXIT_OK, EXIT_REFUSED
from autorate_portal.manifest import sha256_bytes
from autorate_portal.replay import Environment, verify_packet
from conftest import (reseal_manifest, rewrite_bundle, split_bundle,
                      tamper_bundle)

WHEEL_BYTES = b"pinned-autorate-wheel-bytes"


def _env(docker=True, network=True, runner=None, fetcher=None):
    return Environment(docker_available=docker, network_available=network,
                       docker_detail="docker daemon unavailable (injected)",
                       network_detail="PyPI unreachable (injected)",
                       runner=runner, wheel_fetcher=fetcher)


def _runner(stdout="re-derived 612 /612 values\n", rc=0):
    calls = []

    def run(argv, **kwargs):
        calls.append(argv)
        return subprocess.CompletedProcess(argv, rc, stdout=stdout, stderr="")
    return run, calls


def _pin_to(packet, wheel_bytes):
    document, files = split_bundle(packet)
    document["distribution"]["sha256"] = sha256_bytes(wheel_bytes)
    rewrite_bundle(packet, files, reseal_manifest(document))
    return document


def test_ac10_no_docker_no_network_is_a_named_not_run(built):
    outcome = verify_packet(built[0], _env(docker=False, network=False))
    assert outcome.state == "not-run"
    assert outcome.rc == EXIT_NOT_RUN
    assert "docker daemon unavailable" in outcome.reason
    assert "PyPI unreachable" in outcome.reason
    assert outcome.run_row()["state"] != "certified"
    assert outcome.exit_code is None


def test_ac10_a_single_missing_prerequisite_is_never_a_pass(built):
    container = verify_packet(built[0], _env(docker=False, network=True))
    uv = verify_packet(built[0], _env(docker=False, network=False), backend="uv")
    assert container.state == "not-run" and container.rc == EXIT_NOT_RUN
    assert uv.state == "not-run" and uv.rc == EXIT_NOT_RUN
    assert "PyPI unreachable" in uv.reason


def test_i6_swapped_wheel_hash_is_refused_with_both_hashes(built):
    runner, calls = _runner()
    outcome = verify_packet(built[0],
                            _env(runner=runner, fetcher=lambda _: WHEEL_BYTES))
    assert outcome.state == "refused" and outcome.rc == EXIT_REFUSED
    assert "pinned wheel sha256 mismatch" in outcome.reason
    refusal = outcome.refusals[0]
    assert refusal.expected == "7709d3faa560417efcbd8066f6db79d741d995bbbb9b23d2d595ed2a6fb38205"
    assert refusal.actual == sha256_bytes(WHEEL_BYTES)
    assert calls == [], "no command may run when the pinned wheel does not chain"


def test_ac9_clean_replay_reproduces_the_stored_denominator(built):
    packet, manifest, _ = built
    _pin_to(packet, WHEEL_BYTES)
    runner, calls = _runner()
    outcome = verify_packet(packet, _env(runner=runner, fetcher=lambda _: WHEEL_BYTES))
    assert outcome.state == "certified" and outcome.rc == EXIT_OK
    assert outcome.rederived == manifest.expected_rederived == "612 /612"
    assert len(calls) == 1 and calls[0][0] == "docker"
    row = outcome.run_row()
    assert row["exit_code"] == 0
    assert len(row["stdout_sha256"]) == 64
    assert row["packet_id_in"] == manifest.packet_id
    assert row["digest_then"] == manifest.protocol_digest
    assert row["argv"] and row["argv"][0] == "docker"


def test_rederived_disagreement_is_refused(built):
    _pin_to(built[0], WHEEL_BYTES)
    runner, _ = _runner(stdout="re-derived 611 /612 values\n")
    outcome = verify_packet(built[0], _env(runner=runner, fetcher=lambda _: WHEEL_BYTES))
    assert outcome.state == "refused" and outcome.rc == EXIT_REFUSED
    assert outcome.rederived == "611 /612"
    assert "disagrees" in outcome.reason


def test_failed_replay_is_never_reported_as_a_pass(built):
    _pin_to(built[0], WHEEL_BYTES)
    runner, _ = _runner(rc=4)
    outcome = verify_packet(built[0], _env(runner=runner, fetcher=lambda _: WHEEL_BYTES))
    assert outcome.state == "refused" and outcome.rc == EXIT_REFUSED
    assert outcome.run_row()["exit_code"] == 4


def test_replay_without_a_rederived_line_is_refused(built):
    _pin_to(built[0], WHEEL_BYTES)
    runner, _ = _runner(stdout="no denominator here\n")
    outcome = verify_packet(built[0], _env(runner=runner, fetcher=lambda _: WHEEL_BYTES))
    assert outcome.state == "refused" and "no 're-derived" in outcome.reason


def test_a_wheel_fetch_failure_is_a_named_not_run(built):
    def fail(_):
        raise OSError("PyPI refused the connection")
    outcome = verify_packet(built[0], _env(fetcher=fail))
    assert outcome.state == "not-run" and outcome.rc == EXIT_NOT_RUN
    assert "PyPI refused the connection" in outcome.reason


def test_tampered_packet_is_refused_before_any_replay(built):
    tamper_bundle(built[0], "data/cert_laya.json", b"tampered")
    runner, calls = _runner()
    outcome = verify_packet(built[0], _env(runner=runner, fetcher=lambda _: WHEEL_BYTES))
    assert outcome.state == "refused" and calls == []
    assert "nothing was replayed" in outcome.reason


def test_shareable_packet_states_why_replay_is_not_run(tmp_path, source_tree, build_kwargs):
    from autorate_portal.packet import build
    out = tmp_path / "shareable.tar"
    build(source_tree, out, shareable=True, **build_kwargs)
    outcome = verify_packet(out, _env())
    assert outcome.state == "not-run" and outcome.rc == EXIT_NOT_RUN
    assert "section 8.4" in outcome.reason
