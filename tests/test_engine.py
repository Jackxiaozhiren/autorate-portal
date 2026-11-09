"""T11 - AC4's mismatch path, I5's run row, and the engine's refusal ladder."""
from __future__ import annotations

import json
import subprocess

from autorate_portal import EXIT_NOT_RUN, EXIT_OK, EXIT_REFUSED
from autorate_portal.engine import append_row, find_row, read_rows, run
from autorate_portal.manifest import sha256_bytes
from autorate_portal.replay import Environment
from conftest import reseal_manifest, rewrite_bundle, split_bundle, tamper_bundle

WHEEL_BYTES = b"pinned-autorate-wheel-bytes"
WHEEL = "autorate-0.1.2-py3-none-any.whl"


def _registry(tmp_path, sha256, *, version="0.1.2", wheel=WHEEL, name="pins.json"):
    path = tmp_path / name
    path.write_text(json.dumps({"schema": "test", "pins": [
        {"name": "autorate", "version": version, "wheel": wheel, "sha256": sha256,
         "source": "https://pypi.org/pypi/autorate/%s/json" % version}]}), encoding="utf-8")
    return path


def _env(*, docker=True, network=True, stdout="re-derived 612 /612 values\n", rc=0):
    calls = []

    def runner(argv, **kwargs):
        calls.append(argv)
        return subprocess.CompletedProcess(argv, rc, stdout=stdout, stderr="")
    return Environment(docker_available=docker, network_available=network,
                       docker_detail="docker daemon unavailable (injected)",
                       network_detail="PyPI unreachable (injected)",
                       runner=runner, wheel_fetcher=lambda _: WHEEL_BYTES), calls


def _pin_packet_to_the_test_wheel(packet):
    document, files = split_bundle(packet)
    document["distribution"]["sha256"] = sha256_bytes(WHEEL_BYTES)
    rewrite_bundle(packet, files, reseal_manifest(document))


def test_i5_a_certified_run_row_carries_the_pinned_invocation_and_exit_code(built, tmp_path):
    packet = built[0]
    _pin_packet_to_the_test_wheel(packet)
    registry = _registry(tmp_path, sha256_bytes(WHEEL_BYTES))
    env, calls = _env()

    row = run(packet, backend="container", registry_path=registry, env=env)

    assert row.state == "certified" and row.rc == EXIT_OK
    assert row.argv and row.argv[0] == "docker"
    assert row.command == ["verify", "--protocol", "protocol.json"]
    assert row.exit_code == 0
    assert row.distribution == "autorate==0.1.2"
    assert row.wheel_sha256 == sha256_bytes(WHEEL_BYTES)
    assert len(row.stdout_sha256) == 64
    assert row.denominator_replayed == row.denominator_stored == "612 /612"
    assert len(calls) == 1


def test_ac4_a_mismatch_names_both_digests_and_is_never_certified(built, tmp_path):
    packet = built[0]
    _pin_packet_to_the_test_wheel(packet)
    registry = _registry(tmp_path, sha256_bytes(WHEEL_BYTES))
    env, calls = _env(stdout="re-derived 611 /612 values\n")

    row = run(packet, backend="container", registry_path=registry, env=env)

    assert row.state == "mismatch"
    assert row.rc == EXIT_REFUSED
    assert len(row.digest_stored) == 64 and len(row.digest_replayed) == 64
    assert row.digest_stored != row.digest_replayed
    assert row.digest_stored in row.reason
    assert row.digest_replayed in row.reason
    assert row.denominator_stored == "612 /612"
    assert row.denominator_replayed == "611 /612"
    assert len(calls) == 1, "the replay ran; the disagreement is the finding"


def test_an_unregistered_distribution_is_refused_before_anything_runs(built, tmp_path):
    registry = _registry(tmp_path, "0" * 64, version="0.1.1")

    def forbidden(argv, **kwargs):
        raise AssertionError("no command may run when the pin is not registered")

    env = Environment(True, True, "docker present", "PyPI reachable", runner=forbidden,
                      wheel_fetcher=lambda _: WHEEL_BYTES)
    row = run(built[0], backend="container", registry_path=registry, env=env)

    assert row.state == "refused" and row.rc == EXIT_REFUSED
    assert "not in the pinned registry" in row.reason
    assert row.argv == [] and row.exit_code is None
    assert row.refusals and row.refusals[0].actual == "0.1.2"


def test_a_packet_pin_that_disagrees_with_the_registry_is_refused(built, tmp_path):
    registry = _registry(tmp_path, "1" * 64)

    row = run(built[0], backend="container", registry_path=registry)

    assert row.state == "refused" and row.rc == EXIT_REFUSED
    assert "disagrees with the pinned registry" in row.reason
    assert row.argv == [] and row.exit_code is None


def test_a_tampered_packet_is_refused_before_the_engine_runs(built, tmp_path):
    tamper_bundle(built[0], "data/cert_laya.json", b"tampered")
    registry = _registry(tmp_path, sha256_bytes(WHEEL_BYTES))

    row = run(built[0], backend="container", registry_path=registry)

    assert row.state == "refused" and "nothing was replayed" in row.reason
    assert row.argv == [] and row.digest_stored == "" and row.exit_code is None


def test_ac10_the_engine_degrades_to_not_run_with_no_argv(built, tmp_path):
    _pin_packet_to_the_test_wheel(built[0])
    registry = _registry(tmp_path, sha256_bytes(WHEEL_BYTES))
    env, calls = _env(docker=False, network=False)

    row = run(built[0], backend="container", registry_path=registry, env=env)

    assert row.state == "not-run" and row.rc == EXIT_NOT_RUN
    assert row.argv == [] and row.exit_code is None and row.command == []
    assert calls == []
    assert "docker daemon unavailable" in row.reason
    assert "PyPI unreachable" in row.reason


def test_an_unusable_registry_is_not_run_and_not_a_verdict_on_the_packet(built, tmp_path):
    broken = tmp_path / "broken.json"
    broken.write_text("{not json", encoding="utf-8")

    row = run(built[0], backend="container", registry_path=broken)

    assert row.state == "not-run" and row.rc == EXIT_NOT_RUN
    assert "registry unusable" in row.reason


def test_every_attempt_is_its_own_row(built, tmp_path):
    """A monitor's re-runs are a series, not duplicates of one observation.

    The first design keyed rows on "the same observation" and claimed AC14's
    idempotence. CI showed why that is wrong: the replay's stdout hash moves
    with the container's pip output, so the key never matched and the claim was
    vacuous. Two attempts are two rows, each with its own argv and stdout hash.
    """
    packet = built[0]
    _pin_packet_to_the_test_wheel(packet)
    registry = _registry(tmp_path, sha256_bytes(WHEEL_BYTES))
    store = tmp_path / "runs.jsonl"
    env, _ = _env()

    first = run(packet, backend="container", registry_path=registry, env=env, store_path=store)
    second = run(packet, backend="container", registry_path=registry, env=env, store_path=store)

    rows = read_rows(store)
    assert len(rows) == 2
    assert first.run_id != second.run_id
    assert [row["state"] for row in rows] == ["certified", "certified"]
    assert {row["denominator_replayed"] for row in rows} == {"612 /612"}
    assert all(row["argv"] and row["argv"][0] == "docker" for row in rows)
    assert append_row(store, first) is True
    assert len(read_rows(store)) == 3


def test_a_different_observation_is_a_second_row(built, tmp_path):
    packet = built[0]
    _pin_packet_to_the_test_wheel(packet)
    registry = _registry(tmp_path, sha256_bytes(WHEEL_BYTES))
    store = tmp_path / "runs.jsonl"

    good, _ = _env()
    bad, _ = _env(stdout="re-derived 611 /612 values\n")
    certified = run(packet, backend="container", registry_path=registry, env=good, store_path=store)
    mismatch = run(packet, backend="container", registry_path=registry, env=bad, store_path=store)

    assert certified.run_id != mismatch.run_id
    assert [row["state"] for row in read_rows(store)] == ["certified", "mismatch"]
    assert find_row(store, certified.run_id)["state"] == "certified"
    assert find_row(store, mismatch.run_id)["state"] == "mismatch"


def test_a_malformed_store_is_named_not_silently_skipped(tmp_path):
    store = tmp_path / "runs.jsonl"
    store.write_text('{"run_id": "x"}\nnot json\n', encoding="utf-8")
    try:
        read_rows(store)
    except ValueError as exc:
        assert "line 2 is not JSON" in str(exc)
    else:
        raise AssertionError("a malformed store must not read as empty")


def test_the_run_command_accepts_the_image_flag():
    """A gate that passes --image must not die in argparse with rc 2."""
    from autorate_portal.cli import build_parser

    for argv in (["run", "packet.tar", "--image", "python:3.12-slim"],
                 ["verify-packet", "packet.tar", "--image", "python:3.12-slim"]):
        args = build_parser().parse_args(argv)
        assert args.image == "python:3.12-slim", argv
        assert args.backend == "container", argv
