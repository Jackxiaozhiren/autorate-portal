"""T5: a packet can carry the wheel set a replay needs, and the index stops being a prerequisite.

The schema bump is additive on purpose: a default build still writes schema 1, byte for byte,
so every existing packet and fixture keeps its meaning. Schema 2 exists only when somebody
embedded wheels, and then the claim "this packet replays offline" is a declared field backed by
artefacts whose hashes the verifier already checks.
"""
from __future__ import annotations

import subprocess
from pathlib import Path

import pytest

from autorate_portal.manifest import sha256_bytes
from autorate_portal.packet import build, verify_bundle
from autorate_portal.replay import Environment, verify_packet
from conftest import (DEFAULT_EXPECTED, DEFAULT_WHEEL, reseal_manifest,
                      rewrite_bundle, split_bundle)

WHEEL_BYTES = b"autorate wheel bytes for the offline fixture"
WIN_NAME = "numpy-2.2.0-cp313-cp313-win_amd64.whl"
DEP_NAME = "numpy-2.2.0-py3-none-any.whl"
DEP_BYTES = b"numpy wheel bytes for the offline fixture"


def offline_build(tmp_path, source_tree, build_kwargs):
    kwargs = dict(build_kwargs, wheel_sha256=sha256_bytes(WHEEL_BYTES))
    out = tmp_path / "offline.packet.tar"
    manifest, _ = build(source_tree, out,
                        embedded_wheels={DEFAULT_WHEEL: WHEEL_BYTES, DEP_NAME: DEP_BYTES},
                        **kwargs)
    return out, manifest


class RecordingRunner:
    """A docker/uv stand-in that records what it was asked to run."""

    def __init__(self, stdout, rc=0):
        self.calls = []
        self.stdout = stdout
        self.rc = rc
        self.scripts = []
        self.wheelhouses = []
        self.find_links = []

    def __call__(self, argv, **kwargs):
        self.calls.append(list(argv))
        for index, item in enumerate(argv):
            if isinstance(item, str) and item.endswith(":/replay:ro"):
                replay = Path(item[:-len(":/replay:ro")])
                self.scripts.append((replay / "replay.sh").read_text(encoding="utf-8"))
                self.wheelhouses.append(sorted(p.name for p in (replay / "wheelhouse").iterdir()))
            if item == "--find-links":
                folder = Path(argv[index + 1])
                self.find_links.append(sorted(p.name for p in folder.iterdir()))
        return subprocess.CompletedProcess(argv, self.rc, self.stdout, "")


def no_fetch(name):
    raise AssertionError("the index was consulted for %s" % name)


def container_env(runner, network=False):
    return Environment(docker_available=True, network_available=network,
                       docker_detail="docker daemon fixture",
                       network_detail="PyPI metadata unreachable: fixture",
                       runner=runner, wheel_fetcher=no_fetch)


def test_the_default_build_stays_schema_one_and_carries_no_wheel(built):
    _, manifest, _ = built
    assert manifest.schema_version == "1"
    assert manifest.embeds_wheel is False
    assert all(a.kind != "wheel" for a in manifest.artifacts)


def test_embedding_bumps_the_schema_and_lists_every_wheel(tmp_path, source_tree, build_kwargs):
    out, manifest = offline_build(tmp_path, source_tree, build_kwargs)
    assert manifest.schema_version == "2"
    assert manifest.embeds_wheel is True
    kinds = {a.path: a.kind for a in manifest.artifacts}
    assert kinds["wheel/" + DEFAULT_WHEEL] == "wheel"
    assert kinds["wheel/" + DEP_NAME] == "wheel"
    assert verify_bundle(out).ok is True


def test_the_embedded_set_must_contain_the_pinned_wheel(tmp_path, source_tree, build_kwargs):
    with pytest.raises(ValueError, match="does not contain the pinned wheel"):
        build(source_tree, tmp_path / "out.tar", embedded_wheels={DEP_NAME: DEP_BYTES},
              **build_kwargs)


def test_the_pinned_wheels_bytes_must_match_the_declared_hash(tmp_path, source_tree, build_kwargs):
    with pytest.raises(ValueError, match="pinned wheel sha256 mismatch"):
        build(source_tree, tmp_path / "out.tar",
              embedded_wheels={DEFAULT_WHEEL: b"not the declared bytes"}, **build_kwargs)


def test_a_schema_two_manifest_without_the_flag_is_refused(built):
    packet = built[0]
    document, files = split_bundle(packet)
    document["schema_version"] = "2"
    document.pop("wheel_embedded", None)
    rewrite_bundle(packet, files, reseal_manifest(document))
    result = verify_bundle(packet)
    assert result.ok is False
    assert any("wheel_embedded" in r.reason for r in result.refusals)


def test_a_schema_one_manifest_cannot_carry_a_wheel_artefact(built):
    packet = built[0]
    document, files = split_bundle(packet)
    files["wheel/stray-1.0-py3-none-any.whl"] = b"stray"
    document["artifacts"].append({"path": "wheel/stray-1.0-py3-none-any.whl",
                                  "sha256": sha256_bytes(b"stray"), "kind": "wheel",
                                  "bytes": len(b"stray")})
    document["artifacts"].sort(key=lambda a: a["path"])
    rewrite_bundle(packet, files, reseal_manifest(document))
    result = verify_bundle(packet)
    assert result.ok is False
    assert any("schema 1" in r.reason for r in result.refusals)


def test_a_schema_two_packet_without_a_wheel_artefact_is_refused(built):
    packet = built[0]
    document, files = split_bundle(packet)
    document["schema_version"] = "2"
    document["wheel_embedded"] = True
    document["wheel_platforms"] = []
    rewrite_bundle(packet, files, reseal_manifest(document))
    result = verify_bundle(packet)
    assert result.ok is False
    assert any("no wheel artefact" in r.reason for r in result.refusals)


def test_offline_container_replay_never_calls_the_index(tmp_path, source_tree, build_kwargs):
    packet, _ = offline_build(tmp_path, source_tree, build_kwargs)
    runner = RecordingRunner("re-derived %s values\n" % DEFAULT_EXPECTED)
    outcome = verify_packet(packet, container_env(runner), backend="container")
    assert outcome.state == "certified"
    assert outcome.rederived == DEFAULT_EXPECTED
    assert runner.scripts, "the container was never asked to run"
    assert "--no-index" in runner.scripts[0]
    assert "--find-links /replay/wheelhouse" in runner.scripts[0]
    assert runner.wheelhouses[0] == sorted([DEFAULT_WHEEL, DEP_NAME])


def test_offline_container_replay_without_docker_blames_only_docker(
        tmp_path, source_tree, build_kwargs):
    packet, _ = offline_build(tmp_path, source_tree, build_kwargs)
    env = Environment(False, False, "docker executable not found",
                      "PyPI metadata unreachable: fixture",
                      runner=RecordingRunner(""), wheel_fetcher=no_fetch)
    outcome = verify_packet(packet, env, backend="container")
    assert outcome.state == "not-run"
    assert "docker executable not found" in outcome.reason
    assert "PyPI" not in outcome.reason


def test_an_online_packet_still_needs_the_network(built):
    packet = built[0]
    env = Environment(True, False, "docker daemon fixture",
                      "PyPI metadata unreachable: fixture",
                      runner=RecordingRunner(""), wheel_fetcher=no_fetch)
    outcome = verify_packet(packet, env, backend="container")
    assert outcome.state == "not-run"
    assert "PyPI metadata unreachable" in outcome.reason


def test_offline_uv_install_uses_the_local_wheelhouse(tmp_path, source_tree, build_kwargs):
    packet, _ = offline_build(tmp_path, source_tree, build_kwargs)
    runner = RecordingRunner("re-derived %s values\n" % DEFAULT_EXPECTED)
    env = Environment(False, False, "docker executable not found",
                      "PyPI metadata unreachable: fixture",
                      runner=runner, wheel_fetcher=no_fetch)
    outcome = verify_packet(packet, env, backend="uv")
    assert outcome.state == "certified"
    installs = [call for call in runner.calls if "install" in call]
    assert installs, "uv was never asked to install"
    install = installs[0]
    assert "--no-index" in install
    assert runner.find_links[0] == sorted([DEFAULT_WHEEL, DEP_NAME])

def test_online_container_replay_installs_from_the_same_wheelhouse(built, tmp_path,
                                                                  source_tree, build_kwargs):
    """One directory layout for both channels: only the index flag differs."""
    kwargs = dict(build_kwargs, wheel_sha256=sha256_bytes(WHEEL_BYTES))
    packet = tmp_path / "online.tar"
    build(source_tree, packet, **kwargs)
    runner = RecordingRunner("re-derived %s values\n" % DEFAULT_EXPECTED)
    env = Environment(True, True, "docker daemon fixture", "PyPI reachable",
                      runner=runner, wheel_fetcher=lambda name: WHEEL_BYTES)
    outcome = verify_packet(packet, env, backend="container")
    assert outcome.state == "certified"
    assert "/replay/wheelhouse/" + DEFAULT_WHEEL in runner.scripts[0]
    assert "--no-index" not in runner.scripts[0]

def test_the_manifest_records_the_platforms_of_the_embedded_set(tmp_path, source_tree, build_kwargs):
    _, manifest = offline_build(tmp_path, source_tree, build_kwargs)
    assert manifest.wheel_platforms == ["any"]


def test_a_manifest_whose_platforms_disagree_with_its_wheels_is_refused(
        tmp_path, source_tree, build_kwargs):
    packet, _ = offline_build(tmp_path, source_tree, build_kwargs)
    document, files = split_bundle(packet)
    document["wheel_platforms"] = ["win_amd64"]
    rewrite_bundle(packet, files, reseal_manifest(document))
    result = verify_bundle(packet)
    assert result.ok is False
    assert any("wheel_platforms does not match" in r.reason for r in result.refusals)


def test_an_incompatible_wheel_is_refused_before_anything_is_installed(
        tmp_path, source_tree, build_kwargs):
    kwargs = dict(build_kwargs, wheel_sha256=sha256_bytes(WHEEL_BYTES))
    packet = tmp_path / "windows.packet.tar"
    build(source_tree, packet,
          embedded_wheels={DEFAULT_WHEEL: WHEEL_BYTES, WIN_NAME: b"windows wheel"},
          **kwargs)
    runner = RecordingRunner("")
    env = Environment(False, False, "docker executable not found", "PyPI unreachable",
                      runner=runner, wheel_fetcher=no_fetch)
    outcome = verify_packet(packet, env, backend="uv")
    assert outcome.state == "refused"
    assert "win_amd64" in outcome.reason
    assert runner.calls == [], "nothing may be installed once the tags are known to mismatch"


def test_an_install_failure_is_named_not_reported_as_a_bare_exit_code(
        tmp_path, source_tree, build_kwargs):
    packet, _ = offline_build(tmp_path, source_tree, build_kwargs)
    runner = RecordingRunner("")
    runner.rc = 1
    env = Environment(False, False, "docker executable not found", "PyPI unreachable",
                      runner=runner, wheel_fetcher=no_fetch)
    outcome = verify_packet(packet, env, backend="uv")
    assert outcome.state == "refused"
    assert "install step failed" in outcome.reason


def test_a_container_install_failure_is_named_with_the_target_image(offline_built):
    runner = RecordingRunner("INSTALL_FAILED\n", rc=97)
    outcome = verify_packet(offline_built[0], container_env(runner), backend="container")
    assert outcome.state == "refused"
    assert "install step failed inside python:3.13-slim" in outcome.reason
    assert outcome.channel == "offline"
