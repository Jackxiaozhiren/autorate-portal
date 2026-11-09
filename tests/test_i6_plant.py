"""T8 - I6 at the contract level: a swapped pinned wheel hash is a named refusal.

This is the network-free companion to tools/i6_plant.py, which runs the same
plant through the CLI in CI and restores the bundle with a sha256 receipt.
"""
from __future__ import annotations

import hashlib

from autorate_portal import EXIT_REFUSED
from autorate_portal.manifest import Manifest
from autorate_portal.replay import Environment, verify_packet
from conftest import rewrite_bundle, split_bundle
from i6_plant import WRONG_SHA256, reseal

WHEEL_BYTES = b"published-autorate-0.1.2-wheel"


def test_reseal_changes_only_the_wheel_hash_and_keeps_the_manifest_valid(built, tmp_path):
    packet = built[0]
    planted = tmp_path / "planted.tar"
    original, planted_bytes, old, new = reseal(packet, planted)
    assert planted_bytes != original
    assert old == "7709d3faa560417efcbd8066f6db79d741d995bbbb9b23d2d595ed2a6fb38205"
    assert new == WRONG_SHA256

    document, files = split_bundle(packet)
    planted_document, planted_files = split_bundle(planted)
    assert files == planted_files, "the plant must change the manifest, not the artefacts"
    assert planted_document["distribution"]["sha256"] == WRONG_SHA256
    ignore = {"distribution", "manifest_sha256"}
    assert {k: v for k, v in planted_document.items() if k not in ignore} == {
        k: v for k, v in document.items() if k not in ignore}
    assert Manifest.model_validate(planted_document).distribution.sha256 == WRONG_SHA256


def test_swapped_hash_is_refused_with_both_hashes_and_no_command_runs(built, tmp_path):
    packet = built[0]
    planted = tmp_path / "planted.tar"
    reseal(packet, planted)
    calls = []

    def runner(argv, **kwargs):
        import subprocess
        calls.append(argv)
        return subprocess.CompletedProcess(argv, 0, stdout="re-derived 612 /612 values\n", stderr="")

    env = Environment(docker_available=True, network_available=True,
                      docker_detail="injected", network_detail="injected",
                      runner=runner, wheel_fetcher=lambda _: WHEEL_BYTES)
    outcome = verify_packet(planted, env, backend="container")
    assert outcome.state == "refused" and outcome.rc == EXIT_REFUSED
    assert calls == [], "no replay may run when the wheel does not chain"
    refusal = outcome.refusals[0]
    assert refusal.expected == WRONG_SHA256
    assert refusal.actual == hashlib.sha256(WHEEL_BYTES).hexdigest()


def test_resealing_without_a_new_hash_would_be_detected(built, tmp_path):
    """A plant that edits the hash but forgets the self-hash cannot be valid."""
    document, files = split_bundle(built[0])
    document["distribution"]["sha256"] = WRONG_SHA256
    target = tmp_path / "unresealed.tar"
    rewrite_bundle(target, files,
                   __import__("json").dumps(document, sort_keys=True,
                                            separators=(",", ":")).encode())
    from autorate_portal.packet import verify_bundle
    result = verify_bundle(target)
    assert result.ok is False
    assert "self-hash does not match" in result.refusals[0].reason
