"""Self-contained fixtures: no test depends on the frozen repository's files."""
from __future__ import annotations

import io
import json
import sys
import tarfile
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "src"))
sys.path.insert(0, str(ROOT / "tools"))

from autorate_portal.cli import (DEFAULT_EXPECTED, DEFAULT_VERSION,  # noqa: E402
                                 DEFAULT_WHEEL, DEFAULT_WHEEL_SHA256)
from autorate_portal.manifest import payload_sha256, sha256_bytes  # noqa: E402
from autorate_portal.packet import ARTEFACT_PLAN, build  # noqa: E402

RUBRIC = {
    "alpha": 0.05, "beta": 0.05, "delta": 0.05, "seed": 7, "method": "aps",
    "unit": "case", "n_claims": 3, "min_cal": 60, "min_eval": 60,
    "grid": [0.01, 0.02, 0.03],
}
CERT = {
    "alpha": 0.05, "beta": 0.05, "delta": 0.05, "method": "aps",
    "backend": "fixture", "feasible": False, "reason": "empty_feasible_set",
    "autorate": None, "n_cal": 96, "n_eval": 96,
    "meta": {"at_requested_alpha": {"bound_unit": "case"}},
    "envelope": ["no certificate exists, so no action is certified"],
}
RECORD_ROW = b'{"case_id":"fixture-case-1","gold":"secret-conversation-row"}\n'


def fixture_bytes(path: str, kind: str) -> bytes:
    if path == "protocol.json":
        return json.dumps({"frozen_at": "2026-10-17", "rubric": RUBRIC},
                          sort_keys=True, separators=(",", ":")).encode()
    if kind == "certificate":
        return json.dumps({**CERT, "backend": Path(path).stem},
                          sort_keys=True, separators=(",", ":")).encode()
    if kind == "records":
        return RECORD_ROW
    return ("# %s\nfixture document\n" % path).encode()


@pytest.fixture
def source_tree(tmp_path):
    root = tmp_path / "source"
    for path, kind in ARTEFACT_PLAN:
        target = root / path
        target.parent.mkdir(parents=True, exist_ok=True)
        target.write_bytes(fixture_bytes(path, kind))
    return root


@pytest.fixture
def build_kwargs():
    return dict(source_revision="fixture0000000000000000000000000000000000",
                source_version=DEFAULT_VERSION, wheel_filename=DEFAULT_WHEEL,
                wheel_sha256=DEFAULT_WHEEL_SHA256, expected_rederived=DEFAULT_EXPECTED)


@pytest.fixture
def built(tmp_path, source_tree, build_kwargs):
    out = tmp_path / "fixture.packet.tar"
    manifest, raw = build(source_tree, out, **build_kwargs)
    return out, manifest, raw


def rewrite_bundle(path: Path, files: dict[str, bytes], manifest_bytes: bytes) -> bytes:
    """Write a test bundle with fixed tar metadata (our own writer, not a glob)."""
    entries = [("manifest.json", manifest_bytes)] + sorted(files.items())
    buf = io.BytesIO()
    with tarfile.open(fileobj=buf, mode="w", format=tarfile.USTAR_FORMAT) as tar:
        for name, data in entries:
            info = tarfile.TarInfo(name=name)
            info.size = len(data)
            info.mtime = 0
            info.uid = 0
            info.gid = 0
            info.uname = ""
            info.gname = ""
            info.mode = 0o644
            tar.addfile(info, io.BytesIO(data))
    path.write_bytes(buf.getvalue())
    return buf.getvalue()


def split_bundle(path: Path):
    """Return (manifest dict, artefact files)."""
    files = {}
    with tarfile.open(path, mode="r:*") as tar:
        for member in tar:
            files[member.name] = tar.extractfile(member).read()
    return json.loads(files.pop("manifest.json")), files


def reseal_manifest(document: dict) -> bytes:
    document["manifest_sha256"] = payload_sha256(document)
    return json.dumps(document, sort_keys=True, separators=(",", ":"),
                      ensure_ascii=False).encode()


def tamper_bundle(path: Path, target: str, replacement: bytes) -> tuple[str, str]:
    """Replace one artefact's bytes without resealing; return (expected, actual) hashes."""
    document, files = split_bundle(path)
    declared = next(a for a in document["artifacts"] if a["path"] == target)
    old = declared["sha256"]
    files[target] = replacement
    rewrite_bundle(path, files, json.dumps(document, sort_keys=True,
                                           separators=(",", ":")).encode())
    return old, sha256_bytes(replacement)


def resign_bundle(path: Path, patches: dict[str, bytes], manifest_patch=None) -> dict:
    """Patch artefacts and reseal the manifest so integrity checks still pass."""
    document, files = split_bundle(path)
    for target, data in patches.items():
        files[target] = data
        entry = next(a for a in document["artifacts"] if a["path"] == target)
        entry["sha256"] = sha256_bytes(data)
        entry["bytes"] = len(data)
    if manifest_patch:
        for key, value in manifest_patch.items():
            document[key] = value
    rewrite_bundle(path, files, reseal_manifest(document))
    return document
