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


def flip_one_byte(path: Path, target: str) -> tuple[str, str]:
    """Flip a single byte in place, keeping the length: only the hash can catch this.

    ``tamper_bundle`` substitutes a different-length payload, so the manifest's
    byte-count check also fires and a suite could stay green with the hash
    comparison removed. This fixture leaves the declared byte count true, which
    makes the digest the only thing standing between the bytes and acceptance.
    """
    document, files = split_bundle(path)
    declared = next(a for a in document["artifacts"] if a["path"] == target)
    old = declared["sha256"]
    data = bytearray(files[target])
    assert data, "an empty artefact has no byte to flip"
    data[0] ^= 0xFF
    files[target] = bytes(data)
    rewrite_bundle(path, files, json.dumps(document, sort_keys=True,
                                           separators=(",", ":")).encode())
    return old, sha256_bytes(bytes(data))


# M4 fixtures. The M1-M3 defaults above stay byte-identical: F4/F5 need three
# published fields those fixtures never had, and adding them to the shared
# default would silently move every earlier packet hash. The audit text below
# carries the frozen docs/AUDIT.md sentences verbatim, so AC6's comparability
# quote is read from a packet's own bytes in tests too.
KNOWN_LIMITS = [
    "exchangeability within group assumed; none of it is usable here",
    "no certificate exists, so no action is certified",
]
M4_AUDIT_TEXT = """# Audit (fixture)

- gate compared against: `0.85` (upstream's own gating figure), so the implied error rate is `1 - gate = 0.15`
- A field name therefore does not say which quantity a file holds; only the program that wrote it does, and the `attributed scale` column is this repository's measurement of which one the audited corpus carries.
- Quoting either multiple as the other is the definition slip the two definitions make possible, and this artefact publishes both rows precisely so a headline can name which one it means.
- A multiple is a point estimate and needs its interval before it is anything else.
- Nothing here certifies a deployment: this measures a rule the reference README instructs, on archived responses.
"""
M4_FEASIBILITY = {
    "producer": "tools/g1_feasibility.py",
    "rubric": {"alpha": 0.05, "beta": 0.05, "delta": 0.05, "method": "aps", "seed": 7},
    "reference": [{"n": 100, "k_max": 1, "largest_certifiable_error_rate": 0.01,
                   "required_observed_accuracy": 0.99,
                   "size_from": "declared by report.G1_FEASIBILITY_SIZES (the probe's scale)"}],
    "rows": [{"task": "fixture",
              "missing_pool_input": ("meta.errors_among_automated counts the errors INSIDE the "
                                     "automated set, not the errors of the evaluated pool; no "
                                     "published field of this certificate gives the pool count, "
                                     "so the oracle ceiling is not computable from these bytes")}],
}
CERTIFIED_CERT = {
    "alpha": 0.05, "beta": 0.05, "delta": 0.05, "method": "aps", "seed": 7,
    "backend": "fixture", "feasible": True, "reason": None, "autorate": "0.42",
    "conditional_error_bound": "0.05", "n_cal": 600, "n_eval": 600,
    "meta": {"at_requested_alpha": {"bound_unit": "case"}},
}


@pytest.fixture
def m4_source_tree(source_tree):
    """A packet that publishes what F4/F5 read, without touching M1-M3 fixtures."""
    protocol = json.loads((source_tree / "protocol.json").read_bytes())
    protocol["known_limits"] = list(KNOWN_LIMITS)
    (source_tree / "protocol.json").write_text(
        json.dumps(protocol, sort_keys=True, separators=(",", ":")), encoding="utf-8")
    (source_tree / "docs" / "AUDIT.md").write_text(M4_AUDIT_TEXT, encoding="utf-8")
    (source_tree / "data" / "g1_feasibility.json").write_text(
        json.dumps(M4_FEASIBILITY, sort_keys=True), encoding="utf-8")
    return source_tree


@pytest.fixture
def m4_built(tmp_path, m4_source_tree, build_kwargs):
    out = tmp_path / "m4.packet.tar"
    manifest, raw = build(m4_source_tree, out, **build_kwargs)
    return out, manifest, raw


@pytest.fixture
def certified_built(tmp_path, m4_source_tree, build_kwargs):
    """AC5's synthetic certificate: the only way a certified autorate exists."""
    from autorate_portal.packet import build as build_packet

    (m4_source_tree / "data" / "cert_jev.json").write_text(
        json.dumps(CERTIFIED_CERT, sort_keys=True), encoding="utf-8")
    out = tmp_path / "certified.packet.tar"
    manifest, raw = build_packet(m4_source_tree, out, **build_kwargs)
    return out, manifest, raw


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
