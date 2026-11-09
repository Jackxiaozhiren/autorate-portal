"""Deterministic packet bundles (PRD section 7 M1, section 8.4, section 11).

The artefact list is explicit, not a glob. Section 6.3 names the failure mode a
glob creates: a fixture list built by glob silently passes when an artefact is
absent. A missing path here is refused with its name.
"""
from __future__ import annotations

import io
import json
import tarfile
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

from .manifest import (Artefact, Distribution, Manifest, canonical_bytes,
                       payload_sha256, sha256_bytes)

MANIFEST_NAME = "manifest.json"
MAX_BUNDLE_BYTES = 64 * 1024 * 1024


def _plan() -> tuple[tuple[str, str], ...]:
    """(path, kind); every entry is a committed artefact of the frozen repo.

    Keep this list in step with the frozen repository's publication tables. It
    is deliberately a literal, so an artefact that disappears is named.
    """
    certificates = (
        "data/cert_jev.json",
        "data/cert_laya.json",
        "data/cert_massive_de_laya.json",
        "data/cert_massive_en_laya.json",
        "data/cert_massive_km_laya.json",
        "data/cert_massive_sw_laya.json",
        "data/cert_severity_ordinal.json",
    )
    records = (
        "data/records_feishu.jsonl",
        "data/records_massive_de.jsonl",
        "data/records_massive_en.jsonl",
        "data/records_massive_km.jsonl",
        "data/records_massive_sw.jsonl",
        "data/records_ordinal_synthetic.jsonl",
    )
    documents = (
        "data/contamination_probe.json",
        "data/g1_feasibility.json",
        "data/inventory.md",
        "data/inventory.md.json",
        "data/massive_provenance.json",
        "data/pin_app_benchmark.json",
        "data/resplit_200.json",
        "data/slices_language.json",
        "docs/AUDIT.md",
        "docs/CONTAMINATION.md",
        "docs/ERRATA.md",
        "docs/FEASIBILITY.md",
        "docs/G5.md",
        "docs/REPORT.md",
        "docs/RESPLIT.md",
        "docs/RESULTS.md",
        "docs/SEVERITY.md",
        "docs/SLICES.md",
        "docs/VERIFICATION.md",
    )
    return (("protocol.json", "protocol"),
            *((p, "certificate") for p in certificates),
            *((p, "records") for p in records),
            *((p, "document") for p in documents))


ARTEFACT_PLAN = _plan()


class MissingArtefact(Exception):
    """A publication-table artefact is absent from the source tree."""


class BundleError(Exception):
    """The bundle is not a well-formed, safe packet container."""


@dataclass(frozen=True)
class Refusal:
    path: str
    reason: str
    expected: str = ""
    actual: str = ""


@dataclass
class Verification:
    ok: bool
    manifest: Manifest | None = None
    files: dict[str, bytes] = field(default_factory=dict)
    refusals: list[Refusal] = field(default_factory=list)


def _read_source(source: Path, shareable: bool) -> tuple[dict[str, bytes], list[str]]:
    files: dict[str, bytes] = {}
    excluded: list[str] = []
    for path, kind in ARTEFACT_PLAN:
        candidate = source / path
        if not candidate.is_file():
            raise MissingArtefact(
                "%s is declared by the packet artefact plan and is not in this checkout" % path)
        if shareable and kind == "records":
            excluded.append(path)
            continue
        files[path] = candidate.read_bytes()
    return files, sorted(excluded)


def _packet_id(protocol_digest: str, source_revision: str,
               artefacts: list[dict[str, Any]], shareable: bool) -> str:
    basis = canonical_bytes({
        "protocol_digest": protocol_digest,
        "source_revision": source_revision,
        "shareable": shareable,
        "artifacts": [[a["path"], a["sha256"]] for a in artefacts],
    })
    return "pkt-" + sha256_bytes(basis)[:16]


def build_manifest(files: dict[str, bytes], *, source_revision: str,
                   source_version: str, wheel_filename: str, wheel_sha256: str,
                   expected_rederived: str, shareable: bool,
                   excluded_records: list[str]) -> Manifest:
    protocol = json.loads(files["protocol.json"])
    rubric = protocol["rubric"]
    protocol_sha256 = sha256_bytes(files["protocol.json"])
    protocol_digest = protocol_sha256[:12]

    artefacts = [
        Artefact(path=path, sha256=sha256_bytes(files[path]),
                 kind=dict(ARTEFACT_PLAN)[path], bytes=len(files[path])).model_dump(mode="json")
        for path in sorted(files)
    ]
    packet_id = _packet_id(protocol_digest, source_revision, artefacts, shareable)

    payload: dict[str, Any] = {
        "schema_version": "1",
        "packet_id": packet_id,
        "protocol_digest": protocol_digest,
        "protocol_sha256": protocol_sha256,
        "source_revision": source_revision,
        "source_version": source_version,
        "bound_unit": str(rubric["unit"]),
        "lane": "corpus absent",
        "expected_rederived": expected_rederived,
        "rubric": rubric,
        "distribution": Distribution(name="autorate", version=source_version,
                                     wheel=wheel_filename, sha256=wheel_sha256).model_dump(mode="json"),
        "artifacts": artefacts,
        "records_excluded": shareable,
        "excluded_records": excluded_records,
    }
    full = {**payload, "manifest_sha256": sha256_bytes(canonical_bytes(payload))}
    return Manifest.model_validate(full)


def write_bundle(out: Path, manifest: Manifest, files: dict[str, bytes]) -> bytes:
    """Write a deterministic tar: sorted names, fixed metadata, no clock."""
    entries = [(MANIFEST_NAME, json.dumps(manifest.as_dict(), sort_keys=True,
                                         separators=(",", ":"), ensure_ascii=False).encode("utf-8"))]
    entries += [(path, files[path]) for path in sorted(files)]
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
            info.type = tarfile.REGTYPE
            tar.addfile(info, io.BytesIO(data))
    raw = buf.getvalue()
    out.write_bytes(raw)
    return raw


def build(source: Path, out: Path, *, source_revision: str, source_version: str,
          wheel_filename: str, wheel_sha256: str, expected_rederived: str,
          shareable: bool = False) -> tuple[Manifest, bytes]:
    files, excluded = _read_source(source, shareable)
    manifest = build_manifest(files, source_revision=source_revision,
                              source_version=source_version,
                              wheel_filename=wheel_filename,
                              wheel_sha256=wheel_sha256,
                              expected_rederived=expected_rederived,
                              shareable=shareable, excluded_records=excluded)
    return manifest, write_bundle(out, manifest, files)


def read_bundle(path: Path) -> dict[str, bytes]:
    """Read a bundle, refusing traversal, non-regular members and duplicates."""
    files: dict[str, bytes] = {}
    total = 0
    try:
        with tarfile.open(path, mode="r:*") as tar:
            for member in tar:
                name = member.name
                if not member.isfile():
                    raise BundleError("bundle member %r is not a regular file" % name)
                if (name.startswith("/") or "\\" in name
                        or any(p in ("", ".", "..") for p in name.split("/"))):
                    raise BundleError("bundle member %r traverses or is absolute" % name)
                if name in files:
                    raise BundleError("bundle member %r appears twice" % name)
                total += member.size
                if total > MAX_BUNDLE_BYTES:
                    raise BundleError("bundle exceeds the cap: %d bytes read, cap is %d"
                                      % (total, MAX_BUNDLE_BYTES))
                handle = tar.extractfile(member)
                if handle is None:
                    raise BundleError("bundle member %r cannot be read" % name)
                files[name] = handle.read()
    except tarfile.TarError as exc:
        raise BundleError("bundle is not a readable tar: %s" % exc) from exc
    if MANIFEST_NAME not in files:
        raise BundleError("bundle has no %s" % MANIFEST_NAME)
    return files


def parse_manifest(raw: bytes) -> tuple[Manifest | None, Refusal | None]:
    try:
        document = json.loads(raw)
    except (ValueError, UnicodeDecodeError) as exc:
        return None, Refusal(MANIFEST_NAME, "manifest is not JSON: %s" % exc)
    if not isinstance(document, dict):
        return None, Refusal(MANIFEST_NAME, "manifest is not an object")
    computed = payload_sha256(document)
    declared = document.get("manifest_sha256", "")
    if computed != declared:
        return None, Refusal(MANIFEST_NAME, "manifest self-hash does not match",
                             expected=str(declared), actual=computed)
    try:
        return Manifest.model_validate(document), None
    except ValueError as exc:
        return None, Refusal(MANIFEST_NAME, "manifest violates the contract: %s" % exc,
                             expected=str(declared), actual=computed)


def verify_bundle(path: Path) -> Verification:
    """AC1: one tampered byte is a named refusal with both hashes, nothing indexed."""
    try:
        files = read_bundle(path)
    except BundleError as exc:
        return Verification(False, refusals=[Refusal(str(path), str(exc))])

    manifest, refusal = parse_manifest(files.pop(MANIFEST_NAME))
    if refusal is not None or manifest is None:
        return Verification(False, refusals=[refusal or Refusal(MANIFEST_NAME, "invalid manifest")])

    refusals: list[Refusal] = []
    declared = {a.path: a for a in manifest.artifacts}
    for artefact in manifest.artifacts:
        if artefact.path not in files:
            refusals.append(Refusal(artefact.path, "declared artefact is absent from the bundle",
                                    expected=artefact.sha256, actual=""))
            continue
        data = files[artefact.path]
        actual = sha256_bytes(data)
        if actual != artefact.sha256:
            refusals.append(Refusal(artefact.path, "artefact bytes do not match the manifest",
                                    expected=artefact.sha256, actual=actual))
        if len(data) != artefact.bytes:
            refusals.append(Refusal(artefact.path, "artefact byte count does not match the manifest",
                                    expected=str(artefact.bytes), actual=str(len(data))))
    for name in sorted(files):
        if name not in declared:
            refusals.append(Refusal(name, "bundle carries an undeclared file", actual=sha256_bytes(files[name])))

    # A refused bundle has no trusted manifest: never hand one to a caller that
    # might render or index it. The CLI checks `ok` as well; this is the second
    # line of defence, not a relaxation of the first.
    return Verification(not refusals, manifest=None if refusals else manifest,
                        files={} if refusals else files, refusals=refusals)
