"""Idempotent packet registry for M1 (AC14).

M3 replaces this with the SQLAlchemy schema in PRD section 4.3. Keeping M1's
store as one explicit JSON file makes the idempotence rule testable without a
web tier, and keeps the portal's only write target visible.
"""
from __future__ import annotations

import json
from pathlib import Path
from typing import Any

from .manifest import Manifest


def _empty() -> dict[str, Any]:
    return {"packets": {}}


def load(path: Path) -> dict[str, Any]:
    if not path.exists():
        return _empty()
    document = json.loads(path.read_text())
    if not isinstance(document, dict) or "packets" not in document:
        raise ValueError("registry file %s is not a packet registry" % path)
    return document


def ingest(registry_path: Path, manifest: Manifest) -> tuple[dict[str, Any], bool]:
    """Return (row, created). A repeated manifest_sha256 adds no row and no artefact."""
    document = load(registry_path)
    key = manifest.manifest_sha256
    packets = document["packets"]
    if key in packets:
        return packets[key], False

    artefacts = [{"path": a.path, "sha256": a.sha256} for a in manifest.artifacts]
    seen: set[tuple[str, str]] = set()
    unique = []
    for artefact in artefacts:
        ident = (artefact["path"], artefact["sha256"])
        if ident not in seen:
            seen.add(ident)
            unique.append(artefact)

    row = {
        "manifest_sha256": key,
        "packet_id": manifest.packet_id,
        "protocol_digest": manifest.protocol_digest,
        "source_revision": manifest.source_revision,
        "records_excluded": manifest.records_excluded,
        "artifacts": unique,
    }
    packets[key] = row
    registry_path.write_text(json.dumps(document, sort_keys=True, separators=(",", ":"),
                                        ensure_ascii=False) + "\n", encoding="utf-8")
    return row, True
