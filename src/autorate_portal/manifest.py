"""The manifest.json contract (PRD section 7 M1, section 4.3, section 13.3).

Every field is required. A field that is absent is a validation error, never a
default: a packet that silently acquires a default would publish a claim nobody
made. The spellings ``bound_unit``, ``protocol_digest``, ``manifest_sha256`` and
``packet_id`` are fixed by section 13.3 item 3 and are not aliased.
"""
from __future__ import annotations

import hashlib
import json
import re
from typing import Any, Literal

from pydantic import BaseModel, ConfigDict, Field, field_validator, model_validator

HEX64 = re.compile(r"^[0-9a-f]{64}$")
HASH_LABEL = re.compile(r"^[0-9a-f]{12}$")
REDERIVED = re.compile(r"^[0-9]+ /[0-9]+$")
RELATIVE_PATH = re.compile(r"^[A-Za-z0-9_][A-Za-z0-9._/\-]*$")
KINDS = ("certificate", "document", "records", "protocol", "transcript")


def canonical_bytes(payload: dict[str, Any]) -> bytes:
    """One canonical form for hashing: sorted keys, no whitespace, UTF-8."""
    return json.dumps(payload, sort_keys=True, separators=(",", ":"),
                      ensure_ascii=False).encode("utf-8")


def sha256_bytes(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def payload_sha256(manifest: dict[str, Any]) -> str:
    """Hash the manifest with its own hash field removed."""
    payload = {k: v for k, v in manifest.items() if k != "manifest_sha256"}
    return sha256_bytes(canonical_bytes(payload))


def _relative(value: str) -> str:
    if not RELATIVE_PATH.fullmatch(value):
        raise ValueError("path must be a relative POSIX path: %r" % value)
    parts = value.split("/")
    if any(p in ("", ".", "..") for p in parts):
        raise ValueError("path contains a traversal segment: %r" % value)
    if value.startswith("/") or "\\" in value:
        raise ValueError("path must not be absolute or contain a backslash: %r" % value)
    return value


def _hex64(value: str) -> str:
    if not HEX64.fullmatch(value):
        raise ValueError("expected a lowercase 64-character sha256, got %r" % value)
    return value


class Artefact(BaseModel):
    model_config = ConfigDict(extra="forbid")

    path: str
    sha256: str
    kind: Literal["certificate", "document", "records", "protocol", "transcript"]
    bytes: int = Field(ge=0)

    @field_validator("path")
    @classmethod
    def _path(cls, v: str) -> str:
        return _relative(v)

    @field_validator("sha256")
    @classmethod
    def _hash(cls, v: str) -> str:
        return _hex64(v)


class Distribution(BaseModel):
    """The pinned wheel a stranger must be able to fetch from PyPI (I6)."""
    model_config = ConfigDict(extra="forbid")

    name: str
    version: str
    wheel: str
    sha256: str

    @field_validator("sha256")
    @classmethod
    def _hash(cls, v: str) -> str:
        return _hex64(v)

    @field_validator("wheel")
    @classmethod
    def _wheel(cls, v: str) -> str:
        if "/" in v or not v.endswith(".whl"):
            raise ValueError("wheel must be a bare .whl filename: %r" % v)
        return v


class Manifest(BaseModel):
    model_config = ConfigDict(extra="forbid")

    schema_version: Literal["1"]
    packet_id: str
    protocol_digest: str
    protocol_sha256: str
    manifest_sha256: str
    source_revision: str
    source_version: str
    bound_unit: str
    lane: str
    expected_rederived: str
    rubric: dict[str, Any]
    distribution: Distribution
    artifacts: list[Artefact]
    records_excluded: bool
    excluded_records: list[str]

    @field_validator("protocol_sha256", "manifest_sha256")
    @classmethod
    def _hash_fields(cls, v: str) -> str:
        return _hex64(v)

    @field_validator("protocol_digest")
    @classmethod
    def _digest(cls, v: str) -> str:
        if not HASH_LABEL.fullmatch(v):
            raise ValueError("protocol_digest must be 12 lowercase hex chars: %r" % v)
        return v

    @field_validator("expected_rederived")
    @classmethod
    def _rederived(cls, v: str) -> str:
        if not REDERIVED.fullmatch(v):
            raise ValueError("expected_rederived must read like '612 /612': %r" % v)
        return v

    @field_validator("excluded_records")
    @classmethod
    def _excluded(cls, v: list[str]) -> list[str]:
        return [_relative(x) for x in v]

    @model_validator(mode="after")
    def _integrity(self) -> "Manifest":
        payload = self.model_dump(mode="json", exclude={"manifest_sha256"})
        computed = sha256_bytes(canonical_bytes(payload))
        if computed != self.manifest_sha256:
            raise ValueError("manifest_sha256 mismatch: payload hashes to %s, manifest declares %s"
                             % (computed, self.manifest_sha256))
        paths = [a.path for a in self.artifacts]
        if paths != sorted(paths):
            raise ValueError("artifacts must be sorted by path")
        if len(set(paths)) != len(paths):
            raise ValueError("duplicate artefact path in artifacts")
        if not self.artifacts:
            raise ValueError("a packet must declare at least one artefact")
        if self.records_excluded and any(a.kind == "records" for a in self.artifacts):
            raise ValueError("a shareable packet cannot carry records artefacts")
        if self.records_excluded and not self.excluded_records:
            raise ValueError("records_excluded is true but excluded_records names nothing")
        if not self.records_excluded and self.excluded_records:
            raise ValueError("excluded_records is non-empty but records_excluded is false")
        if self.protocol_sha256[:12] != self.protocol_digest:
            raise ValueError("protocol_digest is not the 12-character prefix of protocol_sha256")
        return self

    def as_dict(self) -> dict[str, Any]:
        return self.model_dump(mode="json")
