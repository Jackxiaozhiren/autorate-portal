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

from packaging.utils import InvalidWheelFilename, parse_wheel_filename
from pydantic import BaseModel, ConfigDict, Field, field_validator, model_validator

HEX64 = re.compile(r"^[0-9a-f]{64}$")
HASH_LABEL = re.compile(r"^[0-9a-f]{12}$")
REDERIVED = re.compile(r"^[0-9]+ /[0-9]+$")
RELATIVE_PATH = re.compile(r"^[A-Za-z0-9_][A-Za-z0-9._/\-]*$")
KINDS = ("certificate", "document", "records", "protocol", "transcript", "wheel")


def canonical_bytes(payload: dict[str, Any]) -> bytes:
    """One canonical form for hashing: sorted keys, no whitespace, UTF-8."""
    return json.dumps(payload, sort_keys=True, separators=(",", ":"),
                      ensure_ascii=False).encode("utf-8")


def wheel_platforms_for(paths: list[str]) -> list[str]:
    """The platform tags a wheel set can install on, derived from its filenames.

    Derived rather than declared: a field a builder can type is a field that can
    disagree with the bytes next to it. ``any`` is kept as a platform value
    because it is the honest answer for a pure-Python wheel.
    """
    platforms: set[str] = set()
    for path in paths:
        name = path.rsplit("/", 1)[-1]
        try:
            _, _, _, tags = parse_wheel_filename(name)
        except InvalidWheelFilename as exc:
            raise ValueError("wheel filename is not parseable: %s (%s)" % (name, exc)) from exc
        platforms.update(tag.platform for tag in tags)
    return sorted(platforms)


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
    kind: Literal["certificate", "document", "records", "protocol", "transcript", "wheel"]
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
    """The pinned wheel a replay installs.

    Schema 1 fetches it from the index; schema 2 may carry it inside the packet,
    which is what lets a host without egress replay at all.
    """
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
        if self.schema_version == "1" and any(a.kind == "wheel" for a in self.artifacts):
            raise ValueError("schema 1 packets cannot carry wheel artefacts; embedding requires schema 2")
        return self

    @property
    def embeds_wheel(self) -> bool:
        """Schema 1 cannot embed a wheel; the accessor keeps callers version-agnostic."""
        return False

    def as_dict(self) -> dict[str, Any]:
        return self.model_dump(mode="json")


class ManifestV2(Manifest):
    """Schema 2: the packet may carry the wheel set a replay needs.

    The embedded set is evidence like any other artefact - each wheel is listed
    with its sha256 and byte count, so a replay that uses one can say which bytes
    it used. The flag is explicit rather than inferred from the artefacts because
    "this packet is replayable offline" is a claim, and a claim needs a field
    somebody can be held to.
    """

    schema_version: Literal["2"]
    wheel_embedded: bool
    wheel_platforms: list[str]

    @property
    def embeds_wheel(self) -> bool:
        return self.wheel_embedded

    @model_validator(mode="after")
    def _wheel_set(self) -> "ManifestV2":
        wheels = {a.path.rsplit("/", 1)[-1] for a in self.artifacts if a.kind == "wheel"}
        misplaced = [a.path for a in self.artifacts
                     if (a.kind == "wheel") != a.path.startswith("wheel/")]
        if misplaced:
            raise ValueError("wheel artefacts live under wheel/ and nowhere else: %s"
                             % ", ".join(sorted(misplaced)))
        if self.wheel_embedded:
            if not wheels:
                raise ValueError("wheel_embedded is true but no wheel artefact is declared")
            if self.distribution.wheel not in wheels:
                raise ValueError("the embedded set does not carry the pinned wheel %s"
                                 % self.distribution.wheel)
            derived = wheel_platforms_for([a.path for a in self.artifacts if a.kind == "wheel"])
            if self.wheel_platforms != derived:
                raise ValueError(
                    "wheel_platforms does not match the declared wheels: declared %s, derived %s"
                    % (self.wheel_platforms, derived))
        elif wheels or self.wheel_platforms:
            raise ValueError("wheel artefacts are declared but wheel_embedded is false")
        return self
