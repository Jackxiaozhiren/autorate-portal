"""Pinned-distribution registry (PRD Section 7 M2).

A packet names the distribution it was produced by: ``autorate==<version>``
plus the PyPI wheel's sha256. That pin is only as good as its second reader.
This module is the second reader: a committed list of distributions this portal
has agreed to replay, consulted **before** anything is fetched from the index.
A packet whose manifest was forged therefore cannot bootstrap itself from PyPI
being reachable - the registry contradicts it.

Two different failures, two different states:

* the registry itself cannot be read  -> the environment is unusable, which is
  a ``not-run`` in the caller, not a verdict on the packet;
* the registry reads fine and the packet's pin is absent or different -> a
  named refusal naming both values, which is a verdict on the packet.
"""
from __future__ import annotations

import json
import re
from dataclasses import dataclass
from importlib import resources
from pathlib import Path
from typing import Any, Iterable

from .packet import Refusal

SHA256_HEX = re.compile(r"^[0-9a-f]{64}$")
REQUIRED_FIELDS = ("name", "version", "wheel", "sha256", "source")
OPTIONAL_FIELDS = ("registered",)
DEFAULT_NAME = "autorate"


@dataclass(frozen=True)
class Pin:
    """One distribution this portal will replay."""

    name: str
    version: str
    wheel: str
    sha256: str
    source: str
    registered: str = ""

    @property
    def specifier(self) -> str:
        return "%s==%s" % (self.name, self.version)


class Registry:
    """A validated set of pins, keyed by (name, version)."""

    def __init__(self, pins: Iterable[Pin]) -> None:
        self._pins: dict[tuple[str, str], Pin] = {}
        for pin in pins:
            self._pins[(pin.name, pin.version)] = pin

    def __len__(self) -> int:
        return len(self._pins)

    def __iter__(self):
        return iter(self._pins.values())

    def get(self, name: str, version: str) -> Pin | None:
        return self._pins.get((name, version))

    def versions(self, name: str = DEFAULT_NAME) -> tuple[str, ...]:
        return tuple(sorted(version for (pin_name, version) in self._pins if pin_name == name))


def default_path() -> Path:
    """The registry shipped inside the package."""
    return Path(str(resources.files("autorate_portal").joinpath("pins.json")))


def _validate(entry: Any, index: int) -> tuple[Pin | None, list[Refusal]]:
    where = "pins.json[%d]" % index
    if not isinstance(entry, dict):
        return None, [Refusal(where, "registry entry is not an object")]
    missing = [field for field in REQUIRED_FIELDS if not str(entry.get(field) or "").strip()]
    if missing:
        return None, [Refusal(where, "registry entry is missing required fields",
                              expected=", ".join(REQUIRED_FIELDS), actual=", ".join(missing))]
    extra = sorted(set(entry) - set(REQUIRED_FIELDS) - set(OPTIONAL_FIELDS))
    if extra:
        return None, [Refusal(where, "registry entry carries fields this schema does not define",
                              expected=", ".join(REQUIRED_FIELDS + OPTIONAL_FIELDS),
                              actual=", ".join(extra))]
    pin = Pin(name=str(entry["name"]), version=str(entry["version"]),
              wheel=str(entry["wheel"]), sha256=str(entry["sha256"]),
              source=str(entry["source"]), registered=str(entry.get("registered") or ""))
    if not pin.wheel.endswith(".whl"):
        return None, [Refusal(where, "pinned file is not a wheel", actual=pin.wheel)]
    if not SHA256_HEX.match(pin.sha256):
        return None, [Refusal(where, "pinned sha256 is not 64 lowercase hex characters",
                              actual=pin.sha256)]
    if not pin.source.startswith("https://"):
        return None, [Refusal(where, "pin source is not an https URL", actual=pin.source)]
    return pin, []


def load_registry(path: Path | None = None) -> tuple[Registry, list[Refusal]]:
    """Load and validate; a malformed file is refusals, never a silent partial load."""
    target = Path(path) if path is not None else default_path()
    try:
        document = json.loads(target.read_text(encoding="utf-8"))
    except FileNotFoundError:
        return Registry(()), [Refusal(str(target), "distribution registry not found")]
    except (OSError, ValueError, UnicodeDecodeError) as exc:
        return Registry(()), [Refusal(str(target), "distribution registry unreadable: %s" % exc)]

    entries = document.get("pins") if isinstance(document, dict) else None
    if not isinstance(entries, list):
        return Registry(()), [Refusal(str(target), "distribution registry has no 'pins' list")]

    pins: list[Pin] = []
    refusals: list[Refusal] = []
    seen: set[tuple[str, str]] = set()
    for index, entry in enumerate(entries):
        pin, problems = _validate(entry, index)
        refusals.extend(problems)
        if pin is None:
            continue
        key = (pin.name, pin.version)
        if key in seen:
            refusals.append(Refusal(pin.specifier, "duplicate registry entry; the first one stands"))
            continue
        seen.add(key)
        pins.append(pin)
    return Registry(pins), refusals


def resolve(registry: Registry, *, version: str, wheel: str, sha256: str,
            name: str = DEFAULT_NAME) -> tuple[Pin | None, list[Refusal]]:
    """Match a packet's pin against the registry; refusals name both sides."""
    pin = registry.get(name, version)
    if pin is None:
        return None, [Refusal("%s==%s" % (name, version),
                              "distribution not in the pinned registry",
                              expected="registered: %s" % (", ".join(registry.versions(name)) or "none"),
                              actual=version)]
    refusals: list[Refusal] = []
    if pin.wheel != wheel:
        refusals.append(Refusal(pin.specifier, "wheel filename disagrees with the pinned registry",
                                expected=pin.wheel, actual=wheel))
    if pin.sha256 != sha256:
        refusals.append(Refusal(pin.specifier, "wheel sha256 disagrees with the pinned registry",
                                expected=pin.sha256, actual=sha256))
    return (None if refusals else pin), refusals
