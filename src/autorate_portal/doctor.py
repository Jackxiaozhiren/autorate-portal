"""``doctor``: what this machine can be asked to do, decided before a replay.

Section 7's M2 row pairs the runner with a doctor, and Section 13.1's
clean-machine row is "fresh clone or container, ``doctor`` then AC9". The point
is to reach AC10's ``not-run`` verdict *before* spending a replay, with the same
reason a stranger would see - not to substitute for the replay itself.

Doctor therefore reports check rows and never a certificate verdict: the strings
that mean "this claim is bounded" do not appear in its output at all. A check is
``ok``, ``fail``, or ``not-required`` for the backend that was requested; a
``fail`` on a required check makes the exit code 3, which is the not-run code
everywhere else in this package.
"""
from __future__ import annotations

import shutil
import sys
from dataclasses import dataclass
from pathlib import Path

from . import EXIT_NOT_RUN, EXIT_OK
from .distributions import load_registry
from .packet import verify_bundle
from .replay import Environment, probe_container_network, probe_environment

MIN_PYTHON = (3, 10)
CERTIFICATE_WORDS = ("certified", "certifies", "passed")
DEFAULT_IMAGE = "python:3.13-slim"


@dataclass(frozen=True)
class Check:
    name: str
    status: str  # ok | fail | not-required
    detail: str


def _python() -> Check:
    if sys.version_info[:2] >= MIN_PYTHON:
        return Check("python", "ok", "%d.%d.%d" % sys.version_info[:3])
    return Check("python", "fail", "%d.%d.%d is below the %d.%d floor"
                 % (sys.version_info[:3] + MIN_PYTHON))


def _uv(backend: str) -> Check:
    found = shutil.which("uv")
    if backend != "uv":
        return Check("uv", "not-required", "only the uv backend needs it")
    if found:
        return Check("uv", "ok", found)
    return Check("uv", "fail", "uv not found on PATH and the uv backend was requested")


def _docker(backend: str, env: Environment) -> Check:
    if backend != "container":
        return Check("docker", "not-required", "only the container backend needs it")
    return Check("docker", "ok" if env.docker_available else "fail", env.docker_detail)


def _container_network(backend: str, env: Environment, image: str, probe) -> Check:
    """Egress from inside the container, which the host-level probe cannot see."""
    if backend != "container":
        return Check("container-network", "not-required", "only the container backend needs it")
    if not env.docker_available:
        return Check("container-network", "not-required", "docker itself already failed")
    reachable, detail = probe(image)
    return Check("container-network", "ok" if reachable else "fail", detail)


def _pypi(env: Environment) -> Check:
    if env.network_available:
        return Check("pypi", "ok", env.network_detail)
    return Check("pypi", "fail", env.network_detail)


def _registry(registry_path: Path | None) -> Check:
    registry, problems = load_registry(registry_path)
    if problems:
        return Check("registry", "fail", "; ".join("%s: %s" % (r.path, r.reason) for r in problems))
    return Check("registry", "ok", "%d pinned distribution(s): %s"
                 % (len(registry), ", ".join(pin.specifier for pin in registry)))


def _packet(packet_path: Path | None) -> Check:
    if packet_path is None:
        return Check("packet", "not-required", "no packet was given")
    verification = verify_bundle(Path(packet_path))
    if verification.ok:
        return Check("packet", "ok", str(packet_path))
    return Check("packet", "fail", "; ".join("%s: %s" % (r.path, r.reason)
                                             for r in verification.refusals))


def examine(*, backend: str = "container", registry_path: Path | None = None,
            packet_path: Path | None = None, env: Environment | None = None,
            image: str = DEFAULT_IMAGE,
            container_probe=probe_container_network) -> list[Check]:
    environment = env or probe_environment(image=image)
    return [_python(), _uv(backend), _docker(backend, environment),
            _container_network(backend, environment, image, container_probe),
            _pypi(environment), _registry(registry_path), _packet(packet_path)]


def exit_code(checks: list[Check]) -> int:
    return EXIT_NOT_RUN if any(check.status == "fail" for check in checks) else EXIT_OK


def render(checks: list[Check]) -> str:
    width = max(len(check.name) for check in checks)
    return "\n".join("%-*s  %-12s  %s" % (width, check.name, check.status, check.detail)
                     for check in checks)
