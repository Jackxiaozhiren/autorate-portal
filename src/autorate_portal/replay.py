"""Stranger-verifiable replay (AC9, AC10, I6).

A packet, network access to PyPI and Docker are the three things a stranger is
allowed to have. The pinned wheel is fetched from PyPI and its bytes are checked
against ``distribution.sha256`` *before* anything runs; a swapped hash is a
named refusal, never a pass. With no Docker or no network the result is a named
``not-run`` state with a non-zero exit code (AC10), never a certified result.
"""
from __future__ import annotations

import hashlib
import json
import os
import re
import shutil
import subprocess
import tempfile
import urllib.request
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Callable

from . import EXIT_NOT_RUN, EXIT_OK, EXIT_REFUSED
from .packet import Refusal, Verification, read_bundle, verify_bundle

REDERIVED_LINE = re.compile(r"re-derived\s+([0-9]+)\s*/([0-9]+)\s+values")
PYPI_JSON = "https://pypi.org/pypi/autorate/json"
INNER_COMMAND = ["verify", "--protocol", "protocol.json"]
CONTAINER_PROBE = ["python", "-c",
                   "import urllib.request;"
                   "urllib.request.urlopen('https://pypi.org/pypi/autorate/json', timeout=10)"]
REPLAY_PY = "from autorate.cli import main\nraise SystemExit(main(%r))\n" % (INNER_COMMAND,)
CONTAINER_SH = """#!/bin/sh
set -e
cp -a /packet /work
python -m pip install --no-cache-dir --target /work/lib /replay/{wheel}
cd /work
AUTORATE_FEISHU_ROOT=/nonexistent PYTHONPATH=/work/lib python /replay/run_verify.py
"""


@dataclass
class Environment:
    docker_available: bool
    network_available: bool
    docker_detail: str
    network_detail: str
    image: str = "python:3.13-slim"
    runner: Callable[..., subprocess.CompletedProcess] | None = None
    wheel_fetcher: Callable[[str], bytes] | None = None


@dataclass
class ReplayOutcome:
    state: str  # certified | not-run | refused
    rc: int
    reason: str = ""
    argv: list[str] = field(default_factory=list)
    command: list[str] = field(default_factory=list)
    exit_code: int | None = None
    stdout_sha256: str = ""
    digest_then: str = ""
    packet_id_in: str = ""
    rederived: str = ""
    expected: str = ""
    disagrees: bool = False
    refusals: list[Refusal] = field(default_factory=list)

    def run_row(self) -> dict[str, Any]:
        """PRD section 4.3 run-row shape; section 11 observability.

        ``command`` is the argv handed to ``autorate``'s entry point - the same
        object that generates the replay script, so it is captured rather than
        reconstructed (I5). ``disagrees`` lets the engine name a mismatch
        without widening this module's M1 refusal contract.
        """
        return {"argv": self.argv, "command": self.command, "exit_code": self.exit_code,
                "stdout_sha256": self.stdout_sha256, "digest_then": self.digest_then,
                "packet_id_in": self.packet_id_in, "state": self.state,
                "disagrees": self.disagrees}


def probe_container_network(image: str,
                            runner: Callable[..., subprocess.CompletedProcess] | None = None
                            ) -> tuple[bool, str]:
    """Can the *image* reach the index, not just this host?

    The host-level probe above cannot see inside the container, and the
    difference matters: a container without egress fails while installing the
    pinned wheel's dependencies, which surfaces as ``refused`` with exit 1 and
    reads like a packet defect. ``doctor`` asks this question first so the
    machine gets blamed for its own missing egress.
    """
    docker = shutil.which("docker")
    if not docker:
        return False, "docker executable not found"
    run = runner or (lambda argv, **kw: subprocess.run(argv, capture_output=True, text=True,
                                                      timeout=180, **kw))
    argv = [docker, "run", "--rm", image] + CONTAINER_PROBE
    try:
        proc = run(argv)
    except (OSError, subprocess.TimeoutExpired) as exc:
        return False, "container network probe failed: %s" % exc
    if proc.returncode == 0:
        return True, "%s reaches PyPI from inside the container" % image
    lines = [line for line in (proc.stderr or proc.stdout or "").strip().splitlines() if line.strip()]
    return False, "container cannot reach PyPI: %s" % (lines[-1][:180] if lines else
                                                      "rc=%d" % proc.returncode)


def probe_environment(image: str = "python:3.13-slim") -> Environment:
    docker = shutil.which("docker")
    docker_ok, docker_detail = False, "docker executable not found"
    if docker:
        try:
            proc = subprocess.run([docker, "info", "--format", "{{.ServerVersion}}"],
                                  capture_output=True, text=True, timeout=30)
            docker_ok = proc.returncode == 0
            docker_detail = ("docker daemon %s" % proc.stdout.strip() if docker_ok
                             else "docker info rc=%d: %s" % (proc.returncode, proc.stderr.strip()[:160]))
        except (OSError, subprocess.TimeoutExpired) as exc:
            docker_detail = "docker info failed: %s" % exc
    network_ok, network_detail = False, "PyPI metadata not reachable"
    try:
        with urllib.request.urlopen(PYPI_JSON, timeout=10) as response:
            json.load(response)
        network_ok, network_detail = True, "%s reachable" % PYPI_JSON
    except Exception as exc:  # noqa: BLE001 - a named not-run, never a pass
        network_detail = "PyPI metadata unreachable: %s" % exc
    return Environment(docker_ok, network_ok, docker_detail, network_detail, image=image)


def fetch_wheel(wheel_filename: str) -> bytes:
    with urllib.request.urlopen(PYPI_JSON, timeout=20) as response:
        document = json.load(response)
    for entry in document.get("urls", []):
        if entry.get("filename") == wheel_filename:
            with urllib.request.urlopen(entry["url"], timeout=60) as wheel:
                return wheel.read()
    raise ValueError("PyPI does not publish a distribution file named %s" % wheel_filename)


def _extract(packet_path: Path, destination: Path) -> None:
    files = read_bundle(packet_path)
    files.pop("manifest.json", None)
    for name, data in files.items():
        target = destination / name
        target.parent.mkdir(parents=True, exist_ok=True)
        target.write_bytes(data)


def _parse_rederived(stdout: str) -> str:
    found = REDERIVED_LINE.search(stdout)
    if not found:
        return ""
    return "%s /%s" % (found.group(1), found.group(2))


def _container_argv(env: Environment, work: Path, replay_dir: Path,
                    wheel_filename: str) -> list[str]:
    return ["docker", "run", "--rm",
            "-v", "%s:/packet:ro" % (work / "evidence"),
            "-v", "%s:/replay:ro" % replay_dir,
            env.image, "sh", "/replay/replay.sh"]


def _run_container(env: Environment, work: Path, replay_dir: Path,
                   verification: Verification, wheel: bytes,
                   runner: Callable[..., subprocess.CompletedProcess]) -> tuple[list[str], str, int]:
    manifest = verification.manifest
    wheel_filename = manifest.distribution.wheel
    (replay_dir / wheel_filename).write_bytes(wheel)
    (replay_dir / "run_verify.py").write_text(REPLAY_PY, encoding="utf-8")
    (replay_dir / "replay.sh").write_text(CONTAINER_SH.format(wheel=wheel_filename), encoding="utf-8")
    argv = _container_argv(env, work, replay_dir, wheel_filename)
    proc = runner(argv)
    return argv, proc.stdout or "", proc.returncode


def _run_uv(work: Path, wheel: bytes, wheel_filename: str,
            runner: Callable[..., subprocess.CompletedProcess]) -> tuple[list[str], str, int]:
    """CLI-only path (section 4.2): an isolated uv environment, not the host site-packages."""
    evidence = work / "evidence"
    venv = work / "venv"
    wheel_path = work / wheel_filename
    wheel_path.write_bytes(wheel)
    script = work / "run_verify.py"
    script.write_text(REPLAY_PY, encoding="utf-8")
    python = str(venv / "bin" / "python")
    setup = [["uv", "venv", str(venv)],
             ["uv", "pip", "install", "--python", python, "--target", str(evidence / "lib"),
              str(wheel_path)]]
    for command in setup:
        proc = runner(command)
        if proc.returncode != 0:
            return command, proc.stdout or "", proc.returncode
    argv = [python, str(script)]
    child_env = {**os.environ, "PYTHONPATH": str(evidence / "lib"),
                 "AUTORATE_FEISHU_ROOT": "/nonexistent"}
    proc = runner(argv, cwd=str(evidence), env=child_env)
    return argv, proc.stdout or "", proc.returncode


def verify_packet(packet_path: Path, env: Environment,
                  backend: str = "container") -> ReplayOutcome:
    verification: Verification = verify_bundle(packet_path)
    if not verification.ok or verification.manifest is None:
        return ReplayOutcome("refused", EXIT_REFUSED,
                             "packet integrity check failed; nothing was replayed",
                             refusals=verification.refusals)
    manifest = verification.manifest
    base = {"digest_then": manifest.protocol_digest, "packet_id_in": manifest.packet_id,
            "expected": manifest.expected_rederived}

    if manifest.records_excluded:
        return ReplayOutcome("not-run", EXIT_NOT_RUN,
                             "shareable packet excludes records artefacts; replay needs the full "
                             "org-private packet (PRD section 8.4)", **base)

    required = {"container": env.docker_available and env.network_available,
                "uv": env.network_available}
    if backend not in required:
        return ReplayOutcome("refused", EXIT_REFUSED,
                             "unknown replay backend %r" % backend, **base)
    if not required[backend]:
        reasons = []
        if backend == "container" and not env.docker_available:
            reasons.append(env.docker_detail)
        if not env.network_available:
            reasons.append(env.network_detail)
        return ReplayOutcome("not-run", EXIT_NOT_RUN,
                             "replay prerequisites absent: %s" % "; ".join(reasons), **base)

    getter = env.wheel_fetcher or fetch_wheel
    try:
        wheel = getter(manifest.distribution.wheel)
    except Exception as exc:  # noqa: BLE001 - a named not-run, never a pass
        return ReplayOutcome("not-run", EXIT_NOT_RUN,
                             "pinned wheel could not be fetched: %s" % exc, **base)
    actual = hashlib.sha256(wheel).hexdigest()
    if actual != manifest.distribution.sha256:
        return ReplayOutcome(
            "refused", EXIT_REFUSED,
            "pinned wheel sha256 mismatch; the packet does not chain to the published distribution",
            refusals=[Refusal(manifest.distribution.wheel,
                              "pinned wheel sha256 mismatch",
                              expected=manifest.distribution.sha256, actual=actual)],
            **base)

    runner = env.runner or (lambda argv, **kw: subprocess.run(
        argv, capture_output=True, text=True, timeout=900, **kw))
    with tempfile.TemporaryDirectory(prefix="autorate-portal-replay-") as tmp:
        work = Path(tmp)
        evidence = work / "evidence"
        evidence.mkdir()
        _extract(packet_path, evidence)
        replay_dir = work / "replay"
        replay_dir.mkdir()
        try:
            if backend == "container":
                argv, stdout, exit_code = _run_container(env, work, replay_dir, verification,
                                                         wheel, runner)
            else:
                argv, stdout, exit_code = _run_uv(work, wheel, manifest.distribution.wheel, runner)
        except (OSError, subprocess.TimeoutExpired) as exc:
            return ReplayOutcome("not-run", EXIT_NOT_RUN,
                                 "replay runner failed: %s" % exc, **base)

    stdout_hash = hashlib.sha256(stdout.encode("utf-8", "replace")).hexdigest()
    ran = {"argv": argv, "command": list(INNER_COMMAND), "exit_code": exit_code,
           "stdout_sha256": stdout_hash}
    if exit_code != 0:
        return ReplayOutcome("refused", EXIT_REFUSED,
                             "replay exited %d; a failed replay is not a pass" % exit_code,
                             **ran, **base)
    rederived = _parse_rederived(stdout)
    if not rederived:
        return ReplayOutcome("refused", EXIT_REFUSED,
                             "replay printed no 're-derived N /M values' line",
                             **ran, **base)
    if rederived != manifest.expected_rederived:
        return ReplayOutcome("refused", EXIT_REFUSED,
                             "re-derived line disagrees with the packet's stored denominator",
                             rederived=rederived, disagrees=True, **ran, **base)
    return ReplayOutcome("certified", EXIT_OK, "replay reproduced the packet's stored denominator",
                         rederived=rederived, **ran, **base)
