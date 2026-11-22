"""Stranger-verifiable replay (AC9, AC10, I6).

A packet, Docker and - for a schema 1 packet - network access to PyPI are the
things a stranger is allowed to have. The pinned wheel is fetched from PyPI and
its bytes are checked against ``distribution.sha256`` *before* anything runs; a
swapped hash is a named refusal, never a pass. A schema 2 packet carries its
wheel set, so the index is not consulted and a host without egress can replay;
with no Docker, or with a schema 1 packet on a host without network, the result
is a named ``not-run`` state with a non-zero exit code (AC10), never a certified
result.
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

from packaging.tags import sys_tags
from packaging.utils import InvalidWheelFilename, parse_wheel_filename

from . import EXIT_NOT_RUN, EXIT_OK, EXIT_REFUSED
from .packet import Refusal, Verification, read_bundle, verify_bundle

REDERIVED_LINE = re.compile(r"re-derived\s+([0-9]+)\s*/([0-9]+)\s+values")
SUMMARY_LINE = re.compile(r"^re-derived\s+[0-9]+\s*/[0-9]+\s+values$")
DRIFT_LINE = re.compile(r"^DRIFT:")
PYPI_JSON = "https://pypi.org/pypi/autorate/json"
INNER_COMMAND = ["verify", "--protocol", "protocol.json"]
CONTAINER_PROBE = ["python", "-c",
                   "import urllib.request;"
                   "urllib.request.urlopen('https://pypi.org/pypi/autorate/json', timeout=10)"]
REPLAY_PY = "from autorate.cli import main\nraise SystemExit(main(%r))\n" % (INNER_COMMAND,)
CONTAINER_SH = """#!/bin/sh
set -e
cp -a /packet /work
if ! python -m pip install --no-cache-dir --target /work/lib /replay/wheelhouse/{wheel}; then
  echo INSTALL_FAILED
  exit 97
fi
cd /work
AUTORATE_FEISHU_ROOT=/nonexistent PYTHONPATH=/work/lib python /replay/run_verify.py
"""
# An embedded packet must not reach the index at all: pip is told there is none
# and where the local wheels are. The pinned wheel is still the one installed;
# the rest of the directory is the dependency closure the builder supplied.
CONTAINER_SH_OFFLINE = """#!/bin/sh
set -e
cp -a /packet /work
if ! python -m pip install --no-cache-dir --no-index --find-links /replay/wheelhouse --target /work/lib {wheel}; then
  echo INSTALL_FAILED
  exit 97
fi
cd /work
AUTORATE_FEISHU_ROOT=/nonexistent PYTHONPATH=/work/lib python /replay/run_verify.py
"""


class InstallFailed(Exception):
    """The replay's install step failed; the wheel set may not fit this target."""

    def __init__(self, command: list[str], output: str):
        super().__init__("install step failed: %s" % (output.strip().splitlines()[-1:] or ""))
        self.command = command
        self.output = output


def incompatible_wheels(wheels: dict[str, bytes]) -> list[tuple[str, str]]:
    """Wheels whose tags this interpreter cannot install, with their platforms.

    Called before anything is installed on the uv backend: the interpreter that
    will run `pip` is the one asking, so `sys_tags()` is the right oracle. The
    container backend asks a different interpreter and relies on the install
    step's own failure, which is now named rather than reported as `exited 1`.
    """
    supported = set(sys_tags())
    stuck: list[tuple[str, str]] = []
    for name in sorted(wheels):
        try:
            _, _, _, tags = parse_wheel_filename(name)
        except InvalidWheelFilename:
            stuck.append((name, "unparseable wheel filename"))
            continue
        if not (tags & supported):
            stuck.append((name, ", ".join(sorted({tag.platform for tag in tags}))))
    return stuck


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
    summary_line: str = ""
    expected: str = ""
    disagrees: bool = False
    channel: str = ""  # online | offline; empty only when no manifest was read
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
                "disagrees": self.disagrees, "summary_line": self.summary_line,
                "channel": self.channel or "unknown"}


def summary_line(stdout: str) -> str:
    """The tool's own last word, quoted rather than paraphrased (F6 rule 3).

    `re-derived N /M values` is the line `verify` prints whether it holds or
    drifts; a run that drifted also prints `DRIFT:` on stderr, which a monitor
    surfaces separately. The first matching line wins, so a wrapper that echoes
    the command cannot displace the result.
    """
    for line in stdout.splitlines():
        if SUMMARY_LINE.match(line.strip()):
            return line.strip()
    for line in stdout.splitlines():
        if DRIFT_LINE.match(line.strip()):
            return line.strip()
    return ""


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
                   verification: Verification, wheels: dict[str, bytes], offline: bool,
                   runner: Callable[..., subprocess.CompletedProcess]) -> tuple[list[str], str, int]:
    manifest = verification.manifest
    wheel_filename = manifest.distribution.wheel
    wheelhouse = replay_dir / "wheelhouse"
    wheelhouse.mkdir()
    for name, data in wheels.items():
        (wheelhouse / name).write_bytes(data)
    (replay_dir / "run_verify.py").write_text(REPLAY_PY, encoding="utf-8")
    template = CONTAINER_SH_OFFLINE if offline else CONTAINER_SH
    (replay_dir / "replay.sh").write_text(template.format(wheel=wheel_filename), encoding="utf-8")
    argv = _container_argv(env, work, replay_dir, wheel_filename)
    proc = runner(argv)
    return argv, proc.stdout or "", proc.returncode


def _run_uv(work: Path, wheels: dict[str, bytes], wheel_filename: str, offline: bool,
            runner: Callable[..., subprocess.CompletedProcess]) -> tuple[list[str], str, int]:
    """CLI-only path (section 4.2): an isolated uv environment, not the host site-packages."""
    evidence = work / "evidence"
    venv = work / "venv"
    wheelhouse = work / "wheelhouse"
    wheelhouse.mkdir()
    for name, data in wheels.items():
        (wheelhouse / name).write_bytes(data)
    wheel_path = wheelhouse / wheel_filename
    script = work / "run_verify.py"
    script.write_text(REPLAY_PY, encoding="utf-8")
    python = str(venv / "bin" / "python")
    install = ["uv", "pip", "install", "--python", python, "--target", str(evidence / "lib")]
    if offline:
        install += ["--no-index", "--find-links", str(wheelhouse)]
    setup = [["uv", "venv", str(venv)], install + [str(wheel_path)]]
    for command in setup:
        proc = runner(command)
        if proc.returncode != 0:
            raise InstallFailed(command, proc.stdout or "")
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
    # The channel is a property of the packet, not of the host: a schema 2
    # packet replays offline even on a machine that happens to have egress, and
    # a schema 1 packet stays online even on one that does not. A `not-run`
    # therefore still names the channel it would have used.
    channel = "offline" if manifest.embeds_wheel else "online"
    base = {"digest_then": manifest.protocol_digest, "packet_id_in": manifest.packet_id,
            "expected": manifest.expected_rederived, "channel": channel}

    if manifest.records_excluded:
        return ReplayOutcome("not-run", EXIT_NOT_RUN,
                             "shareable packet excludes records artefacts; replay needs the full "
                             "org-private packet (PRD section 8.4)", **base)

    # A packet that carries its wheel set needs no index. The distinction is the
    # whole point of schema 2: without it, an air-gapped host can only report
    # not-run, which is honest but useless to the auditor who brought the packet.
    offline = manifest.embeds_wheel
    required = {"container": env.docker_available and (offline or env.network_available),
                "uv": offline or env.network_available}
    if backend not in required:
        return ReplayOutcome("refused", EXIT_REFUSED,
                             "unknown replay backend %r" % backend, **base)
    if not required[backend]:
        reasons = []
        if backend == "container" and not env.docker_available:
            reasons.append(env.docker_detail)
        if not offline and not env.network_available:
            reasons.append(env.network_detail)
        return ReplayOutcome("not-run", EXIT_NOT_RUN,
                             "replay prerequisites absent: %s" % "; ".join(reasons), **base)

    if offline:
        wheels = {artifact.path.rsplit("/", 1)[-1]: verification.files[artifact.path]
                  for artifact in manifest.artifacts if artifact.kind == "wheel"}
        if manifest.distribution.wheel not in wheels:
            return ReplayOutcome(
                "refused", EXIT_REFUSED,
                "the packet declares an embedded wheel set but does not carry the pinned wheel %s"
                % manifest.distribution.wheel, **base)
        wheel = wheels[manifest.distribution.wheel]
    else:
        getter = env.wheel_fetcher or fetch_wheel
        try:
            wheel = getter(manifest.distribution.wheel)
        except Exception as exc:  # noqa: BLE001 - a named not-run, never a pass
            return ReplayOutcome("not-run", EXIT_NOT_RUN,
                                 "pinned wheel could not be fetched: %s" % exc, **base)
        wheels = {manifest.distribution.wheel: wheel}
    actual = hashlib.sha256(wheel).hexdigest()
    if actual != manifest.distribution.sha256:
        return ReplayOutcome(
            "refused", EXIT_REFUSED,
            "pinned wheel sha256 mismatch; the packet does not chain to the published distribution",
            refusals=[Refusal(manifest.distribution.wheel,
                              "pinned wheel sha256 mismatch",
                              expected=manifest.distribution.sha256, actual=actual)],
            **base)

    if offline and backend == "uv":
        stuck = incompatible_wheels(wheels)
        if stuck:
            declared = ", ".join(getattr(manifest, "wheel_platforms", []))
            return ReplayOutcome(
                "refused", EXIT_REFUSED,
                "embedded wheel(s) do not install on this interpreter: %s; the packet declares %s"
                % ("; ".join("%s [%s]" % (name, platforms) for name, platforms in stuck), declared),
                refusals=[Refusal(name, "wheel platform does not match this interpreter",
                                  expected=declared, actual=platforms)
                          for name, platforms in stuck],
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
                                                         wheels, offline, runner)
            else:
                argv, stdout, exit_code = _run_uv(work, wheels, manifest.distribution.wheel,
                                                  offline, runner)
        except subprocess.TimeoutExpired as exc:
            # F6 exception (b): a replay that exceeded its budget did not observe
            # anything. The partial stdout is hashed so the record says what the
            # attempt had printed when it was cut off, and the state is not-run.
            partial = exc.stdout or b""
            if isinstance(partial, bytes):
                partial = partial.decode("utf-8", "replace")
            return ReplayOutcome("not-run", EXIT_NOT_RUN,
                                 "replay exceeded its timeout: %s" % exc,
                                 stdout_sha256=hashlib.sha256(
                                     partial.encode("utf-8", "replace")).hexdigest(),
                                 **base)
        except InstallFailed as exc:
            declared = ", ".join(getattr(manifest, "wheel_platforms", []))
            tail = exc.output.strip().splitlines()[-1] if exc.output.strip() else "no output"
            return ReplayOutcome(
                "refused", EXIT_REFUSED,
                "the replay's install step failed: %s; the packet declares %s"
                % (tail, declared or "no platforms"), **base)
        except OSError as exc:
            return ReplayOutcome("not-run", EXIT_NOT_RUN,
                                 "replay runner failed: %s" % exc, **base)

    stdout_hash = hashlib.sha256(stdout.encode("utf-8", "replace")).hexdigest()
    ran = {"argv": argv, "command": list(INNER_COMMAND), "exit_code": exit_code,
           "stdout_sha256": stdout_hash, "summary_line": summary_line(stdout)}
    if exit_code == 97 or "INSTALL_FAILED" in stdout:
        declared = ", ".join(getattr(manifest, "wheel_platforms", []))
        return ReplayOutcome(
            "refused", EXIT_REFUSED,
            "the replay's install step failed inside %s; the packet declares %s"
            % (env.image, declared or "no platforms"), **ran, **base)
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
