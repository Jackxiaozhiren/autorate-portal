"""The replay engine: the only place in this package that executes anything.

Section 7's M2 row gives the engine four jobs - run, capture argv / exit code /
stdout hash, keep a pinned-distribution registry, and degrade to ``not-run``
when it cannot run - and one prohibition: *no endpoint computes a bound*. This
module therefore stores numbers the replay printed and hashes; it never derives
one, never averages two, and never fills a missing value.

Section 4.3's run row is the unit of record, and each attempt is its own row.
This started as "idempotent on ``run_id``, the AC14 pattern applied to runs";
that was wrong on two counts. AC14 is about ingesting the same *packet* twice,
and CI showed a replay's stdout hash moves with the container's package-install
output, so an identity keyed on "the same observation" would have deduplicated
nothing while claiming to. A monitor's re-runs are a series of observations, not
duplicates of one, so the store is append-only and the id names the attempt.

``started_at`` is recorded on every attempt, refusals included, because a series
whose order cannot be recovered is not a series. It is metadata about the
observation, not part of its identity: adding a clock to the id would make the
same observation hash differently on every replay while proving nothing.

States (Section 5.11, AC4):

``certified``  replay ran and reproduced the packet's stored denominator
``mismatch``   replay ran and disagreed; both digests are named on the row
``refused``    integrity, pin or replay failure - never a pass
``not-run``    prerequisites absent; ``argv`` is empty and ``exit_code`` null
"""
from __future__ import annotations

import json
from dataclasses import dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from . import EXIT_NOT_RUN, EXIT_OK, EXIT_REFUSED
from .distributions import load_registry, resolve
from .manifest import sha256_bytes
from .packet import Refusal, verify_bundle
from .replay import Environment, probe_environment, verify_packet

STATES = ("certified", "mismatch", "refused", "not-run")
STATE_RC = {"certified": EXIT_OK, "mismatch": EXIT_REFUSED, "refused": EXIT_REFUSED,
            "not-run": EXIT_NOT_RUN}
RUN_ID_FIELDS = ("packet_id", "backend", "image", "argv", "command", "distribution",
                 "state", "reason", "exit_code", "stdout_sha256", "digest_stored",
                 "digest_replayed", "denominator_stored", "denominator_replayed")


@dataclass(frozen=True)
class RunRow:
    """One replay attempt, in the shape Section 4.3 asks for."""

    run_id: str
    packet_id: str
    backend: str
    image: str
    distribution: str
    wheel_sha256: str
    argv: list[str]
    command: list[str]
    exit_code: int | None
    started_at: str
    stdout_sha256: str
    state: str
    rc: int
    reason: str
    digest_stored: str
    digest_replayed: str
    denominator_stored: str
    denominator_replayed: str
    refusals: list[Refusal] = field(default_factory=list)

    def as_json(self) -> dict[str, Any]:
        return {
            "run_id": self.run_id,
            "packet_id": self.packet_id,
            "backend": self.backend,
            "image": self.image,
            "distribution": self.distribution,
            "wheel_sha256": self.wheel_sha256,
            "argv": list(self.argv),
            "command": list(self.command),
            "exit_code": self.exit_code,
            "started_at": self.started_at,
            "stdout_sha256": self.stdout_sha256,
            "state": self.state,
            "rc": self.rc,
            "reason": self.reason,
            "digest_stored": self.digest_stored,
            "digest_replayed": self.digest_replayed,
            "denominator_stored": self.denominator_stored,
            "denominator_replayed": self.denominator_replayed,
            "refusals": [{"path": r.path, "reason": r.reason,
                          "expected": r.expected, "actual": r.actual} for r in self.refusals],
        }


def describe(refusals: list[Refusal]) -> str:
    return "; ".join("%s: %s" % (r.path, r.reason) for r in refusals)


def run_id_for(observation: dict[str, Any]) -> str:
    """Identity of one attempt: what was asked, and what came back.

    Two attempts are two rows even when they agree, because a row is an
    observation and a monitor needs the series. Including ``argv`` and the
    stdout hash is what makes the id name the attempt rather than the job.
    """
    payload = {key: observation.get(key) for key in RUN_ID_FIELDS}
    encoded = json.dumps(payload, sort_keys=True, separators=(",", ":")).encode("utf-8")
    return sha256_bytes(encoded)


def classify(outcome) -> str:
    """Map a replay outcome onto a run state.

    ``disagrees`` is checked first: a replay that ran and disagreed with the
    stored summary is AC4's mismatch, not a generic refusal. The replay module
    keeps its own M1 state unchanged; the naming happens here.
    """
    if outcome.disagrees:
        return "mismatch"
    if outcome.state in ("certified", "not-run"):
        return outcome.state
    return "refused"


def _row(*, packet_id: str, backend: str, distribution: str, wheel_sha256: str,
         argv: list[str], command: list[str], exit_code: int | None, started_at: str,
         stdout_sha256: str,
         state: str, reason: str, digest_stored: str, digest_replayed: str,
         denominator_stored: str, denominator_replayed: str, image: str = "",
         refusals: list[Refusal] | None = None) -> RunRow:
    observation = {"packet_id": packet_id, "backend": backend, "image": image,
                   "argv": list(argv), "command": list(command),
                   "distribution": distribution, "state": state, "reason": reason,
                   "exit_code": exit_code, "stdout_sha256": stdout_sha256,
                   "digest_stored": digest_stored, "digest_replayed": digest_replayed,
                   "denominator_stored": denominator_stored,
                   "denominator_replayed": denominator_replayed}
    return RunRow(
        run_id=run_id_for(observation),
        packet_id=packet_id, backend=backend, image=image, distribution=distribution,
        wheel_sha256=wheel_sha256, argv=list(argv), command=list(command),
        exit_code=exit_code, started_at=started_at, stdout_sha256=stdout_sha256,
        state=state,
        rc=STATE_RC[state], reason=reason, digest_stored=digest_stored,
        digest_replayed=digest_replayed, denominator_stored=denominator_stored,
        denominator_replayed=denominator_replayed, refusals=list(refusals or []))


def run(packet_path: Path, *, backend: str = "container", registry_path: Path | None = None,
        env: Environment | None = None, store_path: Path | None = None,
        image: str = "python:3.13-slim") -> RunRow:
    """Execute one replay job and, if a store is given, record it."""
    packet = Path(packet_path)
    started_at = datetime.now(timezone.utc).isoformat(timespec="microseconds")
    verification = verify_bundle(packet)
    if not verification.ok or verification.manifest is None:
        row = _row(packet_id="", backend=backend, distribution="", wheel_sha256="",
                   argv=[], command=[], exit_code=None, started_at=started_at,
                   stdout_sha256="",
                   state="refused",
                   reason="packet integrity check failed; nothing was replayed",
                   digest_stored="", digest_replayed="", denominator_stored="",
                   denominator_replayed="", refusals=verification.refusals)
        return _record(row, store_path)

    manifest = verification.manifest
    pinned = "%s==%s" % (manifest.distribution.name, manifest.distribution.version)

    registry, problems = load_registry(registry_path)
    if problems:
        row = _row(packet_id=manifest.packet_id, backend=backend, distribution=pinned,
                   wheel_sha256=manifest.distribution.sha256, argv=[], command=[],
                   exit_code=None, started_at=started_at, stdout_sha256="", state="not-run",
                   reason="pinned-distribution registry unusable: %s" % describe(problems),
                   digest_stored=manifest.manifest_sha256, digest_replayed="",
                   denominator_stored=manifest.expected_rederived, denominator_replayed="",
                   refusals=problems)
        return _record(row, store_path)

    pin, problems = resolve(registry, version=manifest.distribution.version,
                            wheel=manifest.distribution.wheel,
                            sha256=manifest.distribution.sha256)
    if problems:
        row = _row(packet_id=manifest.packet_id, backend=backend, distribution=pinned,
                   wheel_sha256=manifest.distribution.sha256, argv=[], command=[],
                   exit_code=None, started_at=started_at, stdout_sha256="", state="refused",
                   reason="packet pin rejected by the registry: %s" % describe(problems),
                   digest_stored=manifest.manifest_sha256, digest_replayed="",
                   denominator_stored=manifest.expected_rederived, denominator_replayed="",
                   refusals=problems)
        return _record(row, store_path)

    environment = env or probe_environment(image=image)
    outcome = verify_packet(packet, environment, backend=backend)
    image = environment.image if backend == "container" else ""
    state = classify(outcome)
    reason = outcome.reason
    if state == "mismatch":
        reason = ("stored denominator %s disagrees with the replay's %s; "
                  "stored digest %s, replay digest %s"
                  % (manifest.expected_rederived, outcome.rederived,
                     manifest.manifest_sha256, outcome.stdout_sha256))
    row = _row(packet_id=manifest.packet_id, backend=backend, distribution=pin.specifier,
               wheel_sha256=pin.sha256, argv=outcome.argv, command=outcome.command,
               exit_code=outcome.exit_code, started_at=started_at,
               stdout_sha256=outcome.stdout_sha256,
               state=state, reason=reason, digest_stored=manifest.manifest_sha256,
               digest_replayed=outcome.stdout_sha256,
               denominator_stored=manifest.expected_rederived,
               denominator_replayed=outcome.rederived, image=image,
               refusals=outcome.refusals)
    return _record(row, store_path)


def _record(row: RunRow, store_path: Path | None) -> RunRow:
    if store_path is not None:
        append_row(store_path, row)
    return row


def read_rows(store_path: Path) -> list[dict[str, Any]]:
    target = Path(store_path)
    if not target.exists():
        return []
    rows: list[dict[str, Any]] = []
    for number, line in enumerate(target.read_text(encoding="utf-8").splitlines(), start=1):
        if not line.strip():
            continue
        try:
            document = json.loads(line)
        except ValueError as exc:
            raise ValueError("%s line %d is not JSON: %s" % (target, number, exc)) from exc
        if not isinstance(document, dict) or "run_id" not in document:
            raise ValueError("%s line %d is not a run row" % (target, number))
        rows.append(document)
    return rows


def append_row(store_path: Path, row: RunRow) -> bool:
    """Append one attempt to the store. Returns True once the line is written."""
    target = Path(store_path)
    target.parent.mkdir(parents=True, exist_ok=True)
    with target.open("a", encoding="utf-8") as handle:
        handle.write(json.dumps(row.as_json(), sort_keys=True) + "\n")
    return True


def find_row(store_path: Path, run_id: str) -> dict[str, Any] | None:
    for stored in read_rows(store_path):
        if stored.get("run_id") == run_id:
            return stored
    return None


#: The states in which a replay actually observed whether the source still
#: re-derives. ``not-run`` never ran (AC10) and ``refused`` stopped before the
#: replay, so neither is an observation: they can neither block an export nor
#: clear a recorded mismatch.
OBSERVING_STATES = ("certified", "mismatch")


def deciding_row(store_path: Path, packet_id: str) -> dict[str, Any] | None:
    """The last row that observed this packet's source, in append order.

    Only ``certified`` and ``mismatch`` count. A later ``not-run`` (the host
    lost Docker, F6 exception (a)) or ``refused`` (the pin was rejected) is not
    evidence that the source re-derives, so it must not lift an earlier
    mismatch - that would make AC7 bypassable by one ordinary command. A later
    ``certified`` row does supersede an earlier mismatch, because it is an
    observation that the source re-derives again.

    The match is on ``packet_id`` alone. ``packet_id`` is content-derived
    (protocol digest, revision, artefact hashes, shareable) and does **not**
    include the pinned wheel, so a copy re-sealed with a different
    ``distribution.sha256`` shares the id and is decided by the same rows.
    That over-blocks such a copy until a replay of it records ``certified`` -
    the fail-closed reading. Matching the pin instead would let a one-field
    manifest edit launder a recorded mismatch.
    """
    if not packet_id:
        return None
    deciding = [row for row in read_rows(store_path)
                if row.get("packet_id") == packet_id
                and row.get("state") in OBSERVING_STATES]
    return deciding[-1] if deciding else None


def recorded_mismatch(row: dict[str, Any] | None) -> bool:
    """True only for a recorded replay mismatch.

    ``state`` is the one field that names this outcome. Neither exit code can be
    used: the replay process's own ``exit_code`` is 0 when the replay ran and the
    denominator disagreed, and the portal's ``rc`` is ``EXIT_REFUSED`` (4) for
    *both* ``mismatch`` and ``refused`` - reading ``rc`` here would block an
    export because the pin was rejected, which is a different finding.
    """
    return bool(row) and row.get("state") == "mismatch"
