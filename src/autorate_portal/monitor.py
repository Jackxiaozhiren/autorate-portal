"""F6: a monitor is a scheduled replay, and its verdict is the tool's own.

The rules this module makes structural:

* **It reuses the engine.** A monitor row is written by the same replay that a
  human would run; there is no path here that computes a bound, compares two
  numbers of its own, or reads a summary to decide anything.
* **The vocabulary is the CLI's.** Exit ``0`` is ``holds``, ``3`` is
  ``not_certifiable``, ``4`` is ``drift``, ``2`` is ``configuration_bug``. A
  usage error is a bug in the deployment, not a red KPI, and it is named as one.
* **A missing prerequisite is never green.** No Docker, no network, a rejected
  pin, a timeout: ``not_run``, with the doctor detail and - for a timeout - the
  hash of what the attempt had printed.
* **It never writes a summary.** The only rows a monitor run creates are the
  engine's `run` row and a `monitor_result` row. That is asserted by a test that
  compares every `certificate_summary` row before and after.

One state is outside the CLI's four: ``failed``. A replay process that exits with
a code the tool does not document (1, 127, ...) ran, so calling it ``not_run``
would be false, and calling it ``configuration_bug`` would blame the deployment
for a contract violation it cannot see. It is named separately and reported as a
deviation from F6 rule 2's closed list, because a misclassified exit code is the
failure this project exists to prevent.
"""
from __future__ import annotations

import json
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from . import db
from .engine import RunRow, run as run_job

HOLDS = "holds"
NOT_CERTIFIABLE = "not_certifiable"
DRIFT = "drift"
CONFIGURATION_BUG = "configuration_bug"
NOT_RUN = "not_run"
FAILED = "failed"
VERDICTS = (HOLDS, NOT_CERTIFIABLE, DRIFT, CONFIGURATION_BUG, NOT_RUN, FAILED)

#: F6 rule 2, verbatim, as a mapping rather than a chain of ifs.
EXIT_VERDICT = {0: HOLDS, 3: NOT_CERTIFIABLE, 4: DRIFT, 2: CONFIGURATION_BUG}
VERDICT_RC = {HOLDS: 0, NOT_CERTIFIABLE: 3, DRIFT: 4, CONFIGURATION_BUG: 2,
              NOT_RUN: 3, FAILED: 4}


@dataclass(frozen=True)
class MonitorOutcome:
    verdict: str
    reason: str
    run_id: str
    exit_code: int | None
    summary_line: str
    stdout_sha256: str
    doctor: tuple[str, ...] = ()
    partial: bool = False

    def as_dict(self) -> dict[str, Any]:
        return {"verdict": self.verdict, "reason": self.reason, "run_id": self.run_id,
                "exit_code": self.exit_code, "summary_line": self.summary_line,
                "stdout_sha256": self.stdout_sha256, "doctor": list(self.doctor),
                "partial_stdout": self.partial}


def verdict_for(row: RunRow) -> tuple[str, str]:
    """(verdict, reason) from the replay's own exit code, never from a summary."""
    if row.state == "not-run":
        return NOT_RUN, row.reason or "the replay could not run"
    code = row.exit_code
    if code is None:
        return NOT_RUN, row.reason or "no exit code was recorded"
    if code in EXIT_VERDICT:
        verdict = EXIT_VERDICT[code]
        reason = row.reason
        if verdict == DRIFT and not reason:
            reason = "the replay reported drift"
        return verdict, reason
    return FAILED, ("the replay exited %d, which is outside the tool's documented "
                    "0/2/3/4 vocabulary" % code)


def record(session, *, project_id: str, row: RunRow) -> db.MonitorResult | None:
    """Write the observation. ``session=None`` is the CLI's case: the run row is
    the record there, because a command that was given no database must not
    pretend it wrote one."""
    if session is None:
        return None
    verdict, _reason = verdict_for(row)
    result = db.MonitorResult(project_id=project_id, run_id=row.run_id, verdict=verdict,
                              drift_detail_artifact_id=None)
    session.add(result)
    session.flush()
    return result


def observe(session, *, project_id: str, packet_path: Path, store_path: Path | None,
            backend: str = "container", registry_path: Path | None = None,
            env=None, doctor_provider=None) -> MonitorOutcome:
    """One scheduled observation: a replay, its row, and a named verdict."""
    row = run_job(packet_path, backend=backend, registry_path=registry_path,
                  env=env, store_path=store_path)
    record(session, project_id=project_id, row=row)
    verdict, reason = verdict_for(row)
    doctor: tuple[str, ...] = ()
    partial = False
    if verdict == NOT_RUN:
        if doctor_provider is None:
            from .doctor import examine, render
            doctor_provider = lambda: render(examine(backend=backend, registry_path=registry_path,
                                                     packet_path=packet_path))
        doctor = (doctor_provider(),)
        partial = bool(row.stdout_sha256) and row.state == "not-run" and "timeout" in row.reason
    if verdict == DRIFT and not row.summary_line:
        # The alert quotes the tool's own line; if it printed none, the alert
        # says so instead of inventing a sentence (F6 rule 3).
        reason = (reason + " (the replay printed no summary line to quote)").strip()
    return MonitorOutcome(verdict=verdict, reason=reason, run_id=row.run_id,
                          exit_code=row.exit_code, summary_line=row.summary_line,
                          stdout_sha256=row.stdout_sha256, doctor=doctor, partial=partial)


def schedule_for(session, project_id: str) -> db.MonitorSchedule | None:
    from sqlalchemy import select
    return session.scalars(select(db.MonitorSchedule).where(
        db.MonitorSchedule.project_id == project_id)).first()


def set_schedule(session, *, project_id: str, packet_id: str, frequency: str) -> db.MonitorSchedule:
    """One schedule per project; changing it updates the row, never the history."""
    if not frequency.strip():
        raise ValueError("a monitor schedule needs a frequency")
    existing = schedule_for(session, project_id)
    now = datetime.now(timezone.utc).isoformat(timespec="seconds")
    if existing is None:
        existing = db.MonitorSchedule(project_id=project_id, packet_id=packet_id,
                                      frequency=frequency, updated_at=now)
        session.add(existing)
    else:
        existing.packet_id = packet_id
        existing.frequency = frequency
        existing.updated_at = now
    session.flush()
    return existing


def results_for(session, project_id: str, run_store) -> list[dict[str, Any]]:
    """The series, oldest first, with the run row's own words beside each verdict.

    The engine's run rows live in the append-only JSONL store, not in a table, so
    the join happens here. Rows are scoped by `monitor_result.project_id`; a
    result whose run row is missing from the store is dropped rather than
    reported without its observation.
    """
    from sqlalchemy import select
    from .engine import read_rows
    runs = {row.get("run_id"): row for row in read_rows(Path(run_store))}
    out: list[dict[str, Any]] = []
    for result in session.scalars(select(db.MonitorResult).where(
            db.MonitorResult.project_id == project_id)):
        run = runs.get(result.run_id)
        if run is None:
            continue
        out.append({"id": result.id, "run_id": result.run_id, "verdict": result.verdict,
                    "state": run.get("state"), "exit_code": run.get("exit_code"),
                    "summary_line": run.get("summary_line", ""),
                    "started_at": run.get("started_at", "")})
    out.sort(key=lambda item: item["started_at"])
    return out


def parse_frequency(document: str) -> str:
    """A frequency is a cron-like string; this module validates shape, not time.

    Five whitespace-separated fields, each made of digits, `*`, `,`, `-` or `/`.
    The portal does not own a clock - a scheduler does - so an invalid shape is a
    configuration bug at write time rather than a silent never-fires schedule.
    """
    fields = document.split()
    if len(fields) != 5:
        raise ValueError("a frequency needs five fields (minute hour day month weekday)")
    allowed = set("0123456789*,-/")
    for field in fields:
        if not field or set(field) - allowed:
            raise ValueError("frequency field %r is not a cron field" % field)
    return " ".join(fields)


def parse_schedule_body(body: dict[str, Any]) -> tuple[str, str]:
    packet_id = body.get("packet_id")
    frequency = body.get("frequency")
    if not isinstance(packet_id, str) or not packet_id:
        raise ValueError("packet_id is required")
    if not isinstance(frequency, str):
        raise ValueError("frequency is required")
    return packet_id, parse_frequency(frequency)


def dumps(outcome: MonitorOutcome) -> str:
    return json.dumps(outcome.as_dict(), sort_keys=True)
