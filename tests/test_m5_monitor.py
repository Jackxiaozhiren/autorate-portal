"""F6 — the monitor is a replay, its verdict is the tool's exit code, and it
writes a run and a result and nothing else."""
from __future__ import annotations

import json
import subprocess
from pathlib import Path

import pytest
from fastapi.testclient import TestClient
from sqlalchemy import select

from autorate_portal import auth, db, monitor
from autorate_portal.app import create_app
from autorate_portal.cli import DEFAULT_VERSION, DEFAULT_WHEEL
from autorate_portal.engine import RunRow
from autorate_portal.manifest import sha256_bytes
from autorate_portal.replay import Environment
from conftest import reseal_manifest, rewrite_bundle, split_bundle

WHEEL = b"m5-monitor-wheel-bytes"
STDOUT_OK = "claim G5 certified x\nprotocol: protocol.json ce43f8e29cc1 (frozen 2026-10-17)\nre-derived 612 /612 values\n"


def _row(**overrides) -> RunRow:
    values = dict(run_id="run-1", packet_id="pkt-1", backend="container", image="",
                  distribution="autorate==0.1.2", wheel_sha256="a" * 64,
                  argv=["autorate", "verify"], command=["verify"], exit_code=0,
                  started_at="2026-11-16T00:00:00Z", stdout_sha256="b" * 64,
                  summary_line="re-derived 612 /612 values", state="certified", rc=0,
                  reason="", digest_stored="c" * 64, digest_replayed="d" * 64,
                  denominator_stored="612 /612", denominator_replayed="612 /612")
    values.update(overrides)
    return RunRow(**values)


def test_each_documented_exit_code_maps_to_its_verdict():
    table = {0: monitor.HOLDS, 3: monitor.NOT_CERTIFIABLE, 4: monitor.DRIFT,
             2: monitor.CONFIGURATION_BUG}
    for code, expected in table.items():
        verdict, _ = monitor.verdict_for(_row(exit_code=code))
        assert verdict == expected, "exit %d must be %s" % (code, expected)


def test_an_undocumented_exit_code_is_failed_and_never_green():
    verdict, reason = monitor.verdict_for(_row(exit_code=1, state="refused"))
    assert verdict == monitor.FAILED
    assert "outside the tool's documented" in reason


def test_a_not_run_row_is_not_run_whatever_its_numbers_say():
    verdict, reason = monitor.verdict_for(
        _row(state="not-run", exit_code=None, reason="docker executable not found"))
    assert verdict == monitor.NOT_RUN
    assert "docker" in reason


def _packet_and_registry(tmp_path, built):
    """A packet re-pinned to the test wheel, plus a registry that accepts it."""
    source = Path(built[0])
    packet = tmp_path / "monitor.packet.tar"
    document, files = split_bundle(source)
    document["distribution"]["sha256"] = sha256_bytes(WHEEL)
    rewrite_bundle(packet, files, reseal_manifest(document))
    registry = tmp_path / "pins.json"
    registry.write_text(json.dumps({"schema": "test", "pins": [
        {"name": "autorate", "version": DEFAULT_VERSION, "wheel": DEFAULT_WHEEL,
         "sha256": sha256_bytes(WHEEL),
         "source": "https://pypi.org/pypi/autorate/%s/json" % DEFAULT_VERSION}]}),
        encoding="utf-8")
    return packet, registry


def _env(*, rc=0, stdout=STDOUT_OK, ready=True, timeout=None):
    def runner(argv, **kwargs):
        if timeout is not None:
            raise subprocess.TimeoutExpired(argv, timeout, output=stdout.encode())
        return subprocess.CompletedProcess(argv, rc, stdout=stdout, stderr="")

    return Environment(docker_available=ready, network_available=ready,
                       docker_detail="injected" if ready else "no docker (injected)",
                       network_detail="injected" if ready else "no network (injected)",
                       runner=runner, wheel_fetcher=lambda _: WHEEL)


def _session():
    engine = db.make_engine("sqlite://")
    db.create_all(engine)
    session = db.make_session(engine)()
    session.add(db.Org(id="org-1", name="org-1"))
    session.add(db.Project(id="prj-1", org_id="org-1", name="prj-1"))
    session.flush()
    return session


def _summaries(session):
    return [(row.id, row.task, row.autorate, row.bound, row.n_cal, row.n_eval)
            for row in session.scalars(select(db.CertificateSummary))]


def test_a_monitor_run_writes_a_run_and_a_result_and_moves_no_summary(tmp_path, m4_built):
    packet, registry = _packet_and_registry(tmp_path, m4_built)
    session = _session()
    store = tmp_path / "runs.jsonl"
    before = _summaries(session)

    outcome = monitor.observe(session, project_id="prj-1", packet_path=packet,
                              store_path=store, registry_path=registry, env=_env())

    assert outcome.verdict == monitor.HOLDS
    assert _summaries(session) == before, "a monitor never writes a stored summary"
    assert len(store.read_text().splitlines()) == 1, "the engine's run row is the record"
    assert session.scalars(select(db.MonitorResult)).one().verdict == monitor.HOLDS


def test_the_alert_quotes_the_tools_own_summary_line(tmp_path, m4_built):
    packet, registry = _packet_and_registry(tmp_path, m4_built)
    session = _session()

    outcome = monitor.observe(session, project_id="prj-1", packet_path=packet,
                              store_path=tmp_path / "runs.jsonl", registry_path=registry,
                              env=_env(rc=4, stdout=STDOUT_OK + "DRIFT: cert laya.bound\n"))

    assert outcome.verdict == monitor.DRIFT
    assert outcome.summary_line == "re-derived 612 /612 values"
    assert outcome.summary_line in STDOUT_OK, "quoted verbatim, not paraphrased"


def test_a_timeout_is_not_run_and_keeps_the_partial_stdout_hash(tmp_path, m4_built):
    packet, registry = _packet_and_registry(tmp_path, m4_built)
    session = _session()
    partial = "claim G1 not_certifiable\nre-derived 1 /612"

    outcome = monitor.observe(session, project_id="prj-1", packet_path=packet,
                              store_path=tmp_path / "runs.jsonl", registry_path=registry,
                              env=_env(timeout=1, stdout=partial),
                              doctor_provider=lambda: "doctor: fake")

    assert outcome.verdict == monitor.NOT_RUN
    assert outcome.partial is True
    assert outcome.stdout_sha256 == sha256_bytes(partial.encode())
    assert outcome.doctor == ("doctor: fake",)


def test_a_missing_prerequisite_is_not_run_with_the_doctor_output(tmp_path, m4_built):
    packet, registry = _packet_and_registry(tmp_path, m4_built)
    session = _session()

    outcome = monitor.observe(session, project_id="prj-1", packet_path=packet,
                              store_path=tmp_path / "runs.jsonl", registry_path=registry,
                              env=_env(ready=False),
                              doctor_provider=lambda: "docker: missing")

    assert outcome.verdict == monitor.NOT_RUN
    assert outcome.doctor == ("docker: missing",)


def test_the_schedule_is_one_row_per_project_and_needs_a_cron_shape():
    session = _session()
    first = monitor.set_schedule(session, project_id="prj-1", packet_id="pkt-1",
                                 frequency="0 6 * * *")
    second = monitor.set_schedule(session, project_id="prj-1", packet_id="pkt-2",
                                  frequency="30 6 * * 1")
    assert first.id == second.id, "one schedule per project, updated not duplicated"
    assert second.frequency == "30 6 * * 1"

    for bad in ("daily", "0 6 * *", "0 6 * * mon"):
        with pytest.raises(ValueError):
            monitor.parse_frequency(bad)
    assert monitor.parse_frequency("0 6 * * 1-5") == "0 6 * * 1-5"


def test_the_api_schedules_and_lists_without_touching_a_summary(tmp_path, m4_built):
    packet, registry = _packet_and_registry(tmp_path, m4_built)
    engine = db.make_engine("sqlite:///" + str(tmp_path / "portal.db"))
    db.create_all(engine)
    sessions = db.make_session(engine)
    app = create_app(engine=engine, store_dir=tmp_path / "store", salt="s", secret_key="k",
                     monitor_env=_env(), run_store=tmp_path / "runs.jsonl",
                     monitor_registry=registry)
    client = TestClient(app)
    with sessions() as session:
        session.add(db.Org(id="org-1", name="org-1"))
        session.add(db.Project(id="prj-1", org_id="org-1", name="prj-1"))
        session.add(db.User(id="usr-p", email="p@example.test", display="P"))
        session.add(db.Membership(user_id="usr-p", org_id="org-1", role="producer"))
        session.flush()
        token, _ = auth.issue_token(session, user_id="usr-p", project_id="prj-1", salt="s")
        session.commit()

    upload = client.post("/api/v1/packets", headers={"x-api-token": token},
                         files={"file": ("p.tar", packet.read_bytes(), "application/x-tar")})
    assert upload.status_code == 201, upload.text
    packet_id = upload.json()["id"]

    response = client.post("/api/v1/monitors", headers={"x-api-token": token},
                           json={"packet_id": packet_id, "frequency": "0 6 * * *"})
    assert response.status_code == 202, response.text
    assert response.json()["verdict"] == monitor.HOLDS

    listing = client.get("/api/v1/monitors", headers={"x-api-token": token}).json()
    assert listing["schedule"]["frequency"] == "0 6 * * *"
    assert [row["verdict"] for row in listing["results"]] == [monitor.HOLDS]
    assert monitor.NOT_RUN in listing["verdicts"]


def test_a_bad_frequency_is_a_named_422(tmp_path, m4_built):
    packet, _ = _packet_and_registry(tmp_path, m4_built)
    engine = db.make_engine("sqlite:///" + str(tmp_path / "portal.db"))
    db.create_all(engine)
    sessions = db.make_session(engine)
    client = TestClient(create_app(engine=engine, store_dir=tmp_path / "store",
                                   salt="s", secret_key="k", monitor_env=_env()))
    with sessions() as session:
        session.add(db.Org(id="org-1", name="org-1"))
        session.add(db.Project(id="prj-1", org_id="org-1", name="prj-1"))
        session.add(db.User(id="usr-p", email="p@example.test", display="P"))
        session.add(db.Membership(user_id="usr-p", org_id="org-1", role="producer"))
        session.flush()
        token, _ = auth.issue_token(session, user_id="usr-p", project_id="prj-1", salt="s")
        session.commit()

    response = client.post("/api/v1/monitors", headers={"x-api-token": token},
                           json={"packet_id": "pkt-x", "frequency": "daily"})
    assert response.status_code == 422
    assert "five fields" in response.json()["detail"]
