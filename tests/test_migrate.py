"""The schema lock: replicas may start together, and a wrong dialect is refused, not ignored.

The image used to run `alembic upgrade head` at boot. Two replicas starting together read the
same revision, both send the same DDL, and one dies on a constraint the other just created --
a failure that heals on restart, which is the hardest kind to diagnose from logs. These tests
pin the fix: the upgrade runs under a lock, the lock is released, waiting times out as a
refusal rather than a traceback, and a dialect with no lock is refused instead of upgraded.
"""
from __future__ import annotations

import fcntl
import os
import sqlite3
import subprocess
import sys
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path

import pytest
from sqlalchemy import create_engine, inspect

from autorate_portal import cli, migrate

ROOT = Path(__file__).resolve().parents[1]
HEAD = "0005_artifact_wheel_kind"


def _url(tmp_path: Path) -> str:
    return "sqlite:///" + str(tmp_path / "portal.db")


def test_a_fresh_database_reaches_head_and_the_head_is_reported(tmp_path):
    url = _url(tmp_path)
    assert migrate.upgrade_to_head(url) == HEAD
    assert "certificate_summary" in inspect(create_engine(url)).get_table_names()


def test_the_lock_is_released_so_a_second_upgrade_can_take_it(tmp_path):
    url = _url(tmp_path)
    migrate.upgrade_to_head(url)
    assert migrate.upgrade_to_head(url) == HEAD, "the second run must not wait for a dead holder"


def test_four_upgrades_started_together_all_succeed(tmp_path):
    """Without the lock this is the boot race: some of these fail on a duplicate DDL."""
    url = _url(tmp_path)
    with ThreadPoolExecutor(max_workers=4) as pool:
        results = [future.result() for future in
                   [pool.submit(migrate.upgrade_to_head, url) for _ in range(4)]]
    assert results == [HEAD] * 4
    with sqlite3.connect(tmp_path / "portal.db") as connection:
        rows = connection.execute("select count(*) from certificate_summary").fetchone()
    assert rows == (0,), "the table exists exactly once"


def test_two_processes_started_together_all_succeed(tmp_path):
    """Containers are processes, not threads; this is the same race across an interpreter."""
    url = _url(tmp_path)
    environment = {**os.environ, "PYTHONPATH": str(ROOT / "src"), "AUTHORATE_DB_URL": url}
    command = [sys.executable, "-c",
               "from autorate_portal.migrate import upgrade_to_head; print(upgrade_to_head())"]
    first = subprocess.Popen(command, cwd=ROOT, env=environment,
                             stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
    second = subprocess.Popen(command, cwd=ROOT, env=environment,
                              stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
    outcomes = [(process.wait(timeout=120), process.stdout.read(), process.stderr.read())
                for process in (first, second)]
    for status, out, err in outcomes:
        assert status == 0, err
        assert out.strip() == HEAD


def test_waiting_for_a_held_lock_refuses_instead_of_hanging(tmp_path):
    url = _url(tmp_path)
    lock = Path(str(tmp_path / "portal.db") + ".migrate.lock")
    lock.parent.mkdir(parents=True, exist_ok=True)
    holder = open(lock, "a+", encoding="utf-8")
    fcntl.flock(holder.fileno(), fcntl.LOCK_EX | fcntl.LOCK_NB)
    try:
        with pytest.raises(migrate.MigrationLockTimeout) as refusal:
            migrate.upgrade_to_head(url, timeout=0.3)
        assert migrate.LOCK_TIMEOUT_ENV in str(refusal.value)
    finally:
        fcntl.flock(holder.fileno(), fcntl.LOCK_UN)
        holder.close()
    assert not (tmp_path / "portal.db").exists(), "a refusal must not leave half a schema"


def test_the_boot_step_can_be_turned_off_for_a_deployment_that_migrates_in_a_job(tmp_path, monkeypatch):
    url = _url(tmp_path)
    monkeypatch.setenv(migrate.STARTUP_ENV, "0")
    assert cli.main(["migrate", "--if-enabled", "--db-url", url]) == cli.EXIT_OK
    assert not (tmp_path / "portal.db").exists(), "the job owns the schema; the replica did not touch it"


def test_the_boot_step_runs_when_the_flag_is_absent(tmp_path, monkeypatch):
    url = _url(tmp_path)
    monkeypatch.delenv(migrate.STARTUP_ENV, raising=False)
    assert cli.main(["migrate", "--if-enabled", "--db-url", url]) == cli.EXIT_OK
    assert (tmp_path / "portal.db").exists()


def test_a_held_lock_is_a_refusal_exit_code_not_a_traceback(tmp_path):
    url = _url(tmp_path)
    lock = Path(str(tmp_path / "portal.db") + ".migrate.lock")
    lock.parent.mkdir(parents=True, exist_ok=True)
    holder = open(lock, "a+", encoding="utf-8")
    fcntl.flock(holder.fileno(), fcntl.LOCK_EX | fcntl.LOCK_NB)
    try:
        assert cli.main(["migrate", "--db-url", url, "--timeout", "0.3"]) == cli.EXIT_REFUSED
    finally:
        fcntl.flock(holder.fileno(), fcntl.LOCK_UN)
        holder.close()


def test_a_dialect_without_a_lock_is_refused_before_it_connects():
    with pytest.raises(migrate.MigrationConfigurationError) as refusal:
        migrate.upgrade_to_head("mysql+pymysql://user:pass@127.0.0.1:1/never")
    assert "mysql" in str(refusal.value)


def test_the_advisory_key_is_stable_and_scoped_to_one_database():
    assert migrate.advisory_key("autorate") == migrate.advisory_key("autorate")
    assert migrate.advisory_key("autorate") != migrate.advisory_key("autorate_ci"), (
        "two databases on one server must not block each other")
    assert -(2 ** 63) <= migrate.advisory_key("autorate") < 2 ** 63, "pg_advisory_lock takes a bigint"


def test_a_bad_timeout_is_named_rather_than_raised_as_a_bare_value_error(monkeypatch):
    monkeypatch.setenv(migrate.LOCK_TIMEOUT_ENV, "soon")
    with pytest.raises(migrate.MigrationConfigurationError) as refusal:
        migrate.lock_timeout()
    assert migrate.LOCK_TIMEOUT_ENV in str(refusal.value)
