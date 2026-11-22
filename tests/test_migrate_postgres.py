"""The PostgreSQL half of the chain, executed rather than rendered.

`test_migrate_offline.py` proves this build renders the right statements for PostgreSQL. That is
a compile-time claim. These tests make the runtime one: a server accepts the chain, a second
replica waits instead of racing, a lock that is already held becomes a refusal with no DDL
behind it, and a downgrade walks back out.

They need a server, so they read ``AUTHORATE_TEST_PG_URL`` and skip when it is unset: the default
suite must stay runnable with no service and no credentials. The ``postgres`` CI job sets the
variable and then checks that nothing skipped -- a job that quietly skipped its subject would be
green for the wrong reason, which is the failure this repository keeps writing down.
"""
from __future__ import annotations

import os
import time
from concurrent.futures import ThreadPoolExecutor

import pytest
from alembic import command
from fastapi.testclient import TestClient
from sqlalchemy import create_engine, text

from autorate_portal import db, migrate
from autorate_portal.app import create_app

PG_ENV = "AUTHORATE_TEST_PG_URL"
SALT = "test-salt"


def _admin(url: str):
    # AUTOCOMMIT: DROP SCHEMA cannot run inside a transaction block.
    return create_engine(url, future=True, isolation_level="AUTOCOMMIT")


@pytest.fixture()
def pg_url():
    """An empty ``public`` schema on a real server, one per test."""
    url = os.environ.get(PG_ENV, "").strip()
    if not url:
        pytest.skip("%s is not set; the postgres CI job sets it" % PG_ENV)
    engine = _admin(url)
    try:
        with engine.connect() as connection:
            connection.execute(text("drop schema if exists public cascade"))
            connection.execute(text("create schema public"))
    finally:
        engine.dispose()
    yield url


def _constraint(url: str) -> str:
    engine = _admin(url)
    try:
        with engine.connect() as connection:
            return connection.execute(text(
                "select pg_get_constraintdef(oid) from pg_constraint "
                "where conname = 'ck_artifact_kind'")).scalar_one()
    finally:
        engine.dispose()


def _revision(url: str) -> str:
    engine = _admin(url)
    try:
        with engine.connect() as connection:
            return connection.execute(text("select version_num from alembic_version")).scalar_one()
    finally:
        engine.dispose()


def _app(pg_url: str, store) -> TestClient:
    return TestClient(create_app(engine=db.make_engine(pg_url), store_dir=store,
                                 salt=SALT, secret_key="k"))


def test_the_chain_is_accepted_by_a_server_and_the_constraint_is_widened(pg_url):
    assert migrate.upgrade_to_head(pg_url) == migrate.script_head()
    assert _revision(pg_url) == migrate.script_head()
    definition = _constraint(pg_url)
    assert "wheel" in definition, definition
    assert "certificate" in definition, definition


def test_four_replicas_started_together_all_reach_the_same_revision(pg_url):
    """The measured defect: four processes, one exit 0 and three duplicate-key failures."""
    with ThreadPoolExecutor(max_workers=4) as pool:
        revisions = list(pool.map(lambda _: migrate.upgrade_to_head(pg_url), range(4)))
    assert revisions == [migrate.script_head()] * 4
    assert _revision(pg_url) == migrate.script_head()


def test_a_held_lock_is_a_refusal_and_leaves_no_schema_behind(pg_url):
    key = None
    engine = _admin(pg_url)
    try:
        with engine.connect() as holder:
            key = migrate.advisory_key(holder.execute(
                text("select current_database()")).scalar_one())
            holder.execute(text("select pg_advisory_lock(:key)"), {"key": key})
            started = time.monotonic()
            with pytest.raises(migrate.MigrationLockTimeout):
                migrate.upgrade_to_head(pg_url, timeout=0.5)
            waited = time.monotonic() - started
            assert 0.4 <= waited < 10, waited
            # The loser must not have created anything: a refusal is not a partial upgrade.
            assert holder.execute(text(
                "select to_regclass('public.alembic_version')")).scalar_one() is None
    finally:
        engine.dispose()
    assert key is not None


def test_the_lock_is_released_so_the_next_replica_does_not_wait(pg_url):
    migrate.upgrade_to_head(pg_url)
    engine = _admin(pg_url)
    try:
        with engine.connect() as connection:
            key = migrate.advisory_key(connection.execute(
                text("select current_database()")).scalar_one())
            assert connection.execute(text("select pg_try_advisory_lock(:key)"),
                                      {"key": key}).scalar_one() is True, (
                "nobody should still hold the schema lock")
            connection.execute(text("select pg_advisory_unlock(:key)"), {"key": key})
    finally:
        engine.dispose()


def test_a_downgrade_and_upgrade_round_trip_walks_the_constraint_both_ways(pg_url):
    """Offline rendering cannot say whether the server accepts the reverse direction."""
    migrate.upgrade_to_head(pg_url)
    command.downgrade(migrate.alembic_config(pg_url), "0004_packet_tombstone")
    assert "wheel" not in _constraint(pg_url)
    assert _revision(pg_url) == "0004_packet_tombstone"
    assert migrate.upgrade_to_head(pg_url) == migrate.script_head()
    assert "wheel" in _constraint(pg_url)


def test_readiness_refuses_an_unmigrated_server_then_accepts_it(pg_url, tmp_path):
    """The orchestrator case, on the database a deployment uses: the skipped job is caught."""
    answer = _app(pg_url, tmp_path / "store").get("/readyz")
    assert answer.status_code == 503
    assert answer.json() == {"status": "not-ready", "reason": "schema-missing"}

    migrate.upgrade_to_head(pg_url)
    answer = _app(pg_url, tmp_path / "store").get("/readyz")
    assert answer.status_code == 200
    assert answer.json() == {"status": "ready", "schema": migrate.script_head()}


def test_readiness_names_a_schema_behind_the_head_on_a_server(pg_url, tmp_path):
    migrate.upgrade_to_head(pg_url)
    command.downgrade(migrate.alembic_config(pg_url), "0004_packet_tombstone")
    answer = _app(pg_url, tmp_path / "store").get("/readyz")
    assert answer.status_code == 503
    assert answer.json() == {"status": "not-ready", "reason": "schema-behind",
                             "applied": "0004_packet_tombstone",
                             "expected": migrate.script_head()}
