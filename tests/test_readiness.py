"""Liveness and readiness answer different questions, and only one of them may touch the database.

`/healthz` says the process is alive. It returned a constant before this change and still does:
a container whose database is gone should leave the rotation, not be restarted, and a liveness
probe that queried the database would turn an outage into a crash loop.

`/readyz` says this build can serve: a connection opens, `alembic_version` is readable, and the
revision is the one this build's chain ends at. The third question is what catches
`AUTHORATE_MIGRATE_ON_START=0` with a migration job that never ran -- before it existed, such a
replica answered `healthz 200` until the first request that read a table, measured as a 500.
"""
from __future__ import annotations

import pytest
from alembic import command
from fastapi.testclient import TestClient

from autorate_portal import db, migrate
from autorate_portal.app import create_app

SALT = "test-salt"


def _app(tmp_path, url: str) -> TestClient:
    engine = db.make_engine(url)
    return TestClient(create_app(engine=engine, store_dir=tmp_path / "store",
                                 salt=SALT, secret_key="k"))


def _migrated(tmp_path) -> str:
    url = "sqlite:///" + str(tmp_path / "portal.db")
    migrate.upgrade_to_head(url)
    return url


def test_liveness_does_not_touch_the_database(tmp_path):
    """The engine cannot open anything here: the directory does not exist."""
    missing = tmp_path / "absent" / "portal.db"
    client = _app(tmp_path, "sqlite:///" + str(missing))
    assert client.get("/healthz").status_code == 200
    assert client.get("/healthz").json() == {"status": "ok"}
    assert not missing.parent.exists(), "a liveness probe must not create a database"


def test_readiness_is_ready_on_the_head_this_build_ends_at(tmp_path):
    client = _app(tmp_path, _migrated(tmp_path))
    answer = client.get("/readyz")
    assert answer.status_code == 200
    assert answer.json() == {"status": "ready", "schema": migrate.script_head()}


def test_readiness_refuses_a_database_that_was_never_migrated(tmp_path):
    """This is the skipped-job case: the file opens, the revision is not there."""
    client = _app(tmp_path, "sqlite:///" + str(tmp_path / "portal.db"))
    answer = client.get("/readyz")
    assert answer.status_code == 503
    assert answer.json() == {"status": "not-ready", "reason": "schema-missing"}


def test_readiness_refuses_a_schema_behind_the_head(tmp_path):
    url = _migrated(tmp_path)
    command.downgrade(migrate.alembic_config(url), "0004_packet_tombstone")
    answer = _app(tmp_path, url).get("/readyz")
    assert answer.status_code == 503
    assert answer.json() == {"status": "not-ready", "reason": "schema-behind",
                             "applied": "0004_packet_tombstone",
                             "expected": migrate.script_head()}


def test_readiness_refuses_an_unreachable_database(tmp_path):
    absent = tmp_path / "no-such-directory" / "portal.db"
    answer = _app(tmp_path, "sqlite:///" + str(absent)).get("/readyz")
    assert answer.status_code == 503
    assert answer.json() == {"status": "not-ready", "reason": "database-unreachable"}


def test_a_not_ready_answer_carries_no_connection_detail(tmp_path):
    """The probe is unauthenticated; a driver's message quotes the URL, password included."""
    secret = tmp_path / "hunter2" / "portal.db"
    answer = _app(tmp_path, "sqlite:///" + str(secret)).get("/readyz")
    assert answer.status_code == 503
    body = answer.text
    assert "hunter2" not in body, body
    assert str(tmp_path) not in body, body
    assert "sqlite" not in body, body


def test_a_postgres_url_with_a_password_is_not_echoed(tmp_path):
    """The same property through the driver a deployment actually uses, when it is installed.

    CI installs the dev extra without `postgres`, and `create_engine` imports the driver at
    construction, so this is skipped there rather than failing on an ImportError that says
    nothing about the endpoint.
    """
    try:
        __import__("psycopg")
    except ImportError:
        try:
            __import__("psycopg2")
        except ImportError:
            pytest.skip("no PostgreSQL driver installed; the sqlite case covers the endpoint")
    url = "postgresql://portal:hunter2@127.0.0.1:1/none"
    answer = _app(tmp_path, url).get("/readyz")
    assert answer.status_code == 503
    assert "hunter2" not in answer.text, answer.text
    assert "postgresql" not in answer.text, answer.text


def test_readiness_is_open_and_reads_only(tmp_path):
    """No token, and nothing written: two probes in a row leave the database untouched."""
    url = _migrated(tmp_path)
    client = _app(tmp_path, url)
    before = (tmp_path / "portal.db").stat().st_mtime_ns
    for _ in range(3):
        assert client.get("/readyz").status_code == 200
    assert (tmp_path / "portal.db").stat().st_mtime_ns == before
