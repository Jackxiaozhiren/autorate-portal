"""The image must be able to do what its own comment claims.

Two claims were false until 2026-11-22, and only a real ``docker build`` plus a
``docker run`` showed it: the build installed the package without the postgres
extra, so a ``postgresql://`` URL raised ``ModuleNotFoundError: psycopg`` inside
the container; and no database URL was set, so the default relative SQLite path
landed in ``/app``, which the unprivileged user cannot write. A container with no
environment failed with "unable to open database file" instead of the documented
refusal about missing credentials.
"""
from __future__ import annotations

import re
from pathlib import Path

DOCKERFILE = Path(__file__).resolve().parents[1] / "Dockerfile"


def test_the_image_installs_the_postgres_extra():
    text = DOCKERFILE.read_text(encoding="utf-8")
    assert '".[postgres]"' in text, "a postgresql:// URL has to work inside the image"


def test_the_default_database_lives_on_the_volume():
    text = DOCKERFILE.read_text(encoding="utf-8")
    assert "AUTHORATE_DB_URL=sqlite:////data/" in text, (
        "the default path must be writable by the unprivileged user and survive a "
        "restart")


def test_no_credential_is_baked_into_a_layer():
    text = DOCKERFILE.read_text(encoding="utf-8")
    for name in ("AUTHORATE_TOKEN_SALT", "AUTHORATE_SECRET_KEY"):
        assert not re.search(r"^ENV\s+%s=" % name, text, re.M), name


def test_the_server_runs_unprivileged_and_declares_a_healthcheck():
    text = DOCKERFILE.read_text(encoding="utf-8")
    assert "USER portal" in text
    assert "/healthz" in text


def test_the_boot_step_takes_the_schema_lock_before_it_serves():
    """`alembic upgrade head` at boot is the race: two replicas apply the same DDL.

    The lock lives in `autorate-portal migrate`, so the image must call that and not the
    bare alembic command. Measured on PostgreSQL 17: three replicas starting together all
    reach 200, and four concurrent processes leave exactly one revision (see
    docs/verification/2026-11-22-postgres-and-container.md).
    """
    text = DOCKERFILE.read_text(encoding="utf-8")
    assert "autorate-portal migrate --if-enabled && exec autorate-portal serve" in text
    assert "alembic upgrade head" not in text, "the unlocked path must not come back"


def test_the_healthcheck_stays_on_liveness():
    """A healthcheck that reads the database turns its outage into a restart loop."""
    text = DOCKERFILE.read_text(encoding="utf-8")
    healthcheck = text[text.index("HEALTHCHECK"):]
    assert "/healthz" in healthcheck
    assert "/readyz" not in healthcheck, "readiness belongs to the orchestrator, not to HEALTHCHECK"


def test_the_boot_step_can_be_turned_off_for_a_migration_job():
    text = DOCKERFILE.read_text(encoding="utf-8")
    assert "AUTHORATE_MIGRATE_ON_START=0" in text, (
        "a deployment that migrates in its own job needs to be told how")
