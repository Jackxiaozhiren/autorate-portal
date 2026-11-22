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
