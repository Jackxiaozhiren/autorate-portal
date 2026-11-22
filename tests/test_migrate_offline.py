"""The chain has to render for the database we deploy on, not only the one we test on.

The suite runs on SQLite: fast, no service, and that is the right default. The cost is that
the PostgreSQL half of every migration never executes in CI -- and the two dialects do not
merely differ in syntax. 0005 changes a check constraint, which PostgreSQL does in place
(``ALTER TABLE ... DROP CONSTRAINT`` / ``ADD CONSTRAINT``) and SQLite can only do by building
a new table and copying the rows into it. A migration that works on SQLite can therefore
still fail on the first container boot, which is the worst place to find out.

Alembic's offline mode renders the chain for a dialect without connecting to anything, so the
rendering can be asserted inside the same suite that has no PostgreSQL server. These tests pin
three things: the PostgreSQL rendering is complete and needs no server, each dialect uses its
own mechanism, and both end at the same revision with the same constraint.
"""
from __future__ import annotations

import io
from pathlib import Path

import pytest
from alembic import command
from alembic.script import ScriptDirectory

from autorate_portal import migrate

ROOT = Path(__file__).resolve().parents[1]
MIGRATIONS = ROOT / "migrations"
# TEST-NET-1: routable nowhere. Offline mode must not care; an accidental connection
# would fail at once instead of hanging on a TCP timeout.
UNREACHABLE = "postgresql+psycopg://portal:portal@192.0.2.1:5432/portal"


def _render(url: str) -> str:
    """The SQL this build would send to ``url``, produced without a connection."""
    config = migrate.alembic_config(url, script_location=MIGRATIONS)
    buffer = io.StringIO()
    config.output_buffer = buffer
    command.upgrade(config, "head", sql=True)
    return buffer.getvalue()


def _revisions() -> list[str]:
    config = migrate.alembic_config(script_location=MIGRATIONS)
    script = ScriptDirectory.from_config(config)
    return [revision.revision for revision in script.walk_revisions()]


def test_the_chain_renders_for_postgresql_without_reaching_a_server():
    sql = _render(UNREACHABLE)
    assert sql.strip(), "the PostgreSQL rendering is empty"
    assert "CREATE TABLE alembic_version" in sql
    assert sql.lstrip().startswith("BEGIN;")
    assert sql.rstrip().endswith("COMMIT;")


def test_offline_rendering_opens_no_database(tmp_path):
    target = tmp_path / "never-created.db"
    assert _render("sqlite:///" + str(target))
    assert not target.exists(), "offline rendering opened the database it was describing"


@pytest.mark.parametrize("url", [UNREACHABLE, "sqlite://"])
def test_every_revision_is_stamped_before_the_next_one_runs(url):
    """A missing stamp means a revision was skipped, which a partial render would hide.

    The first revision is recorded with ``INSERT ... VALUES``; the rest move the single row
    with ``UPDATE``. Both forms count as a stamp, and they have to appear in chain order --
    a stamp out of order would mean the render is not a sequence a database could follow.
    """
    sql = _render(url)
    positions = []
    for revision in reversed(_revisions()):  # base first
        moved = "version_num='%s'" % revision
        inserted = "VALUES ('%s')" % revision
        if moved in sql:
            positions.append(sql.index(moved))
        else:
            assert inserted in sql, "%s is never recorded" % revision
            positions.append(sql.index(inserted))
    assert positions == sorted(positions), "a revision is stamped out of order"


def test_postgresql_changes_the_constraint_in_place():
    sql = _render(UNREACHABLE)
    assert "ALTER TABLE artifact DROP CONSTRAINT ck_artifact_kind" in sql
    assert "ADD CONSTRAINT ck_artifact_kind CHECK" in sql
    assert "_alembic_tmp_artifact" not in sql, (
        "PostgreSQL is being rendered with SQLite's table rebuild")


def test_sqlite_rebuilds_the_table_because_it_cannot_alter_a_constraint():
    sql = _render("sqlite://")
    assert "_alembic_tmp_artifact" in sql
    assert "DROP CONSTRAINT" not in sql, (
        "SQLite does not support DROP CONSTRAINT; this rendering would fail on boot")


def test_both_dialects_agree_on_the_head_and_the_constraint():
    postgres = _render(UNREACHABLE)
    sqlite = _render("sqlite://")
    head = migrate.script_head(MIGRATIONS)
    expected = "CHECK (kind in ('certificate', 'document', 'records', 'protocol', 'transcript', 'wheel'))"
    for rendering in (postgres, sqlite):
        assert expected in rendering, "a dialect is missing the new kind"
        assert "version_num='%s'" % head in rendering
