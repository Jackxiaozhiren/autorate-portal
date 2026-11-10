"""T3 - the migration builds Section 4.3 on an empty database, and can be read first."""
from __future__ import annotations

import contextlib
import io
from pathlib import Path

from alembic import command
from alembic.config import Config
from sqlalchemy import create_engine, inspect

from autorate_portal import db

ROOT = Path(__file__).resolve().parents[1]
TABLES = tuple(db.SECTION_4_3) + ("audit_row",)


def _config(url: str) -> Config:
    config = Config(str(ROOT / "alembic.ini"))
    config.set_main_option("sqlalchemy.url", url)
    return config


def test_upgrade_head_builds_the_model_on_an_empty_database(tmp_path):
    url = "sqlite:///" + str(tmp_path / "empty.db")
    command.upgrade(_config(url), "head")
    inspector = inspect(create_engine(url))

    assert set(inspector.get_table_names()) == set(TABLES) | {"alembic_version"}
    for table in TABLES:
        migrated = {column["name"]: column for column in inspector.get_columns(table)}
        model = db.Base.metadata.tables[table]
        assert set(migrated) == set(model.columns.keys()), table
        for name, column in model.columns.items():
            assert migrated[name]["nullable"] == column.nullable, "%s.%s nullable" % (table, name)
            assert bool(migrated[name]["primary_key"]) == bool(column.primary_key), \
                "%s.%s primary key" % (table, name)


def test_the_constraints_that_carry_invariants_reached_the_database(tmp_path):
    url = "sqlite:///" + str(tmp_path / "empty.db")
    command.upgrade(_config(url), "head")
    inspector = inspect(create_engine(url))

    unique = {constraint["name"] for constraint in inspector.get_unique_constraints("packet")}
    assert "uq_packet_manifest" in unique, "AC14's identity must be in the schema"
    checks = {constraint["name"] for constraint in
              inspector.get_check_constraints("certificate_summary")}
    roles = {constraint["name"] for constraint in
             inspector.get_check_constraints("membership")}
    assert "ck_membership_role" in roles
    assert checks == set(), "certificate_summary refuses at the writer, not by CHECK"


def test_offline_mode_renders_the_sql_before_it_runs(tmp_path):
    """The gate reads the migration with --sql; a database must not be required."""
    buffer = io.StringIO()
    with contextlib.redirect_stdout(buffer):
        command.upgrade(_config("sqlite:///" + str(tmp_path / "never-created.db")), "head", sql=True)
    sql = buffer.getvalue()
    assert "CREATE TABLE certificate_summary" in sql
    assert "bound TEXT" in sql, "a bound is text in the DDL too"
    assert not (tmp_path / "never-created.db").exists()


def test_no_create_table_is_written_outside_the_migration():
    offenders = []
    for source in sorted((ROOT / "src").rglob("*.py")):
        for number, line in enumerate(source.read_text(encoding="utf-8").splitlines(), start=1):
            if "create table" in line.lower():
                offenders.append("%s:%d" % (source.name, number))
    assert not offenders, "schema belongs to migrations: %s" % ", ".join(offenders)
