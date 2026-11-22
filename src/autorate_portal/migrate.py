"""Serialise schema upgrades: replicas may start together, one migration may not run twice.

The image applies the chain before the server accepts a connection. That is right for one
container and wrong for several: two replicas read the same ``alembic_version``, both decide
0005 is pending, both send the same DDL, and the loser fails on a constraint the winner has
just created. Restarting it then succeeds, which is the worst shape a bug can take -- a boot
loop that heals itself and leaves a red herring in the logs.

So the upgrade runs under a lock that is released only when the upgrade is over:

* PostgreSQL: a session advisory lock keyed on ``current_database()``. The waiter blocks in
  the server, not in a retry loop, and ``lock_timeout`` bounds the wait.
* SQLite: an exclusive ``flock`` on ``<database>.migrate.lock``. SQLite serialises writers
  within a file, but a batch migration is dozens of statements and the loser would surface
  as "database is locked" halfway through; the file lock makes the wait ordered and explicit.

A deployment that would rather migrate once, in a job, sets ``AUTHORATE_MIGRATE_ON_START=0``
on the replicas and runs ``autorate-portal migrate`` in the job. Both paths take the same
lock, so neither of them is the unsafe one.
"""
from __future__ import annotations

import contextlib
import hashlib
import os
import sys
import time
from pathlib import Path

from alembic import command
from alembic.config import Config
from alembic.script import ScriptDirectory
from sqlalchemy import create_engine, text
from sqlalchemy.engine import make_url
from sqlalchemy.exc import DBAPIError

from . import db

STARTUP_ENV = "AUTHORATE_MIGRATE_ON_START"
LOCK_TIMEOUT_ENV = "AUTHORATE_MIGRATE_LOCK_TIMEOUT"
DEFAULT_LOCK_TIMEOUT = 120.0
_OFF = {"0", "false", "no", "off"}


class MigrationError(RuntimeError):
    """The upgrade did not run, and the reason is not a bug in the migration."""


class MigrationLockTimeout(MigrationError):
    """Another replica has held the schema lock for longer than we are willing to wait."""


class MigrationConfigurationError(MigrationError):
    """This command cannot be asked to upgrade this database."""


def migrate_on_start() -> bool:
    """Whether a replica's startup step should apply the chain (default: yes)."""
    return os.environ.get(STARTUP_ENV, "").strip().lower() not in _OFF


def lock_timeout() -> float:
    """Seconds to wait for the schema lock before refusing, from env or the default."""
    raw = os.environ.get(LOCK_TIMEOUT_ENV, "").strip()
    if not raw:
        return DEFAULT_LOCK_TIMEOUT
    try:
        return float(raw)
    except ValueError as exc:
        raise MigrationConfigurationError(
            "%s must be a number of seconds, not %r" % (LOCK_TIMEOUT_ENV, raw)) from exc


def advisory_key(database: str) -> int:
    """A stable signed 64-bit key, scoped to one database name.

    Advisory locks are per cluster, so the name has to be in the key: two databases on one
    server must be able to upgrade at the same time, and the same database must produce the
    same key from every process without reading anything first.
    """
    digest = hashlib.sha256(("autorate-portal:migrate:" + database).encode("utf-8")).digest()
    return int.from_bytes(digest[:8], "big", signed=True)


def alembic_config(url: str | None = None, *,
                   script_location: str | Path | None = None) -> Config:
    """The alembic configuration this deployment would use, with ``url`` if one is given.

    ``alembic.ini`` in the working directory wins, because that is the file the image and a
    source checkout both ship and the file ``alembic`` itself would read. Otherwise the
    migrations directory that travels with the code is used: first the copy inside the
    installed package (``pyproject.toml`` force-includes it), then the checkout's, so an
    editable install migrates the same way an image does.
    """
    if script_location is not None:
        config = Config()
        config.set_main_option("script_location", str(Path(script_location)))
    elif Path("alembic.ini").is_file():
        config = Config("alembic.ini")
    else:
        packaged = packaged_migrations()
        if packaged is None:
            raise MigrationConfigurationError(
                "no alembic.ini in %s and no migrations directory in the package; "
                "pass --migrations" % Path.cwd())
        config = Config()
        config.set_main_option("script_location", str(packaged))
    if url is not None:
        # ConfigParser interpolates `%`, so a password with one in it has to be escaped.
        config.set_main_option("sqlalchemy.url", url.replace("%", "%%"))
    return config


def packaged_migrations() -> Path | None:
    """The migrations directory that travels with this code, whether installed or in a tree."""
    inside_package = Path(__file__).with_name("migrations")
    if inside_package.is_dir():
        return inside_package
    in_tree = Path(__file__).resolve().parents[2] / "migrations"
    return in_tree if in_tree.is_dir() else None


def script_head(script_location: str | Path | None = None) -> str:
    """The revision this build's chain ends at, read without touching a database.

    Readiness compares the database against this. It is re-read on each probe rather than
    cached: the chain is five small files, and a cached head would be a second answer to
    "what does this build expect" that could drift from the first.
    """
    config = alembic_config(script_location=script_location)
    head = ScriptDirectory.from_config(config).get_current_head()
    if head is None:
        raise MigrationConfigurationError("the migration chain has no head revision")
    return head


def upgrade_to_head(url: str | None = None, *, timeout: float | None = None,
                    script_location: str | Path | None = None) -> str:
    """Apply the chain under the schema lock and return the revision now in force."""
    target = url or db.database_url()
    config = alembic_config(target, script_location=script_location)
    with _exclusive(target, lock_timeout() if timeout is None else float(timeout)):
        command.upgrade(config, "head")
    return script_head(script_location)


@contextlib.contextmanager
def _exclusive(url: str, timeout: float):
    parsed = make_url(url)
    backend = parsed.get_backend_name()
    if backend == "postgresql":
        with _postgres_lock(url, timeout):
            yield
    elif backend == "sqlite":
        with _sqlite_lock(parsed.database, timeout):
            yield
    else:
        # An unlocked upgrade is not a slower upgrade, it is the race described above.
        raise MigrationConfigurationError(
            "no schema lock is implemented for %s://; add one before running replicas" % backend)


@contextlib.contextmanager
def _postgres_lock(url: str, timeout: float):
    # AUTOCOMMIT keeps the waiting session out of a transaction: it holds the advisory lock
    # and nothing else, so it cannot block the migration it is waiting for.
    engine = create_engine(url, future=True, isolation_level="AUTOCOMMIT")
    try:
        with engine.connect() as connection:
            database = connection.execute(text("select current_database()")).scalar_one()
            key = advisory_key(database)
            milliseconds = max(1, int(timeout * 1000))
            connection.execute(text("select set_config('lock_timeout', :value, false)"),
                               {"value": "%dms" % milliseconds})
            try:
                connection.execute(text("select pg_advisory_lock(:key)"), {"key": key})
            except DBAPIError as exc:
                if _sqlstate(exc) == "55P03":
                    raise MigrationLockTimeout(
                        "another process holds the schema lock on database %r; waited %gs "
                        "(%s)" % (database, timeout, LOCK_TIMEOUT_ENV)) from exc
                raise
            try:
                yield
            finally:
                # The lock lives as long as the session, so a failed unlock cannot leak it:
                # closing the connection releases it either way.
                with contextlib.suppress(Exception):
                    connection.execute(text("select pg_advisory_unlock(:key)"), {"key": key})
    finally:
        engine.dispose()


@contextlib.contextmanager
def _sqlite_lock(database: str | None, timeout: float):
    if not database or database == ":memory:":
        yield
        return
    try:
        import fcntl
    except ImportError:  # pragma: no cover - Windows only
        print("migrate: no file lock on this platform; concurrent upgrades are not "
              "serialised here", file=sys.stderr)
        yield
        return
    path = Path(str(database) + ".migrate.lock")
    path.parent.mkdir(parents=True, exist_ok=True)
    with open(path, "a+", encoding="utf-8") as handle:
        deadline = time.monotonic() + timeout
        while True:
            try:
                fcntl.flock(handle.fileno(), fcntl.LOCK_EX | fcntl.LOCK_NB)
                break
            except BlockingIOError as exc:
                if time.monotonic() >= deadline:
                    raise MigrationLockTimeout(
                        "another process holds the schema lock %s; waited %gs (%s)"
                        % (path, timeout, LOCK_TIMEOUT_ENV)) from exc
                time.sleep(0.05)
        try:
            yield
        finally:
            fcntl.flock(handle.fileno(), fcntl.LOCK_UN)


def _sqlstate(exc: DBAPIError) -> str | None:
    """The SQLSTATE of the driver error, whatever driver answered."""
    original = getattr(exc, "orig", None)
    return (getattr(original, "sqlstate", None) or getattr(original, "pgcode", None))
