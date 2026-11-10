"""Alembic environment.

Offline mode matters here: the gate has to be able to read the migration's SQL
without a database, and ``--sql`` is the only way to see what a migration will
do before it does it. Both modes use the same URL resolution as the app
(``AUTHORATE_DB_URL``), so a migration cannot silently target another database.
"""
from __future__ import annotations

from alembic import context
from sqlalchemy import create_engine

from autorate_portal import db

config = context.config
target_metadata = db.Base.metadata


def _url() -> str:
    return config.get_main_option("sqlalchemy.url") or db.database_url()


def run_migrations_offline() -> None:
    context.configure(url=_url(), target_metadata=target_metadata,
                      literal_binds=True, render_as_batch=True)
    with context.begin_transaction():
        context.run_migrations()


def run_migrations_online() -> None:
    engine = create_engine(_url(), future=True)
    with engine.connect() as connection:
        context.configure(connection=connection, target_metadata=target_metadata,
                          render_as_batch=True)
        with context.begin_transaction():
            context.run_migrations()


if context.is_offline_mode():
    run_migrations_offline()
else:
    run_migrations_online()
