"""Schema 2 packets carry wheels: let the artifact table record them.

V1 taught packets to embed their wheel set, and nothing told the database. The
`ck_artifact_kind` CHECK still listed the five kinds M2 knew, so ingesting a
schema 2 packet failed with an IntegrityError from SQLite - a packet the CLI
could verify and replay, refused by the portal at the last step. No test caught
it because every ingest fixture was a schema 1 packet.

SQLite cannot alter a CHECK in place, so the constraint is dropped and recreated
through batch mode, which rebuilds the table. `wheel` is appended rather than
inserted to keep the constraint text equal to `db.ARTIFACT_KINDS`'s tuple order.

Revision ID: 0005_artifact_wheel_kind
Revises: 0004_packet_tombstone
Create Date: 2026-11-17
"""
from __future__ import annotations

import sqlalchemy as sa
from alembic import op

revision = "0005_artifact_wheel_kind"
down_revision = "0004_packet_tombstone"
branch_labels = None
depends_on = None

OLD = ("kind in ('certificate', 'document', 'records', 'protocol', 'transcript')")
NEW = ("kind in ('certificate', 'document', 'records', 'protocol', 'transcript', 'wheel')")


def _artifact_mirror(check: str) -> sa.Table:
    """A reflection-free image of the artifact table for batch mode.

    ``--sql`` offline mode has no connection with which to reflect SQLite's
    table, so batch_alter_table needs an explicit ``copy_from``. The columns and
    constraints mirror migration 0001's ``artifact`` definition exactly; only
    the CHECK text differs, which is what this migration changes.
    """
    return sa.Table(
        "artifact",
        sa.MetaData(),
        sa.Column("id", sa.String(32), primary_key=True),
        sa.Column("packet_id", sa.String(32), nullable=False),
        sa.Column("path", sa.String(512), nullable=False),
        sa.Column("sha256", sa.String(64), nullable=False),
        sa.Column("kind", sa.String(32), nullable=False),
        sa.UniqueConstraint("packet_id", "path", name="uq_artifact_path"),
        sa.CheckConstraint(check, name="ck_artifact_kind"),
    )


def upgrade() -> None:
    with op.batch_alter_table("artifact", copy_from=_artifact_mirror(OLD)) as batch:
        batch.drop_constraint("ck_artifact_kind", type_="check")
        batch.create_check_constraint("ck_artifact_kind", NEW)


def downgrade() -> None:
    # A database that already holds a wheel artefact cannot go back: the row
    # would violate the narrower constraint, and deleting it would delete
    # evidence. The failure is the honest outcome, so it is not swallowed.
    with op.batch_alter_table("artifact", copy_from=_artifact_mirror(NEW)) as batch:
        batch.drop_constraint("ck_artifact_kind", type_="check")
        batch.create_check_constraint("ck_artifact_kind", OLD)
