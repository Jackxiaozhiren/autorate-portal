"""F10 deletion: a packet row is tombstoned while its stored bytes are removed.

One column on `packet`. The row stays so an id is never silently re-issued and
an audit trail can still name it; the bytes are removed from the store by the
admin route, not by this migration. Explicit DDL for the same reason 0001-0003
are: a column in `db.py` without a revision must fail the migration test.

Revision ID: 0004_packet_tombstone
Revises: 0003_policy_versions
Create Date: 2026-11-16
"""
from __future__ import annotations

import sqlalchemy as sa
from alembic import op

revision = "0004_packet_tombstone"
down_revision = "0003_policy_versions"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.add_column("packet", sa.Column("tombstoned", sa.Integer(), nullable=False,
                                      server_default="0"))


def downgrade() -> None:
    op.drop_column("packet", "tombstoned")
