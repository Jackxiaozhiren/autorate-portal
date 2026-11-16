"""F7 rule 4: editing a policy creates a version; nothing is overwritten.

Two columns on `policy`. `version` is the sequence number, `supersedes` points
at the previous row's id. Written as an explicit DDL snapshot so a column added
to `db.py` without a revision fails the migration test rather than drifting —
the same reason 0001 and 0002 are explicit.

Revision ID: 0003_policy_versions
Revises: 0002_monitor_schedule
Create Date: 2026-11-16
"""
from __future__ import annotations

import sqlalchemy as sa
from alembic import op

revision = "0003_policy_versions"
down_revision = "0002_monitor_schedule"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.add_column("policy", sa.Column("version", sa.Integer(), nullable=False,
                                      server_default="1"))
    op.add_column("policy", sa.Column("supersedes", sa.String(32), nullable=True))


def downgrade() -> None:
    op.drop_column("policy", "supersedes")
    op.drop_column("policy", "version")
