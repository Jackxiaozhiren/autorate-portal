"""M5's schema additions: the per-project monitor schedule, and a project on the
monitor result so the series is scoped by a column (F6 rules 3 and 4).

Written as an explicit DDL snapshot for the same reason ``0001_initial`` is:
a column added to ``db.py`` without a revision has to fail the migration test
rather than drift. ``monitor_result`` already existed in Section 4.3 and is not
touched here.

Revision ID: 0002_monitor_schedule
Revises: 0001_initial
Create Date: 2026-11-16
"""
from __future__ import annotations

import sqlalchemy as sa
from alembic import op

revision = "0002_monitor_schedule"
down_revision = "0001_initial"
branch_labels = None
depends_on = None


def upgrade() -> None:
    # M5 adds the project to `monitor_result`, so a series is scoped by a column
    # rather than by a join into a store that carries no project.
    op.add_column("monitor_result",
                  sa.Column("project_id", sa.String(32), nullable=False,
                            server_default=""))
    op.create_table(
        "monitor_schedule",
        sa.Column("id", sa.String(32), primary_key=True),
        sa.Column("project_id", sa.String(32),
                  sa.ForeignKey("project.id", ondelete="CASCADE"), nullable=False),
        sa.Column("packet_id", sa.String(32), nullable=False),
        sa.Column("frequency", sa.String(64), nullable=False),
        sa.Column("updated_at", sa.String(40), nullable=False),
        sa.UniqueConstraint("project_id", name="uq_monitor_schedule_project"),
    )


def downgrade() -> None:
    op.drop_table("monitor_schedule")
    op.drop_column("monitor_result", "project_id")
