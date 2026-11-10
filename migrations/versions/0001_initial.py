"""Section 4.3's schema, frozen as it stood at M3.

This is a snapshot, not a view of the models: the column list is written out
here so that adding a column to ``db.py`` without a new revision makes
``tests/test_migrations.py`` fail instead of quietly diverging. Enum values are
literals for the same reason.

Revision ID: 0001_initial
Revises:
Create Date: 2026-11-10
"""
from __future__ import annotations

import sqlalchemy as sa
from alembic import op

revision = "0001_initial"
down_revision = None
branch_labels = None
depends_on = None

#: (table, columns, table-level constraints). Columns are
#: ``(name, type, kwargs)`` and FKs are named in ``kwargs["foreign_key"]``.
DDL = (
    ("org", (
        ("id", sa.String(32), {"primary_key": True}),
        ("name", sa.String(255), {"nullable": False, "unique": True}),
    ), ()),
    ("project", (
        ("id", sa.String(32), {"primary_key": True}),
        ("org_id", sa.String(32), {"nullable": False, "foreign_key": "org.id"}),
        ("name", sa.String(255), {"nullable": False}),
    ), (sa.UniqueConstraint("org_id", "name", name="uq_project_org_name"),)),
    ("packet", (
        ("id", sa.String(32), {"primary_key": True}),
        ("project_id", sa.String(32), {"nullable": False, "foreign_key": "project.id"}),
        ("manifest_sha256", sa.String(64), {"nullable": False}),
        ("protocol_digest", sa.String(255), {"nullable": False}),
        ("source_version", sa.String(255), {"nullable": False}),
        ("source_sha256", sa.String(64), {"nullable": False}),
        ("source_revision", sa.String(255), {"nullable": False}),
        ("created_by", sa.String(255), {"nullable": False}),
        ("ingested_at", sa.String(40), {"nullable": False}),
        ("bytes", sa.Integer(), {"nullable": False}),
        ("retention_until", sa.String(40), {"nullable": True}),
    ), (sa.UniqueConstraint("project_id", "manifest_sha256", name="uq_packet_manifest"),)),
    ("artifact", (
        ("id", sa.String(32), {"primary_key": True}),
        ("packet_id", sa.String(32), {"nullable": False, "foreign_key": "packet.id"}),
        ("path", sa.String(512), {"nullable": False}),
        ("sha256", sa.String(64), {"nullable": False}),
        ("kind", sa.String(32), {"nullable": False}),
    ), (
        sa.UniqueConstraint("packet_id", "path", name="uq_artifact_path"),
        sa.CheckConstraint("kind in ('certificate', 'document', 'records', 'protocol', "
                           "'transcript')", name="ck_artifact_kind"),
    )),
    ("certificate_summary", (
        ("id", sa.String(32), {"primary_key": True}),
        ("artifact_id", sa.String(32), {"nullable": False, "foreign_key": "artifact.id"}),
        ("task", sa.String(255), {"nullable": False}),
        ("backend", sa.String(255), {"nullable": False}),
        ("feasible", sa.Boolean(), {"nullable": True}),
        ("reason", sa.Text(), {"nullable": True}),
        ("autorate", sa.Text(), {"nullable": True}),
        ("bound", sa.Text(), {"nullable": True}),
        ("bound_unit", sa.Text(), {"nullable": True}),
        ("n_cal", sa.Integer(), {"nullable": True}),
        ("n_eval", sa.Integer(), {"nullable": True}),
        ("n_claims", sa.Integer(), {"nullable": True}),
        ("alpha", sa.Text(), {"nullable": True}),
        ("beta", sa.Text(), {"nullable": True}),
        ("delta", sa.Text(), {"nullable": True}),
    ), (sa.UniqueConstraint("artifact_id", "task", "backend", name="uq_summary_task_backend"),)),
    ("run", (
        ("id", sa.String(32), {"primary_key": True}),
        ("project_id", sa.String(32), {"nullable": False, "foreign_key": "project.id"}),
        ("argv", sa.Text(), {"nullable": False}),
        ("exit_code", sa.Integer(), {"nullable": True}),
        ("started_at", sa.String(40), {"nullable": False}),
        ("digest_then", sa.String(64), {"nullable": False}),
        ("stdout_sha256", sa.String(64), {"nullable": False}),
        ("packet_id_in", sa.String(32), {"nullable": False}),
    ), ()),
    ("policy", (
        ("id", sa.String(32), {"primary_key": True}),
        ("project_id", sa.String(32), {"nullable": False, "foreign_key": "project.id"}),
        ("name", sa.String(255), {"nullable": False}),
        ("packet_id", sa.String(32), {"nullable": False}),
        ("slices", sa.Text(), {"nullable": False}),
        ("budget", sa.Text(), {"nullable": False}),
        ("state", sa.String(16), {"nullable": False}),
        ("stale_because", sa.Text(), {"nullable": True}),
    ), (sa.CheckConstraint("state in ('active', 'stale', 'superseded')",
                           name="ck_policy_state"),)),
    ("monitor_result", (
        ("id", sa.String(32), {"primary_key": True}),
        ("run_id", sa.String(32), {"nullable": False, "foreign_key": "run.id"}),
        ("verdict", sa.String(32), {"nullable": False}),
        ("drift_detail_artifact_id", sa.String(32),
         {"nullable": True, "foreign_key": "artifact.id"}),
    ), ()),
    ("user", (
        ("id", sa.String(32), {"primary_key": True}),
        ("email", sa.String(320), {"nullable": False, "unique": True}),
        ("display", sa.String(255), {"nullable": False}),
    ), ()),
    ("membership", (
        ("user_id", sa.String(32), {"primary_key": True, "foreign_key": "user.id"}),
        ("org_id", sa.String(32), {"primary_key": True, "foreign_key": "org.id"}),
        ("role", sa.String(16), {"nullable": False}),
    ), (sa.CheckConstraint("role in ('viewer', 'producer', 'compliance', 'admin', 'auditor')",
                           name="ck_membership_role"),)),
    ("api_token", (
        ("id", sa.String(32), {"primary_key": True}),
        ("user_id", sa.String(32), {"nullable": False, "foreign_key": "user.id"}),
        ("project_id", sa.String(32), {"nullable": False, "foreign_key": "project.id"}),
        ("hash", sa.String(64), {"nullable": False, "unique": True}),
        ("scopes", sa.Text(), {"nullable": False}),
        ("created_at", sa.String(40), {"nullable": False}),
        ("last_used_at", sa.String(40), {"nullable": True}),
    ), ()),
    ("export_bundle", (
        ("id", sa.String(32), {"primary_key": True}),
        ("project_id", sa.String(32), {"nullable": False, "foreign_key": "project.id"}),
        ("kind", sa.String(16), {"nullable": False}),
        ("packet_ids", sa.Text(), {"nullable": False}),
        ("manifest_sha256", sa.String(64), {"nullable": False}),
    ), (sa.CheckConstraint("kind in ('annex_iv', 'iso_42001', 'aap')",
                           name="ck_export_kind"),)),
    ("audit_row", (
        ("id", sa.String(32), {"primary_key": True}),
        ("actor", sa.String(320), {"nullable": False}),
        ("project_id", sa.String(32), {"nullable": True}),
        ("action", sa.String(64), {"nullable": False}),
        ("target", sa.String(512), {"nullable": False}),
        ("at", sa.String(40), {"nullable": False}),
        ("outcome", sa.String(16), {"nullable": False}),
    ), ()),
)


def upgrade() -> None:
    for table, columns, constraints in DDL:
        rendered = []
        for name, kind, options in columns:
            foreign_key = options.get("foreign_key")
            arguments = [sa.ForeignKey(foreign_key, ondelete="CASCADE")] if foreign_key else []
            rendered.append(sa.Column(name, kind,
                                      *arguments,
                                      primary_key=options.get("primary_key", False),
                                      nullable=options.get("nullable", not options.get("primary_key", False)),
                                      unique=options.get("unique", False)))
        op.create_table(table, *rendered, *constraints)


def downgrade() -> None:
    for table, _, _ in reversed(DDL):
        op.drop_table(table)
