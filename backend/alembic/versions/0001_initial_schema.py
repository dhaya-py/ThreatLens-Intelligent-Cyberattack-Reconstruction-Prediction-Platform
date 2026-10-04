"""initial schema

Revision ID: 0001
Revises:
Create Date: 2026-10-01 09:18:27.882197
"""

from collections.abc import Sequence

import sqlalchemy as sa
from alembic import op
from sqlalchemy.dialects import postgresql

revision: str = "0001"
down_revision: str | None = None
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None


def upgrade() -> None:

    op.create_table(
        "hosts",
        sa.Column("id", sa.Integer(), nullable=False),
        sa.Column("hostname", sa.String(length=128), nullable=False),
        sa.Column("ip_address", sa.String(length=45), nullable=False),
        sa.Column("operating_system", sa.String(length=128), nullable=False),
        sa.Column("department", sa.String(length=64), nullable=False),
        sa.Column("criticality", sa.Integer(), nullable=False),
        sa.Column("role", sa.String(length=64), nullable=True),
        sa.Column("network_zone", sa.String(length=32), nullable=True),
        sa.Column(
            "created_at", sa.DateTime(timezone=True), server_default=sa.func.now(), nullable=False
        ),
        sa.CheckConstraint("criticality BETWEEN 1 AND 5", name=op.f("ck_hosts_criticality_range")),
        sa.PrimaryKeyConstraint("id", name=op.f("pk_hosts")),
        sa.UniqueConstraint("hostname", name=op.f("uq_hosts_hostname")),
        sa.UniqueConstraint("ip_address", name=op.f("uq_hosts_ip_address")),
    )
    op.create_table(
        "users",
        sa.Column("id", sa.Integer(), nullable=False),
        sa.Column("username", sa.String(length=128), nullable=False),
        sa.Column("display_name", sa.String(length=128), nullable=True),
        sa.Column("department", sa.String(length=64), nullable=True),
        sa.Column("privilege_level", sa.String(length=32), nullable=False),
        sa.Column("is_service_account", sa.Boolean(), nullable=False),
        sa.Column(
            "created_at", sa.DateTime(timezone=True), server_default=sa.func.now(), nullable=False
        ),
        sa.PrimaryKeyConstraint("id", name=op.f("pk_users")),
        sa.UniqueConstraint("username", name=op.f("uq_users_username")),
    )
    op.create_table(
        "incidents",
        sa.Column("id", sa.Integer(), nullable=False),
        sa.Column("reference", sa.String(length=32), nullable=False),
        sa.Column("title", sa.String(length=256), nullable=False),
        sa.Column("severity", sa.String(length=16), nullable=False),
        sa.Column("status", sa.String(length=16), nullable=False),
        sa.Column("first_seen", sa.DateTime(timezone=True), nullable=False),
        sa.Column("last_seen", sa.DateTime(timezone=True), nullable=False),
        sa.Column("root_host_id", sa.Integer(), nullable=True),
        sa.Column("risk_score", sa.Integer(), nullable=False),
        sa.Column("confidence", sa.Float(), nullable=False),
        sa.Column("summary", sa.Text(), nullable=True),
        sa.Column(
            "root_cause",
            sa.JSON().with_variant(postgresql.JSONB(astext_type=sa.Text()), "postgresql"),
            nullable=False,
        ),
        sa.Column(
            "created_at", sa.DateTime(timezone=True), server_default=sa.func.now(), nullable=False
        ),
        sa.Column(
            "updated_at", sa.DateTime(timezone=True), server_default=sa.func.now(), nullable=False
        ),
        sa.ForeignKeyConstraint(
            ["root_host_id"], ["hosts.id"], name=op.f("fk_incidents_root_host_id_hosts")
        ),
        sa.PrimaryKeyConstraint("id", name=op.f("pk_incidents")),
        sa.UniqueConstraint("reference", name=op.f("uq_incidents_reference")),
    )
    op.create_table(
        "security_events",
        sa.Column("id", sa.Integer(), nullable=False),
        sa.Column("external_id", sa.String(length=128), nullable=True),
        sa.Column("timestamp", sa.DateTime(timezone=True), nullable=False),
        sa.Column("event_type", sa.String(length=32), nullable=False),
        sa.Column("source", sa.String(length=64), nullable=False),
        sa.Column("host_id", sa.Integer(), nullable=True),
        sa.Column("destination_host_id", sa.Integer(), nullable=True),
        sa.Column("username", sa.String(length=128), nullable=True),
        sa.Column("source_ip", sa.String(length=45), nullable=True),
        sa.Column("destination_ip", sa.String(length=45), nullable=True),
        sa.Column("process_name", sa.String(length=256), nullable=True),
        sa.Column("parent_process", sa.String(length=256), nullable=True),
        sa.Column("command_line", sa.Text(), nullable=True),
        sa.Column("domain", sa.String(length=253), nullable=True),
        sa.Column("protocol", sa.String(length=16), nullable=True),
        sa.Column("destination_port", sa.Integer(), nullable=True),
        sa.Column("outcome", sa.String(length=16), nullable=True),
        sa.Column("raw_log", sa.Text(), nullable=True),
        sa.Column(
            "metadata",
            sa.JSON().with_variant(postgresql.JSONB(astext_type=sa.Text()), "postgresql"),
            nullable=False,
        ),
        sa.Column(
            "ingested_at", sa.DateTime(timezone=True), server_default=sa.func.now(), nullable=False
        ),
        sa.ForeignKeyConstraint(
            ["destination_host_id"],
            ["hosts.id"],
            name=op.f("fk_security_events_destination_host_id_hosts"),
        ),
        sa.ForeignKeyConstraint(
            ["host_id"], ["hosts.id"], name=op.f("fk_security_events_host_id_hosts")
        ),
        sa.PrimaryKeyConstraint("id", name=op.f("pk_security_events")),
        sa.UniqueConstraint("external_id", name=op.f("uq_security_events_external_id")),
    )
    with op.batch_alter_table("security_events", schema=None) as batch_op:
        batch_op.create_index(
            batch_op.f("ix_security_events_event_type"), ["event_type"], unique=False
        )
        batch_op.create_index(
            "ix_security_events_host_id_timestamp", ["host_id", "timestamp"], unique=False
        )
        batch_op.create_index(
            batch_op.f("ix_security_events_source_ip"), ["source_ip"], unique=False
        )
        batch_op.create_index(
            batch_op.f("ix_security_events_timestamp"), ["timestamp"], unique=False
        )
        batch_op.create_index(batch_op.f("ix_security_events_username"), ["username"], unique=False)

    op.create_table(
        "attack_edges",
        sa.Column("id", sa.Integer(), nullable=False),
        sa.Column("incident_id", sa.Integer(), nullable=False),
        sa.Column("source_node", sa.String(length=320), nullable=False),
        sa.Column("source_type", sa.String(length=16), nullable=False),
        sa.Column("destination_node", sa.String(length=320), nullable=False),
        sa.Column("destination_type", sa.String(length=16), nullable=False),
        sa.Column("relationship", sa.String(length=32), nullable=False),
        sa.Column("timestamp", sa.DateTime(timezone=True), nullable=False),
        sa.Column("username", sa.String(length=128), nullable=True),
        sa.Column("protocol", sa.String(length=16), nullable=True),
        sa.Column("port", sa.Integer(), nullable=True),
        sa.Column("confidence", sa.Float(), nullable=False),
        sa.Column(
            "evidence",
            sa.JSON().with_variant(postgresql.JSONB(astext_type=sa.Text()), "postgresql"),
            nullable=False,
        ),
        sa.Column(
            "event_ids",
            sa.JSON().with_variant(postgresql.JSONB(astext_type=sa.Text()), "postgresql"),
            nullable=False,
        ),
        sa.ForeignKeyConstraint(
            ["incident_id"],
            ["incidents.id"],
            name=op.f("fk_attack_edges_incident_id_incidents"),
            ondelete="CASCADE",
        ),
        sa.PrimaryKeyConstraint("id", name=op.f("pk_attack_edges")),
    )
    with op.batch_alter_table("attack_edges", schema=None) as batch_op:
        batch_op.create_index(
            batch_op.f("ix_attack_edges_incident_id"), ["incident_id"], unique=False
        )

    op.create_table(
        "attack_steps",
        sa.Column("id", sa.Integer(), nullable=False),
        sa.Column("incident_id", sa.Integer(), nullable=False),
        sa.Column("sequence", sa.Integer(), nullable=False),
        sa.Column("timestamp", sa.DateTime(timezone=True), nullable=False),
        sa.Column("host_id", sa.Integer(), nullable=True),
        sa.Column("tactic", sa.String(length=64), nullable=False),
        sa.Column("technique_id", sa.String(length=16), nullable=False),
        sa.Column("technique_name", sa.String(length=128), nullable=False),
        sa.Column("confidence", sa.Float(), nullable=False),
        sa.Column("description", sa.Text(), nullable=False),
        sa.Column(
            "evidence",
            sa.JSON().with_variant(postgresql.JSONB(astext_type=sa.Text()), "postgresql"),
            nullable=False,
        ),
        sa.Column(
            "event_ids",
            sa.JSON().with_variant(postgresql.JSONB(astext_type=sa.Text()), "postgresql"),
            nullable=False,
        ),
        sa.ForeignKeyConstraint(
            ["host_id"], ["hosts.id"], name=op.f("fk_attack_steps_host_id_hosts")
        ),
        sa.ForeignKeyConstraint(
            ["incident_id"],
            ["incidents.id"],
            name=op.f("fk_attack_steps_incident_id_incidents"),
            ondelete="CASCADE",
        ),
        sa.PrimaryKeyConstraint("id", name=op.f("pk_attack_steps")),
    )
    with op.batch_alter_table("attack_steps", schema=None) as batch_op:
        batch_op.create_index(
            batch_op.f("ix_attack_steps_incident_id"), ["incident_id"], unique=False
        )

    op.create_table(
        "host_risk_scores",
        sa.Column("id", sa.Integer(), nullable=False),
        sa.Column("incident_id", sa.Integer(), nullable=False),
        sa.Column("host_id", sa.Integer(), nullable=False),
        sa.Column("score", sa.Integer(), nullable=False),
        sa.Column("status", sa.String(length=16), nullable=False),
        sa.Column(
            "factors",
            sa.JSON().with_variant(postgresql.JSONB(astext_type=sa.Text()), "postgresql"),
            nullable=False,
        ),
        sa.ForeignKeyConstraint(
            ["host_id"], ["hosts.id"], name=op.f("fk_host_risk_scores_host_id_hosts")
        ),
        sa.ForeignKeyConstraint(
            ["incident_id"],
            ["incidents.id"],
            name=op.f("fk_host_risk_scores_incident_id_incidents"),
            ondelete="CASCADE",
        ),
        sa.PrimaryKeyConstraint("id", name=op.f("pk_host_risk_scores")),
        sa.UniqueConstraint("incident_id", "host_id", name=op.f("uq_host_risk_scores_incident_id")),
    )
    with op.batch_alter_table("host_risk_scores", schema=None) as batch_op:
        batch_op.create_index(
            batch_op.f("ix_host_risk_scores_incident_id"), ["incident_id"], unique=False
        )

    op.create_table(
        "incident_events",
        sa.Column("incident_id", sa.Integer(), nullable=False),
        sa.Column("event_id", sa.Integer(), nullable=False),
        sa.Column("role", sa.String(length=16), nullable=False),
        sa.Column("correlation_confidence", sa.Float(), nullable=False),
        sa.Column(
            "reasons",
            sa.JSON().with_variant(postgresql.JSONB(astext_type=sa.Text()), "postgresql"),
            nullable=False,
        ),
        sa.ForeignKeyConstraint(
            ["event_id"],
            ["security_events.id"],
            name=op.f("fk_incident_events_event_id_security_events"),
            ondelete="CASCADE",
        ),
        sa.ForeignKeyConstraint(
            ["incident_id"],
            ["incidents.id"],
            name=op.f("fk_incident_events_incident_id_incidents"),
            ondelete="CASCADE",
        ),
        sa.PrimaryKeyConstraint("incident_id", "event_id", name=op.f("pk_incident_events")),
    )
    op.create_table(
        "lateral_movements",
        sa.Column("id", sa.Integer(), nullable=False),
        sa.Column("incident_id", sa.Integer(), nullable=False),
        sa.Column("source_host_id", sa.Integer(), nullable=False),
        sa.Column("destination_host_id", sa.Integer(), nullable=False),
        sa.Column("username", sa.String(length=128), nullable=True),
        sa.Column("protocol", sa.String(length=16), nullable=False),
        sa.Column("port", sa.Integer(), nullable=True),
        sa.Column("timestamp", sa.DateTime(timezone=True), nullable=False),
        sa.Column("confidence", sa.Float(), nullable=False),
        sa.Column("reason", sa.Text(), nullable=False),
        sa.Column(
            "evidence",
            sa.JSON().with_variant(postgresql.JSONB(astext_type=sa.Text()), "postgresql"),
            nullable=False,
        ),
        sa.Column(
            "event_ids",
            sa.JSON().with_variant(postgresql.JSONB(astext_type=sa.Text()), "postgresql"),
            nullable=False,
        ),
        sa.ForeignKeyConstraint(
            ["destination_host_id"],
            ["hosts.id"],
            name=op.f("fk_lateral_movements_destination_host_id_hosts"),
        ),
        sa.ForeignKeyConstraint(
            ["incident_id"],
            ["incidents.id"],
            name=op.f("fk_lateral_movements_incident_id_incidents"),
            ondelete="CASCADE",
        ),
        sa.ForeignKeyConstraint(
            ["source_host_id"], ["hosts.id"], name=op.f("fk_lateral_movements_source_host_id_hosts")
        ),
        sa.PrimaryKeyConstraint("id", name=op.f("pk_lateral_movements")),
    )
    with op.batch_alter_table("lateral_movements", schema=None) as batch_op:
        batch_op.create_index(
            batch_op.f("ix_lateral_movements_incident_id"), ["incident_id"], unique=False
        )

    op.create_table(
        "network_connections",
        sa.Column("id", sa.Integer(), nullable=False),
        sa.Column("event_id", sa.Integer(), nullable=True),
        sa.Column("timestamp", sa.DateTime(timezone=True), nullable=False),
        sa.Column("source_host_id", sa.Integer(), nullable=True),
        sa.Column("destination_host_id", sa.Integer(), nullable=True),
        sa.Column("source_ip", sa.String(length=45), nullable=True),
        sa.Column("destination_ip", sa.String(length=45), nullable=True),
        sa.Column("username", sa.String(length=128), nullable=True),
        sa.Column("protocol", sa.String(length=16), nullable=True),
        sa.Column("port", sa.Integer(), nullable=True),
        sa.Column("bytes_sent", sa.BigInteger(), nullable=True),
        sa.ForeignKeyConstraint(
            ["destination_host_id"],
            ["hosts.id"],
            name=op.f("fk_network_connections_destination_host_id_hosts"),
        ),
        sa.ForeignKeyConstraint(
            ["event_id"],
            ["security_events.id"],
            name=op.f("fk_network_connections_event_id_security_events"),
            ondelete="CASCADE",
        ),
        sa.ForeignKeyConstraint(
            ["source_host_id"],
            ["hosts.id"],
            name=op.f("fk_network_connections_source_host_id_hosts"),
        ),
        sa.PrimaryKeyConstraint("id", name=op.f("pk_network_connections")),
    )
    with op.batch_alter_table("network_connections", schema=None) as batch_op:
        batch_op.create_index(
            batch_op.f("ix_network_connections_event_id"), ["event_id"], unique=False
        )
        batch_op.create_index(
            "ix_network_connections_src_dst",
            ["source_host_id", "destination_host_id"],
            unique=False,
        )
        batch_op.create_index(
            batch_op.f("ix_network_connections_timestamp"), ["timestamp"], unique=False
        )

    op.create_table(
        "target_predictions",
        sa.Column("id", sa.Integer(), nullable=False),
        sa.Column("incident_id", sa.Integer(), nullable=False),
        sa.Column("host_id", sa.Integer(), nullable=False),
        sa.Column("rank", sa.Integer(), nullable=False),
        sa.Column("score", sa.Integer(), nullable=False),
        sa.Column(
            "reasons",
            sa.JSON().with_variant(postgresql.JSONB(astext_type=sa.Text()), "postgresql"),
            nullable=False,
        ),
        sa.ForeignKeyConstraint(
            ["host_id"], ["hosts.id"], name=op.f("fk_target_predictions_host_id_hosts")
        ),
        sa.ForeignKeyConstraint(
            ["incident_id"],
            ["incidents.id"],
            name=op.f("fk_target_predictions_incident_id_incidents"),
            ondelete="CASCADE",
        ),
        sa.PrimaryKeyConstraint("id", name=op.f("pk_target_predictions")),
        sa.UniqueConstraint(
            "incident_id", "host_id", name=op.f("uq_target_predictions_incident_id")
        ),
    )
    with op.batch_alter_table("target_predictions", schema=None) as batch_op:
        batch_op.create_index(
            batch_op.f("ix_target_predictions_incident_id"), ["incident_id"], unique=False
        )


def downgrade() -> None:

    with op.batch_alter_table("target_predictions", schema=None) as batch_op:
        batch_op.drop_index(batch_op.f("ix_target_predictions_incident_id"))

    op.drop_table("target_predictions")
    with op.batch_alter_table("network_connections", schema=None) as batch_op:
        batch_op.drop_index(batch_op.f("ix_network_connections_timestamp"))
        batch_op.drop_index("ix_network_connections_src_dst")
        batch_op.drop_index(batch_op.f("ix_network_connections_event_id"))

    op.drop_table("network_connections")
    with op.batch_alter_table("lateral_movements", schema=None) as batch_op:
        batch_op.drop_index(batch_op.f("ix_lateral_movements_incident_id"))

    op.drop_table("lateral_movements")
    op.drop_table("incident_events")
    with op.batch_alter_table("host_risk_scores", schema=None) as batch_op:
        batch_op.drop_index(batch_op.f("ix_host_risk_scores_incident_id"))

    op.drop_table("host_risk_scores")
    with op.batch_alter_table("attack_steps", schema=None) as batch_op:
        batch_op.drop_index(batch_op.f("ix_attack_steps_incident_id"))

    op.drop_table("attack_steps")
    with op.batch_alter_table("attack_edges", schema=None) as batch_op:
        batch_op.drop_index(batch_op.f("ix_attack_edges_incident_id"))

    op.drop_table("attack_edges")
    with op.batch_alter_table("security_events", schema=None) as batch_op:
        batch_op.drop_index(batch_op.f("ix_security_events_username"))
        batch_op.drop_index(batch_op.f("ix_security_events_timestamp"))
        batch_op.drop_index(batch_op.f("ix_security_events_source_ip"))
        batch_op.drop_index("ix_security_events_host_id_timestamp")
        batch_op.drop_index(batch_op.f("ix_security_events_event_type"))

    op.drop_table("security_events")
    op.drop_table("incidents")
    op.drop_table("users")
    op.drop_table("hosts")
