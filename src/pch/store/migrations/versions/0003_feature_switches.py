"""feature_flags and feature_audit: UI/CLI overrides of the feature switches and their append-only audit trail

Revision ID: 0003
Revises: 0002
Create Date: 2026-10-04 09:00:00.000000
"""
from __future__ import annotations

import sqlalchemy as sa
from alembic import op

import pch.store.types

revision = "0003"
down_revision = "0002"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.create_table('feature_flags',
    sa.Column('feature_key', sa.Unicode(length=40), nullable=False),
    sa.Column('enabled', sa.Boolean(), nullable=False),
    sa.Column('updated_by', sa.Unicode(length=100), nullable=False),
    sa.Column('updated_at', pch.store.types.UTCDateTime(), nullable=False),
    sa.PrimaryKeyConstraint('feature_key')
    )
    op.create_table('feature_audit',
    sa.Column('id', sa.Integer(), autoincrement=True, nullable=False),
    sa.Column('feature_key', sa.Unicode(length=40), nullable=False),
    sa.Column('old_value', sa.Unicode(length=8), nullable=False),
    sa.Column('new_value', sa.Unicode(length=8), nullable=False),
    sa.Column('actor_id_hash', sa.Unicode(length=64), nullable=False),
    sa.Column('actor_display_name', sa.Unicode(length=100), nullable=False),
    sa.Column('at', pch.store.types.UTCDateTime(), nullable=False),
    sa.Column('source', sa.Unicode(length=8), nullable=False),
    sa.PrimaryKeyConstraint('id')
    )
    with op.batch_alter_table('feature_audit', schema=None) as batch_op:
        batch_op.create_index(batch_op.f('ix_feature_audit_feature_key'), ['feature_key'], unique=False)


def downgrade() -> None:
    with op.batch_alter_table('feature_audit', schema=None) as batch_op:
        batch_op.drop_index(batch_op.f('ix_feature_audit_feature_key'))

    op.drop_table('feature_audit')
    op.drop_table('feature_flags')
