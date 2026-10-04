"""lineage table: per-scan repo -> pipeline -> release -> stage lineage documents (L2)

Revision ID: 0002
Revises: 0001
Create Date: 2026-10-03 21:00:00.000000
"""
from __future__ import annotations

import sqlalchemy as sa
from alembic import op

revision = "0002"
down_revision = "0001"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.create_table('lineage',
    sa.Column('id', sa.Integer(), autoincrement=True, nullable=False),
    sa.Column('scan_id', sa.Unicode(length=40), nullable=False),
    sa.Column('repo_key', sa.Unicode(length=300), nullable=False),
    sa.Column('kind', sa.Unicode(length=16), nullable=False),
    sa.Column('project', sa.Unicode(length=200), nullable=False),
    sa.Column('provider', sa.Unicode(length=24), nullable=False),
    sa.Column('has_prod', sa.Boolean(), nullable=False),
    sa.Column('n_pipelines', sa.Integer(), nullable=False),
    sa.Column('n_releases', sa.Integer(), nullable=False),
    sa.Column('targets', sa.Unicode(length=300), nullable=False),
    sa.Column('tiers', sa.Unicode(length=100), nullable=False),
    sa.Column('doc', sa.JSON(), nullable=False),
    sa.ForeignKeyConstraint(['scan_id'], ['scans.id'], ),
    sa.PrimaryKeyConstraint('id')
    )
    with op.batch_alter_table('lineage', schema=None) as batch_op:
        batch_op.create_index(batch_op.f('ix_lineage_project'), ['project'], unique=False)
        batch_op.create_index(batch_op.f('ix_lineage_repo_key'), ['repo_key'], unique=False)
        batch_op.create_index(batch_op.f('ix_lineage_scan_id'), ['scan_id'], unique=False)


def downgrade() -> None:
    with op.batch_alter_table('lineage', schema=None) as batch_op:
        batch_op.drop_index(batch_op.f('ix_lineage_scan_id'))
        batch_op.drop_index(batch_op.f('ix_lineage_repo_key'))
        batch_op.drop_index(batch_op.f('ix_lineage_project'))

    op.drop_table('lineage')
