"""initial schema (reviewed: dialect-neutral types only, no raw SQL)

Revision ID: 0001
Revises:
Create Date: 2026-10-03 19:18:06.794743
"""
from __future__ import annotations

import sqlalchemy as sa
from alembic import op

import pch.store.types

revision = "0001"
down_revision = None
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.create_table('scan_locks',
    sa.Column('name', sa.Unicode(length=64), nullable=False),
    sa.Column('holder', sa.Unicode(length=200), nullable=False),
    sa.Column('acquired_at', pch.store.types.UTCDateTime(), nullable=False),
    sa.PrimaryKeyConstraint('name')
    )
    op.create_table('scans',
    sa.Column('id', sa.Unicode(length=40), nullable=False),
    sa.Column('started_at', pch.store.types.UTCDateTime(), nullable=False),
    sa.Column('finished_at', pch.store.types.UTCDateTime(), nullable=True),
    sa.Column('mode', sa.Unicode(length=16), nullable=False),
    sa.Column('status', sa.Unicode(length=16), nullable=False),
    sa.Column('repos_total', sa.Integer(), nullable=False),
    sa.Column('repos_failed', sa.Integer(), nullable=False),
    sa.Column('findings_total', sa.Integer(), nullable=False),
    sa.Column('duration_s', sa.Float(), nullable=True),
    sa.Column('summary', sa.JSON(), nullable=False),
    sa.PrimaryKeyConstraint('id')
    )
    op.create_table('collection_errors',
    sa.Column('id', sa.Integer(), autoincrement=True, nullable=False),
    sa.Column('scan_id', sa.Unicode(length=40), nullable=False),
    sa.Column('source', sa.Unicode(length=32), nullable=False),
    sa.Column('subject', sa.Unicode(length=300), nullable=False),
    sa.Column('message', sa.UnicodeText(), nullable=False),
    sa.ForeignKeyConstraint(['scan_id'], ['scans.id'], ),
    sa.PrimaryKeyConstraint('id')
    )
    with op.batch_alter_table('collection_errors', schema=None) as batch_op:
        batch_op.create_index(batch_op.f('ix_collection_errors_scan_id'), ['scan_id'], unique=False)

    op.create_table('findings',
    sa.Column('id', sa.Integer(), autoincrement=True, nullable=False),
    sa.Column('scan_id', sa.Unicode(length=40), nullable=False),
    sa.Column('repo_key', sa.Unicode(length=300), nullable=False),
    sa.Column('rule_id', sa.Unicode(length=40), nullable=False),
    sa.Column('category', sa.Unicode(length=8), nullable=False),
    sa.Column('severity', sa.Unicode(length=10), nullable=False),
    sa.Column('status', sa.Unicode(length=16), nullable=False),
    sa.Column('pipeline_id', sa.Unicode(length=64), nullable=True),
    sa.Column('pipeline_name', sa.UnicodeText(), nullable=True),
    sa.Column('stage', sa.UnicodeText(), nullable=True),
    sa.Column('message', sa.UnicodeText(), nullable=False),
    sa.Column('evidence', sa.JSON(), nullable=False),
    sa.Column('link', sa.UnicodeText(), nullable=True),
    sa.Column('waiver', sa.JSON(), nullable=True),
    sa.Column('original_status', sa.Unicode(length=16), nullable=True),
    sa.ForeignKeyConstraint(['scan_id'], ['scans.id'], ),
    sa.PrimaryKeyConstraint('id')
    )
    with op.batch_alter_table('findings', schema=None) as batch_op:
        batch_op.create_index(batch_op.f('ix_findings_repo_key'), ['repo_key'], unique=False)
        batch_op.create_index(batch_op.f('ix_findings_scan_id'), ['scan_id'], unique=False)
        batch_op.create_index('ix_findings_scan_rule', ['scan_id', 'rule_id'], unique=False)

    op.create_table('repo_results',
    sa.Column('id', sa.Integer(), autoincrement=True, nullable=False),
    sa.Column('scan_id', sa.Unicode(length=40), nullable=False),
    sa.Column('repo_key', sa.Unicode(length=300), nullable=False),
    sa.Column('project', sa.Unicode(length=200), nullable=False),
    sa.Column('repo', sa.Unicode(length=200), nullable=False),
    sa.Column('url', sa.UnicodeText(), nullable=False),
    sa.Column('owner', sa.Unicode(length=200), nullable=True),
    sa.Column('platform_mix', sa.JSON(), nullable=False),
    sa.Column('targets', sa.JSON(), nullable=False),
    sa.Column('test_state', sa.Unicode(length=32), nullable=False),
    sa.Column('test_state_reason', sa.UnicodeText(), nullable=False),
    sa.Column('coverage', sa.Float(), nullable=True),
    sa.Column('sonar_gate', sa.Unicode(length=16), nullable=True),
    sa.Column('aikido_criticals', sa.Integer(), nullable=True),
    sa.Column('score', sa.Float(), nullable=True),
    sa.Column('status', sa.Unicode(length=16), nullable=False),
    sa.Column('unknowns', sa.Integer(), nullable=False),
    sa.Column('critical_fails', sa.Integer(), nullable=False),
    sa.Column('high_fails', sa.Integer(), nullable=False),
    sa.Column('migration_score', sa.Integer(), nullable=True),
    sa.Column('migration_blockers', sa.JSON(), nullable=False),
    sa.Column('facts', sa.JSON(), nullable=False),
    sa.Column('pipelines', sa.JSON(), nullable=False),
    sa.Column('rule_status', sa.JSON(), nullable=False),
    sa.Column('external_summary', sa.JSON(), nullable=False),
    sa.ForeignKeyConstraint(['scan_id'], ['scans.id'], ),
    sa.PrimaryKeyConstraint('id')
    )
    with op.batch_alter_table('repo_results', schema=None) as batch_op:
        batch_op.create_index(batch_op.f('ix_repo_results_project'), ['project'], unique=False)
        batch_op.create_index(batch_op.f('ix_repo_results_repo_key'), ['repo_key'], unique=False)
        batch_op.create_index(batch_op.f('ix_repo_results_scan_id'), ['scan_id'], unique=False)
        batch_op.create_index(batch_op.f('ix_repo_results_status'), ['status'], unique=False)


def downgrade() -> None:
    with op.batch_alter_table('repo_results', schema=None) as batch_op:
        batch_op.drop_index(batch_op.f('ix_repo_results_status'))
        batch_op.drop_index(batch_op.f('ix_repo_results_scan_id'))
        batch_op.drop_index(batch_op.f('ix_repo_results_repo_key'))
        batch_op.drop_index(batch_op.f('ix_repo_results_project'))

    op.drop_table('repo_results')
    with op.batch_alter_table('findings', schema=None) as batch_op:
        batch_op.drop_index('ix_findings_scan_rule')
        batch_op.drop_index(batch_op.f('ix_findings_scan_id'))
        batch_op.drop_index(batch_op.f('ix_findings_repo_key'))

    op.drop_table('findings')
    with op.batch_alter_table('collection_errors', schema=None) as batch_op:
        batch_op.drop_index(batch_op.f('ix_collection_errors_scan_id'))

    op.drop_table('collection_errors')
    op.drop_table('scans')
    op.drop_table('scan_locks')
