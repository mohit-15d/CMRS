"""add case_viewers association table

Revision ID: c3d5e7f9a1b3
Revises: 1e48e96df32b
Create Date: 2026-09-16

"""
from typing import Sequence, Union

from alembic import op
import sqlalchemy as sa


# revision identifiers, used by Alembic.
revision: str = 'c3d5e7f9a1b3'
down_revision: Union[str, Sequence[str], None] = '1e48e96df32b'
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    """Upgrade schema - create the case_viewers sharing table (additive)."""
    op.create_table('case_viewers',
    sa.Column('case_id', sa.Uuid(), nullable=False),
    sa.Column('user_id', sa.Uuid(), nullable=False),
    sa.ForeignKeyConstraint(['case_id'], ['cases.id'], name=op.f('fk_case_viewers_case_id_cases'), ondelete='CASCADE'),
    sa.ForeignKeyConstraint(['user_id'], ['users.id'], name=op.f('fk_case_viewers_user_id_users'), ondelete='CASCADE'),
    sa.PrimaryKeyConstraint('case_id', 'user_id', name=op.f('pk_case_viewers'))
    )
    op.create_index(op.f('ix_case_viewers_case_id'), 'case_viewers', ['case_id'], unique=False)
    op.create_index(op.f('ix_case_viewers_user_id'), 'case_viewers', ['user_id'], unique=False)


def downgrade() -> None:
    """Downgrade schema - drop the case_viewers table."""
    op.drop_index(op.f('ix_case_viewers_user_id'), table_name='case_viewers')
    op.drop_index(op.f('ix_case_viewers_case_id'), table_name='case_viewers')
    op.drop_table('case_viewers')