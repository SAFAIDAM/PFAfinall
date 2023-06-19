"""added password field

Revision ID: 27205fdb0266
Revises: 5243e51b0a0c
Create Date: 2023-05-30 21:20:39.292641

"""
from alembic import op
import sqlalchemy as sa


# revision identifiers, used by Alembic.
revision = '27205fdb0266'
down_revision = '5243e51b0a0c'
branch_labels = None
depends_on = None


def upgrade():
    # ### commands auto generated by Alembic - please adjust! ###
    with op.batch_alter_table('user', schema=None) as batch_op:
        batch_op.add_column(sa.Column('password_hash', sa.String(length=128), nullable=True))

    # ### end Alembic commands ###


def downgrade():
    # ### commands auto generated by Alembic - please adjust! ###
    with op.batch_alter_table('user', schema=None) as batch_op:
        batch_op.drop_column('password_hash')

    # ### end Alembic commands ###