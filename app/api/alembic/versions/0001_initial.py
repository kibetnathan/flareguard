"""initial schema and verified-brand seed data

Revision ID: 0001_initial
Revises:
Create Date: 2026-11-07

"""

from collections.abc import Sequence

import sqlalchemy as sa

from alembic import op
from services.brands import SEED_BRANDS, slugify

revision: str = "0001_initial"
down_revision: str | None = None
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None


def upgrade() -> None:
    op.create_table(
        "domains",
        sa.Column("id", sa.Integer(), primary_key=True),
        sa.Column("hostname", sa.String(length=255), nullable=False),
        sa.Column("registrable_domain", sa.String(length=255), nullable=True),
        sa.Column("is_ip", sa.Boolean(), nullable=False, server_default=sa.false()),
        sa.Column("rdap_registered_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("rdap_checked_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("rdap_registrar", sa.String(length=255), nullable=True),
        sa.Column("rdap_status", sa.String(length=64), nullable=True),
        sa.Column(
            "created_at", sa.DateTime(timezone=True), nullable=False, server_default=sa.func.now()
        ),
        sa.Column(
            "updated_at", sa.DateTime(timezone=True), nullable=False, server_default=sa.func.now()
        ),
    )
    op.create_index("ix_domains_hostname", "domains", ["hostname"], unique=True)
    op.create_index("ix_domains_registrable_domain", "domains", ["registrable_domain"])

    op.create_table(
        "brands",
        sa.Column("id", sa.Integer(), primary_key=True),
        sa.Column("name", sa.String(length=128), nullable=False),
        sa.Column("slug", sa.String(length=128), nullable=False),
        sa.Column("is_verified", sa.Boolean(), nullable=False, server_default=sa.false()),
        sa.Column(
            "created_at", sa.DateTime(timezone=True), nullable=False, server_default=sa.func.now()
        ),
    )
    op.create_index("ix_brands_name", "brands", ["name"], unique=True)
    op.create_index("ix_brands_slug", "brands", ["slug"])

    op.create_table(
        "brand_domains",
        sa.Column("id", sa.Integer(), primary_key=True),
        sa.Column("brand_id", sa.Integer(), nullable=False),
        sa.Column("domain", sa.String(length=255), nullable=False),
        sa.Column("is_verified", sa.Boolean(), nullable=False, server_default=sa.false()),
        sa.Column(
            "created_at", sa.DateTime(timezone=True), nullable=False, server_default=sa.func.now()
        ),
        sa.ForeignKeyConstraint(
            ["brand_id"], ["brands.id"], name="fk_brand_domains_brand_id_brands", ondelete="CASCADE"
        ),
    )
    op.create_index("ix_brand_domains_brand_id", "brand_domains", ["brand_id"])
    op.create_index("ix_brand_domains_domain", "brand_domains", ["domain"], unique=True)

    op.create_table(
        "threat_indicators",
        sa.Column("id", sa.Integer(), primary_key=True),
        sa.Column("source", sa.String(length=64), nullable=False),
        sa.Column("indicator_type", sa.String(length=16), nullable=False),
        sa.Column("value", sa.String(length=255), nullable=False),
        sa.Column("threat_type", sa.String(length=32), nullable=False),
        sa.Column("severity", sa.String(length=16), nullable=True),
        sa.Column(
            "first_seen_at",
            sa.DateTime(timezone=True),
            nullable=False,
            server_default=sa.func.now(),
        ),
        sa.Column(
            "last_seen_at",
            sa.DateTime(timezone=True),
            nullable=False,
            server_default=sa.func.now(),
        ),
        sa.Column("expires_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column(
            "created_at", sa.DateTime(timezone=True), nullable=False, server_default=sa.func.now()
        ),
        sa.UniqueConstraint(
            "source",
            "indicator_type",
            "value",
            name="uq_threat_indicators_source_type_value",
        ),
    )
    op.create_index("ix_threat_indicators_source", "threat_indicators", ["source"])
    op.create_index("ix_threat_indicators_value", "threat_indicators", ["value"])

    op.create_table(
        "assessments",
        sa.Column("id", sa.String(length=36), primary_key=True),
        sa.Column("domain_id", sa.Integer(), nullable=True),
        sa.Column("hostname", sa.String(length=255), nullable=False),
        sa.Column("registrable_domain", sa.String(length=255), nullable=True),
        sa.Column("scheme", sa.String(length=8), nullable=False),
        sa.Column("is_ip", sa.Boolean(), nullable=False, server_default=sa.false()),
        sa.Column("url_hash", sa.String(length=64), nullable=False),
        sa.Column("path", sa.String(length=512), nullable=True),
        sa.Column("status", sa.String(length=16), nullable=False),
        sa.Column("score", sa.Integer(), nullable=False),
        sa.Column("verdict", sa.String(length=16), nullable=False),
        sa.Column("confidence", sa.String(length=16), nullable=False),
        sa.Column("provider_results", sa.JSON(), nullable=True),
        sa.Column("recommendations", sa.JSON(), nullable=True),
        sa.Column("analyzed_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("cache_expires_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column(
            "created_at", sa.DateTime(timezone=True), nullable=False, server_default=sa.func.now()
        ),
        sa.ForeignKeyConstraint(
            ["domain_id"],
            ["domains.id"],
            name="fk_assessments_domain_id_domains",
            ondelete="SET NULL",
        ),
    )
    op.create_index("ix_assessments_domain_id", "assessments", ["domain_id"])
    op.create_index("ix_assessments_hostname", "assessments", ["hostname"])
    op.create_index("ix_assessments_registrable_domain", "assessments", ["registrable_domain"])
    op.create_index("ix_assessments_url_hash", "assessments", ["url_hash"])
    op.create_index("ix_assessments_cache_expires_at", "assessments", ["cache_expires_at"])

    op.create_table(
        "assessment_signals",
        sa.Column("id", sa.Integer(), primary_key=True),
        sa.Column("assessment_id", sa.String(length=36), nullable=False),
        sa.Column("code", sa.String(length=64), nullable=False),
        sa.Column("category", sa.String(length=32), nullable=False),
        sa.Column("severity", sa.String(length=16), nullable=False),
        sa.Column("score", sa.Integer(), nullable=False),
        sa.Column("message", sa.String(length=512), nullable=False),
        sa.Column(
            "created_at", sa.DateTime(timezone=True), nullable=False, server_default=sa.func.now()
        ),
        sa.ForeignKeyConstraint(
            ["assessment_id"],
            ["assessments.id"],
            name="fk_assessment_signals_assessment_id_assessments",
            ondelete="CASCADE",
        ),
    )
    op.create_index(
        "ix_assessment_signals_assessment_id", "assessment_signals", ["assessment_id"]
    )

    _seed_brands()


def _seed_brands() -> None:
    brands_table = sa.table(
        "brands",
        sa.column("id", sa.Integer()),
        sa.column("name", sa.String()),
        sa.column("slug", sa.String()),
        sa.column("is_verified", sa.Boolean()),
    )
    brand_domains_table = sa.table(
        "brand_domains",
        sa.column("id", sa.Integer()),
        sa.column("brand_id", sa.Integer()),
        sa.column("domain", sa.String()),
        sa.column("is_verified", sa.Boolean()),
    )

    brand_rows = []
    domain_rows = []
    domain_id = 1
    for brand_id, entry in enumerate(SEED_BRANDS, start=1):
        brand_rows.append(
            {
                "id": brand_id,
                "name": entry["name"],
                "slug": slugify(entry["name"]),
                "is_verified": True,
            }
        )
        for domain in entry["domains"]:
            domain_rows.append(
                {"id": domain_id, "brand_id": brand_id, "domain": domain, "is_verified": True}
            )
            domain_id += 1

    op.bulk_insert(brands_table, brand_rows)
    op.bulk_insert(brand_domains_table, domain_rows)


def downgrade() -> None:
    op.drop_index("ix_assessment_signals_assessment_id", table_name="assessment_signals")
    op.drop_table("assessment_signals")
    op.drop_index("ix_assessments_cache_expires_at", table_name="assessments")
    op.drop_index("ix_assessments_url_hash", table_name="assessments")
    op.drop_index("ix_assessments_registrable_domain", table_name="assessments")
    op.drop_index("ix_assessments_hostname", table_name="assessments")
    op.drop_index("ix_assessments_domain_id", table_name="assessments")
    op.drop_table("assessments")
    op.drop_index("ix_threat_indicators_value", table_name="threat_indicators")
    op.drop_index("ix_threat_indicators_source", table_name="threat_indicators")
    op.drop_table("threat_indicators")
    op.drop_index("ix_brand_domains_domain", table_name="brand_domains")
    op.drop_index("ix_brand_domains_brand_id", table_name="brand_domains")
    op.drop_table("brand_domains")
    op.drop_index("ix_brands_slug", table_name="brands")
    op.drop_index("ix_brands_name", table_name="brands")
    op.drop_table("brands")
    op.drop_index("ix_domains_registrable_domain", table_name="domains")
    op.drop_index("ix_domains_hostname", table_name="domains")
    op.drop_table("domains")
