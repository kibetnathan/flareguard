from __future__ import annotations

from dataclasses import dataclass

from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy.orm import selectinload

from db.models.brand import Brand


@dataclass(frozen=True)
class VerifiedBrand:
    name: str
    slug: str
    domains: tuple[str, ...]


# Starter set of reference brands. Official domains are only treated as verified
# when seeded/recorded here with is_verified=True; anything else is not official.
SEED_BRANDS: tuple[dict, ...] = (
    {"name": "Google", "domains": ["google.com", "google.co.uk", "google.de"]},
    {"name": "Gmail", "domains": ["gmail.com", "mail.google.com"]},
    {"name": "PayPal", "domains": ["paypal.com", "paypal.me"]},
    {"name": "Microsoft", "domains": ["microsoft.com", "live.com", "outlook.com"]},
    {"name": "Apple", "domains": ["apple.com", "icloud.com"]},
    {"name": "Amazon", "domains": ["amazon.com", "amazon.co.uk"]},
    {"name": "Facebook", "domains": ["facebook.com", "fb.com"]},
    {"name": "Instagram", "domains": ["instagram.com"]},
    {"name": "WhatsApp", "domains": ["whatsapp.com"]},
    {"name": "Netflix", "domains": ["netflix.com"]},
    {"name": "Stripe", "domains": ["stripe.com"]},
    {"name": "DHL", "domains": ["dhl.com", "dhl.de"]},
    {"name": "Chase", "domains": ["chase.com"]},
    {"name": "Binance", "domains": ["binance.com"]},
    {"name": "Coinbase", "domains": ["coinbase.com"]},
    {"name": "LinkedIn", "domains": ["linkedin.com"]},
    {"name": "Twitter", "domains": ["twitter.com", "x.com"]},
)


def slugify(name: str) -> str:
    return "".join(ch.lower() for ch in name if ch.isalnum())


async def load_verified_brands(session: AsyncSession) -> list[VerifiedBrand]:
    """Load brands whose verification status is explicitly established."""
    stmt = (
        select(Brand)
        .options(selectinload(Brand.domains))
        .where(Brand.is_verified.is_(True))
        .order_by(Brand.id)
    )
    result = await session.execute(stmt)
    brands = result.scalars().all()

    verified: list[VerifiedBrand] = []
    for brand in brands:
        domains = tuple(
            bd.domain
            for bd in brand.domains
            if bd.is_verified
        )
        if domains:
            verified.append(VerifiedBrand(name=brand.name, slug=brand.slug, domains=domains))
    return verified
