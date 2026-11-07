# Flare Guard

Anti-phishing tooling for a Chrome extension. This repository contains a FastAPI
backend that accepts a suspicious URL, analyzes it with deterministic heuristics
and threat intelligence, stores the result in PostgreSQL, and returns an
explainable risk assessment. It also contains the Chrome extension under
`extension/` (see `extension/README.md`).

```
flareguard/
├── app/
│   ├── api/            # FastAPI backend (this README's focus)
│   └── detection/      # placeholder
├── extension/          # Chrome MV3 extension
└── README.md
```

## Architecture

The backend lives in `app/api`:

```
app/api/
├── main.py                      # ASGI entrypoint (`uvicorn main:app`)
├── config.py                    # pydantic-settings configuration
├── application/app.py           # app factory, lifespan, routers, error handling
├── db/                          # async SQLAlchemy engine, session, ORM models
├── models/analyze.py            # Pydantic request/response schemas
├── routes/analyze.py            # POST /api/v1/analyze
├── services/                    # normalization, threat intel, heuristics, scoring, pipeline
├── alembic/                     # migrations (schema + brand seed)
└── tests/                       # pytest suite (SQLite + mocked providers)
```

## Analysis pipeline

`POST /api/v1/analyze` orchestrates these stages (see `services/analysis.py`):

1. **URL validation & normalization** (`services/normalization.py`) — accepts
   `http`/`https` only; rejects credentials, malformed encodings, control
   characters and oversized input; lowercases/strips the host; resolves the
   registrable domain with a Public Suffix List-aware library; detects IPs and
   Punycode/IDN.
2. **Domain lookup** — upserts the domain row and reuses cached RDAP
   registration data when fresh, otherwise fetches it (`services/domain_intel.py`).
3. **Stored threat-intelligence lookup** — checks previously stored
   indicators (from providers) for the host/domain/url hash.
4. **External providers** — run concurrently; a failure never counts as "clean".
5. **Heuristics** — independent analyzers for domain structure, brand
   impersonation, URL structure and domain age return structured signals.
6. **Scoring** — deterministic, configurable rules with grouped/capped signals.
7. **Persistence** — the assessment and its signals are stored.
8. **Response** — a structured, explainable assessment.

Assessment caching reuses recent results per URL; expired assessments are
re-analyzed, and a newer confirmed threat overrides a stale cached result.

## Quickstart

Requirements: Python ≥ 3.11, [`uv`](https://docs.astral.sh/uv/), and Docker
(for PostgreSQL).

```sh
cd app/api

# 1. Start PostgreSQL
docker compose up -d db

# 2. Install dependencies
uv sync

# 3. Configure the environment
cp .env.example .env        # Windows: copy .env.example .env

# 4. Apply database migrations (creates tables + seeds verified brands)
uv run alembic upgrade head

# 5. Run the API
uv run uvicorn main:app --reload     # http://localhost:8000
```

Smoke test:

```sh
curl -s localhost:8000/health
curl -s -X POST localhost:8000/api/v1/analyze \
  -H "Content-Type: application/json" \
  -d '{"url": "https://paypal-login.com/account"}'
```

### Tests

```sh
cd app/api
uv run pytest
uv run ruff check .
```

Tests run against an in-memory SQLite database and mocked external providers —
no PostgreSQL, API keys, or live threat-intelligence services are required.

## API

### `POST /api/v1/analyze`

Request:

```json
{ "url": "https://example.com/login" }
```

Response:

```json
{
  "id": "8ec577f44033405098fb67533249812c",
  "status": "completed",
  "target": { "hostname": "example.com", "registrable_domain": "example.com", "is_ip": false, "scheme": "https" },
  "assessment": { "score": 40, "verdict": "medium", "confidence": "medium" },
  "signals": [
    { "code": "BRAND_IN_DOMAIN", "category": "brand_impersonation", "severity": "high", "score": 30, "message": "..." }
  ],
  "provider_results": [
    { "provider": "google_web_risk", "status": "not_configured", "threat_found": null, "categories": [] }
  ],
  "recommendations": ["..."],
  "analyzed_at": "2026-11-07T14:02:38Z",
  "expires_at": "2026-11-07T14:32:38Z"
}
```

- `status` is `completed` for a fresh analysis or `cached` when a recent
  assessment was reused.
- `verdict` is one of `low` (0–24), `medium` (25–59), `high` (60–99),
  `confirmed` (100, a trusted source reported the URL as phishing/malware), or
  `unknown` (insufficient evidence).
- `confidence` describes the strength/completeness of the evidence, not a
  probability that the site is malicious.
- `provider_results[].threat_found` is `null` for
  `not_configured`/`error`/`timeout` providers — a failed check is never treated
  as "safe".

Invalid URLs return `422` with a sanitized message. Provider failures are
isolated and never crash the endpoint.

## Configuration

Settings are read from the environment / `.env` (see `.env.example`):

| Variable | Default | Purpose |
|---|---|---|
| `DATABASE_URL` | `postgresql+asyncpg://flareguard:flareguard@localhost:5432/flareguard` | Database connection |
| `GOOGLE_WEB_RISK_API_KEY` | _(unset)_ | Google Web Risk Lookup API key |
| `WEB_RISK_ENABLED` | `true` | Enable/disable the Web Risk provider |
| `PROVIDER_TIMEOUT_SECONDS` | `5.0` | External provider request timeout |
| `RDAP_TIMEOUT_SECONDS` | `4.0` | RDAP request timeout |
| `RDAP_CACHE_TTL_SECONDS` | `86400` | How long domain registration data is reused |
| `ASSESSMENT_CACHE_TTL_SECONDS` | `1800` | Assessment cache lifetime |
| `MAX_URL_LENGTH` | `2048` | Maximum accepted URL length |

Never commit real credentials.

### Threat-intelligence providers

Providers implement the `ThreatIntelProvider` interface
(`services/threat_intel/base.py`), so new sources can be added in
`services/threat_intel/registry.py` without changing the analysis engine.

**Google Web Risk** is implemented. Enable it by setting
`GOOGLE_WEB_RISK_API_KEY`. If the key is absent or invalid the provider reports
`not_configured`/`error` and the rest of the pipeline still runs. **RDAP**
domain-registration lookups are performed independently and degrade gracefully.

## Data & privacy

- One `domains` row per hostname (never per URL path).
- URL-level threat indicators are stored as a SHA-256 hash, not the raw URL.
- Only the scheme/host/path are stored for assessments — query strings are not
  persisted, and logs use redacted URLs.

## Limitations

- Detection is heuristic and rule-based; scores are **not** validated
  probabilities. Absence from a threat-intelligence source does **not** mean a
  URL is safe, and a low verdict is not a guarantee of safety.
- No page-content crawling or HTML fetching is performed. Any future
  content scanner would need a separately isolated component with SSRF
  protections, private-IP blocking, redirect revalidation and resource limits.
- The brand reference set is a small starter list seeded via migration.
- The Chrome extension currently performs its detection client-side and does not
  yet call this backend.
