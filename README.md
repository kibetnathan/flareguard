# Flareguard

Flareguard is an anti-phishing prototype with:
- a **Chrome MV3 extension** (`extension/`) that detects buying/payment triggers, collects page evidence, and shows risk UI/blocking based on analysis results;
- a **FastAPI backend** (`app/api/`) that analyzes URLs and returns explainable risk assessments.

## Repository layout

```text
flareguard/
├── app/
│   ├── api/              # FastAPI backend + analysis pipeline
│   ├── detection/        # placeholder
│   ├── docker-compose.yml
│   └── Makefile
├── extension/            # Chrome extension (MV3)
└── README.md
```

## Quick start

### Backend (Docker)

From `app/`:

```bash
make setup   # prepare env, start DB, run Alembic migrations
make start   # build/start API + DB
```

API: `http://localhost:8000/health`

If host port `5432` is already in use:

```bash
make down
POSTGRES_PORT=5433 make setup
POSTGRES_PORT=5433 make start
```

### Extension (unpacked)

1. Open `chrome://extensions`
2. Enable **Developer mode**
3. **Load unpacked** → select `extension/`
4. Open extension **Settings** and confirm the Analyze endpoint (default `http://localhost:8000/api/v1/analyze`)
5. Visit a normal `https://` page

## Extension flow (current)

1. `scripts/content.js` looks for **buying/payment trigger signals** (card fields, payment providers, checkout/payment paths, pay/buy buttons, prices). This is only a trigger.
2. When triggered (or user clicks **Check with API**), content asks background to run analysis.
3. `scripts/collector.js` collects page evidence on demand (URL/title/favicon/logo extension/broken-link sample/trigger signals) and returns it to background.
4. `background.js` sends the page URL to the backend (`POST /api/v1/analyze`) and uses the **API response** to decide risk/verdict/badge/popup state.
5. For API/manual results with score `3/3`, content script shows an in-page interaction block (unless hostname is trusted in Settings).

> Note: collector evidence is currently gathered/logged in the extension; the backend `/api/v1/analyze` schema currently accepts `{ "url": "..." }`. Extend the API model if you want to score collector fields server-side.

## Manual testing

- Popup **Settings → Test tools** can set manual API-style scores for the active tab UI/warning behavior.
- `extension/test-page.html` can emit test results/logs.
- Hardcoded auto-block list (content script): `easycoachbuskenya.co.ke` (and subdomains) is blocked on visit.

## Backend details

See `app/api/README.md` for:
- analysis pipeline
- configuration/env vars
- API request/response
- migrations/tests
- privacy and limitations

## Extension details

See `extension/README.md` for:
- script responsibilities
- popup/settings behavior
- permissions
- development notes

## Safety/limitations

- Heuristic/threat-intel results are **not** guarantees. A low/unknown result does not prove a site is safe.
- Provider failures are treated as unavailable evidence, not “safe”.
- The hardcoded blocklist and manual trust controls are local testing/safety controls; manage carefully.
- Do not commit real API keys or credentials.
