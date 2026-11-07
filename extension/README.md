# Flareguard Extension

Chrome Manifest V3 extension for Flareguard. It detects buying/payment triggers, collects page evidence, and uses API/manual results to present risk in the popup and (for 3/3) block page interaction unless the hostname is trusted.

## Install (unpacked)

1. Open `chrome://extensions`
2. Enable **Developer mode**
3. Click **Load unpacked**
4. Select `flareguard/extension`
5. After code changes: reload the extension and refresh affected tabs

## Key behavior

- **Buying/payment trigger check** (`scripts/content.js`): looks for card fields, payment provider embeds, checkout/payment-like paths, buy/pay buttons, and price text. This is used only to decide whether a deeper check should run.
- **On-demand collection** (`scripts/collector.js`): runs when requested by the background trigger flow and returns page evidence (favicon, navbar logo extension, sampled broken links, trigger signals, URL/title metadata).
- **API-driven decision** (`background.js`): sends `POST /api/v1/analyze` with `{ "url": "<page url>" }` to the configured endpoint and maps the API verdict to extension UI:
  - `confirmed`/`high` → `3/3` (likely)
  - `medium` → `2/3` (possible)
  - other/low/unknown → `1/3` (none/low)
- **Blocking**: API/manual results scored `3/3` trigger an in-page overlay blocking interaction. Trusted hostnames (Settings) bypass the block for that hostname.
- **Hardcoded blocklist**: `easycoachbuskenya.co.ke` (and subdomains) is auto-blocked in `scripts/content.js`.

## Popup pages

- `popup/main.html` — status, threat count, **Check with API**.
- `popup/warning.html` — shown for `>2/3` results; report/save/navigate helpers.
- `popup/settings.html` — API endpoint, trusted hostnames, manual test score tools.
- `popup/logs.html` — session logs from background/content/collector/popup.

## Configuration

In **Settings**:
- **Analyze endpoint**: stored in `chrome.storage.sync.apiEndpoint` (default `http://localhost:8000/api/v1/analyze`).
- **Trusted hostnames**: stored in `chrome.storage.local.trustedHosts`; bypasses 3/3 blocking for matching hostnames.

## Permissions

- `storage` — settings, trust list, logs/results, counters.
- `tabs` — active tab lookup and tab messaging/navigation helpers.
- `host_permissions: <all_urls>` — content script injection and API requests.

## Development notes

- The repo currently contains both TypeScript sources and generated JS for some scripts; check which files are referenced by `manifest.json` before editing.
- Service worker/content script behavior changes usually require extension reload + page refresh.
- `chrome://` pages, extension pages, and some restricted pages cannot be scanned like normal websites.

## Known limitations

- Buying/payment detection is heuristic and trigger-only.
- Collector evidence is not yet sent to `/api/v1/analyze` (backend currently accepts only `url`).
- Broken-link checks can produce false negatives/positives due to browser CORS/no-cors behavior.
- Local/manual trust, hardcoded blocklist, and UI test tools are for development/safety testing and should be reviewed before production use.
