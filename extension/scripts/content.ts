type Signal = { name: string; weight: number; detail?: string };

let fgObserver: MutationObserver | undefined;

function runtimeOk() {
  try { return !!chrome?.runtime?.id; } catch { return false; }
}

function stop() {
  try { clearTimeout(timer); } catch {}
  try { fgObserver?.disconnect(); } catch {}
}

function log(level: string, message: string, data?: unknown) {
  if (!runtimeOk()) return stop();
  try {
    chrome.runtime.sendMessage({
      type: "FG_LOG", ts: Date.now(), level, source: "content", message, data, url: location.href,
    }, () => { try { void chrome.runtime.lastError; } catch {} });
  } catch { stop(); }
}

const FG_BLOCK_ID = "flareguard-risk-block";
function currentHost() { try { return location.hostname.toLowerCase(); } catch { return ""; } }
function trustedHosts(cb: (hosts: string[]) => void) {
  if (!runtimeOk()) return cb([]);
  try {
    chrome.storage.local.get("trustedHosts", (stored) => {
      try { void chrome.runtime.lastError; } catch {}
      const list = Array.isArray(stored.trustedHosts) ? stored.trustedHosts : [];
      cb(list.map((h) => String(h || "").toLowerCase()).filter(Boolean));
    });
  } catch { cb([]); }
}
function unblockPage(reason?: string) {
  document.getElementById(FG_BLOCK_ID)?.remove();
  document.getElementById(FG_BLOCK_ID + "-style")?.remove();
  try { document.documentElement.style.overflow = ""; } catch {}
  if (reason) log("info", `Risk block removed: ${reason}`);
}
function blockPage(result: any) {
  if (!document.documentElement) return;
  if (!document.getElementById(FG_BLOCK_ID + "-style")) {
    const style = document.createElement("style");
    style.id = FG_BLOCK_ID + "-style";
    style.textContent = `#${FG_BLOCK_ID}{all:initial;position:fixed;inset:0;z-index:2147483647;display:flex;align-items:center;justify-content:center;padding:24px;background:rgba(74,9,8,.94);font-family:system-ui,-apple-system,Segoe UI,Roboto,sans-serif}#${FG_BLOCK_ID} *{all:revert;box-sizing:border-box;font-family:inherit}#${FG_BLOCK_ID} .fg-card{max-width:560px;width:100%;background:#fff7f7;color:#0C2220;border-radius:18px;padding:22px;box-shadow:0 18px 60px rgba(0,0,0,.35)}#${FG_BLOCK_ID} h1{margin:0 0 8px;font-size:24px;color:#8f1716}#${FG_BLOCK_ID} p{margin:0 0 10px;line-height:1.45;font-size:15px}#${FG_BLOCK_ID} code{display:block;margin:10px 0;padding:10px 12px;border-radius:10px;background:#f5f5f5;word-break:break-all;font-size:13px}#${FG_BLOCK_ID} .fg-actions{display:flex;gap:10px;flex-wrap:wrap;margin-top:14px}#${FG_BLOCK_ID} button{appearance:none;border:0;border-radius:12px;padding:11px 14px;font:600 14px inherit;cursor:pointer}#${FG_BLOCK_ID} .fg-settings{background:#299F93;color:#fff}#${FG_BLOCK_ID} .fg-back{background:#e7eded;color:#0C2220}#${FG_BLOCK_ID} .fg-note{font-size:13px;color:#445;margin-top:12px}`;
    (document.head || document.documentElement).appendChild(style);
  }
  let block = document.getElementById(FG_BLOCK_ID);
  if (!block) {
    block = document.createElement("div");
    block.id = FG_BLOCK_ID;
    block.setAttribute("role", "dialog");
    block.setAttribute("aria-modal", "true");
    block.innerHTML = `<div class="fg-card"><h1>Flareguard blocked this page</h1><p>This page scored <strong>3/3</strong> risk and interaction is blocked to help prevent payment/credential theft.</p><code></code><p>To access it anyway, open <strong>Flareguard Settings</strong> and manually trust this site’s hostname. Only do this if you are sure it is legitimate.</p><div class="fg-actions"><button type="button" class="fg-settings">Open Flareguard popup → Settings</button><button type="button" class="fg-back">Go back</button></div><p class="fg-note">Settings path: extension popup → Settings → Trust current tab / add hostname, then refresh this page.</p></div>`;
    block.addEventListener("click", (e) => e.stopPropagation(), true);
    block.addEventListener("mousedown", (e) => e.stopPropagation(), true);
    (block.querySelector(".fg-settings") as HTMLButtonElement | null)?.addEventListener("click", () => log("warn", "Blocked page requested settings; open extension popup > Settings to trust hostname", { host: currentHost() }));
    (block.querySelector(".fg-back") as HTMLButtonElement | null)?.addEventListener("click", () => { try { if (history.length > 1) history.back(); else location.href = "about:blank"; } catch { location.href = "about:blank"; } });
    (document.body || document.documentElement).appendChild(block);
    log("warn", "Page interaction blocked due to 3/3 risk", { score: result?.score, verdict: result?.verdict, host: currentHost() });
  }
  const code = block.querySelector("code");
  if (code) code.textContent = location.href;
  try { document.documentElement.style.overflow = "hidden"; } catch {}
}
function applyRiskBlock(result: any) {
  if (!result || typeof result.score !== "number" || result.score < 3) return unblockPage(result ? "score below 3/3" : "no result");
  const host = currentHost();
  trustedHosts((trusted) => { if (host && trusted.includes(host)) return unblockPage(`hostname trusted: ${host}`); blockPage(result); });
}

const PROVIDER_HOSTS = ["js.stripe.com","paypal.com","checkout.paddle.com","paystack.co","flutterwave.com","klarna.com","mollie.com"];
const BUTTON_PATTERNS = [/\b(pay now|buy now|book now|subscribe|upgrade|checkout|place order|start (your )?free trial|make payment|proceed to pay|confirm order)\b/i,/\b(lipa sasa|nunua sasa|jiunge|nunua|lipa|kamilisha agizo|weka agizo|anza jaribio la bure)\b/i];
const PRICE_PATTERN = /(?:[$€£]|KES|KSh|USD|EUR)\s?\d{1,3}(?:[.,]\d{3})*(?:[.,]\d{2})?(?:\s?\/\s?(?:mo|month|yr|year))?/i;

function collectSignals(): Signal[] {
  const signals: Signal[] = [];
  const cardFields = document.querySelectorAll('input[autocomplete^="cc-"], input[name*="card" i], input[name*="cvc" i]');
  if (cardFields.length) signals.push({ name: "card-fields", weight: 5, detail: `${cardFields.length} fields` });
  const embeds = document.querySelectorAll<HTMLIFrameElement | HTMLScriptElement>("iframe[src], script[src]");
  for (const el of embeds) {
    try { const host = new URL(el.src).hostname; if (PROVIDER_HOSTS.some((h) => host.endsWith(h))) { signals.push({ name: "payment-provider", weight: 4, detail: host }); break; } } catch {}
  }
  if (/\/(checkout|pricing|subscribe|billing|payment|cart)/i.test(location.pathname)) signals.push({ name: "url-path", weight: 2, detail: location.pathname });
  const clickable = document.querySelectorAll("button, a[role='button'], input[type='submit']");
  for (const el of clickable) {
    const text = (el.textContent || (el as HTMLInputElement).value || "").trim();
    if (text.length < 60 && BUTTON_PATTERNS.some((p) => p.test(text))) { signals.push({ name: "payment-button", weight: 2, detail: text }); break; }
  }
  const bodyText = document.body?.innerText.slice(0, 50_000) ?? "";
  if (PRICE_PATTERN.test(bodyText)) signals.push({ name: "price-text", weight: 1 });
  return signals;
}

function evaluate() {
  if (!runtimeOk()) return stop();
  try {
    const signals = collectSignals();
    const rawScore = signals.reduce((sum, s) => sum + s.weight, 0);
    const verdict = rawScore >= 5 ? "likely" : rawScore >= 3 ? "possible" : "none";
    const score = verdict === "likely" ? 3 : verdict === "possible" ? 2 : 1;
    const hasPayment = signals.length > 0;
    const result = { type: "SCAN_RESULT" as const, url: location.href, score, verdict, signals };
    log(hasPayment ? "warn" : "info", `Content check ok: hasPayment=${hasPayment}`, { ok: true, hasPayment, score, verdict, rawScore, signals, sample: { url: location.href, title: document.title || "", verdict, hasPayment, signalNames: signals.map((s) => s.name) } });
    applyRiskBlock(result);
    if (!runtimeOk()) return stop();
    chrome.runtime.sendMessage(result, () => { try { void chrome.runtime.lastError; } catch {} });
  } catch (error) { if (runtimeOk()) log("error", "Content check failed", { ok: false, error: String(error) }); }
}

if (runtimeOk()) {
  chrome.runtime.onMessage.addListener((msg, _sender, sendResponse) => {
    if (!runtimeOk()) return;
    if (msg?.type === "SCAN_REQUEST") { log("info", "Manual scan requested"); evaluate(); try { sendResponse({ ok: runtimeOk() }); } catch {} }
  });
  try { chrome.storage.onChanged.addListener((changes, area) => { if (area === "local" && changes.trustedHosts && runtimeOk()) evaluate(); }); } catch {}
}

let timer: number | undefined;
if (runtimeOk()) {
  fgObserver = new MutationObserver(() => { if (!runtimeOk()) return stop(); clearTimeout(timer); timer = window.setTimeout(evaluate, 800); });
  fgObserver.observe(document.documentElement, { childList: true, subtree: true });
  log("info", "Content script loaded");
  evaluate();
}
