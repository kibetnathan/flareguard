"use strict";
let fgObserver;
let fgLastTriggerKey = "";
let fgAnalyzeTimer;
const FG_HARDCODED_BLOCKED_HOSTS = ["easycoachbuskenya.co.ke"];

function fgRuntimeOk() {
    try { return !!(chrome && chrome.runtime && chrome.runtime.id); }
    catch (_a) { return false; }
}
function fgStop() {
    try { clearTimeout(fgAnalyzeTimer); } catch (_a) { }
    try { if (fgObserver) fgObserver.disconnect(); } catch (_a) { }
}
function fgLog(level, message, data) {
    if (!fgRuntimeOk()) return fgStop();
    try {
        chrome.runtime.sendMessage({
            type: "FG_LOG",
            ts: Date.now(),
            level: level,
            source: "content",
            message: message,
            data: data,
            url: location.href,
        }, () => {
            try { void chrome.runtime.lastError; } catch (_a) { }
        });
    }
    catch (_a) { fgStop(); }
}

const FG_BLOCK_ID = "flareguard-risk-block";
function fgCurrentHost() {
    try { return location.hostname.toLowerCase(); } catch (_a) { return ""; }
}
function fgIsHardcodedBlockedHost() {
    const host = fgCurrentHost();
    return FG_HARDCODED_BLOCKED_HOSTS.some((blocked) => host === blocked || host.endsWith("." + blocked));
}
function fgHardcodedBlockResult() {
    return {
        type: "SCAN_RESULT",
        source: "hardcoded-blocklist",
        url: location.href,
        score: 3,
        verdict: "likely",
        signals: [{ name: "hardcoded-blocklist", weight: 999, detail: `Host ${fgCurrentHost()} is on the hardcoded blocklist` }],
        apiAssessment: { verdict: "confirmed", confidence: "high", score: 100 },
    };
}
function fgApplyHardcodedBlock(reason) {
    if (!fgIsHardcodedBlockedHost()) return false;
    const result = fgHardcodedBlockResult();
    fgLog("warn", `Hardcoded blocklist matched: ${fgCurrentHost()}`, { ok: true, reason: reason, url: location.href });
    fgApplyRiskBlock(result);
    if (fgRuntimeOk()) {
        chrome.runtime.sendMessage(result, () => { try { void chrome.runtime.lastError; } catch (_a) { } });
    }
    return true;
}
function fgTrustedHosts(cb) {
    if (!fgRuntimeOk()) return cb([]);
    try {
        chrome.storage.local.get("trustedHosts", (stored) => {
            try { void chrome.runtime.lastError; } catch (_a) { }
            const list = stored && Array.isArray(stored.trustedHosts) ? stored.trustedHosts : [];
            cb(list.map((h) => String(h || "").toLowerCase()).filter(Boolean));
        });
    }
    catch (_a) { cb([]); }
}
function fgUnblockPage(reason) {
    const existing = document.getElementById(FG_BLOCK_ID);
    if (existing) existing.remove();
    const style = document.getElementById(FG_BLOCK_ID + "-style");
    if (style) style.remove();
    try { document.documentElement.style.overflow = ""; } catch (_a) { }
    if (reason) fgLog("info", `Risk block removed: ${reason}`);
}
function fgBlockPage(result) {
    if (!document.documentElement) return;
    let style = document.getElementById(FG_BLOCK_ID + "-style");
    if (!style) {
        style = document.createElement("style");
        style.id = FG_BLOCK_ID + "-style";
        style.textContent = `#${FG_BLOCK_ID}{all:initial;position:fixed;inset:0;z-index:2147483647;display:flex;align-items:center;justify-content:center;padding:24px;background:rgba(74,9,8,.94);font-family:system-ui,-apple-system,Segoe UI,Roboto,sans-serif}#${FG_BLOCK_ID} *{all:revert;box-sizing:border-box;font-family:inherit}#${FG_BLOCK_ID} .fg-card{max-width:560px;width:100%;background:#fff7f7;color:#0C2220;border-radius:18px;padding:22px;box-shadow:0 18px 60px rgba(0,0,0,.35)}#${FG_BLOCK_ID} h1{margin:0 0 8px;font-size:24px;color:#8f1716}#${FG_BLOCK_ID} p{margin:0 0 10px;line-height:1.45;font-size:15px}#${FG_BLOCK_ID} code{display:block;margin:10px 0;padding:10px 12px;border-radius:10px;background:#f5f5f5;word-break:break-all;font-size:13px}#${FG_BLOCK_ID} .fg-actions{display:flex;gap:10px;flex-wrap:wrap;margin-top:14px}#${FG_BLOCK_ID} a,#${FG_BLOCK_ID} button{appearance:none;border:0;border-radius:12px;padding:11px 14px;font:600 14px inherit;cursor:pointer;text-decoration:none}#${FG_BLOCK_ID} .fg-settings{background:#299F93;color:#fff}#${FG_BLOCK_ID} .fg-back{background:#e7eded;color:#0C2220}#${FG_BLOCK_ID} .fg-note{font-size:13px;color:#445;margin-top:12px}`;
        (document.head || document.documentElement).appendChild(style);
    }
    let block = document.getElementById(FG_BLOCK_ID);
    if (!block) {
        block = document.createElement("div");
        block.id = FG_BLOCK_ID;
        block.setAttribute("role", "dialog");
        block.setAttribute("aria-modal", "true");
        block.setAttribute("aria-label", "Flareguard high risk warning");
        block.innerHTML = `<div class="fg-card"><h1>Flareguard blocked this page</h1><p>API analysis marked this page as high risk and interaction is blocked to help prevent payment/credential theft.</p><code></code><p>To access it anyway, open <strong>Flareguard Settings</strong> and manually trust this site’s hostname. Only do this if you are sure it is legitimate.</p><div class="fg-actions"><button type="button" class="fg-settings">Open extension popup for Settings</button><button type="button" class="fg-back">Go back</button></div><p class="fg-note">Settings path: extension popup → Settings → Trust current tab / add hostname, then refresh this page.</p></div>`;
        block.addEventListener("click", (e) => { e.stopPropagation(); }, true);
        block.addEventListener("mousedown", (e) => { e.stopPropagation(); }, true);
        block.addEventListener("keydown", (e) => { e.stopPropagation(); }, true);
        const code = block.querySelector("code");
        if (code) code.textContent = location.href;
        const settingsBtn = block.querySelector(".fg-settings");
        if (settingsBtn) settingsBtn.addEventListener("click", () => {
            fgLog("warn", "Blocked page requested settings; open extension popup > Settings to trust hostname", { host: fgCurrentHost() });
            try { settingsBtn.textContent = "Open Flareguard popup → Settings"; } catch (_a) { }
        });
        const backBtn = block.querySelector(".fg-back");
        if (backBtn) backBtn.addEventListener("click", () => {
            try { if (history.length > 1) history.back(); else location.href = "about:blank"; } catch (_a) { location.href = "about:blank"; }
        });
        (document.body || document.documentElement).appendChild(block);
        fgLog("warn", "Page interaction blocked due to high-risk result", { score: result && result.score, verdict: result && result.verdict, host: fgCurrentHost(), source: result && result.source });
    } else {
        const code = block.querySelector("code");
        if (code) code.textContent = location.href;
    }
    try { document.documentElement.style.overflow = "hidden"; } catch (_a) { }
}
function fgApplyRiskBlock(result) {
    if (!result || typeof result.score !== "number" || result.score < 3) {
        fgUnblockPage(result ? "API score below 3/3" : "no API result");
        return;
    }
    const host = fgCurrentHost();
    fgTrustedHosts((trusted) => {
        if (host && trusted.indexOf(host) !== -1) {
            fgUnblockPage(`hostname trusted: ${host}`);
            return;
        }
        fgBlockPage(result);
    });
}

const PROVIDER_HOSTS = [
    "js.stripe.com",
    "paypal.com",
    "checkout.paddle.com",
    "paystack.co",
    "flutterwave.com",
    "klarna.com",
    "mollie.com",
];
const BUTTON_PATTERNS = [
    /\b(pay now|buy now|book now|subscribe|upgrade|checkout|place order|start (your )?free trial|make payment|proceed to pay|confirm order)\b/i,
    /\b(lipa sasa|nunua sasa|jiunge|nunua|lipa|kamilisha agizo|weka agizo|anza jaribio la bure)\b/i,
];
const PRICE_PATTERN = /(?:[$€£]|KES|KSh|USD|EUR)\s?\d{1,3}(?:[.,]\d{3})*(?:[.,]\d{2})?(?:\s?\/\s?(?:mo|month|yr|year))?/i;

function detectBuyingSignals() {
    var _a, _b;
    const signals = [];
    const cardFields = document.querySelectorAll('input[autocomplete^="cc-"], input[name*="card" i], input[name*="cvc" i]');
    if (cardFields.length) {
        signals.push({ name: "card-fields", weight: 5, detail: `${cardFields.length} fields` });
    }
    const embeds = document.querySelectorAll("iframe[src], script[src]");
    for (const el of embeds) {
        try {
            const host = new URL(el.src).hostname;
            if (PROVIDER_HOSTS.some((h) => host.endsWith(h))) {
                signals.push({ name: "payment-provider", weight: 4, detail: host });
                break;
            }
        }
        catch (_c) { }
    }
    if (/\/(checkout|pricing|subscribe|billing|payment|cart)/i.test(location.pathname)) {
        signals.push({ name: "url-path", weight: 2, detail: location.pathname });
    }
    const clickable = document.querySelectorAll("button, a[role='button'], input[type='submit']");
    for (const el of clickable) {
        const text = (el.textContent || el.value || "").trim();
        if (text.length < 60 && BUTTON_PATTERNS.some((p) => p.test(text))) {
            signals.push({ name: "payment-button", weight: 2, detail: text });
            break;
        }
    }
    const bodyText = (_b = (_a = document.body) === null || _a === void 0 ? void 0 : _a.innerText.slice(0, 50000)) !== null && _b !== void 0 ? _b : "";
    if (PRICE_PATTERN.test(bodyText)) {
        signals.push({ name: "price-text", weight: 1 });
    }
    return signals;
}

function requestApiCheck(reason, force) {
    if (!fgRuntimeOk()) return fgStop();
    if (fgApplyHardcodedBlock(reason || "trigger")) return;
    const buyingSignals = detectBuyingSignals();
    const needsCheck = buyingSignals.length > 0;
    const triggerKey = buyingSignals.map((s) => s.name).sort().join("|") + "|" + location.href;
    if (!force && !needsCheck) {
        fgUnblockPage("no buying/payment trigger");
        fgLog("info", "Buying trigger check: no payment/buying signals; API check skipped", {
            ok: true,
            needsCheck: false,
            reason: reason,
            sample: { url: location.href, title: document.title || "", triggerCount: 0 },
        });
        return;
    }
    if (!force && triggerKey === fgLastTriggerKey) return;
    fgLastTriggerKey = triggerKey;
    fgLog(needsCheck ? "warn" : "info", force ? "Manual scan requested; triggering collector+API check" : "Buying/payment trigger detected; triggering collector+API check", {
        ok: true,
        needsCheck: true,
        force: !!force,
        reason: reason,
        triggerSignals: buyingSignals,
        sample: { url: location.href, title: document.title || "", signalNames: buyingSignals.map((s) => s.name) },
    });
    chrome.runtime.sendMessage({
        type: "FG_TRIGGER_CHECK",
        url: location.href,
        triggerSignals: buyingSignals,
        force: !!force,
        reason: reason || "trigger",
    }, (resp) => {
        try { void chrome.runtime.lastError; } catch (_a) { }
        if (resp && resp.error) fgLog("error", "Background did not accept trigger", { error: resp.error });
    });
}

if (fgRuntimeOk()) {
    chrome.runtime.onMessage.addListener((msg, _sender, sendResponse) => {
        if (!fgRuntimeOk()) return;
        if (msg && msg.type === "SCAN_REQUEST") {
            fgLastTriggerKey = "";
            if (fgApplyHardcodedBlock("manual-scan")) {
                try { sendResponse({ ok: fgRuntimeOk() }); } catch (_a) { }
                return;
            }
            requestApiCheck("manual-scan", true);
            try { sendResponse({ ok: fgRuntimeOk() }); } catch (_a) { }
            return;
        }
        if (msg && msg.type === "FG_APPLY_RESULT") {
            if (fgIsHardcodedBlockedHost() && !(msg.result && msg.result.source === "hardcoded-blocklist")) {
                fgApplyHardcodedBlock("api-result-ignored");
            } else {
                fgApplyRiskBlock(msg.result);
            }
            try { sendResponse({ ok: true }); } catch (_a) { }
            return;
        }
        if (msg && msg.type === "FG_UNBLOCK") {
            if (fgIsHardcodedBlockedHost()) {
                fgApplyHardcodedBlock("unblock-ignored");
            } else {
                fgUnblockPage(msg.reason || "manual unblock");
            }
            try { sendResponse({ ok: true }); } catch (_a) { }
        }
    });
    try {
        chrome.storage.onChanged.addListener((changes, area) => {
            if (area === "local" && changes.trustedHosts && fgRuntimeOk()) {
                if (fgApplyHardcodedBlock("trusted-hosts-changed")) return;
            }
        });
    } catch (_a) { }
}
let timer;
if (fgRuntimeOk()) {
    fgObserver = new MutationObserver(() => {
        if (!fgRuntimeOk()) return fgStop();
        clearTimeout(fgAnalyzeTimer);
        fgAnalyzeTimer = window.setTimeout(() => requestApiCheck("dom-mutation", false), 1200);
    });
    fgObserver.observe(document.documentElement, { childList: true, subtree: true });
    fgLog("info", "Content script loaded (trigger mode: buying check -> collector -> API)");
    if (!fgApplyHardcodedBlock("initial-load")) requestApiCheck("initial-load", false);
}
