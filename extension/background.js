"use strict";
const MAX_LOGS = 500;

function appendLog(entry) {
    try {
        chrome.storage.session.get("logs", (stored) => {
            const logs = stored && Array.isArray(stored.logs) ? stored.logs : [];
            logs.push(entry);
            if (logs.length > MAX_LOGS) logs.splice(0, logs.length - MAX_LOGS);
            chrome.storage.session.set({ logs }, () => {
                try { void chrome.runtime.lastError; } catch (_a) { }
            });
        });
    }
    catch (_a) { }
}

function log(level, source, message, data, sender) {
    appendLog({
        ts: Date.now(),
        level: level || "info",
        source: source || "background",
        message: message || "",
        data: data,
        url: (data && data.url) || (sender && sender.tab && sender.tab.url) || (sender && sender.url) || "",
        tabId: sender && sender.tab ? sender.tab.id : undefined,
        frameId: sender ? sender.frameId : undefined,
    });
}

async function getApiEndpoint() {
    const stored = await chrome.storage.sync.get("apiEndpoint");
    const raw = (stored && stored.apiEndpoint ? String(stored.apiEndpoint) : "").trim();
    return raw || "http://localhost:8000/api/v1/analyze";
}

function verdictToUi(apiVerdict) {
    if (apiVerdict === "confirmed" || apiVerdict === "high") return { score: 3, verdict: "likely" };
    if (apiVerdict === "medium") return { score: 2, verdict: "possible" };
    return { score: 1, verdict: "none" };
}

function apiToScanResult(api, pageUrl, collectorData) {
    const ui = verdictToUi(api && api.assessment && api.assessment.verdict);
    const signals = Array.isArray(api && api.signals) ? api.signals.map((s) => ({
        name: s.code || "signal",
        weight: typeof s.score === "number" ? s.score : 1,
        detail: s.message || s.category || "",
    })) : [];
    return {
        type: "SCAN_RESULT",
        source: "api",
        url: pageUrl,
        score: ui.score,
        verdict: ui.verdict,
        apiAssessment: api && api.assessment ? api.assessment : null,
        signals,
        providerResults: Array.isArray(api && api.provider_results) ? api.provider_results : [],
        recommendations: Array.isArray(api && api.recommendations) ? api.recommendations : [],
        collectorSample: collectorData ? {
            hasFavicon: collectorData.hasFavicon,
            navbarLogoExtension: collectorData.navbarLogoExtension,
            brokenLinksCount: Array.isArray(collectorData.brokenLinks) ? collectorData.brokenLinks.length : 0,
            triggerCount: Array.isArray(collectorData.triggerSignals) ? collectorData.triggerSignals.length : 0,
        } : null,
        analyzedAt: api && api.analyzed_at ? api.analyzed_at : new Date().toISOString(),
    };
}

async function storeAndApplyResult(tabId, result, sender) {
    const key = `tab:${tabId}`;
    log(result.score >= 3 ? "warn" : "info", "background", `API decision: ${result.verdict} (${result.score}/3)`, {
        url: result.url,
        verdict: result.verdict,
        score: result.score,
        apiAssessment: result.apiAssessment,
        collectorSample: result.collectorSample,
    }, sender);

    const prevWrap = await chrome.storage.session.get(key);
    const prev = prevWrap[key];
    const wasFlagged = prev && prev.verdict && prev.verdict !== "none";
    const isFlagged = result.verdict !== "none";
    if (isFlagged && !wasFlagged) {
        const stored = await chrome.storage.local.get("threatsStopped");
        await chrome.storage.local.set({ threatsStopped: (stored.threatsStopped || 0) + 1 });
    }
    await chrome.storage.session.set({ [key]: result });

    try {
        await chrome.action.setBadgeText({ tabId, text: result.verdict === "likely" ? "$" : result.verdict === "possible" ? "?" : "" });
        await chrome.action.setBadgeBackgroundColor({ tabId, color: result.verdict === "likely" ? "#d33" : "#e90" });
    } catch (_a) { }

    try {
        await chrome.tabs.sendMessage(tabId, { type: "FG_APPLY_RESULT", result });
    } catch (_a) {
        log("warn", "background", "Could not deliver API result to tab", { tabId }, sender);
    }
}

async function runCheck(msg, sender) {
    const tabId = sender && sender.tab ? sender.tab.id : null;
    if (!tabId || sender.frameId !== 0) {
        return { ok: false, error: "No top-frame tab context" };
    }
    const pageUrl = msg && msg.url ? msg.url : sender.tab.url;
    log("info", "background", "Trigger received; collecting page data", { reason: msg.reason, force: !!msg.force, url: pageUrl }, sender);

    let collectorResp;
    try {
        collectorResp = await chrome.tabs.sendMessage(tabId, { type: "FG_COLLECT", triggerSignals: msg.triggerSignals || [], reason: msg.reason || "" });
    } catch (e) {
        log("error", "background", "Collector request failed", { error: String(e), url: pageUrl }, sender);
        return { ok: false, error: "Collector not available on page" };
    }
    if (!collectorResp || !collectorResp.ok || !collectorResp.data) {
        log("error", "background", "Collector returned no data", { response: collectorResp, url: pageUrl }, sender);
        return { ok: false, error: "Collector returned no data" };
    }

    const endpoint = await getApiEndpoint();
    log("info", "background", "Sending collected data context and URL to API", { endpoint, url: pageUrl }, sender);
    try {
        const res = await fetch(endpoint, {
            method: "POST",
            headers: { "Content-Type": "application/json" },
            body: JSON.stringify({ url: pageUrl }),
        });
        const text = await res.text();
        let api = null;
        try { api = text ? JSON.parse(text) : null; } catch (_a) {}
        if (!res.ok || !api) {
            log("error", "background", "API analysis failed", { status: res.status, body: text.slice(0, 500), url: pageUrl }, sender);
            return { ok: false, error: `API error ${res.status}` };
        }
        const result = apiToScanResult(api, pageUrl, collectorResp.data);
        await storeAndApplyResult(tabId, result, sender);
        return { ok: true, result };
    } catch (e) {
        log("error", "background", "API request failed", { error: String(e), endpoint, url: pageUrl }, sender);
        return { ok: false, error: String(e) };
    }
}

log("info", "background", "Service worker started", {});

chrome.runtime.onMessage.addListener((msg, sender, sendResponse) => {
    if (msg && msg.type === "FG_TEST_LOG") {
        log("info", "background", "Test log from popup", { ok: true }, sender);
        try { sendResponse({ ok: true }); } catch (_a) { }
        return;
    }
    if (msg && msg.type === "FG_LOG") {
        appendLog({
            ts: typeof msg.ts === "number" ? msg.ts : Date.now(),
            level: msg.level || "info",
            source: msg.source || "unknown",
            message: msg.message || "",
            data: msg.data,
            url: msg.url || (sender && sender.tab && sender.tab.url) || (sender && sender.url) || "",
            tabId: sender && sender.tab ? sender.tab.id : undefined,
            frameId: sender ? sender.frameId : undefined,
        });
        return;
    }
    if (msg && msg.type === "FG_TRIGGER_CHECK") {
        runCheck(msg, sender).then((r) => {
            try { sendResponse(r); } catch (_a) { }
        });
        return true;
    }
    if (msg && msg.type === "SCAN_RESULT" && msg.manualTest && sender && sender.tab && sender.tab.id && sender.frameId === 0) {
        storeAndApplyResult(sender.tab.id, msg, sender).then(() => {
            try { sendResponse({ ok: true }); } catch (_a) { }
        });
        return true;
    }
});
