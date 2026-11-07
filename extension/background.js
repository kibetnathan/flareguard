"use strict";
// background.ts
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

appendLog({ ts: Date.now(), level: "info", source: "background", message: "Service worker started", url: "" });

chrome.runtime.onMessage.addListener((msg, sender, sendResponse) => {
    var _a, _b;
    if (msg && msg.type === "FG_TEST_LOG") {
        appendLog({
            ts: Date.now(),
            level: "info",
            source: "background",
            message: "Test log from popup",
            data: { ok: true },
            url: "",
        });
        try { sendResponse({ ok: true }); } catch (_c) { }
        return;
    }
    if (msg && msg.type === "FG_LOG") {
        appendLog({
            ts: typeof msg.ts === "number" ? msg.ts : Date.now(),
            level: msg.level || "info",
            source: msg.source || "unknown",
            message: msg.message || "",
            data: msg.data,
            url: msg.url || ((_b = sender.tab) === null || _b === void 0 ? void 0 : _b.url) || sender.url || "",
            tabId: (_a = sender.tab) === null || _a === void 0 ? void 0 : _a.id,
            frameId: sender.frameId,
        });
        return;
    }
    if (msg.type !== "SCAN_RESULT" || sender.frameId !== 0 || !((_a = sender.tab) === null || _a === void 0 ? void 0 : _a.id))
        return;
    const tabId = sender.tab.id;
    const key = `tab:${tabId}`;
    appendLog({
        ts: Date.now(),
        level: msg.verdict === "likely" ? "warn" : "info",
        source: "background",
        message: `Scan result: ${msg.verdict} (${msg.score}/3)`,
        data: { url: msg.url, verdict: msg.verdict, score: msg.score, signals: msg.signals },
        url: msg.url,
        tabId,
        frameId: sender.frameId,
    });
    chrome.storage.session.get(key, (prev) => {
        var _a;
        const wasFlagged = ((_a = prev[key]) === null || _a === void 0 ? void 0 : _a.verdict) && prev[key].verdict !== "none";
        const isFlagged = msg.verdict !== "none";
        if (isFlagged && !wasFlagged) {
            chrome.storage.local.get("threatsStopped", (stored) => {
                chrome.storage.local.set({
                    threatsStopped: (stored.threatsStopped || 0) + 1,
                });
            });
        }
        chrome.storage.session.set({ [key]: msg });
    });
    chrome.action.setBadgeText({
        tabId,
        text: msg.verdict === "likely" ? "$" : msg.verdict === "possible" ? "?" : "",
    });
    chrome.action.setBadgeBackgroundColor({
        tabId,
        color: msg.verdict === "likely" ? "#d33" : "#e90",
    });
});
