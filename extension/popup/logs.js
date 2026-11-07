"use strict";

const metaEl = document.getElementById("meta");
const logsEl = document.getElementById("logs");
const testBtn = document.getElementById("test");
const refreshBtn = document.getElementById("refresh");
const copyBtn = document.getElementById("copy");
const clearBtn = document.getElementById("clear");

function fmtTime(ts) {
  try { return new Date(ts).toLocaleString(); } catch (_) { return String(ts || ""); }
}

function render(logs, error) {
  logsEl.replaceChildren();
  const items = Array.isArray(logs) ? [...logs].reverse() : [];
  metaEl.textContent = error
    ? `Log read error: ${error}`
    : `${items.length} log entr${items.length === 1 ? "y" : "ies"} (newest first, session only)`;
  if (!items.length) {
    const empty = document.createElement("div");
    empty.className = "empty";
    empty.textContent = error
      ? "Could not read chrome.storage.session. Reload the extension and check permissions."
      : "No logs yet. Reload the extension, refresh a normal https page, then press Test/Refresh.";
    logsEl.append(empty);
    return;
  }
  items.forEach((log) => {
    const entry = document.createElement("article");
    entry.className = `entry ${log.level || "info"}`;
    const head = document.createElement("div");
    head.className = "head";
    const level = document.createElement("span");
    level.className = "level";
    level.textContent = log.level || "info";
    const source = document.createElement("span");
    source.className = "source";
    source.textContent = log.source || "unknown";
    const time = document.createElement("span");
    time.className = "time";
    time.textContent = fmtTime(log.ts);
    head.append(level, source, time);
    const message = document.createElement("div");
    message.textContent = log.message || "";
    entry.append(head, message);
    if (log.url) {
      const url = document.createElement("div");
      url.className = "url";
      url.textContent = log.url;
      entry.append(url);
    }
    if (log.data !== undefined) {
      const pre = document.createElement("pre");
      try { pre.textContent = JSON.stringify(log.data, null, 2); }
      catch (_) { pre.textContent = String(log.data); }
      entry.append(pre);
    }
    logsEl.append(entry);
  });
}

async function loadLogs() {
  try {
    const stored = await chrome.storage.session.get("logs");
    const err = chrome.runtime.lastError && chrome.runtime.lastError.message;
    render(stored.logs || [], err || "");
    return stored.logs || [];
  } catch (e) {
    render([], String(e));
    return [];
  }
}

testBtn.addEventListener("click", async () => {
  try {
    const response = await chrome.runtime.sendMessage({ type: "FG_TEST_LOG" });
    await loadLogs();
    if (response && response.ok) metaEl.textContent = `${(await chrome.storage.session.get("logs")).logs?.length || 0} log entries (test log sent)`;
  } catch (e) {
    render([], String(e));
  }
});

refreshBtn.addEventListener("click", () => { loadLogs(); });

copyBtn.addEventListener("click", async () => {
  const logs = await loadLogs();
  await navigator.clipboard.writeText(JSON.stringify(logs, null, 2));
  metaEl.textContent = `${logs.length} log entr${logs.length === 1 ? "y" : "ies"} copied to clipboard`;
});

clearBtn.addEventListener("click", async () => {
  try {
    await chrome.storage.session.set({ logs: [] });
  } catch (e) {
    render([], String(e));
    return;
  }
  await loadLogs();
});

try {
  chrome.storage.session.onChanged.addListener((changes) => {
    if (changes.logs) render(changes.logs.newValue || []);
  });
} catch (e) {
  metaEl.textContent = `Storage listener error: ${String(e)}`;
}

loadLogs();
