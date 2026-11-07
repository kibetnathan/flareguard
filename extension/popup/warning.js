"use strict";

const metaEl = document.getElementById("warning-meta");
const urlEl = document.getElementById("warning-url");
const signalsEl = document.getElementById("warning-signals");
const correctUrlEl = document.getElementById("correct-url");
const navigateBtn = document.getElementById("navigate");
const reportBtn = document.getElementById("report");
const saveBtn = document.getElementById("save-url");
const actionStatus = document.getElementById("action-status");

function setStatus(text, tone) {
  actionStatus.className = tone ? `status ${tone}` : "status";
  actionStatus.textContent = text || "";
}

function hostKey(url) {
  try { return new URL(url).host.toLowerCase(); } catch (_) { return ""; }
}

async function getActiveTab() {
  const [tab] = await chrome.tabs.query({ active: true, currentWindow: true });
  return tab;
}

async function loadResult() {
  const tab = await getActiveTab();
  if (!tab || !tab.id) {
    metaEl.textContent = "No active tab.";
    return { tab: null, result: null };
  }
  const key = `tab:${tab.id}`;
  const stored = await chrome.storage.session.get(key);
  const result = stored[key] || null;
  if (!result) {
    metaEl.textContent = "No scan result for this tab. Go back and scan.";
    return { tab, result: null };
  }
  metaEl.textContent = `Risk score: ${result.score} / 3 (${result.verdict || "unknown"})`;
  urlEl.textContent = result.url || tab.url || "";
  signalsEl.replaceChildren();
  (result.signals || []).forEach((s) => {
    const li = document.createElement("li");
    li.textContent = s.detail ? `${s.name}: ${s.detail}` : s.name;
    signalsEl.append(li);
  });
  const correct = result.correctUrl || (await getSavedCorrectUrl(result.url || tab.url || ""));
  if (correct) correctUrlEl.value = correct;
  return { tab, result };
}

async function getSavedCorrectUrl(pageUrl) {
  const key = hostKey(pageUrl);
  if (!key) return "";
  const stored = await chrome.storage.local.get("correctUrls");
  const map = stored.correctUrls || {};
  return map[key] || "";
}

async function saveCorrectUrl(pageUrl, correctUrl) {
  const key = hostKey(pageUrl);
  if (!key) throw new Error("Could not determine site.");
  let url;
  try { url = new URL(correctUrl).href; } catch (_) { throw new Error("Enter a valid URL (https://...)."); }
  const stored = await chrome.storage.local.get("correctUrls");
  const map = stored.correctUrls || {};
  map[key] = url;
  await chrome.storage.local.set({ correctUrls: map });
  return url;
}

async function sendReport(payload) {
  try {
    chrome.runtime.sendMessage({ type: "FG_LOG", ts: Date.now(), level: "warn", source: "popup", message: "User reported site", data: payload });
  } catch (_) {}
  const stored = await chrome.storage.sync.get("apiEndpoint");
  const endpoint = stored.apiEndpoint;
  if (!endpoint) return { sent: false, reason: "no-endpoint" };
  const res = await fetch(endpoint, {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify({ type: "report", ...payload }),
  });
  if (!res.ok) throw new Error(`Report failed (${res.status})`);
  return { sent: true };
}

let ctx = { tab: null, result: null };

navigateBtn.addEventListener("click", async () => {
  const raw = correctUrlEl.value.trim();
  if (!raw) {
    setStatus("Enter the correct URL first, or save one for this site.", "flagged");
    return;
  }
  let url;
  try { url = new URL(raw).href; } catch (_) {
    setStatus("Enter a valid URL (https://...).", "flagged");
    return;
  }
  try {
    if (ctx.tab && ctx.tab.id) await chrome.tabs.update(ctx.tab.id, { url });
    else await chrome.tabs.create({ url });
    window.close();
  } catch (e) {
    setStatus(`Could not navigate: ${String(e)}`, "flagged");
  }
});

reportBtn.addEventListener("click", async () => {
  reportBtn.disabled = true;
  setStatus("Sending report...", "");
  try {
    const payload = {
      reportedUrl: (ctx.result && ctx.result.url) || (ctx.tab && ctx.tab.url) || "",
      correctUrl: correctUrlEl.value.trim() || null,
      score: ctx.result && ctx.result.score,
      verdict: ctx.result && ctx.result.verdict,
      signals: ctx.result && ctx.result.signals || [],
      reportedAt: new Date().toISOString(),
    };
    const out = await sendReport(payload);
    setStatus(out.sent ? "Report sent." : "Report saved locally (no API endpoint configured).", "clean");
  } catch (e) {
    setStatus(`Report failed: ${String(e)}`, "flagged");
  } finally {
    reportBtn.disabled = false;
  }
});

saveBtn.addEventListener("click", async () => {
  try {
    const pageUrl = (ctx.result && ctx.result.url) || (ctx.tab && ctx.tab.url) || "";
    const url = await saveCorrectUrl(pageUrl, correctUrlEl.value.trim());
    correctUrlEl.value = url;
    setStatus("Correct URL saved for this site.", "clean");
  } catch (e) {
    setStatus(String(e.message || e), "flagged");
  }
});

loadResult().then((c) => { ctx = c; });
