"use strict";

const countEl = document.getElementById("count");
const scanButton = document.getElementById("scan");
const statusEl = document.getElementById("status");
const helpLink = document.getElementById("help");

async function getActiveTab() {
  const [tab] = await chrome.tabs.query({ active: true, currentWindow: true });
  return tab;
}

const verdictText = {
  likely: "Likely fraudulent (API).",
  possible: "Possible risk (API).",
  none: "No/low risk reported by API.",
};

async function loadThreatCount() {
  const stored = await chrome.storage.local.get("threatsStopped");
  countEl.textContent = String(stored.threatsStopped || 0);
}

function renderStatus(message, tone) {
  statusEl.className = tone ? `status ${tone}` : "status";
  statusEl.replaceChildren();
  if (typeof message === "string") {
    statusEl.textContent = message;
    return;
  }
  statusEl.append(message);
}

function renderResult(result) {
  if (!result) {
    renderStatus("Open a webpage. Buying/payment signals trigger collection and API analysis.", "");
    return;
  }

  if (result.score > 2 && result.source === "api") {
    location.replace("warning.html");
    return;
  }

  const tone = result.verdict === "possible" ? "flagged" : result.verdict === "likely" ? "flagged" : "clean";
  const root = document.createDocumentFragment();

  const title = document.createElement("strong");
  title.textContent = verdictText[result.verdict] || verdictText.none;
  root.append(title);

  const meta = document.createElement("div");
  meta.textContent = `API risk level ${result.score} / 3` + (result.source === "api" ? "" : " (local/test)");
  root.append(meta);

  if (result.apiAssessment) {
    const a = document.createElement("div");
    a.textContent = `API verdict: ${result.apiAssessment.verdict}, confidence: ${result.apiAssessment.confidence}, score: ${result.apiAssessment.score}`;
    root.append(a);
  }

  if (result.signals && result.signals.length) {
    const list = document.createElement("ul");
    result.signals.slice(0, 8).forEach((signal) => {
      const item = document.createElement("li");
      item.textContent = signal.detail ? `${signal.name}: ${signal.detail}` : signal.name;
      list.append(item);
    });
    root.append(list);
  }

  renderStatus(root, tone);
}

async function loadCurrentResult() {
  const tab = await getActiveTab();
  if (!tab || !tab.id) {
    renderStatus("No active tab found.", "");
    return;
  }
  const key = `tab:${tab.id}`;
  const stored = await chrome.storage.session.get(key);
  renderResult(stored[key]);
  chrome.storage.session.onChanged.addListener((changes) => {
    if (changes[key]) renderResult(changes[key].newValue);
  });
  chrome.storage.local.onChanged.addListener((changes) => {
    if (changes.threatsStopped) countEl.textContent = String(changes.threatsStopped.newValue || 0);
  });
}

async function runScan() {
  const tab = await getActiveTab();
  if (!tab || !tab.id || !tab.url || !/^https?:/i.test(tab.url)) {
    renderStatus("Manual scan works on regular webpages.", "");
    return;
  }
  scanButton.disabled = true;
  renderStatus("Requesting collector + API analysis...", "");
  try {
    const resp = await chrome.tabs.sendMessage(tab.id, { type: "SCAN_REQUEST" });
    if (resp && resp.error) renderStatus(resp.error, "flagged");
    window.setTimeout(async () => {
      const key = `tab:${tab.id}`;
      const stored = await chrome.storage.session.get(key);
      renderResult(stored[key] || null);
      scanButton.disabled = false;
    }, 1500);
  } catch (_) {
    renderStatus("Reload the webpage, then try again.", "flagged");
    scanButton.disabled = false;
  }
}

scanButton.addEventListener("click", () => { runScan(); });

helpLink.addEventListener("click", (event) => {
  event.preventDefault();
  renderStatus("Buying/payment signals trigger collection and API analysis. Fraud decisions come from the API response.", "clean");
});

document.querySelectorAll(".tools button").forEach((button) => {
  button.addEventListener("click", () => {
    const action = button.getAttribute("data-action") || "action";
    if (action === "logs") { location.href = "logs.html"; return; }
    if (action === "settings") { location.href = "settings.html"; return; }
    const labels = {
      account: "Account is not available yet.",
      blocked: "Blocked sites are not available yet.",
      report: "Report flow is not available yet.",
    };
    renderStatus(labels[action] || `${action} is not available yet.`, "");
  });
});

loadThreatCount();
loadCurrentResult();
