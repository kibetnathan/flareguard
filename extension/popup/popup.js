"use strict";

const countEl = document.getElementById("count");
const scanButton = document.getElementById("scan");
const statusEl = document.getElementById("status");
const helpLink = document.getElementById("help");

async function getActiveTab() {
  const [tab] = await chrome.tabs.query({ active: true, currentWindow: true });
  return tab;
}

async function logEvent(level, message, data) {
  try {
    await chrome.runtime.sendMessage({ type: "FG_LOG", ts: Date.now(), level, source: "popup", message, data });
  } catch (_) {}
}

const verdictText = {
  likely: "Likely fraudulent clone detected.",
  possible: "Possible suspicious signals found.",
  none: "No clone or payment risk signals found.",
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
    renderStatus("Open a webpage and press Scan webpage.", "");
    return;
  }

  if (result.score > 2) {
    location.replace("warning.html");
    return;
  }

  const tone = result.verdict === "possible" ? "flagged" : "clean";
  const root = document.createDocumentFragment();

  const title = document.createElement("strong");
  title.textContent = verdictText[result.verdict] || verdictText.none;
  root.append(title);

  const meta = document.createElement("div");
  meta.textContent = `Risk level ${result.score} / 3`;
  root.append(meta);

  if (result.signals && result.signals.length) {
    const list = document.createElement("ul");
    result.signals.forEach((signal) => {
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
    renderStatus("Scanning works on regular webpages.", "");
    return;
  }
  scanButton.disabled = true;
  renderStatus("Scanning webpage...", "");
  try {
    await chrome.tabs.sendMessage(tab.id, { type: "SCAN_REQUEST" });
    window.setTimeout(async () => {
      const key = `tab:${tab.id}`;
      const stored = await chrome.storage.session.get(key);
      renderResult(stored[key]);
      scanButton.disabled = false;
    }, 700);
  } catch (_) {
    renderStatus("Reload the webpage, then try scanning again.", "flagged");
    scanButton.disabled = false;
  }
}

scanButton.addEventListener("click", () => { runScan(); });

helpLink.addEventListener("click", (event) => {
  event.preventDefault();
  renderStatus("Scan a page to check for risky payment or clone signals. Flagged pages show a risk level and the signals found.", "clean");
});

document.querySelectorAll(".tools button").forEach((button) => {
  button.addEventListener("click", () => {
    const action = button.getAttribute("data-action") || "action";
    if (action === "logs") {
      location.href = "logs.html";
      return;
    }
    if (action === "settings") {
      location.href = "settings.html";
      return;
    }
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
