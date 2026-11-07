"use strict";

const root = document.getElementById("fixture-root");
const statusEl = document.getElementById("test-status");

function setStatus(msg, data) {
  statusEl.textContent = msg;
  console.log("[Flareguard Test Page]", msg, data || "");
}

function clearFixtures() {
  root.replaceChildren();
  const em = document.createElement("em");
  em.textContent = "No fixtures injected.";
  root.append(em);
  setStatus("Fixtures cleared.");
}

function addMedium() {
  clearFixtures();
  root.innerHTML = `<p><strong>Checkout preview</strong></p><p>Plan price: USD 19.99 / month</p><button type="button">Pay now</button>`;
  setStatus("Injected medium payment UI fixtures in the page.");
}

function addHigh() {
  clearFixtures();
  root.innerHTML = `<p><strong>Secure checkout</strong></p><p>Total: USD 49.99</p><form><label>Card name<input autocomplete="cc-name" value="Test User"></label><div class="row"><label>Card number<input autocomplete="cc-number" inputmode="numeric" value="4242424242424242"></label><label>CVC<input autocomplete="cc-csc" inputmode="numeric" value="123"></label></div><label>Expiry<input autocomplete="cc-exp" value="12/29"></label><button type="submit">Proceed to pay</button></form><script src="https://js.stripe.com/v3/"></script>`;
  setStatus("Injected high-risk fixtures in the page.");
}

async function currentTabId() {
  const tab = await chrome.tabs.getCurrent();
  if (tab && tab.id) return tab.id;
  const [active] = await chrome.tabs.query({ active: true, currentWindow: true });
  return active && active.id ? active.id : null;
}

async function emitLog(level, message, data) {
  try {
    await chrome.runtime.sendMessage({ type: "FG_LOG", ts: Date.now(), level, source: "test-page", message, data, url: location.href });
  } catch (e) { console.warn("FG_LOG failed", e); }
}

async function emitResult(score, verdict, signals) {
  const tabId = await currentTabId();
  const result = { type: "SCAN_RESULT", url: location.href, score, verdict, signals };
  try {
    await chrome.runtime.sendMessage(result);
  } catch (e) { console.warn("SCAN_RESULT send failed", e); }
  if (tabId) {
    try { await chrome.storage.session.set({ [`tab:${tabId}`]: result }); } catch (e) { console.warn("session set failed", e); }
  }
  await emitLog(score >= 3 ? "warn" : "info", `Test page emitted result: ${verdict} (${score}/3)`, { ok: true, score, verdict, signals, tabId });
  setStatus(`Emitted ${verdict} ${score}/3 for active/test tab. Open popup: >2/3 shows warning; 3/3 also exercises block logic when result is emitted by content script on a matched page.`, result);
  return result;
}

document.getElementById("clean").addEventListener("click", async () => {
  clearFixtures();
  await emitResult(1, "none", []);
});
document.getElementById("medium").addEventListener("click", async () => {
  addMedium();
  await emitResult(2, "possible", [
    { name: "price-text", weight: 1 },
    { name: "payment-button", weight: 2, detail: "Pay now" },
  ]);
});
document.getElementById("high").addEventListener("click", async () => {
  addHigh();
  await emitResult(3, "likely", [
    { name: "card-fields", weight: 5, detail: "3 fields" },
    { name: "payment-provider", weight: 4, detail: "js.stripe.com" },
    { name: "payment-button", weight: 2, detail: "Proceed to pay" },
    { name: "price-text", weight: 1 },
  ]);
});
document.getElementById("remove").addEventListener("click", clearFixtures);
document.getElementById("mutate").addEventListener("click", () => {
  const n = document.createElement("div");
  n.className = "hint";
  n.textContent = `DOM mutation at ${new Date().toLocaleTimeString()}`;
  root.append(n);
  setStatus("Triggered DOM mutation.");
});
document.getElementById("pushstate").addEventListener("click", () => {
  const url = new URL(location.href);
  url.hash = "checkout-test-" + Date.now();
  history.pushState({}, "", url);
  setStatus(`Updated hash to ${url.hash}.`);
});

document.getElementById("emit-log").addEventListener("click", async () => {
  await emitLog("info", "Manual test log from test page", { ok: true, sample: { href: location.href, fixtures: root.children.length } });
  setStatus("Emitted a manual FG_LOG. Open Script logs to verify.");
});

document.getElementById("clear-tab-result").addEventListener("click", async () => {
  const tabId = await currentTabId();
  if (tabId) await chrome.storage.session.remove(`tab:${tabId}`);
  await emitLog("info", "Cleared test tab scan result", { tabId });
  setStatus("Cleared session scan result for this tab.");
});

emitLog("info", "Test page opened", { ok: true, sample: { href: location.href } });
setStatus("Ready. Clean/Medium/High emit scan results for the active tab; use popup to verify warning/logs. For real page-block overlay testing, open a normal http/https page where content scripts run and trigger a 3/3 detection.");
