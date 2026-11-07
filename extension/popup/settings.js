"use strict";

const hostEl = document.getElementById("trust-host");
const trustCurrentBtn = document.getElementById("trust-current");
const addBtn = document.getElementById("add-trust");
const listEl = document.getElementById("trusted-list");
const statusEl = document.getElementById("settings-status");

function setStatus(text, tone) {
  statusEl.className = tone ? `status ${tone}` : "status";
  statusEl.textContent = text || "";
}

function normalizeHost(value) {
  const raw = String(value || "").trim();
  if (!raw) return "";
  try {
    const url = raw.includes("://") ? new URL(raw) : new URL(`https://${raw}`);
    return url.hostname.toLowerCase();
  } catch (_) {
    return raw.replace(/^https?:\/\//i, "").split("/")[0].toLowerCase();
  }
}

async function getTrusted() {
  const stored = await chrome.storage.local.get("trustedHosts");
  const list = Array.isArray(stored.trustedHosts) ? stored.trustedHosts : [];
  return [...new Set(list.map(normalizeHost).filter(Boolean))].sort();
}

async function setTrusted(list) {
  await chrome.storage.local.set({ trustedHosts: [...new Set(list.map(normalizeHost).filter(Boolean))].sort() });
}

async function render() {
  const trusted = await getTrusted();
  listEl.replaceChildren();
  if (!trusted.length) {
    const li = document.createElement("li");
    li.className = "trusted-empty";
    li.textContent = "No manually trusted sites.";
    listEl.append(li);
    return;
  }
  trusted.forEach((host) => {
    const li = document.createElement("li");
    li.className = "trusted-item";
    const name = document.createElement("span");
    name.textContent = host;
    const remove = document.createElement("button");
    remove.type = "button";
    remove.className = "btn ghost small";
    remove.textContent = "Remove";
    remove.addEventListener("click", async () => {
      const next = (await getTrusted()).filter((h) => h !== host);
      await setTrusted(next);
      setStatus(`Removed ${host}. Refresh that page to reapply blocking.`, "clean");
      await render();
    });
    li.append(name, remove);
    listEl.append(li);
  });
}

async function addHost(value) {
  const host = normalizeHost(value);
  if (!host) return setStatus("Enter a hostname or URL.", "flagged");
  const trusted = await getTrusted();
  if (!trusted.includes(host)) trusted.push(host);
  await setTrusted(trusted);
  hostEl.value = host;
  setStatus(`Trusted ${host}. Refresh that page to allow interaction.`, "clean");
  await render();
}

trustCurrentBtn.addEventListener("click", async () => {
  try {
    const [tab] = await chrome.tabs.query({ active: true, currentWindow: true });
    if (!tab || !tab.url) return setStatus("No active tab URL found.", "flagged");
    hostEl.value = normalizeHost(tab.url);
    await addHost(tab.url);
  } catch (e) {
    setStatus(String(e), "flagged");
  }
});

addBtn.addEventListener("click", async () => {
  try { await addHost(hostEl.value); } catch (e) { setStatus(String(e), "flagged"); }
});

chrome.storage.local.onChanged.addListener((changes) => {
  if (changes.trustedHosts) render();
});

render();


const openTestBtn = document.getElementById("open-test-page");
if (openTestBtn) openTestBtn.addEventListener("click", async () => {
  try {
    const url = chrome.runtime.getURL("test-page.html");
    await chrome.tabs.create({ url });
  } catch (e) { setStatus(String(e), "flagged"); }
});
