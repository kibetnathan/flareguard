"use strict";

function fgRuntimeOk() {
  try { return !!(chrome && chrome.runtime && chrome.runtime.id); } catch (_) { return false; }
}
function fgLog(level, message, data) {
  if (!fgRuntimeOk()) return;
  try {
    chrome.runtime.sendMessage({
      type: "FG_LOG",
      ts: Date.now(),
      level,
      source: "collector",
      message,
      data,
      url: location.href,
    }, () => {
      try { void chrome.runtime.lastError; } catch (_) {}
    });
  } catch (_) {}
}

function hasFavicon() {
  const rels = ['icon', 'shortcut icon', 'apple-touch-icon'];
  return !!document.querySelector(`link[rel~="${rels.join('"], link[rel~="')}"]`);
}

function getNavbarLogoExtension() {
  const selectors = [
    'nav img',
    'header img',
    '.navbar img',
    '.logo img',
    '.navbar-logo',
    '.logo',
    'img[alt*="logo"]',
  ];
  for (const sel of selectors) {
    const el = document.querySelector(sel);
    if (!el) continue;
    let src = '';
    if (el instanceof HTMLImageElement) {
      src = el.src;
    } else {
      const bg = getComputedStyle(el).backgroundImage;
      const match = bg.match(/url\(["']?([^"')]+)["']?\)/);
      if (match) src = match[1];
    }
    if (src) {
      const extMatch = src.split('?')[0].match(/\.([a-zA-Z0-9]+)$/);
      return extMatch ? extMatch[1].toLowerCase() : null;
    }
  }
  return null;
}

async function checkBrokenLinks(limit) {
  const links = Array.from(document.querySelectorAll('a[href]'));
  const urls = links.map(l => l.href).filter(h => /^https?:/i.test(h)).slice(0, limit || 20);
  const broken = [];
  const concurrency = 4;
  let i = 0;
  async function worker() {
    while (i < urls.length) {
      const index = i++;
      const url = urls[index];
      try {
        const res = await fetch(url, { method: 'HEAD', mode: 'no-cors' });
        if (res && res.ok === false) broken.push(url);
      } catch (_) {
        try {
          const res2 = await fetch(url, { method: 'GET', mode: 'cors' });
          if (res2 && !res2.ok) broken.push(url);
        } catch (_) {
          // avoid false positives for cross-origin/no-cors failures
        }
      }
    }
  }
  await Promise.all(Array.from({ length: Math.min(concurrency, urls.length || 1) }, worker));
  return broken;
}

function sampleData(data) {
  return {
    url: data.url,
    title: data.title,
    hasFavicon: data.hasFavicon,
    navbarLogoExtension: data.navbarLogoExtension,
    brokenLinksCount: Array.isArray(data.brokenLinks) ? data.brokenLinks.length : 0,
    brokenLinksSample: Array.isArray(data.brokenLinks) ? data.brokenLinks.slice(0, 5) : [],
    triggerCount: Array.isArray(data.triggerSignals) ? data.triggerSignals.length : 0,
  };
}

async function collectData(triggerSignals) {
  const data = {
    url: location.href,
    title: document.title || "",
    hasFavicon: hasFavicon(),
    navbarLogoExtension: getNavbarLogoExtension(),
    brokenLinks: await checkBrokenLinks(20),
    triggerSignals: Array.isArray(triggerSignals) ? triggerSignals : [],
    collectedAt: new Date().toISOString(),
  };
  fgLog("info", "Collector check ok: data collected", { ok: true, sample: sampleData(data) });
  return data;
}

if (fgRuntimeOk()) {
  chrome.runtime.onMessage.addListener((msg, _sender, sendResponse) => {
    if (!msg || msg.type !== "FG_COLLECT") return;
    fgLog("info", "Collector requested by trigger/API flow", { reason: msg.reason || "", triggerCount: (msg.triggerSignals || []).length });
    collectData(msg.triggerSignals || []).then((data) => {
      try { sendResponse({ ok: true, data }); } catch (_) {}
    }).catch((error) => {
      fgLog("error", "Collector check failed", { ok: false, error: String(error) });
      try { sendResponse({ ok: false, error: String(error) }); } catch (_) {}
    });
    return true;
  });
}

fgLog("info", "Collector ready (waiting for trigger)");
