// Collector script for Flare Guard extension
// Captures page data and posts to provided API endpoint

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

async function checkBrokenLinks() {
  const links = Array.from(document.querySelectorAll('a[href]'));
  const urls = links.map(l => l.href).filter(h => h.startsWith('http'));
  const broken = [];
  const concurrency = 5;
  let i = 0;
  async function worker() {
    while (i < urls.length) {
      const index = i++;
      const url = urls[index];
      try {
        const res = await fetch(url, { method: 'HEAD', mode: 'no-cors' });
        if (!res.ok) broken.push(url);
      } catch (_) {
        try {
          const res2 = await fetch(url, { method: 'GET', mode: 'cors' });
          if (!res2.ok) broken.push(url);
        } catch (_) {
          broken.push(url);
        }
      }
    }
  }
  await Promise.all(Array.from({ length: concurrency }, worker));
  return broken;
}

function sampleData(data) {
  return {
    url: data.url,
    hasFavicon: data.hasFavicon,
    navbarLogoExtension: data.navbarLogoExtension,
    brokenLinksCount: Array.isArray(data.brokenLinks) ? data.brokenLinks.length : 0,
    brokenLinksSample: Array.isArray(data.brokenLinks) ? data.brokenLinks.slice(0, 5) : [],
  };
}

async function collectAndSend() {
  if (!fgRuntimeOk()) return;
  try {
    fgLog("info", "Collector started");
    const data = {
      url: location.href,
      hasFavicon: hasFavicon(),
      navbarLogoExtension: getNavbarLogoExtension(),
      brokenLinks: await checkBrokenLinks(),
    };
    if (!fgRuntimeOk()) return;
    fgLog("info", "Collector check ok: data collected", {
      ok: true,
      sample: sampleData(data),
    });
    const endpoint = await new Promise(resolve => {
      try { chrome.storage.sync.get(['apiEndpoint'], result => resolve(result && result.apiEndpoint)); }
      catch (_) { resolve(null); }
    });
    if (!fgRuntimeOk()) return;
    if (!endpoint) {
      fgLog("warn", "API endpoint not configured; sample kept in logs only", {
        ok: true,
        sample: sampleData(data),
      });
      return;
    }
    try {
      await fetch(endpoint, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify(data),
      });
      fgLog("info", "Collector sent data to API endpoint", {
        ok: true,
        sample: sampleData(data),
      });
    } catch (e) {
      fgLog("error", "Collector failed to send page data", {
        ok: false,
        error: String(e),
        sample: sampleData(data),
      });
    }
  } catch (error) {
    fgLog("error", "Collector check failed", { ok: false, error: String(error) });
  }
}

if (document.readyState === 'loading') {
  document.addEventListener('DOMContentLoaded', collectAndSend);
} else {
  collectAndSend();
}
