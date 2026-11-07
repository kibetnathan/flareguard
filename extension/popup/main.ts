type Signal = { name: string; weight: number; detail?: string };

type ScanResult = {
  type: "SCAN_RESULT";
  url: string;
  score: number;
  verdict: "likely" | "possible" | "none";
  signals: Signal[];
};

const VERDICT_LABELS: Record<ScanResult["verdict"], string> = {
  likely: "Likely fraudulent clone",
  possible: "Possibly fraudulent",
  none: "No clone signals detected",
};

const statusEl = document.getElementById("status") as HTMLParagraphElement;
const resultEl = document.getElementById("result") as HTMLElement;
const verdictEl = document.getElementById("verdict") as HTMLDivElement;
const scoreEl = document.getElementById("score") as HTMLElement;
const urlEl = document.getElementById("url") as HTMLParagraphElement;
const signalsEl = document.getElementById("signals") as HTMLUListElement;

function render(result?: ScanResult) {
  if (!result) {
    statusEl.textContent = "No scan result yet. Reload the page and try again.";
    statusEl.hidden = false;
    resultEl.hidden = true;
    return;
  }

  statusEl.hidden = true;
  resultEl.hidden = false;

  verdictEl.textContent = VERDICT_LABELS[result.verdict];
  verdictEl.className = `verdict ${result.verdict}`;
  scoreEl.textContent = `${result.score} / 3`;
  urlEl.textContent = result.url;

  signalsEl.replaceChildren(
    ...result.signals.map((signal) => {
      const item = document.createElement("li");

      const name = document.createElement("span");
      name.className = "signal-name";
      name.textContent = signal.name;

      const detail = document.createElement("span");
      detail.className = "signal-detail";
      detail.textContent = signal.detail ?? "";

      const weight = document.createElement("span");
      weight.className = "signal-weight";
      weight.textContent = `+${signal.weight}`;

      item.append(name, detail, weight);
      return item;
    }),
  );
}

async function getStorageKey(): Promise<string | undefined> {
  const [tab] = await chrome.tabs.query({ active: true, currentWindow: true });
  return tab?.id ? `tab:${tab.id}` : undefined;
}

async function load() {
  const key = await getStorageKey();
  if (!key) {
    render();
    return;
  }

  const stored = await chrome.storage.session.get(key);
  render(stored[key] as ScanResult | undefined);

  chrome.storage.session.onChanged.addListener((changes) => {
    if (changes[key]) render(changes[key].newValue as ScanResult | undefined);
  });
}

load();
