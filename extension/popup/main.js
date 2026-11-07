"use strict";
var __awaiter = (this && this.__awaiter) || function (thisArg, _arguments, P, generator) {
    function adopt(value) { return value instanceof P ? value : new P(function (resolve) { resolve(value); }); }
    return new (P || (P = Promise))(function (resolve, reject) {
        function fulfilled(value) { try { step(generator.next(value)); } catch (e) { reject(e); } }
        function rejected(value) { try { step(generator["throw"](value)); } catch (e) { reject(e); } }
        function step(result) { result.done ? resolve(result.value) : adopt(result.value).then(fulfilled, rejected); }
        step((generator = generator.apply(thisArg, _arguments || [])).next());
    });
};
const VERDICT_LABELS = {
    likely: "Likely fraudulent clone",
    possible: "Possibly fraudulent",
    none: "No clone signals detected",
};
const statusEl = document.getElementById("status");
const resultEl = document.getElementById("result");
const verdictEl = document.getElementById("verdict");
const scoreEl = document.getElementById("score");
const urlEl = document.getElementById("url");
const signalsEl = document.getElementById("signals");
function render(result) {
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
    signalsEl.replaceChildren(...result.signals.map((signal) => {
        var _a;
        const item = document.createElement("li");
        const name = document.createElement("span");
        name.className = "signal-name";
        name.textContent = signal.name;
        const detail = document.createElement("span");
        detail.className = "signal-detail";
        detail.textContent = (_a = signal.detail) !== null && _a !== void 0 ? _a : "";
        const weight = document.createElement("span");
        weight.className = "signal-weight";
        weight.textContent = `+${signal.weight}`;
        item.append(name, detail, weight);
        return item;
    }));
}
function getStorageKey() {
    return __awaiter(this, void 0, void 0, function* () {
        const [tab] = yield chrome.tabs.query({ active: true, currentWindow: true });
        return (tab === null || tab === void 0 ? void 0 : tab.id) ? `tab:${tab.id}` : undefined;
    });
}
function load() {
    return __awaiter(this, void 0, void 0, function* () {
        const key = yield getStorageKey();
        if (!key) {
            render();
            return;
        }
        const stored = yield chrome.storage.session.get(key);
        render(stored[key]);
        chrome.storage.session.onChanged.addListener((changes) => {
            if (changes[key])
                render(changes[key].newValue);
        });
    });
}
load();
