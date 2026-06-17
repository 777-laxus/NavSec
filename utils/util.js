// =============================================================
// util.js  -  Funcoes utilitarias compartilhadas.
// =============================================================

// Abre uma URL externa numa nova aba (redirecionamento).
export function openUrl(url) {
  if (!url) return;
  if (typeof chrome !== "undefined" && chrome.tabs && chrome.tabs.create) {
    chrome.tabs.create({ url });
  } else {
    window.open(url, "_blank", "noopener");
  }
}
